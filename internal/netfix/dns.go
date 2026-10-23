package netfix

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
)

// DNSBackup 保存网络服务接管前的静态 DNS；空列表表示恢复 DHCP 自动获取。
type DNSBackup struct {
	Service string   `json:"service"`
	Servers []string `json:"servers"`
}

// dnsBackupPath 是异常退出后 restore 命令读取的恢复日志位置。
const dnsBackupPath = "/Library/Application Support/TunnelPilot/dns-backup.json"

// dnsSettings 封装 DNS 命令与恢复日志，隔离真实系统操作，便于验证失败和回滚路径。
type dnsSettings struct {
	path string
	run  func(string, ...string) ([]byte, error)
}

// dnsMu 防止同一进程的启停和手动恢复交错覆盖恢复日志。
var dnsMu sync.Mutex

// systemDNS 返回生产 DNS 操作器；param 无；返回值只在显式接管或恢复时执行系统命令。
func systemDNS() dnsSettings {
	return dnsSettings{path: dnsBackupPath, run: func(name string, args ...string) ([]byte, error) {
		return exec.Command(name, args...).CombinedOutput()
	}}
}

// command 执行 networksetup 并识别其退出码为零但输出 Error 的失败情形。
// param args 为固定参数与网络服务名；返回命令输出，系统或工具报错时返回错误。
func (d dnsSettings) command(args ...string) ([]byte, error) {
	out, err := d.run("networksetup", args...)
	if err != nil || strings.Contains(string(out), "** Error") {
		return nil, fmt.Errorf("networksetup %s 失败: %s (%v)", args[0], strings.TrimSpace(string(out)), err)
	}
	return out, nil
}

// listServices 列出启用的网络服务，禁用服务不参与接管。
// param 无；返回服务名列表，读取失败或没有可用服务时返回错误。
func (d dnsSettings) listServices() ([]string, error) {
	out, err := d.command("-listallnetworkservices")
	if err != nil {
		return nil, err
	}
	var services []string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "An asterisk") && !strings.HasPrefix(line, "*") {
			services = append(services, line)
		}
	}
	if len(services) == 0 {
		return nil, errors.New("未找到启用的网络服务")
	}
	return services, nil
}

// servers 读取可恢复的静态 DNS 列表；读取失败不能视为 DHCP 空配置。
// param service 为服务名；返回 IP 列表，未知输出或命令错误时返回错误。
func (d dnsSettings) servers(service string) ([]string, error) {
	out, err := d.command("-getdnsservers", service)
	if err != nil {
		return nil, err
	}
	if strings.Contains(string(out), "aren't any DNS Servers") {
		return nil, nil
	}
	var servers []string
	for _, line := range strings.Fields(string(out)) {
		if net.ParseIP(line) == nil {
			return nil, fmt.Errorf("服务 %s 的 DNS 配置不是有效 IP", service)
		}
		servers = append(servers, line)
	}
	return servers, nil
}

// OverrideDNS 先持久化全部原配置，再接管 DNS；任何失败均尝试恢复所有服务。
// param addr 为虚拟 DNS 的 IPv4 地址；返回待恢复的备份，错误表示接管未完成，非空备份表示回滚仍需重试。
func OverrideDNS(addr string) ([]DNSBackup, error) {
	dnsMu.Lock()
	defer dnsMu.Unlock()
	return systemDNS().override(addr)
}

// override 执行具备恢复日志的 DNS 事务。
// param addr 为虚拟 DNS 地址；返回尚待恢复的备份和接管错误，备份落盘前不会修改系统。
func (d dnsSettings) override(addr string) ([]DNSBackup, error) {
	if net.ParseIP(addr) == nil {
		return nil, errors.New("接管 DNS 地址无效")
	}
	services, err := d.listServices()
	if err != nil {
		return nil, err
	}
	var backups []DNSBackup
	for _, service := range services {
		servers, err := d.servers(service)
		if err != nil {
			return nil, err
		}
		backups = append(backups, DNSBackup{Service: service, Servers: servers})
	}
	if err := d.save(backups); err != nil {
		return nil, fmt.Errorf("DNS 原配置备份失败，未修改系统；若有残留请先 restore: %w", err)
	}
	for _, service := range services {
		if _, err = d.command("-setdnsservers", service, addr); err != nil {
			break
		}
	}
	if err == nil {
		err = d.flush()
	}
	if err != nil {
		if restoreErr := d.restore(backups); restoreErr != nil {
			return backups, errors.Join(err, fmt.Errorf("DNS 回滚失败，备份已保留: %w", restoreErr))
		}
		return nil, err
	}
	return backups, nil
}

// save 排他创建恢复日志并同步到磁盘，拒绝覆盖上一次未恢复的原始配置。
// param backups 为全部原配置；返回落盘错误，失败时调用方不得开始接管。
func (d dnsSettings) save(backups []DNSBackup) error {
	if err := os.MkdirAll(filepath.Dir(d.path), 0755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(backups, "", "  ")
	if err != nil {
		return err
	}
	file, err := os.OpenFile(d.path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, writeErr := file.Write(data)
	return errors.Join(writeErr, file.Sync(), file.Close())
}

// RestoreDNS 恢复内存备份，仅在全部服务和 DNS 缓存恢复成功后删除恢复日志。
// param backups 为接管前的原始配置；返回失败明细，失败时保留备份以便重试。
func RestoreDNS(backups []DNSBackup) error {
	dnsMu.Lock()
	defer dnsMu.Unlock()
	return systemDNS().restore(backups)
}

// restore 尝试全部服务，单个失败不阻止其它服务恢复。
// param backups 为原配置；返回汇总错误，任何失败都保留恢复日志。
func (d dnsSettings) restore(backups []DNSBackup) error {
	var errs []error
	for _, backup := range backups {
		servers := backup.Servers
		if len(servers) == 0 {
			servers = []string{"Empty"}
		}
		if _, err := d.command(append([]string{"-setdnsservers", backup.Service}, servers...)...); err != nil {
			errs = append(errs, err)
		}
	}
	if err := d.flush(); err != nil {
		errs = append(errs, err)
	}
	if err := errors.Join(errs...); err != nil {
		return err
	}
	if err := os.Remove(d.path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// RestoreDNSFromBackup 用于异常退出后的恢复；不把部分失败报告成全部恢复成功。
// param 无；返回成功恢复的服务数，日志损坏或恢复失败时返回错误并保留日志。
func RestoreDNSFromBackup() (int, error) {
	dnsMu.Lock()
	defer dnsMu.Unlock()
	d := systemDNS()
	data, err := os.ReadFile(d.path)
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	var backups []DNSBackup
	if err := json.Unmarshal(data, &backups); err != nil {
		return 0, err
	}
	if len(backups) == 0 {
		return 0, errors.New("DNS 恢复日志为空，已保留文件，请检查原配置")
	}
	for _, backup := range backups {
		if strings.TrimSpace(backup.Service) == "" {
			return 0, errors.New("DNS 恢复日志缺少服务名")
		}
		for _, server := range backup.Servers {
			if net.ParseIP(server) == nil {
				return 0, errors.New("DNS 恢复日志包含无效地址")
			}
		}
	}
	if err := d.restore(backups); err != nil {
		return 0, err
	}
	return len(backups), nil
}

// HasDNSBackup 检查是否存在恢复日志；param 无；返回存在状态，读取权限错误也视为待恢复，避免覆盖。
func HasDNSBackup() bool {
	_, err := os.Stat(dnsBackupPath)
	return !os.IsNotExist(err)
}

// flush 刷新 macOS DNS 缓存；param 无；返回工具失败，禁止静默宣称恢复成功。
func (d dnsSettings) flush() error {
	var errs []error
	for _, command := range [][]string{{"dscacheutil", "-flushcache"}, {"killall", "-HUP", "mDNSResponder"}} {
		if _, err := d.run(command[0], command[1:]...); err != nil {
			errs = append(errs, fmt.Errorf("刷新 DNS 缓存 %s 失败: %w", command[0], err))
		}
	}
	return errors.Join(errs...)
}
