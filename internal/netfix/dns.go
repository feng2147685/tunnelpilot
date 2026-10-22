package netfix

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// DNSBackup 记录某个网络服务在接管前的 DNS 配置
type DNSBackup struct {
	Service string   `json:"service"`
	Servers []string `json:"servers"`
}

const dnsBackupPath = "/Library/Application Support/TunnelPilot/dns-backup.json"

// ListNetworkServices 列出所有网络服务名。
// networksetup 会给禁用的服务加星号前缀，这里去掉星号（设置 DNS 时会失败，忽略即可）。
func ListNetworkServices() []string {
	out, err := exec.Command("networksetup", "-listallnetworkservices").Output()
	if err != nil {
		return nil
	}
	var services []string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "An asterisk") {
			continue
		}
		line = strings.TrimPrefix(line, "*")
		line = strings.TrimSpace(line)
		if line != "" {
			services = append(services, line)
		}
	}
	return services
}

func getDNSServers(service string) []string {
	out, err := exec.Command("networksetup", "-getdnsservers", service).Output()
	if err != nil {
		return nil
	}
	var servers []string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.Contains(line, "aren't any") {
			continue
		}
		// 出错时 networksetup 会输出 "** Error:..."
		if strings.HasPrefix(line, "**") {
			return nil
		}
		servers = append(servers, line)
	}
	return servers
}

// OverrideDNS 把全部网络服务的 DNS 指向 TUN 地址。
// 系统默认 DNS 通常是路由器（192.168.x.1），而 TUN 的自动路由会排除局域网段，
// 因此不接管 DNS 的话，DNS 查询根本不会进入 utun，Fake-IP 分流也就无从谈起。
func OverrideDNS(addr string) ([]DNSBackup, error) {
	services := ListNetworkServices()
	if len(services) == 0 {
		return nil, fmt.Errorf("未找到任何网络服务")
	}

	var backups []DNSBackup
	changed := 0
	for _, s := range services {
		current := getDNSServers(s)
		backups = append(backups, DNSBackup{Service: s, Servers: current})
		if err := exec.Command("networksetup", "-setdnsservers", s, addr).Run(); err == nil {
			changed++
		}
	}

	if changed == 0 {
		return nil, fmt.Errorf("没有成功修改任何网络服务的 DNS")
	}

	if err := saveDNSBackup(backups); err != nil {
		return backups, err
	}
	flushDNSCache()
	return backups, nil
}

// RestoreDNS 用内存中的备份恢复 DNS
func RestoreDNS(backups []DNSBackup) {
	for _, b := range backups {
		setDNSServers(b.Service, b.Servers)
	}
	_ = os.Remove(dnsBackupPath)
	flushDNSCache()
}

// RestoreDNSFromBackup 从磁盘备份恢复，用于进程异常退出后的补救
func RestoreDNSFromBackup() (int, error) {
	data, err := os.ReadFile(dnsBackupPath)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	var backups []DNSBackup
	if err = json.Unmarshal(data, &backups); err != nil {
		return 0, err
	}
	for _, b := range backups {
		setDNSServers(b.Service, b.Servers)
	}
	_ = os.Remove(dnsBackupPath)
	flushDNSCache()
	return len(backups), nil
}

// HasDNSBackup 判断是否存在未恢复的 DNS 备份
func HasDNSBackup() bool {
	_, err := os.Stat(dnsBackupPath)
	return err == nil
}

func setDNSServers(service string, servers []string) {
	if len(servers) == 0 {
		_ = exec.Command("networksetup", "-setdnsservers", service, "Empty").Run()
		return
	}
	args := append([]string{"-setdnsservers", service}, servers...)
	_ = exec.Command("networksetup", args...).Run()
}

func saveDNSBackup(backups []DNSBackup) error {
	if err := os.MkdirAll(filepath.Dir(dnsBackupPath), 0755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(backups, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(dnsBackupPath, data, 0644)
}

func flushDNSCache() {
	_ = exec.Command("dscacheutil", "-flushcache").Run()
	_ = exec.Command("killall", "-HUP", "mDNSResponder").Run()
}
