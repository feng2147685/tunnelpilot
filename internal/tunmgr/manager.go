package tunmgr

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/control"

	"tunnelpilot/internal/config"
	"tunnelpilot/internal/fakeip"
	"tunnelpilot/internal/logx"
	"tunnelpilot/internal/netfix"
	"tunnelpilot/internal/proxy"
	"tunnelpilot/internal/tunengine"
)

// Manager 负责 utun 的创建与销毁，支持反复启停。
// launchd 常驻时 daemon 进程一直在，启停指的是「是否接管系统流量」。
type Manager struct {
	mu      sync.Mutex
	profile func() *config.Profile
	handler *tunengine.Handler
	dialer  *proxy.Dialer
	logger  *logx.Logger

	stack      tun.Stack
	device     tun.Tun
	cleanup    func() error
	cancel     context.CancelFunc
	restoreDNS func([]netfix.DNSBackup) error
	running    bool
	ifName     string
	lastError  string
	dnsBackups []netfix.DNSBackup
}

// New 组装 TUN 生命周期管理，依赖配置快照、转发器、拨号器及日志。
// param profileFn/handler/dialer/logger 为所需服务；返回管理器，此时不修改网络。
func New(profileFn func() *config.Profile, handler *tunengine.Handler, dialer *proxy.Dialer, logger *logx.Logger) *Manager {
	return &Manager{
		profile:    profileFn,
		handler:    handler,
		dialer:     dialer,
		logger:     logger,
		restoreDNS: netfix.RestoreDNS,
	}
}

// Running 查询是否正在接管；param 无；返回加锁读取的运行状态。
func (m *Manager) Running() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.running
}

// InterfaceName 查询接管网卡；param 无；返回网卡名，未运行时为空。
func (m *Manager) InterfaceName() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.ifName
}

// LastError 读取最近启停错误；param 无；返回错误文本，正常状态为空。
func (m *Manager) LastError() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastError
}

// Start 创建 utun 并接管全局流量。
// param 无；返回初始化或 DNS 接管错误，失败时回滚，DNS 恢复失败时保留网卡供重试。
func (m *Manager) Start() (startErr error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	defer func() {
		if startErr != nil {
			m.lastError = startErr.Error()
		}
	}()
	if m.running {
		if m.lastError != "" {
			return fmt.Errorf("接管仍在运行，但需要先处理清理失败: %s", m.lastError)
		}
		return nil
	}

	if len(m.dnsBackups) > 0 || netfix.HasDNSBackup() {
		return fmt.Errorf("存在未恢复的 DNS 配置，请先停止接管或执行 sudo tunnelpilot restore")
	}
	closeOnFailure := func(name string, closeFn func() error) {
		if err := closeFn(); err != nil {
			m.logger.Warn(name, " 清理失败: ", err)
		}
	}
	profile := m.profile()
	prefix := profile.FakeIPPrefixValue()

	interfaceFinder := control.NewDefaultInterfaceFinder()
	if err := interfaceFinder.Update(); err != nil {
		m.logger.Warn("网卡信息初始化失败: ", err)
	}
	networkMonitor, err := tun.NewNetworkUpdateMonitor(m.logger)
	if err != nil {
		return fmt.Errorf("创建网络变化监听失败: %w", err)
	}
	if err = networkMonitor.Start(); err != nil {
		closeOnFailure("网络变化监听", networkMonitor.Close)
		return fmt.Errorf("启动网络变化监听失败: %w", err)
	}
	interfaceMonitor, err := tun.NewDefaultInterfaceMonitor(networkMonitor, m.logger, tun.DefaultInterfaceMonitorOptions{
		InterfaceFinder: interfaceFinder,
	})
	if err != nil {
		closeOnFailure("网络变化监听", networkMonitor.Close)
		return fmt.Errorf("创建默认网卡监听失败: %w", err)
	}
	if err = interfaceMonitor.Start(); err != nil {
		closeOnFailure("默认网卡监听", interfaceMonitor.Close)
		closeOnFailure("网络变化监听", networkMonitor.Close)
		return fmt.Errorf("启动默认网卡监听失败: %w", err)
	}

	// 关键：出站流量绑定物理网卡，否则包会被全局路由引回 utun 形成环路。
	// 回环地址例外（本地代理监听在 127.0.0.1），由 Dialer 内部控制。
	ifName := ""
	if iface := interfaceMonitor.DefaultInterface(); iface != nil {
		ifName = iface.Name
	} else {
		ifName = detectPhysicalInterface()
	}
	if ifName != "" {
		if err := m.dialer.SetBindInterface(ifName); err != nil {
			closeOnFailure("默认网卡监听", interfaceMonitor.Close)
			closeOnFailure("网络变化监听", networkMonitor.Close)
			return err
		}
		m.logger.Info("出站流量已绑定物理网卡: ", ifName)
	} else {
		closeOnFailure("默认网卡监听", interfaceMonitor.Close)
		closeOnFailure("网络变化监听", networkMonitor.Close)
		return fmt.Errorf("未能识别出站网卡，已取消接管以避免路由环路")
	}

	options := tun.Options{
		Name:                    profile.TUNName,
		MTU:                     1500,
		Inet4Address:            []netip.Prefix{prefix},
		AutoRoute:               true,
		StrictRoute:             true,
		EXP_MultiPendingPackets: true,
		InterfaceFinder:         interfaceFinder,
		InterfaceMonitor:        interfaceMonitor,
		Logger:                  m.logger,
	}

	for _, s := range profile.ProxyServers {
		if addr, err := netip.ParseAddr(s.Address); err == nil && !addr.IsLoopback() {
			options.Inet4RouteExcludeAddress = append(options.Inet4RouteExcludeAddress, netip.PrefixFrom(addr, addr.BitLen()))
			continue
		}
		if ips, err := net.LookupIP(s.Address); err == nil {
			for _, ip := range ips {
				if a, ok := netip.AddrFromSlice(ip); ok && !a.IsLoopback() {
					a = a.Unmap()
					options.Inet4RouteExcludeAddress = append(options.Inet4RouteExcludeAddress, netip.PrefixFrom(a, a.BitLen()))
				}
			}
		}
	}

	device, err := tun.New(options)
	if err != nil {
		closeOnFailure("默认网卡监听", interfaceMonitor.Close)
		closeOnFailure("网络变化监听", networkMonitor.Close)
		m.lastError = err.Error()
		return friendlyTunError("创建虚拟网卡", err)
	}
	if err = device.Start(); err != nil {
		closeOnFailure("虚拟网卡", device.Close)
		closeOnFailure("默认网卡监听", interfaceMonitor.Close)
		closeOnFailure("网络变化监听", networkMonitor.Close)
		m.lastError = err.Error()
		return friendlyTunError("启动虚拟网卡", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	stack, err := tun.NewStack("gvisor", tun.StackOptions{
		Context:         ctx,
		Tun:             device,
		TunOptions:      options,
		UDPTimeout:      3 * time.Minute,
		ICMPTimeout:     30 * time.Second,
		Handler:         m.handler,
		Logger:          m.logger,
		InterfaceFinder: interfaceFinder,
	})
	if err != nil {
		cancel()
		closeOnFailure("虚拟网卡", device.Close)
		closeOnFailure("默认网卡监听", interfaceMonitor.Close)
		closeOnFailure("网络变化监听", networkMonitor.Close)
		m.lastError = err.Error()
		return fmt.Errorf("创建网络栈失败: %w", err)
	}
	if err = stack.Start(); err != nil {
		cancel()
		closeOnFailure("协议栈", stack.Close)
		closeOnFailure("虚拟网卡", device.Close)
		closeOnFailure("默认网卡监听", interfaceMonitor.Close)
		closeOnFailure("网络变化监听", networkMonitor.Close)
		m.lastError = err.Error()
		return fmt.Errorf("启动网络栈失败: %w", err)
	}

	name, err := device.Name()
	if err != nil {
		cancel()
		closeOnFailure("协议栈", stack.Close)
		closeOnFailure("虚拟网卡", device.Close)
		closeOnFailure("默认网卡监听", interfaceMonitor.Close)
		closeOnFailure("网络变化监听", networkMonitor.Close)
		return fmt.Errorf("读取虚拟网卡名称失败: %w", err)
	}
	m.cancel = cancel
	m.stack = stack
	m.device = device
	m.cleanup = func() error {
		return errors.Join(interfaceMonitor.Close(), networkMonitor.Close())
	}
	m.running = true
	m.ifName = name
	m.lastError = ""

	m.logger.Info("全局流量已接管，虚拟网卡: ", name)

	// 接管系统 DNS。系统 DNS 通常指向路由器（192.168.x.1），而自动路由会排除
	// 局域网段，DNS 查询不会进入 utun，Fake-IP 与域名分流就无法工作。
	dnsAddr := hijackDNSAddress(prefix)
	if backups, dnsErr := netfix.OverrideDNS(dnsAddr.String()); dnsErr != nil {
		m.dnsBackups = backups
		m.lastError = dnsErr.Error()
		if stopErr := m.stopLocked(); stopErr != nil {
			return fmt.Errorf("DNS 接管失败: %w；清理失败: %v", dnsErr, stopErr)
		}
		return fmt.Errorf("DNS 接管失败，已取消接管: %w", dnsErr)
	} else {
		m.dnsBackups = backups
		m.logger.Info("系统 DNS 已接管 → ", dnsAddr.String())
	}

	return nil
}

// hijackDNSAddress 返回作为 DNS 入口的地址。
//
// 不能与 TUN 接口地址相同（网段首地址）：客户端查询该地址时，
// 源地址由路由决定，也会是网段首地址，写回响应时 FindRoute 的
// local 与 remote 相同，路由自环导致响应发不出去。
// 这里取网段倒数第二个地址，地址池会明确跳过该预留地址。
// param prefix 为合法 IPv4 Fake-IP 网段；返回 DNS 地址，无效网段返回无效地址。
func hijackDNSAddress(prefix netip.Prefix) netip.Addr {
	return fakeip.DNSAddress(prefix)
}

// Stop 停止接管并恢复系统路由。
// param 无；返回 DNS 或资源清理错误，DNS 未恢复时禁止提前拆除网卡。
func (m *Manager) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.stopLocked()
}

// stopLocked 在持有启停锁时恢复 DNS 并拆除 TUN；DNS 恢复失败时保留会话和备份供重试。
// param 无；返回清理错误，错误状态会保存供诊断。
func (m *Manager) stopLocked() error {
	if !m.running {
		return nil
	}

	var errs []string

	// 先恢复 DNS，再拆网卡，避免中间态导致系统无法解析域名
	if len(m.dnsBackups) > 0 {
		if err := m.restoreDNS(m.dnsBackups); err != nil {
			m.lastError = fmt.Sprintf("恢复 DNS 失败，保留 TUN 和备份以便重试: %v", err)
			return fmt.Errorf("%s", m.lastError)
		}
		m.dnsBackups = nil
		m.logger.Info("系统 DNS 已恢复")
	}

	// DNS 已恢复后取消所有活跃流，避免停用后仍有拨号和转发挂起。
	if m.cancel != nil {
		m.cancel()
	}
	if m.stack != nil {
		if err := m.stack.Close(); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if m.device != nil {
		if err := m.device.Close(); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if m.cleanup != nil {
		if err := m.cleanup(); err != nil {
			errs = append(errs, err.Error())
		}
	}

	m.cancel = nil
	m.stack = nil
	m.device = nil
	m.cleanup = nil
	m.running = false
	m.ifName = ""

	if len(errs) > 0 {
		m.lastError = strings.Join(errs, "; ")
		return fmt.Errorf("停止接管时出错: %s", m.lastError)
	}
	m.lastError = ""
	m.logger.Info("已停止接管，系统路由已恢复")
	return nil
}

// friendlyTunError 把底层 errno 翻译成用户能看懂的说明。
// param action/err 为失败操作和底层原因；返回可操作的错误说明。
func friendlyTunError(action string, err error) error {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "operation not permitted"), strings.Contains(msg, "Permission denied"):
		return fmt.Errorf("%s失败：需要 root 权限，请用 sudo 运行，或先执行 sudo tunnelpilot install", action)
	case strings.Contains(msg, "already exists"), strings.Contains(msg, "Device busy"), strings.Contains(msg, "in use"):
		return fmt.Errorf("%s失败：虚拟网卡名称 %s 已被占用，请修改配置中的 tun_name 后重试", action, "")
	case strings.Contains(msg, "no such file"):
		return fmt.Errorf("%s失败：系统未加载 utun 内核模块，请确认系统版本不低于 macOS 13", action)
	default:
		return fmt.Errorf("%s失败: %w", action, err)
	}
}

// detectPhysicalInterface 兜底识别物理网卡。
// param 无；返回启用且有 IPv4 的 en 网卡，无法确认时为空。
func detectPhysicalInterface() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if !strings.HasPrefix(iface.Name, "en") {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if ipNet, ok := addr.(*net.IPNet); ok && ipNet.IP.To4() != nil {
				return iface.Name
			}
		}
	}
	return ""
}
