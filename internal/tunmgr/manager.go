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

	stack         tun.Stack
	device        tun.Tun
	cleanup       func() error
	cancel        context.CancelFunc
	restoreDNS    func([]netfix.DNSBackup) error
	overrideDNS   func(string) ([]netfix.DNSBackup, error)
	routes        *routeSet
	options       tun.Options
	compatibility bool
	running       bool
	ifName        string
	lastError     string
	dnsBackups    []netfix.DNSBackup
}

// New 组装 TUN 生命周期管理，依赖配置快照、转发器、拨号器及日志。
// param profileFn/handler/dialer/logger 为所需服务；返回管理器，此时不修改网络。
func New(profileFn func() *config.Profile, handler *tunengine.Handler, dialer *proxy.Dialer, logger *logx.Logger) *Manager {
	return &Manager{
		profile:     profileFn,
		handler:     handler,
		dialer:      dialer,
		logger:      logger,
		restoreDNS:  netfix.RestoreDNS,
		overrideDNS: netfix.OverrideDNS,
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

	if m.compatibility {
		return m.resumeLocked()
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
	routes, err := newRouteSet(options)
	if err == nil {
		// sing-tun v0.9.6 的 UpdateRouteOptions 先覆盖旧参数再删路由，不能用于切换范围。
		// 仅关闭库的自动清理，原路由范围由本实例精确跟踪；不调用库的范围切换。
		external := options
		external.EXP_ExternalConfiguration = true
		err = device.UpdateRouteOptions(external)
	}
	if err != nil {
		cancel()
		closeOnFailure("协议栈", stack.Close)
		closeOnFailure("虚拟网卡", device.Close)
		closeOnFailure("默认网卡监听", interfaceMonitor.Close)
		closeOnFailure("网络变化监听", networkMonitor.Close)
		return fmt.Errorf("初始化路由生命周期失败: %w", err)
	}
	m.routes, m.options = routes, options
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
	if backups, dnsErr := m.overrideDNS(dnsAddr.String()); dnsErr != nil {
		m.dnsBackups = backups
		m.lastError = dnsErr.Error()
		if stopErr := m.shutdownLocked(); stopErr != nil {
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
// param 无；返回 DNS 或路由切换错误，成功后保留专用网段处理应用缓存的假地址。
func (m *Manager) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.running {
		return nil
	}
	if m.routes == nil {
		return m.shutdownLocked()
	}
	if len(m.dnsBackups) > 0 {
		if err := m.restoreDNS(m.dnsBackups); err != nil {
			m.lastError = err.Error()
			return err
		}
		m.dnsBackups = nil
	}
	// 已有映射不能随网卡消失。后续命中假地址的连接只直连，不再应用代理/阻断规则。
	m.handler.SetBypass(true)
	if err := m.routes.pause(); err != nil {
		m.handler.SetBypass(false)
		m.lastError = err.Error()
		return err
	}
	m.running = false
	m.compatibility = true
	m.lastError = ""
	m.logger.Info("已停止全局接管，系统 DNS 已恢复；保留 Fake-IP 缓存直连兼容")
	return nil
}

// shutdownLocked 在持锁状态下彻底释放网卡与兼容路由，仅用于退出或启动回滚。
// param 无；返回清理错误，错误状态会保存供诊断。
func (m *Manager) shutdownLocked() error {
	if m.device == nil && !m.running {
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
	if m.routes != nil {
		if err := m.routes.close(); err != nil {
			errs = append(errs, err.Error())
		}
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
	m.compatibility = false
	if m.handler != nil {
		m.handler.SetBypass(false)
	}
	m.routes = nil
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

// Compatibility 查询是否仅为应用缓存的 Fake-IP 保留直连通道。
// param 无；返回兼容状态，此时系统 DNS 与全局路由均不再接管。
func (m *Manager) Compatibility() bool { m.mu.Lock(); defer m.mu.Unlock(); return m.compatibility }

// Close 供守护进程退出时彻底释放资源；普通停止应使用 Stop 保留缓存兼容。
// param 无；返回 DNS 或清理错误，DNS 恢复失败时保留网卡及备份。
func (m *Manager) Close() error { m.mu.Lock(); defer m.mu.Unlock(); return m.shutdownLocked() }

// resumeLocked 从缓存兼容状态恢复全局路由及 DNS，复用同一映射表和网络栈。
// param 无；返回恢复错误，失败退回缓存直连模式，保留所有必要的恢复信息。
func (m *Manager) resumeLocked() error {
	if len(m.dnsBackups) > 0 {
		return fmt.Errorf("DNS 回滚尚未完成，请先退出并恢复网络")
	}
	if err := m.routes.resume(); err != nil {
		rollback := m.routes.pause()
		return errors.Join(err, rollback)
	}
	m.handler.SetBypass(false)
	backups, err := m.overrideDNS(hijackDNSAddress(m.options.Inet4Address[0]).String())
	m.dnsBackups = backups
	if err != nil {
		m.handler.SetBypass(true)
		return errors.Join(err, m.routes.pause())
	}
	m.compatibility = false
	m.running = true
	m.lastError = ""
	return nil
}
