package tunmgr

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/control"

	"tunnelpilot/internal/config"
	"tunnelpilot/internal/logx"
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

	stack     tun.Stack
	device    tun.Tun
	cleanup   func()
	running   bool
	ifName    string
	lastError string
}

func New(profileFn func() *config.Profile, handler *tunengine.Handler, dialer *proxy.Dialer, logger *logx.Logger) *Manager {
	return &Manager{
		profile: profileFn,
		handler: handler,
		dialer:  dialer,
		logger:  logger,
	}
}

func (m *Manager) Running() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.running
}

func (m *Manager) InterfaceName() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.ifName
}

func (m *Manager) LastError() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastError
}

// Start 创建 utun 并接管全局流量
func (m *Manager) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.running {
		return nil
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
		networkMonitor.Close()
		return fmt.Errorf("启动网络变化监听失败: %w", err)
	}
	interfaceMonitor, err := tun.NewDefaultInterfaceMonitor(networkMonitor, m.logger, tun.DefaultInterfaceMonitorOptions{
		InterfaceFinder: interfaceFinder,
	})
	if err != nil {
		networkMonitor.Close()
		return fmt.Errorf("创建默认网卡监听失败: %w", err)
	}
	if err = interfaceMonitor.Start(); err != nil {
		networkMonitor.Close()
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
		m.dialer.SetBindInterface(ifName)
		m.logger.Info("出站流量已绑定物理网卡: ", ifName)
	} else {
		m.logger.Warn("未能识别物理网卡，直连可能因路由环路超时")
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
		interfaceMonitor.Close()
		networkMonitor.Close()
		m.lastError = err.Error()
		return friendlyTunError("创建虚拟网卡", err)
	}
	if err = device.Start(); err != nil {
		device.Close()
		interfaceMonitor.Close()
		networkMonitor.Close()
		m.lastError = err.Error()
		return friendlyTunError("启动虚拟网卡", err)
	}

	ctx := context.Background()
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
		device.Close()
		interfaceMonitor.Close()
		networkMonitor.Close()
		m.lastError = err.Error()
		return fmt.Errorf("创建网络栈失败: %w", err)
	}
	if err = stack.Start(); err != nil {
		device.Close()
		interfaceMonitor.Close()
		networkMonitor.Close()
		m.lastError = err.Error()
		return fmt.Errorf("启动网络栈失败: %w", err)
	}

	name, _ := device.Name()
	m.stack = stack
	m.device = device
	m.cleanup = func() {
		_ = interfaceMonitor.Close()
		_ = networkMonitor.Close()
	}
	m.running = true
	m.ifName = name
	m.lastError = ""

	m.logger.Info("全局流量已接管，虚拟网卡: ", name)
	return nil
}

// Stop 停止接管并恢复系统路由
func (m *Manager) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.running {
		return nil
	}

	var errs []string
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
		m.cleanup()
	}

	m.stack = nil
	m.device = nil
	m.cleanup = nil
	m.running = false
	m.ifName = ""

	if len(errs) > 0 {
		m.lastError = strings.Join(errs, "; ")
		return fmt.Errorf("停止接管时出错: %s", m.lastError)
	}
	m.logger.Info("已停止接管，系统路由已恢复")
	return nil
}

// friendlyTunError 把底层 errno 翻译成用户能看懂的说明
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

// detectPhysicalInterface 兜底识别物理网卡
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
