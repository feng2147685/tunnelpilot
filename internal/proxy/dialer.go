package proxy

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"tunnelpilot/internal/config"
)

var ErrBlocked = errors.New("连接被规则阻断")

// ipBoundIf 是 macOS 的 IP_BOUND_IF（netinet/in.h）。
// 把出站 socket 绑定到物理网卡，避免流量被全局路由重新送回 utun 形成死循环。
const ipBoundIf = 25

// Dialer 根据规则动作建立出站连接，支持直连、单代理与三种代理链。
type Dialer struct {
	rrIndex       uint64
	mu            sync.Mutex
	bindInterface string
	bindIndex     int
}

// New 创建出站服务；param 无；返回尚未设置物理网卡的拨号器，TUN 启动前必须配置网卡。
func New() *Dialer {
	return &Dialer{}
}

// SetBindInterface 设置出站流量绑定的物理网卡（如 en0）。
// TUN 接管全局路由后必须设置，否则出站连接会被路由回 utun，导致 i/o timeout。
// param name 为网卡名，空值清除绑定；返回查找错误，失败不覆盖已有绑定。
func (d *Dialer) SetBindInterface(name string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if name == "" {
		d.bindInterface, d.bindIndex = "", 0
		return nil
	}
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return fmt.Errorf("查找出站网卡失败: %w", err)
	}
	d.bindInterface, d.bindIndex = name, iface.Index
	return nil
}

// currentBindIndex 读取绑定网卡索引；param 无；返回索引，零表示尚未配置。
func (d *Dialer) currentBindIndex() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.bindIndex
}

// newNetDialer 同时隔离出站路由和域名解析，防止重新进入 TUN。
// param 无；返回独立解析并绑定物理网卡的拨号器，连接错误由 DialContext 返回。
func (d *Dialer) newNetDialer() *net.Dialer {
	nd := d.socketDialer()
	nd.Resolver = d.outboundResolver()
	return nd
}

// socketDialer 只负责 socket 绑定，供独立 DNS 解析复用，避免递归创建 resolver。
// param 无；返回底层拨号器，回环目标保留系统回环路由。
func (d *Dialer) socketDialer() *net.Dialer {
	idx := d.currentBindIndex()
	nd := &net.Dialer{Timeout: 10 * time.Second}
	if idx <= 0 {
		return nd
	}
	nd.Control = func(network, address string, c syscall.RawConn) error {
		// 回环地址绝不能绑物理网卡，否则连本地代理会报 can't assign requested address
		host, _, splitErr := net.SplitHostPort(address)
		if splitErr != nil {
			host = address
		}
		if isLoopbackHost(host) {
			return nil
		}
		var ctrlErr error
		if err := c.Control(func(fd uintptr) {
			level, option := unix.IPPROTO_IP, ipBoundIf
			if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
				level, option = unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF
			}
			if err := unix.SetsockoptInt(int(fd), level, option, idx); err != nil {
				ctrlErr = fmt.Errorf("绑定网卡索引 %d 失败: %w", idx, err)
			}
		}); err != nil {
			return err
		}
		return ctrlErr
	}
	return nd
}

// isLoopbackHost 判断目标是否为回环地址（本地代理通常监听在 127.0.0.1）
// param host 为 IP 或本地主机名；返回回环状态，未知域名返回 false。
func isLoopbackHost(host string) bool {
	if host == "" {
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	lower := strings.ToLower(host)
	return lower == "localhost" || strings.HasSuffix(lower, ".localhost")
}

// BoundNetDialer 暴露一个绑定物理网卡的 net.Dialer，供 DNS 查询等场景复用
// param 无；返回带独立 resolver 的拨号器，错误由拨号操作返回。
func (d *Dialer) BoundNetDialer() *net.Dialer {
	return d.newNetDialer()
}

// DialUDP 建立绑定到物理网卡的 UDP 连接
// param ctx/addr 为期限及目标域名或地址；返回 UDP socket，解析或建连失败返回错误。
func (d *Dialer) DialUDP(ctx context.Context, addr string) (*net.UDPConn, error) {
	nd := d.newNetDialer()
	conn, err := nd.DialContext(ctx, "udp", addr)
	if err != nil {
		return nil, err
	}
	udpConn, ok := conn.(*net.UDPConn)
	if !ok {
		conn.Close()
		return nil, errors.New("返回的不是 UDP 连接")
	}
	return udpConn, nil
}

// Dial 按动作建立到 target 的连接。target 可以是域名或 IP:Port。
// param ctx/action/profile/target 为期限、动作、配置和目标；返回连接，代理失效或阻断时返回错误。
func (d *Dialer) Dial(ctx context.Context, action config.RuleAction, profile *config.Profile, target string) (net.Conn, error) {
	switch action.Type {
	case config.ActionBlock:
		return nil, ErrBlocked
	case config.ActionDirect:
		return d.dialDirect(ctx, target)
	case config.ActionProxy:
		server, ok := profile.ServerByID(action.ProxyID)
		if !ok {
			return nil, fmt.Errorf("未找到代理服务器 #%d", action.ProxyID)
		}
		return d.dialViaServer(ctx, server, target)
	case config.ActionChain:
		chain, ok := profile.ChainByID(action.ChainID)
		if !ok {
			return nil, fmt.Errorf("未找到代理链 #%d", action.ChainID)
		}
		return d.dialViaChain(ctx, chain, profile, target)
	default:
		return d.dialDirect(ctx, target)
	}
}

// dialDirect 通过物理网卡及独立 DNS 建立直连。
// param ctx/target 为期限和目标；返回 socket 或解析、网络错误。
func (d *Dialer) dialDirect(ctx context.Context, target string) (net.Conn, error) {
	return d.newNetDialer().DialContext(ctx, "tcp", target)
}

// dialViaServer 建立单代理连接并限制握手耗时。
// param ctx/server/target 为期限、代理和目标；返回完成握手的 socket，失败释放连接。
func (d *Dialer) dialViaServer(ctx context.Context, server config.ProxyServer, target string) (net.Conn, error) {
	conn, err := d.newNetDialer().DialContext(ctx, "tcp", net.JoinHostPort(server.Address, strconv.Itoa(int(server.Port))))
	if err != nil {
		return nil, fmt.Errorf("连接代理 %s:%d 失败: %w", server.Address, server.Port, err)
	}
	finish, err := beginHandshake(ctx, conn)
	if err != nil {
		conn.Close()
		return nil, err
	}
	defer finish()
	if err = handshake(conn, server, target); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

// dialViaChain 按串联、主备或轮询策略建立代理链，禁止跳过失效成员。
// param ctx/chain/profile/target 为会话及链配置；返回末跳连接，成员缺失或握手失败返回错误。
func (d *Dialer) dialViaChain(ctx context.Context, chain config.ProxyChain, profile *config.Profile, target string) (net.Conn, error) {
	servers := make([]config.ProxyServer, 0, len(chain.ProxyIDs))
	for _, id := range chain.ProxyIDs {
		s, ok := profile.ServerByID(id)
		if !ok {
			return nil, fmt.Errorf("代理链引用不存在的服务器 #%d", id)
		}
		servers = append(servers, s)
	}
	if len(servers) == 0 {
		return nil, errors.New("代理链中没有可用服务器")
	}

	switch chain.Type {
	case config.ChainRedundancy:
		var lastErr error
		for _, s := range servers {
			if conn, err := d.dialViaServer(ctx, s, target); err == nil {
				return conn, nil
			} else {
				lastErr = err
			}
		}
		return nil, lastErr

	case config.ChainLoadBalancing:
		start := atomic.AddUint64(&d.rrIndex, 1)
		var lastErr error
		for i := 0; i < len(servers); i++ {
			s := servers[(int(start)+i)%len(servers)]
			if conn, err := d.dialViaServer(ctx, s, target); err == nil {
				return conn, nil
			} else {
				lastErr = err
			}
		}
		return nil, lastErr

	default: // simple: 真多跳串联
		first := servers[0]
		conn, err := d.newNetDialer().DialContext(ctx, "tcp", net.JoinHostPort(first.Address, strconv.Itoa(int(first.Port))))
		if err != nil {
			return nil, err
		}
		finish, err := beginHandshake(ctx, conn)
		if err != nil {
			conn.Close()
			return nil, err
		}
		defer finish()
		// 先在第 0 跳上依次打通后续各跳
		for i := 0; i < len(servers)-1; i++ {
			next := servers[i+1]
			if err = handshake(conn, servers[i], net.JoinHostPort(next.Address, strconv.Itoa(int(next.Port)))); err != nil {
				conn.Close()
				return nil, fmt.Errorf("代理链第 %d 跳握手失败: %w", i+1, err)
			}
		}
		last := servers[len(servers)-1]
		if err = handshake(conn, last, target); err != nil {
			conn.Close()
			return nil, fmt.Errorf("代理链末跳握手失败: %w", err)
		}
		return conn, nil
	}
}

// handshake 在已建立的 TCP 连接上完成代理协议握手
// param conn/server/target 为底层连接、代理配置及目标；返回协议协商错误。
func handshake(conn net.Conn, server config.ProxyServer, target string) error {
	switch server.Protocol {
	case config.ProtocolSOCKS4:
		return socks4Handshake(conn, server, target)
	case config.ProtocolHTTPS:
		return httpsConnectHandshake(conn, server, target)
	default:
		return socks5Handshake(conn, server, target)
	}
}

// splitHostPort 解析代理目标端点。
// param target 为 host:port；返回主机和端口，格式错误返回错误。
func splitHostPort(target string) (string, uint16, error) {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return "", 0, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return "", 0, err
	}
	return host, uint16(port), nil
}

// socks5Handshake 复用认证后发送 SOCKS5 CONNECT，并验证完整响应。
// param conn/server/target 为连接、认证配置和目标；返回认证、协议或 I/O 错误。
func socks5Handshake(conn net.Conn, server config.ProxyServer, target string) error {
	if err := socks5Auth(conn, server); err != nil {
		return err
	}

	host, port, err := splitHostPort(target)
	if err != nil {
		return err
	}
	req := []byte{0x05, 0x01, 0x00}
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			req = append(req, 0x01)
			req = append(req, ip4...)
		} else {
			req = append(req, 0x04)
			req = append(req, ip.To16()...)
		}
	} else {
		// 传域名给远端代理解析（Proxifier 的 Resolve through proxy）
		if len(host) > 255 {
			return errors.New("目标域名过长")
		}
		req = append(req, 0x03, byte(len(host)))
		req = append(req, []byte(host)...)
	}
	req = append(req, byte(port>>8), byte(port&0xFF))
	if _, err = conn.Write(req); err != nil {
		return err
	}

	header := make([]byte, 4)
	if _, err = io.ReadFull(conn, header); err != nil {
		return err
	}
	if header[0] != 0x05 || header[2] != 0x00 {
		return errors.New("SOCKS5 CONNECT 响应头无效")
	}
	if header[1] != 0x00 {
		return fmt.Errorf("SOCKS5 CONNECT 被拒绝，错误码 0x%02x", header[1])
	}
	var skip int
	switch header[3] {
	case 0x01:
		skip = 4 + 2
	case 0x04:
		skip = 16 + 2
	case 0x03:
		lenByte := make([]byte, 1)
		if _, err = io.ReadFull(conn, lenByte); err != nil {
			return err
		}
		skip = int(lenByte[0]) + 2
	default:
		return fmt.Errorf("未知 SOCKS5 地址类型 0x%02x", header[3])
	}
	if _, err = io.ReadFull(conn, make([]byte, skip)); err != nil {
		return err
	}
	return nil
}

// socks4Handshake 发送 SOCKS4 或 SOCKS4a 连接请求。
// param conn/server/target 为连接、用户信息和目标；返回协议或 I/O 错误。
func socks4Handshake(conn net.Conn, server config.ProxyServer, target string) error {
	host, port, err := splitHostPort(target)
	if err != nil {
		return err
	}
	req := []byte{0x04, 0x01, byte(port >> 8), byte(port & 0xFF)}
	ip := net.ParseIP(host)
	if ip4 := ip.To4(); ip4 != nil {
		req = append(req, ip4...)
	} else {
		// SOCKS4a：域名放在 USERID 之后
		req = append(req, 0x00, 0x00, 0x00, 0x01)
	}
	if server.Username != "" {
		req = append(req, []byte(server.Username)...)
	}
	req = append(req, 0x00)
	if ip4 := ip.To4(); ip4 == nil {
		req = append(req, []byte(host)...)
		req = append(req, 0x00)
	}
	if _, err = conn.Write(req); err != nil {
		return err
	}
	reply := make([]byte, 8)
	if _, err = io.ReadFull(conn, reply); err != nil {
		return err
	}
	if reply[1] != 0x5A {
		return fmt.Errorf("SOCKS4 CONNECT 被拒绝，状态码 0x%02x", reply[1])
	}
	return nil
}

// httpsConnectHandshake 发送 HTTP CONNECT，建立承载目标 TCP 的隧道。
// param conn/server/target 为连接、认证配置和目标；返回非成功状态或 I/O 错误。
func httpsConnectHandshake(conn net.Conn, server config.ProxyServer, target string) error {
	var header strings.Builder
	header.WriteString("CONNECT " + target + " HTTP/1.1\r\n")
	header.WriteString("Host: " + target + "\r\n")
	if server.Username != "" {
		cred := base64.StdEncoding.EncodeToString([]byte(server.Username + ":" + server.Password))
		header.WriteString("Proxy-Authorization: Basic " + cred + "\r\n")
	}
	header.WriteString("Proxy-Connection: Keep-Alive\r\n\r\n")
	if _, err := conn.Write([]byte(header.String())); err != nil {
		return err
	}

	var resp []byte
	buf := make([]byte, 1)
	for len(resp) < 8192 {
		if _, err := io.ReadFull(conn, buf); err != nil {
			return err
		}
		resp = append(resp, buf[0])
		if len(resp) >= 4 &&
			resp[len(resp)-4] == '\r' && resp[len(resp)-3] == '\n' &&
			resp[len(resp)-2] == '\r' && resp[len(resp)-1] == '\n' {
			break
		}
	}
	line := string(resp)
	if idx := strings.Index(line, "\r\n"); idx > 0 {
		line = line[:idx]
	}
	if !strings.Contains(line, " 200 ") {
		return fmt.Errorf("HTTPS CONNECT 失败: %s", line)
	}
	return nil
}
