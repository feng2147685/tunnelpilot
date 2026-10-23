package tunengine

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"tunnelpilot/internal/config"
	"tunnelpilot/internal/fakeip"
	"tunnelpilot/internal/proc"
	"tunnelpilot/internal/proxy"
	"tunnelpilot/internal/rule"
)

// Record 是一条连接的实时状态，供 Web 界面展示
type Record struct {
	ID          uint64    `json:"id"`
	Network     string    `json:"network"`
	Process     string    `json:"process"`
	PID         int32     `json:"pid"`
	ProcessPath string    `json:"process_path"`
	Source      string    `json:"source"`
	Target      string    `json:"target"`
	RealDomain  string    `json:"real_domain,omitempty"`
	Port        uint16    `json:"port"`
	Rule        string    `json:"rule"`
	Action      string    `json:"action"`
	Status      string    `json:"status"`
	BytesSent   uint64    `json:"bytes_sent"`
	BytesRecv   uint64    `json:"bytes_recv"`
	StartedAt   time.Time `json:"started_at"`
	LatencyMs   int64     `json:"latency_ms"`
}

// Handler 实现 sing-tun 的 tun.Handler，是整条转发链路的决策中枢。
type Handler struct {
	mu       sync.RWMutex
	resolver *proc.Resolver
	rules    *rule.Engine
	dialer   *proxy.Dialer
	fakeip   *fakeip.Pool
	onLog    func(string)

	records map[uint64]*Record
	nextID  uint64
}

// NewHandler 组装进程识别、规则、出站与 Fake-IP 服务，供 TUN 栈调用。
// param resolver/rules/dialer/pool 为核心依赖，onLog 为脱敏日志回调；返回处理器，不修改系统网络。
func NewHandler(resolver *proc.Resolver, rules *rule.Engine, dialer *proxy.Dialer, pool *fakeip.Pool, onLog func(string)) *Handler {
	return &Handler{
		resolver: resolver,
		rules:    rules,
		dialer:   dialer,
		fakeip:   pool,
		onLog:    onLog,
		records:  make(map[uint64]*Record),
	}
}

// log 将业务日志交给外部回调。
// param format/args 为已去除隐私的日志内容；无返回值，未配置回调时不输出。
func (h *Handler) log(format string, args ...any) {
	if h.onLog != nil {
		h.onLog(fmt.Sprintf(format, args...))
	}
}

// Snapshot 返回连接记录副本供控制台读取。
// param limit 为最大条数，非正数表示不限；返回按开始时间倒序的快照。
func (h *Handler) Snapshot(limit int) []Record {
	h.mu.RLock()
	out := make([]Record, 0, len(h.records))
	for _, r := range h.records {
		out = append(out, *r)
	}
	h.mu.RUnlock()

	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j].StartedAt.After(out[j-1].StartedAt); j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

// newRecord 为新流创建监控记录。
// param network/source/destination 为协议及端点；返回记录，后续写入必须通过 update。
func (h *Handler) newRecord(network string, source, destination M.Socksaddr) *Record {
	h.mu.Lock()
	defer h.mu.Unlock()
	r := &Record{
		ID:        h.nextID,
		Network:   network,
		Source:    source.String(),
		Target:    destination.AddrString(),
		Port:      destination.Port,
		Status:    "connecting",
		StartedAt: time.Now(),
	}
	h.nextID++
	h.records[r.ID] = r
	return r
}

// update 在锁内修改会话记录。
// param id 为会话编号，fn 为修改回调；无返回值，记录已删除时不处理。
func (h *Handler) update(id uint64, fn func(*Record)) {
	h.mu.Lock()
	if r, ok := h.records[id]; ok {
		fn(r)
	}
	h.mu.Unlock()
}

// drop 清除结束会话的实时记录。
// param id 为会话编号；无返回值，重复清理无副作用。
func (h *Handler) drop(id uint64) {
	h.mu.Lock()
	delete(h.records, id)
	h.mu.Unlock()
}

// addTraffic 累加成功转发的字节数。
// param id 为会话编号，sent/recv 为本次收发量；无返回值，忽略已结束记录。
func (h *Handler) addTraffic(id uint64, sent, recv uint64) {
	h.mu.Lock()
	if r, ok := h.records[id]; ok {
		r.BytesSent += sent
		r.BytesRecv += recv
	}
	h.mu.Unlock()
}

// decision 保存单个会话的路由结果，依赖规则动作与进程身份，不直接修改系统状态。
type decision struct {
	target  string
	action  config.RuleAction
	rule    string
	domain  string
	ident   proc.Identity
	blocked bool
}

// decide 根据实际进程、原始域名、真实地址和端口选择路由。
// param flowCtx 控制解析期限，isUDP/source/destination/port 为流属性；返回决策，未知 Fake-IP 或必要解析失败时阻断。
func (h *Handler) decide(flowCtx context.Context, isUDP bool, source, destination M.Socksaddr, port uint16) decision {
	ident := h.resolver.Lookup(source.Port, isUDP)

	domain := ""
	if destination.IsIP() && h.fakeip.Has(destination.Addr) {
		var ok bool
		domain, ok = h.fakeip.Lookup(destination.Addr)
		if !ok {
			// 旧 DNS 缓存或未知 Fake-IP 不能当作真实公网地址拨出。
			return decision{ident: ident, blocked: true, action: config.RuleAction{Type: config.ActionBlock}}
		}
	}

	ctx := rule.Context{
		ProcessName: ident.Name,
		ProcessPath: ident.Path,
		Host:        domain,
		IP:          destination.Addr,
		Port:        port,
		IsUDP:       isUDP,
	}
	if ctx.Host == "" && !destination.IsIP() {
		ctx.Host = destination.Fqdn
	}

	var lookup func() ([]netip.Addr, error)
	if domain != "" {
		ctx.IP = netip.Addr{}
		lookup = func() ([]netip.Addr, error) {
			resolveCtx, cancel := context.WithTimeout(flowCtx, 8*time.Second)
			defer cancel()
			return h.dialer.ResolveIPv4(resolveCtx, domain)
		}
	}
	m, err := h.rules.EvaluateWithIPLookup(ctx, lookup)
	if err != nil {
		h.log("规则所需的真实地址解析失败: %s", networkFailure(err))
		return decision{ident: ident, blocked: true, action: config.RuleAction{Type: config.ActionBlock}}
	}

	targetHost := domain
	if targetHost == "" {
		if destination.IsIP() {
			targetHost = destination.AddrString()
		} else {
			targetHost = destination.Fqdn
		}
	}

	return decision{
		target:  net.JoinHostPort(targetHost, fmt.Sprint(port)),
		action:  m.Action,
		rule:    m.Rule.Name,
		domain:  domain,
		ident:   ident,
		blocked: m.Found && m.Action.Type == config.ActionBlock,
	}
}

// describeAction 为控制台生成动作说明。
// param a/profile 为动作及配置；返回展示文本，引用失效时显示对应编号。
func (h *Handler) describeAction(a config.RuleAction, profile *config.Profile) string {
	switch a.Type {
	case config.ActionDirect:
		return "直连"
	case config.ActionBlock:
		return "阻断"
	case config.ActionProxy:
		if s, ok := profile.ServerByID(a.ProxyID); ok {
			return fmt.Sprintf("代理 %s:%d (%s)", s.Address, s.Port, s.Protocol)
		}
		return fmt.Sprintf("代理 #%d", a.ProxyID)
	case config.ActionChain:
		if c, ok := profile.ChainByID(a.ChainID); ok {
			return fmt.Sprintf("代理链 %s", c.Name)
		}
		return fmt.Sprintf("代理链 #%d", a.ChainID)
	}
	return a.Type
}

// udpProtocolNumber 是 IP 协议号里的 UDP（RFC 1700）。
const udpProtocolNumber = 17

// makeDNSBuffer 把 DNS 响应报文包成 sing 的 buffer。
// 每次写回都要新的一份，因为 WritePacket 内部会 Release 传入的 buffer。
// param data 为待写字节；返回独立拥有数据的 buffer，无失败分支。
func makeDNSBuffer(data []byte) *buf.Buffer {
	return buf.As(append([]byte(nil), data...))
}

// JudgeFlow 决定一条新流的处置方式。
// 只有在这里返回 ActionHijackDNS，sing-tun 才会把 DNS 报文交给 NewDNSPacket；
// param network/source/destination/firstPacket 为栈提供的首包属性；返回 DNS 劫持或普通流处置。
func (h *Handler) JudgeFlow(network uint8, source netip.AddrPort, destination netip.AddrPort, firstPacket []byte) tun.FlowVerdict {
	if network == udpProtocolNumber && destination.Port() == 53 {
		return tun.FlowVerdict{Action: tun.ActionHijackDNS}
	}
	return tun.FlowVerdict{Action: tun.ActionAccept}
}

// NewConnectionEx 接收 TUN TCP 会话并异步转发。
// param ctx/conn/source/destination 为流上下文，onClose 为栈清理回调；无返回值，转发结束释放记录与连接。
func (h *Handler) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	rec := h.newRecord("tcp", source, destination)
	go func() {
		defer func() {
			h.drop(rec.ID)
			if onClose != nil {
				onClose(nil)
			}
		}()
		h.handleTCP(ctx, conn, rec, source, destination)
	}()
}

// NewPacketConnectionEx 接收 TUN UDP 会话并异步转发。
// param ctx/conn/source/destination 为流上下文，onClose 为栈清理回调；无返回值，失败或结束时清理记录。
func (h *Handler) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	rec := h.newRecord("udp", source, destination)
	go func() {
		defer func() {
			h.drop(rec.ID)
			if onClose != nil {
				onClose(nil)
			}
		}()
		h.handleUDP(ctx, conn, rec, source, destination)
	}()
}

// handleTCP 完成 TCP 决策、出站连接及双向转发，DNS 交给独立解析处理。
// param ctx/conn/rec/source/destination 为会话依赖；无返回值，错误记入脱敏日志并关闭连接。
func (h *Handler) handleTCP(ctx context.Context, conn net.Conn, rec *Record, source, destination M.Socksaddr) {
	defer conn.Close()
	if destination.Port == 53 {
		h.handleDNSStream(ctx, conn)
		return
	}
	d := h.decide(ctx, false, source, destination, destination.Port)
	profile := h.rules.Profile()

	h.update(rec.ID, func(r *Record) {
		r.Process = d.ident.Name
		r.PID = d.ident.PID
		r.ProcessPath = d.ident.Path
		r.RealDomain = d.domain
		r.Rule = withDefault(d.rule, "Default")
		r.Action = h.describeAction(d.action, profile)
	})

	if d.blocked {
		h.update(rec.ID, func(r *Record) { r.Status = "blocked" })
		conn.Close()
		h.log("TCP 会话 #%d 已阻断", rec.ID)
		return
	}

	start := time.Now()
	remote, err := h.dialer.Dial(ctx, d.action, profile, d.target)
	if err != nil {
		h.update(rec.ID, func(r *Record) { r.Status = "failed" })
		conn.Close()
		h.log("TCP 会话 #%d 拨号失败: %s", rec.ID, networkFailure(err))
		return
	}
	defer remote.Close()
	defer conn.Close()

	latency := time.Since(start).Milliseconds()
	h.update(rec.ID, func(r *Record) {
		r.Status = "active"
		r.LatencyMs = latency
	})

	stop := context.AfterFunc(ctx, func() {
		conn.Close()
		remote.Close()
	})
	defer stop()
	var wg sync.WaitGroup
	wg.Add(2)
	copyOneWay := func(dst, src net.Conn, sent bool) {
		defer wg.Done()
		n, err := io.Copy(dst, src)
		if sent {
			h.addTraffic(rec.ID, uint64(n), 0)
		} else {
			h.addTraffic(rec.ID, 0, uint64(n))
		}
		if err != nil {
			if !errors.Is(err, net.ErrClosed) && ctx.Err() == nil {
				h.log("TCP 会话 #%d 转发失败: %s", rec.ID, networkFailure(err))
			}
			conn.Close()
			remote.Close()
			return
		}
		// 一侧发完后传递 FIN，让等待 EOF 的服务能够开始响应。
		if half, ok := dst.(interface{ CloseWrite() error }); ok {
			if err := half.CloseWrite(); err != nil {
				conn.Close()
				remote.Close()
			}
		} else {
			dst.Close()
		}
	}
	go copyOneWay(remote, conn, true)
	go copyOneWay(conn, remote, false)
	wg.Wait()
	h.update(rec.ID, func(r *Record) { r.Status = "closed" })
}

// handleUDP 按已匹配动作转发 UDP；代理不可用时终止该流，避免意外直连。
// param ctx 控制生命周期，conn 是 TUN 会话，rec 是监控记录，source/destination 是原始端点；失败会记录并关闭会话。
func (h *Handler) handleUDP(ctx context.Context, conn N.PacketConn, rec *Record, source, destination M.Socksaddr) {
	defer conn.Close()
	d := h.decide(ctx, true, source, destination, destination.Port)
	profile := h.rules.Profile()
	h.update(rec.ID, func(r *Record) {
		r.Process, r.PID, r.ProcessPath = d.ident.Name, d.ident.PID, d.ident.Path
		r.RealDomain, r.Rule = d.domain, withDefault(d.rule, "Default")
		r.Action = h.describeAction(d.action, profile)
	})
	if d.blocked {
		h.update(rec.ID, func(r *Record) { r.Status = "blocked" })
		return
	}

	switch d.action.Type {
	case config.ActionDirect:
		h.relayUDPDirect(ctx, conn, rec, destination, d.target)
	case config.ActionProxy:
		server, ok := profile.ServerByID(d.action.ProxyID)
		if !ok || !proxy.SupportsUDP(server) {
			h.udpFailure(rec.ID, fmt.Errorf("所选代理不存在或不支持 UDP"))
			return
		}
		h.relayUDPViaProxy(ctx, conn, rec, destination, d, server)
	default:
		h.udpFailure(rec.ID, fmt.Errorf("当前动作不支持 UDP 转发"))
	}
}

// udpFailure 统一记录 UDP 建连和转发错误，不输出目标域名或带隐私的底层错误文本。
// param id 为监控编号，err 为失败原因；无返回值，失败状态同步给监控记录。
func (h *Handler) udpFailure(id uint64, err error) {
	h.update(id, func(r *Record) { r.Status = "failed" })
	h.log("UDP 会话 #%d 失败: %s", id, networkFailure(err))
}

// relayUDPViaProxy 通过 SOCKS5 中继转发 UDP，并保留原始目标作为回包源。
// param ctx 控制生命周期，conn/rec 为入站会话，destination 是原始目标，d/server 是路由决策；失败终止会话。
func (h *Handler) relayUDPViaProxy(ctx context.Context, conn N.PacketConn, rec *Record, destination M.Socksaddr, d decision, server config.ProxyServer) {
	relay, err := h.dialer.AssociateUDP(ctx, server)
	if err != nil {
		h.udpFailure(rec.ID, err)
		return
	}
	defer relay.Close()
	host, _, err := net.SplitHostPort(d.target)
	if err != nil {
		h.udpFailure(rec.ID, err)
		return
	}
	h.relayUDPSession(ctx, conn, rec, destination,
		func(payload []byte) error { return relay.Send(host, destination.Port, payload) },
		relay.ReadPayload, relay.SetDeadline, relay.Close)
}

// relayUDPDirect 将 Fake-IP 还原出的域名交给独立 resolver，禁止把假地址拨回 TUN。
// param ctx/conn/rec 为会话上下文，destination 为回包源，target 为真实拨号目标；建连失败记入监控。
func (h *Handler) relayUDPDirect(ctx context.Context, conn N.PacketConn, rec *Record, destination M.Socksaddr, target string) {
	remote, err := h.dialer.DialUDP(ctx, target)
	if err != nil {
		h.udpFailure(rec.ID, err)
		return
	}
	defer remote.Close()
	h.relayUDPSession(ctx, conn, rec, destination,
		func(payload []byte) error {
			_, err := remote.Write(payload)
			return err
		}, remote.Read, remote.SetReadDeadline, remote.Close)
}

// relayUDPSession 维护双向 UDP 收发；任一方向结束或取消时同时关闭两端，避免挂起。
// param ctx/conn/rec 为会话，destination 为响应源，其余参数适配直连或中继的收发与清理；无返回值，异常记入日志。
func (h *Handler) relayUDPSession(ctx context.Context, conn N.PacketConn, rec *Record, destination M.Socksaddr, send func([]byte) error, receive func([]byte) (int, error), deadline func(time.Time) error, closeRemote func() error) {
	closeBoth := func() {
		conn.Close()
		closeRemote()
	}
	stop := context.AfterFunc(ctx, closeBoth)
	defer stop()
	defer closeBoth()
	h.update(rec.ID, func(r *Record) { r.Status = "active" })
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer closeBoth()
		buffer := make([]byte, 64*1024)
		for {
			if err := deadline(time.Now().Add(2 * time.Minute)); err != nil {
				h.udpFailure(rec.ID, err)
				return
			}
			n, err := receive(buffer)
			if err != nil {
				return
			}
			// WritePacket 接管并释放 buffer，每个回包都必须分配独立实例。
			if err := conn.WritePacket(makeDNSBuffer(buffer[:n]), destination); err != nil {
				h.udpFailure(rec.ID, err)
				return
			}
			h.addTraffic(rec.ID, 0, uint64(n))
		}
	}()
	defer func() {
		closeBoth()
		<-done
	}()
	for {
		packet := buf.NewPacket()
		if _, err := conn.ReadPacket(packet); err != nil {
			packet.Release()
			return
		}
		n := packet.Len()
		err := send(packet.Bytes())
		packet.Release()
		if err != nil {
			h.udpFailure(rec.ID, err)
			return
		}
		h.addTraffic(rec.ID, uint64(n), 0)
	}
}

// withDefault 为监控文字提供默认值。
// param s/fallback 为原值和兜底文字；返回非空原值或兜底，无失败分支。
func withDefault(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}
