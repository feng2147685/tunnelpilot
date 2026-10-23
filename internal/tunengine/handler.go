package tunengine

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
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

func (h *Handler) log(format string, args ...any) {
	if h.onLog != nil {
		h.onLog(fmt.Sprintf(format, args...))
	}
}

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

func (h *Handler) update(id uint64, fn func(*Record)) {
	h.mu.Lock()
	if r, ok := h.records[id]; ok {
		fn(r)
	}
	h.mu.Unlock()
}

func (h *Handler) drop(id uint64) {
	h.mu.Lock()
	delete(h.records, id)
	h.mu.Unlock()
}

func (h *Handler) addTraffic(id uint64, sent, recv uint64) {
	h.mu.Lock()
	if r, ok := h.records[id]; ok {
		r.BytesSent += sent
		r.BytesRecv += recv
	}
	h.mu.Unlock()
}

type decision struct {
	target  string
	action  config.RuleAction
	rule    string
	domain  string
	ident   proc.Identity
	blocked bool
}

func (h *Handler) decide(isUDP bool, source, destination M.Socksaddr, port uint16) decision {
	ident := h.resolver.Lookup(source.Port, isUDP)

	domain := ""
	if destination.IsIP() && h.fakeip.Has(destination.Addr) {
		if d, ok := h.fakeip.Lookup(destination.Addr); ok {
			domain = d
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

	m := h.rules.Evaluate(ctx)

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
func makeDNSBuffer(data []byte) *buf.Buffer {
	b := buf.NewSize(len(data))
	b.Write(data)
	return b
}

// JudgeFlow 决定一条新流的处置方式。
// 只有在这里返回 ActionHijackDNS，sing-tun 才会把 DNS 报文交给 NewDNSPacket；
// 之前这里无条件返回 ActionAccept，导致 DNS 劫持（以及整个 Fake-IP 分流）从未生效。
func (h *Handler) JudgeFlow(network uint8, source netip.AddrPort, destination netip.AddrPort, firstPacket []byte) tun.FlowVerdict {
	if network == udpProtocolNumber && destination.Port() == 53 {
		return tun.FlowVerdict{Action: tun.ActionHijackDNS}
	}
	return tun.FlowVerdict{Action: tun.ActionAccept}
}

// NewDNSPacket 处理被劫持的 DNS 查询：
//   - 命中 Block 规则  -> 返回 NXDOMAIN
//   - 命中 Direct 规则 -> 本地解析后返回真实 A 记录
//   - 命中代理规则     -> 分配 Fake-IP，域名交由远端代理解析
func (h *Handler) NewDNSPacket(payload []byte, source M.Socksaddr, destination M.Socksaddr, writer N.PacketWriter) {
	msg := new(dns.Msg)
	if err := msg.Unpack(payload); err != nil || len(msg.Question) == 0 {
		return
	}
	question := msg.Question[0]
	name := dns.Fqdn(question.Name)
	// DNS 报文里的域名是 FQDN，带末尾点（www.google.com.），
	// 而规则里的通配符不带点，不裁掉的话 *.google.com 永远匹配不上。
	domain := strings.TrimSuffix(name, ".")
	profile := h.rules.Profile()

	ident := h.resolver.Lookup(source.Port, true)
	m := h.rules.Evaluate(rule.Context{
		ProcessName: ident.Name,
		ProcessPath: ident.Path,
		Host:        domain,
	})

	resp := new(dns.Msg)
	resp.SetReply(msg)
	resp.Authoritative = true

	switch {
	case m.Found && m.Action.Type == config.ActionBlock:
		resp.Rcode = dns.RcodeNameError

	case m.Found && m.Action.Type == config.ActionDirect:
		ips := h.resolveDirect(domain)
		if len(ips) == 0 {
			resp.Rcode = dns.RcodeNameError
		} else {
			for _, ip := range ips {
				resp.Answer = append(resp.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
					A:   ip,
				})
			}
		}

	default:
		if ip, ok := h.fakeip.Allocate(domain); ok {
			resp.Answer = append(resp.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   ip.AsSlice(),
			})
		} else {
			resp.Rcode = dns.RcodeServerFailure
		}
	}

	data, err := resp.Pack()
	if err != nil {
		return
	}

	// UDPBackWriter 内部把 WritePacket 的参数当作「响应包的源地址」来查路由：
	//   FindRoute(nic, AddressFromAddr(destination.Addr), w.source, ...)
	// 而 w.source 存的正是客户端地址，若这里也传 source，local 与 remote 相同，
	// 路由自环导致响应发不出去（表现为客户端反复重试、解析超时）。
	// 因此优先传 destination（DNS 入口地址），失败再回退到 source。
	werr := writer.WritePacket(makeDNSBuffer(data), destination)
	if werr != nil {
		h.log("DNS 响应写回失败(%s)，改用 source 重试: %v", domain, werr)
		werr = writer.WritePacket(makeDNSBuffer(data), source)
	}
	if werr != nil {
		h.log("DNS 响应写回彻底失败 %s: %v", domain, werr)
		return
	}

	h.log("DNS %s (来自 %s) -> %s，动作: %s", domain, ident.Name, answerSummary(resp), h.describeAction(m.Action, profile))
}

// 直连 DNS 服务器。不能走系统 resolver，否则查询会被引回 utun 造成递归。
var directDNSServers = []string{"223.5.5.5:53", "119.29.29.29:53"}

// resolveDirect 用绑定物理网卡的连接直接向公共 DNS 查询真实 IP
func (h *Handler) resolveDirect(domain string) []net.IP {
	query := new(dns.Msg)
	query.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	client := &dns.Client{
		Net:     "udp",
		Dialer:  h.dialer.BoundNetDialer(),
		Timeout: 3 * time.Second,
	}
	for _, srv := range directDNSServers {
		resp, _, err := client.Exchange(query, srv)
		if err != nil {
			continue
		}
		var ips []net.IP
		for _, rr := range resp.Answer {
			if a, ok := rr.(*dns.A); ok {
				ips = append(ips, a.A)
			}
		}
		if len(ips) > 0 {
			return ips
		}
	}
	return nil
}

func answerSummary(resp *dns.Msg) string {
	if resp.Rcode == dns.RcodeNameError {
		return "NXDOMAIN"
	}
	for _, rr := range resp.Answer {
		if a, ok := rr.(*dns.A); ok {
			return a.A.String()
		}
	}
	return "无结果"
}

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

func (h *Handler) handleTCP(ctx context.Context, conn net.Conn, rec *Record, source, destination M.Socksaddr) {
	d := h.decide(false, source, destination, destination.Port)
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
		h.log("TCP 阻断 %s (%s) -> %s", d.ident.Name, d.domain, d.target)
		return
	}

	start := time.Now()
	remote, err := h.dialer.Dial(ctx, d.action, profile, d.target)
	if err != nil {
		h.update(rec.ID, func(r *Record) { r.Status = "failed" })
		conn.Close()
		h.log("TCP %s -> %s 失败: %v", d.ident.Name, d.target, err)
		return
	}
	defer remote.Close()
	defer conn.Close()

	latency := time.Since(start).Milliseconds()
	h.update(rec.ID, func(r *Record) {
		r.Status = "active"
		r.LatencyMs = latency
	})

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		n := relay(conn, remote)
		h.addTraffic(rec.ID, n, 0)
	}()
	go func() {
		defer wg.Done()
		n := relay(remote, conn)
		h.addTraffic(rec.ID, 0, n)
	}()
	wg.Wait()
	h.update(rec.ID, func(r *Record) { r.Status = "closed" })
}

func (h *Handler) handleUDP(ctx context.Context, conn N.PacketConn, rec *Record, source, destination M.Socksaddr) {
	d := h.decide(true, source, destination, destination.Port)
	profile := h.rules.Profile()

	h.update(rec.ID, func(r *Record) {
		r.Process = d.ident.Name
		r.PID = d.ident.PID
		r.RealDomain = d.domain
		r.Rule = withDefault(d.rule, "Default")
		r.Action = h.describeAction(d.action, profile)
		r.Status = "active"
	})

	if d.blocked {
		h.update(rec.ID, func(r *Record) { r.Status = "blocked" })
		return
	}

	// 优先走 SOCKS5 UDP 中继；HTTPS / SOCKS4 无法承载 UDP，回退直连
	if d.action.Type == config.ActionProxy {
		if server, ok := profile.ServerByID(d.action.ProxyID); ok && proxy.SupportsUDP(server) {
			if h.relayUDPViaProxy(ctx, conn, rec, source, destination, d, server) {
				return
			}
		}
	}

	h.relayUDPDirect(ctx, conn, rec, source, destination)
}

// relayUDPViaProxy 通过 SOCKS5 UDP ASSOCIATE 转发，返回 true 表示已接管该流
func (h *Handler) relayUDPViaProxy(ctx context.Context, conn N.PacketConn, rec *Record, source, destination M.Socksaddr, d decision, server config.ProxyServer) bool {
	relay, err := h.dialer.AssociateUDP(ctx, server)
	if err != nil {
		h.log("UDP 中继建立失败，回退直连: %v", err)
		return false
	}
	defer relay.Close()

	targetHost := d.domain
	if targetHost == "" {
		targetHost = destination.AddrString()
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		buffer := make([]byte, 64*1024)
		for {
			relay.SetDeadline(time.Now().Add(2 * time.Minute))
			n, err := relay.ReadPayload(buffer)
			if err != nil {
				return
			}
			pkt := buf.NewSize(n)
			pkt.Write(buffer[:n])
			if err := conn.WritePacket(pkt, source); err != nil {
				return
			}
			h.addTraffic(rec.ID, 0, uint64(n))
		}
	}()

	for {
		pkt := buf.NewPacket()
		if _, err := conn.ReadPacket(pkt); err != nil {
			pkt.Release()
			<-done
			return true
		}
		n := pkt.Len()
		if err := relay.Send(targetHost, destination.Port, pkt.Bytes()); err != nil {
			pkt.Release()
			<-done
			return true
		}
		h.addTraffic(rec.ID, uint64(n), 0)
		pkt.Release()
	}
}

// relayUDPDirect 直连转发 UDP
func (h *Handler) relayUDPDirect(ctx context.Context, conn N.PacketConn, rec *Record, source, destination M.Socksaddr) {
	remote, err := h.dialer.DialUDP(ctx, destination.String())
	if err != nil {
		h.update(rec.ID, func(r *Record) { r.Status = "failed" })
		return
	}
	defer remote.Close()

	go func() {
		buffer := buf.NewPacket()
		defer buffer.Release()
		for {
			remote.SetReadDeadline(time.Now().Add(2 * time.Minute))
			n, _, err := remote.ReadFrom(buffer.FreeBytes())
			if err != nil {
				return
			}
			buffer.Truncate(n)
			_ = conn.WritePacket(buffer, source)
			h.addTraffic(rec.ID, 0, uint64(n))
			buffer.FullReset()
		}
	}()

	for {
		buffer := buf.NewPacket()
		if _, err := conn.ReadPacket(buffer); err != nil {
			buffer.Release()
			return
		}
		n := buffer.Len()
		if _, err := remote.Write(buffer.Bytes()); err != nil {
			buffer.Release()
			return
		}
		h.addTraffic(rec.ID, uint64(n), 0)
		buffer.Release()
	}
}

func withDefault(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

func relay(dst net.Conn, src net.Conn) uint64 {
	buf := make([]byte, 32*1024)
	var total uint64
	for {
		n, err := src.Read(buf)
		if n > 0 {
			total += uint64(n)
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return total
			}
		}
		if err != nil {
			return total
		}
	}
}
