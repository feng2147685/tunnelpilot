package tunengine

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// NewDNSPacket 为 UDP DNS 查询生成响应，回包源保持为原 DNS 目标，禁止回退成客户端地址。
// param payload 为原始报文，source/destination 为客户端与 DNS 端点，writer 接管响应 buffer；协议和写回错误只记录类型。
func (h *Handler) NewDNSPacket(payload []byte, source, destination M.Socksaddr, writer N.PacketWriter) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	response, err := h.dnsResponse(ctx, payload)
	if err != nil {
		h.log("DNS 报文处理失败: %s", networkFailure(err))
		return
	}
	if err := writer.WritePacket(makeDNSBuffer(response), destination); err != nil {
		h.log("DNS 回包失败: %s", networkFailure(err))
	}
}

// dnsResponse 统一 UDP 与 TCP DNS 语义，A 查询保留域名供连接阶段结合真实进程与端口决策。
// param ctx 为查询期限，payload 为 DNS 报文；返回编码响应，无效报文返回错误，上游故障返回 SERVFAIL。
func (h *Handler) dnsResponse(ctx context.Context, payload []byte) ([]byte, error) {
	query := new(dns.Msg)
	if err := query.Unpack(payload); err != nil {
		return nil, err
	}
	resp := new(dns.Msg)
	resp.SetReply(query)
	resp.RecursionAvailable = true
	if query.Response || query.Opcode != dns.OpcodeQuery || len(query.Question) != 1 {
		resp.Rcode = dns.RcodeFormatError
		return resp.Pack()
	}
	question := query.Question[0]
	switch {
	case question.Qclass != dns.ClassINET:
		resp.Rcode = dns.RcodeRefused
	case h.bypass.Load():
		upstream, err := h.dialer.ExchangeDNS(ctx, query)
		if err != nil {
			resp.Rcode = dns.RcodeServerFailure
		} else {
			resp = upstream
		}
	case question.Qtype == dns.TypeA:
		// 系统 DNS 常由 mDNSResponder 发起，此时没有真实应用和目标端口，不能提前按业务规则阻断或直连。
		domain := strings.ToLower(strings.TrimSuffix(question.Name, "."))
		if ip, ok := h.fakeip.Allocate(domain); ok {
			resp.Answer = append(resp.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: question.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   ip.AsSlice(),
			})
		} else {
			resp.Rcode = dns.RcodeServerFailure
		}
	case question.Qtype == dns.TypeAAAA:
		// 当前仅接管 IPv4；空 AAAA 响应促使客户端使用 A，不能返回类型错误的 A 或泄漏真实 IPv6。
	default:
		upstream, err := h.dialer.ExchangeDNS(ctx, query)
		if err != nil {
			h.log("DNS 上游查询失败: %s", networkFailure(err))
			resp.Rcode = dns.RcodeServerFailure
		} else {
			resp = upstream
		}
	}
	return resp.Pack()
}

// handleDNSStream 处理 DNS 的 TCP 长度前缀和连续查询，避免系统 TCP 回退时连接虚拟 DNS 地址失败。
// param ctx 为连接生命周期，conn 为入站 TCP 流；EOF、超时或无效报文时结束，由调用者关闭连接。
func (h *Handler) handleDNSStream(ctx context.Context, conn net.Conn) {
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	for {
		if err := conn.SetDeadline(time.Now().Add(8 * time.Second)); err != nil {
			return
		}
		var length [2]byte
		if _, err := io.ReadFull(conn, length[:]); err != nil {
			return
		}
		payload := make([]byte, int(binary.BigEndian.Uint16(length[:])))
		if _, err := io.ReadFull(conn, payload); err != nil {
			return
		}
		response, err := h.dnsResponse(ctx, payload)
		if err != nil {
			return
		}
		binary.BigEndian.PutUint16(length[:], uint16(len(response)))
		frame := append(length[:], response...)
		if _, err := io.Copy(conn, bytes.NewReader(frame)); err != nil {
			return
		}
	}
}
