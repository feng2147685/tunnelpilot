package proxy

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// directDNSServers 是系统 DNS 接管期间使用的独立上游，地址必须为 IP，避免引导解析递归。
var directDNSServers = []string{"223.5.5.5:53", "119.29.29.29:53"}

// ExchangeDNS 使用绑定物理网卡的 socket 查询独立上游，不经过系统 resolver。
// param ctx 控制查询生命周期，query 为原始问题；返回保留记录类型与响应码的报文，上游全部失败时返回错误。
func (d *Dialer) ExchangeDNS(ctx context.Context, query *dns.Msg) (*dns.Msg, error) {
	var lastErr error
	for _, server := range directDNSServers {
		client := &dns.Client{Net: "udp", Dialer: d.socketDialer(), Timeout: 3 * time.Second}
		resp, _, err := client.ExchangeContext(ctx, query, server)
		if err == nil && resp.Truncated {
			client.Net = "tcp"
			resp, _, err = client.ExchangeContext(ctx, query, server)
		}
		if err == nil && resp.Rcode != dns.RcodeServerFailure && resp.Rcode != dns.RcodeRefused {
			return resp, nil
		}
		if err == nil {
			err = fmt.Errorf("DNS 上游返回 %s", dns.RcodeToString[resp.Rcode])
		}
		lastErr = err
	}
	return nil, fmt.Errorf("独立 DNS 查询失败: %w", lastErr)
}

// outboundResolver 为直连目标和代理服务器域名解析提供独立出口。
// param 无；返回强制使用 Go DNS 协议栈的解析器，避免接管后调用系统 DNS 得到 Fake-IP。
func (d *Dialer) outboundResolver() *net.Resolver {
	var next atomic.Uint64
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			// net.Resolver 负责 DNS 重试和 TCP 回退；此处只替换系统分配的 DNS 地址。
			return d.socketDialer().DialContext(ctx, network, directDNSServers[(next.Add(1)-1)%uint64(len(directDNSServers))])
		},
	}
}

// ResolveIPv4 为 Fake-IP 连接上的 IP/CIDR 规则获取真实 IPv4，不经过系统 DNS。
// param ctx 为期限，domain 为目标域名；返回真实地址，解析错误时调用方不得跳过前置规则。
func (d *Dialer) ResolveIPv4(ctx context.Context, domain string) ([]netip.Addr, error) {
	return d.outboundResolver().LookupNetIP(ctx, "ip4", domain)
}
