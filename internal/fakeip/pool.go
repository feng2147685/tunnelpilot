package fakeip

import (
	"net/netip"
	"strings"
	"sync"
)

// Pool 维护「域名 <-> Fake-IP」双向映射。
// DNS 被劫持时为域名分配一个 198.18.0.0/15 内的假 IP，
// 后续连接到达时再还原真实域名，交由远端代理解析（Proxifier 的 Resolve through proxy）。
type Pool struct {
	mu         sync.RWMutex
	prefix     netip.Prefix
	nextOffset uint32
	domainToIP map[string]netip.Addr
	ipToDomain map[netip.Addr]string
}

// New 创建只分配可用 IPv4 地址的 Fake-IP 池。
// param prefix 为网段；返回地址池，无效、IPv6 或过小网段使用默认 /15。
func New(prefix netip.Prefix) *Pool {
	if !prefix.IsValid() || !prefix.Addr().Is4() || prefix.Bits() < 8 || prefix.Bits() > 30 {
		prefix = netip.MustParsePrefix("198.18.0.0/15")
	}
	return &Pool{
		prefix:     prefix,
		nextOffset: 1,
		domainToIP: make(map[string]netip.Addr),
		ipToDomain: make(map[netip.Addr]string),
	}
}

// Allocate 为域名分配（或返回已分配的）Fake-IP。
// param domain 为目标域名；返回地址和成功状态，空域名或地址耗尽时失败。
func (p *Pool) Allocate(domain string) (netip.Addr, bool) {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	if domain == "" {
		return netip.Addr{}, false
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	if ip, ok := p.domainToIP[domain]; ok {
		return ip, true
	}

	base := p.prefix.Masked().Addr()
	baseUint := ipToUint32(base)
	size := prefixSize(p.prefix)
	for i := 0; i < int(size)-1; i++ {
		offset := p.nextOffset
		p.nextOffset++
		if p.nextOffset >= size {
			p.nextOffset = 1
		}
		candidate := uint32ToIP(baseUint + offset)
		// 预留接口自身、DNS 入口与广播地址，防止业务连接与内部服务冲突。
		if candidate == p.prefix.Addr() || offset >= size-2 || !p.prefix.Contains(candidate) {
			continue
		}
		if _, used := p.ipToDomain[candidate]; used {
			continue
		}
		p.domainToIP[domain] = candidate
		p.ipToDomain[candidate] = domain
		return candidate, true
	}
	return netip.Addr{}, false
}

// Lookup 由 Fake-IP 反查真实域名。
// param ip 为目标地址；返回域名及命中状态，池外或未分配地址不命中。
func (p *Pool) Lookup(ip netip.Addr) (string, bool) {
	if !p.prefix.Contains(ip) {
		return "", false
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	domain, ok := p.ipToDomain[ip]
	return domain, ok
}

// Has 判断某个地址是否落在 Fake-IP 网段内。
// param ip 为待判断地址；返回归属状态，不表示该地址已分配。
func (p *Pool) Has(ip netip.Addr) bool {
	return p.prefix.Contains(ip)
}

// Mappings 读取域名映射快照供控制台使用。
// param 无；返回独立 map，修改它不会影响分流。
func (p *Pool) Mappings() map[string]string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make(map[string]string, len(p.domainToIP))
	for d, ip := range p.domainToIP {
		out[d] = ip.String()
	}
	return out
}

// ipToUint32 将已验证的 IPv4 转换为地址偏移计算值。
// param addr 必须为 IPv4；返回无符号整数，IPv6 输入会触发 netip 的契约 panic。
func ipToUint32(addr netip.Addr) uint32 {
	b := addr.As4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

// uint32ToIP 将地址偏移恢复为 IPv4。
// param v 为 32 位地址值；返回 IPv4，无失败分支。
func uint32ToIP(v uint32) netip.Addr {
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

// prefixSize 计算已验证 IPv4 网段的地址总数。
// param prefix 为 IPv4 网段；返回容量，不负责校验网段。
func prefixSize(prefix netip.Prefix) uint32 {
	bits := prefix.Bits()
	total := prefix.Addr().BitLen()
	if bits >= total {
		return 1
	}
	return uint32(1) << uint(total-bits)
}

// DNSAddress 为 IPv4 Fake-IP 网段预留倒数第二个地址作为 DNS 入口。
// param prefix 为已校验网段；返回入口地址，无效或过小网段返回无效地址。
func DNSAddress(prefix netip.Prefix) netip.Addr {
	if !prefix.IsValid() || !prefix.Addr().Is4() || prefix.Bits() < 8 || prefix.Bits() > 30 {
		return netip.Addr{}
	}
	return uint32ToIP(ipToUint32(prefix.Masked().Addr()) + prefixSize(prefix) - 2)
}
