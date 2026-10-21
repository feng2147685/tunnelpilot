package fakeip

import (
	"net/netip"
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

func New(prefix netip.Prefix) *Pool {
	if !prefix.IsValid() {
		prefix = netip.MustParsePrefix("198.18.0.0/15")
	}
	return &Pool{
		prefix:     prefix,
		nextOffset: 1,
		domainToIP: make(map[string]netip.Addr),
		ipToDomain: make(map[netip.Addr]string),
	}
}

// Allocate 为域名分配（或返回已分配的）Fake-IP
func (p *Pool) Allocate(domain string) (netip.Addr, bool) {
	if domain == "" {
		return netip.Addr{}, false
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	if ip, ok := p.domainToIP[domain]; ok {
		return ip, true
	}

	base := p.prefix.Addr()
	baseUint := ipToUint32(base)
	size := prefixSize(p.prefix)
	for i := 0; i < int(size)-1; i++ {
		offset := p.nextOffset
		p.nextOffset++
		if p.nextOffset >= size {
			p.nextOffset = 1
		}
		candidate := uint32ToIP(baseUint + offset)
		if !p.prefix.Contains(candidate) {
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

// Lookup 由 Fake-IP 反查真实域名
func (p *Pool) Lookup(ip netip.Addr) (string, bool) {
	if !p.prefix.Contains(ip) {
		return "", false
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	domain, ok := p.ipToDomain[ip]
	return domain, ok
}

// Has 判断某个地址是否落在 Fake-IP 网段内
func (p *Pool) Has(ip netip.Addr) bool {
	return p.prefix.Contains(ip)
}

func (p *Pool) Mappings() map[string]string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make(map[string]string, len(p.domainToIP))
	for d, ip := range p.domainToIP {
		out[d] = ip.String()
	}
	return out
}

func ipToUint32(addr netip.Addr) uint32 {
	b := addr.As4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func uint32ToIP(v uint32) netip.Addr {
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

func prefixSize(prefix netip.Prefix) uint32 {
	bits := prefix.Bits()
	total := prefix.Addr().BitLen()
	if bits >= total {
		return 1
	}
	return uint32(1) << uint(total-bits)
}
