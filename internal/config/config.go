package config

import (
	"encoding/xml"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

// 协议类型，与 Proxifier .ppx 中的 type 字段保持一致
const (
	ProtocolSOCKS5 = "SOCKS5"
	ProtocolSOCKS4 = "SOCKS4"
	ProtocolHTTPS  = "HTTPS"
)

// 动作类型
const (
	ActionDirect = "Direct"
	ActionProxy  = "Proxy"
	ActionBlock  = "Block"
	ActionChain  = "Chain"
)

// 链类型
const (
	ChainSimple        = "simple"        // 多跳串联
	ChainRedundancy    = "redundancy"    // 主备容灾
	ChainLoadBalancing = "loadBalancing" // 轮询负载均衡
)

type ProxyServer struct {
	ID       int    `json:"id"`
	Name     string `json:"name"`
	Protocol string `json:"protocol"`
	Address  string `json:"address"`
	Port     uint16 `json:"port"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}

type ProxyChain struct {
	ID       int    `json:"id"`
	Name     string `json:"name"`
	Type     string `json:"type"`
	ProxyIDs []int  `json:"proxy_ids"`
}

type RuleAction struct {
	Type    string `json:"type"`
	ProxyID int    `json:"proxy_id,omitempty"`
	ChainID int    `json:"chain_id,omitempty"`
}

type Rule struct {
	Enabled      bool       `json:"enabled"`
	Name         string     `json:"name"`
	Applications []string   `json:"applications,omitempty"`
	Targets      []string   `json:"targets,omitempty"`
	Ports        []string   `json:"ports,omitempty"`
	Action       RuleAction `json:"action"`
}

type Options struct {
	ResolveHostnameThroughProxy bool     `json:"resolve_through_proxy"`
	HandleDirectConnections     bool     `json:"handle_direct_connections"`
	LoopDetection               bool     `json:"loop_detection"`
	DNSExclusionList            []string `json:"dns_exclusion_list"`
}

type Profile struct {
	Name         string        `json:"name"`
	ProxyServers []ProxyServer `json:"proxy_servers"`
	ProxyChains  []ProxyChain  `json:"proxy_chains"`
	Rules        []Rule        `json:"rules"`
	Options      Options       `json:"options"`
	ListenPort   uint16        `json:"listen_port"`
	TUNName      string        `json:"tun_name"`
	FakeIPPrefix string        `json:"fakeip_prefix"`
}

func DefaultProfile() *Profile {
	return &Profile{
		Name: "默认配置",
		ProxyServers: []ProxyServer{
			{ID: 100, Name: "本地 SOCKS5", Protocol: ProtocolSOCKS5, Address: "127.0.0.1", Port: 7890},
		},
		ProxyChains: []ProxyChain{},
		Rules: []Rule{
			{Enabled: true, Name: "Localhost", Targets: []string{"localhost", "127.0.0.1", "::1", "192.168.*.*", "10.*.*.*"}, Action: RuleAction{Type: ActionDirect}},
			{Enabled: true, Name: "Default", Action: RuleAction{Type: ActionDirect}},
		},
		Options: Options{
			ResolveHostnameThroughProxy: true,
			HandleDirectConnections:     true,
			LoopDetection:               true,
			DNSExclusionList:            []string{"localhost", "*.local", "*.lan"},
		},
		ListenPort:   9090,
		TUNName:      "utun10",
		FakeIPPrefix: "198.18.0.0/15",
	}
}

// FakeIPPrefixValue 读取 IPv4 Fake-IP 网段，供地址池与 TUN 共用。
// param 无；返回合法 /8 至 /30 网段，无法解析或不受支持时回退默认 /15。
func (p *Profile) FakeIPPrefixValue() netip.Prefix {
	prefix, err := netip.ParsePrefix(p.FakeIPPrefix)
	if err != nil || !prefix.Addr().Is4() || prefix.Bits() < 8 || prefix.Bits() > 30 {
		return netip.MustParsePrefix("198.18.0.0/15")
	}
	return prefix
}

func (p *Profile) ServerByID(id int) (ProxyServer, bool) {
	for _, s := range p.ProxyServers {
		if s.ID == id {
			return s, true
		}
	}
	return ProxyServer{}, false
}

func (p *Profile) ChainByID(id int) (ProxyChain, bool) {
	for _, c := range p.ProxyChains {
		if c.ID == id {
			return c, true
		}
	}
	return ProxyChain{}, false
}

// ---------------------------------------------------------------------------
// .ppx 导入导出（Proxifier 原生 XML 配置格式）
// ---------------------------------------------------------------------------

type ppxRoot struct {
	XMLName   xml.Name `xml:"ProxifierProfile"`
	Version   string   `xml:"version,attr"`
	ProxyList struct {
		Proxies []struct {
			ID      string `xml:"id,attr"`
			Type    string `xml:"type,attr"`
			Address string `xml:"Address"`
			Port    string `xml:"Port"`
			Options string `xml:"Options"`
		} `xml:"Proxy"`
	} `xml:"ProxyList"`
	ChainList struct {
		Chains []struct {
			ID      string `xml:"id,attr"`
			Type    string `xml:"type,attr"`
			Name    string `xml:"Name"`
			Proxies []struct {
				Enabled string `xml:"enabled,attr"`
				Value   string `xml:",chardata"`
			} `xml:"Proxy"`
		} `xml:"Chain"`
	} `xml:"ChainList"`
	RuleList struct {
		Rules []struct {
			Enabled      string `xml:"enabled,attr"`
			Name         string `xml:"Name"`
			Applications string `xml:"Applications"`
			Targets      string `xml:"Targets"`
			Ports        string `xml:"Ports"`
			Action       struct {
				Type  string `xml:"type,attr"`
				Value string `xml:",chardata"`
			} `xml:"Action"`
		} `xml:"Rule"`
	} `xml:"RuleList"`
}

// ImportPPX 解析 Proxifier .ppx 文件
func ImportPPX(path string) (*Profile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var root ppxRoot
	if err = xml.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("解析 .ppx 失败: %w", err)
	}

	profile := DefaultProfile()
	profile.Name = strings.TrimSuffix(path, ".ppx")
	profile.ProxyServers = nil
	profile.ProxyChains = nil
	profile.Rules = nil

	for _, p := range root.ProxyList.Proxies {
		id, _ := strconv.Atoi(p.ID)
		port, _ := strconv.Atoi(p.Port)
		profile.ProxyServers = append(profile.ProxyServers, ProxyServer{
			ID:       id,
			Name:     fmt.Sprintf("%s:%s", p.Address, p.Port),
			Protocol: normalizeProtocol(p.Type),
			Address:  p.Address,
			Port:     uint16(port),
		})
	}

	for _, c := range root.ChainList.Chains {
		id, _ := strconv.Atoi(c.ID)
		chain := ProxyChain{
			ID:   id,
			Name: c.Name,
			Type: normalizeChainType(c.Type),
		}
		for _, p := range c.Proxies {
			pid, _ := strconv.Atoi(strings.TrimSpace(p.Value))
			chain.ProxyIDs = append(chain.ProxyIDs, pid)
		}
		profile.ProxyChains = append(profile.ProxyChains, chain)
	}

	for _, r := range root.RuleList.Rules {
		rule := Rule{
			Enabled:      r.Enabled != "false",
			Name:         r.Name,
			Applications: splitList(r.Applications),
			Targets:      splitList(r.Targets),
			Ports:        splitList(r.Ports),
		}
		rule.Action = RuleAction{Type: normalizeAction(r.Action.Type)}
		if v, err := strconv.Atoi(strings.TrimSpace(r.Action.Value)); err == nil {
			switch rule.Action.Type {
			case ActionProxy:
				rule.Action.ProxyID = v
			case ActionChain:
				rule.Action.ChainID = v
			}
		}
		profile.Rules = append(profile.Rules, rule)
	}

	if len(profile.Rules) == 0 {
		profile.Rules = DefaultProfile().Rules
	}
	return profile, nil
}

// ExportPPX 导出为 Proxifier 兼容的 .ppx 文件
func (p *Profile) ExportPPX(path string) error {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` + "\n")
	b.WriteString(`<ProxifierProfile version="102" platform="MacOSX" product_id="2" product_minver="300">` + "\n")
	b.WriteString("  <Options>\n    <Resolve>\n      <ViaProxy enabled=\"true\">\n        <TryLocalDnsFirst enabled=\"false\" />\n      </ViaProxy>\n    </Resolve>\n")
	b.WriteString("    <HandleDirectConnections enabled=\"true\" />\n")
	b.WriteString("    <ConnectionLoopDetection enabled=\"true\" resolve=\"true\" />\n  </Options>\n")

	b.WriteString("  <ProxyList>\n")
	for _, s := range p.ProxyServers {
		b.WriteString(fmt.Sprintf("    <Proxy id=\"%d\" type=\"%s\">\n      <Address>%s</Address>\n      <Port>%d</Port>\n      <Options>0</Options>\n    </Proxy>\n",
			s.ID, s.Protocol, s.Address, s.Port))
	}
	b.WriteString("  </ProxyList>\n")

	b.WriteString("  <ChainList>\n")
	for _, c := range p.ProxyChains {
		b.WriteString(fmt.Sprintf("    <Chain id=\"%d\" type=\"%s\">\n      <Name>%s</Name>\n", c.ID, c.Type, xmlEscape(c.Name)))
		for _, id := range c.ProxyIDs {
			b.WriteString(fmt.Sprintf("      <Proxy enabled=\"true\">%d</Proxy>\n", id))
		}
		b.WriteString("    </Chain>\n")
	}
	b.WriteString("  </ChainList>\n")

	b.WriteString("  <RuleList>\n")
	for _, r := range p.Rules {
		enabled := "true"
		if !r.Enabled {
			enabled = "false"
		}
		b.WriteString(fmt.Sprintf("    <Rule enabled=\"%s\">\n      <Name>%s</Name>\n", enabled, xmlEscape(r.Name)))
		if len(r.Applications) > 0 {
			b.WriteString(fmt.Sprintf("      <Applications>%s</Applications>\n", xmlEscape(strings.Join(r.Applications, "; "))))
		}
		if len(r.Targets) > 0 {
			b.WriteString(fmt.Sprintf("      <Targets>%s</Targets>\n", xmlEscape(strings.Join(r.Targets, "; "))))
		}
		if len(r.Ports) > 0 {
			b.WriteString(fmt.Sprintf("      <Ports>%s</Ports>\n", xmlEscape(strings.Join(r.Ports, ", "))))
		}
		switch r.Action.Type {
		case ActionProxy:
			b.WriteString(fmt.Sprintf("      <Action type=\"Proxy\">%d</Action>\n", r.Action.ProxyID))
		case ActionChain:
			b.WriteString(fmt.Sprintf("      <Action type=\"Chain\">%d</Action>\n", r.Action.ChainID))
		default:
			b.WriteString(fmt.Sprintf("      <Action type=\"%s\" />\n", r.Action.Type))
		}
		b.WriteString("    </Rule>\n")
	}
	b.WriteString("  </RuleList>\n</ProxifierProfile>\n")

	return os.WriteFile(path, []byte(b.String()), 0644)
}

func splitList(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.FieldsFunc(s, func(r rune) bool { return r == ';' || r == ',' })
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func normalizeProtocol(s string) string {
	switch strings.ToUpper(s) {
	case "SOCKS5", "SOCKS", "SOCKS5H":
		return ProtocolSOCKS5
	case "SOCKS4", "SOCKS4A":
		return ProtocolSOCKS4
	case "HTTPS", "HTTP":
		return ProtocolHTTPS
	default:
		return ProtocolSOCKS5
	}
}

func normalizeChainType(s string) string {
	switch strings.ToLower(s) {
	case "redundancy", "failover":
		return ChainRedundancy
	case "loadbalancing", "load_balancing", "balance":
		return ChainLoadBalancing
	default:
		return ChainSimple
	}
}

func normalizeAction(s string) string {
	switch strings.ToLower(s) {
	case "direct":
		return ActionDirect
	case "block", "drop", "reject":
		return ActionBlock
	case "chain":
		return ActionChain
	default:
		return ActionProxy
	}
}

func xmlEscape(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	return s
}
