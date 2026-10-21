package rule

import (
	"net/netip"
	"testing"

	"tunnelpilot/internal/config"
)

func TestWildcardMatch(t *testing.T) {
	cases := []struct {
		pattern string
		value   string
		want    bool
	}{
		{"*.openai.com", "api.openai.com", true},
		{"*.openai.com", "openai.com", false},
		{"*.openai.com", "API.OPENAI.COM", true},
		{"api.*.com", "api.openai.com", true},
		{"*", "anything", true},
		{"curl", "curl", true},
		{"curl", "curlx", false},
		{"a?c", "abc", true},
		{"a?c", "ac", false},
		{"*.github.com", "raw.githubusercontent.com", false},
	}

	for _, c := range cases {
		if got := wildcardMatch(c.pattern, c.value); got != c.want {
			t.Errorf("wildcardMatch(%q, %q) = %v, 期望 %v", c.pattern, c.value, got, c.want)
		}
	}
}

func TestMatchPorts(t *testing.T) {
	cases := []struct {
		spec []string
		port uint16
		want bool
	}{
		{[]string{"443"}, 443, true},
		{[]string{"443"}, 80, false},
		{[]string{"80", "443"}, 80, true},
		{[]string{"8000-8100"}, 8050, true},
		{[]string{"8000-8100"}, 8101, false},
		{[]string{"53", "8000-8100"}, 53, true},
	}

	for _, c := range cases {
		if got := matchPorts(c.spec, c.port); got != c.want {
			t.Errorf("matchPorts(%v, %d) = %v, 期望 %v", c.spec, c.port, got, c.want)
		}
	}
}

func TestEvaluateFirstMatchWins(t *testing.T) {
	profile := &config.Profile{
		Rules: []config.Rule{
			{
				Enabled:      true,
				Name:         "指定应用直连",
				Applications: []string{"curl"},
				Action:       config.RuleAction{Type: config.ActionDirect},
			},
			{
				Enabled: true,
				Name:    "其余全部走代理",
				Action:  config.RuleAction{Type: config.ActionProxy, ProxyID: 100},
			},
		},
	}
	engine := New(profile)

	got := engine.Evaluate(Context{ProcessName: "curl", Host: "api.openai.com", Port: 443})
	if got.Rule.Name != "指定应用直连" || got.Action.Type != config.ActionDirect {
		t.Fatalf("curl 应命中首条规则并直连，实际: %+v", got)
	}

	got = engine.Evaluate(Context{ProcessName: "node", Host: "api.openai.com", Port: 443})
	if got.Rule.Name != "其余全部走代理" || got.Action.Type != config.ActionProxy {
		t.Fatalf("node 应命中兜底规则并走代理，实际: %+v", got)
	}
}

func TestEvaluateDisabledRuleSkipped(t *testing.T) {
	profile := &config.Profile{
		Rules: []config.Rule{
			{Enabled: false, Name: "已禁用", Applications: []string{"curl"}, Action: config.RuleAction{Type: config.ActionBlock}},
			{Enabled: true, Name: "兜底", Action: config.RuleAction{Type: config.ActionDirect}},
		},
	}
	engine := New(profile)

	got := engine.Evaluate(Context{ProcessName: "curl", Port: 443})
	if got.Rule.Name != "兜底" {
		t.Fatalf("禁用的规则不应命中，实际: %+v", got)
	}
}

func TestMatchTargetsIPAndCIDR(t *testing.T) {
	targets := []string{"10.0.0.0/8", "192.168.1.5", "*.example.com"}

	cases := []struct {
		host string
		ip   string
		want bool
	}{
		{"", "10.20.30.40", true},
		{"", "192.168.1.5", true},
		{"", "192.168.1.6", false},
		{"foo.example.com", "1.2.3.4", true},
		{"example.org", "1.2.3.4", false},
	}

	for _, c := range cases {
		ctx := Context{Host: c.host}
		if c.ip != "" {
			ctx.IP = netip.MustParseAddr(c.ip)
		}
		if got := matchTargets(targets, ctx); got != c.want {
			t.Errorf("matchTargets(host=%q ip=%q) = %v, 期望 %v", c.host, c.ip, got, c.want)
		}
	}
}

func TestEvaluateFallsBackToDirect(t *testing.T) {
	engine := New(&config.Profile{})
	got := engine.Evaluate(Context{ProcessName: "curl", Port: 443})
	if got.Action.Type != config.ActionDirect {
		t.Fatalf("无规则时应默认直连，实际: %+v", got)
	}
}
