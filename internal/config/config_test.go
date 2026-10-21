package config

import (
	"path/filepath"
	"testing"
)

func TestImportPPXParsesRules(t *testing.T) {
	path := filepath.Join("..", "..", "DefaultProfile.ppx")
	profile, err := ImportPPX(path)
	if err != nil {
		t.Fatalf("导入 .ppx 失败: %v", err)
	}

	if len(profile.ProxyServers) != 2 {
		t.Fatalf("期望解析出 2 个代理服务器，实际 %d", len(profile.ProxyServers))
	}
	if profile.ProxyServers[0].Port != 7890 {
		t.Errorf("服务器端口解析错误: %d", profile.ProxyServers[0].Port)
	}
	if profile.ProxyServers[0].Protocol != ProtocolSOCKS5 {
		t.Errorf("协议解析错误: %s", profile.ProxyServers[0].Protocol)
	}

	if len(profile.ProxyChains) != 1 {
		t.Fatalf("期望解析出 1 条代理链，实际 %d", len(profile.ProxyChains))
	}
	if len(profile.ProxyChains[0].ProxyIDs) != 2 {
		t.Errorf("代理链成员解析错误: %v", profile.ProxyChains[0].ProxyIDs)
	}

	if len(profile.Rules) != 4 {
		t.Fatalf("期望解析出 4 条规则，实际 %d", len(profile.Rules))
	}

	// 第二条规则带应用程序、目标、端口与 Proxy 动作
	rule := profile.Rules[1]
	if len(rule.Applications) == 0 || rule.Applications[0] != "curl" {
		t.Errorf("应用程序列表解析错误: %v", rule.Applications)
	}
	if rule.Action.Type != ActionProxy || rule.Action.ProxyID != 100 {
		t.Errorf("动作解析错误: %+v", rule.Action)
	}
	if len(rule.Ports) != 3 {
		t.Errorf("端口列表解析错误: %v", rule.Ports)
	}
}

func TestPPXRoundTrip(t *testing.T) {
	src, err := ImportPPX(filepath.Join("..", "..", "DefaultProfile.ppx"))
	if err != nil {
		t.Fatalf("导入失败: %v", err)
	}

	out := filepath.Join(t.TempDir(), "roundtrip.ppx")
	if err = src.ExportPPX(out); err != nil {
		t.Fatalf("导出失败: %v", err)
	}

	again, err := ImportPPX(out)
	if err != nil {
		t.Fatalf("重新导入失败: %v", err)
	}

	if len(again.ProxyServers) != len(src.ProxyServers) {
		t.Errorf("服务器数量不一致: %d vs %d", len(again.ProxyServers), len(src.ProxyServers))
	}
	if len(again.Rules) != len(src.Rules) {
		t.Errorf("规则数量不一致: %d vs %d", len(again.Rules), len(src.Rules))
	}
	for i := range src.Rules {
		if again.Rules[i].Action.Type != src.Rules[i].Action.Type {
			t.Errorf("第 %d 条规则动作不一致: %s vs %s", i, again.Rules[i].Action.Type, src.Rules[i].Action.Type)
		}
	}
}

func TestServerLookup(t *testing.T) {
	p := DefaultProfile()
	p.ProxyServers = []ProxyServer{{ID: 7, Address: "127.0.0.1", Port: 1080}}

	if s, ok := p.ServerByID(7); !ok || s.Port != 1080 {
		t.Fatalf("按 ID 查找服务器失败: %+v %v", s, ok)
	}
	if _, ok := p.ServerByID(99); ok {
		t.Fatal("不存在的 ID 不应返回成功")
	}
}

func TestFakeIPPrefixFallback(t *testing.T) {
	p := &Profile{FakeIPPrefix: "不是个网段"}
	if got := p.FakeIPPrefixValue().String(); got != "198.18.0.0/15" {
		t.Errorf("非法网段应回退到默认值，实际 %s", got)
	}
}
