package fakeip

import (
	"net/netip"
	"testing"
)

func TestAllocateIsStableAndUnique(t *testing.T) {
	pool := New(netip.MustParsePrefix("198.18.0.0/15"))

	a1, ok := pool.Allocate("api.openai.com")
	if !ok {
		t.Fatal("首次分配失败")
	}
	a2, _ := pool.Allocate("api.openai.com")
	if a1 != a2 {
		t.Fatalf("同一域名两次分配结果应一致: %s vs %s", a1, a2)
	}

	b, _ := pool.Allocate("github.com")
	if a1 == b {
		t.Fatalf("不同域名不应分配到同一地址: %s", a1)
	}

	if !pool.Has(a1) {
		t.Errorf("%s 应落在 Fake-IP 网段内", a1)
	}
}

func TestLookupReverse(t *testing.T) {
	pool := New(netip.MustParsePrefix("198.18.0.0/15"))
	ip, _ := pool.Allocate("example.com")

	domain, ok := pool.Lookup(ip)
	if !ok || domain != "example.com" {
		t.Fatalf("反查失败: %s %v", domain, ok)
	}

	if _, ok := pool.Lookup(netip.MustParseAddr("8.8.8.8")); ok {
		t.Error("网段外的地址不应命中")
	}
}

func TestMappingsSnapshot(t *testing.T) {
	pool := New(netip.MustParsePrefix("198.18.0.0/15"))
	pool.Allocate("a.com")
	pool.Allocate("b.com")

	m := pool.Mappings()
	if len(m) != 2 {
		t.Fatalf("期望 2 条映射，实际 %d", len(m))
	}
	if m["a.com"] == "" || m["b.com"] == "" {
		t.Error("映射值不应为空")
	}
}

func TestAllocateEmptyDomain(t *testing.T) {
	pool := New(netip.MustParsePrefix("198.18.0.0/15"))
	if _, ok := pool.Allocate(""); ok {
		t.Error("空域名不应分配地址")
	}
}

func TestHas(t *testing.T) {
	pool := New(netip.MustParsePrefix("198.18.0.0/15"))
	if !pool.Has(netip.MustParseAddr("198.18.3.7")) {
		t.Error("198.18.3.7 应属于 Fake-IP 网段")
	}
	if pool.Has(netip.MustParseAddr("1.1.1.1")) {
		t.Error("1.1.1.1 不应属于 Fake-IP 网段")
	}
}
