package rule

import (
	"net/netip"
	"strconv"
	"strings"
	"sync"

	"tunnelpilot/internal/config"
)

// Context 描述一次连接请求，供规则匹配使用。
type Context struct {
	ProcessName string     // 进程名，如 curl
	ProcessPath string     // 可执行文件路径
	BundleID    string     // macOS bundle identifier
	Host        string     // 域名（Fake-IP 还原后）
	IP          netip.Addr // 目标 IP（可能是 Fake-IP）
	Port        uint16
	IsUDP       bool
}

// Match 描述匹配结果
type Match struct {
	Rule   config.Rule
	Action config.RuleAction
	Found  bool
}

type Engine struct {
	mu      sync.RWMutex
	profile *config.Profile
}

func New(profile *config.Profile) *Engine {
	return &Engine{profile: profile}
}

func (e *Engine) Update(profile *config.Profile) {
	e.mu.Lock()
	e.profile = profile
	e.mu.Unlock()
}

func (e *Engine) Profile() *config.Profile {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.profile
}

// Evaluate 按 RuleList 顺序返回第一条命中的规则。Proxifier 语义：自上而下，首个匹配生效。
func (e *Engine) Evaluate(ctx Context) Match {
	e.mu.RLock()
	profile := e.profile
	e.mu.RUnlock()

	if profile == nil {
		return Match{Action: config.RuleAction{Type: config.ActionDirect}}
	}

	for _, r := range profile.Rules {
		if !r.Enabled {
			continue
		}
		if len(r.Applications) > 0 && !matchApplications(r.Applications, ctx) {
			continue
		}
		if len(r.Targets) > 0 && !matchTargets(r.Targets, ctx) {
			continue
		}
		if len(r.Ports) > 0 && !matchPorts(r.Ports, ctx.Port) {
			continue
		}
		return Match{Rule: r, Action: r.Action, Found: true}
	}

	// 无规则命中时的兜底：Proxifier 默认直连
	return Match{Action: config.RuleAction{Type: config.ActionDirect}}
}

func matchApplications(list []string, ctx Context) bool {
	candidates := []string{ctx.ProcessName}
	if ctx.BundleID != "" {
		candidates = append(candidates, ctx.BundleID)
	}
	if ctx.ProcessPath != "" {
		candidates = append(candidates, ctx.ProcessPath)
		// 应用路径通常形如 /Applications/Cursor.app/Contents/MacOS/Cursor
		if idx := strings.Index(ctx.ProcessPath, ".app/"); idx > 0 {
			candidates = append(candidates, ctx.ProcessPath[:idx+4])
		}
	}
	for _, pattern := range list {
		for _, c := range candidates {
			if c == "" {
				continue
			}
			if wildcardMatch(pattern, c) || strings.Contains(strings.ToLower(c), strings.ToLower(strings.TrimSuffix(pattern, ".app"))) {
				return true
			}
		}
	}
	return false
}

func matchTargets(list []string, ctx Context) bool {
	for _, pattern := range list {
		if ctx.Host != "" && wildcardMatch(pattern, ctx.Host) {
			return true
		}
		if prefix, err := netip.ParsePrefix(pattern); err == nil {
			if ctx.IP.IsValid() && prefix.Contains(ctx.IP) {
				return true
			}
			continue
		}
		if addr, err := netip.ParseAddr(pattern); err == nil {
			if ctx.IP.IsValid() && addr == ctx.IP {
				return true
			}
			continue
		}
	}
	return false
}

func matchPorts(list []string, port uint16) bool {
	for _, spec := range list {
		spec = strings.TrimSpace(spec)
		if strings.Contains(spec, "-") {
			parts := strings.SplitN(spec, "-", 2)
			lo, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
			hi, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
			if err1 == nil && err2 == nil && int(port) >= lo && int(port) <= hi {
				return true
			}
			continue
		}
		if v, err := strconv.Atoi(spec); err == nil && v == int(port) {
			return true
		}
	}
	return false
}

// wildcardMatch 支持 * 与 ? 通配符，大小写不敏感。
func wildcardMatch(pattern, s string) bool {
	pattern = strings.ToLower(pattern)
	s = strings.ToLower(s)
	if pattern == "*" {
		return true
	}
	if !strings.Contains(pattern, "*") && !strings.Contains(pattern, "?") {
		return pattern == s
	}

	var px, sx int
	var starIdx, matchIdx = -1, 0
	for sx < len(s) {
		if px < len(pattern) && (pattern[px] == '?' || pattern[px] == s[sx]) {
			px++
			sx++
		} else if px < len(pattern) && pattern[px] == '*' {
			starIdx = px
			matchIdx = sx
			px++
		} else if starIdx != -1 {
			px = starIdx + 1
			matchIdx++
			sx = matchIdx
		} else {
			return false
		}
	}
	for px < len(pattern) && pattern[px] == '*' {
		px++
	}
	return px == len(pattern)
}
