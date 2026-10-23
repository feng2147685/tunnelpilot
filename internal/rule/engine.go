package rule

import (
	"net/netip"
	"path/filepath"
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

// Engine 持有不可变配置快照并提供首个命中的规则决策，不执行网络写入。
type Engine struct {
	mu      sync.RWMutex
	profile *config.Profile
}

// New 创建按顺序匹配的规则引擎。
// param profile 为配置快照；返回引擎，空配置默认直连。
func New(profile *config.Profile) *Engine {
	return &Engine{profile: profile}
}

// Update 原子替换后续流使用的配置快照。
// param profile 为新配置；无返回值，调用方发布后不得原地修改配置。
func (e *Engine) Update(profile *config.Profile) {
	e.mu.Lock()
	e.profile = profile
	e.mu.Unlock()
}

// Profile 读取当前配置快照。
// param 无；返回只读配置指针，可能为空。
func (e *Engine) Profile() *config.Profile {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.profile
}

// Evaluate 按 RuleList 顺序返回第一条命中的规则。Proxifier 语义：自上而下，首个匹配生效。
// param ctx 为已知流属性；返回命中动作，无命中时默认直连且不访问 DNS。
func (e *Engine) Evaluate(ctx Context) Match {
	match, _ := e.EvaluateWithIPLookup(ctx, nil)
	return match
}

// EvaluateWithIPLookup 按顺序匹配规则，仅在域名流量遇到 IP 条件时解析真实地址。
// param ctx 为连接属性，lookup 为独立 DNS 查询；返回首个命中结果，必要解析失败时返回错误，不能越过前置规则。
func (e *Engine) EvaluateWithIPLookup(ctx Context, lookup func() ([]netip.Addr, error)) (Match, error) {
	e.mu.RLock()
	profile := e.profile
	e.mu.RUnlock()
	if profile == nil {
		return Match{Action: config.RuleAction{Type: config.ActionDirect}}, nil
	}
	var realIPs []netip.Addr
	resolved := false
	for _, r := range profile.Rules {
		if !r.Enabled || (len(r.Applications) > 0 && !matchApplications(r.Applications, ctx)) || (len(r.Ports) > 0 && !matchPorts(r.Ports, ctx.Port)) {
			continue
		}
		if len(r.Targets) > 0 && !matchTargets(r.Targets, ctx) {
			if lookup == nil || !targetsNeedIP(r.Targets) {
				continue
			}
			if !resolved {
				var err error
				realIPs, err = lookup()
				if err != nil {
					return Match{}, err
				}
				resolved = true
			}
			matched := false
			for _, ip := range realIPs {
				realContext := ctx
				realContext.IP = ip
				if matchTargets(r.Targets, realContext) {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
		}
		return Match{Rule: r, Action: r.Action, Found: true}, nil
	}
	return Match{Action: config.RuleAction{Type: config.ActionDirect}}, nil
}

// targetsNeedIP 判断目标条件是否包含地址、CIDR 或 IPv4 通配符。
// param list 为目标模式；返回是否需要真实 IP，纯域名规则不触发本地解析。
func targetsNeedIP(list []string) bool {
	for _, pattern := range list {
		if _, err := netip.ParsePrefix(pattern); err == nil {
			return true
		}
		if _, err := netip.ParseAddr(pattern); err == nil {
			return true
		}
		if strings.Count(pattern, ".") == 3 && strings.Trim(pattern, "0123456789.*?") == "" {
			return true
		}
	}
	return false
}

// matchApplications 匹配完整进程名、路径或所属 app，禁止隐式子串扩大规则范围。
// param list/ctx 为应用模式和进程上下文；返回匹配状态，无匹配时为 false。
func matchApplications(list []string, ctx Context) bool {
	candidates := []string{ctx.ProcessName}
	if ctx.BundleID != "" {
		candidates = append(candidates, ctx.BundleID)
	}
	if ctx.ProcessPath != "" {
		candidates = append(candidates, ctx.ProcessPath)
		// 应用路径通常形如 /Applications/Cursor.app/Contents/MacOS/Cursor
		if idx := strings.Index(ctx.ProcessPath, ".app/"); idx > 0 {
			appPath := ctx.ProcessPath[:idx+4]
			appName := filepath.Base(appPath)
			candidates = append(candidates, appPath, appName, strings.TrimSuffix(appName, ".app"))
		}
	}
	for _, pattern := range list {
		for _, c := range candidates {
			if c == "" {
				continue
			}
			if wildcardMatch(pattern, c) {
				return true
			}
		}
	}
	return false
}

// matchTargets 匹配域名、真实 IP、CIDR 或显式通配符。
// param list/ctx 为目标模式及流属性；返回匹配状态，无效模式不命中。
func matchTargets(list []string, ctx Context) bool {
	for _, pattern := range list {
		if (ctx.Host != "" && wildcardMatch(pattern, strings.TrimSuffix(ctx.Host, "."))) || (ctx.IP.IsValid() && wildcardMatch(pattern, ctx.IP.String())) {
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

// matchPorts 匹配端口单值与闭区间。
// param list/port 为端口模式及目标端口；返回匹配状态，无效范围不命中。
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
// param pattern/s 为模式和待匹配文本；返回完整匹配状态，无失败分支。
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
