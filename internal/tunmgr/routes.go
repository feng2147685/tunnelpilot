package tunmgr

import (
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"strings"

	"github.com/sagernet/sing-tun"
)

// routeSet 跟踪本实例已创建的路由；只操作原 TUN 网关，不覆盖其它 VPN 的路由。
type routeSet struct {
	global        []netip.Prefix
	compatibility netip.Prefix
	gateway       netip.Addr
	installed     map[netip.Prefix]bool
	change        func(bool, netip.Prefix, netip.Addr) error
}

// newRouteSet 接管 sing-tun 已成功安装的路由清理职责。
// param options 为原始启动参数；返回路由状态，无法计算范围时返回错误，不改变系统。
func newRouteSet(options tun.Options) (*routeSet, error) {
	ranges, err := options.BuildAutoRouteRanges(false)
	if err != nil {
		return nil, err
	}
	r := &routeSet{global: ranges, compatibility: options.Inet4Address[0].Masked(), gateway: options.Inet4GatewayAddr(), installed: make(map[netip.Prefix]bool), change: changeRoute}
	for _, prefix := range ranges {
		r.installed[prefix] = true
	}
	return r, nil
}

// changeRoute 使用明确的网段和原 TUN 网关增删路由；不执行默认路由重置或冲突覆盖。
// param add 为添加标志，prefix/gateway 为所属路由；返回系统执行错误。
func changeRoute(add bool, prefix netip.Prefix, gateway netip.Addr) error {
	operation := "delete"
	if add {
		operation = "add"
	}
	output, err := exec.Command("route", "-n", operation, "-net", prefix.String(), gateway.String()).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s TUN 路由 %s 失败: %s: %w", operation, prefix, strings.TrimSpace(string(output)), err)
	}
	return nil
}

// set 幂等更新单条路由，并且只在系统确认成功后更新内存状态。
// param prefix/add 为网段和目标状态；返回系统操作错误，失败保留原状态供重试。
func (r *routeSet) set(prefix netip.Prefix, add bool) error {
	if r.installed[prefix] == add {
		return nil
	}
	if err := r.change(add, prefix, r.gateway); err != nil {
		return err
	}
	if add {
		r.installed[prefix] = true
	} else {
		delete(r.installed, prefix)
	}
	return nil
}

// pause 先建立 Fake-IP 专用路由，再撤销全局路由，确保缓存假地址一直可达。
// param 无；返回错误，部分失败会恢复全局路由，回滚失败时保留准确状态供重试或清理。
func (r *routeSet) pause() error {
	if err := r.set(r.compatibility, true); err != nil {
		return err
	}
	for _, prefix := range r.global {
		if prefix == r.compatibility {
			continue
		}
		if err := r.set(prefix, false); err != nil {
			return errors.Join(err, r.resume())
		}
	}
	return nil
}

// resume 恢复启动时的全局路由；保留专用路由以防恢复过程中缓存地址短暂不可达。
// param 无；返回所有失败，部分成功的路由保留状态供后续重试和退出清理。
func (r *routeSet) resume() error {
	var errs []error
	for _, prefix := range r.global {
		if err := r.set(prefix, true); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// close 删除本实例仍登记的全部路由，不修改其它网关的默认路由。
// param 无；返回聚合错误，未删成功的条目保留，调用方可以重试。
func (r *routeSet) close() error {
	var errs []error
	for prefix := range r.installed {
		if err := r.set(prefix, false); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
