package netfix

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
)

// Status 描述当前系统的路由健康状况
type Status struct {
	DefaultInterface string
	DefaultGateway   string
	PhysicalIf       string
	PhysicalGateway  string
	TunRoutes        []string
	Healthy          bool
	Issues           []string
}

// Diagnose 检查默认路由是否被 utun 劫持或指向了已消失的接口
func Diagnose() Status {
	var st Status

	if ifName, gw, err := defaultRoute(); err == nil {
		st.DefaultInterface = ifName
		st.DefaultGateway = gw
	} else {
		st.Issues = append(st.Issues, "无法读取默认路由："+err.Error())
	}

	st.PhysicalIf, st.PhysicalGateway = physicalInterfaceAndGateway()

	// 查找指向 utun 的半路由（TUN 接管时写入的 0.0.0.0/1 与 128.0.0.0/1）
	out, _ := exec.Command("netstat", "-rn", "-f", "inet").Output()
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		if (fields[0] == "0.0.0.0/1" || fields[0] == "128.0.0.0/1") && strings.HasPrefix(fields[3], "utun") {
			st.TunRoutes = append(st.TunRoutes, line)
		}
	}

	if strings.HasPrefix(st.DefaultInterface, "utun") {
		st.Issues = append(st.Issues, "默认路由指向虚拟网卡 "+st.DefaultInterface+"，当前可能已断网")
	}
	if st.PhysicalIf == "" {
		st.Issues = append(st.Issues, "未找到可用的物理网卡")
	}
	if len(st.TunRoutes) > 0 {
		st.Issues = append(st.Issues, fmt.Sprintf("存在 %d 条指向 utun 的半路由", len(st.TunRoutes)))
	}

	st.Healthy = len(st.Issues) == 0
	return st
}

// Restore 清理残留的 TUN 路由并恢复默认路由
func Restore() ([]string, error) {
	var actions []string

	// 1. 删除 TUN 接管时写入的双半路由
	for _, prefix := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
		out, err := exec.Command("route", "-n", "delete", "-net", prefix).CombinedOutput()
		if err == nil {
			actions = append(actions, "已删除路由 "+prefix)
		} else if !strings.Contains(string(out), "not in table") {
			actions = append(actions, fmt.Sprintf("删除路由 %s 时提示：%s", prefix, strings.TrimSpace(string(out))))
		}
	}

	// 2. 重置默认路由到物理网关
	ifName, gw := physicalInterfaceAndGateway()
	if ifName == "" || gw == "" {
		return actions, fmt.Errorf("未能识别物理网卡或网关，请手动检查 `route -n get default`")
	}
	if _, err := exec.Command("route", "-n", "change", "default", gw).CombinedOutput(); err != nil {
		if out, addErr := exec.Command("route", "-n", "add", "default", gw).CombinedOutput(); addErr != nil {
			return actions, fmt.Errorf("恢复默认路由失败：%s", strings.TrimSpace(string(out)))
		}
	}
	actions = append(actions, fmt.Sprintf("默认路由已指向 %s（网关 %s）", ifName, gw))

	return actions, nil
}

func defaultRoute() (ifName string, gateway string, err error) {
	out, err := exec.Command("route", "-n", "get", "default").Output()
	if err != nil {
		return "", "", err
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "gateway:") {
			gateway = strings.TrimSpace(strings.TrimPrefix(line, "gateway:"))
		}
		if strings.HasPrefix(line, "interface:") {
			ifName = strings.TrimSpace(strings.TrimPrefix(line, "interface:"))
		}
	}
	if ifName == "" {
		return "", "", fmt.Errorf("默认路由中没有 interface 字段")
	}
	return ifName, gateway, nil
}

// physicalInterfaceAndGateway 找第一个已启用且带 IPv4 的 en* 网卡及其 DHCP 网关
func physicalInterfaceAndGateway() (string, string) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", ""
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if !strings.HasPrefix(iface.Name, "en") {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		hasIPv4 := false
		for _, addr := range addrs {
			if ipNet, ok := addr.(*net.IPNet); ok && ipNet.IP.To4() != nil {
				hasIPv4 = true
				break
			}
		}
		if !hasIPv4 {
			continue
		}
		out, err := exec.Command("ipconfig", "getoption", iface.Name, "router").Output()
		if err != nil {
			continue
		}
		gw := strings.TrimSpace(string(out))
		if gw != "" {
			return iface.Name, gw
		}
	}
	return "", ""
}
