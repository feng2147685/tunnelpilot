package main

import (
	_ "embed"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"tunnelpilot/internal/api"
	"tunnelpilot/internal/config"
	"tunnelpilot/internal/fakeip"
	"tunnelpilot/internal/logx"
	"tunnelpilot/internal/netfix"
	"tunnelpilot/internal/proc"
	"tunnelpilot/internal/proxy"
	"tunnelpilot/internal/rule"
	"tunnelpilot/internal/tunengine"
	"tunnelpilot/internal/tunmgr"
)

const (
	launchdLabel = "com.tunnelpilot.daemon"
	plistPath    = "/Library/LaunchDaemons/com.tunnelpilot.daemon.plist"
	installDir   = "/Library/Application Support/TunnelPilot"
	binaryDst    = "/usr/local/bin/tunnelpilot"
	appBundle    = "/Applications/TunnelPilot.app"
	logPath      = "/var/log/tunnelpilot.log"
)

//go:embed assets/AppIcon.icns
var appIconData []byte

var apiServer *api.Server

// main 解析命令并组装控制台与 TUN 守护进程。
// param 由命令行提供；无返回值，启动及退出清理错误写入日志，管理界面仅监听本机。
func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "install":
			if err := installDaemon(); err != nil {
				fmt.Fprintln(os.Stderr, "安装失败:", err)
				os.Exit(1)
			}
			return
		case "uninstall":
			if err := uninstallDaemon(); err != nil {
				fmt.Fprintln(os.Stderr, "卸载失败:", err)
				os.Exit(1)
			}
			return
		case "restore":
			runRestore()
			return
		case "status":
			runStatus()
			return
		}
	}

	var (
		configPath = flag.String("config", defaultConfigPath(), "配置文件路径")
		verbose    = flag.Bool("v", false, "输出调试日志")
		noTun      = flag.Bool("no-tun", false, "只启动管理界面，不接管流量")
		daemon     = flag.Bool("daemon", false, "以 launchd 常驻模式运行")
	)
	flag.Parse()

	logger := logx.New(*verbose)

	profile, err := api.LoadProfile(*configPath)
	if err != nil {
		profile = config.DefaultProfile()
		logger.Info("未找到已有配置，已生成默认配置: ", *configPath)
		_ = api.SaveProfile(profile, *configPath)
	} else {
		logger.Info("已加载配置: ", *configPath)
	}

	pool := fakeip.New(profile.FakeIPPrefixValue())
	rules := rule.New(profile)
	dialer := proxy.New()
	resolver := proc.NewResolver(3 * time.Second)

	logSink := func(line string) {
		logger.Info(line)
		if apiServer != nil {
			apiServer.AppendLog(line)
		}
	}

	handler := tunengine.NewHandler(resolver, rules, dialer, pool, logSink)

	var tunManager *tunmgr.Manager
	if os.Geteuid() == 0 {
		tunManager = tunmgr.New(func() *config.Profile {
			return rules.Profile()
		}, handler, dialer, logger)
	}

	// 注意：必须显式转成接口变量。直接把 (*tunmgr.Manager)(nil) 赋给接口
	// 会产生「非 nil 接口持有 nil 指针」，导致 s.tun != nil 判断失效并 panic。
	var tunController api.TUNController
	if tunManager != nil {
		tunController = tunManager
	}

	apiServer = api.New(api.Options{
		Profile:    profile,
		Rules:      rules,
		Handler:    handler,
		Pool:       pool,
		ConfigPath: *configPath,
		TUN:        tunController,
	})

	go func() {
		addr := fmt.Sprintf("127.0.0.1:%d", profile.ListenPort)
		logger.Info("管理界面已启动: http://", addr)
		if err := http.ListenAndServe(addr, apiServer.Handler()); err != nil {
			logger.Error("管理界面启动失败: ", err)
		}
	}()

	if tunManager != nil && !*noTun {
		if err = tunManager.Start(); err != nil {
			logger.Error("接管流量失败: ", err)
			if *daemon {
				logger.Error("常驻模式下接管失败，5 秒后重试")
				time.Sleep(5 * time.Second)
				if err = tunManager.Start(); err != nil {
					logger.Error("重试仍失败: ", err)
				}
			} else {
				logger.Error("请以 root 运行，或检查是否有其他程序占用 utun")
			}
		}
	} else if tunManager == nil {
		logger.Warn("非 root 运行，仅提供管理界面。接管流量请执行: sudo tunnelpilot install")
	}

	if *daemon {
		logger.Info("常驻模式已就绪")
	}

	waitSignal()

	if tunManager != nil {
		if err = tunManager.Close(); err != nil {
			logger.Error("退出时清理失败: ", err)
		}
	}
}

// ---------------------------------------------------------------------------
// 网络状态诊断与恢复
// ---------------------------------------------------------------------------

func runStatus() {
	st := netfix.Diagnose()
	fmt.Println("当前网络状态")
	fmt.Println("  默认路由网卡:", orDash(st.DefaultInterface))
	fmt.Println("  默认网关:    ", orDash(st.DefaultGateway))
	fmt.Println("  物理网卡:    ", orDash(st.PhysicalIf))
	fmt.Println("  物理网关:    ", orDash(st.PhysicalGateway))
	if netfix.HasDNSBackup() {
		fmt.Println("  系统 DNS:    存在未恢复的备份（接管中，或异常退出残留）")
	} else {
		fmt.Println("  系统 DNS:    正常")
	}
	if len(st.TunRoutes) > 0 {
		fmt.Println("  残留 TUN 路由:", len(st.TunRoutes), "条")
	}
	if st.Healthy {
		fmt.Println("  结论:        正常")
		return
	}
	fmt.Println("  结论:        异常")
	for _, issue := range st.Issues {
		fmt.Println("    -", issue)
	}
	fmt.Println()
	fmt.Println("如需修复请执行: sudo tunnelpilot restore")
}

// runRestore 按 DNS、路由的顺序执行管理员恢复，任何 DNS 残留都会返回非零退出码。
// param 无；无返回值，失败输出明确错误并保留 DNS 备份供重试。
func runRestore() {
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "需要 root 权限，请用 sudo tunnelpilot restore")
		os.Exit(1)
	}
	// 先恢复 DNS，再修路由：否则 DNS 仍指向已消失的虚拟网卡，域名全部解析失败
	n, dnsErr := netfix.RestoreDNSFromBackup()
	if dnsErr != nil {
		fmt.Fprintln(os.Stderr, "恢复 DNS 失败:", dnsErr)
	} else if n > 0 {
		fmt.Printf("  已恢复 %d 个网络服务的 DNS\n", n)
	}

	actions, err := netfix.Restore()
	for _, a := range actions {
		fmt.Println("  " + a)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "恢复失败:", err)
		os.Exit(1)
	}
	if dnsErr != nil {
		fmt.Fprintln(os.Stderr, "路由已处理，但 DNS 尚未恢复；备份已保留，请重试 restore。")
		os.Exit(1)
	}
	fmt.Println("网络配置已恢复。若仍无法上网，请关闭并重新打开 Wi-Fi。")
}

func orDash(s string) string {
	if s == "" {
		return "(未识别)"
	}
	return s
}

// ---------------------------------------------------------------------------
// launchd 常驻安装 / 卸载
// ---------------------------------------------------------------------------

func installDaemon() error {
	if os.Geteuid() != 0 {
		return errors.New("安装需要 root 权限，请用 sudo tunnelpilot install")
	}

	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}

	if err = os.MkdirAll(filepath.Dir(binaryDst), 0755); err != nil {
		return err
	}
	if err = copyFile(exe, binaryDst, 0755); err != nil {
		return fmt.Errorf("复制程序到 %s 失败: %w", binaryDst, err)
	}

	// 配置文件统一到系统目录，保证 daemon（root）与界面访问的是同一份
	if err = os.MkdirAll(installDir, 0755); err != nil {
		return err
	}
	systemConfig := filepath.Join(installDir, "config.json")
	if _, err = os.Stat(systemConfig); err != nil {
		// 依次尝试历史上出现过的配置位置，避免升级后配置丢失
		var candidates []string
		if home, herr := os.UserHomeDir(); herr == nil {
			candidates = append(candidates,
				filepath.Join(home, ".tunnelpilot", "config.json"),
				filepath.Join(home, ".cfproxifier", "config.json"))
		}
		candidates = append(candidates, "/Library/Application Support/CFProxifier/config.json")
		for _, old := range candidates {
			if _, serr := os.Stat(old); serr == nil {
				if cerr := copyFile(old, systemConfig, 0644); cerr == nil {
					fmt.Println("已迁移现有配置:", old, "->", systemConfig)
					break
				}
			}
		}
	}
	if _, err = os.Stat(systemConfig); err != nil {
		p := config.DefaultProfile()
		if serr := api.SaveProfile(p, systemConfig); serr != nil {
			return serr
		}
	}

	plist := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>%s</string>
	<key>ProgramArguments</key>
	<array>
		<string>%s</string>
		<string>-daemon</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>StandardOutPath</key>
	<string>%s</string>
	<key>StandardErrorPath</key>
	<string>%s</string>
</dict>
</plist>
`, launchdLabel, binaryDst, logPath, logPath)

	if err = os.WriteFile(plistPath, []byte(plist), 0644); err != nil {
		return err
	}

	// 先卸载旧实例，避免重复注册
	_ = exec.Command("launchctl", "unload", "-w", plistPath).Run()
	out, err := exec.Command("launchctl", "load", "-w", plistPath).CombinedOutput()
	if err != nil {
		return fmt.Errorf("加载 launchd 服务失败: %v, 输出: %s", err, string(out))
	}

	fmt.Println("已安装并启动常驻服务")
	fmt.Println("  服务标识:", launchdLabel)
	fmt.Println("  程序路径:", binaryDst)
	fmt.Println("  配置文件:", systemConfig)
	fmt.Println("  日志路径:", logPath)

	if err = installTrayAgent(filepath.Dir(exe)); err != nil {
		fmt.Println("菜单栏图标安装跳过:", err)
	} else {
		fmt.Println("菜单栏图标已安装，登录后自动出现在右上角")
	}

	fmt.Println()
	fmt.Println("以后开机自动运行，无需再输密码。")
	return nil
}

// installTrayAgent 把菜单栏程序打包成 .app 并注册为当前用户的登录项。
// 必须打成 .app：裸二进制没有 bundle identifier，macOS 不会稳定渲染 NSStatusItem。
func installTrayAgent(exeDir string) error {
	user := os.Getenv("SUDO_USER")
	if user == "" {
		return errors.New("无法确定当前用户（SUDO_USER 为空）")
	}
	traySrc := filepath.Join(exeDir, "tunnelpilot-tray")
	if _, err := os.Stat(traySrc); err != nil {
		return errors.New("未找到 tunnelpilot-tray，请确认与 tunnelpilot 在同一目录")
	}

	// 1. 组装 .app 包
	macosDir := filepath.Join(appBundle, "Contents", "MacOS")
	if err := os.MkdirAll(macosDir, 0755); err != nil {
		return err
	}
	trayExe := filepath.Join(macosDir, "tunnelpilot-tray")
	if err := copyFile(traySrc, trayExe, 0755); err != nil {
		return err
	}

	// 应用图标
	resDir := filepath.Join(appBundle, "Contents", "Resources")
	if err := os.MkdirAll(resDir, 0755); err != nil {
		return err
	}
	if len(appIconData) > 0 {
		if err := os.WriteFile(filepath.Join(resDir, "AppIcon.icns"), appIconData, 0644); err != nil {
			return err
		}
	}

	infoPlist := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleIdentifier</key>
	<string>com.tunnelpilot.tray</string>
	<key>CFBundleName</key>
	<string>TunnelPilot</string>
	<key>CFBundleDisplayName</key>
	<string>TunnelPilot</string>
	<key>CFBundleExecutable</key>
	<string>tunnelpilot-tray</string>
	<key>CFBundlePackageType</key>
	<string>APPL</string>
	<key>CFBundleIconFile</key>
	<string>AppIcon</string>
	<key>CFBundleShortVersionString</key>
	<string>1.0.0</string>
	<key>CFBundleVersion</key>
	<string>1</string>
	<key>LSUIElement</key>
	<true/>
	<key>NSHighResolutionCapable</key>
	<true/>
</dict>
</plist>
`
	if err := os.WriteFile(filepath.Join(appBundle, "Contents", "Info.plist"), []byte(infoPlist), 0644); err != nil {
		return err
	}
	// ad-hoc 签名，避免 Gatekeeper 拦截
	_ = exec.Command("codesign", "--force", "--deep", "--sign", "-", appBundle).Run()

	// 2. 注册为用户登录项
	home := filepath.Join("/Users", user)
	agentDir := filepath.Join(home, "Library", "LaunchAgents")
	if err := os.MkdirAll(agentDir, 0755); err != nil {
		return err
	}

	// KeepAlive 用 SuccessfulExit=false：异常崩溃才重新拉起，
	// 用户主动「退出」时进程以 0 退出，不会被 launchd 再次唤醒。
	plist := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>com.tunnelpilot.tray</string>
	<key>ProgramArguments</key>
	<array>
		<string>%s</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<dict>
		<key>SuccessfulExit</key>
		<false/>
	</dict>
	<key>ThrottleInterval</key>
	<integer>5</integer>
</dict>
</plist>
`, trayExe)

	plistFile := filepath.Join(agentDir, "com.tunnelpilot.tray.plist")
	if err := os.WriteFile(plistFile, []byte(plist), 0644); err != nil {
		return err
	}
	_ = exec.Command("chown", "-R", user+":staff", appBundle).Run()
	_ = exec.Command("chown", user+":staff", plistFile).Run()
	_ = exec.Command("su", user, "-c", "launchctl unload -w "+plistFile).Run()
	if out, err := exec.Command("su", user, "-c", "launchctl load -w "+plistFile).CombinedOutput(); err != nil {
		return fmt.Errorf("加载登录项失败: %v %s", err, string(out))
	}
	return nil
}

// uninstallDaemon 在恢复 DNS 后移除守护进程与菜单栏应用。
// param 无；返回权限、恢复或卸载错误，DNS 恢复失败时保留服务与原始备份。
func uninstallDaemon() error {
	if os.Geteuid() != 0 {
		return errors.New("卸载需要 root 权限，请用 sudo tunnelpilot uninstall")
	}
	// 防止守护进程没走正常退出流程时 DNS 残留在虚拟网卡上
	if n, err := netfix.RestoreDNSFromBackup(); err != nil {
		return fmt.Errorf("卸载前恢复 DNS 失败，已保留服务和备份供重试: %w", err)
	} else if n > 0 {
		fmt.Printf("已恢复 %d 个网络服务的 DNS\n", n)
	}
	out, err := exec.Command("launchctl", "unload", "-w", plistPath).CombinedOutput()
	if err != nil {
		fmt.Println("停止服务失败（可能未运行）:", string(out))
	}
	if err = os.Remove(plistPath); err != nil && !os.IsNotExist(err) {
		return err
	}

	// 同时卸载菜单栏登录项
	if user := os.Getenv("SUDO_USER"); user != "" {
		agentFile := filepath.Join("/Users", user, "Library", "LaunchAgents", "com.tunnelpilot.tray.plist")
		_ = exec.Command("su", user, "-c", "launchctl unload -w "+agentFile).Run()
		_ = os.Remove(agentFile)
		_ = exec.Command("pkill", "-f", "TunnelPilot").Run()
		_ = os.RemoveAll(appBundle)
		fmt.Println("菜单栏登录项已移除")
	}

	fmt.Println("已卸载常驻服务，系统路由已恢复")
	return nil
}

func copyFile(src, dst string, perm os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	defer out.Close()
	if _, err = io.Copy(out, in); err != nil {
		return err
	}
	return out.Chmod(perm)
}

func waitSignal() {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
}

// defaultConfigPath root 与界面共用系统路径，避免两边读到不同配置
func defaultConfigPath() string {
	systemConfig := filepath.Join(installDir, "config.json")
	if os.Geteuid() == 0 {
		return systemConfig
	}
	if _, err := os.Stat(systemConfig); err == nil {
		return systemConfig
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "tunnelpilot.json"
	}
	return filepath.Join(home, ".tunnelpilot", "config.json")
}
