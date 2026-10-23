package main

/*
#cgo CFLAGS: -x objective-c -fobjc-arc
#cgo LDFLAGS: -framework Cocoa -framework Foundation
#include <stdlib.h>
#include "tray.h"
*/
import "C"

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"time"
	"unsafe"
)

const apiBase = "http://127.0.0.1:9090"

// statusResponse 描述守护进程状态，兼容模式下不再接管全局流量。
type statusResponse struct {
	Compatibility bool   `json:"fakeip_compatibility"`
	Running       bool   `json:"running"`
	TunName       string `json:"tun_name"`
	UID           int    `json:"uid"`
}

var (
	mu        sync.Mutex
	running   bool
	busy      bool
	ifaceName string
)

//export goMenuAction
func goMenuAction(action C.int) {
	switch int(action) {
	case C.CF_TRAY_TOGGLE:
		go toggle()
	case C.CF_TRAY_OPEN:
		openConsole()
	case C.CF_TRAY_QUIT:
		// 只退出菜单栏图标，守护进程与代理配置保持不变
		C.tray_stop()
	case C.CF_TRAY_QUIT_STOP:
		// 先让守护进程停止接管（恢复系统路由），再退出图标
		go func() {
			_ = post("/api/tun/stop")
			time.Sleep(600 * time.Millisecond)
			C.tray_stop()
		}()
	}
}

func init() {
	// 关键：Cocoa 的 NSStatusItem 必须在进程主线程创建。
	// Go 的 main 函数不保证运行在主线程上，必须锁定 OS 线程。
	runtime.LockOSThread()
}

func main() {
	// 预览/校验模式：导出三种状态的图标后退出
	if len(os.Args) > 2 && os.Args[1] == "--export-icons" {
		dir := C.CString(os.Args[2])
		C.tray_export_icons(dir)
		C.free(unsafe.Pointer(dir))
		return
	}

	cTitle := C.CString("代理")
	C.tray_init(cTitle)
	C.free(unsafe.Pointer(cTitle))

	go func() {
		refresh()
		ticker := time.NewTicker(3 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			refresh()
		}
	}()

	C.tray_run()
}

// refresh 刷新菜单栏状态，缓存兼容与全局接管分别显示。
// param 无；后台不可达时显示错误，不更改系统网络。
func refresh() {
	mu.Lock()
	wasBusy := busy
	mu.Unlock()
	if wasBusy {
		return
	}

	resp, err := http.Get(apiBase + "/api/status")
	if err != nil {
		render(false, false, "无法连接后台服务（未安装或未启动）", "启动接管")
		return
	}
	defer resp.Body.Close()

	var status statusResponse
	if err = decodeJSON(resp, &status); err != nil {
		render(false, false, "后台状态解析失败", "启动接管")
		return
	}

	mu.Lock()
	running = status.Running
	ifaceName = status.TunName
	mu.Unlock()

	if status.UID != 0 {
		render(false, false, "后台未以 root 运行，无法接管流量", "启动接管")
		return
	}
	if running {
		render(true, false, "已接管全局流量 · "+status.TunName, "停止接管")
	} else if status.Compatibility {
		render(false, false, "已停止接管 · 缓存连接直连兼容", "启动接管")
	} else {
		render(false, false, "未接管流量（系统直连）", "启动接管")
	}
}

func toggle() {
	mu.Lock()
	if busy {
		mu.Unlock()
		return
	}
	target := !running
	busy = true
	mu.Unlock()

	if target {
		render(false, true, "正在启动接管…", "请稍候")
	} else {
		render(true, true, "正在停止接管…", "请稍候")
	}

	endpoint := "/api/tun/start"
	if !target {
		endpoint = "/api/tun/stop"
	}

	err := post(endpoint)

	mu.Lock()
	busy = false
	mu.Unlock()

	if err != nil {
		render(running, false, "操作失败: "+err.Error(), "重试")
		return
	}
	time.Sleep(300 * time.Millisecond)
	refresh()
}

func render(isRunning, isBusy bool, statusText, toggleText string) {
	cStatus := C.CString(statusText)
	cToggle := C.CString(toggleText)
	defer C.free(unsafe.Pointer(cStatus))
	defer C.free(unsafe.Pointer(cToggle))

	r := 0
	if isRunning {
		r = 1
	}
	b := 0
	if isBusy {
		b = 1
	}
	C.tray_update(C.int(r), C.int(b), cStatus, cToggle)
}

func post(path string) error {
	resp, err := http.Post(apiBase+path, "application/json", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}

func openConsole() {
	_ = exec.Command("open", apiBase).Start()
}

func decodeJSON(resp *http.Response, v any) error {
	return json.NewDecoder(resp.Body).Decode(v)
}

var _ = os.Args
