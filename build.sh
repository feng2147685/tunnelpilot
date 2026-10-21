#!/bin/sh
# 构建 tunnelpilot 与菜单栏图标 tunnelpilot-tray（macOS 原生二进制，不需要 Xcode）
#
# 注意：必须带 with_gvisor 标签。sing-tun 在 Darwin 上的 gVisor 用户态协议栈
# 实现位于 //go:build with_gvisor && darwin 之后，不加这个标签编不进去，
# 运行时会报 "gVisor stack is unsupported on current platform"。
set -e
cd "$(dirname "$0")"

echo "生成应用图标..."
go run ./tools/icongen -o build/AppIcon.icns >/dev/null
mkdir -p cmd/tunnelpilot/assets
cp build/AppIcon.icns cmd/tunnelpilot/assets/AppIcon.icns

echo "编译主程序（含 gVisor 用户态协议栈）..."
go build -tags with_gvisor -ldflags "-s -w" -o tunnelpilot ./cmd/tunnelpilot

echo "编译菜单栏图标..."
go build -tags with_gvisor -ldflags "-s -w" -o tunnelpilot-tray ./cmd/tunnelpilot-tray

# ad-hoc 签名：没有 Apple 开发者账号时，让本机 Gatekeeper 不再拦截
codesign --force --sign - tunnelpilot 2>/dev/null && echo "已签名 tunnelpilot" || echo "跳过签名"
codesign --force --sign - tunnelpilot-tray 2>/dev/null && echo "已签名 tunnelpilot-tray" || echo "跳过签名"

echo
echo "完成："
ls -lh tunnelpilot tunnelpilot-tray
