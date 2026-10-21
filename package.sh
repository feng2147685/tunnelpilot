#!/bin/sh
# 打包可分发的 universal binary（arm64 + x86_64）发布包
#
# 用法: ./package.sh [版本号]
set -e
cd "$(dirname "$0")"

VERSION=${1:-1.0.0}
NAME="TunnelPilot-${VERSION}"
DIST="dist"

rm -rf "$DIST"
mkdir -p "$DIST/build/arm64" "$DIST/build/amd64" "$DIST/$NAME"

build_universal() {
	target=$1
	pkg=$2
	echo "  编译 ${target}（arm64 + x86_64）..."
	GOARCH=arm64 CGO_ENABLED=1 go build -tags with_gvisor -ldflags "-s -w" -o "$DIST/build/arm64/$target" "$pkg"
	GOARCH=amd64 CGO_ENABLED=1 go build -tags with_gvisor -ldflags "-s -w" -o "$DIST/build/amd64/$target" "$pkg"
	lipo -create -output "$DIST/$NAME/$target" "$DIST/build/arm64/$target" "$DIST/build/amd64/$target"
	codesign --force --sign - "$DIST/$NAME/$target" 2>/dev/null || true
}

echo "生成应用图标..."
go run ./tools/icongen -o build/AppIcon.icns >/dev/null
mkdir -p cmd/tunnelpilot/assets
cp build/AppIcon.icns cmd/tunnelpilot/assets/AppIcon.icns

echo "编译 universal binary..."
build_universal tunnelpilot ./cmd/tunnelpilot
build_universal tunnelpilot-tray ./cmd/tunnelpilot-tray

cp README.md LICENSE "$DIST/$NAME/"

cat > "$DIST/$NAME/安装说明.txt" <<'EOF'
TunnelPilot 安装说明
====================

【1】解除隔离
macOS 会拦截从网络下载的程序，先执行：
    xattr -dr com.apple.quarantine .

【2】安装
    sudo ./tunnelpilot install

安装后会：
  · 注册开机自启的守护进程
  · 菜单栏出现 p 图标（灰点=未接管，绿点=已接管）
  · 启动管理界面 http://127.0.0.1:9090

【3】配置
浏览器打开 http://127.0.0.1:9090
  · 「代理服务器」添加你的代理（SOCKS5 / SOCKS4 / HTTPS CONNECT）
  · 「分流规则」按顺序配置，第一个命中的规则生效

【4】卸载
    sudo ./tunnelpilot uninstall

【5】无法上网时
    tunnelpilot status        查看路由是否异常
    sudo tunnelpilot restore  恢复系统默认路由

注意：本程序需要 root 权限接管系统流量，使用前请阅读 README 中的免责声明。
EOF

echo "打包 zip..."
(cd "$DIST" && zip -rq "${NAME}.zip" "$NAME")

echo
echo "完成：dist/${NAME}.zip"
ls -lh "$DIST/${NAME}.zip"
echo
echo "校验架构："
lipo -info "$DIST/$NAME/tunnelpilot"
