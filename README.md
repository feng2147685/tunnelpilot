# TunnelPilot

macOS 上的按进程分流代理工具。接管全局流量后，按「进程 + 域名 + 端口」规则决定每个连接是直连、走代理、走代理链还是阻断——不需要在每个应用里单独配置代理。

纯 Go 实现，不依赖 Xcode，不需要 Apple 开发者账号。

## 特性

- **透明接管**：基于 utun 虚拟网卡 + 用户态 TCP/IP 协议栈，接管全部 TCP/UDP 流量
- **进程级分流**：通过 `libproc` 按源端口反查发起连接的进程（进程名 / 可执行路径 / Bundle ID）
- **域名级分流**：Fake-IP DNS 劫持，域名交由远端代理解析，避免本地 DNS 污染
- **代理协议**：SOCKS5（含用户名密码）、SOCKS4a、HTTPS CONNECT
- **代理链**：多跳串联、主备容灾、轮询负载均衡
- **UDP 转发**：SOCKS5 UDP ASSOCIATE，支持 QUIC / DNS over UDP 等场景
- **配置兼容**：导入导出 `.ppx` 配置文件
- **实时监控**：Web 控制台查看连接、命中规则、延迟与流量，支持按进程/动作/状态筛选
- **菜单栏控制**：一键启停接管，图标颜色表示当前状态

## 环境要求

- macOS 13 Ventura 或更高（在 macOS 15 上测试）
- 安装与运行时需要 `sudo`（创建 utun 需要 root）
- Go 1.24+ 仅编译时需要

## 安装

```bash
git clone <仓库地址> && cd tunnelpilot

# 编译（会自动生成图标并打包菜单栏应用）
./build.sh

# 安装为开机自启的常驻服务（只需执行一次）
sudo ./tunnelpilot install
```

安装后会创建：

| 项目 | 位置 |
|---|---|
| 主程序 | `/usr/local/bin/tunnelpilot` |
| 守护进程 | `/Library/LaunchDaemons/com.tunnelpilot.daemon.plist` |
| 配置文件 | `/Library/Application Support/TunnelPilot/config.json` |
| 日志 | `/var/log/tunnelpilot.log` |
| 菜单栏应用 | `/Applications/TunnelPilot.app` |

装完菜单栏右上角会出现图标：**p + 灰点**表示未接管，点菜单里的「启动接管」变**绿点**。

## 使用

打开控制台：<http://127.0.0.1:9090>

**代理服务器**页添加你的代理，**分流规则**页按顺序配置——自上而下第一个命中的规则生效：

| 规则 | 应用程序 | 目标主机 | 端口 | 动作 |
|---|---|---|---|---|
| 内网直连 | — | `192.168.*.*; 10.*.*.*; 127.0.0.1` | — | 直连 |
| AI 服务 | `ChatGPT; Cursor; node; curl` | `*.openai.com; *.anthropic.com` | 443 | 代理 |
| 兜底 | — | — | — | 直连 |

- 应用程序支持进程名、可执行路径、Bundle ID，留空匹配全部
- 目标主机支持通配符 `*.example.com`、IP、CIDR `10.0.0.0/8`
- 端口支持单个值或范围 `8000-8100`

## 命令行

```bash
sudo tunnelpilot              # 前台运行（调试用，Ctrl+C 退出并恢复路由）
tunnelpilot status            # 查看网络与路由是否健康
sudo tunnelpilot restore      # 恢复被异常修改的路由
sudo tunnelpilot uninstall    # 卸载服务与菜单栏应用
```

## 故障恢复

如果进程被强制杀死（不是 Ctrl+C）导致无法上网：

```bash
tunnelpilot status            # 确认默认路由是否指向 utun
sudo tunnelpilot restore      # 清理残留路由，恢复默认网关
```

仍不通就关闭再打开 Wi-Fi，或重启系统。

## 工作原理

```
应用流量
   ↓
utun 虚拟网卡（内核路由接管）
   ↓
gVisor 用户态网络栈（还原 TCP/UDP 流）
   ↓
libproc 反查进程 + Fake-IP 还原域名
   ↓
规则匹配（进程 / 域名 / IP / 端口）
   ↓
直连 ─ 单代理 ─ 代理链 ─ 阻断
```

出站 socket 会绑定物理网卡（`IP_BOUND_IF`），避免流量被全局路由重新送回 utun 形成环路；回环地址（本地代理）不绑定。

## 已知限制

- UDP 走代理仅支持 SOCKS5；HTTPS / SOCKS4 下的 UDP 会回退直连
- 进程识别依赖「源端口反查」，极短命的连接可能识别不到
- 修改代理服务器地址后需要重启服务（防环路由在启动时计算）；只改规则即时生效
- 未实现 IPv6 分流

## 免责声明

本软件会接管系统全部网络流量并需要 root 权限。使用前请确认你了解其行为，并自行承担由此产生的风险，包括但不限于网络中断、流量泄漏、规则配置错误导致的连接异常。作者不对任何直接或间接损失负责。

请遵守你所在地区的法律法规。

## 许可证

GPL-3.0。本项目链接了 GPL-3.0 的 [sing-tun](https://github.com/SagerNet/sing-tun) 与 [sing](https://github.com/SagerNet/sing)，因此整体以 GPL-3.0 发布。

## 致谢

- [sing-tun](https://github.com/SagerNet/sing-tun) — utun 抽象与 Darwin 平台实现
- [gVisor](https://gvisor.dev/) — 用户态 TCP/IP 协议栈
- [miekg/dns](https://github.com/miekg/dns) — DNS 报文处理
