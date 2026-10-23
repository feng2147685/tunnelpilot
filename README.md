<div align="center">
  <img src="docs/app-icon.png" width="120" alt="TunnelPilot">
  <h1>TunnelPilot</h1>
  <p>macOS 上按进程分流的透明代理工具</p>
  <p>
    <b>中文</b> · <a href="README.en.md">English</a>
  </p>
</div>

接管系统全部流量后，按「进程 + 域名 + 端口」规则决定每个连接是直连、走代理、走代理链还是阻断——不需要在每个应用里单独配代理。纯 Go 实现，不需要 Xcode，不需要 Apple 开发者账号。

![控制台](docs/screenshot-console.png)

## 特性

- **透明接管**：utun 虚拟网卡 + 用户态 TCP/IP 协议栈，覆盖全部 TCP/UDP 流量
- **进程级分流**：`libproc` 按源端口反查发起连接的进程（进程名 / 路径 / Bundle ID）
- **域名级分流**：Fake-IP DNS 劫持，域名交由远端代理解析，避免本地 DNS 污染
- **代理协议**：SOCKS5（含认证）、SOCKS4a、HTTPS CONNECT
- **代理链**：多跳串联、主备容灾、轮询负载均衡
- **UDP 转发**：SOCKS5 UDP ASSOCIATE，覆盖 QUIC、DNS over UDP 等场景
- **配置兼容**：导入导出 `.ppx` 配置文件
- **实时监控**：连接列表可按进程、动作、状态筛选
- **菜单栏控制**：一键启停，图标即时反映当前状态

## 菜单栏状态

| 已接管 | 未接管 | 切换中 |
|:---:|:---:|:---:|
| <img src="docs/tray-started.png" width="72"> | <img src="docs/tray-stopped.png" width="72"> | <img src="docs/tray-starting.png" width="72"> |

## 环境要求

- macOS 13 Ventura 或更高（在 macOS 15 上验证）
- 安装与运行需要 `sudo`（创建 utun 需要 root）
- 从源码编译需要 Go 1.24+

## 安装

### 方式一：下载发布包（推荐）

到 Releases 页面下载 `TunnelPilot-*.zip`，解压后：

```bash
cd TunnelPilot-1.0.0
xattr -dr com.apple.quarantine .   # 解除 macOS 对下载程序的隔离
sudo ./tunnelpilot install
```

### 方式二：从源码编译

```bash
git clone https://github.com/feng2147685/tunnelpilot.git
cd tunnelpilot
./build.sh
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

## 使用

打开控制台：<http://127.0.0.1:9090>

先在**代理服务器**页添加你的代理，再到**分流规则**页配置。规则自上而下匹配，**第一个命中的生效**：

![分流规则](docs/screenshot-rules.png)

| 规则 | 应用程序 | 目标主机 | 端口 | 动作 |
|---|---|---|---|---|
| 内网直连 | — | `192.168.*.*; 10.*.*.*; 127.0.0.1` | — | 直连 |
| AI 服务 | `ChatGPT; Cursor; node` | `*.openai.com; *.anthropic.com` | 443 | 代理 |
| 开发工具 | `git; curl; go` | `*.github.com; *.githubusercontent.com` | 443, 22 | 代理 |
| 阻断遥测 | — | `telemetry.*; *.app-measurement.com` | — | 阻断 |
| Default | — | — | — | 直连 |

- 应用程序支持进程名、可执行路径、Bundle ID，留空匹配全部
- 目标主机支持通配符 `*.example.com`、IP、CIDR `10.0.0.0/8`
- 端口支持单值或范围 `8000-8100`
- 改规则即时生效；改代理服务器地址需重启服务（防环路由在启动时计算）

## 命令行

```bash
sudo tunnelpilot              # 前台运行，调试用（Ctrl+C 退出并恢复路由）
tunnelpilot status            # 查看默认路由与网关是否正常
sudo tunnelpilot restore      # 恢复被异常修改的路由
sudo tunnelpilot uninstall    # 卸载服务与菜单栏应用
```

## 故障恢复

如果进程被强制杀死（而不是 Ctrl+C）导致无法上网：

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

出站 socket 绑定物理网卡（`IP_BOUND_IF`），避免流量被全局路由重新送回 utun 形成环路；回环地址（本地代理）不绑定。

## 网络修复版验证

源码中的修复尚未代表已安装服务或 Release 包已更新。可先运行不修改系统网络的检查：

```bash
go test -race -tags with_gvisor ./internal/tunengine ./internal/proxy ./internal/netfix ./internal/fakeip ./internal/rule ./internal/proc ./internal/config ./internal/tunmgr
./build.sh
```

这些检查覆盖回环 TCP/UDP、SOCKS5 UDP 中继、代理握手期限、TCP 半关闭、DNS 报文与备份恢复失败，不创建 utun，不改变系统 DNS 或路由。

实际接管仍需单独验证：确认本地代理已运行，开启接管，分别检查直连网站、代理网站及指定应用；用普通 DNS 和 TCP DNS 查询同一域名，再确认控制台命中的规则及实际访问结果。最后停止接管，确认原 DNS 配置和普通网络访问恢复。接管或恢复报错时保留日志与 DNS 备份，使用 `sudo tunnelpilot restore` 重试。

DNS 的 A 查询先保留域名映射，再在连接阶段结合真实应用、目标端口决定动作。直连目标、代理服务器域名及必要的 IP/CIDR 判断通过绑定网卡的独立上游解析，避免再次查询被接管的系统 DNS。当前独立上游为 `223.5.5.5` 与 `119.29.29.29`；使用内部 DNS 或无法访问公共 DNS 的网络仍需另行验证。修改 Fake-IP 网段后需重启整个守护进程。

## 已知限制

- UDP 走代理仅支持 SOCKS5；HTTPS / SOCKS4、代理链或关联失败时会结束 UDP 会话，不会自动改成直连。使用 HTTP 代理时，依赖 QUIC 的应用需自行回退 TCP
- 进程识别依赖源端口反查，极短命的连接可能识别不到
- 修改代理服务器地址后需重启服务
- 未实现 IPv6 分流；接管 DNS 时 AAAA 查询返回空记录，使用 A 记录进行 IPv4 分流。这不能覆盖绕过系统 DNS 的 DoH 或直接 IPv6 连接

## 免责声明

本软件会接管系统全部网络流量并需要 root 权限。使用前请确认你了解其行为，并自行承担由此产生的风险，包括但不限于网络中断、流量泄漏、规则配置错误导致的连接异常。作者不对任何直接或间接损失负责。

请遵守你所在地区的法律法规。

## 许可证

[GPL-3.0](LICENSE)。本项目链接了 GPL-3.0 的 [sing-tun](https://github.com/SagerNet/sing-tun) 与 [sing](https://github.com/SagerNet/sing)，因此整体以 GPL-3.0 发布。

## 致谢

- [sing-tun](https://github.com/SagerNet/sing-tun) — utun 抽象与 Darwin 平台实现
- [gVisor](https://gvisor.dev/) — 用户态 TCP/IP 协议栈
- [miekg/dns](https://github.com/miekg/dns) — DNS 报文处理
