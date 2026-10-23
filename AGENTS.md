# AGENTS.md

给 AI 编码助手的项目说明。人类请读 [README.md](README.md)。

## 这是什么

TunnelPilot — macOS 上按进程分流的透明代理。接管 utun 虚拟网卡，按「进程 + 域名 + 端口」规则决定直连 / 代理 / 代理链 / 阻断。

Go + cgo，不需要 Xcode 和 Apple 开发者账号。

## 构建与测试

```bash
./build.sh              # 编译 tunnelpilot + tunnelpilot-tray，并生成应用图标
./package.sh 1.0.1      # 打 universal binary（arm64 + x86_64）发布包到 dist/
go test -tags with_gvisor ./internal/rule ./internal/config ./internal/fakeip ./internal/proxy
```

**必须带 `-tags with_gvisor`**。sing-tun 的 Darwin 协议栈实现位于
`//go:build with_gvisor && darwin` 之后，漏掉标签会编出一个跑不起来的二进制，
运行时才报 `gVisor stack is unsupported on current platform`。

## 代码结构

| 目录 | 职责 |
|---|---|
| `internal/tunengine` | TUN 事件入口：`NewConnectionEx` / `NewPacketConnectionEx` / `NewDNSPacket` / `JudgeFlow` |
| `internal/tunmgr` | utun 生命周期、系统 DNS 接管、出站网卡绑定 |
| `internal/proxy` | 出站 dialer（直连 / SOCKS5 / SOCKS4a / HTTPS）、SOCKS5 UDP ASSOCIATE |
| `internal/rule` | 规则匹配，自上而下首个命中生效 |
| `internal/fakeip` | Fake-IP 分配与反查 |
| `internal/proc` | libproc 按源端口反查进程 |
| `internal/config` | 配置结构 + `.ppx` 导入导出 |
| `internal/netfix` | 路由诊断修复、DNS 备份恢复 |
| `cmd/tunnelpilot` | 主程序：daemon / install / uninstall / restore / status |
| `cmd/tunnelpilot-tray` | 菜单栏，cgo + Objective-C 调 Cocoa `NSStatusItem` |

## 硬约束（违反会直接把用户网络搞断）

1. **出站 socket 必须绑定物理网卡**（`setsockopt IP_BOUND_IF`）。全局路由已指向 utun，
   不绑定的出站连接会被路由回 utun 形成环路，表现为 `i/o timeout`。
2. **回环地址不能绑网卡**。本地代理常监听 `127.0.0.1`，绑了物理网卡会报
   `can't assign requested address`。
3. **Stop 必须先恢复 DNS、再拆网卡**。顺序反了会出现「DNS 指向已消失的接口」。
4. **系统 DNS 不能指向 TUN 接口自身地址**。客户端查询该地址时源地址也由路由决定，
   同样落在该地址上，写回响应时 `FindRoute` 的 local 与 remote 相同 → 路由自环。
   要用网段内其它地址（当前取 `/15` 的倒数第二个）。
5. **不要吞错误**。`_ = writer.WritePacket(...)` 这种写法让路由自环隐藏了三轮排查。

## 已经踩过的坑（改代码前先看）

| 症状 | 真因 |
|---|---|
| 域名规则完全不生效 | `JudgeFlow` 无条件返回 `ActionAccept`。sing-tun 只有收到 `ActionHijackDNS` 才会调 `NewDNSPacket` |
| 通配符规则匹配不上 | DNS 报文里的域名是 FQDN，**带末尾点**（`www.google.com.`），必须 `strings.TrimSuffix(name, ".")` |
| DNS 查询根本不进 utun | sing-tun 只在 Linux/Windows 上改系统 DNS，**Darwin 没有实现**，系统 DNS 仍指向路由器；而 AutoRoute 排除了局域网段 |
| DNS 有日志但客户端超时 | `UDPBackWriter` 把 `WritePacket` 入参当作**响应源地址**去查路由，传客户端地址会导致 local == remote |
| 菜单栏点退出又自己回来 | LaunchAgent `KeepAlive` 写死 `true`，应为 `SuccessfulExit=false` |
| git 忽略整个源码目录 | `.gitignore` 写 `tunnelpilot` 会匹配 `cmd/tunnelpilot/`，必须用前导斜杠 `/tunnelpilot` |

## 排查方法论（重要）

遇到「连不上 / 超时」时，先分清是哪一层，三种情况解法完全不同：

1. **包没进 utun** — 查路由 `route -n get <ip>`、`ifconfig utun10`
2. **包进了但没被处理** — 抓包 `sudo tcpdump -i utun10 -n 'port 53'`，
   看 `packets received by filter` 计数；再对照日志有无对应记录
3. **处理了但没回包** — 看 `WritePacket` / `Write` 是否返回错误

**不要靠猜**。这个项目三层嵌套（utun → gVisor → 协议解析），
在错误的层上打补丁会连续失败多轮。先取证，再改代码。

## 调试命令

```bash
tail -f /var/log/tunnelpilot.log          # 运行日志
curl -s 127.0.0.1:9090/api/status         # 接管状态
curl -s 127.0.0.1:9090/api/connections    # 连接列表（含命中规则与动作）
curl -s 127.0.0.1:9090/api/fakeip         # Fake-IP 映射（0 条说明 DNS 劫持没工作）
tunnelpilot status                        # 路由与 DNS 健康状况
sudo tunnelpilot restore                  # 兜底恢复：DNS + 路由
```

## 提交规范

- 一个 commit 只做一件事
- 涉及网络行为的改动，提交信息里写清「为什么」和「影响范围」
- 不要把 `Proxifier.app`、逆向分析报告之类的东西放进仓库
