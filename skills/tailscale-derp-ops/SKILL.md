---
name: tailscale-derp-ops
description: >-
  跨境 Tailscale 自建加密 DERP 中继部署、无 SNI 双栈 IP 证书绕过 SNI 阻断、
  iptables/ip6tables mangle 阻断跨境 UDP 41641 裸打洞并保留海外互通、
  Tailscale ACL derpMap 防非对称双中继限速收口、客户端（Mihomo/Bettbox 与 Shadowrocket）防套娃分流与链式落地替代，
  以及内核 TCP ss -tinp 与 derper 日志分段排障。
  触发词：Tailscale 很慢、Tailscale 中继、自建 DERP、derper、IP 证书无 SNI、derpMap、防止打洞、跨境 Tailscale 卡顿、小火箭内置 Tailscale 卡、Tailscale-VPS。
  不用于常规代理节点部署（请用 nat-vps-proxy）、出口 IP 纯净度测速（请用 ipsock-check）或本机通用防泄露体检（请用 proxy-leak-check）。
---

# tailscale-derp-ops：跨境 Tailscale / 自建 DERP 组网与排障

目标：解决跨境 Tailscale 在被运营商阻断直连、被迫回落官方 DERP 时的**非对称双中继限速、域名 SNI 阻断、客户端规则套娃、移动端内置用户态断连卡顿**五大难题，实现桌面端数十 Mbps 稳态传输与移动端稳定替代。

> 若本技能同目录存在 `local.md`（本地私有备注，不入库），执行前先一并读取。

## 适用边界与先验决策树

开始调优前，先按终端形态选路，避免无效折腾：

| 终端场景 | 推荐主力路径 | 实测物理特征 | 备选兜底路径 |
| :--- | :--- | :--- | :--- |
| **桌面端**（Windows / macOS / Linux 官方 `tailscaled` + 有线/稳定 Wi-Fi） | 邻区自建无 SNI 双栈 `derper` + ACL `derpMap` 收口 | 内核 `snd_wnd` 可达十余 MB，单流可达 **~50+ Mbps**，4 并发 **~80+ Mbps**，长连接零断连 | 代理客户端设 `Tailscale-VPS → 链式落地`（目标服务经加密代理直达目标机内网路由） |
| **移动端**（iOS Shadowrocket 等单 VPN 内置用户态 Tailscale） | **关闭内置 Tailscale**，客户端规则直接分流 `Tailscale-VPS → 链式落地` | iOS `NEPacketTunnelProvider` 内存配额受限（`snd_wnd` 常被压在 `~128 KB`）、Wi-Fi 省电唤醒加时 `+70ms+` 且易 30~50s 静默断连 | 仅在访问国内家宽内网设备或代理全挂救急时临时打开内置 Tailscale 并选 `TAILSCALE` |
| **纯海外 VPS 间**（如邻区 DERP ↔ 美区/亚太业务机） | 保持裸 WireGuard UDP `:41641` 互打洞直连 | 同境/跨洋 UDP 打洞延迟最稳，实测轻松 **50+ Mbps**，不消耗中继内存与单流开销 | 自动经邻区自建 DERP 中继转发 |

## 第 0 步：先测底线，别盲调

在改动服务端或 ACL 前，分别在控制端与目标 VPS 上抓取基线：

```bash
tailscale status
tailscale netcheck
tailscale ping --c=6 --timeout=3s <对端_Tailscale_IP>
```

重点判断 3 件事：
1. **是直连还是 DERP 中继**：`tailscale status` 中对应 peer 若出现 `direct <IP>:<PORT>` 为打洞直连；若为 `relay "<code>"` 或 `tailscale ping` 显示 `via DERP(...)`，说明处于中继态。
2. **是否出现非对称双中继**：A 端 `netcheck` 离 `iad`（或 `sin`）最近，B 端离 `hkg` 最近时，去程与回程会分走两个不同官方 DERP，叠加公网 QoS/限速，单流极易跌至 `< 0.5 Mbps`。
3. **跨国公网 UDP 是否主动封禁**：若为了防恶意扫描与运营商 UDP QoS 已封禁跨境 UDP `:41641`，不要再反复尝试客户端开启「强制/不强制打洞」，应直接走自建 DERP 或代理链式替代。

## 第 1 步：部署无 SNI 双栈 IP 证书 DERP 节点

当免费域名或二级后缀遭遇 **DNSSEC/CAA `SERVFAIL`** 或 **TLS ClientHello SNI 被主动 TCP RST 阻断** 时，直接放弃域名证书，改用 `derper` 官方 `-certmode=manual` IP 证书模式（RFC 6066 规定 TLS 客户端连接 IP 字面量时不发送 `server_name` SNI 扩展）：

- 生成 10 年双栈 IP-SAN（同时写入公网 IPv4 与标准层 IPv6）ECDSA P-256 证书，写入 `/etc/derper/certs/<IPv4>.{crt,key}`。
- 必开安全双参数：**`--verify-clients`**（拒绝一切未加入本 Tailnet 的陌生人白嫖）与 **`-home=blank`**（隐藏默认 DERP 特征首页）。
- 提取 **`sha256-raw:<64位hex指纹>`** 写入 Tailscale ACL `derpMap` 的 `CertName` 字段，并把 `HostName`/`IPv4`/`IPv6` 全部填为 IP 字面量。
- **权限联动硬坑**：若 DERP 宿主机贴了隔离权限标签（如 `tag:vps-low`），必须在 ACL `grants` 中放通同级标签至少 `icmp:*`（不可简写 `icmp`），否则宿主机 `tailscaled` 无法同步同级节点公钥，导致 `--verify-clients` 误拒自家节点。

详细证书生成脚本、systemd 模板、OpenSSL vs Windows Schannel 验收避坑与卸载回滚命令，见 [references/derper-ip-cert-and-mangle.md](./references/derper-ip-cert-and-mangle.md)。

## 第 2 步：服务端 `mangle` 阻断跨境裸打洞

若要求目标 VPS 与自建 DERP 绝不对国内客户端暴露 WireGuard UDP `:41641` 打洞，同时放行「海外 VPS 之间互打洞 + 本机回环 + 同 VPC 内网」，**规则严禁只写在 `filter INPUT`**：

- **必须挂在 `iptables/ip6tables -w 5 -t mangle` 的 `PREROUTING` 与 `OUTPUT` 链**：`tailscaled` 重启时会在 `filter INPUT 1` 插入 `ts-input` 无条件放行 `:41641`，唯有 `mangle` 先行判定才能防绕过。
- **必放 STUN 回包特征**：`tailscaled` 从源端口 `41641` 向 DERP 发送 STUN 探测，回包特征为 `--sport 3478` / `--sport 34478 --dport 41641`。白名单若漏放 `--sport 3478/34478`，会导致 `Self.Addrs` 变空、连合法海外打洞也一并失效。

完整双端（DERP 中继机 & 海外业务机）持久化脚本与 systemd 单元模板，见 [references/derper-ip-cert-and-mangle.md](./references/derper-ip-cert-and-mangle.md)。

## 第 3 步：Tailscale ACL `derpMap` 精准收口（防抢流与无感兜底）

Tailscale 的原生机制是**每个节点独立选择离自己 `netcheck` 延迟最低的 DERP 当「收件箱」（Home DERP），对端发包直投你的收件箱**：

- **不要留比自建延迟更低的官方邻区节点**：例如家宽直连 `hkg` 42ms 而直连自建邻区 DERP 为 45ms 时，只要 `hkg` 未被屏蔽，本地 Home DERP 就会被 `hkg` 抢走，回程依然跌回 `< 0.5 Mbps`。
- **精准兜底方案**：`OmitDefaultRegions` 设 `false`，显式将除「1 个双端 RTT 均比自建慢 20~30ms 的官方节点」（如两端对 `sin` 均慢 ~25ms）之外的其余全部官方 Region 设为 `null`。平时 0 抢流稳锁自建，自建宕机时自动切到该单一官方兜底，无需人工改 ACL。

完整脱敏 `derpMap` JSON 模板、`tests` 回归用例与实测提速对照，见 [references/acl-derpmap-and-clients.md](./references/acl-derpmap-and-clients.md)。

## 第 4 步：双端客户端防套娃分流与链式替代

**Windows（Mihomo / Bettbox，外部独立 `Tailscale` Wintun 网卡）**：
- `绕过私有网络`（`route-exclude-address`）**必须保留** `100.64.0.0/10` 与 `fd7a:115c:a1e0::/48`；`排除域名`（`bypassDomain`）**严禁加入** `100.*` 或 `*.ts.net`（否则系统代理无法把目标 VPS 流量送入 `Tailscale-VPS` 策略组）。
- Windows 系统代理默认附带 `<local>` 会自动跳过不含点 `.` 的短主机名，浏览器访问内网服务务必使用 `100.x` IP 或完整 `host.tail000000.ts.net`。
- WinINet `ProxyOverride` 不支持 CIDR（写 `100.64.0.0/10` 无效），需要让浏览器直连 Tailscale IP 时应写 `100.*` 或精确 IP。

**iOS（Shadowrocket 等，单 VPN 进程内置用户态 Tailscale）**：
- `tun-excluded-routes` **绝不能写** `100.64.0.0/10`；规则组中兜底回退走内置 TS 时须选内置策略 `TAILSCALE`（非 `DIRECT`）。
- `[Rule]` 最前段必须把自建 DERP 双栈 IP/域名及 **`DOMAIN-WILDCARD,derp*.tailscale.com,DIRECT`** 放在 `100.64.0.0/10,TAILSCALE` 与 `global.list`（含 `.tailscale.com`）之前，防中继流量被套娃代理，同时保留 `controlplane.tailscale.com` 正常走代理。
- 当 iOS 内置 TS 打开时，会在 `[Rule]` 前截胡 `100.64/10` 与 `*.ts.net`；实测若持续遇卡顿、高延迟或每 30~50s 断连，应**直接关闭内置 TS 开关**，让 `[Rule]` 将目标海外 VPS 送入 `Tailscale-VPS → 链式落地`（经目标机本机代理入口直接访问其内网回环/Tailscale IP，前提是目标机 `sing-box` 放行自身目标内网 IP 走 `direct`）。

双端完整规则顺位、Shadowrocket 开关常见误区（控制服务器 URL / 始终使用 DERP）及目标机放行配置，见 [references/acl-derpmap-and-clients.md](./references/acl-derpmap-and-clients.md)。

## 第 5 步：内核级延迟与吞吐分段排障

当终端体感发卡但 `netcheck` 看似正常时，直接上自建 DERP 宿主机抓内核 TCP 套接字状态，1 毫秒级区分责任归属：

```bash
# 1. 在 DERP 节点查看端口 34433 各端内核 RTT、拥塞窗口与接收窗口
sudo ss -tinp '( sport = :34433 )'

# 2. 查看近 15 分钟 derper 超时丢连与节点切键事件
sudo journalctl -u derper --since "15 minutes ago" --no-pager

# 3. 对比两端：桌面端有线/IPv6 vs 移动端 Wi-Fi/IPv4 CGNAT
# 重点看 minrtt(物理下限) / rtt(含ACK延迟) / snd_wnd(窗口上限) / cwnd / bbr估算带宽
```

- 前段 `DERP ↔ 目标 VPS` 共用段 `minrtt` 恒定时，差值全部位于 `DERP ↔ 客户端`：常见原因包括移动端走 IPv4 CGNAT 绕路（`+10~15ms`）、Wi-Fi 省电唤醒（`+50ms+`）、用户态仅给 `~128 KB` `snd_wnd`，以及 `derper` 日志频繁报错 `read: connection timed out` 触发 `disco key` 重建与闪切备用中继。

详细排障判据与对比实例，见 [references/acl-derpmap-and-clients.md](./references/acl-derpmap-and-clients.md)。

## 多 Agent 协作沉淀与演化规范（必读）

本 Skill 设计为可跨会话、跨 Agent 宿主的共享工程知识库。**任何 Agent 在实际排障、压测或适配新客户端时若获得新结论或发现新坑，请严格按以下 4 步回写维护**：

1. **沉淀通用结论与更新日志**：
   - 将可复用的通用结论按模板追加到 [references/findings-log.md](./references/findings-log.md)（写清日期、环境条件、现象、实测指标、根因与结论、验证状态）。
   - 若某条结论已稳定成为通用法则，同步精炼更新至 `SKILL.md` 对应章节或 `references/` 参考文档，并在仓库根目录 `CHANGELOG.md` 递增修订记录。
2. **严格隔离个人环境隐私（`local.md`）**：
   - 任何涉及用户真实公网 IP、Tailscale IP、MagicDNS 域名、个人主机名、云项目名、真实邮箱、证书指纹或私有规则仓库路径的笔记，**只允许写入同目录 `local.md`**（已被 `.gitignore` 忽略）。
   - 严禁在 `SKILL.md`、`references/*`、`README.md`、`CHANGELOG.md` 中写入任何真实资产标识，统一使用 RFC 5737/3849（`198.51.100.x`、`203.0.113.x`、`2001:db8::`）、CGNAT 示例（`100.64.0.x`）、`tail000000.ts.net` 与 `<占位符>`。
3. **提交前强制隐私扫描（0 容忍门禁）**：
   ```bash
   python3 ../../tools/privacy_scan.py   # Windows 使用 python
   ```
   必须输出 **`✅ 隐私与凭据扫描通过（0 风险项）`**，且同步跑通 Python 语法校验后方允许 `git commit` 与 `git push`。
4. **工作区与跟踪清单复核**：
   - 提交前运行 `git status --short` 与 `git diff --cached --name-only`，确认 **未误加入** `local.md`、`.privacy-denylist.local`、`test-prompts.json` 或临时报告/截图。

## 下一步联动

- 若需从零搭建或加固跨境落地/中转 `sing-box`、`shoes` 或 `realm` 服务端（含「6 进 4 出」与防 SSRF 配置），请使用 **`nat-vps-proxy`**。
- 若需对链式落地出口 IP 做纯净度、风控探活与四维安全测速，请使用 **`ipsock-check`**。
- 若需排查本机系统代理 / TUN / DNS / WebRTC 泄露与 Mihomo 节点 `udp: true` 隐患，请使用 **`proxy-leak-check`**。
