# 跨境 Tailscale / DERP 实测沉淀日志（多 Agent 共享演化库）

## Agent 写入与脱敏规范（新增条目前必读）

欢迎后续使用 `tailscale-derp-ops` 的所有 Agent 将新发现的真实踩坑、客户端特性变化、云商网络行为与量化实测沉淀到此文件：

1. **禁止入库敏感词**：严禁写入任何真实公网 IP（IPv4/IPv6）、真实 Tailscale IP、MagicDNS 域名（统一用 `tail000000.ts.net`）、个人域名/子域（用 `derp.example.com`）、个人主机名、本机用户名路径、真实邮箱、证书真实 `sha256-raw` 指纹、UUID/密钥/Token。公网 IP 示例一律用 RFC 5737（`198.51.100.x`、`203.0.113.x`）与 RFC 3849（`2001:db8::/32`）。
2. **统一条目模板**：
   ```markdown
   ### [YYYY-MM-DD] 一句话标题（核心结论）
   - **环境与条件**：客户端/服务端版本、网络形态、前置变更
   - **现象与误区**：表面看起来像什么
   - **实测证据**：命令输出或内核/日志量化数据
   - **最终结论与规避方案**：可执行修复动作
   - **验证状态**：已实测闭环 / 待复验
   ```
3. **强制提交门禁**：每次编辑本文件后，必须在仓库根目录执行 `python3 tools/privacy_scan.py`（输出 `0 风险项`）并核对 `git status`（勿误提交 `local.md` / `.privacy-denylist.local`）。

---

## 历史沉淀条目

### [2026-11-26] 域名遇 DNSSEC CAA 失败与 GFW SNI RST 时，改用 `-certmode=manual` 无 SNI 双栈 IP 证书
- **环境与条件**：自建 DERP 机（双栈公网 `198.51.100.10` / `2001:db8:20:ed::1`），`derper v1.104.7`，国内运营商双栈出口。
- **现象与误区**：免费二级域名申请 ACME 报上游 DNSSEC NSEC `CAA SERVFAIL`，且手动测试 TLS 握手在发出 `ClientHello` 后立即收到 TCP RST。
- **实测证据**：同机切换 ECDSA P-256 双栈 IP-SAN 自签证书（`DERPPort: 34433`, `STUNPort: 34478`, `CertName: "sha256-raw:..."`），OpenSSL 直连 `https://198.51.100.10:34433/` 与 `https://[2001:db8:20:ed::1]:34433/` 均稳定返回 `HTTP 200`（`-home=blank` 响应体为 0）；Windows `curl.exe` Schannel 会误报 `SEC_E_INVALID_TOKEN`（系 Schannel 对无 SNI 自签 IP 证书的自身限制，不影响 Tailscale Go TLS 栈）。
- **最终结论与规避方案**：高风险后缀或免费域名不要硬扛 ACME，直接上双栈 IP-SAN 手动证书 + `CertName` 指纹钉死，实现零 SNI TLS 握手。
- **验证状态**：已实测闭环。

### [2026-11-26] `--verify-clients` 遇低权限 `tag` 节点互拒与 `icmp:*` 语法坑
- **环境与条件**：自建 DERP 机与同级受限节点均标记为 `tag:vps-low`，ACL 默认不授予 `tag:vps-low` 互访。
- **现象与误区**：DERP 开启 `--verify-clients` 后误拒自家 `tag:vps-low` 节点入站；修改 ACL 时写 `"ip": ["icmp"]` 保存报错。
- **实测证据**：Tailscale ACL `grants` 中必须使用 `"icmp:*"`；补上 `{"src":["tag:vps-low"],"dst":["tag:vps-low"],"ip":["icmp:*"]}` 后，`netmap` 下发同级节点公钥、`--verify-clients` 立即放行，且 `tests` 确认零开放 TCP/UDP 端口。
- **最终结论与规避方案**：低权限标签节点承载 `--verify-clients` DERP 时，须额外放通同级 `icmp:*` 以允许公钥同步。
- **验证状态**：已实测闭环。

### [2026-11-26] 阻断 UDP 41641 必须挂 `-t mangle` 并放行 STUN `--sport 3478/34478`
- **环境与条件**：Linux `tailscaled` + `iptables` / `ip6tables` 仅允许海外同伴互打洞、禁止跨境裸打洞。
- **现象与误区**：规则写在 `filter INPUT` 会在 `tailscaled` 重启插入 `ts-input ACCEPT` 后失效；若切到 `mangle` 却忘放 STUN 回包，会发现 `Self.Addrs` 变成空，海外合法打洞一并瘫痪。
- **实测证据**：`tailscaled` 以 `:41641` 为源端口发送 STUN，回包特征为 `--sport 3478/34478 --dport 41641`。加入双栈 `mangle` `PREROUTING`/`OUTPUT` 并放行 `3478/34478` 后，`Self.Addrs` 恢复公网 `:41641`，海外两台 VPS 成功建立直连（~55 Mbps），国内客户端完全走 DERP 且 `direct connection not established`。
- **最终结论与规避方案**：防打洞策略必须落在 `-t mangle`，并显式放行 `3478` 与自定义 STUN 端口入出站。
- **验证状态**：已实测闭环。

### [2026-11-26] ACL 非对称双官方中继限速（0.37 → 56/89 Mbps）与单滞后官方兜底法
- **环境与条件**：国内控制端（家宽双栈）↔ 美区 VPS，默认开启全部官方 DERP（含 `hkg`、`iad`、`sin` 等）。
- **现象与误区**：国内去程落美东 `iad`、美区回程落香港 `hkg`，形成非对称双官方中继，下载仅 `0.371 Mbps`；误以为把 `hkg` 单独留作兜底即可，实测 `hkg` 家宽 RTT（~42ms）快于自建邻区（~44.5ms），立刻抢走主中继拖回低速。
- **实测证据**：在 ACL `derpMap` 将除 `sin`（ID=3）与自建 `901` 外的 26 个官方 Region 全部置 `null`（`sin` 在双端 `netcheck` 上均比自建慢 ~23–25ms）：双端稳锁自建 `901`，单流下行提速至 `56.08 Mbps（+151x）`，4 并发达 `89.41 Mbps（+270x）`，同时保留了断线自动切 `sin` 的兜底能力。
- **最终结论与规避方案**：保留单一「双端均比自建慢 20~30ms」的官方 Region 作无抢流兜底，其余官方 Region 置 `null`。
- **验证状态**：已实测闭环。

### [2026-11-26] Windows Bettbox 与 iOS Shadowrocket 的私有地址/域名排除规则恰好相反
- **环境与条件**：Windows Mihomo（系统代理 + 外部官方 Tailscale Wintun）vs iOS Shadowrocket（单 VPN 进程内置用户态 Tailscale）。
- **现象与误区**：用户常误把两个客户端的私有地址排除列表照抄互通，导致一端断连或策略组失效。
- **实测证据**：
  1. Windows 外部 Wintun：`绕过私有网络` 必须保留 `100.64.0.0/10` 与 `fd7a:115c:a1e0::/48`（防未来开 TUN 黑洞），`排除域名` 绝不能加 `100.*`/`*.ts.net`（否则跳过 `Tailscale-VPS`），且浏览器必须使用 `100.x` IP 或完整 `.ts.net` 避开系统代理 `<local>`。
  2. iOS 单进程：`tun-excluded-routes` 绝不能包含 `100.64.0.0/10`，`Tailscale-VPS` 回退内置 TS 时须选 `TAILSCALE`（非 `DIRECT`）。
- **最终结论与规避方案**：严格按「外挂网卡 vs 单进程内置」区分两套排除列表。
- **验证状态**：已实测闭环。

### [2026-11-26] Shadowrocket `.tailscale.com` 冲突与「控制服务器/始终 DERP」开关误区
- **环境与条件**：iOS Shadowrocket 规则末尾包含 `global.list`（含 `.tailscale.com` 走代理）。
- **现象与误区**：未前置 DERP 域名直连时，内置 TS 容易将官方 DERP 域名送进代理导致套娃；误以为在「控制服务器 URL」填自建 DERP 地址或开启「始终使用 DERP」可加速。
- **实测证据**：在 `[Rule]` 第 0 段（位于 `100.64/10` 与 `global.list` 之前）加入 `DOMAIN-WILDCARD,derp*.tailscale.com,DIRECT`，即可单独直连官方 DERP 并让 `controlplane.tailscale.com` 继续走代理；「控制服务器 URL」仅用于 Headscale，填 DERP 地址会直接认证失败断网。
- **最终结论与规避方案**：前置自建 DERP IP + `DOMAIN-WILDCARD,derp*.tailscale.com,DIRECT`，控制服务器保持留空。
- **验证状态**：已实测闭环。

### [2026-11-26] 用 `ss -tinp` + `derper` 日志拆解 iOS 小火箭内置 TS 卡顿根因（`128KB` 窗口 + 断连 + `+87ms`）
- **环境与条件**：同一本地 Wi-Fi 下，桌面端官方 Tailscale 与 iOS Shadowrocket 内置 TS 同时经自建 DERP 连同一美区 VPS。
- **现象与误区**：同在 `901` 自建 DERP 中继下，美区 VPS `tailscale ping` 桌面端稳定 `243ms`，`ping` iOS 端却高达 `330ms`（固定多 `+87ms`），吞吐仅 `~0.3 Mbps`。
- **实测证据**：在自建 DERP 宿主机运行 `sudo ss -tinp '( sport = :34433 )'` 与 `journalctl -u derper` 拆段得出：
  - 共用段 `美区 VPS ↔ DERP` 完全一致（`minrtt 196.5ms`）；
  - 桌面端段：IPv6 直连 `minrtt 44.2ms`、`rtt 64.2ms`、`snd_wnd 16.78 MB`、`cwnd 6928`、0 超时；
  - iOS 内置 TS 段：IPv4 CGNAT `minrtt 57.6ms`（`+13.4ms`）、`rtt 113.3ms`（Wi-Fi 省电 + `NEPacketTunnelProvider` 用户态滞后 `+74ms`）、`snd_wnd 128 KB`（小 128 倍）、`cwnd 20`，且每 30~50 秒出现 `read: connection timed out` 引发换键闪断与跳连兜底 DERP。
- **最终结论与规避方案**：移动端访问海外 VPS 内网 Web/SSH 服务时，彻底**关闭小火箭内置 Tailscale**，让流量命中 `Tailscale-VPS → 链式落地`（前置中转 + 落地 `sing-box` 本机入站），实测下行直接恢复 `30+ Mbps` 且零断连、更省电。
- **验证状态**：已实测闭环。

### [2026-11-26] 目标 VPS 开启防 SSRF 时，`sing-box` 须为自身 Tailscale 服务网段显式前置放行
- **环境与条件**：海外落地 VPS 的 `sing-box` 已按安全加固配置拦截 `100.64.0.0/10 -> reject`，同时手机/电脑通过 `Tailscale-VPS → 链式落地` 访问该 VPS 仅监听于 Tailscale IP（如 `100.64.0.20:8093`）的管理面。
- **现象与误区**：若不区分自身内网服务，全段 `reject` 会导致链式访问自己的 `100.x:8093` 也报连接被拒。
- **实测证据**：在 `sing-box` `route.rules` 的 `100.64.0.0/10 reject` 规则**之前**，只针对本机（或经 ACL 授权的单向内网接收端）精准 IP 插入 `direct` 出站放行，既保持对其余 CGNAT / 云元数据 SSRF 的拦截，又让链式直通内网导航/SSH 稳定可用。
- **最终结论与规避方案**：防 SSRF 拦截规则前为受控的自身/下级 Tailscale 单 IP 开精确白名单。
- **验证状态**：已实测闭环。
