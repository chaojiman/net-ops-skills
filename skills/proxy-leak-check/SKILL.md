---
name: proxy-leak-check
description: >-
  在客户端本机（macOS / Windows / Linux）诊断代理形态（TUN vs 系统代理）、国内外分流、
  三层 DNS 泄露（Fake-IP / 系统原生 / 代理远端）、IPv4/IPv6 UDP STUN 与 WebRTC 泄露、浏览器防护扩展状态，
  以及 Mihomo/Clash 逐节点 UDP 转发巡检（自动揪出漏写 udp: true 的暗雷节点）。
  触发词：DNS 泄露、WebRTC 泄露、检查代理、检查节点、检查 TUN、UDP 转发、IP 送中、代理体检、代理配置对不对。
  不用于 VPS 服务端部署（请用 nat-vps-proxy），也不用于落地出口 IP 纯净度/风控测速验收（请用 ipsock-check）。
---

# proxy-leak-check：本机代理防泄露与节点体检

目标：用实测证据在 30 秒内判定当前设备的代理形态、DNS 泄露、WebRTC/UDP 穿透、分流准确性与 Mihomo 节点 `udp` 隐患。

## 适用客户端

- **Mihomo / Clash 系**：Bettbox、Clash Verge Rev、Mihomo Party / Sparkle、FlClash（自动接入本地控制 API 逐节点体检）。
- **其他客户端**：Surge、Stash、Loon、Shadowrocket、v2rayN、sing-box、Hiddify（系统层、DNS、UDP STUN、SOCKS5 UDP 与浏览器体检）。

## 安全与只读铁律

1. **绝不泄露凭据**：脚本仅在内存中读取控制端口 `secret`，严禁输出或索取 `secret`、`uuid`、`password`、`public-key` 或订阅 URL。
2. **绝不破坏原状态**：`--audit-nodes` / `--node` 会临时切换活跃策略组（可能中断长连接），**执行前须 🔴 CHECKPOINT 确认**，脚本以 `try ... finally` 恢复原节点。
3. **分享必脱敏 & 默认只读**：分享报告或贴出排障数据时必加 **`--redact`** 打码公网 IP/节点名；**修改配置或重启客户端前须 🔴 CHECKPOINT 确认**。

## 第 1 步：分流执行或离线诊断

- **本机实测**：运行 [scripts/check_proxy_leak.py](./scripts/check_proxy_leak.py)（纯 Python 3 标准库 + `curl`，`v1.1.1`，无 `references/` 目录；Windows 用 `python` + `pwsh` 7）：

```bash
python3 <skill_dir>/scripts/check_proxy_leak.py                 # 全面只读体检（系统代理/ProxyOverride/TUN/分流/三层DNS/双栈STUN/SOCKS5 UDP/浏览器）
python3 <skill_dir>/scripts/check_proxy_leak.py --json --redact # 脱敏 JSON 留档或分享
python3 <skill_dir>/scripts/check_proxy_leak.py --audit-nodes   # 🔴 逐节点巡检 udp=false 暗雷与出口一致性
python3 <skill_dir>/scripts/check_proxy_leak.py --node "关键词" --proxy 127.0.0.1:7890 --api 127.0.0.1:9090
```

- **离线样本 / 咨询排障**：当用户已提供体检 JSON 或仅询问故障排查时，跳过本机实跑，直接基于样本按第 3 步判定并给出脱敏复测命令（使用 `<skill_dir>` 占位而非临时绝对路径）。

## 第 2 步：可选的真实浏览器复验

如需从真实浏览器视角复核，打开以下检测页核对 DNS 与 WebRTC（测完关闭临时页）：

- 综合检测：`https://ipleak.net/`
- DNS 深度检测：`https://browserleaks.com/dns`
- WebRTC 深度检测：`https://browserleaks.com/webrtc`

## 第 3 步：判定红黄绿标准

向用户汇报时，首句直给结论，按以下 6 项标明状态（✅ 正常 / ⚠️ 隐患 / ❌ 泄露）：

1. **代理形态与分流**：`mode` 应为 `rule`；国内探测（`myip.ipip.net`）返回海外 IP 说明误开全局或规则缺失。日常桌面办公用 `规则 + 系统代理` 更防送中；命令行 / 不认系统代理的 App 需切 `TUN 模式`。
2. **DNS 泄露**：经代理访问 `edns.ip-api.com/json` 须返回海外解析器，不得出现国内运营商 DNS；TUN 模式下系统解析海外域应命中 Fake-IP（`198.18.x.x`）。
3. **WebRTC / UDP STUN**：
   - **TUN 模式**：直连 UDP STUN（v4 & v6）应返回代理出口 IP 或被阻断；返回本地家宽 IPv4 或公网 IPv6（如 `2409:`/`240e:`/`2408:`）即 UDP/IPv6 逃逸泄露 ❌。
   - **系统代理模式**：裸 UDP 不走 HTTP 代理属正常，重点查浏览器是否启用原生 WebRTC 策略 `disable_non_proxied_udp`（`Preferences` 中 `webrtc.ip_handling_policy` 或企业策略 `WebRtcIPHandling`），且 `SOCKS5 UDP ASSOCIATE` 返回代理出口 IP。
4. **Mihomo 节点暗雷**：存活节点漏写 `udp: true` 时默认 `udp=false`，TUN 下会静默回落直连暴露家宽 IP，重点检查是否混入 `url-test` 或中转组。
5. **出口一致性**：对比 TCP IP、UDP STUN IP 与 DNS 归属地是否匹配。
6. **认知纠偏**：送中主要源于误开全局将国产特征带往海外节点；本机系统代理还是 TUN 对外部网络不可见，不影响被封概率。

## 第 4 步：跨平台修复与失败模式兜底

- **客户端层**：在覆写脚本中仅对**未声明 `udp`（`proxy.udp === undefined`）**的节点补 `udp: true`（严禁强改显式 `udp: false` 节点，若服务端不支持 UDP 会导致断流）；启用 `dns.enhanced-mode: fake-ip`；macOS TUN 确认 Service Mode 且 `scutil --dns` 指向虚拟网卡；无 v6 出口时关闭 `dns.ipv6`。
- **浏览器层**：优先配置原生策略 `disable_non_proxied_udp`（Chrome/Edge 写入 `Preferences` 的 `webrtc.ip_handling_policy` 或企业策略键 `WebRtcIPHandling`，勿误写为 `WebRtcIPHandlingPolicy`）；**禁止推荐全站注入的 `WebRTC Control` 扩展**；关闭浏览器 DoH；Firefox 设 `media.peerconnection.enabled = false`。
- **常见失败兜底**：
  - **Windows 系统代理 + Tailscale `100.64.0.0/10` 断连（如 noVNC WebSocket 掐断）** → WinINet `ProxyOverride` **不支持 CIDR**（写 `100.64.0.0/10` 无效），须在绕过列表补 `100.*` 或精确 IP（如 `100.64.0.20`），或改用 `ssh -N -L 127.0.0.1:<本地端口>:<TS_IP>:<远端端口>` 走回环。
  - **控制 API 9090/9097 自动探测失败** → 通过 `--api host:port` 显式传入；系统代理下直连 STUN 返回本地 IP 属正常，切勿误判为故障。
  - **本机防漏全绿但出口脏/断连** → 出口纯净度转 **`ipsock-check`**；服务端节点超时或协议报错转 **`nat-vps-proxy`**；跨境 Tailscale 组网、自建无 SNI DERP 中继或内网分流套娃/降速转 **`tailscale-derp-ops`**。
