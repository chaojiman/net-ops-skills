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

> 若本技能同目录存在 `local.md`（本地私有备注，不入库），执行前先一并读取。

## 适用客户端

- **Mihomo / Clash 系**：Bettbox、Clash Verge Rev、Mihomo Party / Sparkle、FlClash（支持自动接入本地控制 API 逐节点体检）。
- **其他客户端**：Surge、Stash、Loon、Shadowrocket、v2rayN、sing-box、Hiddify（支持系统层、DNS、UDP STUN、SOCKS5 UDP 与浏览器体检）。

## 安全与只读铁律

1. **绝不泄露凭据**：脚本仅在内存中读取本地控制端口 `secret`，严禁输出任何 `secret`、`uuid`、`password`、`public-key` 或订阅 URL。
2. **绝不破坏原状态**：使用 `--audit-nodes` / `--node` 临时切节点复测时，`try ... finally` 严格恢复原有默认代理组与选中节点。
3. **分享报告必脱敏**：准备贴到 Issue 或发给他人时，务必加 **`--redact`** 打码真实出口 IP、本机 IPv6 与节点名。
4. **默认只读诊断**：未经用户明确要求，不擅自修改配置文件或重启客户端。

## 第 1 步：运行跨平台体检脚本

脚本位于 [scripts/check_proxy_leak.py](./scripts/check_proxy_leak.py)（纯 Python 3 标准库 + 系统 `curl`，零外部依赖，最低版本 `1.1.0`）：

```bash
# 基础全面体检（代理形态 + 分流 + 三层 DNS + IPv4/IPv6 UDP STUN + SOCKS5 UDP + 浏览器扫描）
python3 <skill_dir>/scripts/check_proxy_leak.py

# 逐节点巡检（Mihomo/Clash 系：查 udp=false 暗雷、TCP/UDP 出口一致性与 DNS 归属）
python3 <skill_dir>/scripts/check_proxy_leak.py --audit-nodes

# 仅复测指定节点（按关键字匹配）
python3 <skill_dir>/scripts/check_proxy_leak.py --node "关键词"

# 脱敏输出 JSON（适合留档或分享排障）
python3 <skill_dir>/scripts/check_proxy_leak.py --json --redact
```

> Windows 环境下将 `python3` 替换为 `python`，优先在 `pwsh` 7 下运行。更新检查请运行 `git ls-remote --tags --refs --sort=-v:refname origin 'v*'`，由用户手动 `git pull --ff-only`。

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
   - **系统代理模式**：裸 UDP 不走 HTTP 代理属正常，重点查浏览器是否装有 WebRTC 防护扩展，且 `SOCKS5 UDP ASSOCIATE` 返回代理出口 IP。
4. **Mihomo 节点暗雷**：存活节点漏写 `udp: true` 时默认 `udp=false`，TUN 下会静默回落直连暴露家宽 IP，重点检查是否混入 `url-test` 或中转组。
5. **出口一致性**：对比 TCP IP、UDP STUN IP 与 DNS 归属地是否匹配。
6. **认知纠偏**：送中主要源于误开全局将国产特征带往海外节点；本机系统代理还是 TUN 对外部网络不可见，不影响被封概率。

## 第 4 步：跨平台修复建议

- **客户端层**：在覆写脚本中对未声明 `udp` 的节点统一补 `udp: true`；启用 `dns.enhanced-mode: fake-ip`；macOS TUN 确认已授权 Service Mode 且 `scutil --dns` 指向虚拟网卡；无 v6 出口时关闭 `dns.ipv6` 避免 v6 逃逸。
- **浏览器层**：安装 **WebRTC Control** 或 **WebRTC Leak Prevent**（策略 `Disable non-proxied UDP`）；浏览器内安全 DNS（DoH）保持关闭交给客户端统一分流；Firefox 可将 `media.peerconnection.enabled` 设为 `false`。

## 下一步联动

- 若本机防漏全部通过但仍怀疑出口 IP 脏或链路慢 → 运行 **`ipsock-check`**；
- 若发现服务端节点超时或协议报错 → 按 **`nat-vps-proxy`** 错误对照表排查服务端。
