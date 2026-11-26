# net-ops-skills

面向跨平台（Windows / macOS / Linux）的网络节点部署、出口 IP 质量验收、客户端防泄露排查与跨境 Tailscale/DERP 组网排障 Agent Skill 合集。所有内置脚本仅依赖 **Python 3 标准库 + 系统 `curl`**，零第三方包安装。

## 技能总览与联动顺序

四个技能各自独立、互不 import 代码，可整库安装或单独拆用，按完整运维链路分工：

- **[`skills/nat-vps-proxy`](./skills/nat-vps-proxy/SKILL.md)**（服务端部署层）
  - 在 Linux / NAT / 低内存（72MB~256MB）小鸡上部署 `sing-box` / `shoes` / `realm`，完成端口映射、内存调优、出口族锁定、安全加固、服务端体检与接入客户端链式。
- **[`skills/ipsock-check`](./skills/ipsock-check/SKILL.md)**（出口验收层）
  - 验收新购静态住宅代理（SOCKS5/HTTP）或已接链式落地 VPS 的出口质量：多轮出口固定性、v4/v6 分离检查、四库纯净度交叉校验、风控站点/验证码探活、全链路延迟稳定性与多源防 429 测速、统一四维体感测速口径。
- **[`skills/proxy-leak-check`](./skills/proxy-leak-check/SKILL.md)**（本机防漏层）
  - 在本机（Windows / macOS / Linux）诊断代理形态（TUN vs 系统代理）、国内外分流、三层 DNS 泄露、IPv4/IPv6 UDP STUN 与 WebRTC 泄露，以及 Mihomo/Clash 逐节点 `udp: true` 隐患排查。
- **[`skills/tailscale-derp-ops`](./skills/tailscale-derp-ops/SKILL.md)**（跨境组网与中继层）
  - 部署无 SNI 双栈 IP 证书自建 `derper`、`mangle` 防跨境 UDP 41641 裸打洞同时保留海外互连、Tailscale ACL `derpMap` 精准收口防非对称双中继降速、双端（Mihomo vs Shadowrocket）防套娃分流与链式替代，以及内核 `ss -tinp` 分段排障。

### 典型使用顺序

- **新落地 VPS 上线**：`nat-vps-proxy`（建机 + 接入客户端链式） → `ipsock-check`（验出口 IP 纯净度与延迟） → `proxy-leak-check --audit-nodes`（确认新节点无 DNS/UDP 泄露）。
- **新静态住宅 SOCKS5 验收**：接入客户端链式 → `ipsock-check` → `proxy-leak-check`。
- **跨境 Tailscale 组网与内网提速**：`tailscale-derp-ops`（无 SNI DERP + `mangle` + `derpMap` 收口 + 客户端防套娃/链式替代） → 按需转 `nat-vps-proxy` 调优 `sing-box` 入站与防 SSRF 放行。
- **日常卡顿或断连排障**：`proxy-leak-check`（先查本机形态） → `ipsock-check`（再查出口质量） → `nat-vps-proxy` 错误对照表 / `tailscale-derp-ops` 内核拆段诊断（最后查服务端）。

## 本地安装与单一源同步（推荐）

本机只克隆一份仓库，将 `skills/<name>` 目录链接到各 Agent 宿主的 skills 目录，以后 `git pull --ff-only` 一次全宿主同步：

```powershell
# Windows（PowerShell，无需管理员权限）
git clone https://github.com/<owner>/net-ops-skills.git D:\paseo\net-ops-skills
cmd /c mklink /J "$env:USERPROFILE\.agents\skills\nat-vps-proxy"      "D:\paseo\net-ops-skills\skills\nat-vps-proxy"
cmd /c mklink /J "$env:USERPROFILE\.agents\skills\ipsock-check"       "D:\paseo\net-ops-skills\skills\ipsock-check"
cmd /c mklink /J "$env:USERPROFILE\.agents\skills\proxy-leak-check"   "D:\paseo\net-ops-skills\skills\proxy-leak-check"
cmd /c mklink /J "$env:USERPROFILE\.agents\skills\tailscale-derp-ops" "D:\paseo\net-ops-skills\skills\tailscale-derp-ops"
```

```bash
# macOS / Linux
git clone https://github.com/<owner>/net-ops-skills.git ~/net-ops-skills
ln -s ~/net-ops-skills/skills/nat-vps-proxy      ~/.agents/skills/nat-vps-proxy
ln -s ~/net-ops-skills/skills/ipsock-check       ~/.agents/skills/ipsock-check
ln -s ~/net-ops-skills/skills/proxy-leak-check   ~/.agents/skills/proxy-leak-check
ln -s ~/net-ops-skills/skills/tailscale-derp-ops ~/.agents/skills/tailscale-derp-ops
```

### 私有叠加层（`local.md`）

如需保留只属于你个人环境的备注（如私有规则仓库路径、自定义注入命令、真实机器备忘），可在对应 `skills/<name>/` 下创建 `local.md`。仓库 `.gitignore` 已强制忽略所有 `local.md`，不会进入 Git 提交；各 `SKILL.md` 均约定在存在 `local.md` 时一并读取。

## 多 Agent 协作沉淀规范

仓库支持多个 AI Agent 在跨会话实战后持续回写改进：

1. **新发现沉淀**：通用、可复用的实测发现与避坑经验，请按标准模板追加到对应技能的 `references/`（如 [`skills/tailscale-derp-ops/references/findings-log.md`](./skills/tailscale-derp-ops/references/findings-log.md)），并在 `CHANGELOG.md` 记录变更；个人资产仅限写进本地 `local.md`。
2. **统一脱敏替换**：公开文档与脚本只允许使用 RFC 5737 / RFC 3849 示例 IP、CGNAT 示例段（如 `100.64.0.x`）、`tail000000.ts.net` 与 `<占位符>`。
3. **推送双门禁**：提交前本地必须运行 `python3 tools/privacy_scan.py` 通过（0 风险项）且 `git status` 无私有文件混入；推送到 GitHub `main` 后由 [`.github/workflows/privacy-scan.yml`](./.github/workflows/privacy-scan.yml) 自动二次校验。

## 隐私与安全自检

推送前务必运行仓库内置的隐私扫描脚本：

```bash
python3 tools/privacy_scan.py
```

如需拦截个人敏感关键词（真实 IP、本地用户名、私有仓库名等），在仓库根目录创建 `.privacy-denylist.local`（每行一个正则/字面量，已入 `.gitignore`），扫描器与 pre-commit 钩子会自动加载。

## 免责声明

本仓库仅提供网络连通性测试、系统运维排查与隐私防泄露自检工具及通用工程文档，请遵守所在地区及各网络服务商的使用条款。提交 Issue 贴测试报告时，请先使用 `--redact` 脱敏。
