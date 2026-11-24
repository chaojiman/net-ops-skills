---
name: ipsock-check
description: >-
  对新购静态住宅代理（SOCKS5/HTTP）或已接链式落地 VPS 进行上线前出口 IP 质量与连通性验收：
  涵盖多轮出口固定性、v4/v6 分离检查、四库 IP 纯净度交叉校验（ipquery/ipwho/ipinfo/ip-api）、
  主流站点与风控验证探活（Reddit/Google/Claude/OpenAI/Gemini/Stripe/Netflix）、全链路延迟稳定性与多源防 429 测速。
  触发词：IP 纯净度、出口质量、风控检测、验证码探活、新购代理验收、静态住宅检查、链式出口验收、测速。
  不用于 VPS 服务端部署与加固（请用 nat-vps-proxy），也不用于本机 DNS/WebRTC/TUN 防泄露诊断（请用 proxy-leak-check）。
---

# ipsock-check：代理出口 IP 质量与连通性验收

用于在新购 **静态住宅代理（SOCKS5/HTTP）** 或 **已接入链式的落地 VPS** 投入正式使用前，完成一次性跨平台（Windows / macOS / Linux）自动化体检与人工复核。

> 若本技能同目录存在 `local.md`（本地私有备注，不入库），执行前先一并读取。

## 1. 脚本运行与获取顺序

脚本为纯 Python 3 标准库 + 系统 `curl` 单文件：[scripts/ipsock_check.py](./scripts/ipsock_check.py)（最低版本 `1.0.0`）。

1. **优先本地执行（常态，不依赖 GitHub）**：直接运行 `<skill_dir>/scripts/ipsock_check.py`。
2. **裸机/无本地脚本时拉取固定发布版本**：按固定 Release Tag 下载到 `/root` 或 `/var/tmp`（**严禁放 `/tmp`**，128MB 容器 `/tmp` 计入内存），校验 SHA256 后再运行；**禁止 `curl main | python3`**。
   ```bash
   curl -fsSL "https://raw.githubusercontent.com/<owner>/net-ops-skills/v1.0.0/skills/ipsock-check/scripts/ipsock_check.py" \
     -o /var/tmp/ipsock_check.py
   # 核对 Release 页公布的 sha256sum 后再执行
   python3 /var/tmp/ipsock_check.py --self-check
   ```
3. **版本检查（只提醒，不自动更新）**：在 git 克隆目录中可用 `git ls-remote --tags --refs --sort=-v:refname origin 'v*'` 检查新 tag；确认需要时由用户手动执行 `git pull --ff-only`。
4. **≤128MB Alpine 极小内存机**：若机器未预装 `python3`，**不要为了跑脚本去 `apk add python3`**（易因 page cache 触发 OOM），改从本机客户端经该节点做端到端检测。

## 2. 安全前提与常用命令

> ⚠️ **严禁裸连过墙**：不要从国内网络直接连接海外明文 SOCKS5/HTTP 代理！先将其接入本地客户端的加密链式出口（前置选与落地同区或邻区节点），再指向本地回环代理端口检测。脚本对非回环明文代理会自动输出警告。

```bash
# 1. 环境自检（核对 curl 版本、schannel/TLS 能力、Python 版本）
python3 <skill_dir>/scripts/ipsock_check.py --self-check

# 2. 标准出口验收（经本地链式端口测试；默认关闭大流量测速以省流）
python3 <skill_dir>/scripts/ipsock_check.py \
  --proxy http://127.0.0.1:7890 \
  --expected-country JP \
  --expect-ip 198.51.100.10

# 3. 开启多源防 429 单线程测速（默认限 5MB，自动跳过 NXDOMAIN/429 源）
python3 <skill_dir>/scripts/ipsock_check.py \
  --proxy http://127.0.0.1:7890 \
  --speed

# 4. 脱敏输出并导出 JSON（用于分享或提 Issue，自动打码出口 IP 与代理凭据）
python3 <skill_dir>/scripts/ipsock_check.py \
  --proxy http://127.0.0.1:7890 \
  --redact \
  --out-json ipsock.report.json
```

*(Windows 下将 `python3` 替换为 `python`，优先在 `pwsh` 7 中运行；脚本自动使用 `curl.exe` 与 `--ssl-revoke-best-effort`。)*

## 3. 脚本检测维度与退出码约定

- **模块 1 · 出口固定性与 v4/v6 分离**：连续 `--rounds`（默认 3）轮分别用 `-4`、`-6` 检查出口 IP，识别动态轮换出口、验证是否命中 `--expect-ip`，并区分「无 IPv6」与「存在 IPv6 出口」。
- **模块 2 · 四库纯净度交叉体检**：查询 `api.ipquery.io`、`ipwho.is`、`ipinfo.io`、`ip-api.com`（免费版走明文 HTTP），核对地区一致性、ASN/ISP 及 `is_datacenter / is_vpn / is_proxy / is_abuser / hosting / risk_score`；单库限流记「未知」不误扣分。
- **模块 3 · 敏感站点与验证探活**：检测 Reddit（403 机房试金石）、Google 搜索（429 / `/sorry/` 验证码）、Claude Web / Anthropic API、ChatGPT Web / OpenAI API、Google Gemini、Stripe API、Netflix 非自制剧（自动跟随区域跳转）的 HTTP 状态、Cloudflare `cf-mitigated` 挑战头与 TTFB。
- **模块 4 · 稳定性与多源防 429 测速**：多轮测 `generate_204`、`api.anthropic.com`、`api.openai.com` 的丢包率与 TTFB；启用 `--speed` 时串行测速并自动在 CacheFly / Fastly / Cloudflare 间兜底（遇 `429` 或 `0` 速标为限流样本，不误报 0 Mbps）。
- **固定退出码（便于 Agent 自动编排）**：
  - `0` = **A 级**（干净稳定，可直接上线）
  - `1` = **B 级**（可用但有轻微提醒项，视业务风险决定）
  - `2` = **C 级**（命中红线：动态漂移 / 丢包 / 高风险 / 验证码拦截，建议更换 IP 或排查链路）
  - `3` = **执行错误**（代理不通、缺 `curl` 或参数非法）

## 4. 人工 1 分钟复核（补齐反爬库与真实浏览器视角）

自动化脚本不绕过带反爬的商业查询页，运行完毕后点击脚本打印的直达链接快速复核：

- **Scamalytics**：建议风险分 `0~10`（Low Risk）。
- **IPQS**：建议 `< 30` 分，且尽量无 `Proxy / VPN` 标记。
- **ping0.cc / AbuseIPDB**：确认无高危黑名单。
- **无痕浏览器实测**：打开 Google 搜索连查两次不弹验证码、打开 Reddit 不报 403、打开目标站点无循环盾。

## 5. 链式落地 VPS 的前置选优流程

若检验对象是刚部署好的落地 VPS（服务端原生态体检请先按 **`nat-vps-proxy`** 完成）：

1. 接入本地链式代理后，先带 `--expect-ip <落地IP>` 确认流量确实从落地 VPS 出口（未漏走前置机）。
2. 在客户端「链式中转」组依次切换 2~3 个邻区前置节点，各跑一次 `ipsock_check.py --rounds 3`（不开 `--speed`），对比 `api.anthropic.com` 与 `generate_204` 的平均 TTFB 和丢包率，锁定最稳前置。

## 下一步联动

出口验收达标后，执行 **`proxy-leak-check --audit-nodes`** 确认本机 TUN / DNS / WebRTC 无泄露且新节点已开启 `udp: true`。
