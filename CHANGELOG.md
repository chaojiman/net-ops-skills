# Changelog

## v1.4.0 (2026-11-26)

- **新增技能 `tailscale-derp-ops`**：系统沉淀跨境 Tailscale 自建无 SNI 双栈 IP 证书 `derper`（`--verify-clients` + `-home=blank` + `tag` 同级 `icmp:*`）、`iptables/ip6tables -t mangle` 跨境禁裸 UDP `:41641` 并放行 STUN 回包、ACL `derpMap` 防非对称双中继限速收口与单滞后官方兜底、Windows Mihomo vs iOS Shadowrocket 防套娃分流与链式替代架构、内核 TCP `ss -tinp` + `derper` 日志毫秒级拆段排障，以及多 Agent 协作演化日志 `references/findings-log.md`。
- `ipsock-check`（`SKILL.md`）：新增「多节点横向对比测速统一四维口径（`204 响应` → `单流 5MB` → `最低握手` → `4 并发 20MB`）」规范。
- `proxy-leak-check`（`SKILL.md`）：将 Windows `ProxyOverride` 示例 IP 进一步脱敏为 RFC 6598 保留段示例 `100.64.0.20`，并补充与 `tailscale-derp-ops` 的相互联动指引。
- 隐私与 CI 防线：升级 `tools/privacy_scan.py` 新增真实 Tailnet MagicDNS（`tail*.ts.net`）与 DERP 证书 `sha256-raw` 指纹拦截，并在 `.github/workflows/privacy-scan.yml` 正式启用 GitHub Actions 自动隐私与语法检查。
- 文档完善：更新 `README.md` 四技能总览、典型顺序、安装命令及「多 Agent 协作沉淀规范」，同步更新 `nat-vps-proxy` 联动引用。

## v1.3.0 (2026-11-25)

- `nat-vps-proxy`（`references/server-benchmark.md`）：新增「客户端安全测速四维权重（`204 响应` → `单流 5MB` → `最低握手` → `4 并发 QoS 照妖镜`）与链式中转前置故障转移排序范式」（双层同测、剔除面板假低延迟丢包点、识别风控期并发限速、跨云异构容灾及双栈 `fallback` 选线避坑）。
- `nat-vps-proxy`（`references/security-hardening.md`、`SKILL.md`）：补强双栈机「6进4出」路由层 `{"ip_version": 6, "action": "reject"}` 硬阻断裸 IPv6 旁路泄漏规则与 `api64.ipify.org` 验收标准；更新 GCP 标准层按区域（Per Region）独立 200 GB/月免费额度、在用公网 IPv4 `$0.005/h` 同价转静态锁纯净度及纯 v6 取舍账本。

## v1.2.0 (2026-11-25)

- `nat-vps-proxy`（`references/server-benchmark.md`）：新增大厂云（GCP/AWS）禁跑 `NetQuality` / `nexttrace --tcp` 大包并发防触发 DoS 风控警告红线；补充 GCP 开启标准层 IPv6（`v6-standard` `2600:1902::` 段）的项目默认层级两步法、普通 VPS 指定省份（`-R 福建`）轻量跑法及空载双栈入口吞吐对比范式。
- `nat-vps-proxy`（`SKILL.md`、`references/security-hardening.md`）：补充非交互环境下用 `sing-box generate` 原生生成 REALITY 配置的免阻塞写法，以及 Debian/Ubuntu 关闭 `systemd-resolved` `5355`（LLMNR/mDNS）多余监听面的巡检项。

## v1.1.0 (2026-11-24)

- `nat-vps-proxy`（`references/low-mem-and-realm.md`）：补充 `realm` 的 Debian/Ubuntu systemd 单元模板，以及同机并跑 `sing-box` + `realm` 时月出站熔断须同时停止双服务的避坑提醒。
- `nat-vps-proxy`（`references/security-hardening.md`）：新增「云厂商计费防爆与零暴露探针接入」章节（GCP 外部 IPv6 层级计费陷阱 + `vnstat` 熔断 + 受限 `permitopen` SSH 隧道探针范式）。
- `nat-vps-proxy`（`references/server-benchmark.md`）：补充 `sudo` 进程替换 `/dev/fd/63` 报错、非交互 SSH `TERM=xterm` 要求、共享小核跑 Geekbench5 耗时影响及单站点 403 定向分流建议。

## v1.0.0 (2026-11-24)

- 初始合并发布三套跨平台网络运维 Skill：`nat-vps-proxy`、`ipsock-check`、`proxy-leak-check`。
- `nat-vps-proxy`：按 ≤500 行精简主文，将 `shoes` / `realm` / 安全加固 / 服务端体检下沉至 `references/`，完成全量隐私脱敏并支持本地 `local.md` 叠加层。
- `ipsock-check`：重写为跨平台零依赖 Python 3 + 系统 `curl` 单文件脚本（`scripts/ipsock_check.py`），内置 `--self-check`、`--speed` 多源防 429 测速、`--redact` 脱敏、stdin `-K -` 凭据保护与标准退出码。
- `proxy-leak-check`：补充 `--redact` 输出脱敏参数，支持安全分享文本与 JSON 报告。
- 新增 `tools/privacy_scan.py` 与 GitHub Actions 自动隐私扫描工作流。
