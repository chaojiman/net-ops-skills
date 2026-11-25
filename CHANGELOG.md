# Changelog

## v1.2.0 (2026-11-25)

- `nat-vps-proxy`（`references/server-benchmark.md`）：新增「指定省份（如福建移动 `-R 福建`）专项路由与 v4 / v6 入口同台 A/B 实测」章节（免 `imagemagick` 轻量 `-n -p` 跑法、闲时 vs 晚高峰 CMI 拥塞防误判、去回程双向对账、GCP 同网卡 `Standard IPv4 + Premium IPv6` 空载多流吞吐对比与测毕切回 `IPV4_ONLY` 防扣费）。
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
