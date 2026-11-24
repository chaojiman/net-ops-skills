# Changelog

## v1.0.0 (2026-11-24)

- 初始合并发布三套跨平台网络运维 Skill：`nat-vps-proxy`、`ipsock-check`、`proxy-leak-check`。
- `nat-vps-proxy`：按 ≤500 行精简主文，将 `shoes` / `realm` / 安全加固 / 服务端体检下沉至 `references/`，完成全量隐私脱敏并支持本地 `local.md` 叠加层。
- `ipsock-check`：重写为跨平台零依赖 Python 3 + 系统 `curl` 单文件脚本（`scripts/ipsock_check.py`），内置 `--self-check`、`--speed` 多源防 429 测速、`--redact` 脱敏、stdin `-K -` 凭据保护与标准退出码。
- `proxy-leak-check`：补充 `--redact` 输出脱敏参数，支持安全分享文本与 JSON 报告。
- 新增 `tools/privacy_scan.py` 与 GitHub Actions 自动隐私扫描工作流。
