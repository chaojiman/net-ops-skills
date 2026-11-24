#!/usr/bin/env python3
"""
仓库隐私与凭据静态扫描器（仅使用 Python 3 标准库）。
用于 pre-commit 本地拦截与 GitHub Actions CI 检查：
  - 非文档段公网 IPv4 / IPv6
  - UUID v4
  - 疑似 43 字符 base64url 密钥（如 REALITY key）与常见 API Token 前缀
  - 本机绝对用户路径（C:\\Users\\<name>、/home/<name>、/Users/<name>）
  - 真实个人邮箱（排除 example.com / users.noreply.github.com）
  - 可选本地黑名单 .privacy-denylist.local（已 gitignore，不入库）
"""

import ipaddress
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

SKIP_DIRS = {".git", "__pycache__", ".venv", "node_modules", "reports"}
SKIP_FILES = {".privacy-denylist.local", "local.md"}
SKIP_EXTS = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico", ".pdf", ".zip", ".gz", ".pyc"}

# 明确允许出现在公开文档/脚本中的公共 DNS、本地回环、文档示例与私有地址
ALLOWED_IPV4 = {
    "127.0.0.1", "0.0.0.0", "1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4",
    "223.5.5.5", "223.6.6.6", "120.53.53.53", "1.12.12.12",
    "169.254.169.254", "198.18.0.2",
}
ALLOWED_IPV4_NETS = [
    ipaddress.ip_network("192.0.2.0/24"),     # RFC 5737 TEST-NET-1
    ipaddress.ip_network("198.51.100.0/24"),  # RFC 5737 TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),   # RFC 5737 TEST-NET-3
    ipaddress.ip_network("198.18.0.0/15"),    # RFC 2544 / Fake-IP
    ipaddress.ip_network("100.64.0.0/10"),    # CGNAT / Tailscale
    ipaddress.ip_network("169.254.0.0/16"),   # Link-local / Cloud Metadata
    ipaddress.ip_network("127.0.0.0/8"),      # Loopback
    ipaddress.ip_network("10.0.0.0/8"),       # RFC 1918
    ipaddress.ip_network("172.16.0.0/12"),    # RFC 1918
    ipaddress.ip_network("192.168.0.0/16"),   # RFC 1918
]
ALLOWED_IPV6_NETS = [
    ipaddress.ip_network("2001:db8::/32"),    # RFC 3849 文档段
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("::/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]

RE_IPV4 = re.compile(r"(?<![0-9.])(\d{1,3}(?:\.\d{1,3}){3})(?![0-9.])")
RE_IPV6 = re.compile(r"(?<![0-9a-fA-F:])((?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{0,4}|[0-9a-fA-F]{4}:[0-9a-fA-F]{1,4}:[0-9a-fA-F:…]{2,})(?![0-9a-fA-F:])")
RE_UUID = re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b")
RE_TOKEN = re.compile(r"\b(?:sk-[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{16,})\b")
RE_USER_PATH = re.compile(r"(?:[A-Za-z]:\\Users\\|/Users/|/home/)([^\\/\s<>'\"`]+)")
RE_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b")
RE_B64_43 = re.compile(r"(?<![A-Za-z0-9_/-])([A-Za-z0-9_-]{43})(?![A-Za-z0-9_/-])")

# 非真实目录的占位用户名与常见代码词汇白名单
ALLOWED_USERS = {"user", "username", "yourname", "ubuntu", "root", "admin", "example"}
ALLOWED_EMAIL_DOMAINS = {"example.com", "example.org", "users.noreply.github.com"}


def is_allowed_ipv4(ip_str: str) -> bool:
    if ip_str in ALLOWED_IPV4:
        return True
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return True  # 非法 IP（如版本号 1.2.3.4 越界）
    # 排除常见软件版本号误报（如 0.x.x.x）
    if ip_str.startswith("0."):
        return True
    return any(addr in net for net in ALLOWED_IPV4_NETS)


def is_allowed_ipv6(v6_str: str) -> bool:
    if "…" in v6_str:
        # 含省略号的真实 v6 片段（如 2400:…:a）除文档段外一律拦截
        return v6_str.lower().startswith("2001:db8:")
    try:
        addr = ipaddress.ip_address(v6_str)
    except ValueError:
        return True  # 常见时间戳/冒号分隔文本不是合法 v6
    return any(addr in net for net in ALLOWED_IPV6_NETS)


def load_local_denylist() -> list[tuple[str, re.Pattern]]:
    deny_file = ROOT / ".privacy-denylist.local"
    patterns = []
    if deny_file.is_file():
        for raw in deny_file.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            try:
                patterns.append((line, re.compile(line, re.IGNORECASE)))
            except re.error:
                patterns.append((line, re.compile(re.escape(line), re.IGNORECASE)))
    return patterns


def scan_file(path: Path, local_deny: list[tuple[str, re.Pattern]]) -> list[str]:
    rel = path.relative_to(ROOT).as_posix()
    findings: list[str] = []
    try:
        text = path.read_text(encoding="utf-8", errors="strict")
    except UnicodeDecodeError:
        return findings

    # 工具自身含示例正则/白名单，仅对本地黑名单检查，不自触发白名单字面量
    is_self = (rel == "tools/privacy_scan.py")

    for lineno, line in enumerate(text.splitlines(), 1):
        # 1. 本地私有黑名单（所有文件都检，含自身）
        for raw_pat, compiled in local_deny:
            if compiled.search(line):
                findings.append(f"{rel}:{lineno}: 命中本地私有黑名单规则")

        if is_self:
            continue

        # 2. 公网 IPv4 检查
        for m in RE_IPV4.finditer(line):
            ip_s = m.group(1)
            # 跳过版本号语境（如 v1.2.3.4 / curl 8.22.0.1 / Safari/537.36）
            prefix = line[max(0, m.start() - 12):m.start()].lower()
            if any(k in prefix for k in ("chrome/", "version", "safari/", "gecko/", "v")):
                continue
            if not is_allowed_ipv4(ip_s):
                findings.append(f"{rel}:{lineno}: 疑似真实公网 IPv4 `{ip_s}`（请替换为 RFC5737 192.0.2.x/198.51.100.x/203.0.113.x）")

        # 3. 公网 IPv6 检查
        for m in RE_IPV6.finditer(line):
            v6_s = m.group(1)
            if not is_allowed_ipv6(v6_s):
                findings.append(f"{rel}:{lineno}: 疑似真实公网 IPv6 `{v6_s}`（请替换为 RFC3849 2001:db8::）")

        # 4. UUID v4
        for m in RE_UUID.finditer(line):
            findings.append(f"{rel}:{lineno}: 疑似真实 UUID `{m.group(0)}`（请替换为 <UUID>）")

        # 5. API Token
        for m in RE_TOKEN.finditer(line):
            findings.append(f"{rel}:{lineno}: 疑似真实 Token `{m.group(0)[:10]}...`")

        # 6. 本机用户绝对路径
        for m in RE_USER_PATH.finditer(line):
            uname = m.group(1).lower()
            if uname not in ALLOWED_USERS and not uname.startswith("$"):
                findings.append(f"{rel}:{lineno}: 暴露本机用户路径 `{m.group(0)}`（请改用 <skill_dir> 或 ~）")

        # 7. 邮箱
        for m in RE_EMAIL.finditer(line):
            dom = m.group(1).lower()
            if dom not in ALLOWED_EMAIL_DOMAINS:
                findings.append(f"{rel}:{lineno}: 疑似个人邮箱 `{m.group(0)}`")

        # 8. 疑似 43 字符 base64url 密钥（仅在 key/pbk/secret/token 语境触发，防误报长标识符）
        if re.search(r"(?:key|pbk|secret|token|psk)", line, re.I):
            for m in RE_B64_43.finditer(line):
                cand = m.group(1)
                if any(c.isdigit() for c in cand) and any(c.islower() for c in cand) and any(c.isupper() for c in cand):
                    findings.append(f"{rel}:{lineno}: 疑似 43 字符密钥 `{cand[:8]}...`")

    return findings


def main() -> int:
    local_deny = load_local_denylist()
    all_findings: list[str] = []

    for dirpath, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            if fn in SKIP_FILES or ".bak" in fn:
                continue
            p = Path(dirpath) / fn
            if p.suffix.lower() in SKIP_EXTS:
                continue
            all_findings.extend(scan_file(p, local_deny))

    if all_findings:
        print("❌ 隐私与凭据扫描未通过，发现以下风险项：")
        for item in all_findings:
            print(f"  - {item}")
        return 1

    print("✅ 隐私与凭据扫描通过（0 风险项）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
