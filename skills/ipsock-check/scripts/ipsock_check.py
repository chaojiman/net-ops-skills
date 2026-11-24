#!/usr/bin/env python3
"""
ipsock_check.py — 跨平台代理出口 IP 纯净度、风控探活与链路性能一键验收工具
仅依赖 Python 3 标准库 + 系统 curl（零第三方 pip 依赖，支持 Windows / macOS / Linux）。

核心安全与工程约定：
  - 通过 curl `-K -` 从 stdin 传递代理地址与凭据，绝不出现在命令行/ps 中。
  - 调用 curl 固定带 `-q` 并清空代理环境变量，消除 .curlrc 与环境变量干扰。
  - 所有下载与响应体不落地 /tmp（适配 128MB 以下 tmpfs 容器），响应读取设 256KB 上限。
  - 测速默认关闭（--speed 开启），多 CDN 源兜底，HTTP 429 / 0 速标为限流样本而非 0 Mbps。
  - 固定退出码：A=0, B=1, C=2, 执行错误=3。
"""

import argparse
import ipaddress
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import time
import urllib.parse

__version__ = "1.0.0"

# ── 易过期外部常量集中区（更新日期：2026-11-24） ──────────────────
DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/131.0.0.0 Safari/537.36"
)
NETFLIX_NON_ORIGINAL_URL = "https://www.netflix.com/title/81280792"  # 非自制剧解锁探测 ID
SPEED_CANDIDATES = [
    ("CacheFly (5MB)", "http://cachefly.cachefly.net/5mb.test", 5_242_880),
    ("Fastly/GitHub (5MB Range)", "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64", 5_242_880),
    ("Cloudflare (5MB)", "https://speed.cloudflare.com/__down?bytes=5000000", 5_000_000),
]
MAX_BODY_BYTES = 256 * 1024  # 响应体内存上限 256KB

OS_NAME = platform.system()
CURL_BIN = "curl.exe" if OS_NAME == "Windows" else (shutil.which("curl") or "curl")
META_MARKER = "__IPSOCK_META__:"


def setup_utf8_stdio() -> None:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


def clean_proxy_env() -> dict:
    env = os.environ.copy()
    for k in (
        "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
        "http_proxy", "https_proxy", "all_proxy", "no_proxy",
    ):
        env.pop(k, None)
    return env


def get_curl_info() -> dict:
    info = {
        "os": f"{OS_NAME} {platform.release()} ({platform.machine()})",
        "python": platform.python_version(),
        "curl_bin": CURL_BIN,
        "curl_found": False,
        "curl_version": "",
        "curl_tuple": (0, 0, 0),
        "has_schannel": False,
        "supports_revoke_best_effort": False,
        "supports_socks5h": False,
    }
    if not shutil.which(CURL_BIN) and not os.path.isfile(CURL_BIN):
        return info
    try:
        r = subprocess.run(
            [CURL_BIN, "--version"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=5,
        )
        if r.returncode != 0:
            return info
        out = r.stdout or ""
        info["curl_found"] = True
        first = out.splitlines()[0] if out.splitlines() else ""
        info["curl_version"] = first
        m = re.search(r"curl\s+(\d+)\.(\d+)\.(\d+)", first)
        if m:
            ver = (int(m.group(1)), int(m.group(2)), int(m.group(3)))
            info["curl_tuple"] = ver
            info["supports_revoke_best_effort"] = ver >= (7, 70, 0)
            info["supports_socks5h"] = ver >= (7, 18, 0)
        info["has_schannel"] = "schannel" in out.lower()
    except Exception:
        pass
    return info


def mask_proxy_url(raw: str) -> str:
    if not raw:
        return "DIRECT"
    return re.sub(r"(://)([^:@/\s]+):([^@/\s]+)@", r"\1***:***@", raw)


def redact_ip(ip_str: str) -> str:
    if not ip_str:
        return ip_str
    try:
        addr = ipaddress.ip_address(ip_str)
        if addr.version == 4:
            parts = ip_str.split(".")
            return f"{parts[0]}.{parts[1]}.*.*"
        segs = addr.exploded.split(":")
        return f"{segs[0]}:{segs[1]}:****::{segs[-1]}"
    except ValueError:
        return ip_str


def is_plaintext_non_loopback_proxy(proxy_url: str) -> bool:
    if not proxy_url:
        return False
    u = urllib.parse.urlparse(proxy_url if "://" in proxy_url else f"http://{proxy_url}")
    scheme = (u.scheme or "").lower()
    host = (u.hostname or "").lower()
    if scheme not in ("http", "socks5", "socks5h", "socks4", "socks4a"):
        return False
    if host in ("127.0.0.1", "localhost", "::1"):
        return False
    try:
        if ipaddress.ip_address(host).is_loopback:
            return False
    except ValueError:
        pass
    return True


def escape_curl_cfg(val: str) -> str:
    return val.replace("\\", "\\\\").replace('"', '\\"')


def curl_request(
    url: str,
    curl_info: dict,
    proxy: str = "",
    timeout: int = 12,
    head_only: bool = False,
    follow_redirect: bool = False,
    ip_version: str = "",
    discard_body: bool = False,
    max_bytes: int = 0,
    user_agent: str = DEFAULT_UA,
) -> dict:
    """
    经 stdin (-K -) 安全传参调用 curl，兼容旧版 curl（不依赖 %{json}），不写 /tmp 临时文件。
    """
    cfg_lines = [
        f'url = "{escape_curl_cfg(url)}"',
        f'user-agent = "{escape_curl_cfg(user_agent)}"',
    ]
    if proxy:
        p = proxy if "://" in proxy else f"http://{proxy}"
        cfg_lines.append(f'proxy = "{escape_curl_cfg(p)}"')
    cfg_stdin = ("\n".join(cfg_lines) + "\n").encode("utf-8")

    cmd = [
        CURL_BIN,
        "-q",
        "-sS",
        "--max-time", str(timeout),
        "--connect-timeout", str(min(timeout, 8)),
        "-K", "-",
    ]
    if OS_NAME == "Windows" and curl_info.get("has_schannel") and curl_info.get("supports_revoke_best_effort"):
        cmd.append("--ssl-revoke-best-effort")
    if ip_version == "4":
        cmd.append("-4")
    elif ip_version == "6":
        cmd.append("-6")
    if head_only:
        cmd.append("-I")
    if follow_redirect:
        cmd.append("-L")
    if max_bytes > 0:
        cmd += ["-r", f"0-{max_bytes - 1}"]

    write_fmt = (
        f"\n{META_MARKER}%{{http_code}}|%{{time_connect}}|%{{time_appconnect}}|"
        f"%{{time_starttransfer}}|%{{time_total}}|%{{size_download}}|%{{speed_download}}|%{{redirect_url}}"
    )
    if discard_body:
        cmd += ["-o", os.devnull, "-w", write_fmt]
    else:
        cmd += ["-i", "-w", write_fmt]

    try:
        proc = subprocess.run(
            cmd,
            input=cfg_stdin,
            capture_output=True,
            env=clean_proxy_env(),
            timeout=timeout + 4,
        )
    except subprocess.TimeoutExpired:
        return {
            "ok": False, "rc": -1, "http_code": 0, "connect_ms": 0.0, "tls_ms": 0.0,
            "ttfb_ms": 0.0, "total_ms": timeout * 1000.0, "bytes": 0, "speed_mbps": 0.0,
            "redirect_url": "", "headers": "", "body": "", "error": "timeout",
        }
    except Exception as e:
        return {
            "ok": False, "rc": -1, "http_code": 0, "connect_ms": 0.0, "tls_ms": 0.0,
            "ttfb_ms": 0.0, "total_ms": 0.0, "bytes": 0, "speed_mbps": 0.0,
            "redirect_url": "", "headers": "", "body": "", "error": str(e),
        }

    raw_out = proc.stdout or b""
    raw_err = (proc.stderr or b"").decode("utf-8", errors="replace").strip()
    marker_b = f"\n{META_MARKER}".encode("ascii")
    idx = raw_out.rfind(marker_b)
    if idx != -1:
        payload_b = raw_out[:idx]
        meta_str = raw_out[idx + len(marker_b):].decode("utf-8", errors="replace").strip()
    else:
        payload_b = raw_out
        meta_str = ""

    parts = meta_str.split("|", 7) if meta_str else []
    def ffloat(pos: int) -> float:
        try:
            return float(parts[pos]) if len(parts) > pos else 0.0
        except ValueError:
            return 0.0

    http_code = int(parts[0]) if (len(parts) >= 1 and parts[0].isdigit()) else 0
    connect_ms = round(ffloat(1) * 1000.0, 1)
    tls_ms = round(ffloat(2) * 1000.0, 1)
    ttfb_ms = round(ffloat(3) * 1000.0, 1)
    total_ms = round(ffloat(4) * 1000.0, 1)
    dl_bytes = int(ffloat(5))
    speed_mbps = round((ffloat(6) * 8.0) / 1_000_000.0, 2)
    redirect_url = parts[7] if len(parts) >= 8 else ""

    headers_text = ""
    body_text = ""
    if not discard_body and payload_b:
        # 处理多段响应头（含代理 CONNECT 200 头或 3xx 跳转头）
        sep = b"\r\n\r\n" if b"\r\n\r\n" in payload_b else b"\n\n"
        chunks = payload_b.split(sep)
        hdr_chunks = []
        body_start_idx = 0
        for i, ch in enumerate(chunks):
            if ch.lstrip().startswith(b"HTTP/"):
                hdr_chunks.append(ch)
                body_start_idx = i + 1
            else:
                break
        if hdr_chunks:
            headers_text = hdr_chunks[-1].decode("utf-8", errors="replace")
            body_b = sep.join(chunks[body_start_idx:])[:MAX_BODY_BYTES]
            body_text = body_b.decode("utf-8", errors="replace")
        else:
            body_text = payload_b[:MAX_BODY_BYTES].decode("utf-8", errors="replace")

    return {
        "ok": (proc.returncode == 0 and http_code > 0),
        "rc": proc.returncode,
        "http_code": http_code,
        "connect_ms": connect_ms,
        "tls_ms": tls_ms,
        "ttfb_ms": ttfb_ms,
        "total_ms": total_ms,
        "bytes": dl_bytes,
        "speed_mbps": speed_mbps,
        "redirect_url": redirect_url,
        "headers": headers_text,
        "body": body_text,
        "error": raw_err if proc.returncode != 0 else "",
    }


def query_json_with_retry(url: str, curl_info: dict, proxy: str, timeout: int = 12) -> dict | None:
    for attempt in range(2):
        r = curl_request(url, curl_info, proxy=proxy, timeout=timeout, ip_version="4")
        if r["ok"] and r["http_code"] == 200 and r["body"].strip():
            try:
                return json.loads(r["body"])
            except Exception:
                pass
        if attempt == 0:
            time.sleep(0.8)
    return None


def run_self_check(curl_info: dict) -> int:
    print(f"ipsock_check v{__version__} 环境自检")
    print(f"  OS          : {curl_info['os']}")
    print(f"  Python      : {curl_info['python']}")
    print(f"  curl 路径    : {curl_info['curl_bin']} (found={curl_info['curl_found']})")
    print(f"  curl 版本    : {curl_info['curl_version'] or '未找到'}")
    print(f"  Schannel    : {curl_info['has_schannel']} | --ssl-revoke-best-effort={curl_info['supports_revoke_best_effort']}")
    print(f"  SOCKS5h 支持 : {curl_info['supports_socks5h']}")
    if not curl_info["curl_found"]:
        print("❌ 未找到系统 curl，无法执行 socks5h/TLS 探测。")
        return 3
    print("✅ 运行环境正常")
    return 0


def main() -> int:
    setup_utf8_stdio()
    parser = argparse.ArgumentParser(
        description="跨平台代理出口 IP 纯净度、风控探活与链路性能一键验收工具（Python 3 + 系统 curl）"
    )
    parser.add_argument("--proxy", default="", help="代理地址，如 http://127.0.0.1:7890 或 socks5h://127.0.0.1:7890（留空则直连测试本机出口）")
    parser.add_argument("--expected-country", default="", help="期望国家两字码，如 JP / US / TW / SG")
    parser.add_argument("--expect-ip", default="", help="期望出口 IPv4（验证链式代理是否命中落地）")
    parser.add_argument("--rounds", type=int, default=3, help="固定性与延迟连测轮数（1~10，默认 3）")
    parser.add_argument("--speed", action="store_true", help="开启多源防 429 单线程下载测速（默认关闭以节省按流量代理额度）")
    parser.add_argument("--redact", action="store_true", help="打码真实出口 IP，适合分享或提 Issue")
    parser.add_argument("--out-json", default="", help="将结构化报告保存为 JSON 文件路径")
    parser.add_argument("--self-check", action="store_true", help="仅检查本机 Python/curl 能力并退出")
    parser.add_argument("--version", action="version", version=f"ipsock_check {__version__}")
    args = parser.parse_args()

    if not (1 <= args.rounds <= 10):
        print("❌ --rounds 取值范围为 1~10")
        return 3

    curl_info = get_curl_info()
    if args.self_check:
        return run_self_check(curl_info)

    if not curl_info["curl_found"]:
        print("❌ 未找到系统 curl。请先安装 curl 或运行 --self-check 检查环境。")
        return 3

    proxy = args.proxy.strip()
    masked_proxy = mask_proxy_url(proxy)

    print("====================================================================")
    print(f"  ipsock-check v{__version__} | 出口 IP 纯净度 + 风控探活 + 链路性能验收")
    print(f"  运行环境：{curl_info['os']} | Python {curl_info['python']}")
    print(f"  curl    ：{curl_info['curl_version']}")
    print(f"  测试出口：{masked_proxy} | 时间：{time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("====================================================================")

    warnings: list[str] = []
    fatals: list[str] = []

    if is_plaintext_non_loopback_proxy(proxy):
        warn_msg = "检测到非回环明文 HTTP/SOCKS 代理，严禁从受限网络直接裸连，请先套本地加密链式前置！"
        print(f"  ⚠️  {warn_msg}")
        warnings.append(warn_msg)

    # ── 1. 出口 IP 固定性与 v4/v6 分离检查 ─────────────────────────
    print(f"\n=== 1. 出口 IP 固定性 & v4/v6 分离检查（连续 {args.rounds} 轮） ===")
    v4_list: list[str] = []
    for i in range(1, args.rounds + 1):
        r = curl_request("https://api.ipify.org", curl_info, proxy=proxy, timeout=10, ip_version="4")
        cand = r["body"].strip()
        if r["ok"] and re.match(r"^\d{1,3}(\.\d{1,3}){3}$", cand):
            v4_list.append(cand)
            disp = redact_ip(cand) if args.redact else cand
            print(f"  [第 {i} 轮] IPv4: {disp}  (TTFB {r['ttfb_ms']} ms)")
        else:
            print(f"  [第 {i} 轮] IPv4 获取失败 (HTTP {r['http_code']}, err={r['error'] or 'unknown'})")

    unique_v4 = list(dict.fromkeys(v4_list))
    if not unique_v4:
        print("❌ 代理不可通或无法获取出口 IPv4，终止检测。")
        return 3

    exit_ip = unique_v4[0]
    disp_ip = redact_ip(exit_ip) if args.redact else exit_ip

    if len(unique_v4) > 1:
        shown = ", ".join(redact_ip(x) if args.redact else x for x in unique_v4)
        msg = f"出口 IPv4 在 {args.rounds} 轮测试中变动：{shown}（动态轮换出口）"
        fatals.append(msg)
        print(f"  ❌ {msg}")
    else:
        print(f"  ✅ 连续 {len(v4_list)}/{args.rounds} 轮出口 IPv4 固定：{disp_ip}")
        if len(v4_list) < args.rounds:
            fatals.append(f"出口 IP 探测存在失败轮次 ({len(v4_list)}/{args.rounds})")

    if args.expect_ip:
        if exit_ip != args.expect_ip.strip():
            msg = "实际出口 IP 与 --expect-ip 不一致，链式代理可能未生效或路由走漏"
            fatals.append(msg)
            print(f"  ❌ {msg}")
        else:
            print(f"  ✅ 精确命中期望落地 IP：{disp_ip}")

    r6 = curl_request("https://api6.ipify.org", curl_info, proxy=proxy, timeout=6, ip_version="6")
    cand6 = r6["body"].strip()
    exit_ip6 = cand6 if (r6["ok"] and ":" in cand6) else ""
    disp_ip6 = redact_ip(exit_ip6) if (exit_ip6 and args.redact) else exit_ip6
    if exit_ip6:
        print(f"  ⚠️  检测到出口 IPv6：{disp_ip6}（请核实归属目标落地，未泄露本机宽带 v6）")
        warnings.append(f"存在 IPv6 出口 ({disp_ip6})")
    else:
        print("  ✅ 无 IPv6 出口（纯 IPv4 出口，无 v6 泄露）")

    # ── 2. 四库 IP 纯净度交叉体检 ──────────────────────────────────
    print("\n=== 2. 四库 IP 归属与纯净度交叉体检 ===")
    ipq = query_json_with_retry(f"https://api.ipquery.io/{exit_ip}?format=json", curl_info, proxy)
    ipwho = query_json_with_retry(f"https://ipwho.is/{exit_ip}", curl_info, proxy)
    ipinfo = query_json_with_retry(f"https://ipinfo.io/{exit_ip}/json", curl_info, proxy)
    # 注：ip-api.com 免费版仅支持明文 HTTP
    ipapi = query_json_with_retry(
        f"http://ip-api.com/json/{exit_ip}?fields=status,countryCode,regionName,city,timezone,isp,org,as,hosting,proxy,mobile",
        curl_info,
        proxy,
    )

    countries: list[str] = []
    if isinstance(ipq, dict) and ipq.get("isp"):
        loc = ipq.get("location") or {}
        isp_o = ipq.get("isp") or {}
        risk = ipq.get("risk") or {}
        cc = str(loc.get("country_code") or "").upper()
        if cc:
            countries.append(cc)
        print(f"  [ipquery]  地区: {cc} / {loc.get('city', '')} | ASN: {isp_o.get('asn', '')} | ISP: {isp_o.get('isp', '')}")
        print(
            f"             风险分: {risk.get('risk_score')} | 机房:{risk.get('is_datacenter')} | "
            f"VPN:{risk.get('is_vpn')} | 代理:{risk.get('is_proxy')} | Tor:{risk.get('is_tor')} | 滥用:{risk.get('is_abuser')}"
        )
        if risk.get("is_datacenter") is True:
            warnings.append("ipquery 判定为机房 IP (is_datacenter=true)")
        if risk.get("is_vpn") is True or risk.get("is_proxy") is True:
            warnings.append("ipquery 标记为 VPN/Proxy")
        if risk.get("is_abuser") is True or risk.get("is_tor") is True:
            fatals.append("ipquery 标记为 Abuser/Tor 高危 IP")
        try:
            r_score = int(risk.get("risk_score") or 0)
            if r_score >= 50:
                fatals.append(f"ipquery 风险分偏高 ({r_score})")
            elif r_score >= 20:
                warnings.append(f"ipquery 存在中等风险分 ({r_score})")
        except ValueError:
            pass
    else:
        print("  [ipquery]  未知（查询失败或限流，不扣分）")

    if isinstance(ipwho, dict) and ipwho.get("success") is True:
        cc = str(ipwho.get("country_code") or "").upper()
        if cc:
            countries.append(cc)
        conn = ipwho.get("connection") or {}
        tz = (ipwho.get("timezone") or {}).get("id", "")
        print(f"  [ipwho.is] 地区: {cc} / {ipwho.get('city', '')} | 时区: {tz} | ASN: AS{conn.get('asn', '')} | ISP: {conn.get('isp', '')}")
    else:
        print("  [ipwho.is] 未知（查询失败或限流，不扣分）")

    if isinstance(ipinfo, dict) and ipinfo.get("ip"):
        cc = str(ipinfo.get("country") or "").upper()
        if cc:
            countries.append(cc)
        print(f"  [ipinfo]   地区: {cc} / {ipinfo.get('city', '')} | 时区: {ipinfo.get('timezone', '')} | Org: {ipinfo.get('org', '')}")
    else:
        print("  [ipinfo]   未知（查询失败或限流，不扣分）")

    if isinstance(ipapi, dict) and ipapi.get("status") == "success":
        cc = str(ipapi.get("countryCode") or "").upper()
        if cc:
            countries.append(cc)
        print(
            f"  [ip-api]   地区: {cc} / {ipapi.get('city', '')} | ISP: {ipapi.get('isp', '')} | "
            f"hosting:{ipapi.get('hosting')} | proxy:{ipapi.get('proxy')} | mobile:{ipapi.get('mobile')}"
        )
        if ipapi.get("hosting") is True:
            warnings.append("ip-api 判定为机房托管 (hosting=true)")
        if ipapi.get("proxy") is True:
            warnings.append("ip-api 判定为代理 (proxy=true)")
    else:
        print("  [ip-api]   未知（查询失败或限流，不扣分）")

    uniq_countries = list(dict.fromkeys([c for c in countries if c]))
    if len(uniq_countries) > 1:
        msg = f"多库定位不一致（疑似广播段漂移）：{', '.join(uniq_countries)}"
        warnings.append(msg)
        print(f"  ⚠️  {msg}")
    if args.expected_country and uniq_countries and (args.expected_country.upper() not in uniq_countries):
        msg = f"实际地区 ({','.join(uniq_countries)}) 与期望地区 ({args.expected_country.upper()}) 不符"
        fatals.append(msg)
        print(f"  ❌ {msg}")

    # ── 3. 主流服务与风控验证探活 ──────────────────────────────────
    print("\n=== 3. 风控与敏感站点探活 ===")
    probes = [
        ("Reddit (机房试金石)", "https://www.reddit.com/", False, "reddit", False),
        ("Google 搜索 (防验证码)", "https://www.google.com/search?q=hello+world&hl=en", True, "google", False),
        ("Claude Web", "https://claude.ai/", True, "claude", False),
        ("Anthropic API", "https://api.anthropic.com/", True, "api", False),
        ("ChatGPT Web", "https://chatgpt.com/", False, "chatgpt", False),
        ("OpenAI API", "https://api.openai.com/v1/models", False, "api", False),
        ("Google Gemini", "https://gemini.google.com/app", False, "gemini", False),
        ("Stripe API", "https://api.stripe.com/", False, "api", False),
        ("Netflix 非自制剧", NETFLIX_NON_ORIGINAL_URL, False, "netflix", True),
    ]

    probe_results = []
    for name, url, critical, kind, follow in probes:
        r = curl_request(url, curl_info, proxy=proxy, timeout=12, follow_redirect=follow)
        cf_challenge = bool(re.search(r"(?im)^cf-mitigated:\s*challenge", r["headers"]))
        code = r["http_code"]
        body = r["body"]
        redir = r["redirect_url"]

        if not r["ok"]:
            tag = "❌ 不通/超时"
            (fatals if critical else warnings).append(f"{name} 无法连通")
        elif kind == "reddit":
            if code == 403 or re.search(r"Blocked by network security|whoa there, pardner", body, re.I):
                tag = "❌ 403 拦截(机房/脏IP信号)"
                warnings.append("Reddit 返回 403 拦截（常见于机房或高风控段）")
            else:
                tag = "✅ 正常放行"
        elif kind == "google":
            if code == 429 or "/sorry/" in redir or re.search(r"unusual traffic from your computer network|recaptcha", body, re.I):
                tag = "❌ 触发验证码/429"
                fatals.append("Google 搜索触发验证码或 429 限流")
            else:
                tag = "✅ 无验证码直出"
        elif kind == "claude":
            if code == 451 or re.search(r"App unavailable|unavailable in your region", body, re.I):
                tag = "❌ 地区不支持(451)"
                fatals.append("Claude 判定该出口地区不支持")
            elif cf_challenge or (code == 403 and re.search(r"Just a moment|cf-browser-verification", body, re.I)):
                tag = "⚠️  触发 CF 挑战盾"
                warnings.append("Claude Web 触发 Cloudflare 挑战（建议无痕浏览器复核）")
            elif code == 403:
                tag = "❌ 403 拒绝访问"
                fatals.append("Claude Web 返回 403 拒绝访问")
            else:
                tag = "✅ 正常可达"
        elif kind == "chatgpt":
            if code == 403 and re.search(r"1020|Access denied", body, re.I):
                tag = "❌ CF 1020 拦截"
                warnings.append("ChatGPT 触发 Cloudflare 1020 拦截")
            elif cf_challenge:
                tag = "⚠️  触发 CF 挑战盾"
                warnings.append("ChatGPT 触发 Cloudflare 挑战")
            else:
                tag = "✅ 正常可达"
        elif kind == "gemini":
            if re.search(r"unavailable|unsupported", redir, re.I) or re.search(r"isn.t currently supported in your country", body, re.I):
                tag = "❌ 地区不支持"
                warnings.append("Gemini 判定地区不支持")
            else:
                tag = "✅ 正常可达"
        elif kind == "netflix":
            if code == 200:
                tag = "✅ 解锁全库(含非自制)"
            elif code == 404:
                tag = "⚠️  仅自制剧"
            elif code == 403:
                tag = "❌ 屏蔽"
            else:
                tag = f"⚠️  状态 {code}"
        else:
            if code in (200, 301, 302, 400, 401, 404, 405):
                tag = "✅ API 放行"
            elif code == 403:
                tag = "❌ 403 拦截"
                (fatals if critical else warnings).append(f"{name} 返回 403")
            else:
                tag = f"⚠️  HTTP {code}"

        print(f"  {name:<22} {tag:<22} (HTTP {code} | TTFB {r['ttfb_ms']}ms)")
        probe_results.append({
            "name": name, "status": tag, "http_code": code, "ttfb_ms": r["ttfb_ms"], "cf_challenge": cf_challenge
        })

    # ── 4. 全链路稳定性与多源防 429 测速 ───────────────────────────
    print(f"\n=== 4. 全链路稳定性（{args.rounds} 轮）& 测速 ===")
    bench_targets = [
        ("Google 204", "https://www.gstatic.com/generate_204"),
        ("Anthropic API", "https://api.anthropic.com/"),
        ("OpenAI API", "https://api.openai.com/"),
    ]
    bench_summary = []
    for bname, burl in bench_targets:
        ttfbs = []
        for idx in range(args.rounds):
            r = curl_request(burl, curl_info, proxy=proxy, timeout=10, head_only=True, discard_body=True)
            if r["ok"]:
                ttfbs.append(r["ttfb_ms"])
            if idx + 1 < args.rounds:
                time.sleep(0.3)
        ok_cnt = len(ttfbs)
        loss = round(((args.rounds - ok_cnt) / args.rounds) * 100)
        if ok_cnt > 0:
            avg_ms = round(sum(ttfbs) / ok_cnt, 1)
            max_ms = round(max(ttfbs), 1)
            print(f"  {bname:<16} 成功 {ok_cnt}/{args.rounds} (丢包 {loss}%) | TTFB 平均 {avg_ms}ms / 最差 {max_ms}ms")
            if loss > 0:
                fatals.append(f"{bname} 存在丢包/超时 ({loss}%)")
            if avg_ms > 1500:
                warnings.append(f"{bname} 全链路延迟偏高 (平均 {avg_ms}ms)")
            bench_summary.append({"name": bname, "ok": ok_cnt, "rounds": args.rounds, "avg_ttfb_ms": avg_ms, "max_ttfb_ms": max_ms})
        else:
            print(f"  {bname:<16} 全部失败 (0/{args.rounds})")
            fatals.append(f"{bname} 连续测速全失败")

    speed_report = None
    if args.speed:
        print("  正在进行多源防 429 单线程突发测速（串行，单次上限 5MB）...")
        total_dl_bytes = 0
        for s_name, s_url, limit_b in SPEED_CANDIDATES:
            r = curl_request(
                s_url, curl_info, proxy=proxy, timeout=20,
                follow_redirect=True, discard_body=True, max_bytes=limit_b,
            )
            total_dl_bytes += r["bytes"]
            if r["http_code"] == 429 or (r["ok"] and r["speed_mbps"] <= 0):
                print(f"    - {s_name}: 限流或无效样本 (HTTP {r['http_code']})，切换备用源...")
                time.sleep(0.5)
                continue
            if not r["ok"]:
                print(f"    - {s_name}: 失败/不可解析 (rc={r['rc']})，切换备用源...")
                time.sleep(0.5)
                continue
            speed_report = {"source": s_name, "speed_mbps": r["speed_mbps"], "bytes": r["bytes"], "total_ms": r["total_ms"]}
            print(f"  ✅ 单线程突发速率：{r['speed_mbps']} Mbps（源：{s_name}，耗时 {r['total_ms']}ms，非长跑均值）")
            if r["speed_mbps"] < 5.0:
                warnings.append(f"单线程速率偏低 ({r['speed_mbps']} Mbps)")
            break
        if not speed_report:
            print("  ⚠️  所有备用测速源均限流或超时（不记为 0 Mbps 故障，请稍后复测）")
            warnings.append("多源测速均未获得有效样本")
        print(f"  本次测速总消耗流量：{round(total_dl_bytes / (1024 * 1024), 2)} MB")
    else:
        print("  默认跳过大流量测速（如需测速请加 --speed）")

    # ── 5. 综合评级与复核链接 ──────────────────────────────────────
    print("\n=== 5. 综合结论 & 人工复核链接 ===")
    if fatals:
        grade_code, exit_code = "C", 2
        grade_desc = "C（命中红线，不建议直接上线，建议更换 IP 或排查链路）"
    elif len(warnings) >= 2:
        grade_code, exit_code = "B", 1
        grade_desc = "B（基本可用，存在轻微风控或性能提醒，视业务要求决定）"
    else:
        grade_code, exit_code = "A", 0
        grade_desc = "A（干净稳定，可作为固定出口长期使用）"

    print(f"  综合评级：{grade_desc}")
    if fatals:
        print("  [红线问题]")
        for item in fatals:
            print(f"   - {item}")
    if warnings:
        print("  [提醒项]")
        for item in warnings:
            print(f"   - {item}")

    print("\n  [人工 1 分钟复核直达链接]")
    print(f"   - Scamalytics 欺诈分 : https://scamalytics.com/ip/{disp_ip}")
    print(f"   - IPQS 深度风控库    : https://www.ipqualityscore.com/free-ip-lookup-proxy-vpn-test/lookup/{disp_ip}")
    print(f"   - ping0.cc 风控视图  : https://ping0.cc/ip/{disp_ip}")
    print(f"   - AbuseIPDB 黑名单   : https://www.abuseipdb.com/check/{disp_ip}")

    if args.out_json:
        def redact_obj(obj):
            if not args.redact:
                return obj
            s = json.dumps(obj, ensure_ascii=False)
            s = s.replace(exit_ip, disp_ip)
            if exit_ip6:
                s = s.replace(exit_ip6, disp_ip6)
            return json.loads(s)

        payload = {
            "version": __version__,
            "checked_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "env": {"os": curl_info["os"], "python": curl_info["python"], "curl": curl_info["curl_version"]},
            "proxy": masked_proxy,
            "redacted": bool(args.redact),
            "exit_ipv4": disp_ip,
            "exit_ipv6": disp_ip6,
            "unique_v4": [redact_ip(x) if args.redact else x for x in unique_v4],
            "grade": grade_code,
            "fatals": fatals,
            "warnings": warnings,
            "ipquery": redact_obj(ipq),
            "ipwho": redact_obj(ipwho),
            "ipinfo": redact_obj(ipinfo),
            "ipapi": redact_obj(ipapi),
            "probes": probe_results,
            "latency_bench": bench_summary,
            "speed": speed_report,
        }
        with open(args.out_json, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
        print(f"\n  已保存 JSON 报告：{args.out_json}")

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
