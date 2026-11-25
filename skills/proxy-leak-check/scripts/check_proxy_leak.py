#!/usr/bin/env python3
"""
跨平台（macOS / Windows / Linux）代理防泄露与节点体检脚本
仅使用 Python 3 标准库，零外部依赖。

特性：
  1. 自动识别 OS、系统代理、TUN 虚拟网卡、默认路由、系统 DNS 与代理监听端口
  2. 国内外分流验证（检测是否误开全局）
  3. 三层 DNS 泄露实测（系统原生 Fake-IP/TXT + 代理 HTTP + 无代理直连）
  4. 双栈 IPv4/IPv6 UDP STUN 穿透实测 + RFC 1928 SOCKS5 UDP ASSOCIATE 实测
  5. 扫描 Chrome / Edge / Brave / Arc 浏览器 WebRTC & DoH 配置与防护扩展
  6. 可选 --audit-nodes / --node：接入本地 Mihomo/Clash 控制 API 逐节点体检，
     自动发现 udp=false 暗雷节点，并在 finally 中严格恢复原选中状态。

安全约定：
  - 绝不输出任何 secret / password / uuid / 订阅 URL。
"""

import argparse
import ipaddress
import json
import os
import platform
import re
import shutil
import socket
import struct
import subprocess
import sys
import time
import urllib.parse
import urllib.request

__version__ = "1.1.1"

OS_NAME = platform.system()  # 'Darwin' | 'Windows' | 'Linux'
CURL_BIN = "curl.exe" if OS_NAME == "Windows" else (shutil.which("curl") or "curl")


def _redact_text(text: str) -> str:
    """对文本中的公网 IPv4 / 公网 IPv6 进行脱敏打码（保留 127.x / 10.x / 192.168.x / 198.18.x）。"""
    if not text:
        return text

    def _mask_v4(m):
        s = m.group(0)
        try:
            a = ipaddress.ip_address(s)
            if a.is_private or a.is_loopback or a.is_link_local or s.startswith("198.18."):
                return s
            p = s.split(".")
            return f"{p[0]}.{p[1]}.*.*"
        except ValueError:
            return s

    def _mask_v6(m):
        s = m.group(0)
        try:
            a = ipaddress.ip_address(s)
            if a.is_loopback or a.is_link_local or a.is_private:
                return s
            segs = a.exploded.split(":")
            return f"{segs[0]}:{segs[1]}:****::{segs[-1]}"
        except ValueError:
            return s

    out = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", _mask_v4, text)
    out = re.sub(r"\b[23][0-9a-fA-F]{3}:[0-9a-fA-F:]+\b", _mask_v6, out)
    return out


def redact_report(obj):
    if isinstance(obj, str):
        return _redact_text(obj)
    if isinstance(obj, list):
        return [redact_report(x) for x in obj]
    if isinstance(obj, dict):
        res = {}
        for k, v in obj.items():
            if k == "node" and isinstance(v, str):
                res[k] = f"node#{abs(hash(v)) % 10000:04d}"
            elif k in ("restored", "udp_false_warnings"):
                res[k] = "<redacted>" if isinstance(v, str) else [f"<warning#{i+1}>" for i in range(len(v))]
            else:
                res[k] = redact_report(v)
        return res
    return obj


def run_cmd(cmd, timeout=8):
    try:
        r = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
            timeout=timeout,
        )
        return (r.stdout or "").strip(), (r.stderr or "").strip(), r.returncode
    except Exception as e:
        return "", str(e), -1


# ── 1. 系统代理、网卡、路由与进程探测 ─────────────────────────────

def detect_system_proxy():
    info = {"enabled": False, "http": None, "https": None, "socks": None}
    if OS_NAME == "Windows":
        try:
            import winreg
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
            )
            enable, _ = winreg.QueryValueEx(key, "ProxyEnable")
            server = ""
            override = ""
            try:
                server, _ = winreg.QueryValueEx(key, "ProxyServer")
            except OSError:
                pass
            try:
                override, _ = winreg.QueryValueEx(key, "ProxyOverride")
            except OSError:
                pass
            winreg.CloseKey(key)
            info["enabled"] = bool(enable)
            if server:
                info["http"] = server
                info["https"] = server
            if override:
                info["override"] = override
        except Exception as e:
            info["error"] = str(e)
    elif OS_NAME == "Darwin":
        out, _, rc = run_cmd(["scutil", "--proxy"])
        if rc == 0:
            kv = {}
            for line in out.splitlines():
                m = re.match(r"^\s*([A-Za-z0-9_]+)\s*:\s*(.+)$", line)
                if m:
                    kv[m.group(1)] = m.group(2).strip()
            if kv.get("HTTPEnable") == "1" and kv.get("HTTPProxy"):
                info["enabled"] = True
                info["http"] = f"{kv['HTTPProxy']}:{kv.get('HTTPPort', '')}"
            if kv.get("HTTPSEnable") == "1" and kv.get("HTTPSProxy"):
                info["enabled"] = True
                info["https"] = f"{kv['HTTPSProxy']}:{kv.get('HTTPSPort', '')}"
            if kv.get("SOCKSEnable") == "1" and kv.get("SOCKSProxy"):
                info["enabled"] = True
                info["socks"] = f"{kv['SOCKSProxy']}:{kv.get('SOCKSPort', '')}"
    else:
        for k, target in [("http_proxy", "http"), ("https_proxy", "https"), ("all_proxy", "socks")]:
            v = os.environ.get(k) or os.environ.get(k.upper())
            if v:
                info["enabled"] = True
                info[target] = v
    return info


def detect_listening_ports():
    common_ports = [7890, 7891, 7897, 7898, 6152, 6153, 1080, 10808, 10809, 2080, 2081, 9090, 9097]
    open_ports = []
    for p in common_ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.25)
        try:
            if s.connect_ex(("127.0.0.1", p)) == 0:
                open_ports.append(p)
        finally:
            s.close()
    return open_ports


def detect_proxy_processes():
    pat = re.compile(
        r"clash|mihomo|verge|bettbox|flclash|sparkle|party|v2ray|xray|sing-box|surge|stash|loon|hiddify|nekobox|nekoray|shadowrocket",
        re.I,
    )
    found = set()
    if OS_NAME == "Windows":
        out, _, _ = run_cmd(["tasklist", "/FO", "CSV", "/NH"])
        for line in out.splitlines():
            name = line.split(",")[0].strip('"')
            if pat.search(name):
                found.add(name)
    else:
        out, _, _ = run_cmd(["ps", "-axo", "comm="])
        for line in out.splitlines():
            name = os.path.basename(line.strip())
            if pat.search(name):
                found.add(name)
    return sorted(found)


def detect_network_and_tun():
    res = {"tun_detected": False, "tun_details": [], "dns_servers": [], "public_v6_local": []}
    if OS_NAME == "Windows":
        ps = (
            "[Console]::OutputEncoding=[Text.UTF8Encoding]::new();"
            "Get-NetIPConfiguration | Where-Object {$_.NetAdapter.Status -eq 'Up'} | ForEach-Object {"
            "  [PSCustomObject]@{"
            "    alias=$_.InterfaceAlias; desc=$_.InterfaceDescription;"
            "    v4=@($_.IPv4Address.IPAddress); v6=@($_.IPv6Address.IPAddress);"
            "    dns=@($_.DNSServer.ServerAddresses)"
            "  }"
            "} | ConvertTo-Json -Compress"
        )
        shell = shutil.which("pwsh") or "powershell"
        out, _, rc = run_cmd([shell, "-NoProfile", "-Command", ps], timeout=10)
        if rc == 0 and out:
            try:
                items = json.loads(out)
                if isinstance(items, dict):
                    items = [items]
                for it in items:
                    alias = str(it.get("alias") or "")
                    desc = str(it.get("desc") or "")
                    v4 = [x for x in (it.get("v4") or []) if x]
                    v6 = [x for x in (it.get("v6") or []) if x]
                    dns = [x for x in (it.get("dns") or []) if x]
                    if (
                        any(k in (alias + " " + desc).lower() for k in ("tun", "meta", "clash", "mihomo", "bettbox", "sing", "wintun", "verge"))
                        and "tailscale" not in (alias + " " + desc).lower()
                    ) or any(ip.startswith("198.18.") for ip in v4):
                        res["tun_detected"] = True
                        res["tun_details"].append(f"{alias} ({desc}) v4={v4} v6={v6} dns={dns}")
                    for ip in v6:
                        if re.match(r"^[23][0-9a-fA-F]{3}:", ip):
                            res["public_v6_local"].append(ip)
                    if dns and "vethernet" not in alias.lower() and "tailscale" not in alias.lower():
                        res["dns_servers"].append(f"{alias}: {', '.join(dns[:6])}")
            except Exception:
                pass
    elif OS_NAME == "Darwin":
        out, _, rc = run_cmd(["ifconfig"])
        if rc == 0:
            cur_if = None
            cur_v4, cur_v6 = [], []

            def flush_if():
                if not cur_if:
                    return
                if cur_if.startswith("utun") and (
                    any(ip.startswith("198.18.") for ip in cur_v4)
                    or any(ip.startswith("fdfe:") for ip in cur_v6)
                ):
                    res["tun_detected"] = True
                    res["tun_details"].append(f"{cur_if} v4={cur_v4} v6={cur_v6}")
                for ip in cur_v6:
                    if re.match(r"^[23][0-9a-fA-F]{3}:", ip):
                        res["public_v6_local"].append(f"{cur_if}:{ip}")

            for line in out.splitlines():
                m = re.match(r"^([a-zA-Z0-9_]+):\s+flags=", line)
                if m:
                    flush_if()
                    cur_if, cur_v4, cur_v6 = m.group(1), [], []
                elif cur_if:
                    m4 = re.search(r"\binet\s+(\d+\.\d+\.\d+\.\d+)", line)
                    if m4:
                        cur_v4.append(m4.group(1))
                    m6 = re.search(r"\binet6\s+([0-9a-fA-F:]+)", line)
                    if m6:
                        cur_v6.append(m6.group(1))
            flush_if()

        dns_out, _, rc2 = run_cmd(["scutil", "--dns"])
        if rc2 == 0:
            servers = []
            for line in dns_out.splitlines():
                m = re.search(r"nameserver\[\d+\]\s*:\s*(\S+)", line)
                if m and m.group(1) not in servers:
                    servers.append(m.group(1))
                if len(servers) >= 8:
                    break
            if servers:
                res["dns_servers"].append("scutil: " + ", ".join(servers))
    else:
        out, _, rc = run_cmd(["ip", "-o", "addr", "show"])
        if rc == 0:
            for line in out.splitlines():
                if "198.18." in line or re.search(r"\b(tun|utun|mihomo|meta)\d*\b", line, re.I):
                    res["tun_detected"] = True
                    res["tun_details"].append(line.strip())
                m6 = re.search(r"\binet6\s+([23][0-9a-fA-F:]+)/", line)
                if m6:
                    res["public_v6_local"].append(m6.group(1))
        if os.path.exists("/etc/resolv.conf"):
            ns = [
                l.split()[1]
                for l in open("/etc/resolv.conf", encoding="utf-8", errors="ignore")
                if l.strip().startswith("nameserver")
            ]
            if ns:
                res["dns_servers"].append("resolv.conf: " + ", ".join(ns))
    return res


# ── 2. DNS / IP / STUN / SOCKS5 UDP 实测 ──────────────────────────

def curl_text(url, proxy=None, noproxy=False, follow=False, ipv4=False, timeout=8, extra=None):
    cmd = [CURL_BIN, "-s", "--max-time", str(timeout)]
    if ipv4:
        cmd.append("-4")
    if follow:
        cmd.append("-L")
    if noproxy:
        cmd += ["--noproxy", "*"]
    elif proxy:
        p = proxy if "://" in proxy else f"http://{proxy}"
        cmd += ["-x", p]
    if extra:
        cmd += extra
    cmd.append(url)
    out, err, rc = run_cmd(cmd, timeout=timeout + 3)
    return out if rc == 0 else f"ERR(rc={rc})"


def parse_edns_json(raw):
    try:
        d = json.loads(raw).get("dns", {})
        if d:
            return f"{d.get('ip')} ({d.get('geo')})"
    except Exception:
        pass
    return raw[:60] if raw else "EMPTY"


def system_dns_checks():
    res = {}
    if OS_NAME == "Windows" or not shutil.which("dig"):
        out1, _, _ = run_cmd(["nslookup", "-type=A", "claude.ai"])
        addrs = re.findall(r"Address(?:es)?:\s*([0-9a-fA-F.:]+)", out1)
        res["claude_ai_a"] = addrs[1:] if len(addrs) > 1 else addrs
        res["fake_ip_active"] = any(a.startswith("198.18.") for a in res["claude_ai_a"])
        out2, _, _ = run_cmd(["nslookup", "-type=TXT", "o-o.myaddr.l.google.com"])
        txts = re.findall(r'"([^"]+)"', out2)
        res["google_txt_resolver"] = txts[:3]
    else:
        out1, _, _ = run_cmd(["dig", "+short", "+time=3", "+tries=1", "A", "claude.ai"])
        addrs = [l.strip() for l in out1.splitlines() if l.strip()]
        res["claude_ai_a"] = addrs
        res["fake_ip_active"] = any(a.startswith("198.18.") for a in addrs)
        out2, _, _ = run_cmd(["dig", "+short", "+time=3", "+tries=1", "TXT", "o-o.myaddr.l.google.com"])
        res["google_txt_resolver"] = [l.strip().strip('"') for l in out2.splitlines() if l.strip()][:3]
    return res


def parse_stun_response(data, txid):
    pos, magic = 20, 0x2112A442
    addrs = []
    while pos + 4 <= len(data):
        atype, alen = struct.unpack("!HH", data[pos:pos + 4])
        val = data[pos + 4:pos + 4 + alen]
        if atype == 0x0020 and alen >= 8:
            fam = val[1]
            xport = struct.unpack("!H", val[2:4])[0] ^ (magic >> 16)
            if fam == 0x01:
                xip = struct.unpack("!I", val[4:8])[0] ^ magic
                addrs.append(f"{socket.inet_ntoa(struct.pack('!I', xip))}:{xport}")
            elif fam == 0x02 and alen >= 20:
                key = struct.pack("!I", magic) + txid
                ip6 = socket.inet_ntop(socket.AF_INET6, bytes(a ^ b for a, b in zip(val[4:20], key)))
                addrs.append(f"[{ip6}]:{xport}")
        elif atype == 0x0001 and alen >= 8 and val[1] == 0x01:
            p = struct.unpack("!H", val[2:4])[0]
            addrs.append(f"{socket.inet_ntoa(val[4:8])}:{p}")
        pos += 4 + ((alen + 3) // 4) * 4
    return addrs


def direct_udp_stun(host, port, family):
    txid = os.urandom(12)
    req = struct.pack("!HHI", 0x0001, 0, 0x2112A442) + txid
    s = socket.socket(family, socket.SOCK_DGRAM)
    s.settimeout(4)
    try:
        infos = socket.getaddrinfo(host, port, family, socket.SOCK_DGRAM)
        s.sendto(req, infos[0][4])
        data, _ = s.recvfrom(2048)
        addrs = parse_stun_response(data, txid)
        return addrs[0] if addrs else "NO_ADDR"
    except Exception as e:
        return f"BLOCKED/FAIL({type(e).__name__})"
    finally:
        s.close()


def socks5_udp_stun(proxy_host, proxy_port, stun_host="stun.cloudflare.com", stun_port=3478):
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    tcp.settimeout(5)
    udp.settimeout(5)
    try:
        tcp.connect((proxy_host, proxy_port))
        tcp.sendall(b"\x05\x01\x00")
        if tcp.recv(2) != b"\x05\x00":
            return "SOCKS5_AUTH_FAIL"
        tcp.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
        resp = tcp.recv(64)
        if len(resp) < 10 or resp[1] != 0x00:
            return f"UDP_ASSOC_FAIL(rep={resp[1] if len(resp) > 1 else '?'})"
        if resp[3] == 1:
            relay_ip = socket.inet_ntoa(resp[4:8])
            relay_port = struct.unpack("!H", resp[8:10])[0]
        elif resp[3] == 4:
            relay_ip = socket.inet_ntop(socket.AF_INET6, resp[4:20])
            relay_port = struct.unpack("!H", resp[20:22])[0]
        else:
            return f"UNSUPPORTED_ATYP({resp[3]})"
        if relay_ip in ("0.0.0.0", "::"):
            relay_ip = proxy_host

        txid = os.urandom(12)
        stun_req = struct.pack("!HHI", 0x0001, 0, 0x2112A442) + txid
        dom = stun_host.encode()
        pkt = b"\x00\x00\x00\x03" + bytes([len(dom)]) + dom + struct.pack("!H", stun_port) + stun_req
        udp.sendto(pkt, (relay_ip, relay_port))
        raw, _ = udp.recvfrom(4096)
        ratyp = raw[3]
        hdr_len = 10 if ratyp == 1 else (22 if ratyp == 4 else 7 + raw[4])
        addrs = parse_stun_response(raw[hdr_len:], txid)
        return addrs[0] if addrs else "STUN_NO_ADDR"
    except Exception as e:
        return f"FAIL({type(e).__name__})"
    finally:
        udp.close()
        tcp.close()


# ── 3. 浏览器 WebRTC / DoH / 扩展扫描（macOS + Windows）─────────────

def scan_browsers():
    home = os.path.expanduser("~")
    if OS_NAME == "Darwin":
        roots = [
            ("Chrome", os.path.join(home, "Library/Application Support/Google/Chrome")),
            ("Edge", os.path.join(home, "Library/Application Support/Microsoft Edge")),
            ("Brave", os.path.join(home, "Library/Application Support/BraveSoftware/Brave-Browser")),
            ("Arc", os.path.join(home, "Library/Application Support/Arc/User Data")),
        ]
    elif OS_NAME == "Windows":
        la = os.environ.get("LOCALAPPDATA", "")
        roots = [
            ("Chrome", os.path.join(la, r"Google\Chrome\User Data")),
            ("Edge", os.path.join(la, r"Microsoft\Edge\User Data")),
            ("Brave", os.path.join(la, r"BraveSoftware\Brave-Browser\User Data")),
        ]
    else:
        roots = [
            ("Chrome", os.path.join(home, ".config/google-chrome")),
            ("Chromium", os.path.join(home, ".config/chromium")),
            ("Brave", os.path.join(home, ".config/BraveSoftware/Brave-Browser")),
        ]

    # 常见 WebRTC 防护插件 ID 或名称关键词
    known_webrtc_ids = {
        "fjkmabmdepjfammlpliljpnbhleegehm": "WebRTC Control",
        "eiadekoaikejlgdbkbdfeijglgfdalml": "WebRTC Leak Prevent",
        "bnomihmgiccainjcjblhegjgglakjdd": "WebRTC Leak Shield",
        "nphplpgoakhhjchkkhmiggakijnkhfnd": "WebRTC Network Limiter",
        "kjkcdgcpmpjklmcjnfmkpbfkcfikfmfh": "WebRTC Leak Prevent (Alt)",
    }
    findings = []
    for bname, base in roots:
        if not os.path.isdir(base):
            continue
        for entry in sorted(os.listdir(base)):
            if entry != "Default" and not entry.startswith("Profile "):
                continue
            pdir = os.path.join(base, entry)
            webrtc = None
            doh = None
            exts = {}
            for pname in ("Preferences", "Secure Preferences"):
                pref = os.path.join(pdir, pname)
                if not os.path.isfile(pref):
                    continue
                try:
                    j = json.load(open(pref, "r", encoding="utf-8", errors="ignore"))
                    if j.get("webrtc"):
                        webrtc = j.get("webrtc")
                    if j.get("dns_over_https"):
                        doh = j.get("dns_over_https")
                    for eid, ev in (j.get("extensions", {}).get("settings") or {}).items():
                        if not isinstance(ev, dict):
                            continue
                        mf = ev.get("manifest") or {}
                        name = str(mf.get("name") or "")
                        state = ev.get("state")
                        if eid in known_webrtc_ids:
                            exts[eid] = f"{known_webrtc_ids[eid]}(state={state})"
                        elif any(k in name.lower() for k in ("webrtc", "leak prevent", "leak shield")):
                            exts[eid] = f"{name}(state={state})"
                except Exception:
                    pass
            # 兜底扫描 Extensions/<id> 目录（刚安装尚未落盘 Preferences 时也能识别）
            ext_dir = os.path.join(pdir, "Extensions")
            if os.path.isdir(ext_dir):
                for eid in os.listdir(ext_dir):
                    if eid in exts:
                        continue
                    if eid in known_webrtc_ids:
                        exts[eid] = f"{known_webrtc_ids[eid]}(installed)"
                        continue
                    epath = os.path.join(ext_dir, eid)
                    if not os.path.isdir(epath):
                        continue
                    for ver in sorted(os.listdir(epath), reverse=True)[:1]:
                        mf_path = os.path.join(epath, ver, "manifest.json")
                        if os.path.isfile(mf_path):
                            try:
                                mf = json.load(open(mf_path, "r", encoding="utf-8", errors="ignore"))
                                text = f"{mf.get('name', '')} {mf.get('description', '')}".lower()
                                if "webrtc" in text:
                                    exts[eid] = f"{mf.get('name', eid)}(installed)"
                            except Exception:
                                pass
            if webrtc or doh or exts:
                findings.append({
                    "browser": f"{bname}/{entry}",
                    "webrtc": webrtc,
                    "doh": doh,
                    "extensions": sorted(exts.values()),
                })
    return findings


# ── 4. Mihomo / Clash 控制 API 自动发现与逐节点巡检 ────────────────

def discover_mihomo_api(explicit_api=None):
    candidates = [explicit_api] if explicit_api else ["127.0.0.1:9090", "127.0.0.1:9097"]
    home = os.path.expanduser("~")
    if OS_NAME == "Darwin":
        cfg_dirs = [
            os.path.join(home, "Library/Application Support/com.appshub.Bettbox"),
            os.path.join(home, "Library/Application Support/io.github.clash-verge-rev.clash-verge-rev"),
            os.path.join(home, "Library/Application Support/mihomo-party"),
            os.path.join(home, "Library/Application Support/flclash"),
            os.path.join(home, ".config/mihomo"),
            os.path.join(home, ".config/clash"),
            os.path.join(home, ".config/clash-verge"),
        ]
    elif OS_NAME == "Windows":
        ap = os.environ.get("APPDATA", "")
        la = os.environ.get("LOCALAPPDATA", "")
        cfg_dirs = [
            os.path.join(ap, r"com.appshub\Bettbox"),
            os.path.join(ap, r"io.github.clash-verge-rev.clash-verge-rev"),
            os.path.join(la, r"io.github.clash-verge-rev.clash-verge-rev"),
            os.path.join(ap, "mihomo-party"),
            os.path.join(ap, "sparkle"),
            os.path.join(ap, "flclash"),
            os.path.join(home, r".config\mihomo"),
            os.path.join(home, r".config\clash"),
        ]
    else:
        cfg_dirs = [
            os.path.join(home, ".config/clash-verge"),
            os.path.join(home, ".config/mihomo"),
            os.path.join(home, ".config/clash"),
            os.path.join(home, ".config/mihomo-party"),
        ]

    secrets = [""]
    for d in cfg_dirs:
        if not os.path.isdir(d):
            continue
        for fname in ("config.json", "config.yaml", "config.yml", "clash-verge.yaml"):
            p = os.path.join(d, fname)
            if not os.path.isfile(p):
                continue
            try:
                txt = open(p, "r", encoding="utf-8", errors="ignore").read()
                for m in re.finditer(r'"secret"\s*:\s*"([^"]+)"', txt):
                    if m.group(1) not in secrets:
                        secrets.append(m.group(1))
                for m in re.finditer(r'^\s*secret\s*:\s*[\'"]?([^\s\'"]+)', txt, re.M):
                    if m.group(1) not in secrets:
                        secrets.append(m.group(1))
            except Exception:
                pass

    for addr in candidates:
        if not addr:
            continue
        for sec in secrets:
            hdrs = {"Authorization": f"Bearer {sec}"} if sec else {}
            try:
                req = urllib.request.Request(f"http://{addr}/configs", headers=hdrs)
                with urllib.request.urlopen(req, timeout=2.5) as r:
                    if r.status == 200:
                        return addr, sec, json.loads(r.read().decode())
            except Exception:
                continue
    return None, None, None


def audit_mihomo_nodes(api_addr, secret, tun_active, proxy_host, proxy_port, node_filter=None):
    hdrs = {"Content-Type": "application/json"}
    if secret:
        hdrs["Authorization"] = f"Bearer {secret}"

    def api_get(path):
        req = urllib.request.Request(f"http://{api_addr}{path}", headers=hdrs)
        with urllib.request.urlopen(req, timeout=5) as r:
            return json.loads(r.read().decode())

    def api_put(path, body):
        req = urllib.request.Request(
            f"http://{api_addr}{path}",
            data=json.dumps(body).encode(),
            headers=hdrs,
            method="PUT",
        )
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status

    proxies = api_get("/proxies").get("proxies", {})
    skip_types = {
        "Selector", "URLTest", "Fallback", "LoadBalance",
        "Direct", "Reject", "RejectDrop", "Pass", "Compatible", "PassRule",
    }

    # 找出可切换的主策略组（优先找包含实际节点的 Selector，如 手动选择 / PROXY / Proxy / 节点选择）
    manual_group = None
    default_group = None
    for cand in ("手动选择", "节点选择", "PROXY", "Proxy", "Select"):
        if cand in proxies and proxies[cand].get("type") == "Selector":
            manual_group = cand
            break
    for cand in ("默认代理", "Proxy", "PROXY", "节点选择"):
        if cand in proxies and proxies[cand].get("type") == "Selector":
            default_group = cand
            break
    if not manual_group:
        for name, info in proxies.items():
            if info.get("type") == "Selector" and name != "GLOBAL":
                members = info.get("all") or []
                if any(proxies.get(m, {}).get("type") not in skip_types for m in members):
                    manual_group = name
                    break

    # 扫描自动组/链式中转里混入 udp=false 的存活节点
    udp_false_warnings = []
    for gname, ginfo in proxies.items():
        if ginfo.get("type") in ("URLTest", "Fallback", "Selector"):
            for m in (ginfo.get("all") or []):
                minfo = proxies.get(m, {})
                if minfo.get("type") not in skip_types and minfo.get("alive") and minfo.get("udp") is False:
                    udp_false_warnings.append(f"组「{gname}」包含 udp=false 存活节点「{m}」")

    if not manual_group:
        return {"error": "未找到可切换节点的 Selector 策略组", "udp_false_warnings": udp_false_warnings}

    members = [
        m for m in (proxies[manual_group].get("all") or [])
        if m in proxies and proxies[m].get("type") not in skip_types
    ]
    if node_filter:
        members = [m for m in members if node_filter.lower() in m.lower()]
    else:
        # 默认跳过已判定死亡/超时的节点
        alive_members = [m for m in members if proxies[m].get("alive") is not False]
        if alive_members:
            members = alive_members

    orig_manual = proxies[manual_group].get("now")
    orig_default = proxies[default_group].get("now") if default_group else None
    m_enc = urllib.parse.quote(manual_group, safe="")
    d_enc = urllib.parse.quote(default_group, safe="") if default_group else None

    results = []
    try:
        if default_group and default_group != manual_group and manual_group in (proxies[default_group].get("all") or []):
            api_put(f"/proxies/{d_enc}", {"name": manual_group})

        for node in members:
            api_put(f"/proxies/{m_enc}", {"name": node})
            time.sleep(0.35)
            p_arg = None if tun_active else f"{proxy_host}:{proxy_port}"
            tcp_ip = curl_text("https://api.ipify.org", proxy=p_arg, noproxy=tun_active, ipv4=True, timeout=7)
            edns_raw = curl_text("http://edns.ip-api.com/json", proxy=p_arg, noproxy=tun_active, follow=True, ipv4=True, timeout=8)
            cf204 = curl_text(
                "https://cp.cloudflare.com/generate_204",
                proxy=p_arg,
                noproxy=tun_active,
                timeout=7,
                extra=["-o", os.devnull, "-w", "%{http_code}/%{time_total}s"],
            )
            if tun_active:
                udp_ip = direct_udp_stun("stun.cloudflare.com", 3478, socket.AF_INET)
            else:
                udp_ip = socks5_udp_stun(proxy_host, proxy_port)

            ninfo = proxies[node]
            results.append({
                "node": node,
                "type": ninfo.get("type"),
                "cfg_udp": ninfo.get("udp"),
                "dialer": ninfo.get("dialer-proxy") or "-",
                "tcp_ip": tcp_ip,
                "udp_stun": udp_ip,
                "dns": parse_edns_json(edns_raw),
                "cf_204": cf204,
            })
    finally:
        if orig_manual:
            api_put(f"/proxies/{m_enc}", {"name": orig_manual})
        if default_group and orig_default:
            api_put(f"/proxies/{d_enc}", {"name": orig_default})

    return {
        "manual_group": manual_group,
        "restored": f"{default_group}={orig_default}, {manual_group}={orig_manual}" if default_group else f"{manual_group}={orig_manual}",
        "udp_false_warnings": sorted(set(udp_false_warnings)),
        "nodes": results,
    }


# ── 5. 主流程与报告输出 ───────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="跨平台代理防泄露与节点体检工具")
    parser.add_argument("--proxy", help="手工指定本地代理 host:port（默认自动探测）")
    parser.add_argument("--api", help="手工指定 Mihomo/Clash 控制 API host:port")
    parser.add_argument("--audit-nodes", action="store_true", help="逐个巡检存活节点 TCP/UDP/DNS")
    parser.add_argument("--node", help="仅复测名称包含该关键字的节点")
    parser.add_argument("--json", action="store_true", help="输出 JSON 格式")
    parser.add_argument("--redact", action="store_true", help="打码公网 IP 与节点名（分享或提 Issue 前推荐开启）")
    parser.add_argument("--version", action="version", version=f"check_proxy_leak {__version__}")
    args = parser.parse_args()

    sys_proxy = detect_system_proxy()
    open_ports = detect_listening_ports()
    procs = detect_proxy_processes()
    net = detect_network_and_tun()
    api_addr, api_secret, live_cfg = discover_mihomo_api(args.api)

    tun_active = bool(net["tun_detected"] or ((live_cfg or {}).get("tun") or {}).get("enable"))

    # 决定使用的本地代理端口（用于系统代理测试 & SOCKS5 UDP）
    proxy_str = args.proxy
    if not proxy_str:
        for cand in (sys_proxy.get("http"), sys_proxy.get("socks")):
            if cand and ":" in cand:
                proxy_str = cand.split("://")[-1]
                break
    if not proxy_str:
        for p in (7890, 7897, 7891, 6152, 6153, 10808, 1080, 2080):
            if p in open_ports:
                proxy_str = f"127.0.0.1:{p}"
                break

    proxy_host, proxy_port = ("127.0.0.1", 7890)
    if proxy_str and ":" in proxy_str:
        h, p = proxy_str.rsplit(":", 1)
        proxy_host = h
        try:
            proxy_port = int(p)
        except ValueError:
            pass

    # 核心网络实测
    sys_dns = system_dns_checks()
    direct_overseas_ip = curl_text("https://api.ipify.org", noproxy=True, ipv4=True, timeout=7)
    direct_cn_ip = curl_text("https://myip.ipip.net", noproxy=True, timeout=7)
    direct_edns = parse_edns_json(curl_text("http://edns.ip-api.com/json", noproxy=True, follow=True, ipv4=True, timeout=8))

    proxy_overseas_ip = curl_text("https://api.ipify.org", proxy=proxy_str, ipv4=True, timeout=7) if proxy_str else None
    proxy_edns = (
        parse_edns_json(curl_text("http://edns.ip-api.com/json", proxy=proxy_str, follow=True, ipv4=True, timeout=8))
        if proxy_str
        else None
    )

    stun = {
        "direct_cf_v4": direct_udp_stun("stun.cloudflare.com", 3478, socket.AF_INET),
        "direct_cf_v6": direct_udp_stun("stun.cloudflare.com", 3478, socket.AF_INET6),
        "direct_google_v4": direct_udp_stun("stun.l.google.com", 19302, socket.AF_INET),
        "direct_google_v6": direct_udp_stun("stun.l.google.com", 19302, socket.AF_INET6),
        "socks5_cf_udp": socks5_udp_stun(proxy_host, proxy_port) if proxy_str else None,
    }

    browsers = scan_browsers()

    node_audit = None
    if args.audit_nodes or args.node:
        if api_addr:
            node_audit = audit_mihomo_nodes(api_addr, api_secret, tun_active, proxy_host, proxy_port, args.node)
        else:
            node_audit = {"error": "未探测到可用的 Mihomo/Clash 控制 API (9090/9097)"}

    report = {
        "os": f"{OS_NAME} {platform.release()} ({platform.machine()})",
        "proxy_processes": procs,
        "listening_ports": open_ports,
        "system_proxy": sys_proxy,
        "tun_active": tun_active,
        "tun_details": net["tun_details"],
        "local_dns_servers": net["dns_servers"],
        "local_public_ipv6": net["public_v6_local"],
        "mihomo_live": {
            "api": api_addr,
            "mode": (live_cfg or {}).get("mode"),
            "ipv6": (live_cfg or {}).get("ipv6"),
            "tun_enable": ((live_cfg or {}).get("tun") or {}).get("enable"),
        } if live_cfg else None,
        "split_routing": {
            "direct_overseas_ip": direct_overseas_ip,
            "proxy_overseas_ip": proxy_overseas_ip,
            "direct_cn_ip": direct_cn_ip,
        },
        "dns_checks": {
            "system_native": sys_dns,
            "direct_edns": direct_edns,
            "proxy_edns": proxy_edns,
        },
        "udp_stun_checks": stun,
        "browsers": browsers,
        "node_audit": node_audit,
    }

    if args.redact:
        report = redact_report(report)

    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return

    sr = report["split_routing"]
    dc = report["dns_checks"]
    st = report["udp_stun_checks"]
    br = report["browsers"]
    na = report["node_audit"]

    print(f"=== 代理防泄露体检 ({report['os']}) {'[已脱敏]' if args.redact else ''} ===")
    print(f"代理进程: {', '.join(report['proxy_processes']) or '未识别'} | 监听端口: {report['listening_ports']}")
    print(f"系统代理: enabled={report['system_proxy']['enabled']} http={report['system_proxy']['http']} socks={report['system_proxy']['socks']}")
    print(f"TUN 模式: {'开启' if report['tun_active'] else '未开启'} {report['tun_details'] or ''}")
    if report["mihomo_live"]:
        ml = report["mihomo_live"]
        print(f"Mihomo 控制口: {ml['api']} | mode={ml['mode']} | ipv6={ml['ipv6']} | tun={ml['tun_enable']}")
    print(f"网卡 DNS: {report['local_dns_servers']}")
    print(f"本机公网 IPv6: {report['local_public_ipv6'] or '无'}")

    print("\n--- 1. 分流与出口 IP ---")
    print(f"  无代理参数直连海外 IP : {sr['direct_overseas_ip']}")
    if proxy_str:
        print(f"  经代理({proxy_str})海外 IP : {sr['proxy_overseas_ip']}")
    print(f"  无代理参数国内测速点  : {sr['direct_cn_ip']}")

    print("\n--- 2. 三层 DNS 泄露实测 ---")
    print(f"  系统解析 claude.ai    : {dc['system_native']['claude_ai_a']} (Fake-IP={dc['system_native']['fake_ip_active']})")
    print(f"  系统解析 Google TXT   : {dc['system_native']['google_txt_resolver']}")
    print(f"  无代理参数 edns       : {dc['direct_edns']}")
    if proxy_str:
        print(f"  经代理({proxy_str}) edns : {dc['proxy_edns']}")

    print("\n--- 3. UDP STUN 穿透与 SOCKS5 UDP 实测 ---")
    print(f"  直连 STUN CF   IPv4   : {st['direct_cf_v4']}")
    print(f"  直连 STUN CF   IPv6   : {st['direct_cf_v6']}")
    print(f"  直连 STUN Goog IPv4   : {st['direct_google_v4']}")
    print(f"  直连 STUN Goog IPv6   : {st['direct_google_v6']}")
    if st["socks5_cf_udp"]:
        print(f"  SOCKS5 UDP CF ({proxy_host}:{proxy_port}): {st['socks5_cf_udp']}")

    print("\n--- 4. 浏览器 WebRTC / DoH 配置扫描 ---")
    if br:
        for b in br:
            print(f"  [{b['browser']}] webrtc={b['webrtc']} | doh={b['doh']} | exts={b['extensions']}")
    else:
        print("  未检测到显式 WebRTC/DoH 自定义配置或防护扩展（Safari 默认受系统隐私保护）")

    if na:
        print("\n--- 5. Mihomo/Clash 节点巡检 ---")
        if "error" in na:
            print(f"  ⚠️ {na['error']}")
        else:
            if na["udp_false_warnings"]:
                print("  ⚠️ 发现 udp=false 暗雷:")
                for w in na["udp_false_warnings"]:
                    print(f"    - {w}")
            for item in na["nodes"]:
                print(
                    f"  [{item['node']}] udp={item['cfg_udp']} | dialer={item['dialer']} | "
                    f"TCP={item['tcp_ip']} | UDP={item['udp_stun']} | DNS={item['dns']} | 204={item['cf_204']}"
                )
            print(f"  已恢复原状态: {na['restored']}")


if __name__ == "__main__":
    main()
