---
name: nat-vps-proxy
description: >-
  在 Linux / NAT / 低内存（72MB~256MB）VPS 服务端部署代理节点（sing-box、shoes 或 realm），
  完成 VLESS-REALITY / SS2022 配置、端口映射、cgroup 内存调优、出口族锁定、安全加固、服务端体检，
  并接进客户端链式代理（Mihomo / Bettbox / Shadowrocket）。
  触发词：搭节点、部署代理、NAT 小鸡、低内存、shoes、realm、端口转发、落地节点、链式代理、入口不通、退订重建。
  不用于出口 IP 纯净度/风控验收（请用 ipsock-check），也不用于本机 DNS/WebRTC/TUN 防泄露检查（请用 proxy-leak-check）。
---

# NAT/VPS 小鸡做代理节点（服务端部署）

目标：将一台 Linux（可能是 NAT、可能仅 72MB~256MB 内存）小鸡在 10 分钟内安全部署为可用节点，完成服务端自证并接入客户端。

> 若本技能同目录存在 `local.md`（本地私有备注，不入库），执行前先一并读取。

## 适用边界

- **适用**：Debian/Ubuntu（systemd）、Alpine + OpenRC 容器；固定地区落地或中转节点；客户端为 Mihomo 系或 Shadowrocket。
- **不适用**：无 bash/apk/rc-service 的极简 scratch 镜像；需要多用户商业面板运营；对原生 UDP 有强独占要求的实时游戏/语音。

## 第 0 步：先探测，别假设

```bash
cat /etc/os-release | head -3; uname -m; nproc
free -m | head -2; df -h / | tail -1
ip -4 -o addr show; ip route | head -3
cat /sys/fs/cgroup/memory.max 2>/dev/null   # 容器内存上限
curl -s4 -m 8 https://api.ipify.org; echo
curl -s "https://ipinfo.io/$(curl -s4 -m 8 https://api.ipify.org)/json" | jq -c '{city,country,org}'
```

先确认 4 件事再选方案：

1. **真 NAT 还是 1:1 公网**：从外部机器 `nc -z` 或 `curl -m3 telnet://<IP>:<端口>` 实测，别轻信面板文案。
2. **入口族 v4 / v6 分别验**：面板若同时给出 v4 与 v6 入口，本机与境外机需**两族分别测 TCP**（常见某国内运营商方向 v4 入口整体超时，但 v6 同端口低延迟连通）。
   - **路径丢包 ≠ 参数错**：客户端超时且服务端日志**零入站** = 路径丢包/阻断；日志见 `REALITY: processed invalid connection` = 参数不匹配或扫描器探测。
3. **内存硬边界**：
   - `≥ 128 MiB`：用 `sing-box`（128MB 需做第 5 步 `GOMEMLIMIT` 调优）；
   - `≤ 96 MiB`：改用 Rust 轻量化 `shoes`（RSS 13~18MB）或 `realm` 纯透传，详见 [references/low-mem-and-realm.md](./references/low-mem-and-realm.md)。
4. **出口族与测速源**：测 `curl -s4` / `curl -s6` 确认默认出站族；若服务商 DNS 将 `speed.cloudflare.com` 返回 NXDOMAIN 或返 429，改用 CacheFly（`http://cachefly.cachefly.net/5mb.test`）或 GitHub Release Fastly 源测速。

## 第 1 步：装 sing-box（≥128MB 机型）

```bash
bash <(wget -qO- -o- https://github.com/233boy/sing-box/raw/main/install.sh)
sb del Hysteria2   # NAT 机通常无 UDP 映射，删掉默认 Hy2
```

**Alpine / OpenRC 容器注意**：
- 管理命令为 `sb`；服务管理用 `rc-service sing-box restart`、`rc-update add sing-box default`。
- 缺 `openssl` 时默认 Hy2 证书生成会失败，直接删掉只保留 REALITY。
- 128MB cgroup 下 `/tmp` 为 tmpfs（算进内存），安装包一律下载到 `/root` 或 `/var/tmp`，部署前清 `/var/cache/apk/* /tmp/*`。

## 第 2 步：建 VLESS-REALITY（直连过墙首选）

```bash
sb add reality 24843 auto www.microsoft.com
sb url reality
sb status
```

- **内部端口取 20000 以上**（如 `24843`），避开 443/8080 撞车与默认规则干扰。
- **必须显式指定 SNI**（如 `www.microsoft.com` / `dl.google.com` / `www.apple.com`），切勿写 `auto`（脚本会把字面量 `auto` 写入配置导致失效）。
- **`short_id` 两阶段加固**：默认生成 `""` 空串；先改为 `["", "<16位hex>"]` 平滑过渡，等所有客户端切换生效后，再用 `jq` 删除空串并 `sing-box check` 重启（`sb url` 不输出手工 `sid`，分发时需手动补 `&sid=<新值>`）。
- **非交互批量自动化建节点**：非交互 `sudo` 下包装脚本 `sb` 可能不在默认 `PATH` 或触发交互等待；安装二进制后可直接 `rm -f /etc/sing-box/conf/Hysteria2-*.json`，用 `/etc/sing-box/bin/sing-box generate uuid` 与 `sing-box generate reality-keypair` 一步生成 `/etc/sing-box/conf/VLESS-REALITY-24843.json`（双栈入站设 `"listen": "::"` 并直接写入非空 16 位 hex `short_id`）。
- **境外链式纯落地备选**：若仅作为境外链式落地（绝不用于家宽直连过墙），可用 SS2022（`2022-blake3-aes-128-gcm`，服务端仅听 TCP + 客户端开 UoT v2）减少双层 TLS 开销，详见 [references/security-hardening.md](./references/security-hardening.md)。

## 第 3 步：端口映射与外部可达性

- NAT 面板配置 `内网 <内部端口>/TCP → 外部 <外部端口>`；v4 与 v6 入口均受映射约束，但须分别验证。
- 边缘端口映射即使后端停服也可能接受裸 TCP 握手，**不能仅靠 TCP 端口通断判定服务正常**，需做 TLS1.3 伪装面校验：

```bash
timeout 5 bash -c '</dev/tcp/198.51.100.10/24843' && echo OPEN
openssl s_client -connect 198.51.100.10:24843 -servername www.microsoft.com -tls1_3 </dev/null 2>/dev/null | grep -E "Protocol|Cipher"
```

- IPv6 字面量写法：URI 链接加方括号 `@[2001:db8:22:c5::a]:24843`，YAML 配置不加方括号但须加引号。

## 第 4 步：节点本机回环自证

不依赖本地客户端，先在 VPS 本机回环验证协议参数：

```bash
cat > /root/cli.json <<'EOF'
{"log":{"level":"warn"},
 "inbounds":[{"type":"socks","listen":"127.0.0.1","listen_port":21080}],
 "outbounds":[{"type":"vless","server":"127.0.0.1","server_port":24843,
  "uuid":"<UUID>","flow":"xtls-rprx-vision",
  "tls":{"enabled":true,"server_name":"www.microsoft.com","utls":{"enabled":true,"fingerprint":"chrome"},
  "reality":{"enabled":true,"public_key":"<pbk>","short_id":"<short_id>"}}}]}
EOF
nohup /etc/sing-box/bin/sing-box run -c /root/cli.json >/root/cli.log 2>&1 &
sleep 2
curl -s --socks5-hostname 127.0.0.1:21080 https://ipinfo.io/json | head -8
```

确认出口 IP/城市正确后按 PID 停止并删掉 `/root/cli.json` 与 `/root/cli.log`（**禁止 `pkill -f cli.json`**，以免误杀当前 shell 会话）。

## 第 5 步：低内存调优 & 出口族锁 v4

- **128MB 内存限制**：
  - systemd：`/etc/systemd/system/sing-box.service.d/override.conf` 写 `Environment=GOMEMLIMIT=56MiB`、`Environment=GOGC=50`，重启并降 `log.level` 为 `warn`。
  - OpenRC（Alpine）：`/etc/conf.d/sing-box` 写 `export GOMEMLIMIT=64MiB`；查真实 PID 用 `ss -ltnp | grep ":<端口> "`（`pgrep -f` 会误中 `supervise-daemon`）；BusyBox 看 RSS 用 `grep VmRSS /proc/<PID>/status`。
- **双栈机锁 v4 出站 + 独立加密 DNS**（入站保留 v6，仅锁出站为 v4）：
  - **首选 IP 字面量 DoT**（如 `{"type":"tls","tag":"dns-tls","server":"1.1.1.1"}`），勿用域名形式 DoH 当默认解析器（避免 bootstrap 被拦导致 REALITY 封面站回落超时）。
  - 在 `/etc/sing-box/config.json` 中配 `route.default_domain_resolver: { "server": "dns-tls", "strategy": "ipv4_only" }`，并务必追加防 SSRF 内网拦截规则（见 [references/security-hardening.md](./references/security-hardening.md)）。
  - 改完执行 `/etc/sing-box/bin/sing-box check -c /etc/sing-box/config.json -C /etc/sing-box/conf` 再重启。

## 第 6 步：接入客户端链式代理（通用 Mihomo / Shadowrocket）

链式路径：`设备 → 前置中转节点 → 落地节点（自建 VPS） → 目标站点`（仅在入口仅境外可达或需要固定出口 IP 时使用；能低延迟直连则直接直连）。

- **Mihomo / Clash Meta 通用写法**：在落地节点配置中指定 `dialer-proxy: <前置组或前置节点名>` 与 `udp: true`；
  - 顶层 `ipv6: true`（允许 IPv6 字面量节点拨号）；若希望应用流量锁死 v4，设 `dns.ipv6: false`（不影响代理服务器域名解析）。
  - 节点写进策略组后，需在实际出口组（如 `默认代理` / 业务分流组）选中该落地节点本身才会生效。
- **Shadowrocket**：编辑落地节点 → **代理通过** → 选前置节点/分组（切勿改全局“设置→代理→前置代理”）。
- **低内存备选与 `realm` 透传对比**：见 [references/low-mem-and-realm.md](./references/low-mem-and-realm.md)。

## 第 7 步：安全加固 & 服务端体检

- **上线必做安全加固**（入站白名单、防 SSRF 规则、配置权限 `700/600`、公网监听巡检、SSH 仅留密钥登录）：见 [references/security-hardening.md](./references/security-hardening.md)。
- **服务端原生态体检与双栈/分省对比**（NodeQuality / Check.Place 指定省份 `-R 福建` 专项回程 / v4 vs v6 入口同台 A/B 实测 / NAT 禁碰清单）：见 [references/server-benchmark.md](./references/server-benchmark.md)。

## 常见错误速查

- **`flow mismatch: expected xtls-rprx-vision`**：客户端未填 `flow`，换 Mihomo 客户端或服务端关闭 vision。
- **`invalid REALITY public key`**：公钥非 43 字符 base64url（截断或带中文引号），从 `sb url reality` 重取。
- **客户端超时且服务端日志零入站**：入口路径被阻断或面板映射规则丢失；检查面板规则并切换 v4/v6 入口族复测。
- **Mihomo 报 `dns resolve failed: ip version error`**：顶层 `ipv6: false` 却填了 IPv6 字面量 `server`；顶层改 `true`，应用锁 v4 改 `dns.ipv6: false`。
- **`tar: Unexpected EOF` / `apk add` 被 Killed**：≤96MB 内存装不下 sing-box，改用 [shoes](./references/low-mem-and-realm.md)。
- **测速 `HTTP 429` 或 `code=000`**：Cloudflare 限流或商家 DNS 拦截测速域，换 CacheFly / Fastly 源再测。

## 退订 / 换机复用

UUID、REALITY 密钥对、SNI、内部端口与 IP 无关，换机前备份即可原样复原：

```bash
sb url reality
grep -o '"private_key": "[^"]*"' /etc/sing-box/conf/VLESS-REALITY-*.json
```

新机执行 `sb add reality 24843 auto www.microsoft.com` → `sb id reality <旧UUID>` → `sb key reality <旧private_key>` → `sb del Hysteria2 && sb restart`，客户端仅改 `server` 与外部 `port`。

## 下一步联动

完成部署与客户端接入后：
1. 用 **`ipsock-check`** 验收出口 IP 纯净度、风控探活与链式延迟测速；
2. 用 **`proxy-leak-check --audit-nodes`** 确认本机无 DNS/WebRTC 泄露且新节点已启用 `udp: true`。
