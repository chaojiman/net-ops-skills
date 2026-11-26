# 自建无 SNI 双栈 IP 证书 DERP 与服务端 mangle 防打洞指南

> 本文档中所有 IP、域名与指纹均已脱敏为 RFC 5737 / RFC 3849 / RFC 6598 文档占位，实际部署时请替换为你的真实资产，并在本机记录至已被 `.gitignore` 忽略的 `local.md`。

## 一、为何改用无 SNI 双栈 IP 证书模式

在跨境场景中，若给自建 DERP 绑定域名（尤其是免费二级域名）：
1. **DNSSEC / CAA 阻断签发**：部分免费托管 NS 存在破损的 DNSSEC NSEC 链，导致 Let's Encrypt 查询 `CAA` 时返回 `SERVFAIL`，ACME 签发直接卡死。
2. **SNI 明文特征被 TCP RST**：TLS 1.3 的 `ClientHello` 中 `server_name`（SNI）仍是明文，整个高风险域名后缀极易被直接注入 TCP RST。

根据 **RFC 6066**，当客户端直接连接 IP 字面量时**不会发送 SNI 扩展**。Tailscale `derper` 官方支持 `-certmode=manual` + 自签多 IP-SAN 证书 + ACL `CertName: "sha256-raw:..."` 强绑定，既无特征 SNI，又能双栈接入且安全校验严格。

---

## 二、部署无 SNI 双栈 IP 证书 `derper`

### 1. 前置放行与安装
- 云防火墙放行入站：`tcp:<DERP端口>`（如 `34433`）、`udp:<STUN端口>`（如 `34478`）对公网双栈（`0.0.0.0/0` 与 `::/0`）开放；`udp:41641` 仅对授权的海外同伙节点公网 IP 开放。
- 宿主机安装官方 `tailscale` 与对应版本的 `derper` 二进制（建议放 `/usr/local/bin/derper` 并确保运行于同一版本线，如 `v1.104.x`）。

### 2. 生成 10 年双栈 IP-SAN ECDSA P-256 证书

```bash
sudo mkdir -p /etc/derper/certs
sudo chmod 700 /etc/derper/certs

# 将 198.51.100.10 与 2001:db8:20:ed::1 替换为 DERP 机真实公网 IPv4 / IPv6
sudo openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -sha256 -days 3650 -nodes \
  -keyout /etc/derper/certs/198.51.100.10.key \
  -out    /etc/derper/certs/198.51.100.10.crt \
  -subj   "/CN=198.51.100.10" \
  -addext "subjectAltName=IP:198.51.100.10,IP:2001:db8:20:ed::1" \
  -addext "basicConstraints=critical,CA:FALSE" \
  -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
  -addext "extendedKeyUsage=serverAuth"

sudo chmod 600 /etc/derper/certs/198.51.100.10.key
sudo chmod 644 /etc/derper/certs/198.51.100.10.crt

# 提取 Tailscale ACL 所需的 raw DER SHA-256 指纹（目录 0700 时必须加 sudo）
sudo openssl x509 -in /etc/derper/certs/198.51.100.10.crt -outform DER | sha256sum
# 输出如：sha256-raw:<64位小写hex指纹>
```

### 3. Systemd 服务模板（`/etc/systemd/system/derper.service`）

关键安全参数：**`-verify-clients`**（必须本机运行 `tailscaled` 并登录同一 Tailnet）+ **`-home=blank`**（禁显默认特征页）+ **`-http-port=-1`**（不开明文 80 端口）：

```ini
[Unit]
Description=Tailscale Self-Hosted DERP Server (IP-Cert No-SNI)
After=network-online.target tailscaled.service
Wants=network-online.target tailscaled.service

[Service]
Type=simple
ExecStart=/usr/local/bin/derper \
  -hostname=198.51.100.10 \
  -a=:34433 \
  -http-port=-1 \
  -stun \
  -stun-port=34478 \
  -certmode=manual \
  -certdir=/etc/derper/certs \
  -verify-clients \
  -home=blank
Restart=always
RestartSec=3
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```

启用服务并确认 BBR 拥塞控制已打开：

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now derper.service
sudo systemctl status derper.service --no-pager
```

### 4. `--verify-clients` 与 ACL `tag` 的隐蔽权限坑

- **症状**：开启 `--verify-clients` 后，某个同级低权限节点（如 `tag:vps-low`）连不上同贴 `tag:vps-low` 的 DERP，日志拒连。
- **根因**：ACL 默认拒绝同级 `tag:vps-low` 互访时，控制面下发的 `netmap` 会把同级节点公钥隐藏，导致 `derper` 本地查询 `tailscaled` 时找不到对端 nodekey。
- **修复**：在 Tailscale ACL `grants` 中增加最小只读级连通（零开放 TCP/UDP 端口）：

```json
{
  "src": ["tag:vps-low"],
  "dst": ["tag:vps-low"],
  "ip":  ["icmp:*"]
}
```

> ⚠️ **Tailscale ACL 语法坑**：必须写 `"icmp:*"`，写 `"icmp"` 会保存报错 `invalid first integer`。

---

## 三、服务端 `mangle` 阻断跨境裸打洞（保留海外直连与 STUN）

### 为什么不能只写 `filter INPUT`

`tailscaled` 每次启动/重启时，都会在 `filter` 表 `INPUT` 第 1 条自动插入 `ts-input`（无条件 `ACCEPT udp dpt:41641`），把后排自定义 DROP 规则架空。因此必须挂在优先级更高的 **`-t mangle`（`PREROUTING` 与 `OUTPUT`）**，并配 systemd 单元随网络开机持久化。

### 1. DERP 中继机脚本（`/usr/local/sbin/tailscale-overseas-only.sh`）

仅放行授权海外业务机公网 IPv4、云内 VPC 段、回环，以及 **`--sport 3478/34478`（入站）和 `--dport 3478/34478`（出站）** STUN 报文：

```bash
#!/usr/bin/env bash
set -euo pipefail

# 示例允许直连打洞的海外业务节点公网 IPv4
OVERSEAS_PEERS="203.0.113.20 203.0.113.21"
VPC_CIDR="10.15.0.0/16"

# IPv4 mangle
iptables -w 5 -t mangle -F ts-wg-in 2>/dev/null || iptables -w 5 -t mangle -N ts-wg-in
iptables -w 5 -t mangle -F ts-wg-out 2>/dev/null || iptables -w 5 -t mangle -N ts-wg-out
iptables -w 5 -t mangle -C PREROUTING -p udp --dport 41641 -j ts-wg-in 2>/dev/null || \
  iptables -w 5 -t mangle -I PREROUTING 1 -p udp --dport 41641 -j ts-wg-in
iptables -w 5 -t mangle -C OUTPUT -p udp --sport 41641 -j ts-wg-out 2>/dev/null || \
  iptables -w 5 -t mangle -I OUTPUT 1 -p udp --sport 41641 -j ts-wg-out

iptables -w 5 -t mangle -A ts-wg-in -s 127.0.0.0/8 -j ACCEPT
iptables -w 5 -t mangle -A ts-wg-in -s "$VPC_CIDR" -j ACCEPT
iptables -w 5 -t mangle -A ts-wg-in -p udp --sport 3478 -j ACCEPT
iptables -w 5 -t mangle -A ts-wg-in -p udp --sport 34478 -j ACCEPT
for ip in $OVERSEAS_PEERS; do
  iptables -w 5 -t mangle -A ts-wg-in -s "${ip}/32" -j ACCEPT
done
iptables -w 5 -t mangle -A ts-wg-in -j DROP

iptables -w 5 -t mangle -A ts-wg-out -d 127.0.0.0/8 -j ACCEPT
iptables -w 5 -t mangle -A ts-wg-out -d "$VPC_CIDR" -j ACCEPT
iptables -w 5 -t mangle -A ts-wg-out -p udp --dport 3478 -j ACCEPT
iptables -w 5 -t mangle -A ts-wg-out -p udp --dport 34478 -j ACCEPT
for ip in $OVERSEAS_PEERS; do
  iptables -w 5 -t mangle -A ts-wg-out -d "${ip}/32" -j ACCEPT
done
iptables -w 5 -t mangle -A ts-wg-out -j DROP

# IPv6 mangle（全部丢弃 41641，仅放行 STUN）
ip6tables -w 5 -t mangle -F ts-wg6-in 2>/dev/null || ip6tables -w 5 -t mangle -N ts-wg6-in
ip6tables -w 5 -t mangle -F ts-wg6-out 2>/dev/null || ip6tables -w 5 -t mangle -N ts-wg6-out
ip6tables -w 5 -t mangle -C PREROUTING -p udp --dport 41641 -j ts-wg6-in 2>/dev/null || \
  ip6tables -w 5 -t mangle -I PREROUTING 1 -p udp --dport 41641 -j ts-wg6-in
ip6tables -w 5 -t mangle -C OUTPUT -p udp --sport 41641 -j ts-wg6-out 2>/dev/null || \
  ip6tables -w 5 -t mangle -I OUTPUT 1 -p udp --sport 41641 -j ts-wg6-out

ip6tables -w 5 -t mangle -A ts-wg6-in -s ::1/128 -j ACCEPT
ip6tables -w 5 -t mangle -A ts-wg6-in -p udp --sport 3478 -j ACCEPT
ip6tables -w 5 -t mangle -A ts-wg6-in -p udp --sport 34478 -j ACCEPT
ip6tables -w 5 -t mangle -A ts-wg6-in -j DROP

ip6tables -w 5 -t mangle -A ts-wg6-out -d ::1/128 -j ACCEPT
ip6tables -w 5 -t mangle -A ts-wg6-out -p udp --dport 3478 -j ACCEPT
ip6tables -w 5 -t mangle -A ts-wg6-out -p udp --dport 34478 -j ACCEPT
ip6tables -w 5 -t mangle -A ts-wg6-out -j DROP
```

### 2. 海外业务机脚本（允许海外互打洞 + 禁止国内打洞）

将上述 `OVERSEAS_PEERS` 替换为 `"198.51.100.10 203.0.113.21"`（即自建 DERP 机与同级海外机器），`VPC_CIDR` 替换为对应区域私网段（如 `10.0.0.0/16`），确保两端互相能打出 `direct <公网IP>:41641`、对内零开放海外以外的裸 UDP。

---

## 四、上线验收与常见误报规避

1. **Windows 校验 IP-Cert 避坑**：Windows `curl.exe` 走 Schannel TLS 栈，连无 SNI 的自签 IP 证书会报错 `SEC_E_INVALID_TOKEN` 属误报；应改用 OpenSSL 栈（如 `node -e "require('https').get('https://198.51.100.10:34433/', {rejectUnauthorized:false}, r=>console.log(r.statusCode))"` 或在 Linux 跑 `openssl s_client -connect 198.51.100.10:34433`），预期收到 `HTTP 200` 且返回体长度为 `0`（`-home=blank` 生效）。
2. **`Self.Addrs` 核查**：在三台服务器上执行 `tailscale status --json | grep -A5 Addrs`，必须包含各自 `<公网IP>:41641`；若为空说明被 `mangle` 误杀 STUN 回包。
3. **正反向验收**：
   - 海外业务机 ↔ 自建 DERP 机：`tailscale ping` 几跳内转为 `via 198.51.100.10:41641`。
   - 国内控制端 ↔ 自建 DERP 机 / 海外业务机：`tailscale ping` 始终 `via DERP(...)`，`direct connection not established`。

## 五、安全回滚 / 彻底卸载

如决定撤回自建 DERP、全盘切回官方中继：
1. 先从 Tailscale ACL 删除 `"derpMap"`（及按需移除仅用于 `--verify-clients` 的 `icmp:*` grant）。
2. 在 DERP 机停止并清理服务：
   `sudo systemctl disable --now derper.service && sudo rm -f /etc/systemd/system/derper.service /usr/local/bin/derper && sudo rm -rf /etc/derper && sudo systemctl daemon-reload`
3. 云防火墙删掉 `34433/tcp` 与 `34478/udp` 入站规则；若不再需要防止打洞，同步停用并卸载 `mangle` 持久化脚本，清空 `mangle` 链。
4. 清理客户端代理规则中自建 DERP IP 直连条目。
