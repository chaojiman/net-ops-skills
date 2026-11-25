# 服务端安全加固与巡检参考

所有公网暴露的代理节点上线前必须过一遍以下底线。

## 一、凭据与入站协议白名单

- 节点凭据（UUID / REALITY 私钥 / pbk / SS2022 PSK）**永不提交到公开仓库**；一旦泄露立刻轮换密钥。
- **严禁公网监听 HTTP / SOCKS5 入站**（即便带账密也属明文/弱认证，易被扫成开放代理导致商家停机）；回环自测仅限 `127.0.0.1` 且测完即删。
- **协议分工**：
  - 家宽直连过墙：只留 **VLESS-REALITY**（服务端锁死常见大站 SNI，客户端改 SNI 无法握手）。
  - 境外链式纯落地（绝不用于直连过墙）：可选 **SS2022（`2022-blake3-aes-128-gcm`）**，服务端仅听 TCP（`"network": "tcp"`），客户端开 `udp: true` + `udp-over-tcp: true`（UoT v2）承载 UDP。
- **大陆云前置机特别提示**：80/443 未备案域名易触发云厂商 ICP/SNI 拦截，业务端口避开 80，使用高位端口。

## 二、公网落地防 SSRF 与双栈机纯静态 IPv4 出站硬锁（必配）

若落地端口面向公网，或双栈机采用「`v6/v4` 入站 + 纯净静态 `IPv4` 出站（6进4出）」方案，必须在 `/etc/sing-box/config.json` 中同时封锁云元数据/内网段与**裸 IPv6 旁路出站**（sing-box 1.12+ 语法）：

```json
"route": {
  "default_domain_resolver": { "server": "dns-tls", "strategy": "ipv4_only" },
  "rules": [
    { "action": "resolve", "strategy": "ipv4_only" },
    { "ip_version": 6, "action": "reject" },
    { "ip_is_private": true, "action": "reject" },
    { "ip_cidr": ["100.64.0.0/10", "169.254.0.0/16", "127.0.0.0/8"], "action": "reject" }
  ],
  "final": "direct"
}
```

- **为什么必须加 `{"ip_version": 6, "action": "reject"}`**：仅设 `strategy: "ipv4_only"` 只对域名解析生效；若客户端本地预解析出 AAAA 记录并发起裸公网 IPv6 连接，流量仍会跳过解析直接从服务器双栈网卡的 IPv6 出口漏出（易触发 Google 人机验证或归属地送中）。加上 `ip_version: 6` 硬拒绝后，客户端毫秒级回退走静态 IPv4。
- **闭环验证**：从客户端经 `v6` 入口请求双栈回显探针 `https://api64.ipify.org` 必须返回服务器的静态 IPv4，请求裸 IPv6 目标（如 `http://[2001:db8::1]/`）与元数据 `169.254.169.254` 均应被服务端阻断（返回 `502` / `000`）。

## 三、配置文件权限收紧

```bash
sudo chmod 700 /etc/sing-box/conf
sudo find /etc/sing-box/conf -type f -exec chmod 600 {} +
```

管理面（面板、Clash API、控制台）只绑 `127.0.0.1` 或内网组网接口，勿与业务端口共用公网暴露面。

## 四、已有机器只读巡检清单

```bash
# 1. 公网监听（排除 loopback 与 100.64/10 内网）
ss -ltnup | awk 'NR==1 || ($5 !~ /^127\.|^\[::1\]|^::1/ && $5 !~ /^100\./)'
# 2. 核对面板映射规则与本机实际监听一一对应，删掉废弃映射
# 3. 排查多余暴露：rpcbind(111)、cups(631)、avahi(5353)、systemd-resolved LLMNR(5355)、mysql(3306)、redis(6379)、Docker 端口
#    Debian/Ubuntu 若见 0.0.0.0:5355 / [::]:5355，写 /etc/systemd/resolved.conf.d/no-llmnr.conf (LLMNR=no / MulticastDNS=no) 并重启 systemd-resolved
# 4. 防火墙与安全组两层同查
iptables -S INPUT 2>/dev/null; ufw status 2>/dev/null
# 5. SSH 鉴权状态
sshd -T | grep -iE '^(passwordauthentication|permitrootlogin|pubkeyauthentication)'
# 6. 核对 sing-box 日志级别（避免 info 记访问域名涨满小盘）与 conf 权限
ls -ld /etc/sing-box/conf && ls -la /etc/sing-box/conf/
```

## 五、SSH 仅保留密钥登录（严格按顺序，先验密钥再关密码）

```bash
# 1. 本地生成密钥（建议带口令）
ssh-keygen -t ed25519 -f ~/.ssh/<node>_ed25519 -C "ops@example.com"

# 2. 远端写入公钥
mkdir -p /root/.ssh && chmod 700 /root/.ssh
# 将 <node>_ed25519.pub 追加到 /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys

# 3. 立即实测密钥登录（必须看到 KEY_OK 才能继续！）
ssh -i ~/.ssh/<node>_ed25519 -p <SSH端口> root@198.51.100.10 'echo KEY_OK'
```

```bash
# 4. 关闭密码登录：务必插在 sshd_config 顶部（Include 之前，防 sshd_config.d/00-*.conf 覆盖回 yes）
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak-$(date +%Y%m%d%H%M)
{ printf 'PermitRootLogin prohibit-password\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nPubkeyAuthentication yes\n\n'
  cat /etc/ssh/sshd_config; } > /root/sshd.new && mv /root/sshd.new /etc/ssh/sshd_config

# 5. 语法校验 + 重启（Debian/Ubuntu 用 systemctl restart ssh；Alpine 用 /etc/init.d/sshd restart）
sshd -t && echo CONFIG_OK
systemctl restart ssh 2>/dev/null || /etc/init.d/sshd restart
sshd -T | grep -iE '^(passwordauthentication|permitrootlogin|kbdinteractiveauthentication)'

# 6. 双向复测：密钥通、密码拒
ssh -i ~/.ssh/<node>_ed25519 -p <SSH端口> root@198.51.100.10 'echo KEY_STILL_OK'
ssh -o PubkeyAuthentication=no -p <SSH端口> root@198.51.100.10   # 应报 Permission denied
```

> 改动前先确认面板 VNC 控制台入口可用作兜底；重装或面板重置后需重新复查第 6 步。

## 六、云厂商计费防爆、多区免费池与静态 IP 账本

- **GCP 网络层级、多区域免费池与 IPv4 真实成本**：
  1. **开启免费标准层双栈（`v4-standard + v6-standard`）**：默认新建外部 IPv6 子网会绑进高价 `PREMIUM`（`2600:1900::` 段）；须先设项目默认层级 `gcloud compute project-info update --default-network-tier=STANDARD` 再新建双栈子网以获取 `2600:1902::` 标准层 IPv6（详见 [server-benchmark.md](./server-benchmark.md)）。
  2. **按区域独立核算首 200 GB/月免费流量**：`STANDARD` 层级每月首 **200 GB** 免费互联网出站按 **Region（区域）** 独立结算（同一结算账号下，如台湾 `asia-east1` 与香港 `asia-east2` 各享独立 200 GB/月免费池，共 400 GB/月），配合 `vnstat` + `cron` 在 180 GiB 时自动执行 `systemctl stop sing-box realm` 即可锁定 `$0` 流量费。
  3. **公网 IPv4 在用费与静态锁纯净度策略**：非美区 Always Free 区域的运行中 VM 挂载公网 IPv4（**无论临时还是静态**）统一按 **`$0.005/小时`（约 `$3.65/月`）** 计费，而停机未挂载的闲置静态 IP 翻倍收 `$0.01/小时`；公网 IPv6 为 `$0/小时`。因此：**确定长期留用的节点应直接将已验明低风险的临时 IPv4 原地转为 `STANDARD` 静态 IPv4（不增加月费且防重启换脏 IP）**，销毁机器时务必一并删除静态 IP；若为省 `$3.65/月` 卸掉公网 IPv4 改纯 IPv6，实例将失去 Google 原生干净 IPv4 出站能力（套免费 Cloudflare WARP 补 v4 出站会显著拉低 AI/搜索抗风控纯净度）。
- **零公网暴露探针上报范式**：节点向集中监控端上报指标时，不要把监控中心上报端口直接暴露在公网；改在监控端 `authorized_keys` 为每个节点分配独立受限密钥：
  ```text
  restrict,port-forwarding,permitopen="127.0.0.1:<上报端口>" ssh-ed25519 <PUBKEY> <node>-tunnel
  ```
  节点侧以无 shell 专用系统用户运行 `ssh -N -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=...` 建立本地端口转发，再由沙箱化 `agent`（`NoNewPrivileges=yes`、`ProtectSystem=strict`、`MemoryMax=64M`）经 `127.0.0.1` 上报，实现零公网监听面。
