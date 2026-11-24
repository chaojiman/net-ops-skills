# 服务端安全加固与巡检参考

所有公网暴露的代理节点上线前必须过一遍以下底线。

## 一、凭据与入站协议白名单

- 节点凭据（UUID / REALITY 私钥 / pbk / SS2022 PSK）**永不提交到公开仓库**；一旦泄露立刻轮换密钥。
- **严禁公网监听 HTTP / SOCKS5 入站**（即便带账密也属明文/弱认证，易被扫成开放代理导致商家停机）；回环自测仅限 `127.0.0.1` 且测完即删。
- **协议分工**：
  - 家宽直连过墙：只留 **VLESS-REALITY**（服务端锁死常见大站 SNI，客户端改 SNI 无法握手）。
  - 境外链式纯落地（绝不用于直连过墙）：可选 **SS2022（`2022-blake3-aes-128-gcm`）**，服务端仅听 TCP（`"network": "tcp"`），客户端开 `udp: true` + `udp-over-tcp: true`（UoT v2）承载 UDP。
- **大陆云前置机特别提示**：80/443 未备案域名易触发云厂商 ICP/SNI 拦截，业务端口避开 80，使用高位端口。

## 二、公网落地防 SSRF / 内网隔离（必配）

若落地端口面向公网或动态机场前置开放，必须在 `/etc/sing-box/config.json` 中封锁云元数据、回环管理面与内网段（sing-box 1.12+ 语法）：

```json
"route": {
  "default_domain_resolver": { "server": "dns-tls", "strategy": "ipv4_only" },
  "rules": [
    { "action": "resolve", "strategy": "ipv4_only" },
    { "ip_is_private": true, "action": "reject" },
    { "ip_cidr": ["100.64.0.0/10", "169.254.0.0/16", "127.0.0.0/8", "::1/128", "fc00::/7", "fe80::/10"], "action": "reject" }
  ],
  "final": "direct"
}
```

配置后用临时回环客户端实测访问 `169.254.169.254`、`127.0.0.1:<管理口>` 与 `100.64.x.x`，均应返回连接拒绝（`HTTP 000`）。

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
# 3. 排查多余暴露：rpcbind(111)、cups(631)、avahi(5353)、mysql(3306)、redis(6379)、Docker 端口
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
