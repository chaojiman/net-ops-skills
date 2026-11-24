# 低内存机型（shoes）与纯 TCP 透传（realm）参考

适用场景：容器内存上限 ≤96 MiB 装不下 `sing-box`，或仅将小鸡作为中转入口透传到后端加密节点。

## 一、≤96 MiB 内存机型：用 `shoes` 替代 `sing-box`

实测 72 MiB cgroup 硬边界：`sing-box` 解压即超 72MB 触发 OOM；`shadowsocks-rust` 占 16MB 但无 REALITY；Rust 静态编译的 **`shoes`（musl）** 仅 31MB 二进制，运行 RSS 约 **13MB（无 vision）/ 18MB（开 vision）**。

### 部署（下载到 `/root`，严禁放 `/tmp`）

```bash
mkdir -p /opt/shoes && cd /root
wget -qO shoes.tar.gz https://github.com/cfal/shoes/releases/latest/download/shoes-x86_64-unknown-linux-musl.tar.gz
tar -xzf shoes.tar.gz -C /opt/shoes && rm -f shoes.tar.gz && chmod +x /opt/shoes/shoes
/opt/shoes/shoes --version
```

### 配置模板（`/opt/shoes/config.yaml`）

注意：`shoes` 的配置层级与 `sing-box` 完全不同——外层是 `type: tls`，内层才是 `vless`。

```yaml
- address: "0.0.0.0:24843"
  protocol:
    type: tls
    reality_targets:
      "www.apple.com":
        private_key: "<X25519私钥_43字符base64url>"
        short_ids: ["<8~16位hex>"]
        dest: "www.apple.com:443"
        vision: true              # 开启后客户端须带 flow: xtls-rprx-vision
        protocol:
          type: vless
          user_id: "<UUID>"
          udp_enabled: true
```

校验：`/opt/shoes/shoes check /opt/shoes/config.yaml` → `Configuration valid`。

### 本地生成 X25519 密钥对（机器缺 openssl 时）

```python
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization
import base64, uuid

k = X25519PrivateKey.generate()
raw = k.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
pub = k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
enc = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()
print("private_key:", enc(raw))
print("public_key :", enc(pub))
print("uuid       :", uuid.uuid4())
```

### Alpine 开机自启 & cgroup page cache 回收

```bash
printf '#!/bin/sh
cd /opt/shoes || exit 0
if ! pgrep -f "shoes /opt/shoes/config.yaml" >/dev/null; then
  nohup /opt/shoes/shoes /opt/shoes/config.yaml >> /var/log/shoes.log 2>&1 &
fi
' > /etc/local.d/shoes.start
chmod +x /etc/local.d/shoes.start && rc-update add local default
```

**72 MiB cgroup 避坑**：`memory.current` 包含 page cache，大文件下载删除后水位仍可能逼近上限触发 OOM，需主动回收：

```bash
sync && echo 50M > /sys/fs/cgroup/memory.reclaim
```

### 入口族路径判据

当境外能连、本地家宽超时且 `tracert` 在境外某跳后全丢时，属于入口族路径不可达（非配置错误），切换 v4/v6 入口族测试；验证 `CMIN2` 宣传可用 `mtr -4 -rwzc 10 223.5.5.5` 看是否经过 `AS58807`（CMIN2 仅针对 v4）。

---

## 二、纯 TCP 透传前置：`realm`

适用场景：小鸡只充当中转入口，加解密放在后端加密节点（如 REALITY / VLESS-TLS）；**严禁拿 `realm` 从国内裸转明文 SOCKS5/HTTP 代理过墙**。

### 安装与配置（`/etc/realm/config.toml`）

```bash
cd /root && wget -qO realm.tgz https://github.com/zhboner/realm/releases/latest/download/realm-x86_64-unknown-linux-musl.tar.gz
tar -xzf realm.tgz -C /usr/local/bin/ realm && rm -f realm.tgz
/usr/local/bin/realm -v
```

```toml
[log]
level = "error"
output = "/var/log/realm.log"

[network]
no_tcp = false
use_udp = false          # 仅转 VLESS/TCP 时关闭；转 Hysteria2/QUIC 才开启

[dns]
mode = "ipv4_only"       # 后端为 v4 且本机 v6 出站不稳时锁 v4
min_ttl = 0
max_ttl = 60             # 后端为 DDNS 域名时压低 TTL；realm 每条新连接按 TTL 解析，无需重启

[[endpoints]]
listen = "[::]:24845"    # 双栈监听；若前置仅 v4 写 0.0.0.0:24845
remote = "backend.example.com:24843"
```

Alpine 开机自启：写入 `/etc/local.d/realm.start` 并 `rc-update add local default`。

### 客户端侧改动要点

- **后端为 REALITY**：客户端仅改 `server`（前置 IP）与 `port`（前置外部端口），`sni / pbk / short-id / uuid / flow` 原样保留。
- **后端为普通 TLS/WS**：除改 `server / port` 外，`sni` 与 `Host` 须显式填写后端原域名。
- **验证**：`ss -ltn | grep 24845`、`grep VmRSS /proc/$(pgrep realm)/status`（通常仅数 MB），再用客户端经前置端口实测出口 IP 应等于后端 IP。

### `realm` 透传 vs 客户端链式（`dialer-proxy` / 小火箭「代理通过」）

- **服务端改动**：`realm` 需在前置装进程并配映射；客户端链式零服务端改动。
- **加密开销与隐私**：`realm` 仅搬运密文（前置看不到目的域名，CPU 占用近乎 0）；客户端链式为双层加密（前置作为协议端可见目的域名）。
- **总延迟**：两者均约等于「本地→前置 + 前置→后端」之和，**切勿误以为链式或 realm 能降低物理总延迟**。
- **建议顺序**：先用客户端链式零改动跑通验证，确有长期稳定中转需求且实测更优时再切 `realm`。

### 常见传闻辟谣（勿轻信）

- 单靠「前置开 BBR」不会神奇翻倍带宽，瓶颈通常在跨境线路，且 LXC/Podman 容器无法改宿主内核拥塞算法。
- Hysteria2 的 Brutal 仅在客户端显式填写上下行带宽时才启用，且 NAT 机常无 UDP 映射。
- 几百 Mbps 内双层 AES 对现代手机算力影响极微，不存在「链式必然严重发热降频」。
