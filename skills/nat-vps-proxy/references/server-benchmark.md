# VPS 服务端原生态体检工具参考

用于在部署前摸清机器的硬件、IP 归属、三网回程与国际互联质量（出口端到端链式体验请交由 `ipsock-check` 验收）。

## 一、常规 VPS（内存 ≥ 512MB）

一条命令完成硬件、IP 质量、三网路由与国际互联检测（chroot 隔离，测完自清）：

```bash
bash <(curl -sL https://run.NodeQuality.com)
```

- **低流量模式**（跳过大流量测速/回程，适合小流量套餐；默认完整版下载 BenchOS 约 298MB，含测速可能消耗 1~5GB）：
  ```bash
  printf 'y\ny\nl\nn\n' | bash <(curl -sL https://run.NodeQuality.com)
  ```
- **重点看四项**：五库 IP 属性（ISP/Residential vs 机房）、风险分与黑名单、流媒体/API 解锁、以及 **「七、国际互连」** 中目标大区（香港/东京/新加坡/洛杉矶）的延迟与重传数。

## 二、极小内存 / 无 `CAP_NET_RAW` 的 NAT 容器（128MB~256MB）

切勿直接跑完整 NodeQuality 或装重型面板，按模块分步轻测：

```bash
# 仅 IP 质量（约 100MB 内存，几 MB 流量）
bash <(curl -Ls https://IP.Check.Place) -y -p

# 仅采集硬件不跑压力测试（避免 fio/内存基准触发 OOM）
bash <(curl -Ls https://Hardware.Check.Place) -y -F -p

# 仅 TCP 握手延迟 + ASN（<5MB 流量，禁公开上传）
goecs -menu=false -upload=false -cpu=false -disk=false -memory=false -speed=false -ut=false -ping=false -tcp=true

# 按需补充单向吞吐（必须加 -b 限速，否则默认 10s 可吃 1GB+）
iperf3 -c <目标服务器> -R -t 3 -b 50M
```

## 三、NAT 容器禁碰清单与常见避坑

- **禁碰**：`backtrace` / `nexttrace` / `mtr` / `nping`（无 `CAP_NET_RAW` 必失败）、NodeQuality / TcpQuality 默认 rootfs（容器内 `mount` 被拒）、`digvps hardware`（极易 OOM）。
- **ICMP 误判**：不少 NAT 机对大陆方向 ICMP 100% 丢包但 TCP 100% 连通，勿以 `ping` 判断线路好坏。
- **隐私上传开关**：`goecs`、`TcpQuality`、`digvps` 默认可能公开上传报告；涉及隐私的机器务必加 `-upload=false` 或 `--no-rank-upload`。
- **动态家宽提醒**：若为动态 IP 家宽机，需先确认 DDNS 域名自动刷新正常，客户端链式配置一律填 DDNS 域名而非写死 IP。

## 四、Debian / 非交互 SSH 体检避坑与定向分流建议

- **避免 `sudo bash <(curl ...)` 失败**：`sudo` 默认关闭额外文件描述符，进程替换会报 `/dev/fd/63: No such file or directory`；正确做法是先 `curl -fsSL <URL> -o /var/tmp/script.sh` 落盘，再 `sudo -E bash /var/tmp/script.sh`。
- **NodeQuality 权限与小核耗时**：`NodeQuality` 依赖 `mount`/`chroot`，必须用 `sudo -E` 运行（普通用户会产出空报告）；0.25 vCPU 等突发共享小核跑完 `Geekbench 5` 可能耗时 20~30 分钟且期间满载会拉高同机代理握手延迟，若只需测 IP 质量请直接单跑 `IP.Check.Place`。
- **非交互 SSH 跑 `IP.Check.Place`**：须显式传入 `TERM=xterm LC_ALL=C.UTF-8`（如 `sudo TERM=xterm LC_ALL=C.UTF-8 bash /var/tmp/ipcheck.sh -4 -y -p`），否则会报 `'unknown': unknown terminal type` 直接退出。
- **单站点 403（如机房 IP 被 Reddit 屏蔽）处理原则**：不要为了少数站点把整台干净原生 IP 挂进 Cloudflare WARP（WARP 公共段同样常遭 Reddit 未登录 403 且伤 AI 风控）；优先在客户端为该站点建独立策略组指向干净节点，或仅在服务端针对该几个域名定向出站到已有干净后端。

## 五、指定省份（如福建移动）专项路由与 v4 / v6 入口同台 A/B 实测

> **⚠️ 大厂云（GCP / AWS / Azure）防风控红线（必读）**：
> **严禁在 GCP 等风控严格的大厂云实例内部运行 `NetQuality`（`Check.Place -N`）、完整 `NodeQuality` 网络章或并发 `nexttrace --tcp/--udp --psize 1400`！**
> 原因：`NetQuality` 会并发启动多个 `nexttrace -p 80 -q 8 --tcp --psize 1400` 向外部靶标高速发送半连接裸 TCP SYN / UDP 大包，会被 GCP 虚拟交换机反滥用系统直接判定为 **TCP SYN Flood 拒绝服务（DoS）攻击** 并下发 72 小时暂停警告邮件！
> - **大厂云安全替代方案**：① **禁在云机内跑发包扫描脚本**，延迟与单流/多流吞吐**一律从本机客户端发起真实代理 HTTPS 下载实测**（纯正常 TLS 1.3 流量，零风控）；② 去程在本机跑 `tracert -d`；若确需看单条回程，仅对自身 IP 跑低频 ICMP `traceroute -I -q 1`（禁 `--tcp` 大包并发）；③ 解锁用单条 `curl` 按需验状态码，避免扫 25 端口。
> - 下方 `NetQuality -R 福建` 仅限用于**无严格出站 SYN 审计的普通独立/常规 VPS**。

`NetQuality`（`Check.Place -N`）默认无参仅测试**北京 / 上海 / 广东**三地回程，且仅看回程不看去程、易受测试时段干扰。若实际宽带位于特定省份（如**福建移动**），所有节点体检必须补齐目标省份专项路由与本机真实双栈入口 A/B 实测：

### 1. 服务端补跑指定省份三网回程（以福建 `-R 福建` 为例）

小核小盘机切勿直接跑 `-y`（会拉取百兆级 `imagemagick` 且未设 `DEBIAN_FRONTEND=noninteractive` 时易卡死交互弹窗）；先装轻量依赖 + `nexttrace`，再用 **`-n -p </dev/null`** 秒出目标省份三网路由（探测靶标如 `FJ-cm-v4.ip.zstaticcdn.com` / `FJ-cm-v6.ip.zstaticcdn.com`）：

```bash
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq && apt-get install -y -qq jq curl mtr-tiny bc
command -v nexttrace >/dev/null || curl -fsSL https://nxtrace.org/nt | bash
curl -fsSL https://raw.githubusercontent.com/xykt/NetQuality/main/net.sh -o /var/tmp/net.sh

# IPv4 福建三网回程（电信 / 联通 / 移动）
sudo TERM=xterm LC_ALL=C.UTF-8 bash /var/tmp/net.sh -4 -R 福建 -n -p -o /var/tmp/nq_fj_v4.txt </dev/null

# 双栈机同步加测 IPv6 福建三网回程
sudo TERM=xterm LC_ALL=C.UTF-8 bash /var/tmp/net.sh -6 -R 福建 -n -p -o /var/tmp/nq_fj_v6.txt </dev/null
```

### 2. 双向去回程对账 + 空载状态 v4 / v6 入口吞吐硬对比

1. **防时段误判**：亚太云机（如 GCP 香港/台湾/东京 `STANDARD` 层级）在移动方向回程均走香港/东京 CMI（`AS15169 -> AS58453 -> AS9808`），电信/联通绕美西（`Verizon/Level3`）。白天闲时移动直连 4 并发可达 150~210 Mbps，而晚高峰 CMI 国际公网口拥塞丢包会跌至个位数 Mbps——**切勿拿他人闲时 NQ 截图与自身晚高峰结果对比误判机器层级优劣**。
2. **补测本机去程（破除 NQ 只看回程盲区）**：在本机家宽直接执行 `tracert -d -4 <VPS_V4>` 与 `tracert -d -6 <VPS_V6>`（如某云东京节点去程 v4 直拔东京 CMI 71ms，而 v6 先绕香港 CMI 再折返东京 88ms）。
3. **云机同网卡双栈 `STANDARD`（含 `v6-standard`）开启与同台 A/B 实测范式**：
   - **开启 GCP 标准层 IPv6（`v6-standard`，`2600:1902::` 段）纯 CLI 三步法**：网页端不可选且 `gcloud` 的 `--ipv6-network-tier` 参数枚举仅列 `PREMIUM`；须① 先将项目默认网络层级设为标准层：`gcloud compute project-info update --default-network-tier=STANDARD`；② **新建**双栈子网（`--stack-type=IPV4_IPV6 --ipv6-access-type=EXTERNAL`，此时子网自动分配 `2600:1902::` 标准层池，而非 `2600:1900::` 高级层池）；③ 建机或更新网卡时**切勿传 `--ipv6-network-tier`**，仅传 `--stack-type=IPV4_IPV6`（已有实例迁子网须停机后分两次单独执行：先改 `--subnetwork`，再改 `--stack-type=IPV4_IPV6`），即可获得 `networkTier: STANDARD` 的外部 IPv6。
   - **务必在远端空载状态下从本机客户端发起真实代理 HTTPS 下载测吞吐**（0.25 vCPU 满载期测速会严重失真），同时对比**单流（5~10MB）与 4 并发（20MB）**。
   - **测毕定型防扣费**：若最终仅保留单栈 IPv4，立即将网卡切回 `IPV4_ONLY` 并 `ip -6 addr flush dev <网卡> scope global`。
