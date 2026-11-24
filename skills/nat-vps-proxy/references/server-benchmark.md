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
