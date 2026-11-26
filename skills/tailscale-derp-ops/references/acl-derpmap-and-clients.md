# Tailscale ACL `derpMap` 精准兜底、双端防套娃与内核分段排障

> 本文档中所有 IP、Tailnet 域名、节点代号与指纹均使用标准脱敏占位。

## 一、为什么不设 `derpMap` 或乱留官方邻区会降速百倍？

### 1. 非对称 Home DERP 机制
Tailscale 客户端**不会协商共用同一个中继点**：
- A 端（如中国家宽）周期性测一遍 `derpMap`，把延迟最低的节点设为主中继（**Home DERP / 收件箱**），向所有对端广播。
- B 端（如美东 VPS）独立挑离自己最近的节点设为主中继（如美东官方 `iad`）。
- 结果：`A → B` 走 B 的收件箱 `iad`，`B → A` 走 A 的收件箱 `hkg`。在跨海 + 公共 DERP 并发限速下，单流下行实测常见 **0.2 ~ 0.4 Mbps**。

### 2. 留一个更近的官方节点就会「抢流」
若为追求「有兜底」而把 `OmitDefaultRegions` 设 `false` 且保留官方全部节点（尤其 `hkg`），只要家宽到官方 `hkg` 比到自建台湾/邻区快 `2~3 ms`，Home DERP 就会立刻被官方 `hkg` 抢走，自建 DERP 形同虚设。

### 3. 精准收口配方：自建主力 + 单一滞后官方兜底

核心原则：**`OmitDefaultRegions: false` + 仅保留 1 个双端 RTT 均比自建慢 `20~30 ms` 的官方 Region，其余 20 余个官方 Region 显式置 `null`**。

实测效果对照（桌面端 `tailscaled` ↔ 美区业务机）：
- 官方非对称双中继（`iad` + `hkg`）：下行 **~0.37 Mbps**（单流）。
- 精准收口至自建邻区 `customderp`（仅留官方 `sin` ID=3 兜底）：下行飙升至 **~56 Mbps（+151x）**，4 并发 **~89 Mbps（+270x）**，且自建重启时自动无缝切 `sin` 不断链。

脱敏 `derpMap` 与 ACL `tests` 示例（区域 ID 与实际官方清单以控制台当前全量为准）：

```json
{
  "derpMap": {
    "OmitDefaultRegions": false,
    "Regions": {
      "1": null, "2": null,
      // "3": 保留官方 sin (Singapore) 兜底，双端平时 RTT 均高于自建 ~25ms 不会抢流
      "4": null, "5": null, "6": null, "7": null, "8": null,
      "9": null, "10": null, "11": null, "12": null, "13": null,
      "14": null, "15": null, "16": null, "17": null, "18": null,
      "19": null, "20": null, "21": null, "22": null, "23": null,
      "25": null, "26": null, "27": null, "28": null,
      "901": {
        "RegionID": 901,
        "RegionCode": "customderp",
        "RegionName": "Custom Edge DERP",
        "Nodes": [
          {
            "Name": "901a",
            "RegionID": 901,
            "HostName": "198.51.100.10",
            "IPv4": "198.51.100.10",
            "IPv6": "2001:db8:20:ed::1",
            "DERPPort": 34433,
            "STUNPort": 34478,
            "CertName": "sha256-raw:<替换为实际64位hex指纹>"
          }
        ]
      }
    }
  },
  "tests": [
    {
      "src": "tag:vps-core",
      "accept": ["100.64.0.21:22"],
      "deny": ["100.64.0.30:22", "100.64.0.30:445"]
    },
    {
      "src": "tag:vps-low",
      "accept": [],
      "deny": ["100.64.0.20:22", "100.64.0.30:22"]
    }
  ]
}
```

> 若确认自建极其稳定且不需要官方兜底，可将 `OmitDefaultRegions` 改为 `true`（仅保留 `901` 块）。

---

## 二、客户端双端对照：Windows（Mihomo/Bettbox）vs iOS（Shadowrocket）

两个客户端的底层网络架构完全相反，**私有段排除规则千万不要写反**：

| 对比维度 | Windows Mihomo / Bettbox（外部独立 `Tailscale` 网卡） | iOS Shadowrocket（同 VPN 进程内置用户态 Tailscale） |
| :--- | :--- | :--- |
| **`100.64.0.0/10` 旁路设置** | `绕过私有网络`（`route-exclude-address`）**必须保留** `100.64.0.0/10` 与 `fd7a:115c:a1e0::/48`，否则开 TUN 时访问命中 `直连` 的国内设备会直接黑洞丢包 | `tun-excluded-routes` **绝不能包含** `100.64.0.0/10`，否则流量进不去小火箭内置 TS |
| **域名排除 / 跳代理** | `排除域名`（`bypassDomain`）**严禁写** `100.*` 或 `*.ts.net`，否则浏览器跳过系统代理，无法命中 `Tailscale-VPS` 链式专线 | 不使用 Windows `ProxyOverride`；当 `设置 → Tailscale` 开启时，小火箭会在 `[Rule]` 前直接截胡 `100.64/10` 与 `*.ts.net` |
| **短主机名坑** | 系统代理默认自带 `<local>`，不含点 `.` 的短名（如 `http://vps-a:8093`）会绕过代理直发，务必改用 `http://100.64.0.20:8093` 或 `http://vps-a.tail000000.ts.net:8093` | 同理使用 `100.x` IP 或完整 `.ts.net` 域名 |
| **回退走 Tailnet 的目标** | 回退走本机官方 `tailscaled` 时，`Tailscale-VPS` 选 **`直连`** | 回退走小火箭内置 TS 时，`Tailscale-VPS` 必须选内置策略 **`TAILSCALE`**（选 `DIRECT` 会把 `100.x` 往物理蜂窝/Wi-Fi 发导致断连） |
| **规则优先级顺位** | ① 自建 DERP `v4/v6/域名 → 直连` → ② 目标 VPS IP/MagicDNS → `Tailscale-VPS` → ③ `100.64.0.0/10` / `fd7a:115c:a1e0::/48` / `ts.net` → `直连` | ① 自建 DERP `v4/v6/域名 → DIRECT` + **`DOMAIN-WILDCARD,derp*.tailscale.com,DIRECT`** → ② 目标 VPS → `Tailscale-VPS` → ③ `100.64/10` / `ts.net` → `TAILSCALE` |

### 1. 小火箭防套娃专项：为什么必须前置 `derp*.tailscale.com,DIRECT`？
- 若后排包含境外大词表 `global.list`（含 `.tailscale.com`），而第 0 段没拦 `derp*.tailscale.com`，小火箭内置 TS 连官方 DERP 兜底时会先走代理跳板，造成**双层加密套娃与随机漂移**。
- 使用 `DOMAIN-WILDCARD,derp*.tailscale.com,DIRECT` 可精确放行所有官方中继域名，同时保持 `controlplane.tailscale.com` 正常走代理。

### 2. 小火箭界面开关的 2 个常见误区
- **「控制服务器 URL」不能填 DERP 地址**：该输入框是给自建 **Headscale** 控制面用的，填入自建 DERP 的 URL 会直接导致节点认证失败断网，使用官方控制面时**必须留空**。
- **「始终使用 DERP」解决不了选区与卡顿**：它仅关闭局域网/公网 UDP 打洞，无法把节点从慢速官方 DERP 切到自建 DERP；若目标服务端本就禁了跨境打洞，打开它反而会连家里局域网直连一并禁掉。

### 3. 为什么移动端最终建议「关内置 TS、改走 `Tailscale-VPS → 链式落地`」？
在同 Wi-Fi 下通过 `derper` 内核对比同一美区业务机：
- 桌面端（有线 + 官方 `tailscaled`）：`minrtt 44.2ms`、`rtt 64.2ms`、`snd_wnd 16.78 MB`、`cwnd 6928`（数小时 **0 次超时**，单流 **56 Mbps**）。
- iOS 手机（Wi-Fi + 小火箭内置 TS）：`minrtt 57.6ms`（CATCH IPv4 绕路 `+13.4ms`）、`rtt 113.3ms`（Wi-Fi 省电 + 用户态滞后 `+74ms`）、**`snd_wnd` 仅 `128 KB`**（差 128 倍）、`cwnd 20`，且每 **30~50 秒静默断连**触发 `disco key` 重建与闪切兜底中继，总延迟高达 `+87ms`、吞吐 `< 1 Mbps`。

因此访问海外 VPS 内网服务的最优架构是：
1. **关闭移动端小火箭 `设置 → Tailscale` 开关**。
2. 客户端规则将目标海外 VPS 的 `100.x` IP 与 `.ts.net` 指向 **`Tailscale-VPS`**（默认 **`链式落地`**），请求经中转跳板进入目标海外 VPS 的 `sing-box` 入站，由 `sing-box` 直接访问该机器本地监听的 `100.x:端口` 或同内网对端。
3. **目标海外 VPS `sing-box` 路由配合要点**：若目标 VPS 按安全加固开启了 `100.64.0.0/10 -> reject` 防 SSRF 规则，须在该条拦截之前为**本机需暴露的服务端口或指定安全内网子网 IP（如本机 `100.64.0.20` 及已授权单向对端）插入 `direct` 放行规则**，同时维持其余 `100.64/10`、`169.254/16` 与 `ip_is_private` 拦截不变。

---

## 三、内核级毫秒分段排障实操命令

当发现某台设备（尤其是移动端或特定宽带）连自建 DERP 依然很慢时，直接登录自建 DERP 宿主机抓取两份真相：

```bash
# 1. 看所有连在 DERP 34433 端口上的活跃客户端真实内核 TCP 指标
sudo ss -tinp '( sport = :34433 )'

# 2. 查 derper 是否发生连接超时、客户端重连或拒绝校验
sudo journalctl -u derper --since "15 minutes ago" --no-pager

# 3. 到目标海外业务机上看它眼里的对端路径变化与抖动
tailscale status
tailscale ping --c=8 --timeout=3s <问题客户端_Tailscale_IP>
```

**解读重点（逐项拆段定位）**：
1. 比较 `DERP ↔ 海外业务机` 的 `minrtt` 与 `rtt`：若两者接近且 `cwnd`/`snd_wnd` 宽裕（如数 MB），说明跨境出海后段完全健康，责任不在 DERP 或目标机。
2. 对比 `DERP ↔ 桌面端` 与 `DERP ↔ 移动端` 的 `minrtt`：若一个是 IPv6 `~44ms`、另一个是 IPv4 `~57ms`，差值 `+13ms` 来自接入协议族绕路。
3. 对比 `rtt` 相对 `minrtt` 的膨胀量及 `snd_wnd` / `cwnd`：若 `snd_wnd` 仅 `128 KB` 且 `journalctl` 周期性打印 `read: connection timed out`，即确认为移动端系统省电/代理进程用户态窗口与长连接保活限制，应切换链式直入替代而非继续微调 DERP 参数。
