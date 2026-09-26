# ops/ — 服务器运维资产（随仓库交付，避免只在某台机器上存在）

| 文件 | 用途 | 安装位置 |
|---|---|---|
| `aegis-console-healthcheck.service` | 控制台 3-strike 健康探测（配套 `aegis-console-healthcheck.timer` 每 60s 触发） | `/etc/systemd/system/`，`systemctl daemon-reload && systemctl enable --now aegis-console-healthcheck.timer` |
| `aegis-console.service.d/limits.conf` | 控制台内存上限 drop-in：`MemoryHigh=2000M` / `MemoryMax=2400M` | `/etc/systemd/system/aegis-console.service.d/`，`systemctl daemon-reload` |
| `aegis-console.service.d/startup-timeout.conf` | 控制台启动超时 drop-in：`TimeoutStartSec=900`（覆盖主单元的 360） | 同上 |

> **drop-in 已入仓**（此前这两个文件只在服务器上手工维护）。入仓理由：这两处都是**生产实测定位出的故障修复**，只存在于一台机器上就等于换机器即丢失、且无法被 review。
> 安装后务必 `systemctl daemon-reload`，并用 `systemctl cat aegis-console` 确认 drop-in 出现在主单元之后（后者覆盖前者）。

## 这两个 drop-in 各自修的问题

### `startup-timeout.conf` — `TimeoutStartSec` 360 → 900

主单元的 `ExecStartPost` 是就绪轮询，最坏耗时 **60 轮 × (`curl -m 5` + `sleep 5`) = 600s**；而 `TimeoutStartSec` 覆盖**整个 start job（含 ExecStartPost）**，原值仅 360s。

⇒ 只要冷编译超过 360s，`ExecStartPost` 必然仍在循环中被 systemd 杀掉，单元判 `timeout` 失败，再被 `Restart=always` 拉起**从零重新编译**。`ExecStartPost` 两个分支都 `exit 0`，它自身永不报错——唯一失败途径就是被 360s 截断，因此这个故障不会在脚本层面留下明确原因。

2026-09-26 生产实测吻合：第 1 次 `10:54:06 → 11:00:06` **恰 360s** 被杀（白烧 `15min11.808s` CPU）；第 2 次 `11:00:11 → 11:06:09` = **358s，仅余 2 秒**侥幸通过。取 900s = 最坏 600s + 300s 余量。

### `limits.conf` — `MemoryHigh` 1600M → 2000M

冷编译内存峰值实测顶穿旧软限，cgroup 计数器留痕：

```
/sys/fs/cgroup/system.slice/aegis-console.service/memory.peak = 1678598144   (1.563 GiB)
                                                  旧 MemoryHigh = 1677721600   (1.5625 GiB)
```

峰值**超出旧软限 876,544 字节** ⇒ 编译期确实被节流，这很可能是冷编译耗时达 358s（远超 `scripts/deploy-console.sh` 注释所称 150–310s）的主因。`MemoryMax=2400M`（硬限）保持不变，`2000M < 2400M` 仍安全；实测 `MemAvailable` 全程 1551–2053MB。

注：`MemoryHigh` 属 cgroup 属性，`daemon-reload` 后**对运行中的单元即时生效，无需重启**；`TimeoutStartSec` 则在下次启动时才起作用。

配套但按机器维护（含环境差异，不入仓）：
- nginx 站点配置：`/etc/nginx/sites-enabled/aegis`（要点：`location /` 的 `proxy_read_timeout 360s`）
