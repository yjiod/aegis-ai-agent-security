# ops/ — 服务器运维资产（随仓库交付，避免只在某台机器上存在）

| 文件 | 用途 | 安装位置 |
|---|---|---|
| `aegis-console-healthcheck.service` | 控制台 3-strike 健康探测（配套 `aegis-console-healthcheck.timer` 每 60s 触发） | `/etc/systemd/system/`，`systemctl daemon-reload && systemctl enable --now aegis-console-healthcheck.timer` |

配套但按机器维护（含环境差异，不入仓）：
- nginx 站点配置：`/etc/nginx/sites-enabled/aegis`（要点：`location /` 的 `proxy_read_timeout 360s`）
- systemd drop-in（内存上限）：`aegis-console.service.d/` MemoryHigh=1600M / MemoryMax=2400M
