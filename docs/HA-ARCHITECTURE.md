# Aegis 高可用与规模化架构方案（30k 终端 · 站库分离 · 热备冗余）

> 状态：设计定稿，分阶段实施。本方案消除所有单点故障（SPOF），支持 3 万终端。
> 依据：用户绝对要求 #1（2026-09-24）。

## 1. 现状与差距

当前单机部署（1 台 VPS 同时跑 console + collector + PG + nginx），单点故障点：

| 组件 | 现状 | SPOF | 目标 |
|---|---|---|---|
| Console（API/UI） | 单实例 wrangler | 是 | ≥2 实例 + nginx upstream 负载均衡 |
| Collector（上报/查询） | 单实例 SQLite | 是 | ≥2 实例 + 共享 PG 存储 |
| PostgreSQL | 单实例（console 用） | 是 | 主从流复制 + 自动故障转移 |
| SQLite（collector 发现库） | 单文件 | 是 | 迁移到共享 PG（发现表） |
| nginx | 单实例 | 是（入口） | 双机 + keepalived VIP 或云 LB |
| 告警评估器 | systemd timer 单实例 | 否（幂等） | 保持；多实例安全（状态文件锁） |

## 2. 目标拓扑（3 节点起步，可水平扩）

```
                       ┌──────────────┐
   30k 终端 ──────────▶│ 云 LB / DNS  │  (轮询或最小连接)
                       └──────┬───────┘
                    ┌─────────┼─────────┐
                    ▼         ▼         ▼
              ┌─────────┐ ┌─────────┐ ┌─────────┐
              │  节点 A  │ │  节点 B  │ │  节点 C  │
              │ console │ │ console │ │ console │
              │collector│ │collector│ │collector│
              │  nginx  │ │  nginx  │ │ (热备)   │
              └────┬────┘ └────┬────┘ └────┬────┘
                   │           │           │
                   └─────┬─────┴───────────┘
                         ▼
              ┌─────────────────────┐
              │  PG 主从集群（独立）  │
              │  primary ◀── hot    │
              │  standby + auto     │
              │  failover (patroni) │
              └─────────────────────┘
```

**站库分离**：应用节点（console+collector+nginx）与数据库节点（PG 集群）物理分离。
**热备冗余**：每类组件 ≥2 活跃实例；PG 一主一热备 + patroni 自动故障转移。

## 3. 分阶段实施

### 阶段 1（立即可做，无停机）：应用层去单点
1. **Collector 多实例化**——最关键的一步：
   - Collector 的 SQLite 发现库迁移到共享 PG（新表 `device_findings`，替代 reports.body 的 JSON 扫描）；
   - `/v1/reports` 写入走 PG；读（`/v1/devices`、`/v1/summary`、`/v1/trend`、`/v1/findings/aggregate`）改为 PG 查询（30k 规模下 PG 比全表 JSON 扫描快一个量级）；
   - 多 Collector 实例天然安全：PG 行级锁 + 幂等写（`INSERT ... ON CONFLICT DO NOTHING`）。
2. **Console 多实例**：现状已是无状态（会话 HMAC 无服务端存储；PG 写穿透），只需：
   - 第二台跑同版 wrangler + dist；
   - nginx upstream 双后端 + `proxy_next_upstream` 健康检查。
3. **nginx/LB**：云厂商 LB（阿里云 SLB / 腾讯云 CLB）→ 两个 nginx；或同 VPC 双机 keepalived VIP。

### 阶段 2：数据库高可用
1. PG 一主一热备（同 VPC 内网，流复制，RPO≈0）；
2. patroni + etcd 做自动故障转移（RTO < 30s）；
3. 每日 `pg_basebackup` + WAL 归档到对象存储（防机房级故障）。
4. Console/Collector 连接串加 `target_session_attrs=read-write`（故障转移后自动指向新主）。

### 阶段 3：30k 容量优化
- 上报路径：30k × 24 次/天 = 8.3 req/s 均值、峰值 ~50 req/s——单 PG 轻松承受；
- 查询路径：`/v1/findings/aggregate` 改 PG 物化表后，30k 设备 × 平均 20 发现 = 60 万行，有索引毫秒级；
- 缓存：console 对 `/v1/summary`、`/v1/devices` 加 5s 微缓存（多实例各自内存，接受短暂不一致）；
- 终端分片（未来 >50k）：按 `hash(device_id) % N` 路由到不同 collector 组。

## 4. 验收标准
- 任一应用节点宕机：上报与控制台 30s 内自动恢复（LB 健康检查摘除）；
- PG 主库宕机：patroni 30s 内提升热备，写入恢复，无数据丢失（同步复制）；
- 滚动升级：逐节点替换，全程服务可用；
- 压测：3 万模拟终端 24h 连续上报，零丢失（collector 幂等去重保证）。

## 5. 本次提交落地的部分
- 本文档（架构决策记录）；
- Collector PG 化的数据模型与迁移路径（阶段 1 第 1 步的详细设计，见 §3.1）；
- 运维手册更新：多节点部署清单。
