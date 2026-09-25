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
| 告警评估器 | systemd timer 单实例 | 否（幂等） | 保持单实例，或改多实例前**先加互斥**（见下方注意） |

> **注意（与代码现状核对后的更正）**：告警评估器 `scripts/aegis_alert_check.py` 的去重状态通过 `load_state()` / `save_state()` 读写一个 JSON 文件，写入用临时文件 + 重命名保证**原子性**，但**没有任何互斥锁**（无 `flock` / `fcntl` / 锁文件）。因此"多实例安全（状态文件锁）"的表述不成立：并发运行会出现"读-改-写"竞争，导致去重状态互相覆盖，表现为同一告警重复推送。多实例化前必须补 `flock` 或改为单实例 + 数据库侧状态。

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
2. **Console 多实例**：会话为 HMAC 无服务端存储、业务数据 PG 写穿透，**但并非完全无状态**——直接起第二台会重复执行后台任务。上多实例前必须先处理下列进程内状态：

   | 位置 | 进程内状态 | 多实例后果 |
   |---|---|---|
   | `middleware.ts` | 每请求调用 `startUpstreamSyncLoop()` / `startIntegrationAlertSync()` / `startAutoRemediationLoop()` | 每个实例（且 workerd 下每个 isolate）各自起一套 `setInterval`，后台任务 N 倍执行 |
   | `lib/auto-remediation.ts` | `sweepLoopStarted` 标志 + 5 分钟循环 | 自动纠偏并发多轮 → 重复 deny / 重复发布策略 |
   | `app/api/tickets/route.ts` | `lastAutoSync` 节流变量（60s） | 节流不跨实例共享 → 工单同步并发重复建单/闭环 |
   | `lib/collector-devices.ts` | 30s TTL 内存缓存 | 各实例缓存独立，姿态数据短暂不一致（可接受，但需知晓） |

   处置建议：把后台循环从请求路径（middleware）移出，改为**独立单实例 worker 或 systemd timer**（告警评估器已是此模式，可作先例），或在 PG 上做 advisory lock 选主。完成后再：
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

## 5. 本文档的落地状态

- 本文档是**架构决策记录（设计稿）**，实施尚未开始。
- 阶段 1 第 1 步（Collector 发现库迁 PG）的详细数据模型与迁移路径**尚未编写**——本文档只给出方向与验收标准，不含表结构与迁移脚本设计。（此前此处引用了不存在的「§3.1」，已更正。）
- 阶段 1 第 2、3 步的前置整改清单见 §3 的"注意"与表格（告警评估器互斥、控制台进程内状态）。
- 此前声明的"运维手册更新：多节点部署清单"**尚未产出**，仓库内没有该内容；待阶段 1 实施时随 `ops/README.md` 一并补齐。

## 6. 与 30k 容量评估的关系（必读）

本文档解决的是**可用性（消除单点）**，不解决**容量（存储与读放大）**。两者不可互相替代：

- 容量评估报告《Aegis 30,000 终端上线：服务器架构评估与性能拆解报告》判定 `reports` 表**整包 body 落盘**是 30k 的"最硬的墙"：30k × 24 次/天 × 30 天保留 = 2,160 万行、按典型画像约 700 GB，且该评估指出"加磁盘也扛不住每次写全表扫"。
  > 该报告**未提交进本仓库**（属内部归档评估），仓内目前只有它的分项落地文档 [`SCALE-P1-1-FINDINGS-AGGREGATE.md`](SCALE-P1-1-FINDINGS-AGGREGATE.md)。若需引用其 P0-2 / P1-4 / 阶段 0–2 放量计划与 SLO 阈值，请向维护者索取，或按 §7 的建议将其纳入仓库。
- 本文档阶段 1 只把**发现库**迁到共享 PG，**不涉及 `reports.body` 的存储模型**；阶段 3 提到物化表与微缓存，也未包含差分/心跳上报与冷热分层。
- 终端 Agent 当前**每周期上报整包报告，无差分或心跳机制**（在 `aegis_agent.py` 中检索 `heartbeat` / `delta` / `unchanged` 均无命中）。
- 因此：**先做本文档阶段 1 而不做容量改造，等于把同一个存储问题从 SQLite 平移到 PG。** 建议实施顺序把"差分/心跳上报 + 冷热分层"排在 Collector PG 化之前或同批，并以容量评估报告第 6 节的 SLO 作为放量门禁。

## 7. 建议的实施顺序与文档整改

**实施顺序**（按"先解除硬约束、再去单点"排列，与 §3 的阶段编号不完全一致）：

1. **控制台进程内状态外移**（§3 阶段 1 第 2 步的前置）：后台循环移出 middleware，改独立 worker / systemd timer，或 PG advisory lock 选主。不做这一步，多实例会重复执行自动纠偏与工单同步。
2. **告警评估器加互斥**（§1 表格的"注意"）：`flock` 或状态落库。
3. **差分/心跳上报 + 报告冷热分层**（§6）：30k 唯一的存储硬墙，且不依赖任何架构迁移即可先做。
4. **Collector 发现库迁共享 PG**（§3 阶段 1 第 1 步）：多 Collector 实例的前提。
5. **控制台多实例 + nginx upstream / 云 LB**（§3 阶段 1 第 2、3 步）。
6. **PG 主从 + patroni 自动故障转移**（§3 阶段 2）。
7. **温层列存/分区 + 冷层对象存储 + 静态分发 CDN**（§3 阶段 3）。

**文档整改建议**：

- 把容量评估报告纳入仓库（如 `docs/SCALE-30K-ASSESSMENT.md`），消除"公开文档引用读者无法访问的本机路径"这一问题。同类悬空引用另见 [`SCALE-P1-1-FINDINGS-AGGREGATE.md`](SCALE-P1-1-FINDINGS-AGGREGATE.md) 头部的 `~/.artifacts/...`。
- 本文档 §3 阶段 1 第 1 步提到的新表名 `device_findings` 与 Collector 现有的 `device_state` 物化表（已实现，见 `aegis_collector.py` 的 `ensure_device_state()`）关系需在详细设计中明确，避免两套物化模型并存。
- §4 验收标准中的"3 万模拟终端 24h 连续上报，零丢失"目前**没有对应的压测器**；建议把合成舰队压测器与 SLO 看板作为该验收项的前置交付物，否则此条无法验证。
