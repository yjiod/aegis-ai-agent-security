# 规模化设计评估 · P1-1：消除控制台对采集器的 per-device N+1 扇出（发现聚合端点）

> 状态：**方案评估（待拍板，未实现）** · 2026-09-22 · 属 30k 终端设计基准的阶段 0/1
> 前置依赖：**P0-3 `device_state` 物化表已落地**（commit c12ca07）——本方案直接复用它。
> 关联：`~/.artifacts/aegis-30k-scale-architecture-report.md`（总报告 P1-1 条目）。

---

## 1. 问题（是什么 / 为什么危险）

控制台在渲染「发现」时，对**每一台设备各发一个 HTTP** 到采集器 `/v1/findings?device_id=…`，用 `Promise.all` 并发扇出：

- `app/api/findings/route.ts:86,98-105`
  ```ts
  const devices = await fetchCollectorDevices();          // 最多 10000 台
  const perDevice = await Promise.all(
    devices.map(async (d) => ({ device: d, res: await fetchDeviceFindings(d.device_id) })),
  );
  ```
- `lib/evidence.ts:541-545`（证据导出，同一模式）
  ```ts
  const per = await Promise.all(targets.map(async (d) => ({ device_id: d.device_id, res: await fetchDeviceFindings(d.device_id) })));
  ```

**30k 下的后果**：单次页面加载最多发起 **10,000 个并发 HTTP**（且因 `limit≤10000` 只覆盖 1/3 舰队）。采集器是 `ThreadingHTTPServer`（1 连接 = 1 OS 线程，无上限、GIL 约束），1 万并发 → 线程爆炸 + 内存飙升；控制台 worker（MemoryMax 2400M）同时在内存里聚合 1 万份响应 → 挂起/OOM。这是「一次开页面就打垮后端」的典型 N+1 反模式。

**根因**：发现数据的「聚合」发生在**控制台侧、逐设备拉取后在内存里拼**，而不是在**数据所在地（采集器）一次算好**。

---

## 2. 关键观察（决定方案走向）

1. **P0-3 已给出「每设备最新报告」的 O(设备数) 定位能力**：`device_state.latest_id` → `reports.body`（PK join）。聚合端点无需再全表扫，也无需逐设备往返。
2. **采集器在写入时就已持有解析后的 `report` dict（含 `findings` 数组）**：`store_report(...)` 的入参就是完整报告。→ **每设备的发现计数（按 severity/category）可以在写入时零额外解析地算出并物化**，读侧完全不必再 `json.loads(body)`。
3. **加白抑制（allow-list）目前在控制台侧**（`allowedAssetKeys()` 来自 labels），采集器不持有该状态。→ 抑制要么留在控制台（聚合端点返回原始发现，控制台过滤），要么新增「标签下发到采集器」的同步路径（耦合↑）。
4. **明细行的体量不可一次性返回**：30k 台 × 每台数十条发现 ≈ 数百 MB。→ 聚合端点**必须游标分页 + 服务端过滤**，不能一把梭。

结论：**把「聚合」拆成两层**——
- **计数层（仪表盘/角标/风险中心徽章）**：读物化计数，**零 body 解析、零扇出、O(设备数)**。
- **明细层（下钻查看具体发现行）**：新增**游标分页 + 服务端过滤**的聚合端点，**一次调用翻页取全量**，取代 per-device N+1。

---

## 3. 方案选型（Options Matrix）

| 方案 | 做法 | 30k 可行性 | 工量 | 风险 | 结论 |
|---|---|---|---|---|---|
| **A. 游标分页聚合端点** | 采集器新增 `GET /v1/findings/aggregate`，服务端 `device_state ⋈ reports`(PK) 逐页解析 body 返回扁平发现流，keyset 游标 + category/severity/since 过滤 | ✅（分页有界） | 中 | 每页仍解析 body；高频调用有 CPU 成本 | **推荐（明细层，阶段 0/1）** |
| **B. `findings_current` 物化明细表** | 写入时把发现拆成行落库（indexed by device/category/severity），聚合读走纯 SQL | ✅✅（最快，支持不传输即计数） | 大 | 写放大、schema 迁移、去重/闭环状态维护复杂 | 阶段 2 演进（明细查询量上来后） |
| **C. 控制台侧并发限流 + 缓存** | 保留 per-device fetch，但限并发 + 短 TTL 缓存 | ❌（仍 O(N) 调用，只是推迟崩溃点） | 小 | 治标不治本 | **否决** |
| **D. 独立分析库（ClickHouse/只读副本）** | 发现明细进列存，聚合走分析库 | ✅✅ | 很大 | 新组件、运维成本 | 阶段 2/3（总报告已列） |
| **计数层增强（叠加在 A 上）** | 扩展 `device_state`（或兄弟表 `device_finding_counts`）存每设备 severity/category 计数，写入时从已持有的 `report` dict 算出 | ✅✅ | 小 | 计数字段随策略发现类型演进需兼容 | **推荐（计数层，与 A 同期）** |

**推荐组合**：**计数层增强（写时物化计数） + 方案 A（游标分页明细聚合端点）**；方案 B/D 留作阶段 2 演进。理由：A 直接复用 P0-3 的 `device_state`，改动内聚、可灰度、可回滚；计数层让最高频的仪表盘/角标读**完全不碰 body、不扇出**，把 CPU 成本只留给「用户主动下钻明细」的低频路径。

---

## 4. 推荐方案契约（供实现，不含真实主机/凭据）

### 4.1 计数层：扩展 device_state（或新增 device_finding_counts）

在 `store_report` 内（已持有 `report["findings"]`）按 category/severity 计数并写入，读侧仪表盘/角标/风险中心徽章直接聚合这张小表（O(设备数)，无 body 解析）：

```
device_finding_counts(
  device_id TEXT PRIMARY KEY,
  critical INTEGER, high INTEGER, medium INTEGER, low INTEGER,
  skill INTEGER, mcp INTEGER, code INTEGER, other INTEGER,   -- 按 category
  scanned_at INTEGER                                          -- 该计数的新鲜度
)
```
- 与 `device_state` 同事务更新，保持一致性。
- 仪表盘「全舰队 critical/high 总数」= `SELECT SUM(critical),SUM(high) FROM device_finding_counts`（3 万行聚合，毫秒级）。

### 4.2 明细层：GET /v1/findings/aggregate

| 参数 | 说明 |
|---|---|
| `category` | `skill｜mcp｜code｜all`（服务端过滤，减载荷） |
| `severity` | `critical｜high｜medium｜low｜all` |
| `since` | epoch，按 `scanned_at` 过滤 |
| `cursor` | 不透明 keyset 游标（见下），首页省略 |
| `limit` | 页大小，`1..1000`（默认 500，硬顶防巨响应） |

**响应**：
```json
{
  "generated_at": 1730000000,
  "complete": false,
  "next_cursor": "ZGV2aWNlLWE6MTI=",   // base64(device_id + ':' + finding_ordinal)
  "devices_scanned": 500,
  "counts": { "total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0 },
  "findings": [ { "device_id": "...", "scanned_at": 0, "kind": "...", "category": "...", "severity": "...", "path": "...", "message": "...", "asset_key": "..." } ]
}
```
- **游标 = keyset `(device_id, finding_ordinal)`**：按 `device_id`（`device_state` PK 有序）+ 发现数组下标稳定排序；比 offset 抗数据变动（翻页期间新报告到达不会漏/重）。
- **服务端实现**：`device_state` 按 `device_id > cursor.device` 分页取设备 → 对每台 PK join `reports.body` → `json.loads` → 过滤 category/severity/since → 累积到 `limit` 条即返回并给出 `next_cursor`。**每页只解析该页设备的 body**，成本有界。
- **可选短 TTL 缓存**（如 5–10s）吸收仪表盘并发刷新；计数层已覆盖高频读，明细层缓存非必需。
- **加白抑制仍留控制台**（不新增标签下发耦合）：端点返回原始发现，控制台 `isFindingAllowed()` 过滤并累计 `suppressed`（与现状一致，审计留痕不销毁）。

### 4.3 向后兼容

- **保留** `/v1/findings?device_id=…`（单设备下钻，工单→设备深链 `/devices?focus=<id>` 仍在用）。
- 新端点纯**增量**；灰度期控制台可 feature-flag 在「聚合端点」与「旧扇出」间切换，异常即回退。

---

## 5. 控制台侧改造（消费端）

- `app/api/findings/route.ts`：删除 `Promise.all(devices.map(fetchDeviceFindings))`，改为 **游标翻页循环** 调 `/v1/findings/aggregate`（带 category/severity），累积到需要为止；`counts` 优先取计数层。抑制/分类逻辑不变。
- `lib/evidence.ts:541`：同样改翻页循环（证据导出需全量，天然适配游标遍历，顺带解 P1-4 的「只覆盖前 1 万台」）。
- `fetchCollectorDevices()` 仍用于「设备清单」，但发现数据不再依赖它逐台 fanout。

---

## 6. 工量 / 风险 / 测试

**工量（估）**：采集器端点 + 计数层 ~1 人日；控制台两处翻页改造 ~1 人日；单测/e2e ~0.5 人日；bundle/门禁/灰度 ~0.5 人日。合计 ~3 人日。

**风险与护栏**：
- 巨响应/OOM：`limit` 硬顶 + 服务端过滤 + keyset 分页（禁止无界返回）。
- 翻页期间数据变动：keyset 游标（非 offset）保证不漏不重。
- 高频刷新 CPU：计数层承接仪表盘/角标；明细层仅下钻时触发（+ 可选 TTL 缓存）。
- 契约守卫：新增字面量若纳入 `aegis_release_verify.py` 的 `missing_*` 校验，须同步（改采集器务必 `aegis_release_build.py` 重建 bundle，否则 `bundle_content_mismatch`）。

**测试计划**：
- 单测：聚合端点分页正确性（keyset 不漏不重）、category/severity/since 过滤、计数层与逐设备解析结果一致、空舰队/单设备/悬挂设备（最新报告被保留清理）边界。
- **扇出回归（e2e，纳入 playwright）**：加载 `/api/findings` 与证据导出，断言采集器**收到的请求数 = O(页数)** 而非 O(设备数)——防止 N+1 复活（对应总报告 SLO「`/api/findings` 触发的采集器请求数 O(1)/O(pages)」）。
- 压测：合成 5k/30k 舰队，聚合端点翻页 p95 < 500ms、内存峰值 < 70%。

---

## 7. 分阶段落地建议

- **阶段 0（与 P0-3 同期，单 VPS）**：计数层（写时物化 severity/category 计数）+ 聚合端点方案 A + 控制台翻页改造 + 扇出回归 e2e。→ 消除 N+1，仪表盘读零 body 解析。
- **阶段 1（sqlite→PG 后）**：聚合端点走 PG，keyset 分页天然高效；可加只读副本承接聚合读。
- **阶段 2（30k）**：若明细查询量上升，演进到方案 B（`findings_current` 物化明细表）或方案 D（列存/副本），实现「不传输即计数 + 明细列存扫描」。

---

## 8. 与 P1-4（limit 截断）的协同

聚合端点的**游标遍历天然解决发现数据的「只覆盖前 N 台」**；设备清单侧的 `limit≤10000`、工单同步 `500`、告警 `1000` 截断需配套改**游标分页**（P1-4 独立项），二者共同保证 30k 舰队 **100% 可见**（总报告正确性红线）。

---

*本文为方案评估，供拍板；实现时按第 4/5 节契约落地并过全门禁 + canary 灰度。采集器改动须重建 bundle/RELEASE-MANIFEST。*
