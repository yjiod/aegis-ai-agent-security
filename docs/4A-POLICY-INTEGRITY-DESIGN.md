# 4A 与策略完整性增强设计（Signed-Policy / Capability-RBAC / Per-Device Tokens）

> 状态：**设计稿（待实施）**。本文把三个高价值但带生产风险的增量先固化成可评审方案，
> 实施按"先设计后动生产"的纪律分批推进；每批独立可回滚。
> 关联现状：`lib/policy.ts`（HMAC keyring 签名）、`public/downloads/aegis_agent.py`
> （`load_policy(verify_key, require_signature)`）、`app/api/enroll/route.ts`
> （去签名策略 + 每设备 signing_secret）、`lib/auth.ts`（3 角色 RBAC）。

---

## 1. 签名策略强制 + 非对称验签密钥分发（最高优先）

### 1.1 现状与缺口
- 服务端用 **对称 HMAC keyring**（`AEGIS_POLICY_SIGNING_KEYS`）对规范化策略体签名，
  `signing_key_id` 为密钥指纹；密钥只来自 env/KMS，不入库。
- Agent 已具备验签能力（`verify_policy_signature` / `load_policy(..., require_signature)`）。
- **但** `/api/enroll` 下发的是**去签名**策略体，Agent 以 `require_signature=false`
  仅凭 TLS 信任加载。缺口：策略完整性依赖传输通道而非密码学；若 TLS 终端被旁路
  （企业代理/受损 CA），策略可被替换；且对称密钥一旦需下发给终端验签即泄露签名能力。

### 1.2 目标态
- **非对称签名**：服务端持 Ed25519（或 ECDSA P-256）私钥（env/KMS，永不下发）；
  终端只持**公钥**验签。公钥非秘密，可安全内嵌与公开分发。
- **enroll 下发签名策略**：保留 `signature` + `signing_key_id`，Agent 以
  `require_signature=true` 加载；验签失败即拒绝并上报（fail-closed）。
- **公钥分发**（三通道冗余）：
  1. 构建期内嵌进安装包（macOS .pkg / Windows .msi / .run），随发行固定；
  2. 未认证只读端点 `GET /aegis/v1/policy/verify-key`（返回公钥 + key-id + 算法）；
  3. enroll 响应附带 `verify_key`（与内嵌一致时采用，不一致以**内嵌/旋转清单**为准）。
- **密钥旋转**：新私钥签一份"旋转清单"（attest 新公钥），由**旧私钥共签**过渡期；
  Agent 信任"当前公钥 ∪ 被旧公钥共签的新公钥"，过渡窗口后仅信新公钥。

### 1.3 迁移与回滚
- 阶段 A（双签）：服务端同时输出 HMAC + Ed25519 签名；Agent 接受任一（兼容旧终端）。
- 阶段 B（强制）：新终端 `require_signature=true` 且仅认 Ed25519；旧终端经版本门禁升级。
- 回滚：env 开关 `AEGIS_POLICY_SIG_MODE=hmac|dual|ed25519`，逐档回退，无需重发终端。

### 1.4 风险
- 私钥管理（KMS/轮换）是新增运维面；公钥内嵌需与发布管道绑定（防错嵌）。
- 强制阶段若旧终端未升级会被拒策略 → 需版本门禁 + 灰度。

---

## 2. Capability-Based RBAC（operator / developer 细粒度角色）

### 2.1 现状与缺口
- 线性 3 角色：admin（全）> auditor（只读+审计）> viewer（只读）。
- 缺口：运维需"管设备但不发策略/不看审计"、开发者需"仅看自己设备"，现模型表达不了；
  把运维升 admin 会过度授权（违反最小权限）。

### 2.2 目标态：能力集（capability）而非线性等级
| capability | admin | auditor | operator | developer | viewer |
|---|---|---|---|---|---|
| device:read | ✓ | ✓ | ✓ | 仅本人设备 | ✓ |
| device:write | ✓ | – | ✓ | – | – |
| ticket:write | ✓ | – | – | – | – |
| policy:publish / keys | ✓ | – | – | – | – |
| label:write（处置） | ✓ | – | – | – | – |
| audit:read / export | ✓ | ✓ | – | – | – |
| user:manage | ✓ | – | – | – | – |

- `roleForSubject` 改为返回**能力集**（由所属 allowlist 并集推导）；路由门禁从
  `requireAdmin/requireAuditor` 迁移到 `requireCapability(session, cap)`。
- developer 的"仅本人设备"在 devices/risks 查询层按 `owner == subject` 过滤（服务端强制）。
- 允许列表持久化：operator/developer 复用 settings 表（`allowlist:operator` 等，
  免新表迁移）或新增表（随 1.x 迁移）；middleware 预热角色缓存（同会话吊销模式）。

### 2.3 风险
- 门禁迁移面广（逐路由），漏改=越权；需 rbac e2e 全矩阵覆盖后才可上线。
- developer 数据范围过滤若漏=横向越权；必须服务端强制+测试。

---

## 3. enroll 每设备令牌（Per-Device Report Tokens）

### 3.1 现状与缺口
- enroll 下发**全局共享** `report_token` + 每设备 `signing_secret`。
- 缺口：单设备泄露/失陷需轮换全局令牌（影响所有终端）；无法按设备吊销上报权。

### 3.2 目标态
- enroll 签发**每设备** `report_token`（CSPRNG，存 Collector 设备凭据表）；
  Collector 校验 per-device token，未知即拒并审计。
- 每设备可吊销/轮换（控制台设备页"吊销上报凭据"），不影响其他终端。
- 迁移：Collector 双接受（全局 ∪ per-device）过渡，按 Agent 版本门禁切全 per-device。

### 3.3 风险
- Collector 凭据表与双接受逻辑改动上报主链路；需灰度 + 回滚开关。

---

## 4. 实施顺序与无人值守边界

| 批 | 内容 | 生产风险 | 可否无人值守 |
|---|---|---|---|
| 1 | 本文档 + rbac/签名 e2e 骨架 | 无 | ✅ |
| 2 | Capability RBAC（含 e2e 全矩阵） | 中（越权面） | ⚠️ 建议有人复核 |
| 3 | 签名策略 dual-sign（阶段 A） | 中 | ⚠️ 建议有人复核 |
| 4 | Per-device tokens 双接受 | 中（上报主链路） | ⚠️ 建议有人复核 |
| 5 | 强制 ed25519 / 全 per-device（阶段 B） | 高（拒服务面） | ❌ 必须有人值守灰度 |

无人值守窗口内只做批 1（设计+测试骨架）与零风险项；批 2-5 留待有人窗口按本设计执行。
