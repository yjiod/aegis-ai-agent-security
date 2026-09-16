# 4A 与策略完整性增强设计（Signed-Policy / Capability-RBAC / Per-Device Tokens）

> 状态：**分批实施中**。批 2（Capability RBAC）、批 3（签名策略 dual-sign）、
> 批 4（每设备令牌）已实施上线；批 5 的**终端侧 Ed25519 独立验签**已实施并经生产
> 端到端验证，剩余**服务端强制灰度**仍留有人窗口。每批独立可回滚。
> 关联现状：`lib/policy.ts`（HMAC keyring 签名 + `ed25519PolicyFields` dual-sign）、
> `lib/ed25519-runtime.ts`（运行时原生 Ed25519：WebCrypto/node:crypto 特征探测）、
> `public/downloads/aegis_agent.py`（`load_policy(verify_key, require_signature)` +
> 纯 Python RFC8032 `ed25519_verify`/`verify_policy_ed25519` 独立验签）、
> `app/api/enroll/route.ts`（去签名策略 + 每设备 signing_secret + per-device report_token）、
> `app/api/policy/verify-key/route.ts`（未认证公开验签公钥）、`lib/auth.ts`（能力集 RBAC）。

---

## 0. 实施进展（截至最新）

| 批 | 内容 | 状态 | 证据 |
|---|---|---|---|
| 2 | Capability RBAC（operator/developer 细粒度 + 持久化） | ✅ 已上线 | commit `279303c`；`/api/developers`、developer 仅本人设备、middleware 预热角色缓存 |
| 3 | 签名策略 dual-sign（HMAC + Ed25519，默认由 seed 开关） | ✅ 已上线 | commit `41135a6`；生产 `/api/policy/verify-key` 返回真实公钥、`/api/policy/artifact` 携带 `ed25519_*` |
| 4 | Per-device 可吊销上报令牌（Collector 双接受过渡） | ✅ 已上线 | commit `8d92527`；enroll 签发每设备 `report_token`、控制台吊销端点 |
| 5a | **终端侧 Ed25519 独立验签**（纯 Python RFC8032，无第三方库） | ✅ 已上线并生产验证 | commit `67aac80`/`a1b5c58`；对**真实生产工件**（v4.12.0）`verify_policy_ed25519` => True、篡改 => False |
| 5b | **服务端强制灰度**（enroll 下发签名工件 + `require_signed_policy` 分档） | ⏳ 留有人窗口 | 见 §1.5 |

### 5a 端到端证明链（已闭合）
- 跨语言 canonical 一致：`test_policy_signature_verification_and_cross_language_canonical`
  对拍 JS `canonicalJson` 与 Python `canonical_json`（逐字节）。
- Python 验签正确性：`test_ed25519_verify_openssl_vector` +
  `test_verify_policy_ed25519_artifact_vector` + `test_verify_policy_ed25519_nested_body_vector`
  （openssl 原生签名向量；openssl 与 TS WebCrypto/node:crypto 同为 RFC8032 原生实现）。
- 群阶常量 `_ED_L` 已修正（此前值错误致标量乘不封闭），`L·B=identity` 不变量成立。
- 生产实测：从 `/api/policy/artifact`（Bearer 机器令牌）取真实签名工件 → 本地纯 Python
  独立验签 True；篡改任一 body 字段 → False。即 **TS(workerd WebCrypto) 签 → wire →
  Python 独立验** 全链通，不依赖传输通道信任。

---

## 1. 签名策略强制 + 非对称验签密钥分发（最高优先）

### 1.1 现状与缺口
- 服务端用 **对称 HMAC keyring**（`AEGIS_POLICY_SIGNING_KEYS`）对规范化策略体签名，
  `signing_key_id` 为密钥指纹；密钥只来自 env/KMS，不入库。**批 3 已叠加 Ed25519 非对称
  dual-sign**（`AEGIS_POLICY_ED25519_SEED` 配置即启用，生产已启用）。
- Agent 已具备验签能力（`verify_policy_signature` HMAC + `verify_policy_ed25519` 纯 Python
  Ed25519 独立验签 / `load_policy(..., require_signature)`）。
- **剩余缺口**：`/api/enroll` 下发的仍是**去签名**策略体，Agent 自动入网时以
  `require_signature=false` 仅凭 TLS 信任加载。即：Ed25519 验签能力已在终端就绪、
  签名工件已可由 `/api/policy/artifact` 获取，但**自动入网链路尚未把"签名工件 + 强制开关"
  下发给终端**，故完整性在 enroll 路径上仍依赖传输通道而非密码学。

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

### 1.5 剩余工作：enroll 路径的强制灰度（批 5b，留有人窗口）
终端验签能力（5a）与签名工件分发（`/api/policy/artifact`）均已就绪，唯独**自动入网**
仍下发去签名体。要把"密码学完整性"覆盖到 enroll 路径，需三件事，且必须灰度：

1. **enroll 下发签名工件而非去签名体**：当设备命中灰度档时，`/api/enroll` 的
   `payload.policy` 改为携带 `signature`/`signing_key_id`/`ed25519_*` 的**完整签名工件**
   （等价 `/api/policy/artifact` 输出），并置 `payload.require_signed_policy=true`。
   未命中档位维持现状（去签名 + `false`），保证零行为变化可回滚。
2. **验签公钥随入网下发/内嵌对齐**：终端以内嵌公钥为准，enroll 附 `verify_key` 仅作校验；
   不一致时终端拒绝并上报 `policy_verify_key_mismatch`（防被诱导换钥）。
3. **灰度分档复用企业 MD 机制**：`all | percent(hash(device_id)%100<p) | department`，
   与既有 `enterprise_md_*` 同一套 rollout 引擎；`AEGIS_POLICY_SIG_MODE=hmac|dual|ed25519`
   作为总闸，逐档回退无需重发终端。

**为何仍留有人窗口（❌ 不无人值守）**：强制档一旦命中而终端未拿到可验签的签名工件/公钥，
Agent 会 fail-closed 拒载策略（保留上一份有效签名策略，但新设备将无策略可用）——属拒服务面。
必须先在有真机、可即时回退 `SIG_MODE` 的窗口按 percent 1%→10%→100% 灰度，并观测
`policy_reload_failed`/`policy_verify_key_mismatch` 上报为零后再进档。

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

| 批 | 内容 | 生产风险 | 可否无人值守 | 现状 |
|---|---|---|---|---|
| 1 | 本文档 + rbac/签名 e2e 骨架 | 无 | ✅ | 已完成 |
| 2 | Capability RBAC（含 e2e 全矩阵） | 中（越权面） | ⚠️ 建议有人复核 | ✅ 已上线（`279303c`） |
| 3 | 签名策略 dual-sign（阶段 A） | 中 | ⚠️ 建议有人复核 | ✅ 已上线（`41135a6`，生产已启用 seed） |
| 4 | Per-device tokens 双接受 | 中（上报主链路） | ⚠️ 建议有人复核 | ✅ 已上线（`8d92527`） |
| 5a | 终端侧 Ed25519 独立验签 | 低（fail-open 回落 HMAC，仅在携带 ed 字段时校验） | ✅ 已无人值守完成 | ✅ 已上线并生产端到端验证（`67aac80`/`a1b5c58`） |
| 5b | 强制 ed25519 / enroll 下发签名工件（阶段 B） | 高（拒服务面） | ❌ 必须有人值守灰度 | ⏳ 待有人窗口，见 §1.5 |

批 5a 之所以可无人值守：终端 Ed25519 验签是**加法**——仅当发布件携带 `ed25519_*` 时才校验，
校验失败 fail-closed 拒载但保留上一份有效签名策略；无 ed 字段则 `None` 回落既有 HMAC 路径，
对现网终端零行为变化。批 5b 会改变 enroll 下发内容并打开强制开关，属拒服务面，必须有人灰度。
