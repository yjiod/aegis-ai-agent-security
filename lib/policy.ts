/**
 * lib/policy.ts — 签名策略发布（把处置决定变成终端可强制、可验签的策略）。
 *
 * 背景：终端 Agent 早已实现 `aegis.policy/v1` 的 allow/block 强制契约，但控制台
 * 的处置(allow/monitor/deny)此前只写进标签表，从未真正生成一份下发给终端的策略。
 * 本模块把标签注册表编译成一份权威的 aegis.policy/v1 文档，用服务端 HMAC 密钥
 * 签名后发布；终端加载时验签，篡改则拒载并 fail-safe 回退上一份有效策略。
 *
 * 跨语言一致性（关键）：签名覆盖的是「策略体的规范化 JSON」——递归按 key 排序、
 * 紧凑分隔符(, :)、UTF-8 不转义非 ASCII。JS(此处) 与 Python(终端 Agent) 必须产出
 * 逐字节相同的规范化串，签名才能互验。tests/test_aegis.py 有对拍用例保证这一点。
 *
 * 厂商中立：签名密钥来自 AEGIS_POLICY_SIGNING_KEY（回退 AEGIS_SESSION_SECRET），
 * 密钥可轮换；signing_key_id 为密钥指纹，终端据此选择验签密钥。无任何厂商耦合。
 */
import { createHmac, createHash, randomUUID } from 'node:crypto';
import { listLabels, type AssetLabel } from './labels';
import {
  ed25519Supported,
  ed25519PublicKey,
  ed25519Sign,
  bytesToB64,
  b64ToBytes,
} from './ed25519-runtime';
import {
  pgEnabled,
  pgLoadPolicyReleases,
  pgInsertPolicyRelease,
  pgSupersedePolicyReleases,
  pgLoadSigningKeys,
  pgUpsertSigningKey,
  type PolicyReleaseRow,
} from './pg-store';

export const POLICY_SCHEMA = 'aegis.policy/v1';

/** 策略里参与签名的确定性字段（自由文本/时间戳类不纳入，避免规范化歧义）。 */
export interface PolicyBody {
  schema: typeof POLICY_SCHEMA;
  version: string;
  limits: Record<string, number>;
  enforcement: Record<string, string>;
  allowed_skills: string[];
  allowed_mcp_transports: string[];
  allowed_mcp_servers: string[];
  allowed_mcp_commands: string[];
  allowed_mcp_command_paths: string[];
  allowed_mcp_invocations: string[][];
  allowed_mcp_domains: string[];
  blocked_commands: string[];
  secret_patterns: string[];
  skill_rules: string[];
  mcp_rules: string[];
  code_rules: string[];
  scan_mode: string;
  agent_self_update: Record<string, unknown>;
  custom_baseline_rules: string[];
  monitor_notes: Record<string, string>;
  modules: Record<string, boolean>;
  deny: { skills: string[]; mcp: string[] };
  /** 仅当发布时 typed override 通过才置 true; 终端据此放行超爆炸半径上限的封禁动作。 */
  enforce_override?: boolean;
}

/**
 * 出厂默认策略基座（与 public/downloads/aegis-policy.json 的静态部分对齐）。
 * 发布时以此为基座，叠加处置注册表推导出的 allowed_* / scan_mode。
 * 这是「已发布策略」的权威基座；静态 json 文件是终端首次部署的出厂默认。
 */
export const BASE_POLICY: Omit<PolicyBody, 'version' | 'allowed_skills' | 'allowed_mcp_servers' | 'scan_mode'> = {
  schema: POLICY_SCHEMA,
  limits: { project_files: 10000, max_file_bytes: 1000000, inventory_items: 5000, findings: 10000 },
  enforcement: { unknown_skill: 'audit', unknown_mcp: 'audit', critical_finding: 'block' },
  allowed_mcp_transports: ['stdio', 'https'],
  allowed_mcp_commands: ['docker', 'node', 'node_repl', 'npx', 'python3', 'uvx'],
  allowed_mcp_command_paths: ['/Applications/Codex.app/Contents/Resources/cua_node/bin/node_repl'],
  allowed_mcp_invocations: [],
  allowed_mcp_domains: [],
  blocked_commands: ['curl * | sh', 'wget * | sh', 'chmod 777', 'rm -rf'],
  secret_patterns: ['AKIA[0-9A-Z]{16}', 'sk-[A-Za-z0-9_-]{20,}', 'ghp_[A-Za-z0-9]{30,}'],
  skill_rules: ['unknown_skill', 'prompt_override', 'hidden_instruction', 'credential_access', 'unbounded_shell', 'skill_symlink_escape'],
  mcp_rules: ['unknown_mcp', 'unapproved_mcp_transport', 'ambiguous_mcp_transport', 'unapproved_mcp_domain', 'unapproved_mcp_command_path', 'unapproved_mcp_invocation', 'invalid_mcp_arguments', 'invalid_mcp_server', 'invalid_mcp_environment', 'mcp_url_credentials', 'broad_filesystem_scope', 'literal_mcp_secret'],
  code_rules: ['hardcoded_secret', 'shell_true', 'dynamic_eval', 'weak_random_token', 'blocked_command', 'insecure_tls_verification', 'unsafe_deserialization', 'debug_mode_enabled', 'empty_exception_handler', 'oversized_file_skipped', 'dependency_unpinned', 'dependency_untrusted_source', 'missing_lockfile'],
  agent_self_update: {
    enabled: true,
    channel: 'pilot',
    // 100%：现网终端规模小且用户要求"手动装新客户端后可未来自更新"。25% 灰度桶经实测
    // 不覆盖任何在网设备(哈希分桶 46/27/73/29 均≥25)，等于自更新永不触发。下载仍强制
    // SHA-256 校验+同源钉子+原子替换+可回滚，风险可控；如需再灰度可回调此值并发布。
    rollout_percent: 100,
    note: '自更新仅为无桌管环境兜底; 主通道为桌管/MDM 推送。下载强制 SHA-256 校验+原子替换+可回滚。',
  },
  custom_baseline_rules: [],
  monitor_notes: {
    node_repl: 'approved+monitor: computer-use 必需能力, 已加白但保持调用审计与 TRUSTED_CODE_PATHS 约束',
  },
  // 模块开关出厂默认：扫描类全开；封禁执行类默认关（deny 名单只报不封，打开才真封禁）。
  modules: {
    skill_scan: true, mcp_scan: true, code_scan: true, deps_scan: true,
    baseline_install: true, network_collect: true, self_update: true,
    skill_enforce: false, mcp_enforce: false,
  },
  deny: { skills: [], mcp: [] },
};

/** 出厂默认已加白清单（叠加处置 allow 之前的基线）。
 *
 * 用户口径（2026-09）：加白以**数据库**(asset_labels, disposition=allow)为唯一来源，
 * 不在代码里硬编码白名单。原生核心由 lib/default-allowlist 经「录入默认自带白名单」
 * 写入 DB；连接器/专家套件/技能库/社区商店/自建项一律待管理员手工决策。
 * 故此处置空——历史上这里硬编码过一批社区/自建 skill 与用户自配 MCP，绕过了 DB
 * 处置，导致"已按新口径清理 DB 但策略仍放行"的不一致。保留空数组以维持类型与合并逻辑。
 */
export const BASE_ALLOWED_SKILLS: string[] = [];
export const BASE_ALLOWED_MCP_SERVERS: string[] = [];

/** 当前扫描模式由 lib/baselines.getScanMode 提供；此处仅声明默认。 */
export const DEFAULT_SCAN_MODE = 'standard';

function dedupeSorted(items: string[]): string[] {
  return [...new Set(items.filter((x) => typeof x === 'string' && x.length > 0))].sort();
}

/**
 * 把处置注册表编译成权威策略体（allow / monitor / deny 三态都真实下发）。
 * - allow 标签的 skill/mcp 并入 allowed_*（去重排序）。
 * - deny 标签的资产从 allowed_* 中剔除（配合 enforcement.unknown_skill=block 即拦截）。
 * - monitor 标签写入 monitor_notes（key=asset_key），终端据此"加白但保持调用审计"，
 *   不再与 deny 等价。
 * - custom_baseline_rules 来自调用方传入的 effectiveRules()∩可执行规则集，使
 *   scan_mode=custom 真正强制导入的基线，而不是空集静默关闭扫描。
 */
/** 封禁爆炸半径硬上限（PM 评审 #1）：单次发布影响资产数上限，及单设备已发现 skill 占比上限。
 *  超限发布需 typed override，且签名策略带 enforce_override 标志终端才放行超 cap 动作。 */
export const BLAST_CAP_ASSETS = 5;
export const BLAST_CAP_PCT = 10;
export const BLAST_OVERRIDE_PHRASE = 'I-ACCEPT-BLAST-RADIUS';
/** 绝对上限（fail-closed，**不可** override）：超过必须分批发布，防"批量识别→一键全封"。 */
export const BLAST_ABS_CAP_ASSETS = 20;
export const BLAST_ABS_CAP_PCT = 50;
/** 终端每周期最多执行的封禁动作数（分期执行，留观察/回滚窗口）。 */
export const ENFORCE_PER_CYCLE = 5;

export function computePolicyBody(opts: { version: string; scanMode: string; labels?: AssetLabel[]; customRuleIds?: string[]; modules?: Record<string, boolean>; enforceOverride?: boolean }): PolicyBody {
  const labels = opts.labels ?? listLabels();
  const allowSkills = labels.filter((l) => l.asset_type === 'skill' && l.disposition === 'allow').map((l) => l.asset_key);
  const allowMcp = labels.filter((l) => l.asset_type === 'mcp' && l.disposition === 'allow').map((l) => l.asset_key);
  const denySkills = new Set(labels.filter((l) => l.asset_type === 'skill' && l.disposition === 'deny').map((l) => l.asset_key));
  const denyMcp = new Set(labels.filter((l) => l.asset_type === 'mcp' && l.disposition === 'deny').map((l) => l.asset_key));

  const allowed_skills = dedupeSorted([...BASE_ALLOWED_SKILLS, ...allowSkills]).filter((s) => !denySkills.has(s));
  const allowed_mcp_servers = dedupeSorted([...BASE_ALLOWED_MCP_SERVERS, ...allowMcp]).filter((s) => !denyMcp.has(s));

  // monitor 处置 → monitor_notes（在出厂注释之上叠加，按 asset_key）。
  const monitor_notes: Record<string, string> = { ...BASE_POLICY.monitor_notes };
  for (const l of labels) {
    if (l.disposition !== 'monitor') continue;
    const detail = [l.tags?.join('/'), l.note].filter((x) => typeof x === 'string' && x.trim()).join(' · ').trim();
    monitor_notes[l.asset_key] = (detail ? `${detail}` : '观察中').slice(0, 180);
  }

  const custom_baseline_rules = dedupeSorted(opts.customRuleIds ?? []);

  // 显式封禁名单(deny.*): 终端执行器据此隔离 Skill / 移除 MCP 配置(受 modules.*_enforce 门控)。
  // 模块开关(modules): 出厂默认之上叠加控制台持久化的覆盖值; 执行类开关默认 false。
  const baseModules = BASE_POLICY.modules;
  const modules: Record<string, boolean> = { ...baseModules };
  if (opts.modules) Object.assign(modules, opts.modules);
  const deny = { skills: dedupeSorted([...denySkills]), mcp: dedupeSorted([...denyMcp]) };

  return {
    ...BASE_POLICY,
    version: opts.version,
    allowed_skills,
    allowed_mcp_servers,
    scan_mode: opts.scanMode || DEFAULT_SCAN_MODE,
    custom_baseline_rules,
    monitor_notes,
    modules,
    deny,
    ...(opts.enforceOverride ? { enforce_override: true } : {}),
  };
}

/** 过滤出终端 Agent 真正可执行的规则 id（∈ BASE_POLICY.code_rules），用于 custom_baseline_rules。 */
export function enforceableRuleIds(ids: string[]): string[] {
  const allowed = new Set(BASE_POLICY.code_rules);
  return dedupeSorted(ids.filter((id) => allowed.has(id)));
}

/**
 * 规范化 JSON：递归按 key 排序 + 紧凑分隔符 + 不转义非 ASCII。
 * 必须与 terminal Agent 的 Python canonical_json 逐字节一致（见 tests 对拍）。
 */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((v) => canonicalJson(v)).join(',')}]`;
  }
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  const parts = keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(obj[k])}`);
  return `{${parts.join(',')}}`;
}

/**
 * 签名密钥环（keyring）。密钥料只来自 env/KMS（AEGIS_POLICY_SIGNING_KEYS 的
 * JSON {key_id: secret}，或单钥 AEGIS_POLICY_SIGNING_KEY），绝不入库、绝不回退到
 * 会话密钥——策略签名与会话认证是两个独立信任域，耦合会让任一方轮换击穿另一方。
 */
function keyringSecrets(): Record<string, string> {
  const raw = process.env.AEGIS_POLICY_SIGNING_KEYS;
  if (raw) {
    try {
      const parsed = JSON.parse(raw) as unknown;
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
        const out: Record<string, string> = {};
        for (const [k, v] of Object.entries(parsed as Record<string, unknown>)) {
          if (typeof v === 'string' && v) out[k] = v;
        }
        if (Object.keys(out).length > 0) return out;
      }
    } catch {
      /* 配置非法时回退单钥 */
    }
  }
  const single = process.env.AEGIS_POLICY_SIGNING_KEY;
  if (single) return { default: single };
  return {};
}

/** 密钥指纹（sha256 前 12 位），仅用于展示/可见性，不是密钥本身。 */
export function fingerprintOf(secret: string): string {
  return createHash('sha256').update(secret).digest('hex').slice(0, 12);
}

const gk = globalThis as typeof globalThis & {
  __aegis_signing_keys?: SigningKeyMeta[];
  __aegis_signing_keys_loaded?: Promise<void> | null;
};

export interface SigningKeyMeta {
  key_id: string;
  fingerprint: string;
  status: 'active' | 'retiring' | 'retired';
  created_at: number;
  created_by: string;
  rotated_at?: number;
  rotated_by?: string;
  retired_at?: number;
  retired_by?: string;
  note?: string;
}

function keyMeta(): SigningKeyMeta[] {
  if (!gk.__aegis_signing_keys) gk.__aegis_signing_keys = [];
  return gk.__aegis_signing_keys;
}

/** 请求期懒加载签名密钥元数据（每 isolate 一次）。无 PG 时直接用内存/env。 */
export function ensureSigningKeysLoaded(): Promise<void> {
  if (!pgEnabled()) return Promise.resolve();
  if (!gk.__aegis_signing_keys_loaded) {
    gk.__aegis_signing_keys_loaded = (async () => {
      const rows = await pgLoadSigningKeys();
      if (!rows) return;
      const arr = keyMeta();
      for (const r of rows) {
        if (!arr.some((x) => x.key_id === r.key_id)) {
          arr.push({
            key_id: r.key_id,
            fingerprint: r.fingerprint || '',
            status: r.status === 'retiring' ? 'retiring' : r.status === 'retired' ? 'retired' : 'active',
            created_at: Number(r.created_at || 0),
            created_by: r.created_by || '',
            ...(r.rotated_at ? { rotated_at: Number(r.rotated_at) } : {}),
            ...(r.rotated_by ? { rotated_by: r.rotated_by } : {}),
            ...(r.retired_at ? { retired_at: Number(r.retired_at) } : {}),
            ...(r.retired_by ? { retired_by: r.retired_by } : {}),
            ...(r.note ? { note: r.note } : {}),
          });
        }
      }
    })();
  }
  return gk.__aegis_signing_keys_loaded;
}

/** 解析当前活跃签名密钥 id：DB active → env ACTIVE_KEY_ID → keyring 唯一/首个 → ''。 */
export function activeKeyIdResolved(): string {
  const ring = keyringSecrets();
  const ids = Object.keys(ring);
  if (ids.length === 0) return '';
  const dbActive = keyMeta().find((k) => k.status === 'active' && k.key_id in ring);
  if (dbActive) return dbActive.key_id;
  const envActive = process.env.AEGIS_POLICY_ACTIVE_KEY_ID;
  if (envActive && envActive in ring) return envActive;
  return ids[0];
}

/** 当前活跃 signing_key_id（写进发布件，供终端按 id 选验签密钥）。 */
export function signingKeyId(): string {
  return activeKeyIdResolved() || 'unconfigured';
}

/** 当前活跃密钥指纹（仅展示）。 */
export function signingKeyFingerprint(): string {
  const ring = keyringSecrets();
  const id = activeKeyIdResolved();
  if (!id || !(id in ring)) return 'unconfigured';
  return fingerprintOf(ring[id]);
}

/** 对策略体规范化串用「活跃密钥」计算 HMAC-SHA256（hex）。无活跃密钥返回空串（不可发布）。 */
export function signPolicyBody(body: PolicyBody): string {
  const ring = keyringSecrets();
  const id = activeKeyIdResolved();
  if (!id || !(id in ring)) return '';
  return createHmac('sha256', ring[id]).update(canonicalJson(body)).digest('hex');
}

/** 供终端消费的完整发布件：策略体 + 签名 + 密钥指纹。 */
export interface SignedPolicy {
  policy: PolicyBody;
  signature: string;
  signing_key_id: string;
}

export function buildSignedPolicy(body: PolicyBody): SignedPolicy {
  return { policy: body, signature: signPolicyBody(body), signing_key_id: signingKeyId() };
}

/**
 * 发布件版本号：必须高于出厂 4.8.0、逐次递增、且可被 posture 精确字符串比对。
 * release 1 -> 4.9.0，release 2 -> 4.10.0 …（替换此前会永久 drifted 的 `${n}.0.0`）。
 */
export function policyVersionString(releaseVersion: number): string {
  return `4.${8 + releaseVersion}.0`;
}

/**
 * 终端可直接加载的「拍平」签名工件：顶层即 aegis.policy/v1 字段 + signature +
 * signing_key_id —— 正是 agent load_policy/verify_policy_signature 期望的形状
 * （验签时剔除 signature/signing_key_id 后对其余字段做规范化）。canonical 是要分发的
 * 逐字节内容，sha256 供 MDM 分发完整性校验。
 */
export interface PolicyArtifact {
  artifact: PolicyBody & { signature: string; signing_key_id: string };
  canonical: string;
  sha256: string;
  version: string;
}

export function buildPolicyArtifact(body: PolicyBody, signature: string, signingKeyId: string): PolicyArtifact {
  const artifact = { ...body, signature, signing_key_id: signingKeyId };
  const canonical = canonicalJson(artifact);
  return {
    artifact,
    canonical,
    sha256: createHash('sha256').update(canonical).digest('hex'),
    version: body.version,
  };
}

/* ── 批3 dual-sign：Ed25519 附加签名（默认关闭，配置 seed 才启用）──────────
 * AEGIS_POLICY_ED25519_SEED = base64(32B seed)。启用后发布件在 HMAC 签名之外附加
 * ed25519_signature / ed25519_public / ed25519_key_id，签名覆盖「不含 ed25519 字段」
 * 的 canonical 串（即 HMAC 工件的逐字节内容），终端/任何持有公钥者可独立验签。
 * 运行时不支持 Ed25519 或 seed 未配置 → 返回 null（优雅回落 HMAC-only，可回滚）。
 */
export interface Ed25519PolicyFields {
  ed25519_signature: string;
  ed25519_public: string;
  ed25519_key_id: string;
}
function ed25519Seed(): Uint8Array | null {
  const b64 = process.env.AEGIS_POLICY_ED25519_SEED;
  if (!b64) return null;
  const seed = b64ToBytes(b64);
  return seed && seed.length === 32 ? seed : null;
}
export async function ed25519PolicyFields(canonicalWithoutEd: string): Promise<Ed25519PolicyFields | null> {
  const seed = ed25519Seed();
  if (!seed) return null;
  if (!(await ed25519Supported())) return null;
  const pub = await ed25519PublicKey(seed);
  const sig = await ed25519Sign(seed, new TextEncoder().encode(canonicalWithoutEd));
  if (!pub || !sig) return null;
  return {
    ed25519_signature: bytesToB64(sig),
    ed25519_public: bytesToB64(pub),
    ed25519_key_id: createHash('sha256').update(pub).digest('hex').slice(0, 12),
  };
}
/** 公开验签钥信息（公钥非秘密，可未认证分发）；未配置返回 null。 */
export async function ed25519VerifyKeyInfo(): Promise<{ algorithm: 'ed25519'; public: string; key_id: string } | null> {
  const seed = ed25519Seed();
  if (!seed) return null;
  if (!(await ed25519Supported())) return null;
  const pub = await ed25519PublicKey(seed);
  if (!pub) return null;
  return { algorithm: 'ed25519', public: bytesToB64(pub), key_id: createHash('sha256').update(pub).digest('hex').slice(0, 12) };
}

/* ─── 发布件存储（内存 + PG 写穿透，遵循 workerd 请求期懒加载约束） ─────── */

export interface PolicyReceipt {
  label_counts: { allow: number; monitor: number; deny: number };
}

export interface PolicyRelease {
  release_id: string;
  version: number;
  created_at: number;
  created_by: string;
  signing_key_id: string;
  signature: string;
  policy: PolicyBody;
  note: string;
  status: 'published' | 'superseded';
  receipt: PolicyReceipt;
}

const g = globalThis as typeof globalThis & {
  __aegis_policy_releases?: PolicyRelease[];
  __aegis_policy_loaded?: Promise<void> | null;
};

function releases(): PolicyRelease[] {
  if (!g.__aegis_policy_releases) g.__aegis_policy_releases = [];
  return g.__aegis_policy_releases;
}

function rowToRelease(r: PolicyReleaseRow): PolicyRelease | null {
  let policy: PolicyBody;
  try {
    policy = JSON.parse(r.policy_json) as PolicyBody;
  } catch {
    return null;
  }
  return {
    release_id: r.release_id,
    version: Number(r.version),
    created_at: Number(r.created_at),
    created_by: r.created_by || '',
    signing_key_id: r.signing_key_id || '',
    signature: r.signature || '',
    policy,
    note: r.note || '',
    status: r.status === 'superseded' ? 'superseded' : 'published',
    receipt: { label_counts: { allow: 0, monitor: 0, deny: 0 } },
  };
}

/** 请求期懒加载已发布策略（每 isolate 一次）。无 PG 时直接用内存。 */
export function ensurePolicyReleasesLoaded(): Promise<void> {
  if (!pgEnabled()) return Promise.resolve();
  if (!g.__aegis_policy_loaded) {
    g.__aegis_policy_loaded = (async () => {
      const rows = await pgLoadPolicyReleases();
      if (!rows) return;
      const arr = releases();
      for (const r of rows) {
        const rel = rowToRelease(r);
        if (rel && !arr.some((x) => x.release_id === rel.release_id)) arr.push(rel);
      }
      arr.sort((a, b) => a.version - b.version);
    })();
  }
  return g.__aegis_policy_loaded;
}

export function listPolicyReleases(): PolicyRelease[] {
  return [...releases()].sort((a, b) => b.version - a.version);
}

/** 当前生效发布件（最高版本的 published），无则 null（绝不伪造）。 */
export function currentPolicyRelease(): PolicyRelease | null {
  const published = releases().filter((r) => r.status === 'published');
  if (published.length === 0) return null;
  return published.reduce((max, r) => (r.version > max.version ? r : max));
}

function countLabels(labels: AssetLabel[]): PolicyReceipt {
  return {
    label_counts: {
      allow: labels.filter((l) => l.disposition === 'allow').length,
      monitor: labels.filter((l) => l.disposition === 'monitor').length,
      deny: labels.filter((l) => l.disposition === 'deny').length,
    },
  };
}

/**
 * 编译 + 签名 + 落库一次策略发布。version 单调递增，旧发布置 superseded。
 * 需要已配置签名密钥；未配置返回 null（调用方据此诚实报错，不产出未签名策略）。
 */
export function publishPolicyRelease(opts: { scanMode: string; by: string; note?: string; customRuleIds?: string[]; modules?: Record<string, boolean>; enforceOverride?: boolean }): PolicyRelease | null {
  if (!activeKeyIdResolved()) return null;
  const arr = releases();
  const nextVersion = arr.reduce((max, r) => Math.max(max, r.version), 0) + 1;
  const labels = listLabels();
  const body = computePolicyBody({ version: policyVersionString(nextVersion), scanMode: opts.scanMode, labels, customRuleIds: opts.customRuleIds, modules: opts.modules, enforceOverride: opts.enforceOverride });
  const signature = signPolicyBody(body);
  if (!signature) return null;
  const now = Date.now();
  const release: PolicyRelease = {
    release_id: randomUUID(),
    version: nextVersion,
    created_at: now,
    created_by: opts.by,
    signing_key_id: signingKeyId(),
    signature,
    policy: body,
    note: opts.note ?? '',
    status: 'published',
    receipt: countLabels(labels),
  };
  // 旧发布失效
  for (const r of arr) if (r.status === 'published') r.status = 'superseded';
  arr.push(release);
  // PG 写穿透
  pgInsertPolicyRelease({
    release_id: release.release_id,
    version: release.version,
    created_at: release.created_at,
    created_by: release.created_by,
    signing_key_id: release.signing_key_id,
    signature: release.signature,
    policy_json: JSON.stringify(release.policy),
    note: release.note,
    status: 'published',
  });
  pgSupersedePolicyReleases(release.release_id);
  return release;
}

/**
 * 一键回滚（PM 评审 #1 的 rollback UX 后端）：把指定历史发布的 policy body 以**新版本号**
 * 重新签名发布（不修改历史release，保持审计不可变）。用于"封错了立刻回到上一版"。
 */
export function publishPolicyBodyRaw(base: PolicyBody, by: string, note: string): PolicyRelease | null {
  if (!activeKeyIdResolved()) return null;
  const arr = releases();
  const nextVersion = arr.reduce((max, r) => Math.max(max, r.version), 0) + 1;
  const body: PolicyBody = { ...base, version: policyVersionString(nextVersion) };
  const signature = signPolicyBody(body);
  if (!signature) return null;
  const now = Date.now();
  const release: PolicyRelease = {
    release_id: randomUUID(),
    version: nextVersion,
    created_at: now,
    created_by: by,
    signing_key_id: signingKeyId(),
    signature,
    policy: body,
    note,
    status: 'published',
    receipt: countLabels(listLabels()),
  };
  for (const r of arr) if (r.status === 'published') r.status = 'superseded';
  arr.push(release);
  pgInsertPolicyRelease({
    release_id: release.release_id,
    version: release.version,
    created_at: release.created_at,
    created_by: release.created_by,
    signing_key_id: release.signing_key_id,
    signature: release.signature,
    policy_json: JSON.stringify(release.policy),
    note: release.note,
    status: 'published',
  });
  pgSupersedePolicyReleases(release.release_id);
  return release;
}

/* ─── 签名密钥治理：轮换 / 退役（密钥料只在 env，DB 仅存元数据） ─────────── */

export interface SigningKeyView {
  key_id: string;
  fingerprint: string;
  in_keyring: boolean;
  status: 'active' | 'retiring' | 'retired' | 'provisioned';
  releases: number;
  created_at?: number;
  rotated_at?: number;
  retired_at?: number;
}

function persistKeyMeta(meta: SigningKeyMeta): void {
  const arr = keyMeta();
  const i = arr.findIndex((k) => k.key_id === meta.key_id);
  if (i >= 0) arr[i] = meta;
  else arr.push(meta);
  pgUpsertSigningKey({
    key_id: meta.key_id,
    fingerprint: meta.fingerprint,
    status: meta.status,
    created_at: meta.created_at,
    created_by: meta.created_by,
    rotated_at: meta.rotated_at ?? null,
    rotated_by: meta.rotated_by ?? null,
    retired_at: meta.retired_at ?? null,
    retired_by: meta.retired_by ?? null,
    note: meta.note ?? null,
  });
}

/** 列出 keyring ∪ DB 中的全部签名密钥（仅指纹/状态，绝不含密钥料）。 */
export function listSigningKeys(): SigningKeyView[] {
  const ring = keyringSecrets();
  const meta = keyMeta();
  const rels = releases();
  const activeId = activeKeyIdResolved();
  const ids = [...new Set([...Object.keys(ring), ...meta.map((m) => m.key_id)])];
  return ids
    .map((id) => {
      const m = meta.find((x) => x.key_id === id);
      const inKeyring = id in ring;
      const fingerprint = inKeyring ? fingerprintOf(ring[id]) : (m?.fingerprint ?? '');
      let status: SigningKeyView['status'];
      if (m) status = m.status;
      else if (id === activeId) status = 'active';
      else if (inKeyring) status = 'provisioned';
      else status = 'retired';
      return {
        key_id: id,
        fingerprint,
        in_keyring: inKeyring,
        status,
        releases: rels.filter((r) => r.signing_key_id === id).length,
        ...(m?.created_at ? { created_at: m.created_at } : {}),
        ...(m?.rotated_at ? { rotated_at: m.rotated_at } : {}),
        ...(m?.retired_at ? { retired_at: m.retired_at } : {}),
      };
    })
    .sort((a, b) => a.key_id.localeCompare(b.key_id));
}

export type RotateResult =
  | { ok: true; active_key_id: string; retired_to: string }
  | { ok: false; error: 'key_not_in_keyring' | 'already_active' | 'no_keyring' };

/** 轮换：把活跃签名密钥切到 keyring 中已预置的 toKeyId；旧活跃钥转 retiring（重叠期内仍可验签）。 */
export function rotateSigningKey(toKeyId: string, by: string): RotateResult {
  const ring = keyringSecrets();
  if (Object.keys(ring).length === 0) return { ok: false, error: 'no_keyring' };
  if (!(toKeyId in ring)) return { ok: false, error: 'key_not_in_keyring' };
  const currentActive = activeKeyIdResolved();
  if (currentActive === toKeyId) return { ok: false, error: 'already_active' };
  const now = Date.now();
  // 旧活跃钥 → retiring（仍在 keyring，终端重叠期可继续验签）
  if (currentActive && currentActive in ring) {
    const prev = keyMeta().find((k) => k.key_id === currentActive);
    persistKeyMeta({
      key_id: currentActive,
      fingerprint: fingerprintOf(ring[currentActive]),
      status: 'retiring',
      created_at: prev?.created_at ?? now,
      created_by: prev?.created_by ?? by,
      rotated_at: now,
      rotated_by: by,
      ...(prev?.retired_at ? { retired_at: prev.retired_at } : {}),
      ...(prev?.retired_by ? { retired_by: prev.retired_by } : {}),
    });
  }
  // 新钥 → active
  const existing = keyMeta().find((k) => k.key_id === toKeyId);
  persistKeyMeta({
    key_id: toKeyId,
    fingerprint: fingerprintOf(ring[toKeyId]),
    status: 'active',
    created_at: existing?.created_at ?? now,
    created_by: existing?.created_by ?? by,
    rotated_at: now,
    rotated_by: by,
  });
  return { ok: true, active_key_id: toKeyId, retired_to: currentActive };
}

export type RetireResult =
  | { ok: true; key_id: string }
  | { ok: false; error: 'is_active' | 'in_use_by_published' | 'not_found' };

/**
 * 退役：把一把 retiring 密钥标记为 retired（终端将不再能用它验签）。
 * 证据门禁：不能退役当前活跃钥；且当前生效发布件不能仍由该钥签发
 * （否则终端拉到的最新策略会验签失败）——必须先发布一份用新活跃钥签名的策略。
 */
export function retireSigningKey(keyId: string, by: string): RetireResult {
  const activeId = activeKeyIdResolved();
  if (keyId === activeId) return { ok: false, error: 'is_active' };
  const cur = currentPolicyRelease();
  if (cur && cur.signing_key_id === keyId) return { ok: false, error: 'in_use_by_published' };
  const ring = keyringSecrets();
  const existing = keyMeta().find((k) => k.key_id === keyId);
  if (!existing && !(keyId in ring)) return { ok: false, error: 'not_found' };
  const now = Date.now();
  persistKeyMeta({
    key_id: keyId,
    fingerprint: existing?.fingerprint ?? (keyId in ring ? fingerprintOf(ring[keyId]) : ''),
    status: 'retired',
    created_at: existing?.created_at ?? now,
    created_by: existing?.created_by ?? by,
    ...(existing?.rotated_at ? { rotated_at: existing.rotated_at } : {}),
    ...(existing?.rotated_by ? { rotated_by: existing.rotated_by } : {}),
    retired_at: now,
    retired_by: by,
  });
  return { ok: true, key_id: keyId };
}
