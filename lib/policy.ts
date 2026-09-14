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
}

/**
 * 出厂默认策略基座（与 public/downloads/aegis-policy.json 的静态部分对齐）。
 * 发布时以此为基座，叠加处置注册表推导出的 allowed_* / scan_mode。
 * 这是「已发布策略」的权威基座；静态 json 文件是终端首次部署的出厂默认。
 */
export const BASE_POLICY: Omit<PolicyBody, 'version' | 'allowed_skills' | 'allowed_mcp_servers' | 'scan_mode'> = {
  schema: POLICY_SCHEMA,
  limits: { project_files: 10000, max_file_bytes: 1000000, inventory_items: 5000, findings: 10000 },
  enforcement: { unknown_skill: 'block', unknown_mcp: 'audit', critical_finding: 'block' },
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
};

/** 出厂默认已加白清单（叠加处置 allow 之前的基线）。 */
export const BASE_ALLOWED_SKILLS = [
  'claude-dev-suite-java-quality', 'dingtalk-aisearch', 'fwrite0920-project-bootstrapping',
  'godot-headless-game-pipeline', 'handwritten-form-to-excel', 'l-mb-py-modernize',
  'majesticlabs-dev-python-debugger', 'majiayu000-deeplearningcoder', 'majiayu000-fix-markdown-lint',
  'majiayu000-frontend-code-quality', 'michaelboeding-feature-council', 'mini-program-dev',
];
export const BASE_ALLOWED_MCP_SERVERS = ['github', 'filesystem', 'postgres'];

/** 当前扫描模式由 lib/baselines.getScanMode 提供；此处仅声明默认。 */
export const DEFAULT_SCAN_MODE = 'standard';

function dedupeSorted(items: string[]): string[] {
  return [...new Set(items.filter((x) => typeof x === 'string' && x.length > 0))].sort();
}

/**
 * 把处置注册表编译成权威策略体。
 * - allow 标签的 skill/mcp 并入 allowed_*（去重排序）。
 * - deny 标签的资产从 allowed_* 中剔除（配合 enforcement.unknown_skill=block 即拦截）。
 * - monitor 标签保持加白但不进 allowed 之外的特殊处理（终端仍审计）。
 */
export function computePolicyBody(opts: { version: string; scanMode: string; labels?: AssetLabel[] }): PolicyBody {
  const labels = opts.labels ?? listLabels();
  const allowSkills = labels.filter((l) => l.asset_type === 'skill' && l.disposition === 'allow').map((l) => l.asset_key);
  const allowMcp = labels.filter((l) => l.asset_type === 'mcp' && l.disposition === 'allow').map((l) => l.asset_key);
  const denySkills = new Set(labels.filter((l) => l.asset_type === 'skill' && l.disposition === 'deny').map((l) => l.asset_key));
  const denyMcp = new Set(labels.filter((l) => l.asset_type === 'mcp' && l.disposition === 'deny').map((l) => l.asset_key));

  const allowed_skills = dedupeSorted([...BASE_ALLOWED_SKILLS, ...allowSkills]).filter((s) => !denySkills.has(s));
  const allowed_mcp_servers = dedupeSorted([...BASE_ALLOWED_MCP_SERVERS, ...allowMcp]).filter((s) => !denyMcp.has(s));

  return {
    ...BASE_POLICY,
    version: opts.version,
    allowed_skills,
    allowed_mcp_servers,
    scan_mode: opts.scanMode || DEFAULT_SCAN_MODE,
  };
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
export function publishPolicyRelease(opts: { scanMode: string; by: string; note?: string }): PolicyRelease | null {
  if (!activeKeyIdResolved()) return null;
  const arr = releases();
  const nextVersion = arr.reduce((max, r) => Math.max(max, r.version), 0) + 1;
  const labels = listLabels();
  const body = computePolicyBody({ version: `${nextVersion}.0.0`, scanMode: opts.scanMode, labels });
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
