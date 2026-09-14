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

/** 策略签名密钥：优先专用密钥，回退会话密钥（与三个会话签发方一致的容错策略）。 */
function signingKey(): string {
  return process.env.AEGIS_POLICY_SIGNING_KEY || process.env.AEGIS_SESSION_SECRET || '';
}

/** 密钥指纹（前 12 位 sha256），作为 signing_key_id，供终端选择验签密钥；不泄露密钥本身。 */
export function signingKeyId(): string {
  const key = signingKey();
  if (!key) return 'unconfigured';
  return createHash('sha256').update(key).digest('hex').slice(0, 12);
}

/** 对策略体规范化串计算 HMAC-SHA256 签名（hex）。密钥未配置时返回空串（不可发布）。 */
export function signPolicyBody(body: PolicyBody): string {
  const key = signingKey();
  if (!key) return '';
  return createHmac('sha256', key).update(canonicalJson(body)).digest('hex');
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
  if (!signingKey()) return null;
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
