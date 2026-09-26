/**
 * lib/labels.ts — 资产标签与处置注册表（skill / MCP 打标 + 加白/观察/拉黑）。
 *
 * 内存快照（globalThis 跨模块重载存活）+ PostgreSQL 提交确认（lib/pg-store）。
 * 水合为请求期懒加载（ensureLabelsLoaded），遵循 workerd 全局作用域禁异步 I/O 约束。
 *
 * disposition 语义：
 *   ''       未处置
 *   'allow'  允许接入；仅明确人工处置保留旧版资产级告警例外语义
 *   'monitor'观察：不阻断，持续上报行为供复查
 *   'deny'   拉黑：加入阻断名单，终端拦截并告警
 */
import { normalizePathKey } from './path-key';
import {
  pgEnabled,
  pgLoadLabels,
  pgApplyLabelChanges,
  pgDeleteLabel,
  type AssetLabelRow,
} from './pg-store';

export type AssetType = 'skill' | 'mcp' | 'path' | 'prefix';
/** prefix = 目录前缀批量忽略（2026-09-25 用户需求）：asset_key 形如 "~/.codex/.tmp/"，
 * 抑制所有归一化后落在该前缀下的 path 资产发现。只作用于 path 类（skill/mcp 名
 * 与目录无关，不做前缀展开，防止意外封禁面扩大）。 */
export type Disposition = '' | 'allow' | 'monitor' | 'deny';

export type DecisionSource = 'manual' | 'preset' | 'automatic' | 'legacy';
const DECISION_SOURCES: DecisionSource[] = ['manual', 'preset', 'automatic', 'legacy'];

export const DISPOSITIONS: Disposition[] = ['', 'allow', 'monitor', 'deny'];

export interface AssetLabel {
  asset_type: AssetType;
  asset_key: string;
  tags: string[];
  disposition: Disposition;
  decision_source?: DecisionSource;
  note: string;
  updated_by: string;
  updated_at: number;
}

const globals = globalThis as typeof globalThis & {
  __aegis_labels?: Map<string, AssetLabel>;
  __aegis_label_loads?: Set<Set<string>>;
  __aegis_label_write_tail?: Promise<void>;
  __aegis_label_epoch?: number;
  __aegis_label_uncertain?: boolean;
};

/** Track only mutations made while a database snapshot is in flight. */
function activeLoads(): Set<Set<string>> {
  if (!globals.__aegis_label_loads) globals.__aegis_label_loads = new Set();
  return globals.__aegis_label_loads;
}

function markLocalMutation(key: string): void {
  for (const changed of activeLoads()) changed.add(key);
}

function store(): Map<string, AssetLabel> {
  if (!globals.__aegis_labels) globals.__aegis_labels = new Map();
  return globals.__aegis_labels;
}

const mapKey = (t: string, k: string) => `${t}:${k}`;

function rowToLabel(r: AssetLabelRow): AssetLabel {
  if (r.asset_type !== 'skill' && r.asset_type !== 'mcp' && r.asset_type !== 'path' && r.asset_type !== 'prefix') {
    throw new Error('invalid_label_asset_type');
  }
  const source = r.decision_source ?? 'legacy';
  if (!DECISION_SOURCES.includes(source as DecisionSource)) throw new Error('invalid_label_decision_source');
  let tags: string[] = [];
  try {
    const parsed = JSON.parse(r.tags || '[]');
    if (Array.isArray(parsed)) tags = parsed.filter((x) => typeof x === 'string');
  } catch {
    tags = [];
  }
  const disposition = (DISPOSITIONS as string[]).includes(r.disposition) ? (r.disposition as Disposition) : '';
  return {
    asset_type: r.asset_type,
    asset_key: r.asset_key,
    tags,
    disposition,
    decision_source: source as DecisionSource,
    note: r.note || '',
    updated_by: r.updated_by || '',
    updated_at: Number(r.updated_at || 0),
  };
}

let loadPromise: Promise<void> | null = null;

/** 请求期懒加载标签注册表（每 isolate 一次）。无 PG 时直接返回（内存/空）。 */
export function ensureLabelsLoaded(): Promise<void> {
  if (!pgEnabled()) return Promise.resolve();
  if (!loadPromise) {
    const epoch = globals.__aegis_label_epoch ?? 0;
    const attempt = (async () => {
      const changed = new Set<string>();
      activeLoads().add(changed);
      try {
        const rows = await pgLoadLabels();
        if (!rows) throw new Error('labels_load_failed');
        // Validate the whole snapshot before changing memory; unknown types must
        // never acquire skill permissions through an implicit conversion.
        const labels = rows.map(rowToLabel);
        if ((globals.__aegis_label_epoch ?? 0) !== epoch) throw new Error('labels_snapshot_obsolete');
        const m = store();
        const present = new Set(labels.map(l => mapKey(l.asset_type, l.asset_key)));
        // A committed-but-unacknowledged deletion must disappear after reload.
        for (const key of m.keys()) if (!present.has(key) && !changed.has(key)) m.delete(key);
        for (const label of labels) {
          const key = mapKey(label.asset_type, label.asset_key);
          // A local edit or deletion during I/O takes priority over this snapshot.
          if (!changed.has(key)) m.set(key, label);
        }
        globals.__aegis_label_uncertain = false;
      } finally {
        activeLoads().delete(changed);
      }
    })().catch(() => {
      if (loadPromise === attempt) loadPromise = null; // Do not reset a newer load.
      throw new Error('labels_load_failed');
    });
    loadPromise = attempt;
  }
  return loadPromise;
}

export function listLabels(): AssetLabel[] {
  return [...store().values()].sort(
    (a, b) => a.asset_type.localeCompare(b.asset_type) || a.asset_key.localeCompare(b.asset_key),
  );
}

/** 当前加白(disposition='allow')资产键集合，形如 "skill:xlsx" / "mcp:qw-builtin"。 */
export function allowedAssetKeys(): Set<string> {
  const s = new Set<string>();
  if (globals.__aegis_label_uncertain) return s;
  for (const l of store().values()) if (l.disposition === 'allow') s.add(mapKey(l.asset_type, l.asset_key));
  return s;
}

/** 一条 finding/工单里可能用于同源匹配的字段（兼容新旧终端）。 */
export interface FindingLike {
  kind?: unknown;
  path?: unknown;
  message?: unknown;
  asset_type?: unknown;
  asset_key?: unknown;
}

/**
 * 归一化 finding → 资产身份 (asset_type, asset_key)。
 * 优先用终端 0.34.1+ 显式上报的 asset_type/asset_key；否则从 kind/path/message 派生以兼容旧终端。
 * 无法可靠判定返回 null（此时**不抑制**，fail-toward-showing，绝不误藏真实告警）。
 */
export function findingAsset(f: FindingLike): { asset_type: AssetType; asset_key: string } | null {
  const at = typeof f.asset_type === 'string' ? f.asset_type.trim().toLowerCase() : '';
  const ak = typeof f.asset_key === 'string' ? f.asset_key.trim() : '';
  if ((at === 'skill' || at === 'mcp') && ak) return { asset_type: at as AssetType, asset_key: ak };
  const kind = typeof f.kind === 'string' ? f.kind.toLowerCase() : '';
  const path = typeof f.path === 'string' ? f.path.replace(/\\/g, '/') : '';
  const msg = typeof f.message === 'string' ? f.message : '';
  // skill：SKILL.md 的父目录名即 skill 名（与终端 scan_skill 的 name=root.name 同源）。
  if (kind.includes('skill') || /\/SKILL\.md$/i.test(path)) {
    const m = path.match(/\/([^/]+)\/SKILL\.md$/i);
    if (m && m[1]) return { asset_type: 'skill', asset_key: m[1] };
    const nm = msg.match(/Skill[:：]\s*([^\s[]+)/);
    if (nm && nm[1]) return { asset_type: 'skill', asset_key: nm[1].trim() };
  }
  // mcp：message 里的 server 名（"…MCP Server: {name}" 或 "MCP {name} …"）。
  if (kind.includes('mcp')) {
    const nm = msg.match(/MCP\s+Server[:：]\s*([^\s]+)/) || msg.match(/MCP\s+([^\s]+)\s/);
    if (nm && nm[1]) return { asset_type: 'mcp', asset_key: nm[1].trim() };
  }
  // path(代码路径)：非 skill/mcp 的文件路径类发现（hardcoded_secret / insecure_tls 等代码质量项）。
  // 引入 path 资产类型后，可按路径加白/观察/拉黑以抑制该路径上的发现（FP 处置通道）。
  // 注意：path 仅在 skill/mcp 均判不出时回落，绝不抢占显式/派生的 skill·mcp 身份。
  //
  // 文件路径归一化（不等于分类＋片段指纹去重）：事件 ID/行号/盘符
  // 大小写/用户主目录前缀（~ 与 绝对路径）/尾部斜杠的差异不得产生不同的资产键，否则
  // 加白后同文件的新发现（ID 不同）仍会重复告警。归一化规则：
  //   1. 统一分隔符为 /（已在上文 f.path 处理）；
  //   2. 丢弃行号/列号后缀（:123、:12:34）与查询串（?...）；
  //   3. 大小写不敏感（Windows 盘符/路径大小写不定）→ 小写化；
  //   4. 用户主目录前缀折叠为 ~（~/x 与 /Users/<u>/x 与 C:\Users\<u>\x 同键）；
  //   5. 折叠尾部斜杠与 ./ 前缀。
  // 运维提示类发现（扫描截断/报告超限/策略重载失败等）不是"可处置的代码资产"——
  // 它们是扫描器自身的运行状态上报，加白它们毫无意义（用户质疑"加白 /users 是不是
  // 全加白了"）。运维类永远不产出资产键；目录级粗路径（/users、~、盘符根）同理跳过。
  const OPS_KINDS = new Set([
    'project_scan_truncated', 'skill_scan_truncated', 'findings_truncated',
    'inventory_truncated', 'oversized_file_skipped', 'policy_reload_failed',
    'user_level_deprecated', 'unreadable', 'agent_baseline_not_loaded',
  ]);
  if (path) {
    if (OPS_KINDS.has(kind)) return null;
    const key = normalizePathKey(path);
    // 目录级粗键（无文件名）：加白 = 整个目录树静默，永远不该出现这种处置项。
    if (!key || key === '~' || key === '/' || /^[a-z]:$/.test(key) || key === '/users' || key === '/home') return null;
    // 文档/日志类不是代码资产（2026-09-25 用户质疑"MD 明显不是代码路径"）：AGENTS.md/
    // references/*.md/log 是文档与运行日志，代码质量规则按字面匹配它们只会产误报；
    // 把它们当"代码路径"加白毫无意义。SKILL.md 的资产身份是 skill（上文已处理）。
    // 二进制/图片类同样不可代码处置（旧终端把它们当文本读出乱码后偶发误报）。
    // 正向白名单：只接受真代码/配置扩展——新文件类型默认不产资产(保守, 防再犯)。
    const CODE_EXT = /\.(py|js|mjs|cjs|ts|tsx|jsx|mts|cts|go|java|rb|php|sh|bash|zsh|fish|ps1|psm1|bat|cmd|json|jsonc|toml|yaml|yml|ini|cfg|conf|env|sql|html|htm|css|scss|vue|svelte|rs|c|h|cpp|hpp|cs|kt|swift|dart|scala|pl|lua|r|m|mm)$/i;
    if (!CODE_EXT.test(key)) return null;
    // Aegis 自身文件（2026-09-25 用户再次抓到"新工单仍显示 aegis_agent.py"）：终端侧已
    // 自免扫描（新报告不再产出），但**旧报告/离线设备的最新报告**仍被 /api/findings 聚合，
    // 控制台侧必须同样排除——.aegis-agent/、/Library/Application Support/AegisAgent/、
    // ProgramData\AegisAgent\ 等 Aegis 安装位置的发现不是"可处置的第三方代码"。
    if (/(^|\/)\.aegis-agent\//i.test(path) || /\/aegisagent\//i.test(path) || /(^|\/)aegis-agent\//i.test(path)) return null;
    return { asset_type: 'path', asset_key: key };
  }
  return null;
}



/** 该 finding 是否命中加白资产（应被抑制/自动消除）。 */
export function isFindingAllowed(f: FindingLike, allowed: Set<string>): boolean {
  if (globals.__aegis_label_uncertain) return false;
  const a = findingAsset(f);
  if (a === null) return false;
  const assetKey = mapKey(a.asset_type, a.asset_key);
  // Always consult the current deny decision, including when a caller retains
  // an allow snapshot from before the asset was denied.
  if (store().get(assetKey)?.disposition === 'deny') return false;
  let matchedAllow = allowed.has(assetKey);
  if (a.asset_type === 'skill' || a.asset_type === 'mcp') {
    const source = store().get(assetKey)?.decision_source ?? 'legacy';
    // Catalog admission and ambiguous historical rows cannot grant an exception
    // for arbitrary new behavioral findings. Editable tags never confer provenance.
    const admissionKind = a.asset_type === 'skill' ? 'unknown_skill' : 'unknown_mcp';
    return matchedAllow && (source === 'manual' || f.kind === admissionKind);
  }
  // 目录前缀批量忽略：path 资产逐级匹配 allow 的 prefix 条目（"~/.codex/.tmp/" 覆盖
  // 其下全部文件）。前缀键在 setLabel 时已归一化并强制尾斜杠（防 "~/.codex" 误吞
  // "~/.codex-config.json" 这类同前缀不同目录的兄弟路径）。
  if (a.asset_type !== 'path') return matchedAllow;
  // 逐级向上：先剥掉文件名与尾斜杠再找上一层（保留尾斜杠时 slice(0, i+1) 会得到
  // 自身 → 死循环，真机教训：3 个 node 进程 85% CPU 转了几分钟）。
  let dir = a.asset_key;
  for (;;) {
    const cut = dir.endsWith('/') ? dir.slice(0, -1) : dir;
    const i = cut.lastIndexOf('/');
    if (i <= 0) return matchedAllow;
    dir = cut.slice(0, i + 1);
    // A broad or narrow deny wins regardless of where an allow was found.
    // Continue to the outermost applicable directory before suppressing.
    if (store().get(`prefix:${dir}`)?.disposition === 'deny') return false;
    if (allowed.has(`prefix:${dir}`)) matchedAllow = true;
  }
}

/** 归一化目录前缀键：~折叠/小写/反斜杠统一/强制尾斜杠。非目录形态原样返回 null。 */
export function normalizePrefixKey(raw: string): string | null {
  const k = normalizePathKey(raw.trim());
  if (!k || k === '~' || k === '/' || /^[a-z]:$/.test(k) || k === '/users' || k === '/home') return null;
  // 必须是目录形态：输入以 / 或 \ 结尾（用户从"忽略此目录"入口传入的天然带尾斜杠）；
  // 不带尾斜杠的裸文件路径不视为前缀。
  if (!/[\\/]$/.test(raw.trim())) return null;
  return k.endsWith('/') ? k : k + '/';
}

export interface SetLabelInput {
  asset_type: AssetType;
  asset_key: string;
  tags?: string[];
  disposition?: Disposition;
  /** Set only by trusted writers, never accepted from an API request body. */
  decision_source?: DecisionSource;
  note?: string;
  updated_by: string;
}

/** Volatile-mode/test setup only. Production writers must use the commit APIs. */
export function setLabelInMemory(input: SetLabelInput): AssetLabel {
  const m = store();
  const k = mapKey(input.asset_type, input.asset_key);
  const prev = m.get(k);
  const rec: AssetLabel = {
    asset_type: input.asset_type,
    asset_key: input.asset_key,
    tags: input.tags ?? prev?.tags ?? [],
    disposition: input.disposition ?? prev?.disposition ?? '',
    decision_source: input.decision_source ?? (input.disposition !== undefined ? 'manual' : prev?.decision_source ?? 'legacy'),
    note: input.note ?? prev?.note ?? '',
    updated_by: input.updated_by,
    updated_at: Date.now(),
  };
  m.set(k, rec);
  markLocalMutation(k);
  return rec;
}

/** Serialize request-time mutations within this process; PostgreSQL remains authoritative. */
function serializeMutation<T>(operation: () => Promise<T>): Promise<T> {
  const pending = (globals.__aegis_label_write_tail ?? Promise.resolve()).then(operation);
  globals.__aegis_label_write_tail = pending.then(() => undefined, () => undefined);
  return pending;
}

function invalidateUnconfirmedState(): void {
  globals.__aegis_label_uncertain = true;
  globals.__aegis_label_epoch = (globals.__aegis_label_epoch ?? 0) + 1;
  loadPromise = null;
}

/** Publish only acknowledged rows into memory. Missing acknowledgement may mean
 * COMMIT succeeded: invalidate the snapshot and do not claim the write rolled back. */
export function persistLabelsDurable(
  inputs: SetLabelInput[], options: { onlyUndecided?: boolean } = {},
): Promise<AssetLabel[]> {
  return serializeMutation(async () => {
    await ensureLabelsLoaded();
    if (!inputs.length) return [];
    if (!pgEnabled()) {
      // Explicit volatile development mode; never claimed to survive a restart.
      const saved: AssetLabel[] = [];
      for (const input of inputs) {
        if (options.onlyUndecided && store().get(mapKey(input.asset_type, input.asset_key))?.disposition) continue;
        saved.push(setLabelInMemory(input));
      }
      return saved;
    }
    try {
      const result = await pgApplyLabelChanges(inputs.map(input => ({
        ...input, tags: input.tags === undefined ? undefined : JSON.stringify(input.tags), updated_at: Date.now(),
      })), options.onlyUndecided === true);
      const records = result.labels.map(rowToLabel); // validate the complete result first
      const applied = new Set(result.appliedKeys);
      for (const record of records) {
        const key = mapKey(record.asset_type, record.asset_key);
        store().set(key, record);
        markLocalMutation(key);
      }
      return records.filter(record => applied.has(mapKey(record.asset_type, record.asset_key)));
    } catch {
      invalidateUnconfirmedState();
      throw new Error('labels_write_unconfirmed');
    }
  });
}

export async function setLabel(input: SetLabelInput): Promise<AssetLabel> {
  return (await persistLabelsDurable([input]))[0];
}

/** Delete from the database even if the process cache does not contain the key. */
export function removeLabel(assetType: AssetType, assetKey: string): Promise<boolean> {
  return serializeMutation(async () => {
    const key = mapKey(assetType, assetKey);
    try {
      const removed = pgEnabled() ? await pgDeleteLabel(assetType, assetKey) : store().has(key);
      store().delete(key);
      markLocalMutation(key);
      return removed;
    } catch {
      invalidateUnconfirmedState();
      throw new Error('labels_write_unconfirmed');
    }
  });
}
