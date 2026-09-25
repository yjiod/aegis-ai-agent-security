/**
 * lib/labels.ts — 资产标签与处置注册表（skill / MCP 打标 + 加白/观察/拉黑）。
 *
 * 内存 Map（globalThis 跨模块重载存活）+ PostgreSQL 写穿透（lib/pg-store）。
 * 水合为请求期懒加载（ensureLabelsLoaded），遵循 workerd 全局作用域禁异步 I/O 约束。
 *
 * disposition 语义：
 *   ''       未处置
 *   'allow'  加白：加入允许名单，不再告警（仍记调用审计）
 *   'monitor'观察：不阻断，持续上报行为供复查
 *   'deny'   拉黑：加入阻断名单，终端拦截并告警
 */
import { normalizePathKey } from './path-key';
import {
  pgEnabled,
  pgLoadLabels,
  pgUpsertLabel,
  pgUpsertLabelsBatch,
  pgDeleteLabel,
  type AssetLabelRow,
} from './pg-store';

export type AssetType = 'skill' | 'mcp' | 'path' | 'prefix';
/** prefix = 目录前缀批量忽略（2026-09-25 用户需求）：asset_key 形如 "~/.codex/.tmp/"，
 * 抑制所有归一化后落在该前缀下的 path 资产发现。只作用于 path 类（skill/mcp 名
 * 与目录无关，不做前缀展开，防止意外封禁面扩大）。 */
export type Disposition = '' | 'allow' | 'monitor' | 'deny';

export const DISPOSITIONS: Disposition[] = ['', 'allow', 'monitor', 'deny'];

export interface AssetLabel {
  asset_type: AssetType;
  asset_key: string;
  tags: string[];
  disposition: Disposition;
  note: string;
  updated_by: string;
  updated_at: number;
}

const globals = globalThis as typeof globalThis & { __aegis_labels?: Map<string, AssetLabel> };

function store(): Map<string, AssetLabel> {
  if (!globals.__aegis_labels) globals.__aegis_labels = new Map();
  return globals.__aegis_labels;
}

const mapKey = (t: string, k: string) => `${t}:${k}`;

function rowToLabel(r: AssetLabelRow): AssetLabel {
  let tags: string[] = [];
  try {
    const parsed = JSON.parse(r.tags || '[]');
    if (Array.isArray(parsed)) tags = parsed.filter((x) => typeof x === 'string');
  } catch {
    tags = [];
  }
  const disposition = (DISPOSITIONS as string[]).includes(r.disposition) ? (r.disposition as Disposition) : '';
  return {
    asset_type: r.asset_type === 'mcp' ? 'mcp' : 'skill',
    asset_key: r.asset_key,
    tags,
    disposition,
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
    loadPromise = (async () => {
      const rows = await pgLoadLabels();
      if (!rows) return;
      const m = store();
      for (const r of rows) m.set(mapKey(r.asset_type, r.asset_key), rowToLabel(r));
    })();
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
  // 归一化（绝对要求 #5, 2026-09-24）：同分类+同实际片段视为同一资产——事件 ID/行号/盘符
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
    if (!CODE_EXT.test(path)) return null;
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
  const a = findingAsset(f);
  if (a === null) return false;
  if (allowed.has(mapKey(a.asset_type, a.asset_key))) return true;
  // 目录前缀批量忽略：path 资产逐级匹配 allow 的 prefix 条目（"~/.codex/.tmp/" 覆盖
  // 其下全部文件）。前缀键在 setLabel 时已归一化并强制尾斜杠（防 "~/.codex" 误吞
  // "~/.codex-config.json" 这类同前缀不同目录的兄弟路径）。
  if (a.asset_type !== 'path') return false;
  // 逐级向上：先剥掉文件名与尾斜杠再找上一层（保留尾斜杠时 slice(0, i+1) 会得到
  // 自身 → 死循环，真机教训：3 个 node 进程 85% CPU 转了几分钟）。
  let dir = a.asset_key;
  for (;;) {
    const cut = dir.endsWith('/') ? dir.slice(0, -1) : dir;
    const i = cut.lastIndexOf('/');
    if (i <= 0) return false;
    dir = cut.slice(0, i + 1);
    if (allowed.has(`prefix:${dir}`)) return true;
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
  note?: string;
  updated_by: string;
}

/** 构造标签记录并写入内存（不触发 PG 调度写；供批量持久化路径收集）。 */
export function setLabelInMemory(input: SetLabelInput): AssetLabel {
  const m = store();
  const k = mapKey(input.asset_type, input.asset_key);
  const prev = m.get(k);
  const rec: AssetLabel = {
    asset_type: input.asset_type,
    asset_key: input.asset_key,
    tags: input.tags ?? prev?.tags ?? [],
    disposition: input.disposition ?? prev?.disposition ?? '',
    note: input.note ?? prev?.note ?? '',
    updated_by: input.updated_by,
    updated_at: Date.now(),
  };
  m.set(k, rec);
  return rec;
}

/** 设置/更新某资产的标签与处置；写穿透到 PG。 */
export function setLabel(input: SetLabelInput): AssetLabel {
  const rec = setLabelInMemory(input);
  pgUpsertLabel({
    asset_type: rec.asset_type,
    asset_key: rec.asset_key,
    tags: JSON.stringify(rec.tags),
    disposition: rec.disposition,
    note: rec.note,
    updated_by: rec.updated_by,
    updated_at: rec.updated_at,
  });
  return rec;
}

/**
 * 批量持久化标签（可等待、单事务，失败抛错）。种子/自动纠偏等"发布前置数据"
 * 必须走本函数（生产事故 2026-09-25：fire-and-forget 批量写静默丢 291 条，
 * 导致签名策略 v37 的 allowed 名单误瘦身；详见 pgUpsertLabelsBatch 注释）。
 */
export async function persistLabelsDurable(labels: AssetLabel[]): Promise<number> {
  if (labels.length === 0) return 0;
  if (!pgEnabled()) return labels.length; // 非 PG 模式（dev/文件存储）无持久化需求
  return pgUpsertLabelsBatch(
    labels.map((rec) => ({
      asset_type: rec.asset_type,
      asset_key: rec.asset_key,
      tags: JSON.stringify(rec.tags),
      disposition: rec.disposition,
      note: rec.note,
      updated_by: rec.updated_by,
      updated_at: rec.updated_at,
    })),
  );
}

/** 移除某资产的标签/处置记录；写穿透到 PG。 */
export function removeLabel(assetType: AssetType, assetKey: string): boolean {
  const m = store();
  const ok = m.delete(mapKey(assetType, assetKey));
  if (ok) pgDeleteLabel(assetType, assetKey);
  return ok;
}
