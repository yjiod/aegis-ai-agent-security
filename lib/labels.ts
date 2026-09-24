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

export type AssetType = 'skill' | 'mcp' | 'path';
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
  if (path) return { asset_type: 'path', asset_key: normalizePathKey(path) };
  return null;
}



/** 该 finding 是否命中加白资产（应被抑制/自动消除）。 */
export function isFindingAllowed(f: FindingLike, allowed: Set<string>): boolean {
  const a = findingAsset(f);
  return a !== null && allowed.has(mapKey(a.asset_type, a.asset_key));
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
