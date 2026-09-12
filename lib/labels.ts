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
import {
  pgEnabled,
  pgLoadLabels,
  pgUpsertLabel,
  pgDeleteLabel,
  type AssetLabelRow,
} from './pg-store';

export type AssetType = 'skill' | 'mcp';
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

export interface SetLabelInput {
  asset_type: AssetType;
  asset_key: string;
  tags?: string[];
  disposition?: Disposition;
  note?: string;
  updated_by: string;
}

/** 设置/更新某资产的标签与处置；写穿透到 PG。 */
export function setLabel(input: SetLabelInput): AssetLabel {
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

/** 移除某资产的标签/处置记录；写穿透到 PG。 */
export function removeLabel(assetType: AssetType, assetKey: string): boolean {
  const m = store();
  const ok = m.delete(mapKey(assetType, assetKey));
  if (ok) pgDeleteLabel(assetType, assetKey);
  return ok;
}
