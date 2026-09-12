/**
 * lib/baselines.ts — 阶段E: 自定义安全编码基线 + 上游同步 + 扫描模式。
 *
 * - 基线分两类: source='custom'(用户导入, 优先) / source='upstream'(定时从上游拉取)。
 * - 生效规则 = upstream + custom 合并, 同 id 时 custom 覆盖 upstream。
 * - 扫描模式 scan_mode: quick | standard | deep | custom (全局设置, 存 settings 表)。
 * - 持久化: PostgreSQL (lib/pg-store), 请求期懒加载 (workerd 全局作用域禁异步 I/O)。
 */
import {
  pgEnabled,
  pgLoadBaselines,
  pgUpsertBaseline,
  pgDeleteBaseline,
  pgGetSettings,
  pgSetSetting,
  type BaselineRow,
} from './pg-store';

export type ScanMode = 'quick' | 'standard' | 'deep' | 'custom';
export const SCAN_MODES: ScanMode[] = ['quick', 'standard', 'deep', 'custom'];
export const DEFAULT_SCAN_MODE: ScanMode = 'standard';

export interface BaselineRule {
  id: string;
  title: string;
  severity?: string;
  mode?: ScanMode | 'all';
  [k: string]: unknown;
}

export interface Baseline {
  name: string;
  source: 'custom' | 'upstream';
  version: string;
  rules: BaselineRule[];
  scan_modes: ScanMode[];
  updated_by: string;
  updated_at: number;
}

const globals = globalThis as typeof globalThis & {
  __aegis_baselines?: Map<string, Baseline>;
  __aegis_settings?: Record<string, string>;
};

function baselines(): Map<string, Baseline> {
  if (!globals.__aegis_baselines) globals.__aegis_baselines = new Map();
  return globals.__aegis_baselines;
}
function settings(): Record<string, string> {
  if (!globals.__aegis_settings) globals.__aegis_settings = { scan_mode: DEFAULT_SCAN_MODE };
  return globals.__aegis_settings;
}

function rowToBaseline(r: BaselineRow): Baseline {
  let rules: BaselineRule[] = [];
  let modes: ScanMode[] = ['standard'];
  try { rules = JSON.parse(r.rules_json || '[]'); } catch { rules = []; }
  try { modes = JSON.parse(r.scan_modes || '["standard"]'); } catch { modes = ['standard']; }
  return { name: r.name, source: r.source === 'upstream' ? 'upstream' : 'custom', version: r.version, rules, scan_modes: modes, updated_by: r.updated_by, updated_at: Number(r.updated_at || 0) };
}

let loadPromise: Promise<void> | null = null;
/** 请求期懒加载基线+设置 (每 isolate 一次)。 */
export function ensureBaselinesLoaded(): Promise<void> {
  if (!pgEnabled()) return Promise.resolve();
  if (!loadPromise) {
    loadPromise = (async () => {
      const [rows, st] = await Promise.all([pgLoadBaselines(), pgGetSettings()]);
      if (rows) for (const r of rows) baselines().set(r.name, rowToBaseline(r));
      if (st) Object.assign(settings(), st);
    })();
  }
  return loadPromise;
}

export function listBaselines(): Baseline[] {
  return [...baselines().values()].sort((a, b) => a.name.localeCompare(b.name));
}

function persist(b: Baseline): void {
  pgUpsertBaseline({ name: b.name, source: b.source, version: b.version, rules_json: JSON.stringify(b.rules), scan_modes: JSON.stringify(b.scan_modes), updated_by: b.updated_by, updated_at: b.updated_at });
}

/** 导入/更新自定义基线。 */
export function importBaseline(input: { name: string; rules: BaselineRule[]; scan_modes?: ScanMode[]; version?: string; updated_by: string }): Baseline {
  const b: Baseline = {
    name: input.name,
    source: 'custom',
    version: input.version ?? '1.0.0',
    rules: input.rules,
    scan_modes: input.scan_modes ?? ['standard'],
    updated_by: input.updated_by,
    updated_at: Date.now(),
  };
  baselines().set(b.name, b);
  persist(b);
  return b;
}

/** 上游同步: 拉取上游基线文本存为 source=upstream; custom 不受影响(合并时优先)。 */
export async function syncUpstream(url: string, updatedBy: string): Promise<Baseline> {
  const resp = await fetch(url, { cache: 'no-store' });
  if (!resp.ok) throw new Error(`upstream_fetch_failed:${resp.status}`);
  const text = await resp.text();
  const b: Baseline = {
    name: 'upstream-baseline',
    source: 'upstream',
    version: String(new Date().toISOString().slice(0, 10)),
    rules: [{ id: 'upstream-text', title: '上游基线全文', mode: 'all', content: text.slice(0, 200000) } as BaselineRule],
    scan_modes: ['quick', 'standard', 'deep'],
    updated_by: updatedBy,
    updated_at: Date.now(),
  };
  baselines().set(b.name, b);
  persist(b);
  return b;
}

export function deleteBaseline(name: string): boolean {
  const ok = baselines().delete(name);
  if (ok) pgDeleteBaseline(name);
  return ok;
}

/** 生效规则 = upstream + custom 合并 (同 id custom 覆盖)。 */
export function effectiveRules(): BaselineRule[] {
  const byId = new Map<string, BaselineRule>();
  for (const b of listBaselines()) {
    if (b.source === 'upstream') for (const r of b.rules) byId.set(r.id, r);
  }
  for (const b of listBaselines()) {
    if (b.source === 'custom') for (const r of b.rules) byId.set(r.id, r);
  }
  return [...byId.values()];
}

export function getScanMode(): ScanMode {
  const v = settings().scan_mode as ScanMode;
  return SCAN_MODES.includes(v) ? v : DEFAULT_SCAN_MODE;
}

export function getSetting(key: string): string {
  return settings()[key] ?? '';
}

export function setSetting(key: string, value: string, updatedBy: string): void {
  settings()[key] = value;
  pgSetSetting(key, value);
  void updatedBy;
}

/* ─── 上游基线定时同步(阶段E 收尾) ───────────────────────────────────────
 * settings['upstream_baseline_url'] 有值时, 每 6 小时拉取上游基线存为
 * source=upstream; 自定义基线不受影响(合并时自定义优先)。每 isolate 只起一个定时器。 */
const UPSTREAM_SYNC_INTERVAL_MS = 6 * 60 * 60 * 1000;
let syncLoopStarted = false;

export function startUpstreamSyncLoop(): void {
  if (syncLoopStarted) return;
  syncLoopStarted = true;
  const tick = () => {
    const url = getSetting('upstream_baseline_url');
    if (url) syncUpstream(url, 'upstream-sync').catch(() => {});
  };
  setInterval(tick, UPSTREAM_SYNC_INTERVAL_MS);
}

export function setScanMode(mode: ScanMode, updatedBy: string): boolean {
  if (!SCAN_MODES.includes(mode)) return false;
  settings().scan_mode = mode;
  pgSetSetting('scan_mode', mode);
  void updatedBy;
  return true;
}
