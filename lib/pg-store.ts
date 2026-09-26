/**
 * lib/pg-store.ts — PostgreSQL persistence for console state (VPS deployment).
 *
 * Alternative to Cloudflare D1: when AEGIS_PG_URL is set, console state
 * (devices overlay / tickets / ticket_history / audit_log / admins) is loaded
 * from Postgres and written through on every mutation. Without AEGIS_PG_URL the
 * console falls back to in-memory + file store.
 *
 * WORKERD CONSTRAINTS (learned the hard way, see comments below):
 *  1. No async I/O at module/global scope — `pg` is imported lazily and every
 *     connect/query happens inside a request handler (or an after() task).
 *  2. The `pg` connection POOL leaks under workerd: its keep-alive socket reuse
 *     depends on node:net lifecycle events workerd's shim does not reliably
 *     emit, so pooled connections are never released and the pool exhausts
 *     (queries then time out / hang). We therefore use a FRESH short-lived
 *     Client per operation (connect -> query -> end). PG is on localhost, so the
 *     extra connect cost is a few ms and correctness wins.
 *  3. Post-response writes must be registered with the runtime or workerd drops
 *     them — write-through is scheduled via Next's after() (vinext wires it to
 *     ctx.waitUntil).
 *
 * Every failure degrades gracefully to the file/in-memory store and is surfaced
 * by pgProbe()/pgStatus() so a silent PG outage never masquerades as durability.
 *
 * Schema: migrations/0002_postgres.sql
 */
import type { Client } from 'pg';
import { after } from 'next/server';
import type { Device, Ticket, AuditEntry } from './store';

type PgClientCtor = new (config: unknown) => Client;
let pgClientPromise: Promise<PgClientCtor | null> | null = null;

export function pgEnabled(): boolean {
  return Boolean(process.env.AEGIS_PG_URL);
}

/** Lazily import `pg` and return its Client constructor (null on failure). */
function loadPgClient(): Promise<PgClientCtor | null> {
  if (!pgClientPromise) {
    pgClientPromise = (async () => {
      try {
        const pg = await import('pg');
        const mod = pg as unknown as { Client?: PgClientCtor; default?: { Client?: PgClientCtor } };
        return mod.Client ?? mod.default?.Client ?? null;
      } catch {
        return null;
      }
    })();
  }
  return pgClientPromise;
}

type PgResult<T> = { ok: true; value: T } | { ok: false; error: string };

const CLIENT_CONFIG = {
  connectionString: () => process.env.AEGIS_PG_URL,
  connectionTimeoutMillis: 5000,
  statement_timeout: 10000,
  query_timeout: 10000,
};

/**
 * Run `fn` against a fresh, short-lived Client. Always ends the client so the
 * socket is closed (no pool, no reuse, no leak). Returns a discriminated result
 * so callers can surface the real error. Must be called in request/after scope.
 */
async function withClient<T>(label: string, fn: (client: Client) => Promise<T>): Promise<PgResult<T>> {
  if (!pgEnabled()) return { ok: false, error: 'not_configured' };
  const Ctor = await loadPgClient();
  if (!Ctor) return { ok: false, error: 'pg_driver_unavailable' };
  let client: Client | null = null;
  try {
    client = new Ctor({ ...CLIENT_CONFIG, connectionString: CLIENT_CONFIG.connectionString() });
    await client.connect();
    const value = await fn(client);
    return { ok: true, value };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    if (['loadLabels', 'applyLabels', 'deleteLabel'].includes(label)) console.error(`[pg] ${label} failed`);
    else console.error(`[pg] ${label} failed:`, msg);
    return { ok: false, error: msg };
  } finally {
    if (client) {
      try { await client.end(); } catch { /* ignore close errors */ }
    }
  }
}

/**
 * Live reachability probe ("SELECT 1"). Used by pgStatus() so operators can tell
 * whether PG is actually backing the console. Never throws, never hangs (bounded
 * by connectionTimeoutMillis/query_timeout).
 */
export async function pgProbe(): Promise<{ ok: boolean; error?: string }> {
  const r = await withClient('probe', (c) => c.query('SELECT 1'));
  return r.ok ? { ok: true } : { ok: false, error: r.error };
}

/** Load all console state from PG (called once per isolate, in request scope). */
export async function pgLoadAll(): Promise<{
  devices: [string, Device][];
  tickets: [string, Ticket][];
  audit: AuditEntry[];
  admins: string[];
  auditors: string[];
} | null> {
  const r = await withClient('loadAll', async (c) => {
    // Sequential queries on one connection.
    const d = await c.query('SELECT * FROM devices');
    const t = await c.query('SELECT * FROM tickets ORDER BY created_at');
    const h = await c.query('SELECT * FROM ticket_history ORDER BY id');
    // P2(30k)：审计有界加载——旧版 SELECT * 整表入内存，规模上来后 hydrate 即爆内存。
    // 只取最近 5000 条（DESC 取再反转为升序，保持既有顺序语义）；更旧审计仍在 PG，可按需分页查。
    const a = await c.query('SELECT * FROM audit_log ORDER BY id DESC LIMIT 5000');
    const ad = await c.query('SELECT employee_no FROM admins');
    const au = await c.query('SELECT employee_no FROM auditors');

    const devices: [string, Device][] = d.rows.map((row) => [
      row.device_id,
      {
        device_id: row.device_id, hostname: row.hostname ?? '', owner: row.owner ?? '',
        agent_type: row.agent_type ?? 'other', agent_version: row.agent_version ?? '0.0.0',
        policy_version: row.policy_version ?? '0.0.0', status: row.status ?? 'offline',
        last_seen: Number(row.last_seen ?? 0), registered_at: Number(row.registered_at ?? 0),
        findings_summary: row.findings ?? { critical: 0, high: 0, medium: 0, low: 0 },
      } as Device,
    ]);
    const histByTicket = new Map<string, Array<{ action: string; actor: string; timestamp: number; note?: string }>>();
    for (const row of h.rows) {
      const arr = histByTicket.get(row.ticket_id) ?? [];
      arr.push({ action: row.action, actor: row.actor ?? '', timestamp: Number(row.ts ?? 0), ...(row.note ? { note: row.note } : {}) });
      histByTicket.set(row.ticket_id, arr);
    }
    const tickets: [string, Ticket][] = t.rows.map((row) => [
      row.ticket_id,
      {
        ticket_id: row.ticket_id, title: row.title, severity: row.severity, status: row.status,
        source: row.source ?? '', device_id: row.device_id ?? '', description: row.description ?? undefined,
        finding_ref: row.finding_ref ?? undefined, assignee: row.assignee ?? undefined,
        created_at: Number(row.created_at ?? 0), updated_at: Number(row.updated_at ?? 0),
        resolved_at: row.resolved_at ? Number(row.resolved_at) : undefined,
        history: histByTicket.get(row.ticket_id) ?? [],
      } as Ticket,
    ]);
    const audit: AuditEntry[] = a.rows.slice().reverse().map((row) => ({
      id: Number(row.id), timestamp: Number(row.ts ?? 0), actor: row.actor ?? '',
      action: row.action, resource_type: row.resource_type,
      ...(row.resource_id ? { resource_id: row.resource_id } : {}),
      ...(row.detail ? { detail: row.detail } : {}),
    })) as AuditEntry[];
    const admins: string[] = ad.rows.map((row) => row.employee_no);
    const auditors: string[] = au.rows.map((row) => row.employee_no);
    return { devices, tickets, audit, admins, auditors };
  });
  return r.ok ? r.value : null;
}

/**
 * Schedule a best-effort PG write that survives the response boundary. after()
 * (vinext -> ctx.waitUntil) keeps the isolate alive to settle it; each write uses
 * its own fresh Client. Errors are logged and swallowed so a PG outage can never
 * break a console mutation (in-memory + file remain authoritative).
 */
function scheduleWrite(label: string, fn: (client: Client) => Promise<unknown>): void {
  if (!pgEnabled()) return;
  const task = () => withClient(label, fn).then(() => undefined);
  try {
    after(task);
  } catch {
    void task();
  }
}

/** Write-through helpers. */
export function pgUpsertDevice(d: Device): void {
  scheduleWrite('upsertDevice', (c) =>
    c.query(
      `INSERT INTO devices(device_id,hostname,owner,agent_type,agent_version,policy_version,status,last_seen,registered_at,findings)
       VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
       ON CONFLICT(device_id) DO UPDATE SET hostname=$2,owner=$3,agent_type=$4,agent_version=$5,policy_version=$6,status=$7,last_seen=$8,registered_at=$9,findings=$10`,
      [d.device_id, d.hostname, d.owner, d.agent_type, d.agent_version, d.policy_version, d.status, d.last_seen, d.registered_at, JSON.stringify(d.findings_summary ?? {})],
    ),
  );
}

export function pgDeleteDevice(deviceId: string): void {
  scheduleWrite('deleteDevice', (c) => c.query('DELETE FROM devices WHERE device_id=$1', [deviceId]));
}

export function pgUpsertTicket(t: Ticket): void {
  // 单连接 + 单事务写入工单及其历史：避免「每条历史开一个新连接」导致的连接风暴
  // (too many clients already)，并用「先删后插」保证历史幂等，杜绝重复累积。
  const history = t.history ?? [];
  scheduleWrite('upsertTicket', async (c) => {
    try {
      await c.query('BEGIN');
      await c.query(
        `INSERT INTO tickets(ticket_id,title,severity,status,source,device_id,description,finding_ref,assignee,created_at,updated_at,resolved_at)
         VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
         ON CONFLICT(ticket_id) DO UPDATE SET title=$2,severity=$3,status=$4,source=$5,device_id=$6,description=$7,finding_ref=$8,assignee=$9,updated_at=$11,resolved_at=$12`,
        [t.ticket_id, t.title, t.severity, t.status, t.source, t.device_id, t.description ?? null, t.finding_ref ?? null, t.assignee ?? null, t.created_at, t.updated_at, t.resolved_at ?? null],
      );
      await c.query('DELETE FROM ticket_history WHERE ticket_id=$1', [t.ticket_id]);
      for (const hEntry of history) {
        await c.query(
          'INSERT INTO ticket_history(ticket_id,action,actor,ts,note) VALUES($1,$2,$3,$4,$5)',
          [t.ticket_id, hEntry.action, hEntry.actor, hEntry.timestamp, hEntry.note ?? null],
        );
      }
      await c.query('COMMIT');
    } catch (err) {
      try { await c.query('ROLLBACK'); } catch { /* ignore rollback failure */ }
      throw err;
    }
  });
}

export function pgInsertAudit(a: AuditEntry): void {
  scheduleWrite('insertAudit', (c) =>
    c.query('INSERT INTO audit_log(ts,actor,action,resource_type,resource_id,detail) VALUES($1,$2,$3,$4,$5,$6)', [a.timestamp, a.actor, a.action, a.resource_type, a.resource_id ?? null, a.detail ?? null]),
  );
}

export function pgAddAdmin(emp: string): void {
  scheduleWrite('addAdmin', (c) => c.query('INSERT INTO admins(employee_no) VALUES($1) ON CONFLICT DO NOTHING', [emp]));
}

export function pgRemoveAdmin(emp: string): void {
  scheduleWrite('removeAdmin', (c) => c.query('DELETE FROM admins WHERE employee_no=$1', [emp]));
}

export function pgAddAuditor(emp: string): void {
  scheduleWrite('addAuditor', (c) => c.query('INSERT INTO auditors(employee_no) VALUES($1) ON CONFLICT DO NOTHING', [emp]));
}

export function pgRemoveAuditor(emp: string): void {
  scheduleWrite('removeAuditor', (c) => c.query('DELETE FROM auditors WHERE employee_no=$1', [emp]));
}

/* ─── 资产标签 / 处置（skill / MCP 打标 + 加白/观察/拉黑） ─────────────── */
export interface AssetLabelRow {
  asset_type: string;
  asset_key: string;
  tags: string; // JSON array string
  disposition: string; // '' | allow | monitor | deny
  decision_source?: string; // manual | preset | automatic | legacy
  note: string;
  updated_by: string;
  updated_at: number;
}

export async function pgLoadLabels(): Promise<AssetLabelRow[] | null> {
  const r = await withClient('loadLabels', (c) =>
    c.query('SELECT asset_type,asset_key,tags,disposition,note,updated_by,updated_at,decision_source FROM asset_labels ORDER BY asset_type, asset_key'),
  );
  return r.ok ? (r.value.rows as AssetLabelRow[]) : null;
}

export interface AssetLabelPatchRow {
  asset_type: string;
  asset_key: string;
  tags?: string;
  disposition?: string;
  note?: string;
  decision_source?: string;
  updated_by: string;
  updated_at: number;
}

/** Merge patches against authoritative rows, atomically. Conditional writers may
 * fill undecided entries only; this predicate is enforced inside PostgreSQL. */
export async function pgApplyLabelChanges(
  patches: AssetLabelPatchRow[], onlyUndecided = false,
): Promise<{ labels: AssetLabelRow[]; appliedKeys: string[] }> {
  if (!patches.length) return { labels: [], appliedKeys: [] };
  const ordered = [...new Map(patches.map(p => [`${p.asset_type}:${p.asset_key}`, p])).entries()]
    .sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0);
  const r = await withClient('applyLabels', async c => {
    const labels: AssetLabelRow[] = [];
    const appliedKeys: string[] = [];
    try {
      await c.query('BEGIN');
      for (const [key, row] of ordered) {
        const result = await c.query(
          `INSERT INTO asset_labels(asset_type,asset_key,tags,disposition,note,updated_by,updated_at,decision_source)
           VALUES($1,$2,COALESCE($3,'[]'),COALESCE($4,''),COALESCE($5,''),$6,$7,
             COALESCE($8,CASE WHEN $4::text IS NULL THEN 'legacy' ELSE 'manual' END))
           ON CONFLICT(asset_type,asset_key) DO UPDATE SET
             tags=COALESCE($3,asset_labels.tags), disposition=COALESCE($4,asset_labels.disposition),
             note=COALESCE($5,asset_labels.note), updated_by=$6, updated_at=$7,
             decision_source=CASE WHEN $4::text IS NULL THEN asset_labels.decision_source
               ELSE COALESCE($8,'manual') END
           WHERE NOT $9::boolean OR asset_labels.disposition=''
           RETURNING asset_type,asset_key,tags,disposition,note,updated_by,updated_at,decision_source`,
          [row.asset_type, row.asset_key, row.tags ?? null, row.disposition ?? null, row.note ?? null,
            row.updated_by, row.updated_at, row.decision_source ?? null, onlyUndecided],
        );
        if (result.rows.length) {
          labels.push(result.rows[0] as AssetLabelRow);
          appliedKeys.push(key);
        } else {
          if (!onlyUndecided) throw new Error('label_write_not_applied');
          // ON CONFLICT holds the row lock even when the predicate rejects it.
          const current = await c.query(
            'SELECT asset_type,asset_key,tags,disposition,note,updated_by,updated_at,decision_source FROM asset_labels WHERE asset_type=$1 AND asset_key=$2',
            [row.asset_type, row.asset_key],
          );
          if (current.rows.length !== 1) throw new Error('label_conflict_unavailable');
          labels.push(current.rows[0] as AssetLabelRow);
        }
      }
      await c.query('COMMIT');
      return { labels, appliedKeys };
    } catch (error) {
      await c.query('ROLLBACK').catch(() => {});
      throw error;
    }
  });
  if (!r.ok) throw new Error('labels_write_unconfirmed');
  return r.value;
}

export async function pgUpsertLabel(row: AssetLabelRow): Promise<void> {
  await pgApplyLabelChanges([row]);
}

export async function pgUpsertLabelsBatch(rows: AssetLabelRow[]): Promise<number> {
  return (await pgApplyLabelChanges(rows)).appliedKeys.length;
}

export async function pgDeleteLabel(assetType: string, assetKey: string): Promise<boolean> {
  const r = await withClient('deleteLabel', c =>
    c.query('DELETE FROM asset_labels WHERE asset_type=$1 AND asset_key=$2', [assetType, assetKey]),
  );
  if (!r.ok) throw new Error('labels_write_unconfirmed');
  return (r.value.rowCount ?? 0) > 0;
}

/* ─── 阶段E: 基线(baselines) + 全局设置(settings) ─────────────────────── */
export interface BaselineRow {
  name: string;
  source: string;
  version: string;
  rules_json: string;
  scan_modes: string;
  updated_by: string;
  updated_at: number;
}

export async function pgLoadBaselines(): Promise<BaselineRow[] | null> {
  const r = await withClient('loadBaselines', (c) =>
    c.query('SELECT name,source,version,rules_json,scan_modes,updated_by,updated_at FROM baselines ORDER BY name'),
  );
  return r.ok ? (r.value.rows as BaselineRow[]) : null;
}

export function pgUpsertBaseline(b: BaselineRow): void {
  scheduleWrite('upsertBaseline', (c) =>
    c.query(
      `INSERT INTO baselines(name,source,version,rules_json,scan_modes,updated_by,updated_at)
       VALUES($1,$2,$3,$4,$5,$6,$7)
       ON CONFLICT(name) DO UPDATE SET source=$2,version=$3,rules_json=$4,scan_modes=$5,updated_by=$6,updated_at=$7`,
      [b.name, b.source, b.version, b.rules_json, b.scan_modes, b.updated_by, b.updated_at],
    ),
  );
}

export function pgDeleteBaseline(name: string): void {
  scheduleWrite('deleteBaseline', (c) => c.query('DELETE FROM baselines WHERE name=$1', [name]));
}

export async function pgGetSettings(): Promise<Record<string, string> | null> {
  const r = await withClient('getSettings', (c) => c.query('SELECT key,value FROM settings'));
  if (!r.ok) return null;
  const out: Record<string, string> = {};
  for (const row of r.value.rows) out[row.key] = row.value;
  return out;
}

export function pgSetSetting(key: string, value: string): void {
  scheduleWrite('setSetting', (c) =>
    c.query('INSERT INTO settings(key,value) VALUES($1,$2) ON CONFLICT(key) DO UPDATE SET value=$2', [key, value]),
  );
}

/* ─── 控制台凭据（改密持久化 · 4A 凭据生命周期）──────────────────────
 * 复用 settings 键值表（无需新迁移），键为 console_password_hash:<subject>，
 * 值为 PBKDF2-SHA256 哈希串。与 pgSetSetting 的 fire-and-forget 不同，这里用
 * withClient 同步确认写入结果——改密必须能如实告知"是否真的持久化"，绝不能
 * 假装成功（红线）。PG 未配置/不可达时返回 null/false，调用方回落到 env 凭据
 * 或如实报错。
 */
const CRED_KEY_PREFIX = 'console_password_hash:';

export async function pgGetCredential(subject: string): Promise<string | null> {
  const r = await withClient('getCredential', (c) =>
    c.query('SELECT value FROM settings WHERE key=$1', [CRED_KEY_PREFIX + subject]),
  );
  if (!r.ok || !r.value?.rows?.length) return null;
  const v = (r.value.rows[0] as { value?: unknown }).value;
  return typeof v === 'string' && v.length > 0 ? v : null;
}

export async function pgSetCredential(subject: string, hash: string): Promise<boolean> {
  const r = await withClient('setCredential', (c) =>
    c.query(
      'INSERT INTO settings(key,value) VALUES($1,$2) ON CONFLICT(key) DO UPDATE SET value=$2',
      [CRED_KEY_PREFIX + subject, hash],
    ),
  );
  return r.ok;
}

/* ─── 会话吊销（4A · 跨设备会话生命周期）────────────────────────────
 * 键 session_invalid_before:<subject> =  epoch ms。凡"签发时间早于该值"的会话
 * 一律失效（改密/移除白名单/管理员显式吊销时写入）。会话为无状态 HMAC Cookie
 * （subject.expiry.sig，expiry=签发+7d），故签发时间可由 expiry-7d 还原，无需改
 * Cookie 格式即可实现吊销。读取走 lib/auth 的 30s TTL 内存缓存（middleware 预热），
 * PG 不可用时缓存保持旧值/空 → fail-open，保可用性不锁死登录。
 */
const REVOKE_KEY_PREFIX = 'session_invalid_before:';

export async function pgGetSessionRevocations(): Promise<Record<string, number> | null> {
  const r = await withClient('getSessionRevocations', (c) =>
    c.query('SELECT key,value FROM settings WHERE key LIKE $1', [REVOKE_KEY_PREFIX + '%']),
  );
  if (!r.ok) return null;
  const out: Record<string, number> = {};
  for (const row of r.value.rows as Array<{ key: string; value: string }>) {
    const subject = row.key.slice(REVOKE_KEY_PREFIX.length);
    const ts = Number(row.value);
    if (subject && Number.isFinite(ts)) out[subject] = ts;
  }
  return out;
}

export async function pgSetSessionRevocation(subject: string, ts: number): Promise<boolean> {
  const r = await withClient('setSessionRevocation', (c) =>
    c.query(
      'INSERT INTO settings(key,value) VALUES($1,$2) ON CONFLICT(key) DO UPDATE SET value=$2',
      [REVOKE_KEY_PREFIX + subject, String(ts)],
    ),
  );
  return r.ok;
}

/* ─── MFA / TOTP 两步验证状态（4A · Authentication）──────────────────
 * 键 mfa:<subject> = JSON {secret, enabled}。secret 为 base32 TOTP 密钥；
 * enabled=false 表示已生成待确认（enroll 后需提交一个有效码才启用），
 * enabled=true 表示登录强制二次验证。默认无记录 = 未启用（不影响既有登录）。
 */
const MFA_KEY_PREFIX = 'mfa:';

export interface MfaRecord {
  secret: string;
  enabled: boolean;
}

export async function pgGetMfa(subject: string): Promise<MfaRecord | null> {
  const r = await withClient('getMfa', (c) =>
    c.query('SELECT value FROM settings WHERE key=$1', [MFA_KEY_PREFIX + subject]),
  );
  if (!r.ok || !r.value?.rows?.length) return null;
  try {
    const parsed = JSON.parse(String((r.value.rows[0] as { value: unknown }).value)) as Partial<MfaRecord>;
    if (typeof parsed.secret !== 'string' || !parsed.secret) return null;
    return { secret: parsed.secret, enabled: Boolean(parsed.enabled) };
  } catch {
    return null;
  }
}

export async function pgSetMfa(subject: string, rec: MfaRecord): Promise<boolean> {
  const r = await withClient('setMfa', (c) =>
    c.query(
      'INSERT INTO settings(key,value) VALUES($1,$2) ON CONFLICT(key) DO UPDATE SET value=$2',
      [MFA_KEY_PREFIX + subject, JSON.stringify(rec)],
    ),
  );
  return r.ok;
}

/* ─── Operator 白名单持久化（4A · capability RBAC 批2b）──────────────
 * 复用 settings 表（键 allowlist:operators = JSON 数组），避免新增 PG 表/迁移。
 * 返回 [] 表示"已连接但无记录"（空白名单）；返回 null 表示 PG 不可用（调用方保留旧缓存）。
 */
const OPERATORS_KEY = 'allowlist:operators';

export async function pgGetOperators(): Promise<string[] | null> {
  const r = await withClient('getOperators', (c) =>
    c.query('SELECT value FROM settings WHERE key=$1', [OPERATORS_KEY]),
  );
  if (!r.ok) return null;
  if (!r.value?.rows?.length) return [];
  try {
    const arr = JSON.parse(String((r.value.rows[0] as { value: unknown }).value));
    return Array.isArray(arr) ? arr.filter((x): x is string => typeof x === 'string') : [];
  } catch {
    return [];
  }
}

export async function pgSetOperators(list: string[]): Promise<boolean> {
  const r = await withClient('setOperators', (c) =>
    c.query(
      'INSERT INTO settings(key,value) VALUES($1,$2) ON CONFLICT(key) DO UPDATE SET value=$2',
      [OPERATORS_KEY, JSON.stringify(list)],
    ),
  );
  return r.ok;
}

/* ─── Developer 白名单持久化（capability RBAC：仅可读本人设备）────────── */
const DEVELOPERS_KEY = 'allowlist:developers';

export async function pgGetDevelopers(): Promise<string[] | null> {
  const r = await withClient('getDevelopers', (c) =>
    c.query('SELECT value FROM settings WHERE key=$1', [DEVELOPERS_KEY]),
  );
  if (!r.ok) return null;
  if (!r.value?.rows?.length) return [];
  try {
    const arr = JSON.parse(String((r.value.rows[0] as { value: unknown }).value));
    return Array.isArray(arr) ? arr.filter((x): x is string => typeof x === 'string') : [];
  } catch {
    return [];
  }
}

export async function pgSetDevelopers(list: string[]): Promise<boolean> {
  const r = await withClient('setDevelopers', (c) =>
    c.query(
      'INSERT INTO settings(key,value) VALUES($1,$2) ON CONFLICT(key) DO UPDATE SET value=$2',
      [DEVELOPERS_KEY, JSON.stringify(list)],
    ),
  );
  return r.ok;
}

/* ─── 签名策略发布件（policy_releases） ─────────────────────────────── */
export interface PolicyReleaseRow {
  release_id: string;
  version: number;
  created_at: number;
  created_by: string;
  signing_key_id: string;
  signature: string;
  policy_json: string;
  note: string;
  status: string;
}

export async function pgLoadPolicyReleases(): Promise<PolicyReleaseRow[] | null> {
  const r = await withClient('loadPolicyReleases', (c) =>
    c.query('SELECT release_id,version,created_at,created_by,signing_key_id,signature,policy_json,note,status FROM policy_releases ORDER BY version'),
  );
  return r.ok ? (r.value.rows as PolicyReleaseRow[]) : null;
}

export function pgInsertPolicyRelease(row: PolicyReleaseRow): void {
  scheduleWrite('insertPolicyRelease', (c) =>
    c.query(
      `INSERT INTO policy_releases(release_id,version,created_at,created_by,signing_key_id,signature,policy_json,note,status)
       VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT(release_id) DO NOTHING`,
      [row.release_id, row.version, row.created_at, row.created_by, row.signing_key_id, row.signature, row.policy_json, row.note, row.status],
    ),
  );
}

/** 把除 keepId 外的所有发布件置为 superseded（新版本发布后旧版本失效）。 */
export function pgSupersedePolicyReleases(keepId: string): void {
  scheduleWrite('supersedePolicyReleases', (c) =>
    c.query(`UPDATE policy_releases SET status='superseded' WHERE release_id <> $1 AND status='published'`, [keepId]),
  );
}

/* ─── 签名密钥元数据（policy_signing_keys）——只存元数据，绝不存密钥料 ─────── */
export interface SigningKeyRow {
  key_id: string;
  fingerprint: string;
  status: string;
  created_at: number;
  created_by: string;
  rotated_at: number | null;
  rotated_by: string | null;
  retired_at: number | null;
  retired_by: string | null;
  note: string | null;
}

export async function pgLoadSigningKeys(): Promise<SigningKeyRow[] | null> {
  const r = await withClient('loadSigningKeys', (c) =>
    c.query('SELECT key_id,fingerprint,status,created_at,created_by,rotated_at,rotated_by,retired_at,retired_by,note FROM policy_signing_keys ORDER BY created_at'),
  );
  return r.ok ? (r.value.rows as SigningKeyRow[]) : null;
}

export function pgUpsertSigningKey(row: SigningKeyRow): void {
  scheduleWrite('upsertSigningKey', (c) =>
    c.query(
      `INSERT INTO policy_signing_keys(key_id,fingerprint,status,created_at,created_by,rotated_at,rotated_by,retired_at,retired_by,note)
       VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
       ON CONFLICT(key_id) DO UPDATE SET fingerprint=$2,status=$3,rotated_at=$6,rotated_by=$7,retired_at=$8,retired_by=$9,note=$10`,
      [row.key_id, row.fingerprint, row.status, row.created_at, row.created_by, row.rotated_at, row.rotated_by, row.retired_at, row.retired_by, row.note],
    ),
  );
}

/* ─── 规则更新管道遥测（pipeline_events，append-only）──────────────────────
 * 真实管道活动：策略发布 / 基线同步 / 企业 MD 发布在各自路由里跑门禁并记录
 * 每阶段 ok/fail + 耗时；无 PG 时 record 静默 no-op、load 返回 null（诚实空态）。 */
export interface PipelineEventRow {
  id?: number;
  ts: number;
  pipeline: string;
  source: string;
  stages: string; // JSON: [{name,ok,detail?}]
  ok: boolean;
  latency_ms: number;
  actor: string;
  detail: string;
}

const PIPELINE_DDL = `CREATE TABLE IF NOT EXISTS pipeline_events(
  id BIGSERIAL PRIMARY KEY, ts BIGINT NOT NULL, pipeline TEXT NOT NULL, source TEXT NOT NULL,
  stages TEXT NOT NULL, ok BOOLEAN NOT NULL, latency_ms INTEGER NOT NULL, actor TEXT NOT NULL, detail TEXT NOT NULL)`;

export async function pgInsertPipelineEvent(e: PipelineEventRow): Promise<void> {
  await withClient('pipeline-ddl', (c) => c.query(PIPELINE_DDL));
  scheduleWrite('insertPipelineEvent', (c) =>
    c.query(
      'INSERT INTO pipeline_events(ts,pipeline,source,stages,ok,latency_ms,actor,detail) VALUES($1,$2,$3,$4,$5,$6,$7,$8)',
      [e.ts, e.pipeline, e.source, e.stages, e.ok, e.latency_ms, e.actor, e.detail],
    ),
  );
}

export async function pgLoadPipelineEvents(limit = 20): Promise<PipelineEventRow[] | null> {
  await withClient('pipeline-ddl', (c) => c.query(PIPELINE_DDL));
  const r = await withClient('loadPipelineEvents', (c) =>
    c.query('SELECT id,ts,pipeline,source,stages,ok,latency_ms,actor,detail FROM pipeline_events ORDER BY id DESC LIMIT $1', [limit]),
  );
  return r.ok ? (r.value.rows as PipelineEventRow[]) : null;
}
