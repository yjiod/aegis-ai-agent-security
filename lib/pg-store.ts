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
    console.error(`[pg] ${label} failed:`, msg);
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
} | null> {
  const r = await withClient('loadAll', async (c) => {
    // Sequential queries on one connection.
    const d = await c.query('SELECT * FROM devices');
    const t = await c.query('SELECT * FROM tickets ORDER BY created_at');
    const h = await c.query('SELECT * FROM ticket_history ORDER BY id');
    const a = await c.query('SELECT * FROM audit_log ORDER BY id');
    const ad = await c.query('SELECT employee_no FROM admins');

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
    const audit: AuditEntry[] = a.rows.map((row) => ({
      id: Number(row.id), timestamp: Number(row.ts ?? 0), actor: row.actor ?? '',
      action: row.action, resource_type: row.resource_type,
      ...(row.resource_id ? { resource_id: row.resource_id } : {}),
      ...(row.detail ? { detail: row.detail } : {}),
    })) as AuditEntry[];
    const admins: string[] = ad.rows.map((row) => row.employee_no);
    return { devices, tickets, audit, admins };
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
  scheduleWrite('upsertTicket', (c) =>
    c.query(
      `INSERT INTO tickets(ticket_id,title,severity,status,source,device_id,description,finding_ref,assignee,created_at,updated_at,resolved_at)
       VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
       ON CONFLICT(ticket_id) DO UPDATE SET title=$2,severity=$3,status=$4,source=$5,device_id=$6,description=$7,finding_ref=$8,assignee=$9,updated_at=$11,resolved_at=$12`,
      [t.ticket_id, t.title, t.severity, t.status, t.source, t.device_id, t.description ?? null, t.finding_ref ?? null, t.assignee ?? null, t.created_at, t.updated_at, t.resolved_at ?? null],
    ),
  );
  for (const hEntry of t.history ?? []) {
    scheduleWrite('ticketHistory', (c) =>
      c.query('INSERT INTO ticket_history(ticket_id,action,actor,ts,note) VALUES($1,$2,$3,$4,$5)', [t.ticket_id, hEntry.action, hEntry.actor, hEntry.timestamp, hEntry.note ?? null]),
    );
  }
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
