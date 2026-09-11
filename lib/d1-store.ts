/**
 * lib/d1-store.ts — Cloudflare D1 persistence adapter for the Aegis console.
 *
 * Provides the same Device / Ticket / AuditEntry domain types from lib/store.ts,
 * but backed by parameterized D1 queries instead of the in-memory `globalThis`
 * Maps. Used in production (Cloudflare Workers with a D1 binding); local dev
 * without a binding falls back to the in-memory store in lib/store.ts.
 *
 * RULES:
 *   - Every query is parameterized via `.bind(...)` — no string interpolation of
 *     user values. Only column/table names, which are literals defined here, are
 *     ever concatenated into SQL.
 *   - Timestamps are epoch **milliseconds**, matching lib/store.ts and the
 *     INTEGER columns declared in migrations/0001_init.sql.
 *   - Domain <-> row mapping is explicit: `findings_summary` is flattened into
 *     four INTEGER columns, and a ticket's `history[]` lives in `ticket_history`.
 */

import type {
  AgentType,
  AuditEntry,
  AuditResourceType,
  Device,
  DeviceStatus,
  FindingsSummary,
  Ticket,
  TicketHistoryEntry,
  TicketSeverity,
  TicketStatus,
} from '@/lib/store';
import { AUDIT_RESOURCE_TYPES } from '@/lib/store';

/* ------------------------------------------------------------------ *
 * Environment / binding
 * ------------------------------------------------------------------ */

export interface D1Env {
  DB?: D1Database;
}

/**
 * Resolves the D1 binding from the Worker environment. Returns null when no
 * binding is present (e.g. local dev), which is the caller's signal to fall back
 * to the in-memory store.
 */
export function getDb(env?: D1Env): D1Database | null {
  return env?.DB ?? null;
}

/* ------------------------------------------------------------------ *
 * Row shapes (as stored in D1) and defaults
 * ------------------------------------------------------------------ */

interface DeviceRow {
  device_id: string;
  hostname: string;
  owner: string;
  agent_type: string;
  agent_version: string;
  policy_version: string;
  status: string;
  last_seen: number;
  registered_at: number;
  notes: string | null;
  findings_critical: number | null;
  findings_high: number | null;
  findings_medium: number | null;
  findings_low: number | null;
}

interface TicketRow {
  ticket_id: string;
  title: string;
  severity: string;
  status: string;
  source: string;
  device_id: string;
  description: string | null;
  finding_ref: string | null;
  assignee: string | null;
  created_at: number;
  updated_at: number;
  resolved_at: number | null;
}

interface HistoryRow {
  ticket_id: string;
  action: string;
  actor: string;
  timestamp: number;
  note: string | null;
}

interface AuditRow {
  id: number;
  timestamp: number;
  actor: string;
  action: string;
  resource_type: string;
  resource_id: string | null;
  detail: string | null;
  ip_address: string | null;
}

interface CountRow {
  count: number;
}

/** Default page size / ceiling shared with the HTTP routes. */
const DEFAULT_LIMIT = 50;
const MAX_LIMIT = 200;
const MAX_OFFSET = 100_000;

function clampLimit(limit?: number): number {
  if (limit === undefined) return DEFAULT_LIMIT;
  if (!Number.isSafeInteger(limit) || limit < 1) return DEFAULT_LIMIT;
  return Math.min(limit, MAX_LIMIT);
}

function clampOffset(offset?: number): number {
  if (offset === undefined) return 0;
  if (!Number.isSafeInteger(offset) || offset < 0) return 0;
  return Math.min(offset, MAX_OFFSET);
}

/* ------------------------------------------------------------------ *
 * Row -> domain mappers
 * ------------------------------------------------------------------ */

function toFindings(row: DeviceRow): FindingsSummary {
  return {
    critical: row.findings_critical ?? 0,
    high: row.findings_high ?? 0,
    medium: row.findings_medium ?? 0,
    low: row.findings_low ?? 0,
  };
}

function mapDeviceRow(row: DeviceRow): Device {
  return {
    device_id: row.device_id,
    hostname: row.hostname,
    owner: row.owner,
    agent_type: row.agent_type as AgentType,
    agent_version: row.agent_version,
    policy_version: row.policy_version,
    status: row.status as DeviceStatus,
    last_seen: row.last_seen,
    registered_at: row.registered_at,
    findings_summary: toFindings(row),
    ...(row.notes === null ? {} : { notes: row.notes }),
  };
}

function mapHistoryRow(row: HistoryRow): TicketHistoryEntry {
  return {
    action: row.action,
    actor: row.actor,
    timestamp: row.timestamp,
    ...(row.note === null ? {} : { note: row.note }),
  };
}

function mapTicketRow(row: TicketRow, history: TicketHistoryEntry[]): Ticket {
  return {
    ticket_id: row.ticket_id,
    title: row.title,
    severity: row.severity as TicketSeverity,
    status: row.status as TicketStatus,
    source: row.source,
    device_id: row.device_id,
    created_at: row.created_at,
    updated_at: row.updated_at,
    history,
    ...(row.description === null ? {} : { description: row.description }),
    ...(row.finding_ref === null ? {} : { finding_ref: row.finding_ref }),
    ...(row.assignee === null ? {} : { assignee: row.assignee }),
    ...(row.resolved_at === null ? {} : { resolved_at: row.resolved_at }),
  };
}

function mapAuditRow(row: AuditRow): AuditEntry {
  return {
    id: row.id,
    timestamp: row.timestamp,
    actor: row.actor,
    action: row.action,
    resource_type: (AUDIT_RESOURCE_TYPES as readonly string[]).includes(row.resource_type)
      ? (row.resource_type as AuditResourceType)
      : 'system',
    ...(row.resource_id === null ? {} : { resource_id: row.resource_id }),
    ...(row.detail === null ? {} : { detail: row.detail }),
  };
}

/** Deterministic severity ordering used by the ticket queue. */
const SEVERITY_ORDER_SQL =
  "CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 " +
  "WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END";

/** Loads history for many tickets in one query, grouped by ticket_id. */
async function loadHistories(
  db: D1Database,
  ticketIds: readonly string[],
): Promise<Map<string, TicketHistoryEntry[]>> {
  const grouped = new Map<string, TicketHistoryEntry[]>();
  if (ticketIds.length === 0) return grouped;

  const placeholders = ticketIds.map(() => '?').join(', ');
  const { results } = await db
    .prepare(
      `SELECT ticket_id, action, actor, timestamp, note FROM ticket_history
       WHERE ticket_id IN (${placeholders})
       ORDER BY timestamp ASC, id ASC`,
    )
    .bind(...ticketIds)
    .all<HistoryRow>();

  for (const row of results) {
    const list = grouped.get(row.ticket_id);
    if (list) list.push(mapHistoryRow(row));
    else grouped.set(row.ticket_id, [mapHistoryRow(row)]);
  }
  return grouped;
}

/* ------------------------------------------------------------------ *
 * Device operations
 * ------------------------------------------------------------------ */

export async function d1ListDevices(
  db: D1Database,
  opts?: { q?: string; status?: string },
): Promise<Device[]> {
  const where: string[] = [];
  const params: unknown[] = [];

  if (opts?.q && opts.q.trim() !== '') {
    const like = `%${opts.q.trim()}%`;
    where.push('(device_id LIKE ? OR hostname LIKE ? OR owner LIKE ?)');
    params.push(like, like, like);
  }
  if (opts?.status && opts.status !== '') {
    where.push('status = ?');
    params.push(opts.status);
  }

  const clause = where.length > 0 ? ` WHERE ${where.join(' AND ')}` : '';
  const { results } = await db
    .prepare(`SELECT * FROM devices${clause} ORDER BY last_seen DESC`)
    .bind(...params)
    .all<DeviceRow>();

  return results.map(mapDeviceRow);
}

export async function d1GetDevice(
  db: D1Database,
  device_id: string,
): Promise<Device | null> {
  const row = await db
    .prepare('SELECT * FROM devices WHERE device_id = ?')
    .bind(device_id)
    .first<DeviceRow>();
  return row ? mapDeviceRow(row) : null;
}

export async function d1CreateDevice(db: D1Database, device: Device): Promise<void> {
  const findings = device.findings_summary;
  await db
    .prepare(
      `INSERT INTO devices (
         device_id, hostname, owner, agent_type, agent_version, policy_version,
         status, last_seen, registered_at, notes,
         findings_critical, findings_high, findings_medium, findings_low
       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      device.device_id,
      device.hostname,
      device.owner,
      device.agent_type,
      device.agent_version,
      device.policy_version,
      device.status,
      device.last_seen,
      device.registered_at,
      device.notes ?? null,
      findings?.critical ?? 0,
      findings?.high ?? 0,
      findings?.medium ?? 0,
      findings?.low ?? 0,
    )
    .run();
}

/**
 * Applies a partial update. Only recognized, provided columns are written; the
 * SET clause is assembled from literal column names and bound positionally, so no
 * value is ever interpolated into SQL. A no-op patch issues no query.
 */
export async function d1UpdateDevice(
  db: D1Database,
  device_id: string,
  fields: Partial<Device>,
): Promise<void> {
  const sets: string[] = [];
  const params: unknown[] = [];

  if (fields.hostname !== undefined) {
    sets.push('hostname = ?');
    params.push(fields.hostname);
  }
  if (fields.owner !== undefined) {
    sets.push('owner = ?');
    params.push(fields.owner);
  }
  if (fields.agent_type !== undefined) {
    sets.push('agent_type = ?');
    params.push(fields.agent_type);
  }
  if (fields.agent_version !== undefined) {
    sets.push('agent_version = ?');
    params.push(fields.agent_version);
  }
  if (fields.policy_version !== undefined) {
    sets.push('policy_version = ?');
    params.push(fields.policy_version);
  }
  if (fields.status !== undefined) {
    sets.push('status = ?');
    params.push(fields.status);
  }
  if (fields.last_seen !== undefined) {
    sets.push('last_seen = ?');
    params.push(fields.last_seen);
  }
  if (fields.registered_at !== undefined) {
    sets.push('registered_at = ?');
    params.push(fields.registered_at);
  }
  if ('notes' in fields) {
    sets.push('notes = ?');
    params.push(fields.notes ?? null);
  }
  if (fields.findings_summary !== undefined) {
    const f = fields.findings_summary;
    sets.push(
      'findings_critical = ?',
      'findings_high = ?',
      'findings_medium = ?',
      'findings_low = ?',
    );
    params.push(f.critical, f.high, f.medium, f.low);
  }

  if (sets.length === 0) return;

  await db
    .prepare(`UPDATE devices SET ${sets.join(', ')} WHERE device_id = ?`)
    .bind(...params, device_id)
    .run();
}

export async function d1DeleteDevice(
  db: D1Database,
  device_id: string,
): Promise<void> {
  await db.prepare('DELETE FROM devices WHERE device_id = ?').bind(device_id).run();
}

/* ------------------------------------------------------------------ *
 * Ticket operations
 * ------------------------------------------------------------------ */

export async function d1ListTickets(
  db: D1Database,
  opts?: { status?: string; severity?: string; limit?: number; offset?: number },
): Promise<{ tickets: Ticket[]; total: number }> {
  const where: string[] = [];
  const params: unknown[] = [];

  if (opts?.status && opts.status !== '') {
    where.push('status = ?');
    params.push(opts.status);
  }
  if (opts?.severity && opts.severity !== '') {
    where.push('severity = ?');
    params.push(opts.severity);
  }

  const clause = where.length > 0 ? ` WHERE ${where.join(' AND ')}` : '';
  const limit = clampLimit(opts?.limit);
  const offset = clampOffset(opts?.offset);

  const countRow = await db
    .prepare(`SELECT COUNT(*) AS count FROM tickets${clause}`)
    .bind(...params)
    .first<CountRow>();
  const total = countRow?.count ?? 0;

  const { results } = await db
    .prepare(
      `SELECT * FROM tickets${clause}
       ORDER BY ${SEVERITY_ORDER_SQL}, created_at DESC, ticket_id ASC
       LIMIT ? OFFSET ?`,
    )
    .bind(...params, limit, offset)
    .all<TicketRow>();

  const ids = results.map((row) => row.ticket_id);
  const histories = await loadHistories(db, ids);

  const tickets = results.map((row) => mapTicketRow(row, histories.get(row.ticket_id) ?? []));
  return { tickets, total };
}

export async function d1GetTicket(
  db: D1Database,
  ticket_id: string,
): Promise<Ticket | null> {
  const row = await db
    .prepare('SELECT * FROM tickets WHERE ticket_id = ?')
    .bind(ticket_id)
    .first<TicketRow>();
  if (!row) return null;

  const histories = await loadHistories(db, [ticket_id]);
  return mapTicketRow(row, histories.get(ticket_id) ?? []);
}

/**
 * Inserts the ticket and its full history in one batch so a create is atomic:
 * either the ticket and its trail both land, or neither does.
 */
export async function d1CreateTicket(db: D1Database, ticket: Ticket): Promise<void> {
  const statements = [
    db
      .prepare(
        `INSERT INTO tickets (
           ticket_id, title, severity, status, source, device_id,
           description, finding_ref, assignee, created_at, updated_at, resolved_at
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .bind(
        ticket.ticket_id,
        ticket.title,
        ticket.severity,
        ticket.status,
        ticket.source,
        ticket.device_id,
        ticket.description ?? null,
        ticket.finding_ref ?? null,
        ticket.assignee ?? null,
        ticket.created_at,
        ticket.updated_at,
        ticket.resolved_at ?? null,
      ),
    ...ticket.history.map((entry) =>
      db
        .prepare(
          `INSERT INTO ticket_history (ticket_id, action, actor, timestamp, note)
           VALUES (?, ?, ?, ?, ?)`,
        )
        .bind(ticket.ticket_id, entry.action, entry.actor, entry.timestamp, entry.note ?? null),
    ),
  ];

  await db.batch(statements);
}

export async function d1UpdateTicket(
  db: D1Database,
  ticket_id: string,
  fields: Partial<Ticket>,
): Promise<void> {
  const sets: string[] = [];
  const params: unknown[] = [];

  if (fields.title !== undefined) {
    sets.push('title = ?');
    params.push(fields.title);
  }
  if (fields.severity !== undefined) {
    sets.push('severity = ?');
    params.push(fields.severity);
  }
  if (fields.status !== undefined) {
    sets.push('status = ?');
    params.push(fields.status);
  }
  if (fields.source !== undefined) {
    sets.push('source = ?');
    params.push(fields.source);
  }
  if (fields.device_id !== undefined) {
    sets.push('device_id = ?');
    params.push(fields.device_id);
  }
  if ('description' in fields) {
    sets.push('description = ?');
    params.push(fields.description ?? null);
  }
  if ('finding_ref' in fields) {
    sets.push('finding_ref = ?');
    params.push(fields.finding_ref ?? null);
  }
  if ('assignee' in fields) {
    sets.push('assignee = ?');
    params.push(fields.assignee ?? null);
  }
  if (fields.created_at !== undefined) {
    sets.push('created_at = ?');
    params.push(fields.created_at);
  }
  if (fields.updated_at !== undefined) {
    sets.push('updated_at = ?');
    params.push(fields.updated_at);
  }
  if ('resolved_at' in fields) {
    sets.push('resolved_at = ?');
    params.push(fields.resolved_at ?? null);
  }

  if (sets.length === 0) return;

  await db
    .prepare(`UPDATE tickets SET ${sets.join(', ')} WHERE ticket_id = ?`)
    .bind(...params, ticket_id)
    .run();
}

/** Removes a ticket and its history together (history first, for FK sanity). */
export async function d1DeleteTicket(
  db: D1Database,
  ticket_id: string,
): Promise<void> {
  await db.batch([
    db.prepare('DELETE FROM ticket_history WHERE ticket_id = ?').bind(ticket_id),
    db.prepare('DELETE FROM tickets WHERE ticket_id = ?').bind(ticket_id),
  ]);
}

export async function d1AddHistory(
  db: D1Database,
  ticket_id: string,
  entry: TicketHistoryEntry,
): Promise<void> {
  await db
    .prepare(
      `INSERT INTO ticket_history (ticket_id, action, actor, timestamp, note)
       VALUES (?, ?, ?, ?, ?)`,
    )
    .bind(ticket_id, entry.action, entry.actor, entry.timestamp, entry.note ?? null)
    .run();
}

export async function d1GetHistory(
  db: D1Database,
  ticket_id: string,
): Promise<TicketHistoryEntry[]> {
  const { results } = await db
    .prepare(
      `SELECT ticket_id, action, actor, timestamp, note FROM ticket_history
       WHERE ticket_id = ? ORDER BY timestamp ASC, id ASC`,
    )
    .bind(ticket_id)
    .all<HistoryRow>();
  return results.map(mapHistoryRow);
}

/* ------------------------------------------------------------------ *
 * Audit operations
 * ------------------------------------------------------------------ */

export async function d1LogAudit(
  db: D1Database,
  entry: {
    action: string;
    resource_type: string;
    resource_id?: string;
    detail?: string;
    actor?: string;
    ip_address?: string;
  },
): Promise<void> {
  await db
    .prepare(
      `INSERT INTO audit_log (timestamp, actor, action, resource_type, resource_id, detail, ip_address)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      Date.now(),
      entry.actor || 'console_user',
      entry.action,
      entry.resource_type,
      entry.resource_id ?? null,
      entry.detail ?? null,
      entry.ip_address ?? null,
    )
    .run();
}

export async function d1ListAudit(
  db: D1Database,
  opts?: {
    limit?: number;
    offset?: number;
    resource_type?: string;
    action?: string;
  },
): Promise<{ entries: AuditEntry[]; total: number }> {
  const where: string[] = [];
  const params: unknown[] = [];

  if (opts?.resource_type && opts.resource_type !== '') {
    where.push('resource_type = ?');
    params.push(opts.resource_type);
  }
  if (opts?.action && opts.action !== '') {
    // Accept either a bare verb ('create') or a namespaced one ('device:create').
    where.push('(action = ? OR action LIKE ?)');
    params.push(opts.action, `%:${opts.action}`);
  }

  const clause = where.length > 0 ? ` WHERE ${where.join(' AND ')}` : '';
  const limit = clampLimit(opts?.limit);
  const offset = clampOffset(opts?.offset);

  const countRow = await db
    .prepare(`SELECT COUNT(*) AS count FROM audit_log${clause}`)
    .bind(...params)
    .first<CountRow>();
  const total = countRow?.count ?? 0;

  const { results } = await db
    .prepare(
      `SELECT * FROM audit_log${clause} ORDER BY timestamp DESC, id DESC LIMIT ? OFFSET ?`,
    )
    .bind(...params, limit, offset)
    .all<AuditRow>();

  return { entries: results.map(mapAuditRow), total };
}
