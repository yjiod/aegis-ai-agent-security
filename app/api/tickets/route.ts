/**
 * app/api/tickets/route.ts — risk ticket collection for the Aegis console.
 *
 * GET  /api/tickets?status=open&severity=critical&device_id=ID&limit=50&offset=0
 * POST /api/tickets -> open a ticket (201)
 *
 * Per-ticket operations (transition, assign, delete) live in
 * app/api/tickets/[id]/route.ts; the collection deliberately does not implement
 * PUT/DELETE so a bulk mutation can never bypass the per-ticket audit history.
 *
 * The store is the in-memory demo registry in lib/store.ts and must be swapped
 * for D1 in production — see the note at the top of that file.
 */

import { NextResponse } from 'next/server';
import { requireAdmin } from '@/lib/auth';
import {
  apiError,
  boundedString,
  intParam,
  jsonResponse,
  methodNotAllowed,
  readJsonObject,
} from '@/lib/api';
import {
  DEVICE_ID_PATTERN,
  ensurePgHydrated,
  getDeviceStore,
  getTicketStore,
  isTicketSeverity,
  logAudit,
  nextTicketId,
  TICKET_SEVERITIES,
  TICKET_STATUSES,
  type Ticket,
  type TicketHistoryEntry,
  type TicketSeverity,
  type TicketStatus,
} from '@/lib/store';

export const dynamic = 'force-dynamic';

/**
 * Auto-create an open ticket for any Collector device reporting critical/high
 * findings that has no existing open ticket. Best-effort: failures are ignored
 * so a Collector outage never blocks ticket reads. This closes the loop
 * Collector findings -> console tickets in production.
 */
let lastAutoSync = 0;
const AUTO_SYNC_INTERVAL_MS = 60_000;

async function syncTicketsFromCollector(): Promise<void> {
  const url = process.env.AEGIS_COLLECTOR_URL;
  const token = process.env.AEGIS_COLLECTOR_TOKEN;
  if (!url || !token) return;
  // 先等 PG 水合, 避免并发请求/多 isolate 在水合完成前各自重复建单+写审计(刷屏)。
  await ensurePgHydrated().catch(() => {});
  const now0 = Date.now();
  if (now0 - lastAutoSync < AUTO_SYNC_INTERVAL_MS) return;
  lastAutoSync = now0;
  try {
    const res = await fetch(`${url.replace(/\/$/, '')}/v1/devices?limit=500`, {
      headers: { Authorization: `Bearer ${token}`, Accept: 'application/json' },
      cache: 'no-store',
      signal: AbortSignal.timeout(5000),
    });
    if (!res.ok) return;
    const data = (await res.json()) as { devices?: Array<Record<string, unknown>> };
    const store = getTicketStore();
    for (const d of data.devices ?? []) {
      const deviceId = String(d.device_id ?? '');
      if (!deviceId) continue;
      const sev = (d.latest_severity ?? {}) as Record<string, number>;
      const critical = Number(sev.critical ?? 0);
      const high = Number(sev.high ?? 0);
      if (critical + high <= 0) continue;
      // Skip if an open ticket already exists for this device
      const hasOpen = [...store.values()].some(
        (t) => t.device_id === deviceId && t.status !== 'resolved' && t.status !== 'dismissed',
      );
      if (hasOpen) continue;
      const severity: TicketSeverity = critical > 0 ? 'critical' : 'high';
      const now = Date.now();
      const ticket: Ticket = {
        ticket_id: nextTicketId(store, now),
        title: `设备 ${deviceId} 存在 ${critical} 个 critical / ${high} 个 high 发现`,
        severity,
        status: 'open',
        source: 'aegis-collector.auto',
        device_id: deviceId,
        description: `Collector 上报 latest_severity: critical=${critical}, high=${high}。自动生成工单待研判。`,
        created_at: now,
        updated_at: now,
        history: [
          { action: 'create', actor: 'aegis-collector', timestamp: now, note: '由 Collector 发现自动生成' },
        ],
      };
      store.set(ticket.ticket_id, ticket);
      logAudit({ actor: 'aegis-collector', action: 'ticket:create', resource_type: 'ticket', resource_id: ticket.ticket_id, detail: `auto from collector findings critical=${critical} high=${high}` });
    }
  } catch {
    /* best-effort sync */
  }
}

/** Methods this collection resource really implements (used for the 405 Allow). */
const ALLOW = 'GET, POST';

const MAX_TITLE = 200;
const MAX_SOURCE = 200;
const MAX_DESCRIPTION = 4_000;
const MAX_FINDING_REF = 300;
const MAX_ASSIGNEE = 128;
const MAX_ACTOR = 128;

/** Default page size and hard ceiling for `limit`. */
const DEFAULT_LIMIT = 50;
const MAX_LIMIT = 200;
const MAX_OFFSET = 100_000;

/** Actor recorded when a caller does not identify itself. */
const DEFAULT_ACTOR = 'aegis-console';

/** Highest severity first, matching the risks page's "按风险等级与时间排序". */
const SEVERITY_RANK: Readonly<Record<TicketSeverity, number>> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
};

/**
 * Server-managed fields. A ticket's identity, lifecycle stamps and audit history
 * are never client-writable — accepting them would let a caller forge a trail.
 */
const READ_ONLY_ON_CREATE = [
  'ticket_id',
  'status',
  'created_at',
  'updated_at',
  'resolved_at',
  'history',
] as const;

/* ------------------------------------------------------------------ *
 * Query parsing
 * ------------------------------------------------------------------ */

/**
 * Reads a multi-valued enum filter. Accepts both repeated params
 * (`?status=open&status=acknowledged`) and comma-separated lists
 * (`?status=open,acknowledged`). Returns null when a value is not in the enum so
 * the caller can answer 400 instead of silently returning an empty page.
 */
function readEnumFilter<T extends string>(
  searchParams: URLSearchParams,
  key: string,
  allowed: readonly T[],
  problems: string[],
): ReadonlySet<T> | null {
  const values = searchParams
    .getAll(key)
    .flatMap((raw) => raw.split(','))
    .map((raw) => raw.trim())
    .filter((raw) => raw.length > 0);
  if (values.length === 0) return null;

  const matched = new Set<T>();
  for (const value of values) {
    if (!(allowed as readonly string[]).includes(value)) {
      problems.push(
        `${key} must be one of ${allowed.map((item) => `'${item}'`).join(', ')}`,
      );
      continue;
    }
    matched.add(value as T);
  }
  return matched.size > 0 ? matched : null;
}

/** Deterministic queue order: severity, then newest first, then id. */
function compareTickets(left: Ticket, right: Ticket): number {
  const bySeverity =
    SEVERITY_RANK[left.severity] - SEVERITY_RANK[right.severity];
  if (bySeverity !== 0) return bySeverity;
  if (left.created_at !== right.created_at)
    return right.created_at - left.created_at;
  return left.ticket_id < right.ticket_id
    ? -1
    : left.ticket_id > right.ticket_id
      ? 1
      : 0;
}

/** Optional bounded string: absent/null -> undefined, invalid -> pushes a problem. */
function readOptional(
  value: unknown,
  field: string,
  max: number,
  problems: string[],
): string | undefined {
  if (value === undefined || value === null) return undefined;
  const text = boundedString(value, max);
  if (text === null) {
    problems.push(
      `${field} must be a non-empty string of at most ${max} characters`,
    );
    return undefined;
  }
  return text;
}

/* ------------------------------------------------------------------ *
 * Handlers
 * ------------------------------------------------------------------ */

/**
 * GET /api/tickets
 *
 * `total` is the post-filter count so a client can page without a second query;
 * `tickets` is only the requested slice.
 */
export async function GET(request: Request): Promise<NextResponse> {
  await syncTicketsFromCollector();
  const searchParams = new URL(request.url).searchParams;
  const problems: string[] = [];

  const statuses = readEnumFilter<TicketStatus>(
    searchParams,
    'status',
    TICKET_STATUSES,
    problems,
  );
  const severities = readEnumFilter<TicketSeverity>(
    searchParams,
    'severity',
    TICKET_SEVERITIES,
    problems,
  );

  // device_id is a plain string filter, so an invalid shape can never match and
  // is reported rather than quietly returning an empty page.
  let deviceFilter: string | null = null;
  const rawDeviceId = searchParams.get('device_id');
  if (rawDeviceId !== null && rawDeviceId !== '') {
    const trimmed = rawDeviceId.trim();
    if (!DEVICE_ID_PATTERN.test(trimmed)) {
      problems.push('device_id must be 3-64 characters of [A-Za-z0-9-]');
    } else {
      deviceFilter = trimmed;
    }
  }

  const limit = intParam(searchParams, 'limit', DEFAULT_LIMIT, 1, MAX_LIMIT);
  if (limit === null) {
    problems.push(`limit must be an integer between 1 and ${MAX_LIMIT}`);
  }
  const offset = intParam(searchParams, 'offset', 0, 0, MAX_OFFSET);
  if (offset === null) {
    problems.push(`offset must be an integer between 0 and ${MAX_OFFSET}`);
  }

  if (problems.length > 0 || limit === null || offset === null) {
    return apiError(
      'validation_failed',
      'Ticket query was rejected.',
      400,
      problems,
    );
  }

  const tickets = Array.from(getTicketStore().values())
    .filter((ticket) =>
      statuses === null ? true : statuses.has(ticket.status),
    )
    .filter((ticket) =>
      severities === null ? true : severities.has(ticket.severity),
    )
    .filter((ticket) =>
      deviceFilter === null ? true : ticket.device_id === deviceFilter,
    )
    .sort(compareTickets);

  return jsonResponse({
    tickets: tickets.slice(offset, offset + limit),
    total: tickets.length,
    returned: Math.max(0, Math.min(limit, tickets.length - offset)),
    limit,
    offset,
  });
}

/**
 * POST /api/tickets — open a ticket.
 *
 * Body: `{ title, severity, source, device_id, description?, finding_ref?,
 * assignee?, actor? }`. The ticket id, `status: 'open'`, timestamps and the first
 * history entry are all assigned server-side. Returns 201.
 *
 * `device_id` is format-validated but not required to exist in the registry:
 * Collector-reported devices are not necessarily enrolled in the demo registry,
 * and dropping a risk because an asset row is missing would be worse than keeping
 * a dangling reference.
 */
export async function POST(request: Request): Promise<NextResponse> {
  const __denied = requireAdmin(request);
  if (__denied) return __denied;
  const parsed = await readJsonObject(request);
  if (!parsed.ok) return parsed.response;
  const body = parsed.value;

  const forbidden = READ_ONLY_ON_CREATE.filter((field) => field in body);
  if (forbidden.length > 0) {
    return apiError(
      'read_only_field',
      'Tickets are always created open; identity, timestamps and history are server-assigned.',
      400,
      forbidden.map((field) => `${field} is read-only`),
    );
  }

  const problems: string[] = [];

  const title = boundedString(body.title, MAX_TITLE);
  if (title === null) {
    problems.push(
      `title must be a non-empty string of at most ${MAX_TITLE} characters`,
    );
  }

  const severity = isTicketSeverity(body.severity) ? body.severity : null;
  if (severity === null) {
    problems.push(
      `severity must be one of ${TICKET_SEVERITIES.map((s) => `'${s}'`).join(', ')}`,
    );
  }

  const source = boundedString(body.source, MAX_SOURCE);
  if (source === null) {
    problems.push(
      `source must be a non-empty string of at most ${MAX_SOURCE} characters`,
    );
  }

  const deviceId =
    typeof body.device_id === 'string' ? body.device_id.trim() : '';
  if (!DEVICE_ID_PATTERN.test(deviceId)) {
    problems.push('device_id must be 3-64 characters of [A-Za-z0-9-]');
  }

  // Optional fields: `undefined` keeps the key out of the stored object entirely.
  const description = readOptional(
    body.description,
    'description',
    MAX_DESCRIPTION,
    problems,
  );
  const findingRef = readOptional(
    body.finding_ref,
    'finding_ref',
    MAX_FINDING_REF,
    problems,
  );
  const assignee = readOptional(
    body.assignee,
    'assignee',
    MAX_ASSIGNEE,
    problems,
  );
  const actor =
    readOptional(body.actor, 'actor', MAX_ACTOR, problems) ?? DEFAULT_ACTOR;

  if (problems.length > 0 || !title || !severity || !source || !deviceId) {
    return apiError(
      'validation_failed',
      'Ticket creation was rejected.',
      400,
      problems,
    );
  }

  const store = getTicketStore();
  const now = Date.now();
  const history: TicketHistoryEntry[] = [
    {
      action: 'create',
      actor,
      timestamp: now,
      note: `由 ${source} 上报创建。`,
    },
  ];

  const ticket: Ticket = {
    ticket_id: nextTicketId(store, now),
    title,
    severity,
    status: 'open',
    source,
    device_id: deviceId,
    created_at: now,
    updated_at: now,
    history,
    ...(description === undefined ? {} : { description }),
    ...(findingRef === undefined ? {} : { finding_ref: findingRef }),
    ...(assignee === undefined ? {} : { assignee }),
  };
  store.set(ticket.ticket_id, ticket);

  logAudit({
    actor,
    action: 'ticket:create',
    resource_type: 'ticket',
    resource_id: ticket.ticket_id,
    detail: `创建${severity}级工单「${title}」，来源 ${source}，设备 ${deviceId}。`,
  });

  return jsonResponse(
    {
      ticket,
      created: true,
      // Handy for the console: was this device known to the registry?
      device_registered: getDeviceStore().has(deviceId),
    },
    201,
  );
}

/**
 * PUT / DELETE / PATCH are not implemented on the collection. Ticket mutations
 * are per-ticket operations so every change lands in that ticket's `history`;
 * exporting these keeps the 405 body JSON (with `Cache-Control: no-store`) rather
 * than the framework's empty response.
 */
export function PUT(): NextResponse {
  return methodNotAllowed(ALLOW);
}

export function DELETE(): NextResponse {
  return methodNotAllowed(ALLOW);
}

export function PATCH(): NextResponse {
  return methodNotAllowed(ALLOW);
}
