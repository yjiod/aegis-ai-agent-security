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
import { requireAdmin, requireSession } from '@/lib/auth';
import { ensureLabelsLoaded, allowedAssetKeys, isFindingAllowed } from '@/lib/labels';
import {
  apiError,
  boundedString,
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

/**
 * 加白感知重算某设备的 critical/high 计数：扣除命中"加白资产"的发现。
 * findings 拉取失败/未配置 → 返回 null，调用方保守沿用 Collector 的 latest_severity
 * （宁可多开一张待研判工单，也绝不因抑制逻辑漏掉真实风险）。
 */
async function adjustedSeverity(
  deviceId: string,
  allowed: Set<string>,
): Promise<{ critical: number; high: number; empty: boolean } | null> {
  const url = process.env.AEGIS_COLLECTOR_URL;
  const token = process.env.AEGIS_COLLECTOR_TOKEN;
  if (!url || !token) return null;
  try {
    const res = await fetch(`${url.replace(/\/$/, '')}/v1/findings?device_id=${encodeURIComponent(deviceId)}&limit=1000`, {
      headers: { Authorization: `Bearer ${token}`, Accept: 'application/json' },
      cache: 'no-store',
      signal: AbortSignal.timeout(5000),
    });
    if (!res.ok) return null;
    const data = (await res.json()) as { findings?: unknown };
    const findings = Array.isArray(data.findings) ? (data.findings as Array<Record<string, unknown>>) : [];
    let critical = 0;
    let high = 0;
    for (const f of findings) {
      if (isFindingAllowed(f, allowed)) continue;
      const s = String(f.severity ?? '');
      if (s === 'critical') critical += 1;
      else if (s === 'high') high += 1;
    }
    // empty：本次 findings 读取为空。若 collector 原始 latest_severity 仍报 critical/high，
    // 二者矛盾（多为瞬态空读取），调用方不得据此自动闭环工单。
    return { critical, high, empty: findings.length === 0 };
  } catch {
    return null;
  }
}

async function syncTicketsFromCollector(): Promise<void> {
  const url = process.env.AEGIS_COLLECTOR_URL;
  const token = process.env.AEGIS_COLLECTOR_TOKEN;
  if (!url || !token) return;
  // 先等 PG 水合, 避免并发请求/多 isolate 在水合完成前各自重复建单+写审计(刷屏)。
  await ensurePgHydrated().catch(() => {});
  const now0 = Date.now();
  if (now0 - lastAutoSync < AUTO_SYNC_INTERVAL_MS) return;
  lastAutoSync = now0;
  // 加白集合：已处置为 allow 的资产不再触发自动工单（"已加白不再告警"延伸到风险流水线）。
  await ensureLabelsLoaded().catch(() => {});
  const allowed = allowedAssetKeys();
  try {
    // P1-4：游标翻页遍历全量舰队（旧实现 limit=500 单页 → 30k 下自动工单只覆盖前 500 台，
    // 2.95 万台无工单，正确性红线）。任一页失败即放弃本轮同步（绝不用半量误判/误闭环工单）。
    const devices: Array<Record<string, unknown>> = [];
    // 设备显示名（用户口径 2026-09-25 第三轮）：序列号（过长截断）+ 主机名，不再用 device_id 哈希。
    // 例: "R1NRKD01325701C (SHINESTRIX16)" / "Parallels-0E 3F… (M4-WIN)"。
    const deviceLabel = (d: Record<string, unknown>): string => {
      const serial = typeof d.serial === 'string' ? d.serial : '';
      const hostname = typeof d.hostname === 'string' ? d.hostname : '';
      const short = serial.length > 12 ? `${serial.slice(0, 10)}…` : serial;
      if (serial && hostname) return `${short} (${hostname})`;
      if (serial) return short;
      if (hostname) return hostname;
      return String(d.device_id ?? '未知设备');
    };
    let cursor = '';
    for (let page = 0; page < 200; page += 1) {
      const qs = new URLSearchParams({ limit: '10000' });
      if (cursor) qs.set('cursor', cursor);
      const res = await fetch(`${url.replace(/\/$/, '')}/v1/devices?${qs.toString()}`, {
        headers: { Authorization: `Bearer ${token}`, Accept: 'application/json' },
        cache: 'no-store',
        signal: AbortSignal.timeout(5000),
      });
      if (!res.ok) return;
      const data = (await res.json()) as { devices?: Array<Record<string, unknown>>; complete?: boolean; next_cursor?: string };
      if (Array.isArray(data.devices)) devices.push(...data.devices);
      cursor = typeof data.next_cursor === 'string' ? data.next_cursor : '';
      if (data.complete !== false || !cursor) break;
    }
    const store = getTicketStore();
    for (const d of devices) {
      const deviceId = String(d.device_id ?? '');
      if (!deviceId) continue;
      const sev = (d.latest_severity ?? {}) as Record<string, number>;
      const rawCritHigh = Number(sev.critical ?? 0) + Number(sev.high ?? 0);
      // 由 Collector 自动生成、仍未关闭的工单（人工工单不在此列，绝不自动改动）。
      const openAuto = [...store.values()].filter(
        (t) =>
          t.device_id === deviceId &&
          t.source === 'aegis-collector.auto' &&
          t.status !== 'resolved' &&
          t.status !== 'dismissed',
      );
      // 原始计数为 0 且无待消除的自动工单 → 本机无事可做，省去一次 findings 拉取。
      if (rawCritHigh <= 0 && openAuto.length === 0) continue;
      let critical = Number(sev.critical ?? 0);
      let high = Number(sev.high ?? 0);
      // 扣除加白资产的发现后重算；拉取失败(null)保守沿用 Collector 原计数。
      const adj = await adjustedSeverity(deviceId, allowed);
      if (adj) { critical = adj.critical; high = adj.high; }
      // 加白后同源告警自动消除：仅当"确认"(adj 非 null)重算后已无 critical/high 时，
      // 自动 resolve 该设备由 Collector 自动生成的 open 工单并留审计痕迹。
      // adj 为 null（findings 拉取失败）时绝不误关——宁可留一张待研判工单。
      if (adj && critical + high <= 0) {
        // 防瞬态空读取误闭环：本次 findings 读取为空、但 collector 原始 latest_severity 仍报
        // critical/high，二者矛盾（多为瞬态空读取/上报间隙），不自动 resolve——否则会出现
        // "误闭环→下轮又重建"的工单抖动（风险中心曾因此角标与页面计数不一致）。等两者一致再闭环。
        if (adj.empty && rawCritHigh > 0) {
          continue;
        }
        if (openAuto.length > 0) {
          const now = Date.now();
          for (const t of openAuto) {
            const resolved: Ticket = {
              ...t,
              status: 'resolved',
              resolved_at: now,
              updated_at: now,
              history: [
                ...t.history,
                { action: 'resolve', actor: 'aegis-collector', timestamp: now, note: '同源 critical/high 发现已全部加白，自动消除告警' },
              ],
            };
            store.set(t.ticket_id, resolved);
            logAudit({ actor: 'aegis-collector', action: 'ticket:resolve', resource_type: 'ticket', resource_id: t.ticket_id, detail: `加白后同源告警自动消除（设备 ${deviceId}）` });
          }
        }
        continue;
      }
      // 存活自动工单的计数随加白/修复实时收敛：标题与严重度按"当前(扣除加白后)"计数刷新，
      // 避免工单永远停留在创建那一刻的原始计数（用户反馈"加白了风险中心还是这些"）。
      // 仅刷新 Collector 自动工单；人工工单绝不自动改动。adj 为 null 时不动(保守)。
      if (adj && openAuto.length > 0 && critical + high > 0) {
        const nowU = Date.now();
        const severityU: TicketSeverity = critical > 0 ? 'critical' : 'high';
        const titleU = `设备 ${deviceLabel(d)} 存在 ${critical} 个 critical / ${high} 个 high 发现`;
        for (const t of openAuto) {
          if (t.title === titleU && t.severity === severityU) continue;
          const refreshed: Ticket = {
            ...t,
            title: titleU,
            severity: severityU,
            description: `Collector 实时重算(已扣除加白资产): critical=${critical}, high=${high}。待研判。`,
            updated_at: nowU,
            history: [
              ...t.history,
              { action: 'update', actor: 'aegis-collector', timestamp: nowU, note: `计数收敛: critical=${critical}, high=${high}` },
            ],
          };
          store.set(t.ticket_id, refreshed);
        }
        continue; // 已有 open 自动工单且已刷新计数，无需新建
      }
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
        title: `设备 ${deviceLabel(d)} 存在 ${critical} 个 critical / ${high} 个 high 发现`,
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

/**
 * Integer query parameter that CLAMPS out-of-range values instead of rejecting.
 *
 * 与 lib/api.ts 的 intParam 的唯一区别：intParam 对越界返回 null（调用方据此 400），
 * 本函数把越界值钳制进 [min, max]。理由：调用方多要一点数据不该让整个请求失败——
 * 前端总览页用 `?limit=500` 调本端点，400 会被 lib/api.ts 的 getJson 静默吞成空数组，
 * 首页处置进度/完成率/MTTR 随之全显示 0% 或「—」，且**没有任何错误提示**（看起来
 * 像"真的没工单"，比直接报错更危险）。
 *
 * 边界取舍：
 *  - **非法输入仍然 400**（`limit=abc`、`limit=1e3`、超过 9 位数字）→ 返回 null。
 *    clamp 只放宽"越界的合法整数"，不放宽"根本不是整数"。
 *  - **不提高 MAX_LIMIT**：200 是有意的内存/性能护栏，提高上限属阶段2
 *    「工单服务端游标分页」专项。
 *  - 返回 `requested`（钳制前的原始值）与 `clamped`，让调用方能如实回传
 *    "仅取前 N 条"。钳制若不上报就等于静默截断，违反"数据不完整却宣称完整"红线。
 */
function clampedIntParam(
  searchParams: URLSearchParams,
  key: string,
  fallback: number,
  min: number,
  max: number,
): { value: number; requested: number; clamped: boolean } | null {
  const raw = searchParams.get(key);
  if (raw === null || raw === '') {
    return { value: fallback, requested: fallback, clamped: false };
  }
  const trimmed = raw.trim();
  // 允许前导符号，这样 `-1` 属于"越界的合法整数"(clamp) 而非"非法输入"(400)。
  if (!/^[+-]?\d{1,9}$/.test(trimmed)) return null;
  const parsed = Number.parseInt(trimmed, 10);
  if (!Number.isSafeInteger(parsed)) return null;
  const value = Math.min(Math.max(parsed, min), max);
  return { value, requested: parsed, clamped: value !== parsed };
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
 *
 * TODO(P1-4, 阶段2 专项)：本 handler 通过 syncTicketsFromCollector() 带有写副作用
 * （自动建单 / 自动闭环 / 刷新标题严重度 / 写审计）。GET 带副作用违反幂等语义，
 * 且任何已认证身份的只读请求都会推动工单状态机。本轮止血**只补验签闸，不重构**；
 * 把同步移出 GET（改为独立 POST /api/tickets/sync 或后台循环）属阶段2 专项。
 */
export async function GET(request: Request): Promise<NextResponse> {
  // 会话验签闸（契约声明 /tickets = session）：middleware 只校验 Cookie 存在性+expiry
  // 不验签，伪造 Cookie 能过 middleware，故必须在此真验签。任何已认证身份可读
  // （viewer/auditor/operator 的只读流程不得被打断）；写操作另有 requireAdmin。
  const __denied = requireSession(request);
  if (__denied) return __denied;
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

  // limit/offset 越界 → clamp（不再 400）；非法输入 → 仍 400。见 clampedIntParam。
  const limitParam = clampedIntParam(
    searchParams,
    'limit',
    DEFAULT_LIMIT,
    1,
    MAX_LIMIT,
  );
  if (limitParam === null) {
    problems.push(`limit must be an integer (clamped into 1..${MAX_LIMIT})`);
  }
  const offsetParam = clampedIntParam(
    searchParams,
    'offset',
    0,
    0,
    MAX_OFFSET,
  );
  if (offsetParam === null) {
    problems.push(`offset must be an integer (clamped into 0..${MAX_OFFSET})`);
  }

  if (problems.length > 0 || limitParam === null || offsetParam === null) {
    return apiError(
      'validation_failed',
      'Ticket query was rejected.',
      400,
      problems,
    );
  }
  const limit = limitParam.value;
  const offset = offsetParam.value;

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
    // 诚实钳制披露：请求值越界时如实回传原始请求值，让前端能显示"仅取前 N 条"，
    // 而不是把钳制伪装成"数据就这么多"。均为**新增**字段，既有字段名一律不动
    // （前端正在并行改动，改既有字段名会连带炸前端）。
    ...(limitParam.clamped
      ? { limit_clamped: true, requested_limit: limitParam.requested }
      : {}),
    ...(offsetParam.clamped
      ? { offset_clamped: true, requested_offset: offsetParam.requested }
      : {}),
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
