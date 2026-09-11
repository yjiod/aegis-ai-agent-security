/**
 * lib/store.ts — shared typed access to the console's device + ticket stores.
 *
 * WHY `globalThis`: vinext/Next.js re-evaluates route modules on every dev hot
 * reload, and a single Cloudflare Workers isolate serves many requests. Hanging
 * the Maps off `globalThis` keeps the registry alive across module reloads
 * inside one process instead of re-seeding on every request.
 *
 * PRODUCTION NOTE: this store is deliberately ephemeral. It is per-isolate,
 * wiped on restart, and never shared across regions or deployments — fine for a
 * demo/dev console, wrong for real governance state. Swap these helpers for
 * Cloudflare D1 (or the Collector's SQLite) before this API drives real
 * decisions. All reads and writes go through `getDeviceStore` / `getTicketStore`
 * so that migration only has to touch this file.
 *
 * Timestamps everywhere in this module are unix epoch **milliseconds**
 * (`Date.now()`), which is what `date-fns` on the client expects. The Python
 * Collector uses epoch seconds; convert at that boundary, not here.
 */

/* ------------------------------------------------------------------ *
 * Domain types
 * ------------------------------------------------------------------ */

export const AGENT_TYPES = [
  'cursor',
  'claude_code',
  'codex_cli',
  'windsurf',
  'other',
] as const;
export type AgentType = (typeof AGENT_TYPES)[number];

export const DEVICE_STATUSES = [
  'online',
  'offline',
  'stale',
  'needs_attention',
] as const;
export type DeviceStatus = (typeof DEVICE_STATUSES)[number];

export const TICKET_SEVERITIES = ['critical', 'high', 'medium', 'low'] as const;
export type TicketSeverity = (typeof TICKET_SEVERITIES)[number];

export const TICKET_STATUSES = [
  'open',
  'acknowledged',
  'investigating',
  'resolved',
  'dismissed',
] as const;
export type TicketStatus = (typeof TICKET_STATUSES)[number];

/** Open findings rolled up per device, by severity. */
export interface FindingsSummary {
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export interface Device {
  device_id: string;
  hostname: string;
  owner: string;
  agent_type: AgentType;
  agent_version: string;
  policy_version: string;
  status: DeviceStatus;
  /** Epoch milliseconds of the last accepted report; 0 = never reported. */
  last_seen: number;
  /** Epoch milliseconds. */
  registered_at: number;
  notes?: string;
  findings_summary?: FindingsSummary;
}

export interface TicketHistoryEntry {
  action: string;
  actor: string;
  /** Epoch milliseconds. */
  timestamp: number;
  note?: string;
}

export interface Ticket {
  /** `TKT-YYYYMMDD-NNNN`, allocated by {@link nextTicketId}. */
  ticket_id: string;
  title: string;
  severity: TicketSeverity;
  status: TicketStatus;
  /** Originating detector, e.g. "cursor-mcp-filesystem", "prompt-helper.skill". */
  source: string;
  device_id: string;
  description?: string;
  /** `<finding kind>:<path>` from the originating aegis.report/v1 document. */
  finding_ref?: string;
  assignee?: string;
  /** Epoch milliseconds. */
  created_at: number;
  updated_at: number;
  /** Set when the ticket reaches a terminal state; cleared on reopen. */
  resolved_at?: number;
  history: TicketHistoryEntry[];
}

/* ------------------------------------------------------------------ *
 * Identifier shapes
 * ------------------------------------------------------------------ */

/**
 * device_id is the join key between the console, the Collector and EDR, so its
 * shape is fixed: 3-64 characters of ASCII alphanumerics and hyphens. No dots,
 * slashes or unicode — it ends up in URLs, log lines and on-disk paths.
 */
export const DEVICE_ID_PATTERN = /^[A-Za-z0-9-]{3,64}$/;

/** The `TKT-YYYYMMDD-NNNN` shape allocated by {@link nextTicketId}. */
export const TICKET_ID_PATTERN = /^TKT-\d{8}-\d{4}$/;

/* ------------------------------------------------------------------ *
 * Type guards (used by the route handlers for input validation)
 * ------------------------------------------------------------------ */

function oneOf(values: readonly string[], candidate: unknown): boolean {
  return (
    typeof candidate === 'string' &&
    (values as readonly string[]).includes(candidate)
  );
}

export function isAgentType(value: unknown): value is AgentType {
  return oneOf(AGENT_TYPES, value);
}

export function isDeviceStatus(value: unknown): value is DeviceStatus {
  return oneOf(DEVICE_STATUSES, value);
}

export function isTicketSeverity(value: unknown): value is TicketSeverity {
  return oneOf(TICKET_SEVERITIES, value);
}

export function isTicketStatus(value: unknown): value is TicketStatus {
  return oneOf(TICKET_STATUSES, value);
}

/* ------------------------------------------------------------------ *
 * Ticket state machine
 * ------------------------------------------------------------------ */

/**
 * The single source of truth for the ticket lifecycle, consumed by
 * app/api/tickets/[id]/route.ts:
 *
 *   open -> acknowledged -> investigating -> resolved | dismissed
 *   any non-open state -> open (reopen)
 *
 * `open -> resolved` is therefore impossible: a risk has to be owned and looked
 * at before it can be closed. `acknowledged -> dismissed` is kept deliberately —
 * a claimed ticket can still turn out to be a false positive, and the console
 * offers that action.
 */
const VALID_TRANSITIONS: Record<TicketStatus, TicketStatus[]> = {
  open: ['acknowledged'],
  acknowledged: ['investigating', 'dismissed', 'open'],
  investigating: ['resolved', 'dismissed', 'open'],
  resolved: ['open'],
  dismissed: ['open'],
};

export function isValidTransition(
  from: TicketStatus,
  to: TicketStatus,
): boolean {
  return VALID_TRANSITIONS[from]?.includes(to) ?? false;
}

export function getValidTransitions(from: TicketStatus): TicketStatus[] {
  return VALID_TRANSITIONS[from] ?? [];
}

/* ------------------------------------------------------------------ *
 * globalThis plumbing
 * ------------------------------------------------------------------ */

type AegisStores = {
  __aegis_devices?: Map<string, Device>;
  __aegis_tickets?: Map<string, Ticket>;
  __aegis_audit?: AuditEntry[];
};

/**
 * A narrow cast rather than `declare global { var ... }` keeps this module free
 * of ambient side effects and avoids tripping the repo's `no-var` lint rule.
 */
const globals = globalThis as typeof globalThis & AegisStores;

/* ------------------------------------------------------------------ *
 * Seed data
 * ------------------------------------------------------------------ */

const MINUTE = 60_000;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;

/**
 * The six devices mirror `deviceRows` in app/devices/page.tsx one-for-one so the
 * API and the (still hardcoded) UI tell the same story:
 *
 *   受保护 -> online          需处理 -> needs_attention       离线 -> offline
 *
 * The `v3.x` / `v4.x` versions are the console's demo-world versions, matching
 * the page's `required_agent_version ?? 'v3.8'` fallback. A live Collector
 * reports semver instead (agent 0.30.0, policy 4.8.0) — see scripts/dev-collector.sh.
 */
type DeviceSeed = Omit<Device, 'last_seen' | 'registered_at'> & {
  /** How long ago the device last reported. */
  seen_ago_ms: number;
  /** How long ago the device was enrolled. */
  enrolled_ago_ms: number;
};

const DEVICE_SEEDS: readonly DeviceSeed[] = [
  {
    device_id: 'ENG-MBP-1032',
    hostname: 'eng-mbp-1032.corp.aegis.local',
    owner: '陈昊',
    agent_type: 'cursor',
    agent_version: 'v3.8',
    policy_version: 'v4.8',
    status: 'online',
    seen_ago_ms: 4 * MINUTE,
    enrolled_ago_ms: 214 * DAY,
    notes: '研发部 · Cursor 企业版已纳管，Skill 白名单生效。',
    findings_summary: { critical: 0, high: 0, medium: 1, low: 0 },
  },
  {
    device_id: 'MKT-LT-2841',
    hostname: 'mkt-lt-2841.corp.aegis.local',
    owner: '林妍',
    agent_type: 'cursor',
    agent_version: 'v3.7',
    policy_version: 'v4.8',
    status: 'needs_attention',
    seen_ago_ms: 2 * MINUTE,
    enrolled_ago_ms: 96 * DAY,
    notes: '市场部 · MCP filesystem 越权访问待研判。',
    findings_summary: { critical: 0, high: 1, medium: 0, low: 0 },
  },
  {
    device_id: 'ENG-LT-0948',
    hostname: 'eng-lt-0948.corp.aegis.local',
    owner: '周航',
    agent_type: 'codex_cli',
    agent_version: 'v3.8',
    policy_version: 'v4.8',
    status: 'online',
    seen_ago_ms: 11 * MINUTE,
    enrolled_ago_ms: 158 * DAY,
    notes: '研发部 · Codex CLI 生成代码进入人工复核队列。',
    findings_summary: { critical: 0, high: 0, medium: 1, low: 1 },
  },
  {
    device_id: 'OPS-MBP-0314',
    hostname: 'ops-mbp-0314.corp.aegis.local',
    owner: '罗宁',
    agent_type: 'claude_code',
    agent_version: 'v3.8',
    policy_version: 'v4.8',
    status: 'offline',
    seen_ago_ms: 26 * HOUR,
    enrolled_ago_ms: 301 * DAY,
    notes: '运维部 · 超过 24 小时未上报，离线前存在未签名 MCP 出站。',
    findings_summary: { critical: 0, high: 1, medium: 0, low: 0 },
  },
  {
    device_id: 'DESK-WIN-0521',
    hostname: 'desk-win-0521.corp.aegis.local',
    owner: '赵磊',
    agent_type: 'windsurf',
    agent_version: 'v3.8',
    policy_version: 'v4.8',
    status: 'online',
    seen_ago_ms: 7 * MINUTE,
    enrolled_ago_ms: 74 * DAY,
    notes: '客服部 · Windows 桌面，历史工单已闭环。',
    findings_summary: { critical: 0, high: 0, medium: 0, low: 0 },
  },
  {
    device_id: 'MKT-MBP-0847',
    hostname: 'mkt-mbp-0847.corp.aegis.local',
    owner: '吴婷',
    agent_type: 'cursor',
    agent_version: 'v3.6',
    policy_version: 'v4.6',
    status: 'needs_attention',
    seen_ago_ms: 52 * MINUTE,
    enrolled_ago_ms: 122 * DAY,
    notes: '市场部 · Agent 落后基线两个版本，待推送升级。',
    findings_summary: { critical: 0, high: 1, medium: 0, low: 0 },
  },
];

/** Returns six fresh Device objects (never shared references). */
export function seedDevices(): Device[] {
  const now = Date.now();
  return DEVICE_SEEDS.map(({ seen_ago_ms, enrolled_ago_ms, ...device }) => ({
    ...device,
    last_seen: now - seen_ago_ms,
    registered_at: now - enrolled_ago_ms,
  }));
}

type TicketSeed = {
  title: string;
  severity: TicketSeverity;
  status: TicketStatus;
  source: string;
  device_id: string;
  description: string;
  finding_ref: string;
  assignee?: string;
  /** created_at = now - age_ms. Seeds are listed oldest first. */
  age_ms: number;
  /** Terminal-state timestamp, as an offset after created_at. */
  closed_after_ms?: number;
  /** Transitions after creation, as offsets after created_at. */
  trail?: ReadonlyArray<{
    action: string;
    actor: string;
    offset_ms: number;
    note?: string;
  }>;
};

/**
 * Five tickets mirror the hardcoded `risks` list in app/risks/page.tsx
 * (高危 -> high, 中危 -> medium, 低危 -> low, and the same relative ages), plus
 * two extra tickets so the workflow enum is exercised end to end:
 *   - MKT-MBP-0847 explains that device's `needs_attention` state;
 *   - DESK-WIN-0521 is a `resolved` ticket, matching the risks page's
 *     "17 本周已处置" KPI.
 */
const TICKET_SEEDS: readonly TicketSeed[] = [
  // 0001 — already closed, so the resolved branch has demo coverage.
  {
    title: 'Windsurf MCP 配置中写入明文令牌',
    severity: 'medium',
    status: 'resolved',
    source: 'windsurf-mcp-config',
    device_id: 'DESK-WIN-0521',
    description:
      'mcp_config.json 内以明文保存供应商 API 令牌；已轮换凭据并改用系统钥匙串注入。',
    finding_ref:
      'secret_in_mcp_config:C:\\Users\\zhaolei\\.codeium\\windsurf\\mcp_config.json',
    assignee: '罗宁',
    age_ms: 2 * DAY,
    closed_after_ms: 3 * HOUR,
    trail: [
      { action: 'acknowledge', actor: '罗宁', offset_ms: 12 * MINUTE },
      { action: 'investigate', actor: '罗宁', offset_ms: 40 * MINUTE },
      {
        action: 'resolve',
        actor: '罗宁',
        offset_ms: 3 * HOUR,
        note: '凭据已轮换，配置改为钥匙串引用；基线复核通过。',
      },
    ],
  },
  // 0002 — risks page row 5 (低危, 1 小时前).
  {
    title: '依赖包命中 CVE-2026-1847',
    severity: 'low',
    status: 'open',
    source: 'data-pipeline / requirements.txt',
    device_id: 'ENG-LT-0948',
    description:
      'Agent 生成的依赖清单固定了一个存在已知 CVE 的传递依赖版本，建议升级并锁定补丁版本。',
    finding_ref: 'vulnerable_dependency:data-pipeline/requirements.txt',
    age_ms: 1 * HOUR,
  },
  // 0003 — risks page row 4 (高危, 46 分钟前).
  {
    title: '未签名的 MCP 出站连接被放行',
    severity: 'high',
    status: 'acknowledged',
    source: 'postgres-mcp · 45.83.12.7',
    device_id: 'OPS-MBP-0314',
    description:
      'postgres-mcp 向未在企业白名单内的公网地址发起出站连接，且二进制缺少可信发布者签名。设备随后离线，需先恢复上报再研判。',
    finding_ref: 'unsigned_mcp_server:/Users/luoning/.cursor/mcp.json',
    assignee: '罗宁',
    age_ms: 46 * MINUTE,
    trail: [
      {
        action: 'acknowledge',
        actor: '罗宁',
        offset_ms: 9 * MINUTE,
        note: '已认领；设备当前离线，等待 EDR 侧确认出站目标归属。',
      },
    ],
  },
  // 0004 — risks page row 3 (中危, 31 分钟前).
  {
    title: '生成代码使用弱随机数创建会话令牌',
    severity: 'medium',
    status: 'investigating',
    source: 'payment-service / PR #184',
    device_id: 'ENG-LT-0948',
    description:
      'Codex CLI 在 payment-service PR #184 中使用非加密安全随机数生成会话令牌，需确认是否已合入主干。',
    finding_ref:
      'weak_crypto_in_generated_code:payment-service/src/session/token.ts',
    assignee: '周航',
    age_ms: 31 * MINUTE,
    trail: [
      { action: 'acknowledge', actor: '周航', offset_ms: 6 * MINUTE },
      {
        action: 'investigate',
        actor: '周航',
        offset_ms: 14 * MINUTE,
        note: '拉取 PR 差异与 CI 记录中。',
      },
    ],
  },
  // 0005 — extra: explains MKT-MBP-0847 being 需处理 on the devices page.
  {
    title: 'Agent 版本落后企业基线两个版本',
    severity: 'high',
    status: 'open',
    source: 'aegis-agent.version-posture',
    device_id: 'MKT-MBP-0847',
    description:
      '终端 Agent 仍为 v3.6（基线要求 v3.8），策略包同时停留在 v4.6，缺少最新的 MCP 出站校验规则。',
    finding_ref: 'outdated_agent:/usr/local/bin/aegis-agent',
    age_ms: 25 * MINUTE,
  },
  // 0006 — risks page row 2 (中危, 18 分钟前).
  {
    title: 'Skill 包含可疑的隐藏指令覆盖',
    severity: 'medium',
    status: 'open',
    source: 'prompt-helper.skill',
    device_id: 'ENG-MBP-1032',
    description:
      'prompt-helper Skill 在系统提示中嵌入了不可见的指令覆盖片段，可能改变 Agent 的工具调用边界。',
    finding_ref:
      'prompt_injection_artifact:/Users/chenhao/.cursor/skills/prompt-helper/SKILL.md',
    age_ms: 18 * MINUTE,
  },
  // 0007 — risks page row 1 (高危, 2 分钟前).
  {
    title: 'MCP Server 请求了未授权文件目录',
    severity: 'high',
    status: 'open',
    source: 'cursor-mcp-filesystem',
    device_id: 'MKT-LT-2841',
    description:
      'filesystem MCP Server 尝试读取声明作用域之外的目录，已被本地策略拦截并上报，等待安全运营研判。',
    finding_ref: 'mcp_unauthorized_path:/Users/linyan/.cursor/mcp.json',
    age_ms: 2 * MINUTE,
  },
];

/**
 * Allocates the next `TKT-YYYYMMDD-NNNN` id for the UTC day of `createdAt`.
 *
 * The sequence is derived by scanning the store rather than kept in a counter,
 * so it stays correct after a re-seed, a restart, or an out-of-band insert, and
 * can never collide with an id that is already present.
 */
export function nextTicketId(
  store: ReadonlyMap<string, Ticket>,
  createdAt: number,
): string {
  const prefix = `TKT-${ticketDay(createdAt)}-`;
  let highest = 0;
  for (const ticketId of store.keys()) {
    if (!ticketId.startsWith(prefix)) continue;
    const sequence = Number.parseInt(ticketId.slice(prefix.length), 10);
    if (Number.isSafeInteger(sequence) && sequence > highest)
      highest = sequence;
  }
  return `${prefix}${String(highest + 1).padStart(4, '0')}`;
}

/** `YYYYMMDD` in UTC — ticket ids must not shift with the server's timezone. */
export function ticketDay(timestamp: number): string {
  return new Date(timestamp).toISOString().slice(0, 10).replaceAll('-', '');
}

/** Returns seven fresh Ticket objects (never shared references), oldest first. */
export function seedTickets(): Ticket[] {
  const now = Date.now();
  const seeded = new Map<string, Ticket>();

  for (const seed of TICKET_SEEDS) {
    const createdAt = now - seed.age_ms;
    const history: TicketHistoryEntry[] = [
      {
        action: 'create',
        actor: 'aegis-collector',
        timestamp: createdAt,
        note: `由 ${seed.source} 自动上报生成。`,
      },
    ];

    for (const step of seed.trail ?? []) {
      history.push({
        action: step.action,
        actor: step.actor,
        timestamp: createdAt + step.offset_ms,
        ...(step.note === undefined ? {} : { note: step.note }),
      });
    }

    const isClosed = seed.status === 'resolved' || seed.status === 'dismissed';
    const resolvedAt =
      isClosed && seed.closed_after_ms !== undefined
        ? createdAt + seed.closed_after_ms
        : undefined;
    const lastEntry = history.at(-1);
    const updatedAt = Math.max(
      resolvedAt ?? 0,
      lastEntry?.timestamp ?? createdAt,
    );

    const ticket: Ticket = {
      ticket_id: nextTicketId(seeded, createdAt),
      title: seed.title,
      severity: seed.severity,
      status: seed.status,
      source: seed.source,
      device_id: seed.device_id,
      description: seed.description,
      finding_ref: seed.finding_ref,
      created_at: createdAt,
      updated_at: updatedAt,
      history,
      ...(seed.assignee === undefined ? {} : { assignee: seed.assignee }),
      ...(resolvedAt === undefined ? {} : { resolved_at: resolvedAt }),
    };
    seeded.set(ticket.ticket_id, ticket);
  }

  return Array.from(seeded.values());
}

/* ------------------------------------------------------------------ *
 * Store accessors (seed on first access)
 * ------------------------------------------------------------------ */

/** The live device registry, seeded with six demo devices on first access. */
export function getDeviceStore(): Map<string, Device> {
  const existing = globals.__aegis_devices;
  if (existing) return existing;

  // Start EMPTY — real device data comes from the Collector.
  // Console-side registry is only for manually registered devices.
  const store = new Map<string, Device>();
  globals.__aegis_devices = store;
  return store;
}

/** The live ticket registry. Starts empty; tickets are created from real findings. */
export function getTicketStore(): Map<string, Ticket> {
  const existing = globals.__aegis_tickets;
  if (existing) return existing;

  // Start EMPTY — no fake demo tickets.
  const store = new Map<string, Ticket>();
  globals.__aegis_tickets = store;
  return store;
}

/* ------------------------------------------------------------------ *
 * Audit log
 *
 * An append-only, per-isolate trail of every governance mutation. It mirrors the
 * `audit_log` D1 table one-for-one so the in-memory demo store and the
 * production D1 adapter (lib/d1-store.ts) expose the same shape. Like the device
 * and ticket registries this is ephemeral — swap `getAuditStore` / `logAudit` for
 * the D1 helpers before this drives real compliance reporting.
 *
 * Timestamps are epoch **milliseconds**, matching every other timestamp in this
 * module (and what `date-fns` on the client expects).
 * ------------------------------------------------------------------ */

/** The resource an audit entry describes. */
export const AUDIT_RESOURCE_TYPES = [
  'device',
  'ticket',
  'policy',
  'system',
] as const;
export type AuditResourceType = (typeof AUDIT_RESOURCE_TYPES)[number];

export interface AuditEntry {
  /** Monotonic within one isolate; the D1 `AUTOINCREMENT` id in production. */
  id: number;
  /** Epoch milliseconds. */
  timestamp: number;
  actor: string;
  /**
   * Verb, namespaced by resource: 'device:create', 'device:update',
   * 'device:delete', 'ticket:create', 'ticket:transition', 'ticket:assign',
   * 'policy:publish'.
   */
  action: string;
  resource_type: AuditResourceType;
  resource_id?: string;
  detail?: string;
}

export function isAuditResourceType(
  value: unknown,
): value is AuditResourceType {
  return oneOf(AUDIT_RESOURCE_TYPES, value);
}

/** Actor recorded when a caller does not identify itself. */
const DEFAULT_AUDIT_ACTOR = 'console_user';

/** Hard ceiling so a long-lived isolate cannot grow the trail without bound. */
const MAX_AUDIT_ENTRIES = 1_000;

type AuditSeed = Omit<AuditEntry, 'id' | 'timestamp'> & { ago_ms: number };

/**
 * Five demo entries: recent device registrations and ticket transitions that
 * line up with the seeded devices/tickets above, oldest first.
 */
const AUDIT_SEEDS: readonly AuditSeed[] = [
  {
    ago_ms: 26 * HOUR,
    actor: 'aegis-collector',
    action: 'device:create',
    resource_type: 'device',
    resource_id: 'OPS-MBP-0314',
    detail: '运维部终端接入注册表，Claude Code Agent 首次上报。',
  },
  {
    ago_ms: 3 * HOUR,
    actor: '罗宁',
    action: 'ticket:transition',
    resource_type: 'ticket',
    resource_id: 'TKT-DEMO-0001',
    detail: '工单状态 investigating → resolved：MCP 明文令牌已轮换。',
  },
  {
    ago_ms: 96 * MINUTE,
    actor: '陈昊',
    action: 'device:create',
    resource_type: 'device',
    resource_id: 'ENG-MBP-1032',
    detail: '研发部 Cursor 企业版终端完成纳管，Skill 白名单已生效。',
  },
  {
    ago_ms: 9 * MINUTE,
    actor: '罗宁',
    action: 'ticket:transition',
    resource_type: 'ticket',
    resource_id: 'TKT-DEMO-0003',
    detail: '工单状态 open → acknowledged：已认领未签名 MCP 出站事件。',
  },
  {
    ago_ms: 2 * MINUTE,
    actor: 'aegis-collector',
    action: 'ticket:create',
    resource_type: 'ticket',
    resource_id: 'TKT-DEMO-0007',
    detail: '由 cursor-mcp-filesystem 自动上报，创建高危工单。',
  },
];

/** Returns five fresh AuditEntry objects (never shared references), oldest first. */
export function seedAudit(): AuditEntry[] {
  const now = Date.now();
  return AUDIT_SEEDS.map(({ ago_ms, ...entry }, index) => ({
    id: index + 1,
    timestamp: now - ago_ms,
    ...entry,
  }));
}

/** Next monotonic id for the in-memory audit array. */
function nextAuditId(entries: readonly AuditEntry[]): number {
  return entries.reduce((highest, entry) => Math.max(highest, entry.id), 0) + 1;
}

/**
 * The live audit trail, seeded with five demo entries on first access. Newest
 * entries are appended at the end; readers sort/filter as needed.
 */
export function getAuditStore(): AuditEntry[] {
  const existing = globals.__aegis_audit;
  if (existing) return existing;

  const store: AuditEntry[] = [];
  globals.__aegis_audit = store;
  return store;
}

/**
 * Appends one audit entry, stamping `id` and `timestamp` server-side so a caller
 * can never forge the trail's ordering. Returns the stored entry.
 */
export function logAudit(
  entry: Omit<AuditEntry, 'id' | 'timestamp'>,
): AuditEntry {
  const store = getAuditStore();
  const record: AuditEntry = {
    id: nextAuditId(store),
    timestamp: Date.now(),
    actor: entry.actor || DEFAULT_AUDIT_ACTOR,
    action: entry.action,
    resource_type: entry.resource_type,
    ...(entry.resource_id === undefined
      ? {}
      : { resource_id: entry.resource_id }),
    ...(entry.detail === undefined ? {} : { detail: entry.detail }),
  };
  store.push(record);
  // Drop oldest first once the cap is reached, keeping the trail bounded.
  if (store.length > MAX_AUDIT_ENTRIES)
    store.splice(0, store.length - MAX_AUDIT_ENTRIES);
  return record;
}
