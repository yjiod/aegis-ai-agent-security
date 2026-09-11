/**
 * app/api/devices/route.ts — device registry CRUD for the Aegis console.
 *
 * GET    /api/devices                 -> registry list + (optional) live fleet summary
 * POST   /api/devices                 -> register a device            (201)
 * PUT    /api/devices                 -> update device metadata       (200)
 * DELETE /api/devices?device_id=ID    -> remove from the registry     (200)
 *
 * The registry is the in-memory demo store in lib/store.ts. In production it must
 * be backed by D1 (or the Collector's SQLite) — see the note at the top of that
 * file. GET additionally tries the authenticated, read-only Collector summary so
 * the fleet KPIs can be real while per-device rows stay demo data, which is
 * exactly the "混合只读模式" the devices page already describes.
 */

import { NextResponse } from 'next/server';
import type { FleetSummary } from '@/components/collector-context';
import {
  apiError,
  boundedString,
  boundedTimestamp,
  boundedVersion,
  jsonResponse,
  methodNotAllowed,
  readJsonObject,
} from '@/lib/api';
import {
  DEVICE_ID_PATTERN,
  getDeviceStore,
  getTicketStore,
  isAgentType,
  isDeviceStatus,
  logAudit,
  type AgentType,
  type Device,
  type DeviceStatus,
  type FindingsSummary,
} from '@/lib/store';

export const dynamic = 'force-dynamic';

/** Methods this collection resource really implements (used for the 405 Allow). */
const ALLOW = 'DELETE, GET, POST, PUT';

/** Conservative hostname/FQDN shape. */
const HOSTNAME_PATTERN = /^[A-Za-z0-9._-]{1,253}$/;

const MAX_HOSTNAME = 253;
const MAX_OWNER = 128;
const MAX_NOTES = 2_000;

/** Version recorded before a device has ever uploaded a report. */
const UNREPORTED = 'unreported';

/**
 * Fields a client may never write on registration: they are derived from
 * Collector reports or stamped by the server. Rejecting them beats silently
 * ignoring them — a governance console must not look like it accepted a forged
 * posture.
 */
const READ_ONLY_ON_CREATE = [
  'status',
  'last_seen',
  'registered_at',
  'findings_summary',
] as const;

/**
 * Stamped once at enrolment and never editable. `device_id` is not listed here
 * because a PUT body must carry it as the lookup key; renaming a device is a
 * delete + re-register, not an update.
 */
const IMMUTABLE = ['registered_at'] as const;

/* ------------------------------------------------------------------ *
 * Collector summary (read-only, fail-soft)
 * ------------------------------------------------------------------ */

const LEVELS = ['critical', 'high', 'normal'] as const;
const POSTURES = [
  'current',
  'agent_mismatch',
  'policy_mismatch',
  'both_mismatch',
  'unknown',
] as const;
const CREDENTIAL_POSTURES = ['current', 'previous', 'legacy'] as const;

function isCount(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}

function isShortString(value: unknown): value is string {
  return typeof value === 'string' && value.length >= 1 && value.length <= 64;
}

/** Every key must be a count, and they must sum to `total`. */
function validCounts(
  block: unknown,
  keys: readonly string[],
  total: number,
): block is Record<string, number> {
  if (!block || typeof block !== 'object' || Array.isArray(block)) return false;
  const record = block as Record<string, unknown>;
  if (!keys.every((key) => isCount(record[key]))) return false;
  return keys.reduce((sum, key) => sum + Number(record[key]), 0) === total;
}

/**
 * Validates the Collector's `/v1/summary` payload and returns only the fields the
 * console understands. Anything unexpected -> null, which degrades to demo mode
 * instead of surfacing unvalidated numbers.
 */
function sanitizedFleet(value: unknown): FleetSummary | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const data = value as Record<string, unknown>;
  const total = data.total_devices;
  const active = data.active_devices;
  const stale = data.stale_devices;
  if (!isCount(total) || !isCount(active) || !isCount(stale)) return null;
  if (active + stale !== total) return null;
  if (!isShortString(data.required_agent_version)) return null;
  if (!isShortString(data.required_policy_version)) return null;
  if (!validCounts(data.latest_severity, LEVELS, total)) return null;
  if (!validCounts(data.version_posture, POSTURES, total)) return null;

  const severity = data.latest_severity;
  const posture = data.version_posture;
  // Optional block: only echoed when it is present *and* internally consistent.
  const credentials = validCounts(
    data.credential_posture,
    CREDENTIAL_POSTURES,
    total,
  )
    ? data.credential_posture
    : null;

  return {
    total_devices: total,
    active_devices: active,
    stale_devices: stale,
    required_agent_version: data.required_agent_version,
    required_policy_version: data.required_policy_version,
    latest_severity: {
      critical: severity.critical,
      high: severity.high,
      normal: severity.normal,
    },
    version_posture: {
      current: posture.current,
      agent_mismatch: posture.agent_mismatch,
      policy_mismatch: posture.policy_mismatch,
      both_mismatch: posture.both_mismatch,
      unknown: posture.unknown,
    },
    ...(credentials
      ? {
          credential_posture: {
            current: credentials.current,
            previous: credentials.previous,
            legacy: credentials.legacy,
          },
        }
      : {}),
  };
}

/**
 * Reads the Collector summary behind the same guards app/api/summary/route.ts
 * uses (allowlisted host, no embedded credentials or query, https unless local
 * dev, size cap, hard timeout). Never throws: `null` means "demo mode".
 */
async function fetchFleetSummary(): Promise<FleetSummary | null> {
  const endpoint = process.env.AEGIS_COLLECTOR_URL;
  const allowedHost = process.env.AEGIS_COLLECTOR_ALLOWED_HOST;
  const token = process.env.AEGIS_COLLECTOR_TOKEN;
  if (!endpoint || !allowedHost || !token) return null;
  if (token.length < 32 || token.length > 4_096) return null;

  let target: URL;
  try {
    const base = new URL(endpoint);
    const isLocalDev =
      process.env.NODE_ENV === 'development' &&
      (base.hostname === '127.0.0.1' || base.hostname === 'localhost');
    if (
      (!isLocalDev && base.protocol !== 'https:') ||
      base.hostname.toLowerCase() !== allowedHost.toLowerCase() ||
      base.username ||
      base.password ||
      base.search ||
      base.hash
    ) {
      return null;
    }
    target = new URL('/v1/summary', base.origin);
  } catch {
    return null;
  }

  try {
    const response = await fetch(target, {
      headers: { Authorization: `Bearer ${token}`, Accept: 'application/json' },
      cache: 'no-store',
      signal: AbortSignal.timeout(5_000),
    });
    if (!response.ok) return null;
    const declared = Number(response.headers.get('content-length') ?? 0);
    if (Number.isSafeInteger(declared) && declared > 65_536) return null;
    return sanitizedFleet(await response.json());
  } catch {
    // Collector down, slow, or unconfigured: the registry still answers.
    return null;
  }
}

/* ------------------------------------------------------------------ *
 * Field readers
 *
 * Each reader pushes a human-readable problem onto `problems` and returns null on
 * failure, so a single 400 can report every bad field at once and the happy path
 * stays free of type assertions.
 * ------------------------------------------------------------------ */

function readDeviceId(value: unknown, problems: string[]): string | null {
  const deviceId = typeof value === 'string' ? value.trim() : '';
  if (!DEVICE_ID_PATTERN.test(deviceId)) {
    problems.push('device_id must be 3-64 characters of [A-Za-z0-9-]');
    return null;
  }
  return deviceId;
}

function readHostname(value: unknown, problems: string[]): string | null {
  const hostname = boundedString(value, MAX_HOSTNAME);
  if (hostname === null || !HOSTNAME_PATTERN.test(hostname)) {
    problems.push(
      `hostname must be 1-${MAX_HOSTNAME} characters of [A-Za-z0-9._-]`,
    );
    return null;
  }
  return hostname;
}

function readOwner(value: unknown, problems: string[]): string | null {
  const owner = boundedString(value, MAX_OWNER);
  if (owner === null) {
    problems.push(
      `owner must be a non-empty string of at most ${MAX_OWNER} characters`,
    );
    return null;
  }
  return owner;
}

function readAgentType(value: unknown, problems: string[]): AgentType | null {
  if (!isAgentType(value)) {
    problems.push(
      "agent_type must be one of 'cursor', 'claude_code', 'codex_cli', 'windsurf', 'other'",
    );
    return null;
  }
  return value;
}

function readStatus(value: unknown, problems: string[]): DeviceStatus | null {
  if (!isDeviceStatus(value)) {
    problems.push(
      "status must be one of 'online', 'offline', 'stale', 'needs_attention'",
    );
    return null;
  }
  return value;
}

function readVersion(
  field: 'agent_version' | 'policy_version',
  value: unknown,
  problems: string[],
): string | null {
  const version = boundedVersion(value);
  if (version === null) {
    problems.push(`${field} must match [A-Za-z0-9._+-]{1,64}`);
    return null;
  }
  return version;
}

function readLastSeen(value: unknown, problems: string[]): number | null {
  const lastSeen = boundedTimestamp(value);
  if (lastSeen === null) {
    problems.push(
      'last_seen must be a non-negative integer (epoch milliseconds)',
    );
    return null;
  }
  return lastSeen;
}

function readFindingsSummary(
  value: unknown,
  problems: string[],
): FindingsSummary | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    problems.push('findings_summary must be an object');
    return null;
  }
  const record = value as Record<string, unknown>;
  const critical = record.critical;
  const high = record.high;
  const medium = record.medium;
  const low = record.low;
  if (
    !isCount(critical) ||
    !isCount(high) ||
    !isCount(medium) ||
    !isCount(low)
  ) {
    problems.push(
      'findings_summary must contain non-negative integers for critical, high, medium and low',
    );
    return null;
  }
  return { critical, high, medium, low };
}

/** `notes` is tri-state on update: absent, cleared (null/""), or set. */
type NotesPatch =
  | { kind: 'absent' }
  | { kind: 'clear' }
  | { kind: 'set'; value: string };

function readNotes(
  body: Record<string, unknown>,
  problems: string[],
): NotesPatch {
  if (!('notes' in body)) return { kind: 'absent' };
  const raw = body.notes;
  if (raw === null || (typeof raw === 'string' && raw.trim() === '')) {
    return { kind: 'clear' };
  }
  const notes = boundedString(raw, MAX_NOTES);
  if (notes === null) {
    problems.push(`notes must be a string of at most ${MAX_NOTES} characters`);
    // Safe: a non-empty `problems` always short-circuits before anything is applied.
    return { kind: 'absent' };
  }
  return { kind: 'set', value: notes };
}

/** Rejects server-managed fields appearing in a client body. */
function findForbidden(
  body: Record<string, unknown>,
  fields: readonly string[],
): string[] {
  return fields.filter((field) => field in body);
}

/* ------------------------------------------------------------------ *
 * Handlers
 * ------------------------------------------------------------------ */

/**
 * GET /api/devices
 *
 * Returns the registry in insertion order (the six seeded devices first, matching
 * app/devices/page.tsx) plus the live fleet summary when the Collector is
 * reachable. `connected: false` is not an error — it is the console's demo mode.
 */
export async function GET(): Promise<NextResponse> {
  const devices = Array.from(getDeviceStore().values());
  const fleet = await fetchFleetSummary();

  return jsonResponse({
    devices,
    count: devices.length,
    connected: fleet !== null,
    source: fleet === null ? 'demo' : 'live',
    fleet,
  });
}

/**
 * POST /api/devices — register a device.
 *
 * Body: `{ device_id, hostname, owner, agent_type, notes?, agent_version?, policy_version? }`
 * 201 on success; 409 when the device_id is already registered.
 */
export async function POST(request: Request): Promise<NextResponse> {
  const parsed = await readJsonObject(request);
  if (!parsed.ok) return parsed.response;
  const body = parsed.value;

  const forbidden = findForbidden(body, READ_ONLY_ON_CREATE);
  if (forbidden.length > 0) {
    return apiError(
      'read_only_field',
      'These fields are managed by the server and cannot be set on registration.',
      400,
      forbidden.map((field) => `${field} is read-only`),
    );
  }

  const problems: string[] = [];
  const deviceId = readDeviceId(body.device_id, problems);
  const hostname = readHostname(body.hostname, problems);
  const owner = readOwner(body.owner, problems);
  const agentType = readAgentType(body.agent_type, problems);
  const notes = readNotes(body, problems);

  // Optional: a freshly enrolled device has usually not reported a version yet.
  let agentVersion = UNREPORTED;
  if ('agent_version' in body && body.agent_version !== null) {
    const value = readVersion('agent_version', body.agent_version, problems);
    if (value !== null) agentVersion = value;
  }
  let policyVersion = UNREPORTED;
  if ('policy_version' in body && body.policy_version !== null) {
    const value = readVersion('policy_version', body.policy_version, problems);
    if (value !== null) policyVersion = value;
  }

  if (problems.length > 0 || !deviceId || !hostname || !owner || !agentType) {
    return apiError(
      'validation_failed',
      'Device registration was rejected.',
      400,
      problems,
    );
  }

  const store = getDeviceStore();
  if (store.has(deviceId)) {
    return apiError(
      'device_already_registered',
      `Device ${deviceId} is already in the registry; use PUT to update it.`,
      409,
    );
  }

  const device: Device = {
    device_id: deviceId,
    hostname,
    owner,
    agent_type: agentType,
    agent_version: agentVersion,
    policy_version: policyVersion,
    // Offline until the Collector actually hears from it; last_seen 0 = never.
    status: 'offline',
    last_seen: 0,
    registered_at: Date.now(),
    ...(notes.kind === 'set' ? { notes: notes.value } : {}),
  };
  store.set(deviceId, device);

  logAudit({
    actor: 'console_user',
    action: 'device:create',
    resource_type: 'device',
    resource_id: deviceId,
    detail: `注册设备 ${hostname}（负责人 ${owner}，${agentType}）。`,
  });

  return jsonResponse({ device, created: true }, 201);
}

/**
 * PUT /api/devices — update device metadata.
 *
 * Body: `{ device_id, ...fields }`; at least one updatable field is required.
 * 404 when the device is not registered. `device_id` identifies the target and
 * cannot itself be changed.
 */
export async function PUT(request: Request): Promise<NextResponse> {
  const parsed = await readJsonObject(request);
  if (!parsed.ok) return parsed.response;
  const body = parsed.value;

  const immutable = findForbidden(body, IMMUTABLE);
  if (immutable.length > 0) {
    return apiError(
      'immutable_field',
      'registered_at is stamped once at enrolment and cannot be changed.',
      400,
      immutable.map((field) => `${field} is immutable`),
    );
  }

  const keyProblems: string[] = [];
  const deviceId = readDeviceId(body.device_id, keyProblems);
  if (deviceId === null) {
    return apiError(
      'validation_failed',
      'device_id is required to identify the device to update.',
      400,
      keyProblems,
    );
  }

  const store = getDeviceStore();
  const existing = store.get(deviceId);
  if (!existing) {
    return apiError(
      'device_not_found',
      `No device registered with id ${deviceId}.`,
      404,
    );
  }

  const problems: string[] = [];
  const patch: Partial<Device> = {};

  if ('hostname' in body) {
    const hostname = readHostname(body.hostname, problems);
    if (hostname !== null) patch.hostname = hostname;
  }
  if ('owner' in body) {
    const owner = readOwner(body.owner, problems);
    if (owner !== null) patch.owner = owner;
  }
  if ('agent_type' in body) {
    const agentType = readAgentType(body.agent_type, problems);
    if (agentType !== null) patch.agent_type = agentType;
  }
  if ('agent_version' in body) {
    const version = readVersion('agent_version', body.agent_version, problems);
    if (version !== null) patch.agent_version = version;
  }
  if ('policy_version' in body) {
    const version = readVersion(
      'policy_version',
      body.policy_version,
      problems,
    );
    if (version !== null) patch.policy_version = version;
  }
  if ('status' in body) {
    const status = readStatus(body.status, problems);
    if (status !== null) patch.status = status;
  }
  if ('last_seen' in body) {
    const lastSeen = readLastSeen(body.last_seen, problems);
    if (lastSeen !== null) patch.last_seen = lastSeen;
  }
  if ('findings_summary' in body) {
    const summary = readFindingsSummary(body.findings_summary, problems);
    if (summary !== null) patch.findings_summary = summary;
  }

  const notes = readNotes(body, problems);
  const notesChanged = notes.kind === 'set' || notes.kind === 'clear';

  if (problems.length > 0) {
    return apiError(
      'validation_failed',
      'Device update was rejected.',
      400,
      problems,
    );
  }
  if (Object.keys(patch).length === 0 && !notesChanged) {
    return apiError(
      'no_updatable_fields',
      'Provide at least one updatable field besides device_id.',
      400,
    );
  }

  const updated: Device = { ...existing, ...patch };
  if (notes.kind === 'set') updated.notes = notes.value;
  else if (notes.kind === 'clear') delete updated.notes;

  store.set(deviceId, updated);

  const changedFields = [...Object.keys(patch), ...(notesChanged ? ['notes'] : [])];
  logAudit({
    actor: 'console_user',
    action: 'device:update',
    resource_type: 'device',
    resource_id: deviceId,
    detail: `更新设备字段：${changedFields.join(', ')}。`,
  });

  return jsonResponse({ device: updated, updated: true });
}

/**
 * DELETE /api/devices?device_id=ID — drop a device from the registry.
 *
 * Tickets referencing the device are intentionally retained: a governance audit
 * trail must outlive the asset it describes. The response reports how many were
 * left behind so the caller can warn the operator.
 */
export async function DELETE(request: Request): Promise<NextResponse> {
  const problems: string[] = [];
  const deviceId = readDeviceId(
    new URL(request.url).searchParams.get('device_id'),
    problems,
  );
  if (deviceId === null) {
    return apiError(
      'validation_failed',
      'The device_id query parameter is required.',
      400,
      problems,
    );
  }

  const store = getDeviceStore();
  if (!store.has(deviceId)) {
    return apiError(
      'device_not_found',
      `No device registered with id ${deviceId}.`,
      404,
    );
  }
  store.delete(deviceId);

  let retainedTickets = 0;
  for (const ticket of getTicketStore().values()) {
    if (ticket.device_id === deviceId) retainedTickets += 1;
  }

  logAudit({
    actor: 'console_user',
    action: 'device:delete',
    resource_type: 'device',
    resource_id: deviceId,
    detail: `从注册表移除设备，保留 ${retainedTickets} 条关联工单。`,
  });

  return jsonResponse({
    deleted: true,
    device_id: deviceId,
    retained_tickets: retainedTickets,
  });
}

/** PATCH is not implemented — PUT rewrites the mutable fields wholesale. */
export function PATCH(): NextResponse {
  return methodNotAllowed(ALLOW);
}
