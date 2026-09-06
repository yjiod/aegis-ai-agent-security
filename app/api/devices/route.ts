/**
 * app/api/devices/route.ts — device registry CRUD for the Aegis console.
 *
 * GET    /api/devices                 -> registry list + (optional) live fleet summary
 * POST   /api/devices                 -> register a device            (201)
 * PUT    /api/devices                 -> update device metadata      (200)
 * DELETE /api/devices?device_id=ID    -> remove from the registry    (200)
 *
 * The registry itself is the in-memory demo store in lib/store.ts. In production
 * it must be backed by D1 (or the Collector's SQLite) — see the note at the top
 * of that file. GET additionally tries the authenticated, read-only Collector
 * summary so the fleet KPIs can be real while the per-device rows stay demo data,
 * exactly like the "混合只读模式" the devices page already describes.
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
  getDeviceStore,
  getTicketStore,
  isAgentType,
  isDeviceStatus,
  type AgentType,
  type Device,
  type DeviceStatus,
  type FindingsSummary,
} from '@/lib/store';

export const dynamic = 'force-dynamic';

/** Methods this collection resource really implements (used for 405 `Allow`). */
const ALLOW = 'DELETE, GET, POST, PUT';

/**
 * device_id is the join key between the console, the Collector and EDR, so the
 * shape is fixed: 3-64 chars of ASCII alphanumerics and hyphens. No dots, no
 * slashes, no unicode — it ends up in URLs, log lines and file paths.
 */
const DEVICE_ID_PATTERN = /^[A-Za-z0-9-]{3,64}$/;

/** Conservative hostname/FQDN shape; also what the Collector accepts. */
const HOSTNAME_PATTERN = /^[A-Za-z0-9._-]{1,253}$/;

const MAX_OWNER = 128;
const MAX_NOTES = 2_000;

/** Version reported before a device has ever uploaded a report. */
const UNREPORTED = 'unreported';

/**
 * Fields the client may never write: they are derived from Collector reports or
 * stamped by the server. Rejecting them beats silently ignoring them, because a
 * governance console must not look like it accepted a forged posture.
 */
const READ_ONLY_ON_CREATE = ['status', 'last_seen', 'registered_at', 'findings_summary'] as const;
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

/** Counts must all be present and sum to `total_devices`. */
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
 * rather than surfacing unvalidated numbers.
 */
function sanitizedFleet(value: unknown): FleetSummary | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const data = value as Record<string, unknown>;
  const { total_devices: total, active_devices: active, stale_devices: stale } = data;
  if (!isCount(total) || !isCount(active) || !isCount(stale)) return null;
  if (active + stale !== total) return null;
  if (!isShortString(data.required_agent_version)) return null;
  if (!isShortString(data.required_policy_version)) return null;
  if (!validCounts(data.latest_severity, LEVELS, total)) return null;
  if (!validCounts(data.version_posture, POSTURES, total)) return null;

  const severity = data.latest_severity as Record<string, number>;
  const posture = data.version_posture as Record<string, number>;
  const hasCredentials = validCounts(data.credential_posture, CREDENTIAL_POSTURES, total);
  const credentials = hasCredentials
    ? (data.credential_posture as Record<string, number>)
    : undefined;

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
 * Reads the Collector summary with the same guards app/api/summary/route.ts uses
 * (allowlisted host, no embedded credentials/query, https unless local dev,
 * bounded body, hard timeout). Never throws: `null` means "demo mode".
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
    // Collector down, slow, or not configured: the registry still answers.
    return null;
  }
}

/* ------------------------------------------------------------------ *
 * Field readers
 * ------------------------------------------------------------------ */

/**
 * `notes` may be cleared with an empty string on update. Returns
 * `{ value: undefined }` to mean "remove the key".
 */
function readNotes(
  body: Record<string, unknown>,
  problems: string[],
): { present: boolean; value?: string } {
  if (!('notes' in body)) return { present: false };
  const raw = body.notes;
  if (raw === null || (typeof raw === 'string' && raw.trim() === '')) {
    return { present: true, value: undefined };
  }
  const notes = boundedString(raw, MAX_NOTES);
  if (notes === null) {
    problems.push(`notes must be a non-empty string of at most ${MAX_NOTES} characters`);
    return { present: true, value: undefined };
  }
  return { present: true, value: notes };
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
  const keys = ['critical', 'high', 'medium', 'low'] as const;
  if (!keys.every((key) => isCount(record[key]))) {
    problems.push(
      'findings_summary must contain non-negative integers for critical, high, medium and low',
    );
    return null;
  }
  return {
    critical: record.critical as number,
    high: record.high as number,
    medium: record.medium as number,
    low: record.low as number,
  };
}

function rejectReadOnlyFields(
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
 * Returns the registry in insertion order (the seeded six first, matching
 * app/devices/page.tsx) alongside the live fleet summary when the Collector is
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
    ...(fleet === null ? { fleet: null } : { fleet }),
  });
}

/**
 * POST /api/devices — register a device.
 * Body: `{ device_id, hostname, owner, agent_type, notes?, agent_version?, policy_version? }`
 * 201 on success, 409 if the device_id is already registered.
 */
export async function POST(request: Request): Promise<NextResponse> {
  const parsed = await readJsonObject(request);
  if (!parsed.ok) return parsed.response;
  const body = parsed.value;

  const readOnly = rejectReadOnlyFields(body, READ_ONLY_ON_CREATE);
  if (readOnly.length > 0) {
    return apiError(
      'read_only_field',
      'These fields are managed by the server and cannot be set on registration.',
      400,
      readOnly.map((field) => `${field} is read-only`),
    );
  }

  const problems: string[] = [];

  const deviceId = typeof body.device_id === 'string' ? body.device_id.trim() : '';
  if (!DEVICE_ID_PATTERN.test(deviceId)) {
    problems.push('device_id must be 3-64 characters of [A-Za-z0-9-]');
  }

  const hostname = boundedString(body.hostname, 253);
  if (hostname === null || !HOSTNAME_PATTERN.test(hostname)) {
    problems.push('hostname must be 1-253 characters of [A-Za-z0-9._-]');
  }

  const owner = boundedString(body.owner, MAX_OWNER);
  if (owner === null) {
    problems.push(`owner must be a non-empty string of at most ${MAX_OWNER} characters`);
  }

  if (!isAgentType(body.agent_type)) {
    problems.push(
      "agent_type must be one of 'cursor', 'claude_code', 'codex_cli', 'windsurf', 'other'",
    );
  }

  // Optional versions: a freshly enrolled device has usually not reported yet.
  let agentVersion = UNREPORTED;
  if ('agent_version' in body && body.agent_version !== null) {
    const value = boundedVersion(body.agent_version);
    if (value === null) {
      problems.push('agent_version must match [A-Za-z0-9._+-]{1,64}');
    } else {
      agentVersion = value;
    }
  }

  let policyVersion = UNREPORTED;
  if ('policy_version' in body && body.policy_version !== null) {
    const value = boundedVersion(body.policy_version);
    if (value === null) {
      problems.push('policy_version must match [A-Za-z0-9._+-]{1,64}');
    } else {
      policyVersion = value;
    }
  }

  const notes = readNotes(body, problems);

  if (problems.length > 0) {
    return apiError('validation_failed', 'Device registration was rejected.', 400, problems);
  }

  const store = getDeviceStore();
  if (store.has(deviceId)) {
    return apiError(
      'device_already_registered',
      `Device ${deviceId} is already in the registry; use PUT to update it.`,
      409,
    );
  }

  const now = Date.now();
  const device: Device = {
    device_id: deviceId,
    hostname: hostname as string,
    owner: owner as string,
    agent_type: body.agent_type as AgentType,
    agent_version: agentVersion,
    policy_version: policyVersion,
    // A device that has never reported is offline until the Collector hears from it.
    status: 'offline',
    last_seen: 0,
    registered_at: now,
    ...(notes.value === undefined ? {} : { notes: notes.value }),
  };
  store.set(deviceId, device);

  return jsonResponse({ device, created: true }, 201);
}

/**
 * PUT /api/devices — update device metadata.
 * Body: `{ device_id, ...fields }`; at least one updatable field is required.
 * 404 when the device is not registered.
 */
export async function PUT(request: Request): Promise<NextResponse> {
  const parsed = await readJsonObject(request);
  if (!parsed.ok) return parsed.response;
  const body = parsed.value;

  const immutable = rejectReadOnlyFields(body, IMMUTABLE);
  if (immutable.length > 0) {
    return apiError(
      'immutable_field',
      'registered_at is stamped once at enrolment and cannot be changed.',
      400,
      immutable.map((field) => `${field} is immutable`),
    );
  }

  const problems: string[] = [];

  const deviceId = typeof body.device_id === 'string' ? body.device_id.trim() : '';
  if (!DEVICE_ID_PATTERN.test(deviceId)) {
    return apiError(
      'validation_failed',
      'device_id is required to identify the device to update.',
      400,
      ['device_id must be 3-64 characters of [A-Za-z0-9-]'],
    );
  }

  const store = getDeviceStore();
  const existing = store.get(deviceId);
  if (!existing) {
    return apiError('device_not_found', `No device registered with id ${deviceId}.`, 404);
  }

  const patch: Partial<Device> = {};

  if ('hostname' in body) {
    const hostname = boundedString(body.hostname, 253);
    if (hostname === null || !HOSTNAME_PATTERN.test(hostname)) {
      problems.push('hostname must be 1-253 characters of [A-Za-z0-9._-]');
    } else {
      patch.hostname = hostname;
    }
  }

  if ('owner' in body) {
    const owner = boundedString(body.owner, MAX_OWNER);
    if (owner === null) {
      problems.push(`owner must be a non-empty string of at most ${MAX_OWNER} characters`);
    } else {
      patch.owner = owner;
    }
  }

  if ('agent_type' in body) {
    if (!isAgentType(body.agent_type)) {
      problems.push(
        "agent_type must be one of 'cursor', 'claude_code', 'codex_cli', 'windsurf', 'other'",
      );
    } else {
      patch.agent_type = body.agent_type;
    }
  }

  if ('agent_version' in body) {
    const value = boundedVersion(body.agent_version);
    if (value === null) {
      problems.push('agent_version must match [A-Za-z0-9._+-]{1,64}');
    } else {
      patch.agent_version = value;
    }
  }

  if ('policy_version' in body) {
    const value = boundedVersion(body.policy_version);
    if (value === null) {
      problems.push('policy_version must match [A-Za-z0-9._+-]{1,64}');
    } else {
      patch.policy_version = value;
    }
  }

  if ('status' in body) {
    if (!isDeviceStatus(body.status)) {
      problems.push(
        "status must be one of 'online', 'offline', 'stale', 'needs_attention'",
      );
    } else {
      patch.status = body.status as DeviceStatus;
    }
  }

  if ('last_seen' in body) {
    const value = boundedTimestamp(body.last_seen);
    if (value === null) {
      problems.push('last_seen must be a non-negative integer (epoch milliseconds)');
    } else {
      patch.last_seen = value;
    }
  }

  if ('findings_summary' in body) {
    const value = readFindingsSummary(body.findings_summary, problems);
    if (value !== null) patch.findings_summary = value;
  }

  const notes = readNotes(body, problems);
  const notesCleared = notes.present && notes.value === undefined && 'notes' in body;

  if (problems.length > 0) {
    return apiError('validation_failed', 'Device update was rejected.', 400, problems);
  }

  const changedFields = Object.keys(patch).length + (notes.present ? 1 : 0);
  if (changedFields === 0) {
    return apiError(
      'no_updatable_fields',
      'Provide at least one updatable field besides device_id.',
      400,
    );
  }

  const updated: Device = { ...existing, ...patch };
  if (notes.present) {
    if (notes.value === undefined) delete updated.notes;
    else updated.notes = notes.value;
  }
  // `delete` above can leave the key absent; make the "cleared" case explicit.
  if (notesCleared) delete updated.notes;

  store.set(deviceId, updated);
  return jsonResponse({ device: updated, updated: true });
}

/**
 * DELETE /api/devices?device_id=ID — drop a device from the registry.
 *
 * Tickets referencing the device are intentionally retained: a governance audit
 * trail must outlive the asset it describes. The response reports how many were
 * left behind so a caller can warn the operator.
 */
export async function DELETE(request: Request): Promise<NextResponse> {
  const deviceId = new URL(request.url).searchParams.get('device_id')?.trim() ?? '';
  if (!DEVICE_ID_PATTERN.test(deviceId)) {
    return apiError(
      'validation_failed',
      'The device_id query parameter is required.',
      400,
      ['device_id must be 3-64 characters of [A-Za-z0-9-]'],
    );
  }

  const store = getDeviceStore();
  if (!store.has(deviceId)) {
    return apiError('device_not_found', `No device registered with id ${deviceId}.`, 404);
  }
  store.delete(deviceId);

  let retainedTickets = 0;
  for (const ticket of getTicketStore().values()) {
    if (ticket.device_id === deviceId) retainedTickets += 1;
  }

  return jsonResponse({ deleted: true, device_id: deviceId, retained_tickets: retainedTickets });
}

/** PATCH is not implemented — PUT replaces the mutable fields wholesale. */
export function PATCH(): NextResponse {
  return methodNotAllowed(ALLOW);
}
