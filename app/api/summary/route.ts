import { NextResponse } from 'next/server';

export const dynamic = 'force-dynamic';

const levels = ['critical', 'high', 'normal'] as const;
const postures = [
  'current',
  'agent_mismatch',
  'policy_mismatch',
  'both_mismatch',
  'unknown',
] as const;
const credentialPostures = ['current', 'previous', 'legacy'] as const;

function boundedCount(value: unknown): value is number {
  return Number.isSafeInteger(value) && Number(value) >= 0;
}
function boundedVersion(value: unknown): value is string {
  return typeof value === 'string' && value.length >= 1 && value.length <= 64;
}

function validSummary(value: unknown) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const data = value as Record<string, unknown>;
  if (
    !boundedCount(data.total_devices) ||
    !boundedCount(data.active_devices) ||
    !boundedCount(data.stale_devices) ||
    data.active_devices + data.stale_devices !== data.total_devices ||
    !boundedVersion(data.required_agent_version) ||
    !boundedVersion(data.required_policy_version)
  )
    return false;
  const severity = data.latest_severity as Record<string, unknown> | undefined;
  const posture = data.version_posture as Record<string, unknown> | undefined;
  const credentials = data.credential_posture as Record<string, unknown> | undefined;
  if (!severity || !posture) return false;
  if (!levels.every((key) => boundedCount(severity[key]))) return false;
  if (!postures.every((key) => boundedCount(posture[key]))) return false;
  if (credentials && !credentialPostures.every((key) => boundedCount(credentials[key]))) return false;
  return (
    levels.reduce((sum, key) => sum + Number(severity[key]), 0) ===
      data.total_devices &&
    postures.reduce((sum, key) => sum + Number(posture[key]), 0) ===
      data.total_devices &&
    (!credentials ||
      credentialPostures.reduce((sum, key) => sum + Number(credentials[key]), 0) ===
        data.total_devices)
  );
}

async function readBoundedJson(response: Response, limit = 65_536) {
  const declared = Number(response.headers.get('content-length') || 0);
  if (declared > limit) throw new Error('collector response too large');
  if (!response.body) throw new Error('collector response missing');
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > limit) {
      await reader.cancel();
      throw new Error('collector response too large');
    }
    chunks.push(value);
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)) as unknown;
}

function sanitizedSummary(value: unknown) {
  if (!validSummary(value)) return null;
  const data = value as Record<string, unknown>;
  const severity = data.latest_severity as Record<string, number>;
  const posture = data.version_posture as Record<string, number>;
  const credentials = data.credential_posture as Record<string, number> | undefined;
  return {
    total_devices: data.total_devices,
    active_devices: data.active_devices,
    stale_devices: data.stale_devices,
    required_agent_version: data.required_agent_version,
    required_policy_version: data.required_policy_version,
    latest_severity: Object.fromEntries(levels.map((key) => [key, severity[key]])),
    version_posture: Object.fromEntries(postures.map((key) => [key, posture[key]])),
    ...(credentials
      ? { credential_posture: Object.fromEntries(credentialPostures.map((key) => [key, credentials[key]])) }
      : {}),
  };
}

function unavailable(error: string, status = 503) {
  return NextResponse.json(
    { connected: false, error },
    { status, headers: { 'Cache-Control': 'no-store' } },
  );
}

export async function GET() {
  const endpoint = process.env.AEGIS_COLLECTOR_URL;
  const allowedHost = process.env.AEGIS_COLLECTOR_ALLOWED_HOST;
  const token = process.env.AEGIS_COLLECTOR_TOKEN;
  if (!endpoint || !allowedHost || !token)
    return unavailable('collector_not_configured');
  let target: URL;
  try {
    const base = new URL(endpoint);
    if (
      base.protocol !== 'https:' ||
      base.hostname.toLowerCase() !== allowedHost.toLowerCase() ||
      base.username ||
      base.password ||
      base.search ||
      base.hash ||
      token.length < 32 ||
      token.length > 4096
    )
      throw new Error('invalid collector configuration');
    target = new URL('/v1/summary', base.origin);
  } catch {
    return unavailable('collector_configuration_invalid');
  }
  try {
    const response = await fetch(target, {
      headers: { Authorization: `Bearer ${token}`, Accept: 'application/json' },
      cache: 'no-store',
      signal: AbortSignal.timeout(5000),
    });
    if (!response.ok)
      return unavailable('collector_unavailable');
    const summary = sanitizedSummary(await readBoundedJson(response));
    if (!summary) return unavailable('collector_contract_invalid', 502);
    return NextResponse.json(
      { connected: true, summary },
      { headers: { 'Cache-Control': 'no-store' } },
    );
  } catch {
    return unavailable('collector_unavailable');
  }
}
