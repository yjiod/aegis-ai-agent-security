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

function boundedCount(value: unknown): value is number {
  return Number.isSafeInteger(value) && Number(value) >= 0;
}

function validSummary(value: unknown) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const data = value as Record<string, unknown>;
  if (
    !boundedCount(data.total_devices) ||
    !boundedCount(data.active_devices) ||
    !boundedCount(data.stale_devices) ||
    data.active_devices + data.stale_devices !== data.total_devices ||
    typeof data.required_agent_version !== 'string' ||
    typeof data.required_policy_version !== 'string'
  )
    return false;
  const severity = data.latest_severity as Record<string, unknown> | undefined;
  const posture = data.version_posture as Record<string, unknown> | undefined;
  if (!severity || !posture) return false;
  if (!levels.every((key) => boundedCount(severity[key]))) return false;
  if (!postures.every((key) => boundedCount(posture[key]))) return false;
  return (
    levels.reduce((sum, key) => sum + Number(severity[key]), 0) ===
      data.total_devices &&
    postures.reduce((sum, key) => sum + Number(posture[key]), 0) ===
      data.total_devices
  );
}

export async function GET() {
  const endpoint = process.env.SENTINEL_COLLECTOR_URL;
  const allowedHost = process.env.SENTINEL_COLLECTOR_ALLOWED_HOST;
  const token = process.env.SENTINEL_COLLECTOR_TOKEN;
  if (!endpoint || !allowedHost || !token)
    return NextResponse.json(
      { connected: false, error: 'collector_not_configured' },
      { status: 503 },
    );
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
    return NextResponse.json(
      { connected: false, error: 'collector_configuration_invalid' },
      { status: 503 },
    );
  }
  try {
    const response = await fetch(target, {
      headers: { Authorization: `Bearer ${token}`, Accept: 'application/json' },
      cache: 'no-store',
      signal: AbortSignal.timeout(5000),
    });
    if (!response.ok)
      return NextResponse.json(
        { connected: false, error: 'collector_unavailable' },
        { status: 503 },
      );
    const summary: unknown = await response.json();
    if (!validSummary(summary))
      return NextResponse.json(
        { connected: false, error: 'collector_contract_invalid' },
        { status: 502 },
      );
    return NextResponse.json(
      { connected: true, summary },
      { headers: { 'Cache-Control': 'no-store' } },
    );
  } catch {
    return NextResponse.json(
      { connected: false, error: 'collector_unavailable' },
      { status: 503 },
    );
  }
}
