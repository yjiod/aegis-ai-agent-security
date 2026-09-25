import { NextResponse } from 'next/server';
import { requireSession } from '@/lib/auth';
import { ensurePgHydrated } from '@/lib/store';
import { ensurePolicyReleasesLoaded, currentPolicyRelease } from '@/lib/policy';
import { fetchCollectorDevices, computeVersionPosture } from '@/lib/collector-devices';

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
  const ft = data.finding_totals as Record<string, number> | undefined;
  const findingTotals =
    ft && typeof ft === 'object'
      ? {
          critical: Number(ft.critical ?? 0),
          high: Number(ft.high ?? 0),
          medium: Number(ft.medium ?? 0),
          low: Number(ft.low ?? 0),
        }
      : undefined;
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
    // 计数层(stage-1)：透传舰队累计发现计数（O(设备数)），供总览/趋势显示，避免全量拉 findings。
    ...(findingTotals ? { finding_totals: findingTotals } : {}),
  };
}

function unavailable(error: string, status = 503) {
  return NextResponse.json(
    { connected: false, error },
    { status, headers: { 'Cache-Control': 'no-store' } },
  );
}

type SanitizedSummary = NonNullable<ReturnType<typeof sanitizedSummary>>;

/**
 * 版本姿态单一可信源：用控制台已发布策略版本重算 version_posture 并覆盖
 * required_policy_version，使仪表盘与 /api/policy/posture 对同一批终端给出一致结论
 * （此前 summary 用 Collector 静态 4.8.0 分桶、posture 用已发布 4.9.0+，结论相反）。
 *
 * 诚实降级：设备集与 summary 计数不一致（缓存陈旧 / 新终端刚入网）时先绕过缓存重取
 * 一次；仍拿不到可逐台核对的设备集，就保留 Collector 原分桶与其静态 required 版本，
 * 并标注 required_policy_version_source='collector_static'、version_posture_recomputed=false
 * ——绝不伪造姿态，也不把未重算的分桶冠以"权威版本"之名。
 */
async function withAuthoritativePosture(summary: SanitizedSummary): Promise<Record<string, unknown>> {
  await ensurePgHydrated().catch(() => {});
  await ensurePolicyReleasesLoaded().catch(() => {});
  const rel = currentPolicyRelease();
  // validSummary 已保证这些字段的类型/取值范围，此处的强制转换是安全的收窄。
  const totalDevices = Number(summary.total_devices);
  const requiredAgent = String(summary.required_agent_version);
  const authoritativePolicy = rel?.policy.version ?? String(summary.required_policy_version);

  let devices = await fetchCollectorDevices();
  if (devices && devices.length !== totalDevices) devices = await fetchCollectorDevices(true);

  if (!devices || devices.length !== totalDevices) {
    return {
      ...summary,
      required_policy_version_source: 'collector_static',
      version_posture_recomputed: false,
    };
  }

  const posture = computeVersionPosture(devices, requiredAgent, authoritativePolicy);
  return {
    ...summary,
    required_policy_version: authoritativePolicy,
    version_posture: posture,
    required_policy_version_source: rel ? 'published_release' : 'collector_default',
    version_posture_recomputed: true,
  };
}

export async function GET(request: Request) {
  // 会话验签闸（契约 lib/openapi.ts 声明 /summary = session）：middleware 只校验
  // Cookie 存在性+expiry 不验签，伪造 Cookie 能过 middleware，故必须在此真验签。
  const __denied = requireSession(request);
  if (__denied) return __denied;
  const endpoint = process.env.AEGIS_COLLECTOR_URL;
  const allowedHost = process.env.AEGIS_COLLECTOR_ALLOWED_HOST;
  const token = process.env.AEGIS_COLLECTOR_TOKEN;
  if (!endpoint || !allowedHost || !token)
    return unavailable('collector_not_configured');
  let target: URL;
  try {
    const base = new URL(endpoint);
    // Localhost connections never leave the machine — HTTP is safe regardless of NODE_ENV.
    // This allows wrangler/miniflare runtime (which forces NODE_ENV=production) to
    // reach a same-host Collector over HTTP.
    const isLocalhost =
      base.hostname === '127.0.0.1' || base.hostname === 'localhost' || base.hostname === '[::1]';
    if (
      (!isLocalhost && base.protocol !== 'https:') ||
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
      { connected: true, summary: await withAuthoritativePosture(summary) },
      { headers: { 'Cache-Control': 'no-store' } },
    );
  } catch {
    return unavailable('collector_unavailable');
  }
}
