import { NextResponse } from 'next/server';
import { getSession } from '@/lib/auth';
import { getDeviceStore, ensurePgHydrated } from '@/lib/store';
import { ensurePolicyReleasesLoaded, currentPolicyRelease } from '@/lib/policy';

export const dynamic = 'force-dynamic';
const NO_STORE = { 'Cache-Control': 'no-store' } as const;

interface CollectorDevice {
  device_id: string;
  policy_version?: string;
}

/**
 * 拉取 Collector 活体设备（携带 agent 真实上报的 policy_version）。
 * 30s TTL 模块级缓存，避免 posture 每次请求都向 Collector 扇出（沿用 ticket-sync
 * 的节流思路）；5s 超时；不可达返回 null（调用方诚实回退注册表）。
 */
let cache: { at: number; devices: CollectorDevice[] | null } = { at: 0, devices: null };
const CACHE_TTL_MS = 30_000;

async function fetchCollectorDevices(): Promise<CollectorDevice[] | null> {
  const now = Date.now();
  if (cache.devices !== null && now - cache.at < CACHE_TTL_MS) return cache.devices;
  const url = process.env.AEGIS_COLLECTOR_URL;
  const token = process.env.AEGIS_COLLECTOR_TOKEN;
  if (!url || !token) return null;
  try {
    const res = await fetch(`${url.replace(/\/$/, '')}/v1/devices?limit=500`, {
      headers: { Authorization: `Bearer ${token}`, Accept: 'application/json' },
      cache: 'no-store',
      signal: AbortSignal.timeout(5000),
    });
    if (!res.ok) return null;
    const data = (await res.json()) as { devices?: CollectorDevice[] };
    const devices = Array.isArray(data?.devices) ? data.devices : null;
    if (devices) cache = { at: now, devices };
    return devices;
  } catch {
    return null;
  }
}

/**
 * GET /api/policy/posture — 策略生效态势（任意已认证身份可读，含审计员）。
 *
 * 回答"我发布的签名策略到底有没有真的落到终端"。数据源优先用 Collector 活体
 * /v1/devices（agent 上报的真实 policy_version）；Collector 不可达时诚实回退控制台
 * 注册表，并在响应里用 source/connected 标明来源——绝不把注册表的默认 0.0.0
 * 当成真实终端版本而系统性误报 drifted。无发布件时返回 published:false。
 */
export async function GET(request: Request) {
  const session = getSession(request);
  if (!session) return NextResponse.json({ error: 'unauthenticated' }, { status: 401, headers: NO_STORE });

  await ensurePgHydrated().catch(() => {});
  await ensurePolicyReleasesLoaded().catch(() => {});

  const rel = currentPolicyRelease();

  // 选数据源：Collector 活体优先，回退注册表。
  const collectorDevices = await fetchCollectorDevices();
  const useCollector = collectorDevices !== null;
  const versions: Array<string | undefined> = useCollector
    ? (collectorDevices as CollectorDevice[]).map((d) => d.policy_version)
    : [...getDeviceStore().values()].map((d) => d.policy_version);
  const source = useCollector ? 'collector' : 'registry';
  const total = versions.length;

  if (!rel) {
    return NextResponse.json(
      { published: false, source, connected: useCollector, total_devices: total, on_current: 0, drifted: 0, unknown: total },
      { headers: NO_STORE },
    );
  }

  const currentVersion = rel.policy.version;
  let onCurrent = 0;
  let drifted = 0;
  let unknown = 0;
  for (const raw of versions) {
    const pv = (raw ?? '').trim();
    // 注册表回退时，未上报过策略版本的终端(0.0.0/空)计为 unknown，绝不当作 drifted。
    if (!pv || pv === '0.0.0') unknown += 1;
    else if (pv === currentVersion) onCurrent += 1;
    else drifted += 1;
  }

  return NextResponse.json(
    {
      published: true,
      source,
      connected: useCollector,
      current_version: currentVersion,
      release_version: rel.version,
      signing_key_id: rel.signing_key_id,
      total_devices: total,
      on_current: onCurrent,
      drifted,
      unknown,
      coverage: total > 0 ? Number(((onCurrent / total) * 100).toFixed(1)) : 0,
    },
    { headers: NO_STORE },
  );
}
