/**
 * lib/collector-devices.ts — 共享的 Collector /v1/devices 拉取。
 *
 * posture 与 summary 两个路由都需要"每台终端上报的 agent_version / policy_version"
 * 来计算版本姿态。此前各自扇出一次 /v1/devices，且 summary 用的是 Collector 静态
 * required_policy_version(4.8.0)、posture 用的是已发布策略版本(4.9.0+)，导致仪表盘
 * 与策略页对同一批终端给出相反的 current/drifted 结论。统一到这里：单次拉取 + 30s
 * TTL 缓存（消除重复扇出），版本姿态一律以控制台已发布策略版本为单一可信源。
 *
 * 不可达 / 未配置时返回 null，调用方据此诚实降级（绝不伪造姿态）。
 */
export interface CollectorDeviceLite {
  device_id: string;
  agent_version?: string;
  policy_version?: string;
  last_seen?: number;
}

let cache: { at: number; devices: CollectorDeviceLite[] | null } = { at: 0, devices: null };
const TTL_MS = 30_000;

export async function fetchCollectorDevices(bypassCache = false): Promise<CollectorDeviceLite[] | null> {
  const now = Date.now();
  if (!bypassCache && cache.devices !== null && now - cache.at < TTL_MS) return cache.devices;
  const url = process.env.AEGIS_COLLECTOR_URL;
  const token = process.env.AEGIS_COLLECTOR_TOKEN;
  if (!url || !token) return null;
  try {
    const res = await fetch(`${url.replace(/\/$/, '')}/v1/devices?limit=10000`, {
      headers: { Authorization: `Bearer ${token}`, Accept: 'application/json' },
      cache: 'no-store',
      signal: AbortSignal.timeout(5000),
    });
    if (!res.ok) return null;
    const data = (await res.json()) as { devices?: CollectorDeviceLite[] };
    const devices = Array.isArray(data.devices) ? data.devices : null;
    if (devices) cache = { at: now, devices };
    return devices;
  } catch {
    return null;
  }
}

export type VersionPosture = {
  current: number;
  agent_mismatch: number;
  policy_mismatch: number;
  both_mismatch: number;
  unknown: number;
};

/**
 * 与 Collector collector_summary 完全一致的分桶逻辑，但用调用方传入的"权威"
 * required 版本（required_policy 来自已发布策略），保证仪表盘与策略页同源。
 */
export function computeVersionPosture(
  devices: CollectorDeviceLite[],
  requiredAgent: string,
  requiredPolicy: string,
): VersionPosture {
  const p: VersionPosture = { current: 0, agent_mismatch: 0, policy_mismatch: 0, both_mismatch: 0, unknown: 0 };
  for (const d of devices) {
    const agent = (d.agent_version ?? '').trim();
    const policy = (d.policy_version ?? '').trim();
    if (!agent || !policy) p.unknown += 1;
    else if (agent !== requiredAgent && policy !== requiredPolicy) p.both_mismatch += 1;
    else if (agent !== requiredAgent) p.agent_mismatch += 1;
    else if (policy !== requiredPolicy) p.policy_mismatch += 1;
    else p.current += 1;
  }
  return p;
}
