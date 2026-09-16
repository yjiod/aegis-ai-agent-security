/**
 * app/api/devices/route.ts — Device registry backed by REAL Collector data.
 *
 * GET    /api/devices              -> real device list from Collector /v1/devices
 * POST   /api/devices              -> register device (console-side registry)
 * PUT    /api/devices              -> update device metadata
 * DELETE /api/devices?device_id=ID -> remove from registry
 *
 * Production: reads live fleet data from the Collector (same-host HTTP).
 * Falls back to empty list (NOT demo data) when Collector is unreachable.
 */

import { NextResponse } from 'next/server';
import { requireDeviceWriter, getSession, roleReadsAllDevices } from '@/lib/auth';
import { getDeviceStore, logAudit } from '@/lib/store';

export const dynamic = 'force-dynamic';

const HEADERS = { 'Cache-Control': 'no-store' };

function json(data: unknown, status = 200) {
  return NextResponse.json(data, { status, headers: HEADERS });
}

interface CollectorDevice {
  device_id: string;
  last_seen: number;
  report_count: number;
  generation?: number;
  agent_version?: string;
  policy_version?: string;
  latest_severity?: { critical: number; high: number; medium: number; low: number };
  tools?: string[];
}

async function fetchCollectorDevices(): Promise<CollectorDevice[] | null> {
  const url = process.env.AEGIS_COLLECTOR_URL;
  const token = process.env.AEGIS_COLLECTOR_TOKEN;
  if (!url || !token) return null;
  try {
    const res = await fetch(`${url.replace(/\/$/, '')}/v1/devices?limit=200`, {
      headers: { Authorization: `Bearer ${token}`, Accept: 'application/json' },
      cache: 'no-store',
      signal: AbortSignal.timeout(5000),
    });
    if (!res.ok) return null;
    const data = (await res.json()) as any;
    return Array.isArray(data?.devices) ? data.devices : null;
  } catch {
    return null;
  }
}

/**
 * 连接态（connectivity）与关注态（attention）分离：
 * - status 只反映"是否在线/过期/离线"（由 last_seen 推导），不被发现严重度覆盖；
 *   否则一台在线但有高危发现的终端会被标 needs_attention 而"在线数"恒为 0（用户反馈 bug）。
 * - attention 单独布尔：有 critical/high 发现需人工研判。
 */
function connectivityStatus(lastSeen?: number): string {
  const now = Math.floor(Date.now() / 1000);
  if (!lastSeen) return 'offline';
  if (now - lastSeen > 86400) return 'offline';
  if (now - lastSeen > 7200) return 'stale';
  return 'online';
}
function hasAttention(sev?: { critical: number; high: number; medium: number; low: number }): boolean {
  return Boolean(sev && (sev.critical > 0 || sev.high > 0));
}

export async function GET(request: Request) {
  const url = new URL(request.url);
  const search = url.searchParams.get('q')?.toLowerCase() ?? '';
  const statusFilter = url.searchParams.get('status');

  // capability RBAC：developer 档仅可读"本人"设备（owner/os_user == subject）。
  const session = getSession(request);
  const scopeToSelf = session ? !roleReadsAllDevices(session.role) : false;
  const applyScope = <T extends { owner: string; os_user?: string }>(list: T[]): T[] =>
    scopeToSelf && session
      ? list.filter((d) => d.owner === session.subject || (d.os_user ?? '') === session.subject)
      : list;

  // Try real Collector data first
  const collectorDevices = await fetchCollectorDevices();

  if (collectorDevices && collectorDevices.length > 0) {
    let devices = collectorDevices.map((d) => ({
      device_id: d.device_id,
      hostname: (d as any).hostname as string ?? d.device_id,
      owner: ((d as any).owner as string) || ((d as any).os_user as string) || '待分配',
      os_user: ((d as any).os_user as string) || '',
      os: ((d as any).os as string) || '',
      agent_type: d.tools?.[0] ?? 'unknown',
      tools: d.tools ?? [],
      agent_version: d.agent_version ?? '0.0.0',
      policy_version: d.policy_version ?? '0.0.0',
      status: connectivityStatus(d.last_seen),
      attention: hasAttention(d.latest_severity),
      last_seen: d.last_seen,
      registered_at: d.last_seen,
      report_count: d.report_count ?? 0,
      findings_summary: d.latest_severity ?? { critical: 0, high: 0, medium: 0, low: 0 },
    }));

    if (search) {
      devices = devices.filter(
        (d) => d.device_id.toLowerCase().includes(search) || d.hostname.toLowerCase().includes(search),
      );
    }
    if (statusFilter) {
      devices = devices.filter((d) => d.status === statusFilter);
    }
    devices = applyScope(devices);

    return json({ devices, total: devices.length, connected: true, source: 'collector' });
  }

  // Collector unreachable or empty: return console-side registry (may be empty)
  const store = getDeviceStore();
  let devices = [...store.values()];
  if (search) {
    devices = devices.filter(
      (d) => d.device_id.toLowerCase().includes(search) || d.hostname.toLowerCase().includes(search) || d.owner.toLowerCase().includes(search),
    );
  }
  if (statusFilter) devices = devices.filter((d) => d.status === statusFilter);
  devices = applyScope(devices);

  return json({ devices, total: devices.length, connected: false, source: 'registry' });
}

export async function POST(request: Request) {
  const __denied = requireDeviceWriter(request);
  if (__denied) return __denied;
  let body: Record<string, unknown>;
  try { body = await request.json(); } catch { return json({ error: 'invalid_json' }, 400); }

  const device_id = String(body.device_id ?? '').trim();
  const hostname = String(body.hostname ?? '').trim();
  const owner = String(body.owner ?? '').trim();
  const agent_type = String(body.agent_type ?? 'other');

  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$/.test(device_id)) return json({ error: 'invalid_device_id' }, 400);
  if (!hostname || hostname.length > 128) return json({ error: 'invalid_hostname' }, 400);
  if (!owner || owner.length > 64) return json({ error: 'invalid_owner' }, 400);

  const store = getDeviceStore();
  if (store.has(device_id)) return json({ error: 'device_already_exists' }, 409);

  const now = Math.floor(Date.now() / 1000);
  const device = {
    device_id, hostname, owner,
    agent_type: agent_type as 'cursor' | 'claude_code' | 'codex_cli' | 'windsurf' | 'other',
    agent_version: '0.0.0', policy_version: '0.0.0',
    status: 'offline' as const, last_seen: now, registered_at: now,
    notes: body.notes ? String(body.notes).slice(0, 500) : undefined,
    findings_summary: { critical: 0, high: 0, medium: 0, low: 0 },
  };
  store.set(device_id, device);
  logAudit({ actor: getSession(request)?.subject ?? 'console', action: 'device:create', resource_type: 'device', resource_id: device_id, detail: `注册终端 ${hostname}（负责人 ${owner}）` });
  return json({ device }, 201);
}

export async function PUT(request: Request) {
  const __denied = requireDeviceWriter(request);
  if (__denied) return __denied;
  let body: Record<string, unknown>;
  try { body = await request.json(); } catch { return json({ error: 'invalid_json' }, 400); }

  const device_id = String(body.device_id ?? '').trim();
  if (!device_id) return json({ error: 'missing_device_id' }, 400);

  const store = getDeviceStore();
  const now = Math.floor(Date.now() / 1000);

  // Upsert: Collector-discovered devices get an overlay entry on first edit.
  const existing = store.get(device_id) ?? {
    device_id,
    hostname: device_id,
    owner: '待分配',
    agent_type: 'other' as const,
    agent_version: '0.0.0',
    policy_version: '0.0.0',
    status: 'online' as const,
    last_seen: now,
    registered_at: now,
    findings_summary: { critical: 0, high: 0, medium: 0, low: 0 },
  };

  if (body.hostname) existing.hostname = String(body.hostname).slice(0, 128);
  if (body.owner) existing.owner = String(body.owner).slice(0, 64);
  if (body.agent_type) existing.agent_type = String(body.agent_type) as typeof existing.agent_type;
  if (body.notes !== undefined) existing.notes = String(body.notes).slice(0, 500) || undefined;

  store.set(device_id, existing);
  logAudit({ actor: getSession(request)?.subject ?? 'console', action: 'device:update', resource_type: 'device', resource_id: device_id, detail: `更新终端 ${device_id} 登记信息` });
  return json({ device: existing });
}

export async function DELETE(request: Request) {
  const __denied = requireDeviceWriter(request);
  if (__denied) return __denied;
  const url = new URL(request.url);
  const device_id = url.searchParams.get('device_id')?.trim();
  if (!device_id) return json({ error: 'missing_device_id' }, 400);

  const store = getDeviceStore();
  const inRegistry = store.has(device_id);
  if (inRegistry) store.delete(device_id);
  // 同时清除 Collector 侧该设备的报告/每设备令牌/认证代次（硬件ID化后用于清理旧
  // hostname 派生的重复设备；设备若仍在线会继续上报并重新出现）。
  let purged = false;
  const collectorUrl = process.env.AEGIS_COLLECTOR_URL;
  const collectorToken = process.env.AEGIS_COLLECTOR_TOKEN;
  if (collectorUrl && collectorToken) {
    try {
      const r = await fetch(`${collectorUrl.replace(/\/$/, '')}/v1/devices?device_id=${encodeURIComponent(device_id)}`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${collectorToken}` },
        cache: 'no-store',
        signal: AbortSignal.timeout(5000),
      });
      purged = r.ok;
    } catch {
      purged = false;
    }
  }
  if (!inRegistry && !purged) return json({ error: 'device_not_found' }, 404);
  logAudit({ actor: getSession(request)?.subject ?? 'console', action: 'device:delete', resource_type: 'device', resource_id: device_id, detail: `移除终端 ${device_id}（注册表=${inRegistry} collector清除=${purged}）` });
  return json({ deleted: true, device_id, purged });
}
