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
import { getDeviceStore } from '@/lib/store';

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
    const data = await res.json();
    return Array.isArray(data?.devices) ? data.devices : null;
  } catch {
    return null;
  }
}

function severityToStatus(sev?: { critical: number; high: number; medium: number; low: number }, lastSeen?: number): string {
  const now = Math.floor(Date.now() / 1000);
  if (lastSeen && now - lastSeen > 86400) return 'offline';
  if (sev && (sev.critical > 0 || sev.high > 0)) return 'needs_attention';
  if (lastSeen && now - lastSeen > 7200) return 'stale';
  return 'online';
}

export async function GET(request: Request) {
  const url = new URL(request.url);
  const search = url.searchParams.get('q')?.toLowerCase() ?? '';
  const statusFilter = url.searchParams.get('status');

  // Try real Collector data first
  const collectorDevices = await fetchCollectorDevices();

  if (collectorDevices && collectorDevices.length > 0) {
    let devices = collectorDevices.map((d) => ({
      device_id: d.device_id,
      hostname: (d as Record<string, unknown>).hostname as string ?? d.device_id,
      owner: ((d as Record<string, unknown>).owner as string) || '待分配',
      agent_type: d.tools?.[0] ?? 'unknown',
      tools: d.tools ?? [],
      agent_version: d.agent_version ?? '0.0.0',
      policy_version: d.policy_version ?? '0.0.0',
      status: severityToStatus(d.latest_severity, d.last_seen),
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

  return json({ devices, total: devices.length, connected: false, source: 'registry' });
}

export async function POST(request: Request) {
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
  return json({ device }, 201);
}

export async function PUT(request: Request) {
  let body: Record<string, unknown>;
  try { body = await request.json(); } catch { return json({ error: 'invalid_json' }, 400); }

  const device_id = String(body.device_id ?? '').trim();
  if (!device_id) return json({ error: 'missing_device_id' }, 400);

  const store = getDeviceStore();
  const existing = store.get(device_id);
  if (!existing) return json({ error: 'device_not_found' }, 404);

  if (body.hostname) existing.hostname = String(body.hostname).slice(0, 128);
  if (body.owner) existing.owner = String(body.owner).slice(0, 64);
  if (body.notes !== undefined) existing.notes = String(body.notes).slice(0, 500) || undefined;

  store.set(device_id, existing);
  return json({ device: existing });
}

export async function DELETE(request: Request) {
  const url = new URL(request.url);
  const device_id = url.searchParams.get('device_id')?.trim();
  if (!device_id) return json({ error: 'missing_device_id' }, 400);

  const store = getDeviceStore();
  if (!store.has(device_id)) return json({ error: 'device_not_found' }, 404);
  store.delete(device_id);
  return json({ deleted: true, device_id });
}
