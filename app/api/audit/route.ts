/**
 * app/api/audit/route.ts — Audit log backed by REAL Collector data.
 *
 * GET /api/audit -> real audit entries from Collector /v1/audit
 * Falls back to console-side audit store when Collector unreachable.
 */

import { NextResponse } from 'next/server';
import { getAuditStore } from '@/lib/store';

export const dynamic = 'force-dynamic';

const HEADERS = { 'Cache-Control': 'no-store' };

function json(data: unknown, status = 200) {
  return NextResponse.json(data, { status, headers: HEADERS });
}

interface CollectorAuditEntry {
  id: number;
  timestamp: number;
  actor?: string;
  action: string;
  resource_type?: string;
  resource_id?: string;
  detail?: string;
}

async function fetchCollectorAudit(): Promise<CollectorAuditEntry[] | null> {
  const url = process.env.AEGIS_COLLECTOR_URL;
  const token = process.env.AEGIS_COLLECTOR_TOKEN;
  if (!url || !token) return null;
  try {
    const res = await fetch(`${url.replace(/\/$/, '')}/v1/audit?limit=200`, {
      headers: { Authorization: `Bearer ${token}`, Accept: 'application/json' },
      cache: 'no-store',
      signal: AbortSignal.timeout(5000),
    });
    if (!res.ok) return null;
    const data = (await res.json()) as Record<string, unknown>;
    return Array.isArray(data?.entries) ? data.entries : Array.isArray(data) ? data : null;
  } catch {
    return null;
  }
}

export async function GET(request: Request) {
  const url = new URL(request.url);
  const limit = Math.min(Number(url.searchParams.get('limit') ?? 50), 200);
  const offset = Number(url.searchParams.get('offset') ?? 0);
  const resourceType = url.searchParams.get('resource_type');
  const actionFilter = url.searchParams.get('action');

  // Try real Collector audit log first
  const collectorEntries = await fetchCollectorAudit();

  if (collectorEntries && collectorEntries.length > 0) {
    let entries = collectorEntries.map((e, i) => ({
      id: e.id ?? i + 1,
      timestamp: e.timestamp,
      actor: e.actor ?? 'collector',
      action: e.action,
      resource_type: (e.resource_type ?? 'system') as 'device' | 'ticket' | 'policy' | 'system',
      resource_id: e.resource_id,
      detail: e.detail,
    }));

    if (resourceType) entries = entries.filter((e) => e.resource_type === resourceType);
    if (actionFilter) entries = entries.filter((e) => e.action.startsWith(actionFilter));

    entries.sort((a, b) => b.timestamp - a.timestamp);
    const total = entries.length;
    return json({ entries: entries.slice(offset, offset + limit), total, limit, offset, connected: true, source: 'collector' });
  }

  // Fallback: console-side audit store
  let entries = getAuditStore();
  if (resourceType) entries = entries.filter((e) => e.resource_type === resourceType);
  if (actionFilter) entries = entries.filter((e) => e.action.startsWith(actionFilter));
  entries.sort((a, b) => b.timestamp - a.timestamp);
  const total = entries.length;

  return json({ entries: entries.slice(offset, offset + limit), total, limit, offset, connected: false, source: 'console' });
}
