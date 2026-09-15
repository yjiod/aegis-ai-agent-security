/**
 * app/api/audit/route.ts — Audit log backed by REAL Collector data.
 *
 * GET /api/audit -> real audit entries from Collector /v1/audit
 * Falls back to console-side audit store when Collector unreachable.
 */

import { NextResponse } from 'next/server';
import { requireAuditor } from '@/lib/auth';
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
  const denied = requireAuditor(request);
  if (denied) return denied;
  const url = new URL(request.url);
  const limit = Math.min(Number(url.searchParams.get('limit') ?? 50), 200);
  const offset = Number(url.searchParams.get('offset') ?? 0);
  const resourceType = url.searchParams.get('resource_type');
  const actionFilter = url.searchParams.get('action');

  // 合并两个审计源（4A · Accounting 完整性）：
  //   - Collector /v1/audit：终端/设备侧事件；
  //   - 控制台 logAudit 存储：控制面操作 + 认证事件（login/logout/改密/SSO/锁定）。
  // 此前"Collector 有数据就只返回 Collector"，会导致认证/控制面审计在生产（Collector
  // 已连接）不可见——审计trail 必须两源合并，缺一不可。
  const collectorEntries = await fetchCollectorAudit();
  const consoleEntries = getAuditStore();

  let entries: Array<Record<string, unknown>> = [
    ...(collectorEntries ?? []).map((e, i) => ({
      id: e.id ?? i + 1,
      timestamp: e.timestamp,
      actor: e.actor ?? 'collector',
      action: e.action,
      resource_type: (e.resource_type ?? 'system') as 'device' | 'ticket' | 'policy' | 'system',
      resource_id: e.resource_id,
      detail: e.detail,
      source: 'collector',
    })),
    ...consoleEntries.map((e) => ({
      id: e.id,
      timestamp: e.timestamp,
      actor: e.actor,
      action: e.action,
      resource_type: e.resource_type,
      resource_id: e.resource_id,
      detail: e.detail,
      source: 'console',
    })),
  ];

  if (resourceType) entries = entries.filter((e) => e.resource_type === resourceType);
  if (actionFilter) entries = entries.filter((e) => String(e.action).startsWith(actionFilter));

  entries.sort((a, b) => Number(b.timestamp) - Number(a.timestamp));
  const total = entries.length;
  return json({
    entries: entries.slice(offset, offset + limit),
    total,
    limit,
    offset,
    connected: collectorEntries !== null,
    source: collectorEntries && collectorEntries.length > 0 ? 'merged' : 'console',
  });
}
