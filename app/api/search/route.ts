import { NextResponse } from 'next/server';
import { getSession } from '@/lib/auth';
import { fetchCollectorDevices } from '@/lib/collector-devices';
import { getTicketStore } from '@/lib/store';
import { listLabels } from '@/lib/labels';

export const dynamic = 'force-dynamic';
const NO_STORE = { 'Cache-Control': 'no-store' } as const;
const PER_SOURCE = 8;

export interface SearchResults {
  q: string;
  devices: Array<{ device_id: string; hostname?: string; owner?: string; agent_version?: string; status?: string }>;
  tickets: Array<{ id: string; title?: string; device_id?: string; status?: string; severity?: string }>;
  assets: Array<{ asset_type: string; asset_key: string; disposition?: string }>;
}

/**
 * GET /api/search?q= — 顶栏全局搜索（AIDR 式）。跨 资产(devices) / 工单(tickets) / 打标资产(labels)
 * 三源做有界模糊匹配（每源最多 8 条），供顶栏下拉快速跳转。findings 的检索在各扫描页内
 * 本地过滤（全量发现体不适合进全局搜索）。未登录 401；q 过短返回空结果不报错。
 */
export async function GET(request: Request): Promise<NextResponse> {
  const session = getSession(request);
  if (!session) return NextResponse.json({ error: 'unauthenticated' }, { status: 401, headers: NO_STORE });
  const q = (new URL(request.url).searchParams.get('q') ?? '').trim().toLowerCase();
  const empty: SearchResults = { q, devices: [], tickets: [], assets: [] };
  if (q.length < 1) return NextResponse.json(empty, { headers: NO_STORE });

  const devices: SearchResults['devices'] = [];
  const fleet = await fetchCollectorDevices();
  for (const d of fleet ?? []) {
    const rec = d as unknown as Record<string, unknown>;
    const hay = [rec.device_id, rec.hostname, rec.owner, rec.agent_version, (rec.network as Record<string, unknown> | undefined)?.egress_ip]
      .filter((x): x is string => typeof x === 'string')
      .join(' ')
      .toLowerCase();
    const ips = ((rec.network as Record<string, unknown> | undefined)?.local_ips as unknown[] | undefined) ?? [];
    const hayAll = hay + ' ' + ips.filter((x): x is string => typeof x === 'string').join(' ').toLowerCase();
    if (hayAll.includes(q)) {
      devices.push({
        device_id: String(rec.device_id ?? ''),
        hostname: typeof rec.hostname === 'string' ? rec.hostname : undefined,
        owner: typeof rec.owner === 'string' ? rec.owner : undefined,
        agent_version: typeof rec.agent_version === 'string' ? rec.agent_version : undefined,
      });
      if (devices.length >= PER_SOURCE) break;
    }
  }

  const tickets: SearchResults['tickets'] = [];
  for (const t of getTicketStore().values()) {
    const rec = t as unknown as Record<string, unknown>;
    const hay = [rec.id, rec.title, rec.device_id, rec.status, rec.severity]
      .filter((x): x is string => typeof x === 'string')
      .join(' ')
      .toLowerCase();
    if (hay.includes(q)) {
      tickets.push({
        id: String(rec.id ?? ''),
        title: typeof rec.title === 'string' ? rec.title : undefined,
        device_id: typeof rec.device_id === 'string' ? rec.device_id : undefined,
        status: typeof rec.status === 'string' ? rec.status : undefined,
        severity: typeof rec.severity === 'string' ? rec.severity : undefined,
      });
      if (tickets.length >= PER_SOURCE) break;
    }
  }

  const assets: SearchResults['assets'] = [];
  for (const l of listLabels()) {
    if (l.asset_key.toLowerCase().includes(q) || l.tags.some((t) => t.toLowerCase().includes(q))) {
      assets.push({ asset_type: l.asset_type, asset_key: l.asset_key, disposition: l.disposition || undefined });
      if (assets.length >= PER_SOURCE) break;
    }
  }

  return NextResponse.json({ q, devices, tickets, assets }, { headers: NO_STORE });
}
