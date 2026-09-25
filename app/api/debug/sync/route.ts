import { NextResponse } from 'next/server';
import { requireAdmin } from '@/lib/auth';

export const dynamic = 'force-dynamic';

/**
 * TEMP debug: run the collector->ticket sync and surface any error.
 *
 * 契约 lib/openapi.ts 声明 /debug/sync = **admin**：本端点回传 collector 连通性、
 * 设备总数与首台设备的完整原始记录（out.first），属敏感诊断面。middleware 不验签，
 * 伪造 Cookie 即可读到，故必须 requireAdmin（未认证 401 / 非 admin 403）。
 */
export async function GET(request: Request) {
  const __denied = requireAdmin(request);
  if (__denied) return __denied;
  const url = process.env.AEGIS_COLLECTOR_URL;
  const token = process.env.AEGIS_COLLECTOR_TOKEN;
  const out: Record<string, unknown> = { has_url: Boolean(url), has_token: Boolean(token) };
  if (!url || !token) return NextResponse.json(out);
  try {
    const res = await fetch(`${url.replace(/\/$/, '')}/v1/devices?limit=500`, {
      headers: { Authorization: `Bearer ${token}`, Accept: 'application/json' },
      cache: 'no-store',
    });
    out.fetch_status = res.status;
    const data = (await res.json()) as { devices?: Array<Record<string, unknown>> };
    out.device_count = (data.devices ?? []).length;
    out.first = (data.devices ?? [])[0];
  } catch (e) {
    out.error = String(e);
  }
  return NextResponse.json(out);
}
