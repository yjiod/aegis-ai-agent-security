import { NextResponse } from 'next/server';
import { requireAdmin, getSession } from '@/lib/auth';
import { ensureBaselinesLoaded } from '@/lib/baselines';
import { logAudit } from '@/lib/store';
import { exemptDevices, setExemptDevices } from '@/lib/exempt';

export const dynamic = 'force-dynamic';
const NO_STORE = { 'Cache-Control': 'no-store' } as const;

/** GET /api/settings/exempt — 封禁豁免设备清单（登录即可）。 */
export async function GET(request: Request) {
  const session = getSession(request);
  if (!session) return NextResponse.json({ error: 'unauthenticated' }, { status: 401, headers: NO_STORE });
  await ensureBaselinesLoaded().catch(() => {});
  return NextResponse.json({ exempt: exemptDevices() }, { headers: NO_STORE });
}

/** PUT /api/settings/exempt — 设置豁免清单（admin）。body: { devices: string[] } */
export async function PUT(request: Request) {
  const denied = requireAdmin(request);
  if (denied) return denied;
  const session = getSession(request);
  let body: Record<string, unknown> = {};
  try { body = await request.json(); } catch { return NextResponse.json({ error: 'invalid_json' }, { status: 400, headers: NO_STORE }); }
  const devices = Array.isArray(body.devices) ? (body.devices as unknown[]).map((x) => String(x)) : [];
  await ensureBaselinesLoaded().catch(() => {});
  const saved = setExemptDevices(devices, session?.subject ?? 'console');
  logAudit({ actor: session?.subject ?? 'console', action: 'settings:exempt', resource_type: 'policy', detail: `封禁豁免设备清单更新为 ${saved.length} 台: ${saved.join(',') || '(空)'}` });
  return NextResponse.json({ exempt: saved }, { headers: NO_STORE });
}
