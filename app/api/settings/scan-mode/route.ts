import { NextResponse } from 'next/server';
import { requireAdmin, getSession } from '@/lib/auth';
import { ensureBaselinesLoaded, getScanMode, setScanMode, SCAN_MODES, type ScanMode } from '@/lib/baselines';

export const dynamic = 'force-dynamic';
const NO_STORE = { 'Cache-Control': 'no-store' } as const;

/** GET /api/settings/scan-mode — 当前扫描模式(登录即可)。 */
export async function GET(request: Request) {
  const session = getSession(request);
  if (!session) return NextResponse.json({ error: 'unauthenticated' }, { status: 401, headers: NO_STORE });
  await ensureBaselinesLoaded().catch(() => {});
  return NextResponse.json({ scan_mode: getScanMode(), available: SCAN_MODES }, { headers: NO_STORE });
}

/** PUT /api/settings/scan-mode — 设置扫描模式(admin)。body:{mode} */
export async function PUT(request: Request) {
  const denied = requireAdmin(request);
  if (denied) return denied;
  const session = getSession(request);
  let body: Record<string, unknown>;
  try { body = await request.json(); } catch { return NextResponse.json({ error: 'invalid_json' }, { status: 400, headers: NO_STORE }); }
  const mode = String(body.mode ?? '') as ScanMode;
  await ensureBaselinesLoaded().catch(() => {});
  const ok = setScanMode(mode, session?.subject ?? 'console');
  if (!ok) return NextResponse.json({ error: 'invalid_mode', available: SCAN_MODES }, { status: 400, headers: NO_STORE });
  return NextResponse.json({ scan_mode: getScanMode() }, { headers: NO_STORE });
}
