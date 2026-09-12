import { NextResponse } from 'next/server';
import { requireAdmin, getSession } from '@/lib/auth';
import { getScanMode, setScanMode, getSetting, setSetting, SCAN_MODES } from '@/lib/baselines';

export const dynamic = 'force-dynamic';
const NO_STORE = { 'Cache-Control': 'no-store' } as const;

const ALLOWED_KEYS = ['scan_mode', 'upstream_baseline_url'];

/** GET /api/settings — 读全局设置(扫描模式 + 上游基线 URL)。 */
export async function GET(request: Request) {
  const session = getSession(request);
  if (!session) return NextResponse.json({ error: 'unauthenticated' }, { status: 401, headers: NO_STORE });
  return NextResponse.json(
    { scan_mode: getScanMode(), upstream_baseline_url: getSetting('upstream_baseline_url'), available: SCAN_MODES },
    { headers: NO_STORE },
  );
}

/** PUT /api/settings — 更新设置(admin)。body:{scan_mode?|upstream_baseline_url?} */
export async function PUT(request: Request) {
  const denied = requireAdmin(request);
  if (denied) return denied;
  const session = getSession(request);
  let body: Record<string, unknown>;
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: 'invalid_json' }, { status: 400, headers: NO_STORE });
  }
  const updated: string[] = [];
  if (typeof body.scan_mode === 'string') {
    if (!setScanMode(body.scan_mode as any, session?.subject ?? 'console'))
      return NextResponse.json({ error: 'invalid_mode', available: SCAN_MODES }, { status: 400, headers: NO_STORE });
    updated.push('scan_mode');
  }
  if (typeof body.upstream_baseline_url === 'string') {
    const v = String(body.upstream_baseline_url).trim();
    if (v && !/^https?:\/\//.test(v)) return NextResponse.json({ error: 'invalid_url' }, { status: 400, headers: NO_STORE });
    setSetting('upstream_baseline_url', v, session?.subject ?? 'console');
    updated.push('upstream_baseline_url');
  }
  if (updated.length === 0) return NextResponse.json({ error: 'nothing_to_update', allowed: ALLOWED_KEYS }, { status: 400, headers: NO_STORE });
  return NextResponse.json({ updated, scan_mode: getScanMode(), upstream_baseline_url: getSetting('upstream_baseline_url') }, { headers: NO_STORE });
}
