import { NextResponse } from 'next/server';
import { requireAdmin, getSession } from '@/lib/auth';
import { syncUpstream } from '@/lib/baselines';

export const dynamic = 'force-dynamic';
const NO_STORE = { 'Cache-Control': 'no-store' } as const;

/** POST /api/baselines/sync — 从上游 URL 拉取基线(admin)。body:{url} */
export async function POST(request: Request) {
  const denied = requireAdmin(request);
  if (denied) return denied;
  const session = getSession(request);
  let body: Record<string, unknown>;
  try { body = await request.json(); } catch { return NextResponse.json({ error: 'invalid_json' }, { status: 400, headers: NO_STORE }); }
  const url = String(body.url ?? '').trim();
  if (!/^https?:\/\//.test(url)) return NextResponse.json({ error: 'invalid_url' }, { status: 400, headers: NO_STORE });
  try {
    const b = await syncUpstream(url, session?.subject ?? 'console');
    return NextResponse.json({ baseline: { name: b.name, version: b.version, rules: b.rules.length } }, { headers: NO_STORE });
  } catch (e) {
    return NextResponse.json({ error: e instanceof Error ? e.message : 'sync_failed' }, { status: 502, headers: NO_STORE });
  }
}
