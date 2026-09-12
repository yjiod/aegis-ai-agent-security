import { NextResponse } from 'next/server';
import { requireAdmin, getSession } from '@/lib/auth';
import { ensureBaselinesLoaded, listBaselines, importBaseline, deleteBaseline, type BaselineRule, type ScanMode } from '@/lib/baselines';

export const dynamic = 'force-dynamic';
const NO_STORE = { 'Cache-Control': 'no-store' } as const;

/** GET /api/baselines — 列出基线(登录即可)。 */
export async function GET(request: Request) {
  const session = getSession(request);
  if (!session) return NextResponse.json({ error: 'unauthenticated' }, { status: 401, headers: NO_STORE });
  await ensureBaselinesLoaded().catch(() => {});
  return NextResponse.json({ baselines: listBaselines() }, { headers: NO_STORE });
}

/** POST /api/baselines — 导入/更新自定义基线(admin)。body:{name,rules,scan_modes?,version?} */
export async function POST(request: Request) {
  const denied = requireAdmin(request);
  if (denied) return denied;
  const session = getSession(request);
  let body: Record<string, unknown>;
  try { body = await request.json(); } catch { return NextResponse.json({ error: 'invalid_json' }, { status: 400, headers: NO_STORE }); }
  const name = String(body.name ?? '').trim();
  if (!name || name.length > 128) return NextResponse.json({ error: 'invalid_name' }, { status: 400, headers: NO_STORE });
  const rules = Array.isArray(body.rules) ? (body.rules as BaselineRule[]) : [];
  const modes = Array.isArray(body.scan_modes) ? (body.scan_modes as ScanMode[]) : undefined;
  await ensureBaselinesLoaded().catch(() => {});
  const b = importBaseline({ name, rules, ...(modes ? { scan_modes: modes } : {}), ...(typeof body.version === 'string' ? { version: body.version } : {}), updated_by: session?.subject ?? 'console' });
  return NextResponse.json({ baseline: b }, { headers: NO_STORE });
}

/** DELETE /api/baselines?name=X — 删除基线(admin)。 */
export async function DELETE(request: Request) {
  const denied = requireAdmin(request);
  if (denied) return denied;
  const name = new URL(request.url).searchParams.get('name') ?? '';
  if (!name) return NextResponse.json({ error: 'missing_name' }, { status: 400, headers: NO_STORE });
  await ensureBaselinesLoaded().catch(() => {});
  const removed = deleteBaseline(name);
  return NextResponse.json({ removed }, { headers: NO_STORE });
}
