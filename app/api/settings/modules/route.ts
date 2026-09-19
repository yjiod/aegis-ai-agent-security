import { NextResponse } from 'next/server';
import { requireAdmin, getSession } from '@/lib/auth';
import { ensureBaselinesLoaded } from '@/lib/baselines';
import { logAudit } from '@/lib/store';
import { MODULE_KEYS, MODULE_LABELS, moduleOverrides, setModuleOverrides } from '@/lib/modules';

export const dynamic = 'force-dynamic';
const NO_STORE = { 'Cache-Control': 'no-store' } as const;

/** GET /api/settings/modules — 当前模块开关覆盖值(登录即可)。 */
export async function GET(request: Request) {
  const session = getSession(request);
  if (!session) return NextResponse.json({ error: 'unauthenticated' }, { status: 401, headers: NO_STORE });
  await ensureBaselinesLoaded().catch(() => {});
  return NextResponse.json({ modules: moduleOverrides(), keys: MODULE_KEYS, labels: MODULE_LABELS }, { headers: NO_STORE });
}

/** PUT /api/settings/modules — 设置模块开关(admin)。body:{modules:{key:boolean}}。影响后续签名策略。 */
export async function PUT(request: Request) {
  const denied = requireAdmin(request);
  if (denied) return denied;
  const session = getSession(request);
  let body: Record<string, unknown>;
  try { body = await request.json(); } catch { return NextResponse.json({ error: 'invalid_json' }, { status: 400, headers: NO_STORE }); }
  const mods = (body.modules ?? {}) as Record<string, unknown>;
  await ensureBaselinesLoaded().catch(() => {});
  const saved = setModuleOverrides(mods, session?.subject ?? 'console');
  const changed = Object.entries(saved).map(([k, v]) => `${MODULE_LABELS[k as keyof typeof MODULE_LABELS] ?? k}=${v ? '开' : '关'}`).join(', ');
  logAudit({ actor: session?.subject ?? 'console', action: 'policy:modules', resource_type: 'policy', detail: changed ? `模块开关变更: ${changed}（影响后续签名策略）` : '模块开关变更: 无有效键' });
  return NextResponse.json({ modules: saved }, { headers: NO_STORE });
}
