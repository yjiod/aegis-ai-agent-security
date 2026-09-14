import { NextResponse } from 'next/server';
import { requireAdmin, getSession } from '@/lib/auth';
import { logAudit } from '@/lib/store';
import { ensurePolicyReleasesLoaded, ensureSigningKeysLoaded, retireSigningKey } from '@/lib/policy';

export const dynamic = 'force-dynamic';
const NO_STORE = { 'Cache-Control': 'no-store' } as const;

type RouteContext = { params: Promise<{ id: string }> };

/**
 * POST /api/policy/keys/:id/retire — 退役一把签名密钥（admin，证据门禁）。
 * 门禁：不能退役当前活跃钥；当前生效发布件不能仍由该钥签发（否则终端拉到的最新
 * 策略会验签失败）——必须先发布一份用新活跃钥签名的策略，再退役旧钥。
 * 退役只是把元数据标记为 retired（终端不再能用它验签）；不删除 env 里的密钥料。
 */
export async function POST(request: Request, context: RouteContext) {
  const denied = requireAdmin(request);
  if (denied) return denied;
  const session = getSession(request);
  const { id } = await context.params;
  const keyId = typeof id === 'string' ? id.trim() : '';
  if (!keyId) return NextResponse.json({ error: 'missing_key_id' }, { status: 400, headers: NO_STORE });

  await ensureSigningKeysLoaded().catch(() => {});
  await ensurePolicyReleasesLoaded().catch(() => {});

  const result = retireSigningKey(keyId, session?.subject ?? 'console');
  if (!result.ok) {
    const status = result.error === 'not_found' ? 404 : 409;
    return NextResponse.json({ error: result.error }, { status, headers: NO_STORE });
  }
  logAudit({
    actor: session?.subject ?? 'console',
    action: 'policy:key_retire',
    resource_type: 'policy',
    resource_id: keyId,
    detail: `签名密钥退役：${keyId}（已确认无生效发布件依赖）`,
  });
  return NextResponse.json({ ok: true, key_id: keyId }, { headers: NO_STORE });
}
