import { NextResponse } from 'next/server';
import { requireAdmin, requireAuditor, getSession } from '@/lib/auth';
import { logAudit } from '@/lib/store';
import { ensureLabelsLoaded } from '@/lib/labels';
import {
  ensurePolicyReleasesLoaded,
  ensureSigningKeysLoaded,
  listSigningKeys,
  rotateSigningKey,
  activeKeyIdResolved,
  signingKeyFingerprint,
} from '@/lib/policy';

export const dynamic = 'force-dynamic';
const NO_STORE = { 'Cache-Control': 'no-store' } as const;

/**
 * GET /api/policy/keys — 签名密钥治理视图（admin + auditor 可读）。
 * 只返回元数据：key_id / 指纹 / 状态 / 关联发布数；绝不返回密钥料。
 */
export async function GET(request: Request) {
  const denied = requireAuditor(request);
  if (denied) return denied;
  await ensureSigningKeysLoaded().catch(() => {});
  await ensurePolicyReleasesLoaded().catch(() => {});
  await ensureLabelsLoaded().catch(() => {});
  return NextResponse.json(
    {
      active_key_id: activeKeyIdResolved() || null,
      active_fingerprint: signingKeyFingerprint(),
      keys: listSigningKeys(),
    },
    { headers: NO_STORE },
  );
}

/**
 * POST /api/policy/keys — 轮换活跃签名密钥（admin）。
 * body: { to_key_id }。目标密钥必须已预置在 keyring(env AEGIS_POLICY_SIGNING_KEYS)；
 * 旧活跃钥转 retiring（重叠期内终端仍可验签），不删除任何密钥料。
 */
export async function POST(request: Request) {
  const denied = requireAdmin(request);
  if (denied) return denied;
  const session = getSession(request);
  let body: Record<string, unknown> = {};
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: 'invalid_json' }, { status: 400, headers: NO_STORE });
  }
  const toKeyId = String(body.to_key_id ?? '').trim();
  if (!toKeyId) return NextResponse.json({ error: 'missing_to_key_id' }, { status: 400, headers: NO_STORE });

  await ensureSigningKeysLoaded().catch(() => {});
  await ensurePolicyReleasesLoaded().catch(() => {});

  const result = rotateSigningKey(toKeyId, session?.subject ?? 'console');
  if (!result.ok) {
    const status = result.error === 'key_not_in_keyring' ? 400 : result.error === 'already_active' ? 409 : 503;
    return NextResponse.json({ error: result.error }, { status, headers: NO_STORE });
  }
  logAudit({
    actor: session?.subject ?? 'console',
    action: 'policy:key_rotate',
    resource_type: 'policy',
    resource_id: result.active_key_id,
    detail: `签名密钥轮换：active → ${result.active_key_id}（旧钥 ${result.retired_to || '无'} 转 retiring）`,
  });
  return NextResponse.json(
    { ok: true, active_key_id: result.active_key_id, retired_to: result.retired_to, keys: listSigningKeys() },
    { headers: NO_STORE },
  );
}
