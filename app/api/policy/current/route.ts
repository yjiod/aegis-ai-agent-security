import { NextResponse } from 'next/server';
import { getSession } from '@/lib/auth';
import { ensureLabelsLoaded } from '@/lib/labels';
import { ensurePolicyReleasesLoaded, currentPolicyRelease } from '@/lib/policy';

export const dynamic = 'force-dynamic';
const NO_STORE = { 'Cache-Control': 'no-store' } as const;

/**
 * GET /api/policy/current — 当前生效的已签名策略（任意已认证身份可读，含审计员）。
 * 无发布件时返回 { published:false }（绝不伪造一份策略）。
 */
export async function GET(request: Request) {
  const session = getSession(request);
  if (!session) return NextResponse.json({ error: 'unauthenticated' }, { status: 401, headers: NO_STORE });
  await ensurePolicyReleasesLoaded().catch(() => {});
  await ensureLabelsLoaded().catch(() => {});
  const rel = currentPolicyRelease();
  if (!rel) return NextResponse.json({ published: false }, { headers: NO_STORE });
  return NextResponse.json(
    {
      published: true,
      release_id: rel.release_id,
      version: rel.version,
      created_at: rel.created_at,
      created_by: rel.created_by,
      signing_key_id: rel.signing_key_id,
      signature: rel.signature,
      note: rel.note,
      receipt: rel.receipt,
      policy: rel.policy,
    },
    { headers: NO_STORE },
  );
}
