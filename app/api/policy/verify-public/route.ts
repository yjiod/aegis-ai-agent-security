import { NextResponse } from 'next/server';
import { ensurePolicyReleasesLoaded, currentPolicyRelease } from '@/lib/policy';

export const dynamic = 'force-dynamic';
const NO_STORE = { 'Cache-Control': 'no-store' } as const;

/**
 * GET /api/policy/verify-public — 控制台策略签名 ed25519 **公钥**（公开信息，随每份签名策略下发）。
 * 供安装器/运维在入网前后获取带外信任锚并写入终端缓存（ed25519-public.b64），
 * 使终端在"策略带 signature 但无 HMAC 验签环"的正常态下可非对称验签
 * （防 2026-09-24 停报事故复发）。不返回任何私钥/对称密钥/策略体。
 * 无已发布策略时 404（此时策略未签名，终端无需信任锚）。
 */
export async function GET(): Promise<NextResponse> {
  await ensurePolicyReleasesLoaded().catch(() => {});
  const rel = currentPolicyRelease();
  const pub = rel && typeof (rel.policy as unknown as Record<string, unknown>)?.ed25519_public === 'string'
    ? ((rel.policy as unknown as Record<string, unknown>).ed25519_public as string)
    : '';
  if (!pub) return NextResponse.json({ error: 'no_published_policy' }, { status: 404, headers: NO_STORE });
  return NextResponse.json(
    {
      ed25519_public: pub,
      ed25519_key_id: ((rel!.policy as unknown as Record<string, unknown>).ed25519_key_id as string) ?? '',
    },
    { headers: NO_STORE },
  );
}
