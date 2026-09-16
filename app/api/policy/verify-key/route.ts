import { NextResponse } from 'next/server';
import { ed25519VerifyKeyInfo } from '@/lib/policy';

export const dynamic = 'force-dynamic';

/**
 * GET /api/policy/verify-key — 公开的策略验签公钥（批3）。
 *
 * 公钥非秘密：任何持有者皆可独立验证发布件的 Ed25519 签名，无需信任传输通道。
 * 未配置 AEGIS_POLICY_ED25519_SEED 或运行时不支持 Ed25519 → 404（dual-sign 关闭）。
 * 未认证可读（分发公钥不构成泄露）。
 */
export async function GET() {
  const info = await ed25519VerifyKeyInfo();
  if (!info) {
    return NextResponse.json({ error: 'ed25519_not_configured' }, { status: 404, headers: { 'Cache-Control': 'no-store' } });
  }
  return NextResponse.json(info, { headers: { 'Cache-Control': 'no-store' } });
}
