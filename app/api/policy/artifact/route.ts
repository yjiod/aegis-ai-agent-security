import { NextResponse } from 'next/server';
import { getSession } from '@/lib/auth';
import { ensurePolicyReleasesLoaded, currentPolicyRelease, buildPolicyArtifact } from '@/lib/policy';

export const dynamic = 'force-dynamic';

/**
 * GET /api/policy/artifact — 终端可加载的「拍平」签名策略工件。
 *
 * 这是把"控制台发布"真正变成"终端可强制"的缺失环节：输出顶层即 aegis.policy/v1
 * 字段 + signature + signing_key_id 的 JSON（与 agent load_policy/verify_policy_signature
 * 期望逐字节一致），可直接经 MDM/桌管分发为终端的 aegis-policy.json。响应头给出
 * sha256（分发完整性校验）与 version。
 *
 * 鉴权双通道：控制台会话（任意已认证身份，含审计员）可下载；机器/MDM 可用
 * Bearer <AEGIS_COLLECTOR_TOKEN> 拉取。无发布件时 404 not_published（绝不伪造）。
 */
export async function GET(request: Request) {
  // 会话或 Bearer 二选一。
  const session = getSession(request);
  const authz = request.headers.get('authorization') ?? '';
  const machineToken = process.env.AEGIS_COLLECTOR_TOKEN;
  const bearerOk = Boolean(machineToken) && authz === `Bearer ${machineToken}`;
  if (!session && !bearerOk) {
    return NextResponse.json({ error: 'unauthenticated' }, { status: 401, headers: { 'Cache-Control': 'no-store' } });
  }

  await ensurePolicyReleasesLoaded().catch(() => {});
  const rel = currentPolicyRelease();
  if (!rel) {
    return NextResponse.json({ error: 'not_published' }, { status: 404, headers: { 'Cache-Control': 'no-store' } });
  }

  const { canonical, sha256, version } = buildPolicyArtifact(rel.policy, rel.signature, rel.signing_key_id);
  // 直接把规范化字节作为响应体，使其与 sha256 逐字节一致；MDM 可原样落盘为 aegis-policy.json。
  return new NextResponse(canonical, {
    status: 200,
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': 'no-store',
      'X-Aegis-Policy-Sha256': sha256,
      'X-Aegis-Policy-Version': version,
      'X-Aegis-Policy-Key-Id': rel.signing_key_id,
    },
  });
}
