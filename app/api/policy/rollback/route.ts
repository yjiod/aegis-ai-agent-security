import { NextResponse } from 'next/server';
import { requireAdmin, getSession } from '@/lib/auth';
import { logAudit } from '@/lib/store';
import { ensurePolicyReleasesLoaded, ensureSigningKeysLoaded, listPolicyReleases, publishPolicyBodyRaw } from '@/lib/policy';

export const dynamic = 'force-dynamic';
const NO_STORE = { 'Cache-Control': 'no-store' } as const;

/**
 * POST /api/policy/rollback — 一键回滚（PM 评审 #1）：把指定历史版本(默认=上一个被取代版本)
 * 的 policy body 以新版本号重新签名发布。历史 release 不修改(审计不可变)。
 * body: { to_version?: number, note?: string }
 */
export async function POST(request: Request) {
  const denied = requireAdmin(request);
  if (denied) return denied;
  const session = getSession(request);
  let body: Record<string, unknown> = {};
  try { body = await request.json(); } catch { /* optional */ }
  const note = typeof body.note === 'string' ? body.note.slice(0, 300) : '';

  await ensurePolicyReleasesLoaded().catch(() => {});
  await ensureSigningKeysLoaded().catch(() => {});
  const releases = listPolicyReleases();
  if (releases.length === 0) return NextResponse.json({ error: 'no_releases' }, { status: 409, headers: NO_STORE });
  const current = releases.find((r) => r.status === 'published');
  let target = typeof body.to_version === 'number' ? releases.find((r) => r.version === body.to_version) : undefined;
  if (!target) target = releases.find((r) => r.status === 'superseded');
  if (!target || target === current) {
    return NextResponse.json({ error: 'no_rollback_target', hint: '没有可回滚的历史发布版本' }, { status: 409, headers: NO_STORE });
  }
  const rel = publishPolicyBodyRaw(target.policy, session?.subject ?? 'console', note || `rollback to v${target.version}`);
  if (!rel) return NextResponse.json({ error: 'signing_key_not_configured' }, { status: 503, headers: NO_STORE });
  logAudit({
    actor: session?.subject ?? 'console',
    action: 'policy:rollback',
    resource_type: 'policy',
    resource_id: `v${rel.version}`,
    detail: `回滚发布 v${rel.version}（内容=v${target.version}，原当前=v${current?.version ?? '?'}）${note ? ` note=${note}` : ''}`,
  });
  return NextResponse.json({ published: true, version: rel.version, rolled_back_to: target.version }, { headers: NO_STORE });
}
