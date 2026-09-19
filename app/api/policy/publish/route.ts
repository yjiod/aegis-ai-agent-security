import { NextResponse } from 'next/server';
import { requireAdmin, getSession } from '@/lib/auth';
import { ensureLabelsLoaded } from '@/lib/labels';
import { getScanMode, effectiveRules, ensureBaselinesLoaded } from '@/lib/baselines';
import { logAudit } from '@/lib/store';
import { ensurePolicyReleasesLoaded, ensureSigningKeysLoaded, publishPolicyRelease, signingKeyId, enforceableRuleIds } from '@/lib/policy';
import { moduleOverrides } from '@/lib/modules';

export const dynamic = 'force-dynamic';
const NO_STORE = { 'Cache-Control': 'no-store' } as const;

/**
 * POST /api/policy/publish — 编译当前处置 → 签名 → 落库为新的生效策略版本。
 * admin-only；全程审计。签名密钥未配置时诚实返回 503（绝不产出未签名策略）。
 * body: { note?: string }
 */
export async function POST(request: Request) {
  const denied = requireAdmin(request);
  if (denied) return denied;
  const session = getSession(request);
  let body: Record<string, unknown> = {};
  try {
    body = await request.json();
  } catch {
    /* note 可选，解析失败按空处理 */
  }
  const note = typeof body.note === 'string' ? body.note.slice(0, 500) : '';

  await ensurePolicyReleasesLoaded().catch(() => {});
  await ensureSigningKeysLoaded().catch(() => {});
  await ensureLabelsLoaded().catch(() => {});
  await ensureBaselinesLoaded().catch(() => {});

  const scanMode = getScanMode();
  const customRuleIds = enforceableRuleIds(effectiveRules().map((r) => r.id));
  // fail-closed：custom 模式必须有终端可执行的规则，否则等于签发一份"静默关闭扫描"的策略。
  if (scanMode === 'custom' && customRuleIds.length === 0) {
    return NextResponse.json(
      { error: 'custom_mode_has_no_enforceable_rules', hint: 'custom 扫描模式需要已导入且终端可执行的基线规则；请先在「基线管理」导入规则或改用 standard 模式' },
      { status: 409, headers: NO_STORE },
    );
  }

  const rel = publishPolicyRelease({ scanMode, by: session?.subject ?? 'console', note, customRuleIds, modules: moduleOverrides() });
  if (!rel) {
    return NextResponse.json(
      { error: 'signing_key_not_configured', hint: '设置 AEGIS_POLICY_SIGNING_KEYS（或单钥 AEGIS_POLICY_SIGNING_KEY）后才能发布签名策略' },
      { status: 503, headers: NO_STORE },
    );
  }

  logAudit({
    actor: session?.subject ?? 'console',
    action: 'policy:publish',
    resource_type: 'policy',
    resource_id: `v${rel.version}`,
    detail: `发布签名策略 v${rel.version}（key=${rel.signing_key_id}）：allow=${rel.receipt.label_counts.allow} monitor=${rel.receipt.label_counts.monitor} deny=${rel.receipt.label_counts.deny}${note ? ` note=${note}` : ''}`,
  });

  return NextResponse.json(
    {
      published: true,
      release_id: rel.release_id,
      version: rel.version,
      signing_key_id: rel.signing_key_id,
      signature: rel.signature,
      created_at: rel.created_at,
      receipt: rel.receipt,
      policy: rel.policy,
    },
    { headers: NO_STORE },
  );
}

/** GET /api/policy/publish — 返回签名能力状态（是否已配置签名密钥）。 */
export async function GET(request: Request) {
  const denied = requireAdmin(request);
  if (denied) return denied;
  return NextResponse.json(
    { signing_configured: signingKeyId() !== 'unconfigured', signing_key_id: signingKeyId() },
    { headers: NO_STORE },
  );
}
