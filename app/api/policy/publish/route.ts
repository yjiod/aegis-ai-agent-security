import { NextResponse } from 'next/server';
import { requireAdmin, getSession } from '@/lib/auth';
import { listLabels } from '@/lib/labels';
import { labelsReadyFor } from '@/lib/label-readiness';
import { getScanMode, effectiveRules, ensureBaselinesLoaded } from '@/lib/baselines';
import { logAudit } from '@/lib/store';
import { ensurePolicyReleasesLoaded, ensureSigningKeysLoaded, publishPolicyRelease, signingKeyId, enforceableRuleIds, BLAST_CAP_ASSETS, BLAST_CAP_PCT, BLAST_ABS_CAP_ASSETS, BLAST_ABS_CAP_PCT, BLAST_OVERRIDE_PHRASE } from '@/lib/policy';
import { moduleOverrides } from '@/lib/modules';
import { exemptDevices, pinnedDevices } from '@/lib/exempt';
import { getRollout } from '@/lib/rollout';
import { recordPipelineEvent } from '@/lib/pipeline-telemetry';

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
  const t0 = Date.now();
  let body: Record<string, unknown> = {};
  try {
    body = await request.json();
  } catch {
    /* note 可选，解析失败按空处理 */
  }
  const note = typeof body.note === 'string' ? body.note.slice(0, 500) : '';

  if (!(await labelsReadyFor('policy:publish', session?.subject ?? 'console'))) {
    return NextResponse.json({ error: 'labels_unavailable' }, { status: 503, headers: NO_STORE });
  }
  await ensurePolicyReleasesLoaded().catch(() => {});
  await ensureSigningKeysLoaded().catch(() => {});
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

  // ── 封禁爆炸半径闸（PM 评审 #1）：发布前用 Collector 各设备已发现资产预估影响面。
  // 超上限(资产数/单设备占比)即 409 拦截并回传精确清单；typed override 通过才放行，
  // 且签名策略带 enforce_override 标志，终端侧独立 cap 据此放行（双闸）。
  const mods = moduleOverrides();
  const exempt = exemptDevices();
  const pinned = pinnedDevices();
  const rollout = getRollout();
  const enforceOn = Boolean(mods.skill_enforce) || Boolean(mods.mcp_enforce);
  let enforceOverride = false;
  let blastNote = '';
  if (enforceOn) {
    const labelsNow = listLabels();
    const denySkills = labelsNow.filter((l) => l.asset_type === 'skill' && l.disposition === 'deny').map((l) => l.asset_key);
    const denyMcp = labelsNow.filter((l) => l.asset_type === 'mcp' && l.disposition === 'deny').map((l) => l.asset_key);
    if (denySkills.length || denyMcp.length) {
      type DevAssets = { device_id: string; skills?: string[]; mcp_assets?: string[] };
      let devices: DevAssets[] = [];
      try {
        const cu = process.env.AEGIS_COLLECTOR_URL;
        const ct = process.env.AEGIS_COLLECTOR_TOKEN;
        if (cu && ct) {
          const r = await fetch(`${cu.replace(/\/$/, '')}/v1/devices?limit=500`, { headers: { Authorization: `Bearer ${ct}`, Accept: 'application/json' }, cache: 'no-store' });
          if (r.ok) { const d = (await r.json()) as { devices?: DevAssets[] }; devices = d.devices ?? []; }
        }
      } catch { devices = []; }
      // 豁免设备(开发主机)不执行封禁, 影响面计算排除它们。
      const exemptSet = new Set(exempt.map((x) => x.toLowerCase()));
      devices = devices.filter((d) => !exemptSet.has(String(d.device_id).toLowerCase()));
      const impact = devices
        .map((dev) => {
          const s = (dev.skills ?? []).filter((x) => denySkills.includes(x));
          const m = (dev.mcp_assets ?? []).filter((x) => denyMcp.includes(x));
          const denom = (dev.skills ?? []).length;
          return { device_id: dev.device_id, skills: s, mcp: m, count: s.length + m.length, pct: denom ? Math.round((100 * s.length) / denom) : 0 };
        })
        .filter((x) => x.count > 0);
      const total = impact.reduce((a, b) => a + b.count, 0);
      const overPct = impact.some((x) => x.pct > BLAST_CAP_PCT);
      const bulkNames = denySkills.length + denyMcp.length;
      // 绝对上限 fail-closed(不可 override): 批量识别→一键全封 必须被拆批。
      const absExceeded = total > BLAST_ABS_CAP_ASSETS || impact.some((x) => x.pct > BLAST_ABS_CAP_PCT) || bulkNames > BLAST_ABS_CAP_ASSETS;
      if (absExceeded) {
        return NextResponse.json(
          {
            error: 'blast_radius_absolute',
            hint: `影响面(${total} 资产 / deny 名单 ${bulkNames} 条)超过绝对上限(${BLAST_ABS_CAP_ASSETS} 资产 / 单设备 ${BLAST_ABS_CAP_PCT}%)，不可 override。请分批发布（每批 ≤ ${BLAST_CAP_ASSETS} 个资产）。`,
            impact,
            caps: { assets: BLAST_CAP_ASSETS, pct: BLAST_CAP_PCT, abs_assets: BLAST_ABS_CAP_ASSETS, abs_pct: BLAST_ABS_CAP_PCT },
          },
          { status: 409, headers: NO_STORE },
        );
      }
      const exceeded = total > BLAST_CAP_ASSETS || overPct || bulkNames > BLAST_CAP_ASSETS;
      const overrideOk = typeof body.override === 'string' && body.override === BLAST_OVERRIDE_PHRASE;
      if (exceeded && !overrideOk) {
        return NextResponse.json(
          {
            error: 'blast_radius_exceeded',
            hint: `本次发布将影响 ${total} 个资产（上限 ${BLAST_CAP_ASSETS}）或单设备占比超 ${BLAST_CAP_PCT}%。确需执行请在 override 字段输入 ${BLAST_OVERRIDE_PHRASE} 后重试。`,
            impact,
            caps: { assets: BLAST_CAP_ASSETS, pct: BLAST_CAP_PCT, override: BLAST_OVERRIDE_PHRASE },
          },
          { status: 409, headers: NO_STORE },
        );
      }
      if (exceeded && overrideOk) {
        enforceOverride = true;
        blastNote = ` blast-override=${BLAST_OVERRIDE_PHRASE} affected=${total}`;
      }
    }
  }

  const rel = publishPolicyRelease({ scanMode, by: session?.subject ?? 'console', note, customRuleIds, modules: mods, enforceOverride, exempt, pinned, rollout });
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
    detail: `发布签名策略 v${rel.version}（key=${rel.signing_key_id}）：allow=${rel.receipt.label_counts.allow} monitor=${rel.receipt.label_counts.monitor} deny=${rel.receipt.label_counts.deny}${blastNote}${note ? ` note=${note}` : ''}`,
  });
  // 管道遥测：策略发布 = 结构验证 → 签名 → 发布（真实门禁结果，非样例）。
  void recordPipelineEvent({
    pipeline: 'policy-publish',
    source: 'console',
    stages: [
      { name: '结构验证', ok: true, detail: `scan_mode=${scanMode}` },
      { name: '签名', ok: true, detail: `key=${rel.signing_key_id}` },
      { name: '发布', ok: true, detail: `v${rel.version}` },
    ],
    ok: true,
    latencyMs: Date.now() - t0,
    actor: session?.subject ?? 'console',
    detail: `v${rel.version} allow=${rel.receipt.label_counts.allow} deny=${rel.receipt.label_counts.deny}`,
  }).catch(() => {});

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
