import { NextResponse } from 'next/server';
import { requireAdmin, getSession } from '@/lib/auth';
import { listLabels, setLabelInMemory, persistLabelsDurable, type AssetLabel } from '@/lib/labels';
import { defaultBundledEntries } from '@/lib/default-allowlist';
import { logAudit } from '@/lib/store';
import { labelsReadyFor } from '@/lib/label-readiness';

export const dynamic = 'force-dynamic';

const NO_STORE = { 'Cache-Control': 'no-store' } as const;

/**
 * POST /api/labels/seed-defaults — 把各 AI Agent 默认自带的 skill/MCP 录入白名单库
 * （disposition=allow, note=默认自带, tags=[default-bundled]）。已存在且已处置的条目
 * 不覆盖（尊重人工处置）；仅缺失或尚未处置(disposition='')的写入 allow。
 * 之后随签名策略发布为 allowed_skills/allowed_mcp，终端对默认自带资产不再产生
 * unknown_* 发现；额外加载的才进入审查/处置。仅 admin。
 *
 * 持久化（2026-09-25 生产事故修复）：批量写走 persistLabelsDurable（单事务可等待），
 * 绝不再用 fire-and-forget——此前 501 条 after() 写静默丢 291 条，重启后
 * 签名策略 allow 从 594 误缩到 300。落库失败返回 500，绝不谎报成功。
 */
export async function POST(request: Request) {
  const denied = requireAdmin(request);
  if (denied) return denied;

  const actor = getSession(request)?.subject ?? 'admin';
  if (!(await labelsReadyFor('labels:seed_defaults', actor))) {
    return NextResponse.json({ error: 'labels_unavailable' }, { status: 503, headers: NO_STORE });
  }
  const existing = new Map(listLabels().map((l) => [`${l.asset_type}:${l.asset_key}`, l]));
  let seeded = 0;
  let skipped = 0;
  const pending: AssetLabel[] = [];
  for (const entry of defaultBundledEntries()) {
    const key = `${entry.asset_type}:${entry.asset_key}`;
    const prev = existing.get(key);
    if (prev && prev.disposition) {
      skipped += 1; // 已有人工处置，不覆盖
      continue;
    }
    const rec = setLabelInMemory({
      asset_type: entry.asset_type,
      asset_key: entry.asset_key,
      disposition: 'allow',
      tags: ['default-bundled'],
      note: '默认自带',
      updated_by: actor,
    });
    pending.push(rec);
    seeded += 1;
  }
  try {
    await persistLabelsDurable(pending);
  } catch (e) {
    return NextResponse.json(
      { error: 'persist_failed', hint: '批量落库失败，本次种子未生效；请重试', detail: e instanceof Error ? e.message : String(e) },
      { status: 500, headers: NO_STORE },
    );
  }
  logAudit({
    actor,
    action: 'labels:seed_defaults',
    resource_type: 'policy',
    detail: `录入默认自带白名单 seeded=${seeded} skipped=${skipped}`,
  });
  return NextResponse.json({ ok: true, seeded, skipped }, { headers: NO_STORE });
}
