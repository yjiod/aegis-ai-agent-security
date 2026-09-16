import { NextResponse } from 'next/server';
import { requireAdmin, getSession } from '@/lib/auth';
import { ensureLabelsLoaded, listLabels, setLabel } from '@/lib/labels';
import { defaultBundledEntries } from '@/lib/default-allowlist';
import { logAudit } from '@/lib/store';

export const dynamic = 'force-dynamic';

const NO_STORE = { 'Cache-Control': 'no-store' } as const;

/**
 * POST /api/labels/seed-defaults — 把各 AI Agent 默认自带的 skill/MCP 录入白名单库
 * （disposition=allow, note=默认自带, tags=[default-bundled]）。已存在且已处置的条目
 * 不覆盖（尊重人工处置）；仅缺失或尚未处置(disposition='')的写入 allow。
 * 之后随签名策略发布为 allowed_skills/allowed_mcp，终端对默认自带资产不再产生
 * unknown_* 发现；额外加载的才进入审查/处置。仅 admin。
 */
export async function POST(request: Request) {
  const denied = requireAdmin(request);
  if (denied) return denied;

  await ensureLabelsLoaded().catch(() => {});
  const existing = new Map(listLabels().map((l) => [`${l.asset_type}:${l.asset_key}`, l]));
  const actor = getSession(request)?.subject ?? 'admin';
  let seeded = 0;
  let skipped = 0;
  for (const entry of defaultBundledEntries()) {
    const key = `${entry.asset_type}:${entry.asset_key}`;
    const prev = existing.get(key);
    if (prev && prev.disposition) {
      skipped += 1; // 已有人工处置，不覆盖
      continue;
    }
    setLabel({
      asset_type: entry.asset_type,
      asset_key: entry.asset_key,
      disposition: 'allow',
      tags: ['default-bundled'],
      note: '默认自带',
      updated_by: actor,
    });
    seeded += 1;
  }
  logAudit({
    actor,
    action: 'labels:seed_defaults',
    resource_type: 'policy',
    detail: `录入默认自带白名单 seeded=${seeded} skipped=${skipped}`,
  });
  return NextResponse.json({ ok: true, seeded, skipped }, { headers: NO_STORE });
}
