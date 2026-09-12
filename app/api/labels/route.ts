import { NextResponse } from 'next/server';
import { requireAdmin, getSession } from '@/lib/auth';
import {
  ensureLabelsLoaded,
  listLabels,
  setLabel,
  removeLabel,
  DISPOSITIONS,
  type AssetType,
  type Disposition,
} from '@/lib/labels';
import { logAudit } from '@/lib/store';

export const dynamic = 'force-dynamic';

const NO_STORE = { 'Cache-Control': 'no-store' } as const;

function isAssetType(v: unknown): v is AssetType {
  return v === 'skill' || v === 'mcp';
}

/** GET /api/labels — 列出资产标签/处置（登录即可读）。 */
export async function GET(request: Request) {
  const session = getSession(request);
  if (!session) return NextResponse.json({ error: 'unauthenticated' }, { status: 401, headers: NO_STORE });
  await ensureLabelsLoaded().catch(() => {});
  return NextResponse.json({ labels: listLabels() }, { headers: NO_STORE });
}

/** POST /api/labels — 设置/更新标签与处置（admin）。body: {asset_type, asset_key, tags?, disposition?, note?} */
export async function POST(request: Request) {
  const denied = requireAdmin(request);
  if (denied) return denied;
  const session = getSession(request);
  let body: Record<string, unknown>;
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: 'invalid_json' }, { status: 400, headers: NO_STORE });
  }
  const assetType = body.asset_type;
  const assetKey = String(body.asset_key ?? '').trim();
  if (!isAssetType(assetType)) return NextResponse.json({ error: 'invalid_asset_type' }, { status: 400, headers: NO_STORE });
  if (!assetKey || assetKey.length > 128) return NextResponse.json({ error: 'invalid_asset_key' }, { status: 400, headers: NO_STORE });

  const rawDisp = body.disposition;
  if (rawDisp !== undefined && !(DISPOSITIONS as string[]).includes(String(rawDisp))) {
    return NextResponse.json({ error: 'invalid_disposition' }, { status: 400, headers: NO_STORE });
  }
  const tags = Array.isArray(body.tags) ? (body.tags as unknown[]).map((t) => String(t)).filter(Boolean).slice(0, 20) : undefined;

  await ensureLabelsLoaded().catch(() => {});
  const rec = setLabel({
    asset_type: assetType,
    asset_key: assetKey,
    ...(tags !== undefined ? { tags } : {}),
    ...(rawDisp !== undefined ? { disposition: String(rawDisp) as Disposition } : {}),
    ...(typeof body.note === 'string' ? { note: body.note.slice(0, 500) } : {}),
    updated_by: session?.subject ?? 'console',
  });
  logAudit({
    actor: session?.subject ?? 'console',
    action: 'label:set',
    resource_type: 'system',
    resource_id: `${assetType}:${assetKey}`,
    detail: `disposition=${rec.disposition || 'unset'} tags=${rec.tags.join(',') || '-'}`,
  });
  return NextResponse.json({ label: rec }, { status: 200, headers: NO_STORE });
}

/** DELETE /api/labels?asset_type=X&asset_key=Y — 移除标签/处置（admin）。 */
export async function DELETE(request: Request) {
  const denied = requireAdmin(request);
  if (denied) return denied;
  const session = getSession(request);
  const url = new URL(request.url);
  const assetType = url.searchParams.get('asset_type');
  const assetKey = (url.searchParams.get('asset_key') ?? '').trim();
  if (!isAssetType(assetType) || !assetKey) {
    return NextResponse.json({ error: 'invalid_params' }, { status: 400, headers: NO_STORE });
  }
  await ensureLabelsLoaded().catch(() => {});
  const removed = removeLabel(assetType, assetKey);
  logAudit({
    actor: session?.subject ?? 'console',
    action: 'label:remove',
    resource_type: 'system',
    resource_id: `${assetType}:${assetKey}`,
    detail: removed ? 'removed' : 'not_found',
  });
  return NextResponse.json({ removed }, { headers: NO_STORE });
}
