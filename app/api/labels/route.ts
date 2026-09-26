import { NextResponse } from 'next/server';
import { requireAdmin, getSession } from '@/lib/auth';
import {
  listLabels,
  setLabel,
  removeLabel,
  normalizePrefixKey,
  DISPOSITIONS,
  type AssetType,
  type Disposition,
} from '@/lib/labels';
import { logAudit } from '@/lib/store';
import { labelsReadyFor } from '@/lib/label-readiness';

export const dynamic = 'force-dynamic';

const NO_STORE = { 'Cache-Control': 'no-store' } as const;

function isAssetType(v: unknown): v is AssetType {
  return v === 'skill' || v === 'mcp' || v === 'path' || v === 'prefix';
}

/** GET /api/labels — 列出资产标签/处置（登录即可读）。 */
export async function GET(request: Request) {
  const session = getSession(request);
  if (!session) return NextResponse.json({ error: 'unauthenticated' }, { status: 401, headers: NO_STORE });
  if (!(await labelsReadyFor('labels:read', session.subject))) {
    return NextResponse.json({ error: 'labels_unavailable' }, { status: 503, headers: NO_STORE });
  }
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
  // prefix（目录前缀批量忽略）：归一化（~折叠/小写/尾斜杠强制）；非目录形态拒绝。
  const normalizedKey = assetType === 'prefix' ? normalizePrefixKey(assetKey) : assetKey;
  if (assetType === 'prefix' && !normalizedKey) {
    return NextResponse.json(
      { error: 'invalid_prefix', hint: '目录前缀必须以 / 或 \\ 结尾，且不能是根/家目录这类全量级路径' },
      { status: 400, headers: NO_STORE },
    );
  }
  const finalKey = normalizedKey ?? assetKey;
  if (!finalKey || (assetType === 'path' || assetType === 'prefix' ? finalKey.length > 256 : finalKey.length > 128)) {
    return NextResponse.json({ error: 'invalid_asset_key' }, { status: 400, headers: NO_STORE });
  }
  // skill/mcp 的 asset_key 是资产「名字」(skill 名 / MCP server 名)，不是文件路径。拒绝路径型
  // key（含 / \ 或以 ~ 开头）——历史上处置中心曾按 finding 的文件 path 建标签，污染出
  // "mcp:~/.codex/config.toml" 这类永不命中的垃圾白名单项。skill 名允许含 ':'(如
  // product-design:frame)，故只拦路径分隔符与 '~' 前缀。
  // path 类型则**专门**承载文件路径（代码质量发现 hardcoded_secret/insecure_tls 的 FP 处置
  // 通道）：key 必须是归一化路径(~ / 或盘符开头)，与 skill/mcp 的名字空间隔离(mapKey 带类型前缀)。
  if (assetType === 'path') {
    if (!assetKey.startsWith('~') && !assetKey.startsWith('/') && !/^[A-Za-z]:/.test(assetKey)) {
      return NextResponse.json({ error: 'invalid_asset_key' }, { status: 400, headers: NO_STORE });
    }
  } else if (assetType !== 'prefix' && (/[/\\]/.test(assetKey) || assetKey.startsWith('~'))) {
    return NextResponse.json({ error: 'invalid_asset_key' }, { status: 400, headers: NO_STORE });
  }

  const rawDisp = body.disposition;
  if (rawDisp !== undefined && !(DISPOSITIONS as string[]).includes(String(rawDisp))) {
    return NextResponse.json({ error: 'invalid_disposition' }, { status: 400, headers: NO_STORE });
  }
  const tags = Array.isArray(body.tags) ? (body.tags as unknown[]).map((t) => String(t)).filter(Boolean).slice(0, 20) : undefined;

  if (!(await labelsReadyFor('labels:write', session?.subject ?? 'console'))) {
    return NextResponse.json({ error: 'labels_unavailable' }, { status: 503, headers: NO_STORE });
  }
  const rec = setLabel({
    asset_type: assetType,
    asset_key: finalKey,
    ...(tags !== undefined ? { tags } : {}),
    ...(rawDisp !== undefined ? { disposition: String(rawDisp) as Disposition } : {}),
    ...(typeof body.note === 'string' ? { note: body.note.slice(0, 500) } : {}),
    updated_by: session?.subject ?? 'console',
  });
  logAudit({
    actor: session?.subject ?? 'console',
    action: 'label:set',
    resource_type: 'system',
    resource_id: `${assetType}:${finalKey}`,
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
  if (!(await labelsReadyFor('labels:delete', session?.subject ?? 'console'))) {
    return NextResponse.json({ error: 'labels_unavailable' }, { status: 503, headers: NO_STORE });
  }
  const delKey = assetType === 'prefix' ? (normalizePrefixKey(assetKey) ?? assetKey) : assetKey;
  const removed = removeLabel(assetType, delKey);
  logAudit({
    actor: session?.subject ?? 'console',
    action: 'label:remove',
    resource_type: 'system',
    resource_id: `${assetType}:${delKey}`,
    detail: removed ? 'removed' : 'not_found',
  });
  return NextResponse.json({ removed }, { headers: NO_STORE });
}
