import { NextResponse } from 'next/server';
import { getSession } from '@/lib/auth';
import { BASE_POLICY } from '@/lib/policy';
import { ensureLabelsLoaded, allowedAssetKeys, findingAsset, isFindingAllowed } from '@/lib/labels';

export const dynamic = 'force-dynamic';

const NO_STORE = { 'Cache-Control': 'no-store' } as const;
const CATEGORIES = ['skill', 'mcp', 'code'] as const;
type Category = (typeof CATEGORIES)[number];

// kind → 类目分类：以策略规则集为权威（skill_rules 含 credential_access/unbounded_shell 等
// 不带 "skill" 字样的命中），再用子串兜底。运维类命中（enrollment/reporting/policy_reload）
// 归 other，不在三个扫描器页展示。
const SKILL_RULES = new Set(BASE_POLICY.skill_rules);
const MCP_RULES = new Set(BASE_POLICY.mcp_rules);
const CODE_RULES = new Set(BASE_POLICY.code_rules);
function categorize(kind: string): Category | 'other' {
  const k = kind.toLowerCase();
  if (SKILL_RULES.has(kind) || k.includes('skill')) return 'skill';
  if (MCP_RULES.has(kind) || k.includes('mcp')) return 'mcp';
  if (CODE_RULES.has(kind) || k.includes('dependency') || k.includes('secret') || k.includes('unicode')) return 'code';
  return 'other';
}

const SEVERITY_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
const SEVERITIES = ['critical', 'high', 'medium', 'low'] as const;

interface RawFinding {
  kind?: unknown;
  severity?: unknown;
  path?: unknown;
  message?: unknown;
  evidence?: unknown;
  signal_matches?: unknown;
  asset_type?: unknown;
  asset_key?: unknown;
}

/**
 * GET /api/findings?category=skill|mcp|code|all&limit=N
 * 跨设备聚合 Collector 真实上报的发现，按类目过滤、严重度+时间排序。
 * 这是 Skill/MCP/代码质量三个扫描器页的真实数据源——此前那些页面渲染的是伪造静态
 * 样例却标注"实时"，违反"绝不伪造数据"红线。Collector 不可达时诚实返回 connected:false
 * 与空列表，由前端展示空态/断连态，绝不编造发现。
 */
export async function GET(request: Request) {
  const session = getSession(request);
  if (!session) return NextResponse.json({ error: 'unauthenticated' }, { status: 401, headers: NO_STORE });

  const url = new URL(request.url);
  const catParam = url.searchParams.get('category') ?? 'all';
  const category: Category | 'all' = (CATEGORIES as readonly string[]).includes(catParam)
    ? (catParam as Category)
    : 'all';
  const limit = Math.min(Math.max(Number(url.searchParams.get('limit') ?? 200) || 200, 1), 1000);

  const empty = { connected: false as const, category, devices: 0, devices_with_findings: 0, suppressed: 0, counts: { total: 0, critical: 0, high: 0, medium: 0, low: 0 }, findings: [] as unknown[] };
  const collector = process.env.AEGIS_COLLECTOR_URL;
  const token = process.env.AEGIS_COLLECTOR_TOKEN;
  if (!collector || !token) return NextResponse.json(empty, { headers: NO_STORE });

  // 加白抑制：已处置为 allow 的资产，其发现不再作为告警出现（"已加白不再告警"），
  // 且既有告警随本次查询即时消失（"加白后同源告警自动消除"）。抑制是查询期过滤，
  // 不销毁 Collector 侧原始发现（审计留痕仍在）。归一化优先用终端显式 asset_key，
  // 兼容旧终端从 path/message 派生；无法判定则不抑制（绝不误藏真实告警）。
  await ensureLabelsLoaded().catch(() => {});
  const allowed = allowedAssetKeys();

  // P1-1：游标翻页拉取跨设备聚合发现，取代对每台设备各发一个 /v1/findings 的 N+1 扇出
  // （30k 下旧写法单页最多 1 万并发打垮 ThreadingHTTPServer 采集器 + 控制台 worker OOM）。
  // category 过滤与加白抑制仍在本地做（categorize 规则单一可信源，不与采集器双写）；任一页
  // 失败即诚实降级为 connected:false 空态，绝不拿半量冒充全量、绝不伪造发现。
  const base = collector.replace(/\/$/, '');
  const agg: Array<{ device_id: string; scanned_at: number; finding: RawFinding }> = [];
  let devicesScanned = 0;
  let cursor = '';
  for (let page = 0; page < 200; page += 1) {
    const qs = new URLSearchParams({ limit: '1000' });
    if (cursor) qs.set('cursor', cursor);
    let data: { complete?: boolean; next_cursor?: string; devices_scanned?: number; findings?: Array<{ device_id: string; scanned_at: number; finding: RawFinding }> };
    try {
      const res = await fetch(`${base}/v1/findings/aggregate?${qs.toString()}`, {
        headers: { Authorization: `Bearer ${token}`, Accept: 'application/json' },
        cache: 'no-store',
        signal: AbortSignal.timeout(8000),
      });
      if (!res.ok) return NextResponse.json(empty, { headers: NO_STORE });
      data = (await res.json()) as typeof data;
    } catch {
      return NextResponse.json(empty, { headers: NO_STORE });
    }
    devicesScanned += typeof data.devices_scanned === 'number' ? data.devices_scanned : 0;
    if (Array.isArray(data.findings)) agg.push(...data.findings);
    cursor = typeof data.next_cursor === 'string' ? data.next_cursor : '';
    if (data.complete !== false || !cursor) break;
  }

  const all: Array<Record<string, unknown>> = [];
  const devicesWithFindingsSet = new Set<string>();
  let suppressed = 0;
  for (const item of agg) {
    const f = item.finding ?? {};
    const deviceId = String(item.device_id ?? '');
    const kind = typeof f.kind === 'string' ? f.kind : '';
    const c = categorize(kind);
    if (category !== 'all' && c !== category) continue;
    // 命中加白资产 → 抑制（不计入告警/计数），仅累计 suppressed 供透明展示。
    if (isFindingAllowed(f, allowed)) { suppressed += 1; continue; }
    const asset = findingAsset(f);
    if (deviceId) devicesWithFindingsSet.add(deviceId);
    all.push({
      device_id: deviceId,
      kind,
      category: c,
      severity: typeof f.severity === 'string' ? f.severity : 'low',
      path: typeof f.path === 'string' ? f.path : '',
      message: typeof f.message === 'string' ? f.message : '',
      ...(asset ? { asset_type: asset.asset_type, asset_key: asset.asset_key } : {}),
      ...(f.signal_matches !== undefined ? { signal_matches: f.signal_matches } : {}),
      scanned_at: item.scanned_at || 0,
    });
  }
  const devicesWithFindings = devicesWithFindingsSet.size;

  all.sort(
    (a, b) =>
      (SEVERITY_RANK[String(a.severity)] ?? 9) - (SEVERITY_RANK[String(b.severity)] ?? 9) ||
      Number(b.scanned_at) - Number(a.scanned_at),
  );

  const counts = { total: all.length, critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of all) {
    const s = String(f.severity) as (typeof SEVERITIES)[number];
    if (SEVERITIES.includes(s)) counts[s] += 1;
  }

  return NextResponse.json(
    {
      connected: true,
      category,
      devices: devicesScanned,
      devices_with_findings: devicesWithFindings,
      suppressed,
      counts,
      findings: all.slice(0, limit),
    },
    { headers: NO_STORE },
  );
}
