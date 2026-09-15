import { NextResponse } from 'next/server';
import { getSession } from '@/lib/auth';
import { fetchCollectorDevices } from '@/lib/collector-devices';
import { BASE_POLICY } from '@/lib/policy';

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
}

/** 拉取单台设备最新报告的发现（沿用 /api/devices/[id]/findings 的 Collector 代理方式）。 */
async function fetchDeviceFindings(
  deviceId: string,
): Promise<{ scanned_at: number; findings: RawFinding[] } | null> {
  const collector = process.env.AEGIS_COLLECTOR_URL;
  const token = process.env.AEGIS_COLLECTOR_TOKEN;
  if (!collector || !token) return null;
  try {
    const res = await fetch(
      `${collector.replace(/\/$/, '')}/v1/findings?device_id=${encodeURIComponent(deviceId)}&limit=1000`,
      {
        headers: { Authorization: `Bearer ${token}`, Accept: 'application/json' },
        cache: 'no-store',
        signal: AbortSignal.timeout(5000),
      },
    );
    if (!res.ok) return null;
    const data = (await res.json()) as { scanned_at?: unknown; findings?: unknown };
    return {
      scanned_at: typeof data.scanned_at === 'number' ? data.scanned_at : 0,
      findings: Array.isArray(data.findings) ? (data.findings as RawFinding[]) : [],
    };
  } catch {
    return null;
  }
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

  const devices = await fetchCollectorDevices();
  const empty = { connected: false as const, category, devices: 0, devices_with_findings: 0, counts: { total: 0, critical: 0, high: 0, medium: 0, low: 0 }, findings: [] as unknown[] };
  if (devices === null) return NextResponse.json(empty, { headers: NO_STORE });

  // 并发拉取各设备发现（机队规模有界；Collector 侧另有速率限制兜底）。
  const perDevice = await Promise.all(
    devices.map(async (d) => ({ device: d, res: await fetchDeviceFindings(d.device_id) })),
  );

  const all: Array<Record<string, unknown>> = [];
  let devicesWithFindings = 0;
  for (const { device, res } of perDevice) {
    if (!res) continue;
    let matched = 0;
    for (const f of res.findings) {
      const kind = typeof f.kind === 'string' ? f.kind : '';
      const c = categorize(kind);
      if (category !== 'all' && c !== category) continue;
      matched += 1;
      all.push({
        device_id: device.device_id,
        kind,
        category: c,
        severity: typeof f.severity === 'string' ? f.severity : 'low',
        path: typeof f.path === 'string' ? f.path : '',
        message: typeof f.message === 'string' ? f.message : '',
        ...(f.signal_matches !== undefined ? { signal_matches: f.signal_matches } : {}),
        scanned_at: res.scanned_at || device.last_seen || 0,
      });
    }
    if (matched > 0) devicesWithFindings += 1;
  }

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
      devices: devices.length,
      devices_with_findings: devicesWithFindings,
      counts,
      findings: all.slice(0, limit),
    },
    { headers: NO_STORE },
  );
}
