'use client';

/**
 * Dashboard (生产实时数据版).
 *
 * 本页所有数字均来自真实数据源, 不再有硬编码演示值:
 *  - 顶部指标卡  : useCollector() -> /api/summary (接收器实时汇总); 未连接时显示 0, 不造假。
 *  - 终端覆盖    : /api/devices 按 agent_type 聚合 在线/总数。
 *  - 风险事件    : /api/tickets 取待处置工单(按时间倒序)。
 *  - 版本姿态    : /api/summary 的 version_posture 真实分类计数。
 *  - 近期动态    : /api/audit 真实审计条目。
 * 无数据时显示空状态, 绝不展示虚构数字。
 */
import { useEffect, useMemo, useRef, useState } from 'react';
import {
  Laptop,
  Bot,
  AlertTriangle,
  ShieldCheck,
  ChevronDown,
  Play,
  Check,
  Sparkles,
  Network,
  Code2,
  TrendingUp,
  Activity,
  Rocket,
  ScanLine,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import Link from 'next/link';
import {
  ResponsiveContainer,
  ComposedChart,
  Area,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip as RechartsTooltip,
  Legend,
} from 'recharts';

import { useCollector } from '@/components/collector-context';

/* ─── Animated number ──────────────────────────────────────────────────── */
function useAnimatedNumber(target: number) {
  const [value, setValue] = useState(0);
  const raf = useRef(0);
  useEffect(() => {
    const from = value;
    const start = performance.now();
    const dur = 700;
    const tick = (now: number) => {
      const p = Math.min(1, (now - start) / dur);
      setValue(Math.round(from + (target - from) * (1 - Math.pow(1 - p, 3))));
      if (p < 1) raf.current = requestAnimationFrame(tick);
    };
    raf.current = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf.current);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [target]);
  return value;
}

/* ─── 展示映射(仅标签/样式, 不含任何虚构数值) ─────────────────────────── */
const AGENT_LABEL: Record<string, string> = {
  cursor: 'Cursor',
  claude_code: 'Claude Code',
  codex_cli: 'Codex CLI',
  windsurf: 'Windsurf',
  gemini_cli: 'Gemini CLI',
  github_copilot_cli: 'GitHub Copilot',
  qwen_enterprise: 'Qwen 企业版',
  tongyi_lingma: '通义灵码',
  codebuddy: 'CodeBuddy',
  workbuddy: 'WorkBuddy',
  other: '其他',
};

const SEVERITY_META: Record<string, { label: string; color: string }> = {
  critical: { label: '严重', color: 'critical' },
  high: { label: '高危', color: 'red' },
  medium: { label: '中危', color: 'orange' },
  low: { label: '低危', color: 'blue' },
};

const AUDIT_VERB: Record<string, string> = {
  'device:create': '终端注册',
  'device:update': '终端更新',
  'device:delete': '终端移除',
  'ticket:create': '工单创建',
  'ticket:transition': '工单流转',
  'ticket:assign': '工单指派',
  'policy:publish': '策略发布',
  'admin:add': '管理员添加',
  'admin:remove': '管理员移除',
};

function relTime(ts: number): string {
  const s = Math.max(0, Math.floor((Date.now() - ts) / 1000));
  if (s < 60) return `${s} 秒前`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m} 分钟前`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h} 小时前`;
  return `${Math.floor(h / 24)} 天前`;
}

/* ─── 轻量数据类型(仅本页展示所需字段) ────────────────────────────────── */
interface DeviceLite {
  device_id: string;
  agent_type?: string;
  status?: string;
  hostname?: string;
  agent_version?: string;
  owner?: string;
}
interface TicketLite {
  ticket_id: string;
  title: string;
  severity: string;
  status: string;
  device_id?: string;
  created_at: number;
}
interface AuditLite {
  id: number;
  timestamp: number;
  actor: string;
  action: string;
  resource_type?: string;
  detail?: string;
}

/* ─── 防护能力(功能描述, 非指标) ──────────────────────────────────────── */
interface TrendBucketLite {
  t: number;
  reports: number;
  critical: number;
  high: number;
}
const modules = [
  { icon: ScanLine, title: '终端 Agent 发现', desc: '清点已安装的 AI 编码工具', status: '已启用', tone: 'green' },
  { icon: Sparkles, title: 'Skill 扫描器', desc: '权限、指令与依赖', status: '已启用', tone: 'green' },
  { icon: Network, title: 'MCP 扫描器', desc: '工具、密钥与外联', status: '已启用', tone: 'green' },
  { icon: Code2, title: '代码质量扫描', desc: 'SAST、依赖与密钥', status: '已启用', tone: 'green' },
];

/* ─── Typed fetch helper (avoids untyped r.json() '{}') ───────────────── */
async function getJson<T>(url: string): Promise<T | null> {
  try {
    const r = await fetch(url, { cache: 'no-store' });
    if (!r.ok) return null;
    return (await r.json()) as T;
  } catch {
    return null;
  }
}

/* ─── Overview Page ────────────────────────────────────────────────────── */
export default function Home() {
  const { fleet, collectorState } = useCollector();

  const [devices, setDevices] = useState<DeviceLite[] | null>(null);
  const [tickets, setTickets] = useState<TicketLite[] | null>(null);
  const [audit, setAudit] = useState<AuditLite[] | null>(null);
  // 2026-09 总览重构(handoff 4.2)：处置进度需全量工单状态分布（有界 500）。
  const [ticketsAll, setTicketsAll] = useState<TicketLite[] | null>(null);
  // 2026-09 改版：首页趋势图 + KPI 环比数据源（/api/trend → Collector /v1/trend，小时桶）。
  const [trend, setTrend] = useState<{ hours: number; buckets: TrendBucketLite[] } | null>(null);

  useEffect(() => {
    let alive = true;
    getJson<{ devices?: DeviceLite[] }>('/api/devices?limit=2000').then((d) => {
      if (alive) setDevices(Array.isArray(d?.devices) ? (d.devices as DeviceLite[]) : []);
    });
    getJson<{ tickets?: TicketLite[] }>('/api/tickets?limit=6').then((d) => {
      if (alive) setTickets(Array.isArray(d?.tickets) ? (d.tickets as TicketLite[]) : []);
    });
    getJson<{ tickets?: TicketLite[] }>('/api/tickets?limit=500').then((d) => {
      if (alive) setTicketsAll(Array.isArray(d?.tickets) ? (d.tickets as TicketLite[]) : []);
    });
    getJson<{ entries?: AuditLite[] }>('/api/audit?limit=6').then((d) => {
      if (alive) setAudit(Array.isArray(d?.entries) ? (d.entries as AuditLite[]) : []);
    });
    getJson<{ hours?: number; buckets?: TrendBucketLite[] }>('/api/trend?hours=48').then((d) => {
      if (alive && d && Array.isArray(d.buckets)) setTrend({ hours: d.hours ?? 48, buckets: d.buckets });
    });
    return () => {
      alive = false;
    };
  }, []);

  /* 真实指标: 未连接接收器时为 0, 不使用任何虚构回退值 */
  const totalDevices = fleet?.total_devices ?? 0;
  const activeDevices = fleet?.active_devices ?? 0;
  const staleDevices = fleet?.stale_devices ?? 0;
  const currentDevices = fleet?.version_posture?.current ?? 0;
  const coverage = totalDevices ? (currentDevices / totalDevices) * 100 : 0;
  const highRiskDevices = fleet ? fleet.latest_severity.critical + fleet.latest_severity.high : 0;
  const driftDevices = fleet ? totalDevices - currentDevices : 0;

  const animDevices = useAnimatedNumber(totalDevices);
  const animCoverage = useAnimatedNumber(Math.round(coverage * 10));
  const animRisk = useAnimatedNumber(highRiskDevices);
  const animDrift = useAnimatedNumber(driftDevices);

  /* 趋势 KPI：近24h vs 前24h 环比（真实 Collector 数据；未连接为 0/—，不造假） */
  const buckets24 = trend ? trend.buckets.slice(-24) : [];
  const prior24 = trend ? trend.buckets.slice(-48, -24) : [];
  const sumBy = (bs: TrendBucketLite[], k: 'reports' | 'critical' | 'high') => bs.reduce((a, b) => a + (b[k] || 0), 0);
  const reports24 = sumBy(buckets24, 'reports');
  const reportsPrior = sumBy(prior24, 'reports');
  const crit24 = sumBy(buckets24, 'critical');
  const critPrior = sumBy(prior24, 'critical');
  const high24 = sumBy(buckets24, 'high');
  const highPrior = sumBy(prior24, 'high');
  const deltaPct = (cur: number, prev: number) => (prev > 0 ? Math.round(((cur - prev) / prev) * 100) : cur > 0 ? 100 : 0);
  const chartData = buckets24.map((b) => ({ ...b, label: `${new Date(b.t * 1000).getHours()}:00` }));

  /* 系统健康度（handoff 4.2）：五项真实检查 + 环形摘要分；无真实数据不渲染假分数 */
  const healthChecks = [
    { label: 'Collector 连接', ok: collectorState === 'live' },
    { label: 'Agent 在线率', ok: totalDevices > 0 && activeDevices / totalDevices >= 0.5 },
    { label: '版本覆盖', ok: totalDevices > 0 && currentDevices / totalDevices >= 0.5 },
    { label: '上报趋势', ok: trend !== null },
    { label: '审计链路', ok: audit !== null },
  ];
  const healthScore = Math.round((healthChecks.filter((c) => c.ok).length / healthChecks.length) * 100);

  /* 风险资产表：版本漂移 / 上报过期(offline/stale) / 未闭环工单 优先（handoff 4.2） */
  const openTicketDevices = new Set(
    (ticketsAll ?? [])
      .filter((t) => t.status !== 'resolved' && t.status !== 'closed' && t.device_id)
      .map((t) => t.device_id as string),
  );
  const riskRows = (devices ?? [])
    .filter(
      (d) =>
        d.status === 'offline' ||
        d.status === 'stale' ||
        (fleet ? d.agent_version !== fleet.required_agent_version : false) ||
        openTicketDevices.has(d.device_id),
    )
    .slice(0, 6);

  /* 处置进度：工单状态四段分布（handoff 4.2） */
  const dispCounts: Record<string, number> = { resolved: 0, processing: 0, pending: 0, closed: 0 };
  for (const t of ticketsAll ?? []) {
    const s =
      t.status === 'resolved' ? 'resolved' : t.status === 'closed' ? 'closed' : t.status === 'investigating' || t.status === 'acknowledged' ? 'processing' : 'pending';
    dispCounts[s] = (dispCounts[s] ?? 0) + 1;
  }
  const dispTotal = (ticketsAll ?? []).length || 1;

  /* 真实分工具覆盖: 由 /api/devices 按 agent_type 聚合 */
  const toolCoverage = useMemo(() => {
    const map = new Map<string, { total: number; online: number }>();
    for (const d of devices ?? []) {
      const key = d.agent_type || 'other';
      const entry = map.get(key) ?? { total: 0, online: 0 };
      entry.total += 1;
      if (d.status === 'online') entry.online += 1;
      map.set(key, entry);
    }
    return [...map.entries()]
      .map(([type, v]) => ({ type, ...v }))
      .sort((a, b) => b.total - a.total)
      .slice(0, 5);
  }, [devices]);

  /* 真实待处置风险: 开放态工单按时间倒序 */
  const openTickets = useMemo(
    () =>
      (tickets ?? [])
        .filter((t) => ['open', 'acknowledged', 'investigating'].includes(t.status))
        .sort((a, b) => b.created_at - a.created_at)
        .slice(0, 5),
    [tickets],
  );

  /* 真实版本姿态 */
  const posture = fleet?.version_posture;

  return (
    <>
      <div className="page-head animate-entrance animate-entrance-1">
        <div>
          <p className="eyebrow">安全态势 / 实时数据</p>
          <h1>AI Agent 安全总览</h1>
          <p>统一发现、校验并约束员工终端上的 AI Agent 行为。</p>
        </div>
        <div className="head-actions">
          <Button variant="outline" disabled title="时间范围筛选尚未接入">
            <ChevronDown />
            过去 24 小时
          </Button>
          <Button disabled title="任务下发 API 未接入，未对任何终端执行操作">
            <Play fill="currentColor" />
            扫描下发未接入
          </Button>
        </div>
      </div>

      {(!fleet || fleet.total_devices === 0) && (
        <div className="panel animate-entrance" style={{ padding: 14, marginBottom: 14, display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
          <Rocket size={18} />
          <span style={{ fontSize: 13, color: 'var(--muted-foreground)' }}>
            还没有纳管终端？按五步把 Aegis 接入你的团队。
          </span>
          <Link className="handle" href="/onboarding" style={{ marginLeft: 'auto', fontSize: 13 }}>
            打开快速开始 →
          </Link>
        </div>
      )}

      {/* ─── Metric Cards (real fleet summary; — when disconnected) ─── */}
      <div className="metrics">
        <article className="metric animate-entrance animate-entrance-1">
          <div className="metric-top">
            <span>已纳管设备</span>
            <Laptop size={18} />
          </div>
          <strong>{fleet ? animDevices : '—'}</strong>
          <p>
            <em>{activeDevices}</em> 活跃 · {staleDevices} 过期
          </p>
        </article>
        <article className="metric animate-entrance animate-entrance-2">
          <div className="metric-top">
            <span>当前版本覆盖率</span>
            <Bot size={18} />
          </div>
          <strong>
            {fleet ? (animCoverage / 10).toFixed(1) : '—'}
            {fleet ? <small>%</small> : null}
          </strong>
          <Progress value={coverage} />
          <p>
            当前版本设备 <em>{currentDevices}</em> 台
          </p>
        </article>
        <article className="metric danger animate-entrance animate-entrance-3">
          <div className="metric-top">
            <span>高风险设备</span>
            <AlertTriangle size={18} />
          </div>
          <strong>{fleet ? animRisk : '—'}</strong>
          <p>
            <i>{fleet?.latest_severity?.critical ?? 0} 严重</i> · {fleet?.latest_severity?.high ?? 0} 高危
          </p>
        </article>
        <article className="metric animate-entrance animate-entrance-4">
          <div className="metric-top">
            <span>版本漂移设备</span>
            <ShieldCheck size={18} />
          </div>
          <strong>{fleet ? animDrift : '—'}</strong>
          <p>Agent 或策略版本不一致</p>
        </article>
        {/* 2026-09 改版 KPI：近24h 上报量 / 近24h 严重+高危上报，带环比 delta（AIDR 式） */}
        <article className="metric animate-entrance animate-entrance-5">
          <div className="metric-top">
            <span>近24h 上报</span>
            <Activity size={18} />
          </div>
          <strong>{trend ? reports24 : '—'}</strong>
          <p>
            环比前24h{' '}
            {trend ? (
              <em style={{ color: deltaPct(reports24, reportsPrior) >= 0 ? 'var(--destructive)' : 'var(--primary)' }}>
                {deltaPct(reports24, reportsPrior) >= 0 ? '↑' : '↓'} {Math.abs(deltaPct(reports24, reportsPrior))}%
              </em>
            ) : (
              '—'
            )}
          </p>
        </article>
        <article className="metric danger animate-entrance animate-entrance-6">
          <div className="metric-top">
            <span>近24h 严重/高危上报</span>
            <TrendingUp size={18} />
          </div>
          <strong>{trend ? crit24 + high24 : '—'}</strong>
          <p>
            <i>{crit24} 严重</i> · {high24} 高危 · 环比{' '}
            {trend ? (
              <em>{deltaPct(crit24 + high24, critPrior + highPrior) >= 0 ? '↑' : '↓'} {Math.abs(deltaPct(crit24 + high24, critPrior + highPrior))}%</em>
            ) : (
              '—'
            )}
          </p>
        </article>
      </div>

      {/* ─── 上报趋势（近24小时，AIDR 式趋势图）────────────────────────── */}
      <section
        className="panel animate-entrance animate-entrance-5"
        style={{
          padding: 16,
          marginBottom: 16,
          backgroundImage: 'url(/sentinel-threat-grid.svg)',
          backgroundSize: 'cover',
          backgroundPosition: 'center',
        }}
      >
        <div className="panel-head">
          <div>
            <h2>上报趋势（近24小时）</h2>
            <p>
              按小时分桶的终端上报 / 严重 / 高危设备上报数（Collector 真实数据）
              {trend ? ` · 更新于 ${new Date(trend.buckets[trend.buckets.length - 1]?.t * 1000).toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit' })}` : ''}
            </p>
          </div>
          <Badge variant="outline">
            <span className="live-dot" />
            {trend ? '实时' : '未连接'}
          </Badge>
        </div>
        {trend ? (
          <div style={{ display: 'flex', gap: 16, alignItems: 'stretch', flexWrap: 'wrap' }}>
            <div style={{ flex: '1 1 480px', height: 220, minWidth: 300 }}>
              <ResponsiveContainer width="100%" height="100%">
                <ComposedChart data={chartData} margin={{ top: 8, right: 8, left: -18, bottom: 0 }}>
                  <CartesianGrid stroke="var(--border)" strokeDasharray="3 3" vertical={false} />
                  <XAxis dataKey="label" tick={{ fontSize: 11, fill: 'var(--muted-foreground)' }} stroke="var(--border)" interval="preserveStartEnd" />
                  <YAxis tick={{ fontSize: 11, fill: 'var(--muted-foreground)' }} stroke="var(--border)" allowDecimals={false} />
                  <RechartsTooltip
                    contentStyle={{ background: 'var(--popover)', border: '1px solid var(--border)', borderRadius: 8, fontSize: 12 }}
                    labelStyle={{ color: 'var(--muted-foreground)' }}
                  />
                  <Legend wrapperStyle={{ fontSize: 12 }} />
                  <Area type="monotone" dataKey="reports" name="上报数" stroke="var(--primary)" fill="var(--primary)" fillOpacity={0.12} strokeWidth={2} />
                  <Line type="monotone" dataKey="critical" name="严重" stroke="var(--destructive)" strokeWidth={2} dot={false} />
                  <Line type="monotone" dataKey="high" name="高危" stroke="#e8a33d" strokeWidth={2} dot={false} />
                </ComposedChart>
              </ResponsiveContainer>
            </div>
            <div style={{ flex: '0 0 180px', display: 'grid', gap: 10, alignContent: 'start' }}>
              <div>
                <div style={{ fontSize: 12, color: 'var(--muted-foreground)' }}>总上报（24h）</div>
                <strong style={{ fontSize: 22 }}>{reports24}</strong>
              </div>
              <div>
                <div style={{ fontSize: 12, color: 'var(--muted-foreground)' }}>严重（24h）</div>
                <strong style={{ fontSize: 22, color: 'var(--destructive)' }}>{crit24}</strong>
              </div>
              <div>
                <div style={{ fontSize: 12, color: 'var(--muted-foreground)' }}>高危（24h）</div>
                <strong style={{ fontSize: 22, color: '#e8a33d' }}>{high24}</strong>
              </div>
              {/* 计数层(stage-1)：舰队累计发现总数，读 summary.finding_totals（O(设备数)，零 body 解析） */}
              <div style={{ borderTop: '1px solid var(--border)', paddingTop: 8 }}>
                <div style={{ fontSize: 12, color: 'var(--muted-foreground)' }}>舰队累计 严重 / 高危</div>
                <strong style={{ fontSize: 18, fontVariantNumeric: 'tabular-nums' }}>
                  <span style={{ color: 'var(--destructive)' }}>{fleet?.finding_totals?.critical ?? 0}</span>
                  {' / '}
                  <span style={{ color: '#e8a33d' }}>{fleet?.finding_totals?.high ?? 0}</span>
                </strong>
              </div>
            </div>
          </div>
        ) : (
          <p className="empty-hint">接收器未连接，暂无趋势数据。</p>
        )}
      </section>

      {/* ─── 态势三区：系统健康度 / 风险资产 / 处置进度（handoff 4.2）────── */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: 14, marginBottom: 16 }}>
        <section className="panel" style={{ padding: 16 }}>
          <div className="panel-head">
            <div>
              <h2>系统健康度</h2>
              <p>Collector / Agent 在线 / 版本覆盖 / 趋势 / 审计 五项真实检查</p>
            </div>
          </div>
          <div style={{ display: 'flex', gap: 16, alignItems: 'center' }}>
            <div style={{ position: 'relative', width: 92, height: 92, flex: '0 0 92px' }}>
              <svg viewBox="0 0 42 42" width="92" height="92" role="img" aria-label={`健康度 ${healthScore} 分`}>
                <circle cx="21" cy="21" r="15.9" fill="none" stroke="var(--border)" strokeWidth="3.6" />
                <circle
                  cx="21"
                  cy="21"
                  r="15.9"
                  fill="none"
                  stroke={healthScore >= 80 ? 'var(--sentinel-accent)' : healthScore >= 50 ? 'var(--sentinel-warning)' : 'var(--sentinel-danger)'}
                  strokeWidth="3.6"
                  strokeDasharray={`${healthScore} ${100 - healthScore}`}
                  strokeDashoffset="25"
                  strokeLinecap="round"
                />
              </svg>
              <div style={{ position: 'absolute', inset: 0, display: 'grid', placeItems: 'center' }}>
                <strong className="sentinel-metric-value" style={{ fontSize: 22 }}>
                  {trend || fleet ? healthScore : '—'}
                </strong>
              </div>
            </div>
            <ul style={{ listStyle: 'none', margin: 0, padding: 0, display: 'grid', gap: 6, flex: 1 }}>
              {healthChecks.map((c) => (
                <li key={c.label} className="sentinel-status" data-state={c.ok ? 'normal' : 'stale'} style={{ justifyContent: 'space-between', width: '100%' }}>
                  <span>{c.label}</span>
                  <span>{c.ok ? '正常' : '异常'}</span>
                </li>
              ))}
            </ul>
          </div>
        </section>

        <section className="panel" style={{ padding: 16 }}>
          <div className="panel-head">
            <div>
              <h2>风险资产</h2>
              <p>版本漂移 / 上报过期 / 未闭环 优先</p>
            </div>
            <Link href="/devices" style={{ fontSize: 12, color: 'var(--sentinel-cyan)' }}>
              查看全部
            </Link>
          </div>
          <table className="sentinel-table">
            <thead>
              <tr>
                <th>资产</th>
                <th>Agent</th>
                <th>状态</th>
              </tr>
            </thead>
            <tbody>
              {riskRows.length === 0 && (
                <tr>
                  <td colSpan={3} style={{ color: 'var(--muted-foreground)' }}>
                    暂无风险资产
                  </td>
                </tr>
              )}
              {riskRows.map((d) => (
                <tr key={d.device_id}>
                  <td>
                    <b>{d.hostname || d.device_id}</b>
                    <div style={{ fontSize: 11, color: 'var(--muted-foreground)', fontFamily: 'var(--sentinel-font-mono)' }}>{d.device_id}</div>
                  </td>
                  <td style={{ fontFamily: 'var(--sentinel-font-mono)' }}>{d.agent_version ?? '—'}</td>
                  <td>
                    <span className="sentinel-status" data-state={d.status === 'online' ? 'normal' : d.status === 'stale' ? 'warning' : 'offline'}>
                      {d.status ?? '—'}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>

        <section className="panel" style={{ padding: 16 }}>
          <div className="panel-head">
            <div>
              <h2>处置进度</h2>
              <p>工单状态四段分布</p>
            </div>
            <Link href="/risks" style={{ fontSize: 12, color: 'var(--sentinel-cyan)' }}>
              查看全部
            </Link>
          </div>
          <div style={{ display: 'flex', height: 10, borderRadius: 99, overflow: 'hidden', background: 'var(--surface-2)', marginBottom: 12 }}>
            <div style={{ width: `${(dispCounts.resolved / dispTotal) * 100}%`, background: 'var(--sentinel-accent)' }} />
            <div style={{ width: `${(dispCounts.processing / dispTotal) * 100}%`, background: 'var(--sentinel-cyan)' }} />
            <div style={{ width: `${(dispCounts.pending / dispTotal) * 100}%`, background: 'var(--sentinel-warning)' }} />
            <div style={{ width: `${(dispCounts.closed / dispTotal) * 100}%`, background: 'var(--sentinel-text-3)' }} />
          </div>
          <ul style={{ listStyle: 'none', margin: 0, padding: 0, display: 'grid', gap: 6, fontSize: 12 }}>
            <li className="sentinel-status" data-state="resolved" style={{ justifyContent: 'space-between', width: '100%' }}>
              <span>已完成</span>
              <span style={{ fontFamily: 'var(--sentinel-font-mono)' }}>{dispCounts.resolved}</span>
            </li>
            <li className="sentinel-status" data-state="processing" style={{ justifyContent: 'space-between', width: '100%' }}>
              <span>处理中</span>
              <span style={{ fontFamily: 'var(--sentinel-font-mono)' }}>{dispCounts.processing}</span>
            </li>
            <li className="sentinel-status" data-state="warning" style={{ justifyContent: 'space-between', width: '100%' }}>
              <span>待处理</span>
              <span style={{ fontFamily: 'var(--sentinel-font-mono)' }}>{dispCounts.pending}</span>
            </li>
            <li className="sentinel-status" data-state="stale" style={{ justifyContent: 'space-between', width: '100%' }}>
              <span>已关闭</span>
              <span style={{ fontFamily: 'var(--sentinel-font-mono)' }}>{dispCounts.closed}</span>
            </li>
          </ul>
        </section>
      </div>

      {/* ─── Content Grid ─────────────────────────────────────────── */}
      <div className="content-grid">
        <section className="panel capabilities animate-entrance animate-entrance-5">
          <div className="panel-head">
            <div>
              <h2>防护能力</h2>
              <p>自动随企业 Agent 加载并持续更新</p>
            </div>
            <Badge variant="outline">
              <span className="live-dot" />
              发行包可用
            </Badge>
          </div>
          <div className="module-grid">
            {modules.map(({ icon: Icon, title, desc, status, tone }) => (
              <article className="module" key={title}>
                <span className={`module-icon ${tone}`}>
                  <Icon size={19} />
                </span>
                <div>
                  <h3>{title}</h3>
                  <p>{desc}</p>
                </div>
                <span className={`status ${tone}`}>
                  <Check size={13} />
                  {status}
                </span>
              </article>
            ))}
          </div>
          <div className="flow">
            <span>员工安装 AI Agent</span>
            <b>→</b>
            <span>安全 Agent 静默加载</span>
            <b>→</b>
            <span>策略校验 + 持续扫描</span>
            <b>→</b>
            <span className="safe">
              <ShieldCheck size={15} />
              安全放行
            </span>
          </div>
        </section>

        {/* ─── Coverage Panel (real per-agent from /api/devices) ───── */}
        <section className="panel coverage animate-entrance animate-entrance-6">
          <div className="panel-head">
            <div>
              <h2>终端覆盖</h2>
              <p>按 Agent 工具</p>
            </div>
            <Link href="/devices">查看全部</Link>
          </div>
          {devices === null ? (
            <p className="empty-hint">加载终端数据…</p>
          ) : toolCoverage.length === 0 ? (
            <p className="empty-hint">暂无纳管终端；Agent 上报后此处按工具显示在线覆盖。</p>
          ) : (
            toolCoverage.map(({ type, total, online }) => (
              <div className="coverage-row" key={type}>
                <div className="tool-logo">{(AGENT_LABEL[type] ?? type).slice(0, 1)}</div>
                <div className="coverage-data">
                  <div>
                    <strong>{AGENT_LABEL[type] ?? type}</strong>
                    <span>
                      {online}/{total} 在线
                    </span>
                    <span className="trend-badge up">{total ? Math.round((online / total) * 100) : 0}%</span>
                  </div>
                  <Progress value={total ? (online / total) * 100 : 0} />
                </div>
              </div>
            ))
          )}
        </section>

        {/* ─── Risks Panel (real open tickets) ─────────────────────── */}
        <section className="panel risks animate-entrance animate-entrance-7" id="risks">
          <div className="panel-head">
            <div>
              <h2>风险事件实时</h2>
              <p>按风险等级与时间排序</p>
            </div>
            <Link href="/risks">进入风险中心 →</Link>
          </div>
          <div className="risk-table">
            {tickets === null ? (
              <p className="empty-hint">加载风险事件…</p>
            ) : openTickets.length === 0 ? (
              <p className="empty-hint">暂无待处置风险事件；新的上报会自动进入该队列。</p>
            ) : (
              openTickets.map((t) => {
                const meta = SEVERITY_META[t.severity] ?? { label: t.severity, color: 'orange' };
                return (
                  <div className="risk-row" key={t.ticket_id}>
                    <span className={`severity ${meta.color}`}>{meta.label}</span>
                    <div className="risk-main">
                      <strong>{t.title}</strong>
                      <span>{t.ticket_id}</span>
                    </div>
                    <span className="device">{t.device_id || '—'}</span>
                    <span className="time">{relTime(t.created_at)}</span>
                    <Link className="handle" href={`/risks?ticket=${encodeURIComponent(t.ticket_id)}`}>
                      处置
                    </Link>
                  </div>
                );
              })
            )}
          </div>
        </section>

        {/* ─── Version Posture Panel (real summary counts) ─────────── */}
        <section className="panel score animate-entrance animate-entrance-7">
          <div className="panel-head">
            <div>
              <h2>版本姿态</h2>
              <p>接收器实时版本分类</p>
            </div>
          </div>
          <div className="score-body">
            <div className="score-list" style={{ width: '100%' }}>
              <p>
                <span className="score-dot" style={{ background: '#49e8a5' }} />
                <span>当前版本</span>
                <b>{posture?.current ?? 0}</b>
              </p>
              <p>
                <span className="score-dot" style={{ background: '#ffb454' }} />
                <span>Agent 版本不一致</span>
                <b>{posture?.agent_mismatch ?? 0}</b>
              </p>
              <p>
                <span className="score-dot" style={{ background: '#ff8f6b' }} />
                <span>策略版本不一致</span>
                <b>{posture?.policy_mismatch ?? 0}</b>
              </p>
              <p>
                <span className="score-dot" style={{ background: '#ff685f' }} />
                <span>两者均不一致</span>
                <b>{posture?.both_mismatch ?? 0}</b>
              </p>
              <p>
                <span className="score-dot" style={{ background: '#8a9a94' }} />
                <span>未知</span>
                <b>{posture?.unknown ?? 0}</b>
              </p>
            </div>
          </div>
        </section>
      </div>

      {/* ─── Recent Activity Timeline (real audit entries) ─────────── */}
      <section className="panel activity-timeline animate-entrance animate-entrance-7">
        <div className="panel-head">
          <div>
            <h2>近期动态</h2>
            <p>最近的安全事件与操作</p>
          </div>
          <Badge variant="outline">
            <TrendingUp size={13} />
            实时更新
          </Badge>
        </div>
        <div className="timeline">
          {audit === null ? (
            <p className="empty-hint">加载动态…</p>
          ) : audit.length === 0 ? (
            <p className="empty-hint">暂无动态；治理操作与终端上报会实时记录在此。</p>
          ) : (
            audit.map((event, idx) => (
              <div
                className="timeline-item animate-entrance"
                key={event.id}
                style={{ animationDelay: `${idx * 80 + 500}ms` }}
              >
                <div className="timeline-marker">
                  <span className="timeline-dot">
                    <Activity size={12} />
                  </span>
                  {idx < audit.length - 1 && <span className="timeline-line" />}
                </div>
                <div className="timeline-content">
                  <div className="timeline-header">
                    <strong>{AUDIT_VERB[event.action] ?? event.action}</strong>
                    <span className="timeline-time">{relTime(event.timestamp)}</span>
                  </div>
                  <p>
                    {event.actor}
                    {event.detail ? ` · ${event.detail}` : ''}
                  </p>
                </div>
              </div>
            ))
          )}
        </div>
      </section>
    </>
  );
}
