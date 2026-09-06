'use client';
import { useEffect, useRef, useState } from 'react';
import {
  Activity,
  AlertTriangle,
  ArrowDownRight,
  ArrowUpRight,
  Bot,
  Check,
  ChevronDown,
  CircleDot,
  Code2,
  Cpu,
  Laptop,
  LockKeyhole,
  Network,
  Play,
  RefreshCw,
  Search,
  Settings,
  ShieldCheck,
  SlidersHorizontal,
  Sparkles,
  TrendingUp,
  Users,
  Wrench,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import {
  AreaChart,
  Area,
  RadialBarChart,
  RadialBar,
  PolarAngleAxis,
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
} from 'recharts';

/* ─── Animated Number Hook ─────────────────────────────────────────────── */
function useAnimatedNumber(target: number, duration = 800): number {
  const [value, setValue] = useState(0);
  const startTime = useRef<number | null>(null);
  const raf = useRef<number>(0);

  useEffect(() => {
    startTime.current = null;
    const easeOutExpo = (t: number) => (t === 1 ? 1 : 1 - Math.pow(2, -10 * t));
    function step(ts: number) {
      if (startTime.current === null) startTime.current = ts;
      const elapsed = ts - startTime.current;
      const progress = Math.min(elapsed / duration, 1);
      setValue(Math.round(easeOutExpo(progress) * target));
      if (progress < 1) raf.current = requestAnimationFrame(step);
    }
    raf.current = requestAnimationFrame(step);
    return () => cancelAnimationFrame(raf.current);
  }, [target, duration]);

  return value;
}

/* ─── Demo Data ────────────────────────────────────────────────────────── */
const sparkDevices = [280, 295, 310, 305, 312, 308, 312];
const sparkCoverage = [91.2, 92.4, 93.1, 94.0, 95.2, 96.1, 96.8];
const sparkRisk = [18, 16, 15, 14, 13, 12, 12];
const sparkDrift = [22, 19, 17, 15, 13, 11, 10];

const coverageTrends: { name: string; total: number; online: number; delta: number }[] = [
  { name: 'Cursor', total: 124, online: 100, delta: 3.2 },
  { name: 'Claude Code', total: 86, online: 78, delta: 5.1 },
  { name: 'Codex CLI', total: 64, online: 58, delta: -1.4 },
  { name: 'Windsurf', total: 38, online: 34, delta: 2.8 },
];

const radialScoreData = [
  { name: '综合评分', value: 92, fill: '#49e8a5' },
  { name: '配置合规', value: 98, fill: '#37c48c' },
  { name: 'Agent 行为', value: 94, fill: '#2fae7c' },
  { name: '代码安全', value: 87, fill: '#28976c' },
];

const scoreData = [
  { name: '配置合规', value: 98, fill: '#49e8a5' },
  { name: 'Agent 行为', value: 94, fill: '#49e8a5' },
  { name: '代码安全', value: 87, fill: '#49e8a5' },
];

const activityTimeline = [
  { time: '14:32', icon: Laptop, label: '新设备接入', desc: 'ENG-LT-1205 完成注册并通过基线校验' },
  { time: '13:58', icon: RefreshCw, label: '策略同步完成', desc: 'v4.8 基线已推送至 312 台在线终端' },
  { time: '12:45', icon: ShieldCheck, label: '高危事件已处置', desc: 'MCP 越权访问已隔离，工单 #R-2841 关闭' },
  { time: '11:20', icon: Code2, label: '基线更新推送', desc: 'SEC-DEP-04 规则阈值调整为 critical 阻断' },
  { time: '10:05', icon: Cpu, label: 'Agent 版本升级', desc: 'Endpoint Agent 0.30.0 → 0.30.1 灰度 15%' },
];

const scanTrendData = [
  { day: '周一', count: 12 },
  { day: '周二', count: 18 },
  { day: '周三', count: 9 },
  { day: '周四', count: 22 },
  { day: '周五', count: 15 },
  { day: '周六', count: 6 },
  { day: '周日', count: 4 },
];

const modules = [
  {
    icon: ShieldCheck,
    title: '安全编码基线',
    desc: '企业规则基线 · v4.8',
    status: '已打包',
    tone: 'green',
  },
  {
    icon: Sparkles,
    title: 'Skill 扫描器',
    desc: '权限、指令与依赖',
    status: '已打包',
    tone: 'blue',
  },
  {
    icon: Network,
    title: 'MCP 扫描器',
    desc: '工具、密钥与外联',
    status: '已启用',
    tone: 'green',
  },
  {
    icon: Code2,
    title: '代码质量扫描',
    desc: 'SAST、依赖与密钥',
    status: '已启用',
    tone: 'green',
  },
];
const risks = [
  {
    severity: '高危',
    title: 'MCP Server 请求了未授权文件目录',
    source: 'cursor-mcp-filesystem',
    device: 'MKT-LT-2841',
    time: '2 分钟前',
    color: 'red',
  },
  {
    severity: '中危',
    title: 'Skill 包含可疑的隐藏指令覆盖',
    source: 'prompt-helper.skill',
    device: 'ENG-MBP-1032',
    time: '18 分钟前',
    color: 'orange',
  },
  {
    severity: '中危',
    title: '生成代码使用弱随机数创建会话令牌',
    source: 'payment-service / PR #184',
    device: 'ENG-LT-0948',
    time: '31 分钟前',
    color: 'orange',
  },
];
const viewNames = {
  onboarding: '接入中心',
  devices: '设备与 Agent',
  risks: '风险中心',
  baseline: '安全编码规范基线',
  skills: 'Skill 扫描器',
  mcp: 'MCP 扫描器',
  quality: '代码质量扫描',
  policies: '策略配置',
  team: '团队与权限',
  settings: '系统设置',
} as const;
type DetailKey = keyof typeof viewNames;
type FleetSummary = {
  total_devices: number;
  active_devices: number;
  stale_devices: number;
  required_agent_version: string;
  required_policy_version: string;
  latest_severity: { critical: number; high: number; normal: number };
  version_posture: {
    current: number;
    agent_mismatch: number;
    policy_mismatch: number;
    both_mismatch: number;
    unknown: number;
  };
  credential_posture?: { current: number; previous: number; legacy: number };
};

/* ─── Sparkline Component ──────────────────────────────────────────────── */
function Sparkline({ data, color = '#49e8a5' }: { data: number[]; color?: string }) {
  const chartData = data.map((v, i) => ({ x: i, y: v }));
  return (
    <div className="sparkline-wrap">
      <ResponsiveContainer width="100%" height={40}>
        <AreaChart data={chartData} margin={{ top: 2, right: 0, bottom: 0, left: 0 }}>
          <defs>
            <linearGradient id={`spark-${color.replace('#', '')}`} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor={color} stopOpacity={0.25} />
              <stop offset="100%" stopColor={color} stopOpacity={0.02} />
            </linearGradient>
          </defs>
          <Area
            type="monotone"
            dataKey="y"
            stroke={color}
            strokeWidth={1.5}
            fill={`url(#spark-${color.replace('#', '')})`}
            dot={false}
            isAnimationActive={false}
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}

/* ─── Skeleton Component ───────────────────────────────────────────────── */
function PanelSkeleton() {
  return (
    <div className="skeleton-rows">
      {[1, 2, 3].map((i) => (
        <div className="skeleton-row" key={i}>
          <div className="skeleton-bar skeleton-bar--icon" />
          <div className="skeleton-bar skeleton-bar--text" />
          <div className="skeleton-bar skeleton-bar--badge" />
        </div>
      ))}
    </div>
  );
}

/* ─── Main Page ────────────────────────────────────────────────────────── */
export default function Home() {
  const [toast, setToast] = useState('');
  const [detail, setDetail] = useState<DetailKey | null>(null);
  const [fleet, setFleet] = useState<FleetSummary | null>(null);
  const [collectorState, setCollectorState] = useState<'checking' | 'live' | 'demo'>('checking');
  function runScan() {
    setToast('当前为演示数据，尚未连接任务下发 API；未对任何终端执行操作。');
  }
  useEffect(() => {
    const controller = new AbortController();
    fetch('/api/summary', { cache: 'no-store', signal: controller.signal })
      .then(async (response) => {
        if (!response.ok) throw new Error('collector unavailable');
        const value = (await response.json()) as { connected?: boolean; summary?: FleetSummary };
        if (!value.connected || !value.summary) throw new Error('collector disconnected');
        setFleet(value.summary); setCollectorState('live');
      })
      .catch((error: unknown) => {
        if ((error as { name?: string })?.name !== 'AbortError') setCollectorState('demo');
      });
    return () => controller.abort();
  }, []);
  const totalDevices = fleet?.total_devices ?? 312;
  const activeDevices = fleet?.active_devices ?? 284;
  const staleDevices = fleet?.stale_devices ?? 28;
  const currentDevices = fleet?.version_posture.current ?? 302;
  const coverage = totalDevices ? (currentDevices / totalDevices) * 100 : 0;
  const highRiskDevices = fleet ? fleet.latest_severity.critical + fleet.latest_severity.high : 12;
  const driftDevices = fleet ? totalDevices - currentDevices : 10;

  const animDevices = useAnimatedNumber(totalDevices);
  const animCoverage = useAnimatedNumber(Math.round(coverage * 10));
  const animRisk = useAnimatedNumber(highRiskDevices);
  const animDrift = useAnimatedNumber(driftDevices);

  return (
    <main className="min-h-screen bg-[#07110f] text-[#eaf7f2]">
      <header className="topbar">
        <div className="brand">
          <span className="brandmark">
            <ShieldCheck size={19} />
          </span>
          <span>
            Aegis<span className="brand-muted"> / Agent Security</span>
          </span>
        </div>
        <div className="header-actions">
          <span className="system-ok">
            <span className={collectorState === 'live' ? 'live-dot' : 'demo-dot'} />
            {collectorState === 'live' ? '只读摘要已连接' : collectorState === 'checking' ? '正在检查接收器' : '演示数据 · 接收器未连接'}
          </span>
          <button className="icon-btn" aria-label="搜索">
            <Search size={18} />
          </button>
          <button className="avatar" aria-label="账户菜单">
            SL
          </button>
        </div>
      </header>
      <div className="shell">
        <aside className="sidebar">
          <nav aria-label="主导航">
            <p className="nav-label">控制台</p>
            <button className="nav-item active" onClick={() => setDetail(null)}>
              <Activity size={18} />
              总览
            </button>
            <Nav
              icon={Bot}
              label="接入中心"
              target="onboarding"
              open={setDetail}
            />
            <Nav
              icon={Laptop}
              label="设备与 Agent"
              target="devices"
              open={setDetail}
              count="312"
            />
            <Nav
              icon={AlertTriangle}
              label="风险中心"
              target="risks"
              open={setDetail}
              alert="12"
            />
            <p className="nav-label section-gap">安全能力</p>
            <Nav
              icon={Code2}
              label="编码规范基线"
              target="baseline"
              open={setDetail}
            />
            <Nav
              icon={Sparkles}
              label="Skill 扫描器"
              target="skills"
              open={setDetail}
            />
            <Nav
              icon={Network}
              label="MCP 扫描器"
              target="mcp"
              open={setDetail}
            />
            <Nav
              icon={Wrench}
              label="代码质量"
              target="quality"
              open={setDetail}
            />
            <p className="nav-label section-gap">管理</p>
            <Nav
              icon={SlidersHorizontal}
              label="策略配置"
              target="policies"
              open={setDetail}
            />
            <Nav
              icon={Users}
              label="团队与权限"
              target="team"
              open={setDetail}
            />
            <Nav
              icon={Settings}
              label="系统设置"
              target="settings"
              open={setDetail}
            />
          </nav>
          <div className="side-foot">
            <LockKeyhole size={16} />
            <div>
              <strong>企业安全策略</strong>
              <small>尚未连接接收器</small>
            </div>
            <Check size={16} />
          </div>
        </aside>
        <section className="workspace" id="overview">
          <div className="demo-notice" role="note"><AlertTriangle size={16} /><span><strong>{fleet ? '混合只读模式' : '演示模式'}</strong>{fleet ? ' 顶部四项指标来自已验证的接收器摘要；终端明细、覆盖分布和风险事件仍为界面样例。' : ' 页面指标、设备和风险事件均为界面样例，不代表真实终端状态。请部署报告接收器并完成私有 API 接入后再用于运营判断。'}</span></div>
          <div className="page-head">
            <div>
              <p className="eyebrow">安全态势 / 演示数据</p>
              <h1>AI Agent 安全总览</h1>
              <p>统一发现、校验并约束员工终端上的 AI Agent 行为。</p>
            </div>
            <div className="head-actions">
              <Button variant="outline">
                <ChevronDown />
                过去 24 小时
              </Button>
              <Button onClick={runScan}>
                <Play fill="currentColor" />
                扫描下发未接入
              </Button>
            </div>
          </div>
          {toast && (
            <div className="toast" role="status">
              <CircleDot size={16} />
              {toast}
            </div>
          )}

          {/* ─── Metric Cards with Sparklines ──────────────────────────── */}
          <div className="metrics">
            <article className="metric">
              <div className="metric-top">
                <span>已纳管设备{fleet ? '' : '（样例）'}</span>
                <Laptop size={18} />
              </div>
              <strong>{animDevices}</strong>
              <p>
                <em>{activeDevices}</em> 活跃 · {staleDevices} 过期
              </p>
              <Sparkline data={sparkDevices} />
            </article>
            <article className="metric">
              <div className="metric-top">
                <span>当前版本覆盖率{fleet ? '' : '（样例）'}</span>
                <Bot size={18} />
              </div>
              <strong>
                {(animCoverage / 10).toFixed(1)}<small>%</small>
              </strong>
              <Progress value={coverage} />
              <p>
                当前版本设备 <em>{currentDevices}</em> 台
              </p>
              <Sparkline data={sparkCoverage} />
            </article>
            <article className="metric danger">
              <div className="metric-top">
                <span>高风险设备{fleet ? '' : '（样例）'}</span>
                <AlertTriangle size={18} />
              </div>
              <strong>{animRisk}</strong>
              <p>
                <i>{fleet?.latest_severity.critical ?? 3} 严重</i> · {fleet?.latest_severity.high ?? 9} 高危
              </p>
              <Sparkline data={sparkRisk} color="#ff685f" />
            </article>
            <article className="metric">
              <div className="metric-top">
                <span>版本漂移设备{fleet ? '' : '（样例）'}</span>
                <ShieldCheck size={18} />
              </div>
              <strong>{animDrift}</strong>
              <p>
                Agent 或策略版本不一致
              </p>
              <Sparkline data={sparkDrift} />
            </article>
          </div>

          {/* ─── Content Grid ─────────────────────────────────────────── */}
          <div className="content-grid">
            <section className="panel capabilities">
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

            {/* ─── Coverage Panel with Trend Indicators ─────────────────── */}
            <section className="panel coverage">
              <div className="panel-head">
                <div>
                  <h2>终端覆盖</h2>
                  <p>按 Agent 工具</p>
                </div>
                <button>查看全部</button>
              </div>
              {coverageTrends.map(({ name, total, online, delta }) => (
                <div className="coverage-row" key={name}>
                  <div className="tool-logo">{name.slice(0, 1)}</div>
                  <div className="coverage-data">
                    <div>
                      <strong>{name}</strong>
                      <span>
                        {online}/{total} 在线
                      </span>
                      <span className={`trend-badge ${delta >= 0 ? 'up' : 'down'}`}>
                        {delta >= 0 ? <ArrowUpRight size={12} /> : <ArrowDownRight size={12} />}
                        {Math.abs(delta)}%
                      </span>
                    </div>
                    <Progress value={(online / total) * 100} />
                  </div>
                </div>
              ))}
            </section>

            <section className="panel risks" id="risks">
              <div className="panel-head">
                <div>
                  <h2>风险事件样例</h2>
                  <p>按风险等级与时间排序</p>
                </div>
                <button>进入风险中心 →</button>
              </div>
              <div className="risk-table">
                {risks.map((r) => (
                  <div className="risk-row" key={r.title}>
                    <span className={`severity ${r.color}`}>{r.severity}</span>
                    <div className="risk-main">
                      <strong>{r.title}</strong>
                      <span>{r.source}</span>
                    </div>
                    <span className="device">{r.device}</span>
                    <span className="time">{r.time}</span>
                    <button
                      className="handle"
                      onClick={() => setToast(`已打开「${r.title}」处置详情。`)}
                    >
                      处置
                    </button>
                  </div>
                ))}
              </div>
            </section>

            {/* ─── Score Panel with RadialBarChart ────────────────────── */}
            <section className="panel score">
              <div className="panel-head">
                <div>
                  <h2>安全评分</h2>
                  <p>企业基线综合得分</p>
                </div>
              </div>
              <div className="score-body">
                <div className="score-ring-chart">
                  <ResponsiveContainer width={180} height={180}>
                    <RadialBarChart
                      cx="50%"
                      cy="50%"
                      innerRadius="30%"
                      outerRadius="95%"
                      barSize={10}
                      data={radialScoreData}
                      startAngle={90}
                      endAngle={-270}
                    >
                      <PolarAngleAxis
                        type="number"
                        domain={[0, 100]}
                        angleAxisId={0}
                        tick={false}
                        axisLine={false}
                      />
                      <RadialBar
                        background={{ fill: '#1a2e28' }}
                        dataKey="value"
                        cornerRadius={6}
                        angleAxisId={0}
                      />
                    </RadialBarChart>
                  </ResponsiveContainer>
                  <div className="score-center-text">
                    <strong>92</strong>
                    <span>/ 100</span>
                  </div>
                </div>
                <div className="score-list">
                  {scoreData.map((item) => (
                    <p key={item.name}>
                      <span className="score-dot" style={{ background: item.fill }} />
                      <span>{item.name}</span>
                      <b>{item.value}</b>
                    </p>
                  ))}
                </div>
              </div>
            </section>
          </div>

          {/* ─── Recent Activity Timeline ──────────────────────────────── */}
          <section className="panel activity-timeline">
            <div className="panel-head">
              <div>
                <h2>近期动态</h2>
                <p>最近 24 小时安全事件与操作</p>
              </div>
              <Badge variant="outline">
                <TrendingUp size={13} />
                实时更新
              </Badge>
            </div>
            <div className="timeline">
              {activityTimeline.map((event, idx) => {
                const Icon = event.icon;
                return (
                  <div className="timeline-item" key={idx}>
                    <div className="timeline-marker">
                      <span className="timeline-dot">
                        <Icon size={12} />
                      </span>
                      {idx < activityTimeline.length - 1 && <span className="timeline-line" />}
                    </div>
                    <div className="timeline-content">
                      <div className="timeline-header">
                        <strong>{event.label}</strong>
                        <span className="timeline-time">{event.time}</span>
                      </div>
                      <p>{event.desc}</p>
                    </div>
                  </div>
                );
              })}
            </div>
          </section>
        </section>
      </div>
      {detail && (
        <DetailPanel
          view={detail}
          close={() => setDetail(null)}
          notify={setToast}
          fleet={fleet}
        />
      )}
    </main>
  );
}

function Nav({
  icon: Icon,
  label,
  target,
  open,
  count,
  alert,
}: {
  icon: typeof Activity;
  label: string;
  target: DetailKey;
  open: (v: DetailKey) => void;
  count?: string;
  alert?: string;
}) {
  return (
    <button className="nav-item" onClick={() => open(target)}>
      <Icon size={18} />
      {label}
      {count && <span>{count}</span>}
      {alert && <b>{alert}</b>}
    </button>
  );
}

function DetailPanel({
  view,
  close,
  notify,
  fleet,
}: {
  view: DetailKey;
  close: () => void;
  notify: (s: string) => void;
  fleet: FleetSummary | null;
}) {
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setLoading(true);
    const timer = setTimeout(() => setLoading(false), 600);
    return () => clearTimeout(timer);
  }, [view]);

  const scanRows =
    view === 'skills'
      ? [
          ['prompt-helper.skill', '隔离', '隐藏指令覆盖', '高危'],
          ['jira-assistant.skill', '放行', '权限声明完整', '通过'],
          ['release-notes.skill', '观察', '依赖包待升级', '中危'],
        ]
      : view === 'mcp'
        ? [
            ['filesystem-mcp', '限制', '越权目录访问', '高危'],
            ['github-mcp', '放行', 'OAuth 范围合规', '通过'],
            ['postgres-mcp', '观察', '出站地址未锁定', '中危'],
          ]
        : [
            ['payment-service', '阻断', '弱随机数生成令牌', '高危'],
            ['customer-portal', '放行', '质量门禁通过', '通过'],
            ['data-pipeline', '观察', '依赖存在 CVE', '中危'],
          ];
  const scanner = view === 'skills' || view === 'mcp' || view === 'quality';
  return (
    <div
      className="detail-overlay"
      role="dialog"
      aria-modal="true"
      aria-label={viewNames[view]}
    >
      <button className="overlay-bg" aria-label="关闭" onClick={close} />
      <section className="detail-panel">
        <div className="detail-title">
          <div>
            <p className="eyebrow">治理工作台</p>
            <h1>{viewNames[view]}</h1>
          </div>
          <button className="close-btn" onClick={close}>
            ×
          </button>
        </div>
        <div className="demo-notice" role="note"><AlertTriangle size={16} /><span><strong>演示模式</strong> 本面板中的终端、风险、合规率和处置结果均为样例；企业 API 接入前不会执行外部操作。</span></div>

        {loading ? (
          <PanelSkeleton />
        ) : (
          <>
            {view === 'onboarding' && (
              <>
                <div className="baseline-banner">
                  <div>
                    <h2>Aegis Endpoint Agent 0.30.0</h2>
                    <p>Intune 部署 · 深信服 EDR 联动 · 联软桌管兜底</p>
                  </div>
                  <strong>可验证<span>本地执行</span></strong>
                </div>
                <div className="panel inset onboarding">
                  <h2>企业部署编排</h2>
                  <div className="control-planes">
                    <article><b>Microsoft Intune</b><span>主部署通道</span><p>Windows Remediations 与 macOS Shell Script，负责安装、版本检测、周期修复和自定义合规。</p></article>
                    <article><b>深信服 EDR</b><span>响应处置</span><p>接收高危事件，按现网版本能力执行隔离、查杀或 IOC 取证。</p></article>
                    <article><b>联软桌管</b><span>资产与兜底</span><p>软件分发、资产核验及未安装终端的准入修复。</p></article>
                  </div>
                  <ol><li><b>自动发现</b><span>Intune 周期任务检测 Cursor、Claude Code、Codex 与 Windsurf 配置。</span></li><li><b>加载基线</b><span>为受管项目增量安装 Agent 规则，并持续扫描 Skill、MCP 与代码。</span></li><li><b>联动处置</b><span>以 device_id 关联深信服 EDR 与联软资产，按风险等级分级响应。</span></li></ol>
                  <div className="download-actions">
                    <a className="download-primary" href="/downloads/aegis-enterprise-bundle.zip" download>下载完整部署包</a>
                    <a className="download-primary" href="/downloads/DEPLOYMENT-GUIDE.md" download>下载部署指南</a>
                    <a href="/downloads/intune-windows-detect.ps1" download>Windows 检测脚本</a>
                    <a href="/downloads/intune-windows-remediate.ps1" download>Windows 修复脚本</a>
                    <a href="/downloads/intune-macos-install.sh" download>macOS Intune 脚本</a>
                    <a href="/downloads/intune-macos-compliance.sh" download>macOS 合规脚本</a>
                    <a href="/downloads/aegis-policy.json" download>策略基线</a>
                    <a href="/downloads/aegis_device_credentials.py" download>逐设备凭据工具</a>
                  </div>
                  <p className="safety-note"><LockKeyhole size={15}/>部署脚本不包含深信服或联软管理凭据；正式联动需按现网版本申请服务账号与接口授权。</p>
                </div>
              </>
            )}
            {scanner && (
              <>
                <div className="detail-kpis">
                  <article>
                    <strong>
                      {view === 'skills' ? 68 : view === 'mcp' ? 41 : 126}
                    </strong>
                    <span>已扫描对象</span>
                  </article>
                  <article>
                    <strong>
                      {view === 'skills' ? 3 : view === 'mcp' ? 2 : 7}
                    </strong>
                    <span>待处理发现</span>
                  </article>
                  <article>
                    <strong>100%</strong>
                    <span>在线终端覆盖</span>
                  </article>
                </div>
                {/* ─── Scan Trend BarChart ─────────────────────────────── */}
                <div className="panel inset scan-trend">
                  <div className="panel-head">
                    <div>
                      <h2>过去 7 天扫描趋势</h2>
                      <p>每日发现数量统计</p>
                    </div>
                  </div>
                  <ResponsiveContainer width="100%" height={140}>
                    <BarChart data={scanTrendData} margin={{ top: 8, right: 8, bottom: 0, left: -20 }}>
                      <XAxis
                        dataKey="day"
                        axisLine={false}
                        tickLine={false}
                        tick={{ fill: '#86a39a', fontSize: 11 }}
                      />
                      <YAxis
                        axisLine={false}
                        tickLine={false}
                        tick={{ fill: '#86a39a', fontSize: 11 }}
                      />
                      <Tooltip
                        contentStyle={{
                          background: '#0d1a17',
                          border: '1px solid #1a2e28',
                          borderRadius: 8,
                          color: '#eaf7f2',
                          fontSize: 12,
                        }}
                        labelStyle={{ color: '#86a39a' }}
                      />
                      <Bar
                        dataKey="count"
                        name="发现数"
                        fill="#49e8a5"
                        radius={[4, 4, 0, 0]}
                        barSize={24}
                      />
                    </BarChart>
                  </ResponsiveContainer>
                </div>
                <div className="panel inset">
                  <div className="panel-head">
                    <div>
                      <h2>最近扫描结果</h2>
                      <p>终端安全 Agent 上报样例</p>
                    </div>
                    <Button
                      onClick={() => notify('演示模式：未连接规则同步 API，未修改任何终端。')}
                    >
                      同步规则库
                    </Button>
                  </div>
                  <DataTable rows={scanRows} />
                </div>
              </>
            )}
            {view === 'devices' && (
              <div className="panel inset">
                <div className="panel-head">
                  <div>
                    <h2>受管终端</h2>
                    <p>{fleet ? `${fleet.total_devices} 台设备 · ${fleet.active_devices} 台在线` : '312 台设备 · 284 台在线（样例）'}</p>
                    {fleet?.credential_posture && <p>凭据代次：当前 {fleet.credential_posture.current} · 上一代 {fleet.credential_posture.previous} · Legacy {fleet.credential_posture.legacy}</p>}
                  </div>
                  <Button onClick={() => notify('演示模式：请直接下载已验证发行包，未创建外部任务。')}>
                    生成部署包
                  </Button>
                </div>
                <DataTable
                  rows={[
                    ['ENG-MBP-1032', '陈昊 · Cursor', 'v3.8', '受保护'],
                    ['MKT-LT-2841', '林妍 · Cursor', 'v3.7', '需处理'],
                    ['ENG-LT-0948', '周航 · Codex CLI', 'v3.8', '受保护'],
                    ['OPS-MBP-0314', '罗宁 · Claude Code', 'v3.8', '离线'],
                  ]}
                />
              </div>
            )}
            {view === 'risks' && (
              <div className="panel inset">
                <div className="panel-head">
                  <div>
                    <h2>待研判事件</h2>
                    <p>3 个高危事件需要人工确认</p>
                  </div>
                  <Button onClick={() => notify('演示模式：未连接 EDR 审批接口，未隔离任何对象。')}>
                    隔离全部高危
                  </Button>
                </div>
                {risks.map((r) => (
                  <div className="risk-row wide" key={r.title}>
                    <span className={`severity ${r.color}`}>{r.severity}</span>
                    <div className="risk-main">
                      <strong>{r.title}</strong>
                      <span>{r.source}</span>
                    </div>
                    <span className="device">{r.device}</span>
                    <span className="time">{r.time}</span>
                    <button
                      className="handle"
                      onClick={() => notify(`演示模式：未连接工单接口，未认领「${r.title}」。`)}
                    >
                      认领处置
                    </button>
                  </div>
                ))}
              </div>
            )}
            {view === 'baseline' && (
              <>
                <div className="baseline-banner">
                  <div>
                    <h2>企业 AI Coding 安全基线 v4.8</h2>
                    <p>规则应用范围与合规率为界面样例</p>
                  </div>
                  <strong>
                    98.2%<span>合规率</span>
                  </strong>
                </div>
                <div className="policy-grid">
                  {[
                    ['SEC-AUTH-01', '禁止硬编码密钥与令牌', '阻断'],
                    ['SEC-INJ-03', '外部输入必须参数化处理', '阻断'],
                    ['SEC-LOG-02', '敏感字段不得写入日志', '阻断'],
                    ['SEC-DEP-04', '高危依赖不得进入主分支', '需审批'],
                  ].map((r) => (
                    <article className="panel policy-card" key={r[0]}>
                      <span>{r[0]}</span>
                      <h3>{r[1]}</h3>
                      <div>
                        <i className={r[2] === '阻断' ? 'fail' : 'warn'}>{r[2]}</i>
                        <button onClick={() => notify(`${r[0]} 规则详情已打开。`)}>
                          配置
                        </button>
                      </div>
                    </article>
                  ))}
                </div>
              </>
            )}
            {view === 'policies' && (
              <div className="panel inset">
                <div className="panel-head">
                  <div>
                    <h2>默认终端策略</h2>
                    <p>变更将自动同步至在线安全 Agent</p>
                  </div>
                  <Button onClick={() => notify('演示模式：未连接策略发布 API，未修改任何终端。')}>
                    发布策略
                  </Button>
                </div>
                {[
                  ['自动发现 AI Agent', '检测主流 AI Coding 工具', true],
                  ['强制加载安全基线', '启动时注入企业编码规范', true],
                  ['高危 MCP 自动隔离', '阻断越权文件访问与外联', true],
                  ['未知 Skill 默认禁用', '等待签名与安全审批', false],
                ].map(([a, b, on]) => (
                  <div className="setting-row" key={String(a)}>
                    <div>
                      <strong>{a}</strong>
                      <span>{b}</span>
                    </div>
                    <button
                      className={`switch ${on ? 'on' : ''}`}
                      onClick={(e) => {
                        e.currentTarget.classList.toggle('on');
                        notify(`演示模式：${a} 未被修改，设置 API 尚未连接。`);
                      }}
                      aria-label={`切换${a}`}
                    >
                      <span />
                    </button>
                  </div>
                ))}
              </div>
            )}
            {(view === 'team' || view === 'settings') && (
              <div className="empty-detail">
                <ShieldCheck size={44} />
                <h2>{viewNames[view]}已接入</h2>
                <p>下一阶段可连接企业身份、通知和审计系统。</p>
                <Button onClick={() => notify('演示模式：配置向导尚未连接企业后端。')}>
                  打开配置向导
                </Button>
              </div>
            )}
          </>
        )}
      </section>
    </div>
  );
}

function DataTable({ rows }: { rows: string[][] }) {
  return (
    <div className="data-table">
      <div className="data-head">
        <span>对象</span>
        <span>策略动作</span>
        <span>检测结果</span>
        <span>状态</span>
      </div>
      {rows.map((r) => (
        <div className="data-row" key={r[0]}>
          <strong>{r[0]}</strong>
          <span>{r[1]}</span>
          <span>{r[2]}</span>
          <i
            className={
              r[3] === '通过' || r[3] === '受保护'
                ? 'pass'
                : r[3] === '高危' || r[3] === '需处理'
                  ? 'fail'
                  : 'warn'
            }
          >
            {r[3]}
          </i>
        </div>
      ))}
    </div>
  );
}
