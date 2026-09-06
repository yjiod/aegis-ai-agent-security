'use client';
import { useEffect, useRef, useState } from 'react';
import {
  AlertTriangle,
  ArrowDownRight,
  ArrowUpRight,
  Bot,
  Check,
  ChevronDown,
  Code2,
  Cpu,
  Laptop,
  Network,
  Play,
  RefreshCw,
  ShieldCheck,
  Sparkles,
  TrendingUp,
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
} from 'recharts';
import { useCollector } from '@/components/collector-context';
import { Toast } from '@/components/toast';

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

/* ─── Overview Page ────────────────────────────────────────────────────── */
export default function Home() {
  const [toast, setToast] = useState('');
  const { fleet } = useCollector();

  function runScan() {
    setToast('当前为演示数据，尚未连接任务下发 API；未对任何终端执行操作。');
  }

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
    <>
      <div className="demo-notice" role="note"><AlertTriangle size={16} /><span><strong>{fleet ? '混合只读模式' : '演示模式'}</strong>{fleet ? ' 顶部四项指标来自已验证的接收器摘要；终端明细、覆盖分布和风险事件仍为界面样例。' : ' 页面指标、设备和风险事件均为界面样例，不代表真实终端状态。请部署报告接收器并完成私有 API 接入后再用于运营判断。'}</span></div>
      <div className="page-head animate-entrance animate-entrance-1">
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
      <Toast message={toast} />

      {/* ─── Metric Cards with Sparklines ──────────────────────────── */}
      <div className="metrics">
        <article className="metric animate-entrance animate-entrance-1">
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
        <article className="metric animate-entrance animate-entrance-2">
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
        <article className="metric danger animate-entrance animate-entrance-3">
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
        <article className="metric animate-entrance animate-entrance-4">
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

        {/* ─── Coverage Panel with Trend Indicators ─────────────────── */}
        <section className="panel coverage animate-entrance animate-entrance-6">
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

        <section className="panel risks animate-entrance animate-entrance-7" id="risks">
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
        <section className="panel score animate-entrance animate-entrance-7">
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
      <section className="panel activity-timeline animate-entrance animate-entrance-7">
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
              <div
                className="timeline-item animate-entrance"
                key={idx}
                style={{ animationDelay: `${idx * 80 + 500}ms` }}
              >
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
    </>
  );
}
