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
  ScanLine,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { Toast } from '@/components/toast';
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
  critical: { label: '严重', color: 'red' },
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
const modules = [
  { icon: ScanLine, title: '终端 Agent 发现', desc: '清点已安装的 AI 编码工具', status: '已启用', tone: 'green' },
  { icon: Sparkles, title: 'Skill 扫描器', desc: '权限、指令与依赖', status: '已打包', tone: 'blue' },
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
  const [toast, setToast] = useState('');
  const { fleet } = useCollector();

  const [devices, setDevices] = useState<DeviceLite[] | null>(null);
  const [tickets, setTickets] = useState<TicketLite[] | null>(null);
  const [audit, setAudit] = useState<AuditLite[] | null>(null);

  useEffect(() => {
    let alive = true;
    getJson<{ devices?: DeviceLite[] }>('/api/devices?limit=2000').then((d) => {
      if (alive) setDevices(Array.isArray(d?.devices) ? (d.devices as DeviceLite[]) : []);
    });
    getJson<{ tickets?: TicketLite[] }>('/api/tickets?limit=6').then((d) => {
      if (alive) setTickets(Array.isArray(d?.tickets) ? (d.tickets as TicketLite[]) : []);
    });
    getJson<{ entries?: AuditLite[] }>('/api/audit?limit=6').then((d) => {
      if (alive) setAudit(Array.isArray(d?.entries) ? (d.entries as AuditLite[]) : []);
    });
    return () => {
      alive = false;
    };
  }, []);

  function runScan() {
    setToast('当前为实时数据，尚未连接任务下发 API；未对任何终端执行操作。');
  }

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

      {/* ─── Metric Cards (real fleet summary; 0 when disconnected) ─── */}
      <div className="metrics">
        <article className="metric animate-entrance animate-entrance-1">
          <div className="metric-top">
            <span>已纳管设备</span>
            <Laptop size={18} />
          </div>
          <strong>{animDevices}</strong>
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
            {(animCoverage / 10).toFixed(1)}
            <small>%</small>
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
          <strong>{animRisk}</strong>
          <p>
            <i>{fleet?.latest_severity?.critical ?? 0} 严重</i> · {fleet?.latest_severity?.high ?? 0} 高危
          </p>
        </article>
        <article className="metric animate-entrance animate-entrance-4">
          <div className="metric-top">
            <span>版本漂移设备</span>
            <ShieldCheck size={18} />
          </div>
          <strong>{animDrift}</strong>
          <p>Agent 或策略版本不一致</p>
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

        {/* ─── Coverage Panel (real per-agent from /api/devices) ───── */}
        <section className="panel coverage animate-entrance animate-entrance-6">
          <div className="panel-head">
            <div>
              <h2>终端覆盖</h2>
              <p>按 Agent 工具</p>
            </div>
            <a href="/devices">查看全部</a>
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
            <a href="/risks">进入风险中心 →</a>
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
                    <a className="handle" href="/risks">
                      处置
                    </a>
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
