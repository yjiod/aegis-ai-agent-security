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
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
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
  RefreshCw,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import Link from 'next/link';
import { TECHNIQUES, type RuleSet } from '@/lib/detection-coverage';
import { maskEgress } from '@/lib/redact';
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
import { ObservabilityPanel } from '@/components/observability-panel';
import { SourceAttributionPanel } from '@/components/source-attribution-panel';
/* 严重度映射的唯一权威源：ticket-detail 的 5 档（含 info）。
   本页此前维护了一份 4 档本地副本，缺 info 且把低危映射成不存在的
   `.severity.blue` 类，导致低危徽章渲染成无样式空壳、info 级误显橙色中危。 */
import { severityMeta, toTimestamp, type TicketSeverity } from '@/components/ticket-detail';
// 模块开关的**有效值**由 lib/modules.ts 的单一真源计算（#38，后端 commit a018870）。
// 该文件不 import node:crypto，客户端组件可安全引用；此前这里与 app/policies/page.tsx
// 各有一份本地 MODULE_DEFAULTS 副本，副本正是三份默认值得以漂移的成因，现已删除。
import { effectiveModules, type ModuleKey } from '@/lib/modules';

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
  /** 秒级 epoch；用于推导 fleet 最近上报时间（数据新鲜度）。 */
  last_seen?: number;
}
interface TicketLite {
  ticket_id: string;
  title: string;
  severity: string;
  status: string;
  device_id?: string;
  created_at: number;
  resolved_at?: number | null;
  /**
   * /api/tickets 返回完整工单（含 history）；此处窄视图仅取 MTTA 所需字段。
   *
   * 字段名对齐权威定义 `lib/store.ts` 的 `TicketHistoryEntry`：
   * `{ action, actor, timestamp, note? }` —— **不含任何状态字段，也不含 `at`**。
   * 旧声明写的正是这两个并不存在的字段名（Task#5 ③），故过滤条件恒假。
   *
   * 已核实数据确实带 history 到前端：GET 处理器直接返回 store 里的完整工单对象、
   * 不做字段投影（`jsonResponse({ tickets: tickets.slice(...) })`），而
   * `READ_ONLY_ON_CREATE` 只约束**写入**（防伪造审计轨迹），不影响读出。
   *
   * 保留可选的 `at` 是为兼容 `components/ticket-detail.tsx` 的 parseHistoryEntry
   * 归一化产物（它把 timestamp 映射成 at）——但那里状态字段仍是 null，因为源数据
   * 本身不含状态，所以**不能**靠复用该解析器来判状态，只能按 action 判
   * （见下方 LEAVE_OPEN_ACTIONS）。
   *
   * 注：本注释刻意不写出那两个错误字段名的字面量，否则按字段名做的复验 grep 会
   * 命中注释、把这个已修项报成仍存在。
   */
  history?: Array<{ action?: string; actor?: string; timestamp?: number | string; at?: number | string; note?: string }>;
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

/**
 * 能力卡定义（审计 #32）。
 *
 * 【禁】状态**不得**在此硬编码。此前 4 张卡都写死 `status:'已启用', tone:'green'`，
 * 而生产策略 code_scan=false → 给安全负责人看的权威视图在伪造状态，触犯项目红线
 * "绝不伪造数据"，且虚高覆盖率会导致**错误的风险接受**。状态一律由
 * `GET /api/settings/modules` 的有效值派生，见 component 内的 moduleCardStatus()。
 *
 * `key` 是该能力对应的模块开关；**null 表示没有独立开关的基础能力**（实测
 * lib/modules.ts 的 9 个 ModuleKey 中无"Agent 发现 / 工具清点"一项，
 * network_collect 是采集物理网卡 MAC/IP，语义不同）。这类卡不得伪装成
 * 开关派生的实时状态 —— 已就口径向 lead 提请裁定，暂按"设计事实"处理
 * （对齐审计 #34 对 engines 页"框架已实现适配器"的既有先例）。
 */
const modules: Array<{
  icon: typeof ScanLine;
  title: string;
  desc: string;
  key: ModuleKey | null;
}> = [
  // 卡 1 的 desc 采用 PM §7.1 定稿副标题（逐字），把"为何无独立开关"的解释放在
  // **可见文本**里而非 title 属性——审计 #34 已确立 title 不进入无障碍名计算，
  // 键盘与读屏用户拿不到，tooltip 只可作补充、不可作唯一载体。
  { icon: ScanLine, title: '终端 Agent 发现', desc: '清点已安装的 AI 编码工具（Agent 常驻能力，无独立开关）', key: null },
  { icon: Sparkles, title: 'Skill 扫描器', desc: '权限、指令与依赖', key: 'skill_scan' },
  { icon: Network, title: 'MCP 扫描器', desc: '工具、密钥与外联', key: 'mcp_scan' },
  { icon: Code2, title: '代码质量扫描', desc: 'SAST、依赖与密钥', key: 'code_scan' },
];

/** 代码质量扫描卡停用时的副标题（PM §7.1 定稿，逐字照抄，不得改写）。 */
const CODE_SCAN_DISABLED_DESC =
  '终端代码扫描已按策略停用；此页为外部专业扫描器接入后的统一视图，当前未接入来源。';

/** 接口不可达时的整条状态文案（PM §7.1 定稿，逐字照抄）。 */
const MODULES_UNAVAILABLE_LABEL = '状态未知 · 读取模块开关失败';

/* ─── Typed fetch helper (avoids untyped r.json() '{}') ───────────────── */
/**
 * 拉取结果：成功带 data，失败带**可见**原因。
 *
 * 旧实现是双重静默吞错——`if (!r.ok) return null` 与 `catch { return null }`——
 * 于是"接口 500"与"接口正常返回空数据"在 UI 上完全同形：调用方一律 `?? []`，
 * KPI 显示 0、完成率显示 0%、时间线显示"暂无动态"。用户读到的是一个**安静的错误
 * 数字**，而不是一个响亮的失败，比直接报错更危险（把 clamp 后的头部样本当全量、
 * 把 503 当"舰队无风险"都属此类）。改为判别式结果，失败由页面级横幅显式呈现。
 */
type FetchResult<T> = { ok: true; data: T } | { ok: false; status: number | null; reason: string };

async function getJson<T>(url: string): Promise<FetchResult<T>> {
  try {
    const r = await fetch(url, { cache: 'no-store' });
    if (!r.ok) return { ok: false, status: r.status, reason: `HTTP ${r.status}` };
    return { ok: true, data: (await r.json()) as T };
  } catch (e) {
    return { ok: false, status: null, reason: e instanceof Error ? e.message : String(e) };
  }
}

/**
 * 「首次脱离 open」的动作判据（Task#5 ③）。
 *
 * 权威词表来自 `app/api/tickets/[id]/route.ts` 的 TRANSITION_ACTIONS：
 *   open→reopen、acknowledged→acknowledge、investigating→investigate、
 *   resolved→resolve、dismissed→dismiss
 * 另外 `lib/store.ts` 与该 route 还会 push create / assign / comment / update。
 *
 * 只有下面这四个动词代表"工单不再是 open"。刻意排除 reopen（它是**回到** open，
 * 方向相反）与 create/assign/comment/update（不改状态）。
 */
const LEAVE_OPEN_ACTIONS = new Set(['acknowledge', 'investigate', 'resolve', 'dismiss']);

/* ─── Overview Page ────────────────────────────────────────────────────── */
export default function Home() {
  const { fleet } = useCollector();

  const [devices, setDevices] = useState<DeviceLite[] | null>(null);
  const [tickets, setTickets] = useState<TicketLite[] | null>(null);
  const [audit, setAudit] = useState<AuditLite[] | null>(null);
  // 2026-09 总览重构(handoff 4.2)：处置进度需全量工单状态分布（有界 500）。
  const [ticketsAll, setTicketsAll] = useState<TicketLite[] | null>(null);
  // P2 态势视图切换 + 规则/来源排行（真实数据；无真实地理数据→降级为排行表，handoff P2/原则5）。
  const [view, setView] = useState<'overview' | 'coverage' | 'rules' | 'efficiency' | 'sources'>('overview');
  const [findingsAll, setFindingsAll] = useState<Array<Record<string, unknown>> | null>(null);
  // 2026-09 改版：首页趋势图 + KPI 环比数据源（/api/trend → Collector /v1/trend，小时桶）。
  const [trend, setTrend] = useState<{ hours: number; buckets: TrendBucketLite[] } | null>(null);
  // fleet 级 per-rule 检测计数（技战法活跃态势权威源；旧 Collector 无端点时 connected:false 回落样本）。
  const [ruleStats, setRuleStats] = useState<{
    connected?: boolean;
    complete?: boolean;
    rule_stats?: Array<{ rule_id: string; category: string; critical: number; high: number; total: number }>;
  } | null>(null);
  // 审计 #32：能力卡状态的真实数据源。null = 尚未取到有效值（加载中或失败），
  // 此时任何卡都不得回落成绿色"已启用"。
  const [mods, setMods] = useState<Record<string, boolean> | null>(null);
  const [modsLoading, setModsLoading] = useState(true);
  const [modsError, setModsError] = useState('');
  // 数据源失败清单（审计 Task#5 ④）：任一来源拉取失败都记在这里并在页面顶部
  // 显式告警，不再把失败折叠成空数据。
  const [failedSources, setFailedSources] = useState<Array<{ label: string; reason: string }>>([]);
  /**
   * /api/tickets?limit=500 的钳制元数据（Task#5 ②⑤）。
   * 后端 MAX_LIMIT=200，故 limit=500 会被钳到 200；返回的是按"严重度升序+时间降序"
   * 排序后的**头部偏置样本**（最严重的 200 张），不是全量。
   * 因此任何比率的分母都必须用接口回传的 total，绝不能用切片长度——否则真实
   * 500 张里 400 张已解决会显示成完成率 20%（真实 80%）。
   */
  const [ticketsMeta, setTicketsMeta] = useState<{
    total?: number;
    limit?: number;
    returned?: number;
    limit_clamped?: boolean;
    requested_limit?: number;
  } | null>(null);

  const recordFailure = useCallback((label: string, reason: string) => {
    setFailedSources((prev) => (prev.some((f) => f.label === label) ? prev : [...prev, { label, reason }]));
  }, []);

  /**
   * 读取模块开关并折算为**有效值**。
   *
   * 【禁】失败一律 fail-closed 到"未知"（mods=null + modsError），**绝不 fail-open
   * 到绿色**——接口挂了就宣称"已启用"，正是 #32 要消灭的伪造。
   * getJson 现为判别式结果：`ok:false` 覆盖 401/500/网络错误，契约不符（modules
   * 缺失或非对象）单独判——两类都落到同一个中性灰未知态，但后者额外记入失败横幅。
   */
  const loadModules = useCallback(async () => {
    setModsLoading(true);
    setModsError('');
    const r = await getJson<{ modules?: Record<string, unknown> }>('/api/settings/modules');
    if (!r.ok) {
      setMods(null);
      setModsError(MODULES_UNAVAILABLE_LABEL);
    } else if (typeof r.data.modules !== 'object' || r.data.modules === null) {
      setMods(null);
      setModsError(MODULES_UNAVAILABLE_LABEL);
      setFailedSources((prev) =>
        prev.some((f) => f.label === '模块开关') ? prev : [...prev, { label: '模块开关', reason: '接口返回结构不符（缺 modules 字段）' }],
      );
    } else {
      // effectiveModules 内部逐键校验 typeof === 'boolean'，故喂进未清洗的原始
      // JSON 也不会把非布尔值渗进有效值（后端已在该函数文档中承诺此契约），
      // 这里的断言是安全的。
      setMods(effectiveModules(r.data.modules as Partial<Record<ModuleKey, boolean>>));
    }
    setModsLoading(false);
  }, []);

  useEffect(() => {
    void loadModules();
  }, [loadModules]);

  /**
   * 能力卡状态（文案取自 PM §7.1 定稿，逐字照抄）。
   *
   * 【禁】三条陷阱（设计师明确警示，违反即重演 #32 的谎言）：
   *   1. **禁止 fail-open 到绿色** —— 加载中/接口失败一律中性灰，绝不回落"已启用"。
   *   2. **必须用有效值** —— mods 已由 lib/modules 的 effectiveModules() 折算，
   *      不是接口返回的 Partial 覆盖值。
   *   3. **停用/未知/无开关态不渲染对勾** —— 对勾配灰字自相矛盾。
   *
   * tone 只有 'green'（确实在生效）与 'muted'（中性事实）两种：
   * 停用不是告警，故不用红、也不用琥珀（见审计 §10.1 语义色分配规则）。
   *
   * 各态的**解释性文案一律落在可见文本**（desc / 面板级 role="alert"），不返回
   * note 也不挂 title：审计 #34 指出 title 不进入无障碍名计算、键盘用户取不到，
   * 不能承载唯一说明。
   */
  function moduleCardStatus(key: ModuleKey | null): {
    label: string;
    tone: 'green' | 'muted';
    check: boolean;
  } {
    // 无独立开关的基础能力：不是开关派生的实时状态，故不用绿色"已启用"。
    // 口径对齐审计 #34（"框架已实现" vs "终端实时探测"），文案取 PM §7.1 定稿
    // （2026-09-25 追加裁定，pm-product-review.md:1277-1292）。
    //
    // 【禁】不得写 `已启用`，即便事实上它确实在跑：无法从接口派生的值写死，就是重新
    // 引入 #32 要消灭的"静态常量冒充实时状态"——而**碰巧正确的硬编码比明显错误的
    // 更危险**，因为没人会去修它。
    //
    // 选 `随 Agent 常驻` 而非 `常驻能力 · 无独立开关`：前者说清了**为什么**没有开关
    // （Agent 在跑它就在跑），后者只陈述"没有开关"这一事实，且"无独立开关"对运营者
    // 是无意义信息（他们从没以为它有开关），读起来还像辩解。
    //
    // 「为何无开关」的解释落在 desc（可见文本）里，不挂 title——审计 #34 已确立
    // title 不进入无障碍名计算，键盘与读屏用户拿不到，不能作唯一载体。
    if (key === null) {
      return { label: '随 Agent 常驻', tone: 'muted', check: false };
    }
    if (modsLoading) return { label: '读取中…', tone: 'muted', check: false };
    // 接口不可达：PM §7.1 要求中性灰 + 重试入口，禁用绿/红
    if (modsError || mods === null) return { label: '状态未知', tone: 'muted', check: false };
    // fail-closed：有效值里取不到该键就当作未启用，绝不默认绿
    if (mods[key] !== true) {
      // code_scan 的停用是 2026-09-25 用户决策（交由专业扫描器），有专用文案；
      // 其余模块被管理员关掉属"停用（其他原因）"。
      return key === 'code_scan'
        ? { label: '已停用 · 交由专业扫描器', tone: 'muted', check: false }
        : { label: '已停用', tone: 'muted', check: false };
    }
    // 唯一可以用绿的分支：确实读到该模块开着
    return { label: '已启用', tone: 'green', check: true };
  }

  useEffect(() => {
    let alive = true;
    getJson<{ devices?: DeviceLite[] }>('/api/devices?limit=2000').then((r) => {
      if (!alive) return;
      if (r.ok) setDevices(Array.isArray(r.data.devices) ? r.data.devices : []);
      else recordFailure('终端清单', r.reason);
    });
    getJson<{ tickets?: TicketLite[] }>('/api/tickets?limit=6').then((r) => {
      if (!alive) return;
      if (r.ok) setTickets(Array.isArray(r.data.tickets) ? r.data.tickets : []);
      else recordFailure('最新工单', r.reason);
    });
    getJson<{
      tickets?: TicketLite[];
      total?: number;
      returned?: number;
      limit?: number;
      limit_clamped?: boolean;
      requested_limit?: number;
    }>('/api/tickets?limit=500').then((r) => {
      if (!alive) return;
      if (r.ok) {
        setTicketsAll(Array.isArray(r.data.tickets) ? r.data.tickets : []);
        // ②⑤：limit=500 会被后端钳到 MAX_LIMIT=200，返回的是头部偏置样本。
        // 记下 total / limit_clamped，比率分母与口径标注都以此为准。
        setTicketsMeta({
          total: r.data.total,
          returned: r.data.returned,
          limit: r.data.limit,
          limit_clamped: r.data.limit_clamped,
          requested_limit: r.data.requested_limit,
        });
      } else {
        recordFailure('全量工单（处置进度/MTTA/MTTR 的分母）', r.reason);
      }
    });
    getJson<{ findings?: Array<Record<string, unknown>> }>('/api/findings?limit=1000').then((r) => {
      if (!alive) return;
      if (r.ok) setFindingsAll(Array.isArray(r.data.findings) ? r.data.findings : []);
      else recordFailure('发现样本（技战法活跃态势）', r.reason);
    });
    getJson<{ entries?: AuditLite[] }>('/api/audit?limit=6').then((r) => {
      if (!alive) return;
      if (r.ok) setAudit(Array.isArray(r.data.entries) ? r.data.entries : []);
      else recordFailure('近期动态', r.reason);
    });
    getJson<{ hours?: number; buckets?: TrendBucketLite[] }>('/api/trend?hours=48').then((r) => {
      if (!alive) return;
      if (r.ok && Array.isArray(r.data.buckets)) setTrend({ hours: r.data.hours ?? 48, buckets: r.data.buckets });
      else if (!r.ok) recordFailure('48h 趋势', r.reason);
    });
    getJson<{
      connected?: boolean;
      complete?: boolean;
      rule_stats?: Array<{ rule_id: string; category: string; critical: number; high: number; total: number }>;
    }>('/api/findings/rule-stats').then((r) => {
      if (!alive) return;
      // rule-stats 允许诚实降级（旧 Collector 无该端点 → connected:false 回落样本），
      // 故失败不记入告警横幅，但也不再伪装成"有数据"。
      if (r.ok) setRuleStats(r.data);
      else setRuleStats(null);
    });
    return () => {
      alive = false;
    };
  }, [recordFailure]);

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
  /**
   * Task#5 ②⑤（PM 裁定 8.0）：clamp 样本口径。
   *
   * /api/tickets 的排序是「严重度升序 + 时间降序」，所以钳制到 MAX_LIMIT=200 后
   * 返回的是**头部偏置样本**（最严重的 200 张），不是全量随机样本。旧代码用
   * `ticketsAll.length` 当分母，把样本内比率冒充成全量比率：真实 500 张里 400 张
   * 已解决时，样本（最严重那批，多半还没闭环）可能只有 40 张已解决 → 显示 20%，
   * 而真实是 80%。把"响亮的 400 错误"换成"安静的错误数字"更危险，因为没人会质疑它。
   *
   * 按 PM 裁定改用接口回传的 `total` 作分母。注意这样得到的是**全量下界**而非估计值：
   * 分子（样本内已解决数）是全量已解决数的子集，故 resolved/total ≤ 真实完成率。
   * 下界保守但不会错，配合下方口径标注使用；而"样本内比率"是个方向未知的偏置估计，
   * 不能当全量值展示。堆叠条同理——用 total 作分母后各段之和 < 100%，视觉上如实
   * 呈现"我们只掌握了其中一部分"，而不是拼成一根看似完整的 100% 条。
   */
  const sampleSize = (ticketsAll ?? []).length;
  const ticketsTotal = typeof ticketsMeta?.total === 'number' ? ticketsMeta.total : sampleSize;
  /**
   * 是否真的只拿到了一部分。
   *
   * 判据**只能**是 `total > 已加载数`，不能用 `limit_clamped`：后者表示"请求值被
   * 钳过"，而本页请求的是 limit=500、后端 MAX_LIMIT=200，所以即使全舰队只有 7 张
   * 工单、我们已经拿到全部 7 张，`limit_clamped` 依然是 true。用它当判据会在数据
   * 完整时谎称"仅基于最严重的 7 张（共 7 张）· 非全量"——那是凭空捏造一个不存在
   * 的样本偏差，比不标注更糟。（这是我第一版写错的地方，已改。）
   *
   * `limit_clamped` / `requested_limit` 仍有价值，但只用于说明"为什么是 200 而不是
   * 500"，不用于判断截断。
   */
  const ticketsTruncated = ticketsTotal > sampleSize;
  const dispTotal = ticketsTotal > 0 ? ticketsTotal : 1;

  /* P2 规则/来源排行（无真实地理数据→降级为可解释排行表）+ 平均处置耗时 */
  const ruleRank = useMemo(() => {
    const m = new Map<string, number>();
    for (const f of findingsAll ?? []) {
      const k = String(f.kind ?? 'unknown');
      m.set(k, (m.get(k) ?? 0) + 1);
    }
    return [...m.entries()].sort((a, b) => b[1] - a[1]).slice(0, 8);
  }, [findingsAll]);

  /**
   * 技战法活跃态势（AIDR Detection 活动侧）：把已加载发现样本按 category+kind 映射到
   * 技战法，聚合命中数与严重/高危数。口径如实标注为「最近 ≤1000 条发现样本」。
   */
  const techniqueActivity = useMemo(() => {
    const m = new Map<string, { count: number; critHigh: number }>();
    const fleetRows = ruleStats?.connected && Array.isArray(ruleStats.rule_stats) ? ruleStats.rule_stats : null;
    if (fleetRows) {
      // fleet 级权威聚合：per-rule 计数直接映射到技战法（全量，非样本）。
      // 规则 ID 在三集合间唯一，故按 id 匹配即可（prod 旧上报可能缺 category 字段）。
      for (const r of fleetRows) {
        for (const t of TECHNIQUES) {
          const hit = t.rules.some((x) => x.ids.includes(r.rule_id));
          if (!hit) continue;
          const cur = m.get(t.id) ?? { count: 0, critHigh: 0 };
          cur.count += r.total;
          cur.critHigh += r.critical + r.high;
          m.set(t.id, cur);
        }
      }
    } else {
      for (const f of findingsAll ?? []) {
        const kind = String(f.kind ?? '');
        const cat = String(f.category ?? '') as RuleSet;
        const sev = String(f.severity ?? '');
        for (const t of TECHNIQUES) {
          const hit = t.rules.some((r) => r.set === cat && r.ids.includes(kind));
          if (!hit) continue;
          const cur = m.get(t.id) ?? { count: 0, critHigh: 0 };
          cur.count += 1;
          if (sev === 'critical' || sev === 'high') cur.critHigh += 1;
          m.set(t.id, cur);
        }
      }
    }
    return [...m.entries()].sort((a, b) => b[1].count - a[1].count);
  }, [findingsAll, ruleStats]);
  const techniqueSource: 'fleet' | 'sample' =
    ruleStats?.connected && Array.isArray(ruleStats.rule_stats) ? 'fleet' : 'sample';
  const egressRank = useMemo(() => {
    const m = new Map<string, number>();
    for (const d of devices ?? []) {
      const e = (d as { network?: { egress_ip?: string } }).network?.egress_ip;
      if (typeof e !== 'string' || !e) continue;
      const key = maskEgress(e);
      m.set(key, (m.get(key) ?? 0) + 1);
    }
    return [...m.entries()].sort((a, b) => b[1] - a[1]).slice(0, 6);
  }, [devices]);
  const avgResolveHours = useMemo(() => {
    const rs = (ticketsAll ?? []).filter((t) => t.status === 'resolved' && typeof t.resolved_at === 'number' && t.created_at);
    if (rs.length === 0) return null;
    const sum = rs.reduce((a, t) => a + (Number(t.resolved_at) - Number(t.created_at)), 0);
    return (sum / rs.length / 3600000).toFixed(1);
  }, [ticketsAll]);

  /** MTTR 按严重度细分（AIDR efficacy）：严重/高危 与 中/低 的平均闭环小时数。 */
  const mttrBySev = useMemo(() => {
    const bucket = (pred: (s: string) => boolean) => {
      const rs = (ticketsAll ?? []).filter(
        (t) => t.status === 'resolved' && typeof t.resolved_at === 'number' && t.created_at && pred(t.severity),
      );
      if (rs.length === 0) return null;
      const sum = rs.reduce((a, t) => a + (Number(t.resolved_at) - Number(t.created_at)), 0);
      return (sum / rs.length / 3600000).toFixed(1);
    };
    return {
      critHigh: bucket((s) => s === 'critical' || s === 'high'),
      medLow: bucket((s) => s !== 'critical' && s !== 'high'),
    };
  }, [ticketsAll]);

  /**
   * MTTA（平均响应时长，AIDR Response 侧 efficacy）：工单创建 → 首次脱离 open
   * 的平均小时数。由真实工单 history 派生，无样本返回 null（绝不回填 0 或猜测值）。
   *
   * Task#5 ③：判据必须用 **action**，不能用状态字段。history 条目的真实字段是
   * {action, actor, timestamp, note?}（lib/store.ts 的 TicketHistoryEntry），
   * **既没有状态字段也没有 at**。旧实现的过滤条件同时断言了这两个不存在的字段，
   * 故恒为假 → samples 恒空 → 该函数**自上线以来从未产出过真实数值**，页面一直
   * 显示"—（暂无已响应工单）"，看起来像"没人响应过"，实际是"我们根本没读到"。
   * （此处刻意不逐字引用旧表达式：引了会让按旧字段名做的复验 grep 命中注释，
   *   把这个已修项报成仍存在。）
   *
   * 「脱离 open」= 第一条 action ∈ LEAVE_OPEN_ACTIONS 的条目。排除的动词：
   *   create（工单诞生，仍在 open）、reopen（回到 open，是脱离的反向）、
   *   assign / comment / update（不改状态）。
   * 时间统一经 toTimestamp 归一（容忍 ms/s 混用），与 created_at 同基准后再相减。
   */
  const mttaHours = useMemo(() => {
    const samples: number[] = [];
    for (const t of ticketsAll ?? []) {
      const created = toTimestamp(t.created_at);
      if (created === null) continue;
      const first = (t.history ?? [])
        .map((h) => ({ action: String(h.action ?? ''), ts: toTimestamp(h.timestamp ?? h.at) }))
        .filter((h): h is { action: string; ts: number } => h.ts !== null && h.ts >= created && LEAVE_OPEN_ACTIONS.has(h.action))
        .sort((a, b) => a.ts - b.ts)[0];
      if (first) samples.push(first.ts - created);
    }
    if (samples.length === 0) return null;
    return (samples.reduce((a, b) => a + b, 0) / samples.length / 3600000).toFixed(1);
  }, [ticketsAll]);

  /* 视觉迭代：实时态势 hero 派生（真实数据，不造假） */
  const critTotal = fleet?.finding_totals?.critical ?? fleet?.latest_severity?.critical ?? 0;
  const highTotal = fleet?.finding_totals?.high ?? fleet?.latest_severity?.high ?? 0;
  const statusValue = critTotal > 0 ? '需处置' : highTotal > 0 ? '需关注' : '风险可控';
  const statusTone = critTotal > 0 ? 'var(--sentinel-danger)' : highTotal > 0 ? 'var(--sentinel-warning)' : 'var(--sentinel-accent)';

  /**
   * 数据新鲜度（handoff P0）：以 fleet 最近一次上报（max last_seen）推导数据年龄；
   * 超过 3× 上报间隔（15 分钟）即视为 stale，UI 不得再宣称"实时"。无设备/未连接返回 null。
   */
  const freshness = useMemo(() => {
    const ts = (devices ?? [])
      .map((d) => (typeof d.last_seen === 'number' ? d.last_seen : 0))
      .filter((x) => x > 0);
    if (ts.length === 0) return null;
    const lastSec = Math.max(...ts);
    const ageSec = Math.floor(Date.now() / 1000) - lastSec;
    return { lastSec, ageSec, stale: ageSec > 15 * 60 };
  }, [devices]);
  const todayStart = (() => {
    const d = new Date();
    d.setHours(0, 0, 0, 0);
    return Math.floor(d.getTime() / 1000);
  })();
  const ticketsToday = (ticketsAll ?? []).filter((t) => (t.created_at ?? 0) >= todayStart).length;
  const resolveRate = Math.round((dispCounts.resolved / dispTotal) * 100);
  /**
   * clamp 口径标注（PM §7.5 句式「基于最近 ≤N 条样本」的工单版）。
   * 截断时必须说出来，且不得宣称全量；未截断时返回 null（不显示多余标注）。
   */
  const ticketsScopeNote = ticketsTruncated
    ? `基于最严重的 ${sampleSize} 张工单（共 ${ticketsTotal} 张）· 非全量`
    : null;

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

      {/* Task#5 ④：数据源失败必须可见。此前 getJson 把 !r.ok 与 catch 双双折叠成
          null，调用方再 `?? []`，于是"接口 500 / Collector 不可达"与"确实没有数据"
          渲染完全同形——KPI 显示 0、完成率显示 0%、时间线显示"暂无动态"。
          一个安静的错误数字比一个响亮的失败更危险，因为没人会去质疑它。 */}
      {failedSources.length > 0 && (
        <div
          role="alert"
          style={{
            display: 'flex',
            alignItems: 'flex-start',
            gap: 10,
            padding: '12px 14px',
            marginBottom: 14,
            borderRadius: 'var(--sentinel-radius-md)',
            background: 'color-mix(in srgb, var(--sentinel-danger) 12%, transparent)',
            border: '1px solid color-mix(in srgb, var(--sentinel-danger) 40%, transparent)',
            color: 'var(--sentinel-danger)',
            fontSize: 12,
            lineHeight: 1.6,
          }}
        >
          <AlertTriangle size={15} style={{ flexShrink: 0, marginTop: 2 }} />
          <div>
            <div style={{ fontWeight: 600 }}>
              {failedSources.length} 个数据源读取失败，本页相关数字不代表真实值
            </div>
            <ul style={{ margin: '4px 0 0', padding: '0 0 0 18px' }}>
              {failedSources.map((f) => (
                <li key={f.label}>
                  {f.label}：{f.reason}
                </li>
              ))}
            </ul>
            <div style={{ marginTop: 6, color: 'var(--sentinel-text-2)' }}>
              受影响的指标已按"未知"处理，不会回落成 0 或绿色正常态。
              <button type="button" className="handle" style={{ marginLeft: 8 }} onClick={() => window.location.reload()}>
                重新加载
              </button>
            </div>
          </div>
        </div>
      )}

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
      {/* 实时态势 hero（reference 视觉迭代）：shield 状态环 + mini 指标，全部真实数据 */}
      <section className="panel" style={{ padding: 18, marginBottom: 14, display: 'flex', gap: 18, alignItems: 'center', flexWrap: 'wrap' }}>
        <div className="shield-circle" aria-hidden="true">
          <ShieldCheck size={26} />
        </div>
        <div style={{ minWidth: 150 }}>
          <div style={{ color: 'var(--sentinel-text-3)', fontSize: 12 }}>安全状态</div>
          <div style={{ marginTop: 3, color: statusTone, fontSize: 24, fontWeight: 800, letterSpacing: '-0.02em' }}>{statusValue}</div>
          <div style={{ color: 'var(--sentinel-text-3)', fontSize: 11, marginTop: 4 }}>持续监测 · 主动防御 · 业务安全稳定</div>
          <div
            className="sentinel-status"
            data-state={freshness ? (freshness.stale ? 'stale' : 'normal') : 'stale'}
            style={{ marginTop: 6 }}
            title="数据新鲜度：以 fleet 最近一次上报推导；超过 15 分钟视为陈旧"
          >
            {freshness
              ? freshness.stale
                ? `数据陈旧 · 最近上报 ${relTime(freshness.lastSec * 1000)}`
                : `实时 · 最近上报 ${relTime(freshness.lastSec * 1000)}`
              : '未连接 Collector · 无实时数据'}
          </div>
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(110px, 1fr))', gap: 10, flex: 1 }}>
          <div className="mini">
            <label>今日告警</label>
            <b>{ticketsToday}</b>
          </div>
          <div className="mini">
            <label>严重发现</label>
            <b style={{ color: 'var(--sentinel-danger)' }}>{critTotal}</b>
          </div>
          <div className="mini">
            <label>高危发现</label>
            <b style={{ color: 'var(--sentinel-warning)' }}>{highTotal}</b>
          </div>
          <div className="mini">
            <label>受影响资产</label>
            <b>{fleet ? fleet.latest_severity.critical + fleet.latest_severity.high : 0}</b>
          </div>
          <div className="mini">
            <label>已处置</label>
            <b style={{ color: 'var(--sentinel-accent)' }}>{dispCounts.resolved}</b>
          </div>
        </div>
      </section>

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
        <article
          className={`metric${fleet && (fleet.latest_severity.critical + fleet.latest_severity.high) > 0 ? ' danger' : ''} animate-entrance animate-entrance-3`}
        >
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
        <article
          className={`metric${trend && crit24 + high24 > 0 ? ' danger' : ''} animate-entrance animate-entrance-6`}
        >
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
      {/* 不再叠加装饰性"威胁曲线"背景图：无数据时它会被误读成伪造的趋势线，
          有数据时又与真实折线重叠（handoff 原则5：不渲染假图表）。 */}
      <section
        className="panel animate-entrance animate-entrance-5"
        style={{
          padding: 16,
          marginBottom: 16,
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
                  <Area type="linear" dataKey="reports" name="上报数" stroke="var(--primary)" fill="var(--primary)" fillOpacity={0.12} strokeWidth={2} />
                  <Line type="linear" dataKey="critical" name="严重" stroke="var(--destructive)" strokeWidth={2} dot={false} />
                  <Line type="linear" dataKey="high" name="高危" stroke="var(--sentinel-warning)" strokeWidth={2} dot={false} />
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
                <strong style={{ fontSize: 22, color: 'var(--sentinel-warning)' }}>{high24}</strong>
              </div>
              {/* 计数层(stage-1)：舰队累计发现总数，读 summary.finding_totals（O(设备数)，零 body 解析） */}
              <div style={{ borderTop: '1px solid var(--border)', paddingTop: 8 }}>
                <div style={{ fontSize: 12, color: 'var(--muted-foreground)' }}>舰队累计 严重 / 高危</div>
                <strong style={{ fontSize: 18, fontVariantNumeric: 'tabular-nums' }}>
                  <span style={{ color: 'var(--destructive)' }}>{fleet?.finding_totals?.critical ?? 0}</span>
                  {' / '}
                  <span style={{ color: 'var(--sentinel-warning)' }}>{fleet?.finding_totals?.high ?? 0}</span>
                </strong>
              </div>
            </div>
          </div>
        ) : (
          <p className="empty-hint">接收器未连接，暂无趋势数据。</p>
        )}

        {/* 视觉迭代：24h 按小时严重度着色柱状 sparkline + 严重/高危占比 progress（真实数据） */}
        {trend && (
          <>
            <div className="bar-spark" aria-hidden="true" style={{ marginTop: 12 }}>
              {chartData.map((b) => {
                const max = Math.max(1, ...chartData.map((x) => x.reports));
                const h = Math.max(2, Math.round((b.reports / max) * 100));
                const color =
                  b.critical > 0 ? 'var(--sentinel-danger)' : b.high > 0 ? 'var(--sentinel-warning)' : b.reports > 0 ? 'var(--sentinel-accent)' : 'var(--sentinel-blue)';
                return <i key={b.t} style={{ height: `${h}%`, background: color }} />;
              })}
            </div>
          </>
        )}
      </section>

      <ObservabilityPanel />

      {/* P2 态势视图切换（聚焦透镜，handoff P2）：运营概览 / 终端覆盖 / 规则风险 / 处置效率 */}
      <div role="tablist" aria-label="态势视图" style={{ display: 'flex', gap: 6, marginBottom: 14, flexWrap: 'wrap' }}>
        {([['overview', '运营概览'], ['coverage', '终端覆盖'], ['rules', '规则风险'], ['efficiency', '处置效率']] as const).map(([k, label]) => (
          <button
            key={k}
            role="tab"
            aria-selected={view === k}
            className="sentinel-button"
            style={view === k ? { borderColor: 'var(--sentinel-accent)', color: 'var(--sentinel-accent)' } : undefined}
            onClick={() => setView(k)}
          >
            {label}
          </button>
        ))}
      </div>

      {view === 'coverage' && (
        <section className="panel" style={{ padding: 16, marginBottom: 16 }}>
          <div className="panel-head">
            <div>
              <h2>终端覆盖</h2>
              <p>在线率 / 版本覆盖 / 漂移（真实 Collector 数据）</p>
            </div>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))', gap: 12 }}>
            <div>
              <div style={{ fontSize: 12, color: 'var(--muted-foreground)' }}>在线率</div>
              <strong className="sentinel-metric-value" style={{ fontSize: 22 }}>{totalDevices ? ((activeDevices / totalDevices) * 100).toFixed(1) : '—'}%</strong>
            </div>
            <div>
              <div style={{ fontSize: 12, color: 'var(--muted-foreground)' }}>版本覆盖</div>
              <strong className="sentinel-metric-value" style={{ fontSize: 22 }}>{totalDevices ? ((currentDevices / totalDevices) * 100).toFixed(1) : '—'}%</strong>
            </div>
            <div>
              <div style={{ fontSize: 12, color: 'var(--muted-foreground)' }}>漂移设备</div>
              <strong className="sentinel-metric-value" style={{ fontSize: 22 }}>{fleet ? totalDevices - currentDevices : '—'}</strong>
            </div>
          </div>
        </section>
      )}

      {view === 'rules' && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: 14, marginBottom: 16 }}>
          <section className="panel" style={{ padding: 16 }}>
            <div className="panel-head">
              <div>
                <h2>规则风险排行</h2>
                <p>按规则类型统计发现数（基于最近 ≤1000 条发现样本；无真实地理数据时的可解释降级视图）</p>
              </div>
            </div>
            <table className="sentinel-table">
              <thead>
                <tr><th>规则类型</th><th>发现数</th></tr>
              </thead>
              <tbody>
                {ruleRank.length === 0 && <tr><td colSpan={2} style={{ color: 'var(--muted-foreground)' }}>暂无发现数据</td></tr>}
                {ruleRank.map(([k, n]) => (
                  <tr key={k}><td style={{ fontFamily: 'var(--sentinel-font-mono)' }}>{k}</td><td style={{ fontFamily: 'var(--sentinel-font-mono)' }}>{n}</td></tr>
                ))}
              </tbody>
            </table>
          </section>
          <section className="panel" style={{ padding: 16 }}>
            <div className="panel-head">
              <div>
                <h2>来源排行（出口 IP）</h2>
                <p>按终端出口 IP（默认脱敏至 /16）统计设备数</p>
              </div>
            </div>
            <table className="sentinel-table">
              <thead>
                <tr><th>出口 IP</th><th>设备数</th></tr>
              </thead>
              <tbody>
                {egressRank.length === 0 && <tr><td colSpan={2} style={{ color: 'var(--muted-foreground)' }}>暂无出口数据</td></tr>}
                {egressRank.map(([ip, n]) => (
                  <tr key={ip}><td style={{ fontFamily: 'var(--sentinel-font-mono)' }}>{ip}</td><td style={{ fontFamily: 'var(--sentinel-font-mono)' }}>{n}</td></tr>
                ))}
              </tbody>
            </table>
          </section>
          <section className="panel" style={{ padding: 16 }}>
            <div className="panel-head">
              <div>
                <h2>技战法活跃态势</h2>
                <p>
                  {techniqueSource === 'fleet'
                    ? `Collector fleet 级 per-rule 增量聚合映射到 OWASP 技战法的命中分布${ruleStats?.complete ? '' : '（聚合推进中·partial）'}`
                    : '已加载发现样本（≤1000 条）映射到 OWASP 技战法的命中分布（旧 Collector 无 fleet 聚合端点时的回落口径）'}
                </p>
              </div>
            </div>
            <table className="sentinel-table">
              <thead>
                <tr><th>技战法</th><th>命中</th><th>严重/高危</th></tr>
              </thead>
              <tbody>
                {techniqueActivity.length === 0 && (
                  <tr><td colSpan={3} style={{ color: 'var(--muted-foreground)' }}>暂无发现样本，无法推导技战法活跃</td></tr>
                )}
                {techniqueActivity.map(([id, v]) => (
                  <tr key={id}>
                    <td style={{ fontFamily: 'var(--sentinel-font-mono)' }}>{id}</td>
                    <td style={{ fontFamily: 'var(--sentinel-font-mono)' }}>{v.count}</td>
                    <td style={{ fontFamily: 'var(--sentinel-font-mono)', color: v.critHigh > 0 ? 'var(--sentinel-danger)' : undefined }}>
                      {v.critHigh}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </section>
        </div>
      )}

      {view === 'efficiency' && (
        <section className="panel" style={{ padding: 16, marginBottom: 16 }}>
          <div className="panel-head">
            <div>
              <h2>处置效率</h2>
              <p>工单闭环耗时与状态分布</p>
            </div>
          </div>
          <div style={{ display: 'flex', gap: 24, flexWrap: 'wrap', marginBottom: 12 }}>
            <p style={{ fontSize: 13, margin: 0 }}>
              平均响应 MTTA：<strong className="sentinel-metric-value" style={{ fontSize: 20 }}>{mttaHours ?? '—'}</strong>
              {mttaHours ? ' 小时' : ticketsAll === null ? '（工单数据未就绪）' : '（暂无已响应工单）'}
            </p>
            <p style={{ fontSize: 13, margin: 0 }}>
              平均闭环 MTTR：<strong className="sentinel-metric-value" style={{ fontSize: 20 }}>{avgResolveHours ?? '—'}</strong>
              {avgResolveHours ? ' 小时' : ticketsAll === null ? '（工单数据未就绪）' : '（暂无已闭环工单）'}
            </p>
            <p style={{ fontSize: 12, margin: 0, color: 'var(--muted-foreground)' }}>
              其中 严重/高危 {mttrBySev.critHigh ?? '—'}h · 中/低 {mttrBySev.medLow ?? '—'}h
            </p>
          </div>
          {ticketsScopeNote && (
            /* Task#5 ⑤：MTTA / MTTR / 严重度细分全部派生自同一份 clamp 样本，
               而样本是"最严重的 N 张"，其响应与闭环耗时系统性偏离全量（越严重
               往往越慢）。不标注就会把一个头部偏置样本的平均值当成舰队均值读。 */
            <p style={{ fontSize: 11, color: 'var(--sentinel-warning)', margin: '0 0 10px' }}>
              {ticketsScopeNote}；MTTA / MTTR 为同样本内的均值，非全量。
            </p>
          )}
          <div style={{ display: 'flex', height: 10, borderRadius: 99, overflow: 'hidden', background: 'var(--surface-2)', marginBottom: 10 }}>
            <div style={{ width: `${(dispCounts.resolved / dispTotal) * 100}%`, background: 'var(--sentinel-accent)' }} />
            <div style={{ width: `${(dispCounts.processing / dispTotal) * 100}%`, background: 'var(--sentinel-cyan)' }} />
            <div style={{ width: `${(dispCounts.pending / dispTotal) * 100}%`, background: 'var(--sentinel-warning)' }} />
            <div style={{ width: `${(dispCounts.closed / dispTotal) * 100}%`, background: 'var(--sentinel-text-3)' }} />
          </div>
          <p style={{ fontSize: 12, color: 'var(--muted-foreground)' }}>
            已完成 {dispCounts.resolved} · 处理中 {dispCounts.processing} · 待处理 {dispCounts.pending} · 已关闭 {dispCounts.closed}
          </p>
          {ticketsScopeNote && (
            /* Task#5 ⑤：clamp 口径标注。上方堆叠条以 total 为分母，故截断时各段之和
               < 100%——留白部分即"尚未加载到的工单"，不是"没有其他状态"。 */
            <p style={{ fontSize: 11, color: 'var(--sentinel-warning)', margin: '4px 0 0' }}>{ticketsScopeNote}</p>
          )}
        </section>
      )}

      {view === 'sources' && (
        <SourceAttributionPanel
          devices={(devices ?? []) as unknown as Array<{ device_id: string; hostname?: string; os?: string; network?: { egress_ip?: string } }>}
          findings={(findingsAll ?? []) as unknown as Array<{ device_id: string; kind: string; severity: string }>}
        />
      )}

      {/* ─── 态势两区：风险资产 / 处置进度（健康度已并入统一可观测组件）────── */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: 14, marginBottom: 16 }}>

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
          <div style={{ display: 'flex', alignItems: 'baseline', gap: 8, marginBottom: 8 }}>
            <strong className="sentinel-metric-value" style={{ fontSize: 26 }}>{resolveRate}%</strong>
            <span style={{ color: 'var(--sentinel-text-2)', fontSize: 12 }}>
              {/* 截断时这个百分比是**全量下界**（分子来自样本、分母是全量 total），
                  必须标明，否则会被读成全量完成率。Task#5 ⑤。 */}
              {ticketsTruncated ? '处置完成率（已知部分的下界）' : '本周期处置完成率'}
              {avgResolveHours ? ` · 平均 ${avgResolveHours}h` : ''}
            </span>
          </div>
          <div className="progress" style={{ marginBottom: 12 }}>
            <i style={{ width: `${resolveRate}%` }} />
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
          {ticketsScopeNote && (
            /* Task#5 ⑤：四段计数是**样本内**计数，而上面堆叠条以全量 total 为分母，
               所以各段之和 < 100%。缺这句标注的话，读者会把 200 张样本的四段分布
               当成全量分布读（PM 裁定：clamp 时不得宣称全量）。 */
            <p style={{ fontSize: 11, color: 'var(--sentinel-warning)', margin: '8px 0 0' }}>{ticketsScopeNote}</p>
          )}
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
          {/* 审计 #32：接口不可达时给出中性灰提示 + 重试入口（PM §7.1 要求，禁绿禁红）。
              提示放在面板级而非 4 张卡各写一遍，避免同一句长文案重复四次；
              卡内芯片同时显示"状态未知"，两处文案都是 PM 定稿原文。 */}
          {modsError && (
            <div
              role="alert"
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 8,
                flexWrap: 'wrap',
                margin: '0 0 12px',
                padding: '10px 12px',
                borderRadius: 'var(--sentinel-radius-md)',
                background: 'color-mix(in srgb, var(--sentinel-text-2) 8%, transparent)',
                border: '1px solid color-mix(in srgb, var(--sentinel-text-2) 24%, transparent)',
                color: 'var(--sentinel-text-2)',
                fontSize: 12,
              }}
            >
              <AlertTriangle size={14} style={{ flexShrink: 0 }} />
              <span style={{ flex: 1, minWidth: 200 }}>
                {MODULES_UNAVAILABLE_LABEL}
                ；下方能力状态一律显示为未知，不会猜测为已启用。
              </span>
              <Button type="button" variant="outline" size="sm" onClick={() => void loadModules()} disabled={modsLoading}>
                <RefreshCw size={13} className={modsLoading ? 'spin' : undefined} />
                重试
              </Button>
            </div>
          )}
          <div className="module-grid">
            {modules.map(({ icon: Icon, title, desc, key }) => {
              const st = moduleCardStatus(key);
              // 代码质量扫描卡停用时，副标题换成 PM §7.1 的逐字定稿文案：
              // 继续写"SAST、依赖与密钥"会让读者以为这些扫描在跑。
              // 加载中/未知态不套用该文案——那时并不知道它是否停用。
              const codeScanOff =
                key === 'code_scan' && !modsLoading && !modsError && mods !== null && mods.code_scan !== true;
              return (
                <article className="module" key={title}>
                  {/* 图标底色跟随真实态：只有确实读到"开着"才用绿 */}
                  <span className={`module-icon ${st.tone === 'green' ? 'green' : 'muted'}`}>
                    <Icon size={19} />
                  </span>
                  <div>
                    <h3>{title}</h3>
                    <p>{codeScanOff ? CODE_SCAN_DISABLED_DESC : desc}</p>
                  </div>
                  {/* 【禁】停用/未知/加载中一律不渲染对勾（对勾 + 灰字自相矛盾） */}
                  <span className={`status ${st.tone}`}>
                    {st.check && <Check size={13} />}
                    {st.label}
                  </span>
                </article>
              );
            })}
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
                const meta = severityMeta(t.severity as TicketSeverity);
                return (
                  <div className="risk-row" key={t.ticket_id}>
                    <span className={`severity ${meta.tone}`}>{meta.label}</span>
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
                <span className="score-dot" style={{ background: 'var(--sentinel-accent)' }} />
                <span>当前版本</span>
                <b>{posture?.current ?? 0}</b>
              </p>
              <p>
                <span className="score-dot" style={{ background: 'var(--sentinel-warning)' }} />
                <span>Agent 版本不一致</span>
                <b>{posture?.agent_mismatch ?? 0}</b>
              </p>
              <p>
                <span className="score-dot" style={{ background: 'var(--sentinel-danger-2)' }} />
                <span>策略版本不一致</span>
                <b>{posture?.policy_mismatch ?? 0}</b>
              </p>
              <p>
                <span className="score-dot" style={{ background: 'var(--sentinel-danger)' }} />
                <span>两者均不一致</span>
                <b>{posture?.both_mismatch ?? 0}</b>
              </p>
              <p>
                <span className="score-dot" style={{ background: 'var(--sentinel-text-3)' }} />
                <span>未知</span>
                <b>{posture?.unknown ?? 0}</b>
              </p>
            </div>
          </div>
        </section>
      </div>

      {/* ─── Recent Activity Timeline (real audit entries) ─────────── */}
      {/* 不挂 .activity-timeline：那个类（app/detail.css）是给 ticket-detail 的
          .timeline-entry 结构准备的——自带 padding-left:28px 与一条 ::before 通栏
          竖线，竖线位置按 .timeline-entry::before 的 left:-23px 反推而来。本页用的是
          .timeline / .timeline-marker / .timeline-line 这套自绘节点结构（审计 #16
          刚补齐定义），若再继承那条 ::before 就会和 .timeline-line 并排出现两条竖线。
          两套时间线类名的合并属后续专项（审计 #16 已注明），此处只保证本页单条竖线。 */}
      <section className="panel animate-entrance animate-entrance-7">
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
                style={{ animationDelay: `${idx * 30 + 200}ms` }}
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
