'use client';

/**
 * 风险中心 — 安全事件工单队列。
 *
 * 工单来自 `GET /api/tickets`（内存注册表，见 lib/store.ts），状态流转走
 * `PUT /api/tickets/:id`，新建走 `POST /api/tickets`；服务端是唯一的状态机权威，
 * 非法流转会以 409 返回并原样提示给运营人员。接口不可用时回落到与旧版页面同源的
 * 界面实时数据，并在顶部横幅说明，此时任何流转都只会得到失败提示，不会伪造成功。
 */

import { Fragment, useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type { CSSProperties, FormEvent } from 'react';
import Link from 'next/link';
import { useSearchParams, useRouter } from 'next/navigation';
import { findingAsset } from '@/lib/labels';
import {
  AlertTriangle,
  ChevronDown,
  CircleCheck,
  CircleDot,
  Filter,
  Plus,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  X,
} from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { RiskSignalHelp, SignalSummary, SignalDetails } from '@/components/risk-signal-help';
import {
  NativeSelect,
  NativeSelectOption,
} from '@/components/ui/native-select';
import { Spinner } from '@/components/ui/spinner';
import { Textarea } from '@/components/ui/textarea';
import { useCollector } from '@/components/collector-context';
import { useRole } from '@/components/role-context';
import { Pagination, paginate } from '@/components/pagination';
import TicketDetail, {
  formatRelativeTime,
  parseTicket,
  parseTicketList,
  severityMeta,
  severityStyle,
  statusBadgeStyle,
  statusLabel,
  ticketTransitions,
  type Ticket,
  type TicketSeverity,
  type TicketStatus,
} from '@/components/ticket-detail';
import { DetailDrawer, type DrawerSection } from '@/components/detail-drawer';
import { ActionConfirmDialog, type ActionConfirmVariant } from '@/components/action-confirm-dialog';
import { EmptyState, ErrorState, LoadingState } from '@/components/ui-states';

/* ─── 展示层常量 ─────────────────────────────────────────── */

type TicketSource = 'loading' | 'api' | 'error';
type ToastTone = 'info' | 'success' | 'error';
type FilterKey = 'all' | 'pending' | 'investigating' | 'resolved';

/** 风险中心需二次确认的动作（批量终态 / 批量拉黑 / 单工单终态）。 */
type RiskConfirm =
  | { kind: 'batchTransition'; status: TicketStatus }
  | { kind: 'batchDeny' }
  | { kind: 'singleTransition'; ticket: Ticket; status: TicketStatus };

/** 为每类待确认动作生成「影响范围 + 回滚方式」文案（handoff P0：动作前展示影响与回滚）。 */
function buildRiskConfirmCopy(
  confirm: RiskConfirm | null,
  selectedCount: number,
): {
  title: string;
  description: string;
  impact: string[];
  rollback: string;
  variant: ActionConfirmVariant;
  confirmLabel: string;
} | null {
  if (!confirm) return null;
  if (confirm.kind === 'batchDeny') {
    return {
      title: '批量拉黑（封禁）',
      description: `确认对所选 ${selectedCount} 个工单的关联资产执行【拉黑】？`,
      impact: [
        '被拉黑的 Skill / MCP / 路径将编译进签名策略并下发终端强制执行',
        '终端命中拉黑项时会阻断该资产，可能影响相关业务',
        '仅管理员可执行；动作会记入审计日志',
      ],
      rollback: '可在「处置中心」把对应资产改回加白 / 观察，再发布一版策略即可撤销封禁。',
      variant: 'danger',
      confirmLabel: '确认拉黑',
    };
  }
  if (confirm.kind === 'batchTransition') {
    const label = statusLabel(confirm.status);
    return {
      title: `批量转为「${label}」`,
      description: `确认将所选 ${selectedCount} 个工单批量转为「${label}」？`,
      impact: [
        `这 ${selectedCount} 个工单的状态将变为「${label}」`,
        '终态流转会写入审计日志，作为处置闭环依据',
      ],
      rollback: '如需撤销，重新打开对应工单流转到「处理中」即可。',
      variant: 'warning',
      confirmLabel: '确认流转',
    };
  }
  const label = confirm.status === 'resolved' ? '标记为已解决' : '驳回';
  return {
    title: `${label}工单`,
    description: `确认将工单「${confirm.ticket.title}」${label}？`,
    impact: ['该工单将进入终态，从待处理队列移出', '流转结果会记入审计日志'],
    rollback: '如需撤销，重新打开该工单流转到「处理中」即可。',
    variant: 'warning',
    confirmLabel: '确认',
  };
}

const JSON_HEADERS = { 'Content-Type': 'application/json' } as const;


/** 状态筛选：与服务端 `?status=` 的枚举一致，这里在客户端过滤以保留全量计数。 */
const FILTERS: { key: FilterKey; label: string; match: TicketStatus[] | null }[] = [
  { key: 'all', label: '全部', match: null },
  { key: 'pending', label: '待处理', match: ['open', 'acknowledged'] },
  { key: 'investigating', label: '调查中', match: ['investigating'] },
  { key: 'resolved', label: '已解决', match: ['resolved', 'dismissed'] },
];

const SEVERITY_OPTIONS: { value: TicketSeverity; label: string }[] = [
  { value: 'critical', label: '严重' },
  { value: 'high', label: '高危' },
  { value: 'medium', label: '中危' },
  { value: 'low', label: '低危' },
];

/** 与 lib/store.ts 的 SEVERITY_RANK 一致：高危优先，其次最新。 */
const SEVERITY_RANK: Record<TicketSeverity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

/** 接口错误码的中文说明，`details` 存在时优先展示逐字段原因。 */
const ERROR_COPY: Record<string, string> = {
  ticket_not_found: '工单不存在或已被移除',
  invalid_ticket_id: '工单编号格式不正确',
  invalid_status_transition: '当前状态不允许该流转',
  validation_failed: '提交内容未通过服务端校验',
  no_updatable_fields: '没有需要更新的字段',
  read_only_field: '请求包含服务端托管字段',
};

/**
 * `.wide` 是 5 列网格；最后一列放宽到 auto，让「标记已解决 + 驳回」这类
 * 双动作也能并排显示。窄屏下 `.device` / `.time` 由 globals.css 隐藏。
 */
// 6 列：[选择框][严重度][主信息][设备][时间][操作]。此前加选择框后未同步列数导致行内容错位。
const TICKET_ROW_GRID = '30px 54px minmax(0,1fr) 150px 70px auto';

const handleStyle: CSSProperties = { cursor: 'pointer' };

const inlinePanelStyle: CSSProperties = { margin: '2px 0 12px' };


function compareTickets(left: Ticket, right: Ticket): number {
  const bySeverity =
    (SEVERITY_RANK[left.severity] ?? 9) - (SEVERITY_RANK[right.severity] ?? 9);
  if (bySeverity !== 0) return bySeverity;
  const leftStamp = Number(left.created_at) || 0;
  const rightStamp = Number(right.created_at) || 0;
  if (leftStamp !== rightStamp) return rightStamp - leftStamp;
  return left.ticket_id.localeCompare(right.ticket_id);
}

/* ─── 响应与错误解析 ─────────────────────────────────────── */

function isAbortError(error: unknown): boolean {
  return error instanceof Error && error.name === 'AbortError';
}

function errorText(error: unknown): string {
  return error instanceof Error && error.message ? error.message : '未知错误';
}

/** `{ error, message, details }` 是 lib/api.ts 的统一错误信封。 */
function describeError(payload: unknown, fallback: string): string {
  if (payload && typeof payload === 'object' && !Array.isArray(payload)) {
    const data = payload as Record<string, unknown>;
    const code = typeof data.error === 'string' ? data.error : '';
    const details = Array.isArray(data.details)
      ? data.details.filter((item): item is string => typeof item === 'string')
      : [];
    const copy = ERROR_COPY[code] ?? (typeof data.message === 'string' ? data.message : '');
    if (details.length > 0) return details.join('；');
    if (copy) return copy;
    if (code) return code;
  }
  return fallback;
}

/** 取 `{ ticket: {...} }` 里的记录；没有包装时退回载荷本身。 */
function pickRecord(payload: unknown, key: string): unknown {
  if (payload && typeof payload !== 'object' && !Array.isArray(payload)) {
    const data = payload as Record<string, unknown>;
    if (data[key] !== undefined) return data[key];
  }
  return payload;
}

/* ─── 页面 ───────────────────────────────────────────────── */

/**
 * 响应 Playbook（AIDR「Response」侧 / SOAR 引导）：按工单严重度 + 来源/描述类别，给出有序的
 * 推荐处置步骤；步骤尽量带深链（href）直达对应控制台能力，使 runbook 可执行而非纯文字。
 * 阈值为产品内置标准；已闭环不计。不含任何虚构数据。
 */
const SLA_HOURS: Record<string, number> = { critical: 1, high: 4, medium: 24, low: 24, info: 24 };
function isSlaBreached(t: Ticket): boolean {
  if (t.status === 'resolved' || t.status === 'dismissed') return false;
  if (typeof t.created_at !== 'number') return false;
  const limit = SLA_HOURS[t.severity] ?? 24;
  return Date.now() / 1000 - t.created_at > limit * 3600;
}

interface PlaybookStep {
  text: string;
  href?: string;
}
function buildResponsePlaybook(ticket: Ticket): PlaybookStep[] {
  const steps: PlaybookStep[] = [
    { text: '认领工单并确认影响面：终端、关联资产、规则信号与首次 / 最近出现时间' },
  ];
  const blob = `${ticket.source ?? ''} ${ticket.description ?? ''} ${ticket.title ?? ''}`.toLowerCase();
  if (ticket.severity === 'critical' || ticket.severity === 'high') {
    steps.push({
      text: '高危 / 严重：在处置中心对关联资产执行【拉黑】，编译进签名策略下发终端（需 admin；超爆炸半径需 typed override）',
      href: '/dispositions',
    });
    steps.push({ text: '发布策略后核对终端回执与版本姿态，确认封禁已在网生效', href: '/devices' });
  } else {
    steps.push({ text: '中 / 低危：优先【观察】留存证据，复核后再决定加白或拉黑', href: '/dispositions' });
  }
  if (/secret|credential|凭据|密钥|token|akia|ghp_/.test(blob)) {
    steps.push({ text: '凭据类：立即轮换泄露凭据，并审计该凭据近期调用记录', href: '/audit' });
  }
  if (/depend|lockfile|supply|依赖|供应链|unpinned|untrusted/.test(blob)) {
    steps.push({ text: '供应链类：锁定 / 移除不受信依赖，补齐 lockfile 后重新扫描', href: '/quality' });
  }
  if (/domain|egress|network|url|出站|网络|tls|transport/.test(blob)) {
    steps.push({ text: '网络 / 出站类：收紧 allowed_mcp_domains 与传输白名单，复核异常外联', href: '/mcp' });
  }
  if (/eval|shell|deserial|exec|命令|注入|prompt|override/.test(blob)) {
    steps.push({ text: '代码执行 / 注入类：隔离相关 Skill / MCP，禁用动态执行路径并复扫', href: '/skills' });
  }
  steps.push({ text: '处置完成后流转至「已解决」闭环（终态需二次确认），全程留审计' });
  return steps;
}

/** 按资产类型聚合可处置资产（skill / mcp / path），供汇总工单逐项处置入口。 */
function aggregateRemediable(findings: Array<Record<string, unknown>>): Array<{ asset_type: Exclude<import('@/lib/labels').AssetType, 'prefix'>; keys: string[]; kinds: string[] }> {
  const byType = new Map<import('@/lib/labels').AssetType, { keys: Set<string>; kinds: Set<string> }>();
  for (const f of findings) {
    const a = findingAsset(f as never);
    if (!a) continue;
    const slot = byType.get(a.asset_type) ?? { keys: new Set<string>(), kinds: new Set<string>() };
    slot.keys.add(a.asset_key);
    if (typeof f.kind === 'string') slot.kinds.add(f.kind);
    byType.set(a.asset_type, slot);
  }
  return [...byType.entries()]
    .map(([asset_type, v]) => ({ asset_type: asset_type as Exclude<typeof asset_type, 'prefix'>, keys: [...v.keys].sort(), kinds: [...v.kinds].sort() }))
    .sort((a, b) => b.keys.length - a.keys.length);
}

interface DeviceIdent {
  serial: string;
  os_user: string;
  hostname: string;
  network?: { egress_ip?: string; local_ips?: string[]; macs?: string[]; physical_nics?: { name: string; mac: string; ips?: string[] }[] };
}

export default function RisksPage() {
  const { fleet } = useCollector();
  const { role, subject } = useRole();
  const canMutate = role === 'admin';
  const searchParams = useSearchParams();
  const router = useRouter();

  const [tickets, setTickets] = useState<Ticket[]>([]);
  // 设备识别信息（用户反馈 2026-09-25：光看 device_id 哈希分辨不出是哪台机器）：
  // device_id → {serial, os_user, hostname, network}。IP/MAC 默认折叠，点开再看。
  const [deviceInfo, setDeviceInfo] = useState<Record<string, DeviceIdent>>({});
  const [netOpen, setNetOpen] = useState<Set<string>>(new Set());
  // 规模化分页（几千工单）：列表分页渲染。
  const [page, setPage] = useState(1);
  const PAGE_SIZE = 50;
  const [source, setSource] = useState<TicketSource>('loading');
  const [notice, setNotice] = useState('');
  const [refreshing, setRefreshing] = useState(false);
  const [filter, setFilter] = useState<FilterKey>('all');
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [showCreate, setShowCreate] = useState(false);
  const [pendingAction, setPendingAction] = useState<{
    id: string;
    status: TicketStatus;
  } | null>(null);
  // 不可逆 / 高影响动作（批量终态流转、批量拉黑、单工单终态流转）统一确认弹窗。
  const [riskConfirm, setRiskConfirm] = useState<RiskConfirm | null>(null);
  const [confirmBusy, setConfirmBusy] = useState(false);
  const [toast, setToast] = useState<{ text: string; tone: ToastTone } | null>(null);
  // P1：批量选择 / 详情抽屉 / 列表光标 / 本地搜索 / 快捷键（/ r f j/k Enter）
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [drawerTicket, setDrawerTicket] = useState<Ticket | null>(null);
  // D&R 闭环：抽屉打开时解析 工单→发现→资产→当前处置，暴露"检测了但未处置"的缺口。
  const [loopInfo, setLoopInfo] = useState<{
    asset_type?: string;
    asset_key?: string;
    disposition?: string;
    kind?: string;
    findingsTotal?: number;
    /** 按资产类型聚合的可处置资产清单（用户要求：汇总工单也要有具体的处置方式——
     *  哪个 skill、哪个 mcp、哪个代码路径，逐项直达处置）。 */
    perCategory?: Array<{ asset_type: 'skill' | 'mcp' | 'path'; keys: string[]; kinds: string[] }>;
    state: 'loading' | 'ready' | 'error';
    /** state==='error' 时的**可见**原因。此前 error 态在渲染层没有任何分支，
     *  会掉进"未匹配到发现"/"?个发现"，于是"读取失败"与"确实没有发现"渲染成
     *  同一句话——用户无法区分"系统没读到"和"一切正常无发现"（审计 #33 同类问题）。 */
    errorText?: string;
    /** 该设备被加白抑制而**未计入** findingsTotal 的发现数（端点回传 suppressed）。
     *  不显示它，"关联该设备全部 N 个发现"这句就是错的——N 是抑制后的数。 */
    suppressed?: number;
  } | null>(null);
  useEffect(() => {
    let alive = true;
    if (!drawerTicket) {
      setLoopInfo(null);
      return;
    }
    const t = drawerTicket;
    (async () => {
      // 无关联终端时不能拼出 /api/devices//findings 这种畸形 URL，也不能假装"无发现"。
      if (!t.device_id) {
        if (alive) setLoopInfo({ state: 'error', errorText: '该工单未关联终端，无法拉取其发现明细' });
        return;
      }
      try {
        setLoopInfo({ state: 'loading' });
        // P0-1 跨设备误封修复（同 runBatchLabel）：原先打的是 /api/findings 并附带一个
        // device_id 查询参数，但该路由从不读这个参数，返回的是最多 200 **台设备**的
        // 聚合发现，于是 findingsTotal 与 perCategory 都是对 200 台集合算的 ——
        // 抽屉里"关联该设备全部 N 个发现"是一句跨设备假关联。改用设备级端点后
        // N 才真的是这台设备的。
        // （注释刻意不写出完整的旧查询串，否则按该串做的复验 grep 会命中注释、
        //   把这个已修复的 P0 报成仍存在。）
        const fr = await fetch(`/api/devices/${encodeURIComponent(t.device_id)}/findings?limit=200`, { cache: 'no-store' });
        if (!fr.ok) {
          // 不再用 `fr.ok ? json : null` 把失败折叠成"空列表"：那样 503（Collector
          // 不可达）会渲染成"未匹配到发现"，与"确实没有发现"无法区分。
          if (alive) setLoopInfo({ state: 'error', errorText: `发现明细读取失败（HTTP ${fr.status}），无法确认关联资产` });
          return;
        }
        const fd = (await fr.json()) as { findings?: unknown; suppressed?: unknown };
        const findings = Array.isArray(fd?.findings) ? (fd.findings as Array<Record<string, unknown>>) : [];
        // 端点会剔除已加白的同源发现并回传计数；不带上它，"全部 N 个"就是错的。
        const suppressed = typeof fd?.suppressed === 'number' ? fd.suppressed : 0;
        // 匹配链只允许精确级：finding_ref 命中 → kind 命中。**禁止**按 severity 兜底——
        // 旧版第三级"取第一条同严重度发现"让每张设备级自动工单都关联到同一个随机
        // 发现（用户抓包质疑"所有工单关联的都是这个？"，属实是误导）。设备级汇总
        // 工单（source=aegis-collector.auto、无 finding_ref）就该诚实显示未关联单一资产。
        const match: Record<string, unknown> | null =
          (t.finding_ref
            ? findings.find((f) => `${String(f.kind)}:${(f.asset_key as string) || (f.path as string) || ''}` === t.finding_ref)
            : undefined)
          ?? findings.find((f) => f.kind === t.source)
          ?? null;
        const asset = match
          ? (findingAsset(match as never) ?? { asset_type: 'path' as const, asset_key: String(match.path ?? '') })
          : null;
        if (!asset) {
          if (alive) setLoopInfo({ state: 'ready', kind: String(match?.kind ?? ''), findingsTotal: findings.length, suppressed, perCategory: aggregateRemediable(findings) });
          return;
        }
        const lr = await fetch('/api/labels', { cache: 'no-store' });
        const ld = lr.ok ? ((await lr.json()) as { labels?: unknown }) : null;
        const labels = Array.isArray(ld?.labels) ? (ld.labels as Array<{ asset_type: string; asset_key: string; disposition?: string }>) : [];
        const lab = labels.find((l) => l.asset_type === asset.asset_type && l.asset_key === asset.asset_key);
        if (alive)
          setLoopInfo({
            state: 'ready',
            asset_type: asset.asset_type,
            asset_key: asset.asset_key,
            disposition: lab?.disposition,
            kind: String(match?.kind ?? ''),
            findingsTotal: findings.length,
            suppressed,
            perCategory: aggregateRemediable(findings),
          });
      } catch {
        if (alive) setLoopInfo({ state: 'error', errorText: '发现明细读取失败（网络错误），无法确认关联资产' });
      }
    })();
    return () => {
      alive = false;
    };
  }, [drawerTicket]);
  const [cursorIdx, setCursorIdx] = useState(0);
  const [query, setQuery] = useState('');
  // 统一筛选条（handoff P0）：等级 / 来源 / 终端 / 时间窗，与状态筛选 + 搜索叠加。
  const [sevFilter, setSevFilter] = useState<'all' | TicketSeverity>('all');
  const [sourceFilter, setSourceFilter] = useState('all');
  const [deviceFilter, setDeviceFilter] = useState('');
  const [timeFilter, setTimeFilter] = useState<'all' | '24h' | '7d' | '30d'>('all');
  const [slaOnly, setSlaOnly] = useState(false);
  const localSearchRef = useRef<HTMLInputElement>(null);
  const toastTimer = useRef<number | null>(null);

  const notify = useCallback((text: string, tone: ToastTone = 'info') => {
    setToast({ text, tone });
    if (toastTimer.current !== null) window.clearTimeout(toastTimer.current);
    toastTimer.current = window.setTimeout(() => setToast(null), 4_000);
  }, []);

  useEffect(
    () => () => {
      if (toastTimer.current !== null) window.clearTimeout(toastTimer.current);
    },
    [],
  );

  const loadTickets = useCallback(async (signal?: AbortSignal) => {
    const response = await fetch('/api/tickets', { cache: 'no-store', signal });
    const payload: unknown = await response.json().catch(() => null);
    if (!response.ok)
      throw new Error(describeError(payload, `工单接口返回 ${response.status}`));
    return parseTicketList(payload);
  }, []);

  /** 接口不可用：诚实进入 error 态，保留已有真实工单，绝不伪装成"已连接/已清空"。 */
  const applyFallback = useCallback((message: string) => {
    setNotice(message);
    setSource((prev) => (prev === 'api' ? 'api' : 'error'));
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    let active = true;
    void (async () => {
      try {
        const list = await loadTickets(controller.signal);
        if (!active) return;
        setTickets(list);
        setSource('api');
        setNotice('');
      } catch (error) {
        if (!active || isAbortError(error)) return;
        applyFallback(errorText(error));
      }
    })();
    return () => {
      active = false;
      controller.abort();
    };
  }, [applyFallback, loadTickets]);

  // 深链接：/risks?ticket=<id> 直接展开对应工单（来自总览/通知的闭环入口）。
  useEffect(() => {
    const t = searchParams.get('ticket');
    if (t) setExpandedId(t);
  }, [searchParams]);

  // 设备识别信息（序列号/用户/网络）：失败静默——工单行回落到仅 device_id，不阻塞。
  useEffect(() => {
    let alive = true;
    fetch('/api/devices', { cache: 'no-store' })
      .then((r) => (r.ok ? (r.json() as Promise<{ devices?: unknown[] }>) : null))
      .then((d) => {
        if (!alive || !Array.isArray(d?.devices)) return;
        const map: Record<string, DeviceIdent> = {};
        for (const x of d.devices as Array<Record<string, unknown>>) {
          map[String(x.device_id ?? '')] = {
            serial: String(x.serial ?? ''),
            os_user: String(x.os_user ?? ''),
            hostname: String(x.hostname ?? ''),
            network: (x.network as DeviceIdent['network']) ?? undefined,
          };
        }
        setDeviceInfo(map);
      })
      .catch(() => {});
    return () => {
      alive = false;
    };
  }, []);

  // 统一筛选条 URL 持久化（可分享 / 可收藏的研判视图）：挂载时从 query 恢复筛选，
  // 筛选变化时回写 query（保留 ticket/focus 等其它参数）。用 ref 读当前 params 以避免
  // replace→searchParams 变化→effect 重入 的循环。
  const searchParamsRef = useRef(searchParams);
  searchParamsRef.current = searchParams;
  const [urlReady, setUrlReady] = useState(false);
  useEffect(() => {
    if (urlReady) return;
    const sev = searchParams.get('sev');
    const src = searchParams.get('src');
    const dev = searchParams.get('dev');
    const win = searchParams.get('win');
    const sla = searchParams.get('sla');
    const q = searchParams.get('q');
    if (sev === 'critical' || sev === 'high' || sev === 'medium' || sev === 'low' || sev === 'info') setSevFilter(sev);
    if (src) setSourceFilter(src);
    if (dev) setDeviceFilter(dev);
    if (win === '24h' || win === '7d' || win === '30d') setTimeFilter(win);
    if (sla === '1') setSlaOnly(true);
    if (q) setQuery(q);
    setUrlReady(true);
  }, [searchParams, urlReady]);

  useEffect(() => {
    if (!urlReady) return;
    const p = new URLSearchParams(searchParamsRef.current.toString());
    const put = (key: string, value: string, def: string) => {
      if (value === def) p.delete(key);
      else p.set(key, value);
    };
    put('sev', sevFilter, 'all');
    put('src', sourceFilter, 'all');
    put('dev', deviceFilter, '');
    put('win', timeFilter, 'all');
    put('sla', slaOnly ? '1' : '', '');
    put('q', query, '');
    const qs = p.toString();
    router.replace(qs ? `?${qs}` : window.location.pathname, { scroll: false });
  }, [urlReady, sevFilter, sourceFilter, deviceFilter, timeFilter, slaOnly, query, router]);

  /** 写操作失败时的提示：实时模式下明确说明「没有真的改动」。 */
  const failureCopy = useCallback(
    (action: string, title: string, error: unknown) =>
      source === 'error'
        ? `提示：工单接口不可用，未${action}「${title}」。`
        : `${action}失败：${errorText(error)}`,
    [source],
  );

  async function refresh() {
    setRefreshing(true);
    try {
      const list = await loadTickets();
      setTickets(list);
      setSource('api');
      setNotice('');
      notify(`已刷新，共 ${list.length} 张工单。`, 'success');
    } catch (error) {
      applyFallback(errorText(error));
      notify(`刷新失败：${errorText(error)}`, 'error');
    } finally {
      setRefreshing(false);
    }
  }

  async function transition(ticket: Ticket, status: TicketStatus, note?: string) {
    if (pendingAction) return;
    setPendingAction({ id: ticket.ticket_id, status });
    try {
      const response = await fetch(
        `/api/tickets/${encodeURIComponent(ticket.ticket_id)}`,
        {
          method: 'PUT',
          headers: JSON_HEADERS,
          body: JSON.stringify({ status, ...(note ? { note } : {}) }),
        },
      );
      const payload: unknown = await response.json().catch(() => null);
      if (!response.ok)
        throw new Error(describeError(payload, `工单接口返回 ${response.status}`));
      const updated = parseTicket(pickRecord(payload, 'ticket'));
      if (updated) {
        setTickets((prev) =>
          prev.map((item) => (item.ticket_id === updated.ticket_id ? updated : item)),
        );
      } else {
        setTickets(await loadTickets());
      }
      setSource('api');
      notify(`工单 ${ticket.ticket_id} 已转为「${statusLabel(status)}」。`, 'success');
    } catch (error) {
      notify(failureCopy('流转', ticket.title, error), 'error');
    } finally {
      setPendingAction(null);
    }
  }

  async function remediate(ticket: Ticket, phase: 'recommend' | 'approve' | 'receipt', note: string) {
    try {
      const response = await fetch(
        `/api/tickets/${encodeURIComponent(ticket.ticket_id)}/remediation`,
        { method: 'POST', headers: JSON_HEADERS, body: JSON.stringify({ phase, note }) },
      );
      const payload: unknown = await response.json().catch(() => null);
      if (!response.ok)
        throw new Error(describeError(payload, `修复闭环接口返回 ${response.status}`));
      const updated = parseTicket(pickRecord(payload, 'ticket'));
      if (updated) {
        setTickets((prev) =>
          prev.map((item) => (item.ticket_id === updated.ticket_id ? updated : item)),
        );
      } else {
        setTickets(await loadTickets());
      }
      setSource('api');
      const label = phase === 'recommend' ? '修复建议' : phase === 'approve' ? '修复审批' : '执行回执';
      notify(`工单 ${ticket.ticket_id} 已记录${label}。`, 'success');
    } catch (error) {
      notify(failureCopy('记录修复闭环', ticket.title, error), 'error');
    }
  }

  async function createTicket(draft: TicketDraft) {
    try {
      const response = await fetch('/api/tickets', {
        method: 'POST',
        headers: JSON_HEADERS,
        body: JSON.stringify({
          title: draft.title,
          severity: draft.severity,
          source: draft.source,
          device_id: draft.device_id,
          ...(draft.description ? { description: draft.description } : {}),
        }),
      });
      const payload: unknown = await response.json().catch(() => null);
      if (!response.ok)
        throw new Error(describeError(payload, `工单接口返回 ${response.status}`));
      const created = parseTicket(pickRecord(payload, 'ticket'));
      if (created) {
        setTickets((prev) =>
          [...prev, created].sort(compareTickets),
        );
        setExpandedId(created.ticket_id);
      } else {
        setTickets(await loadTickets());
      }
      setSource('api');
      setNotice('');
      setShowCreate(false);
      setFilter('all');
      notify(`工单 ${created?.ticket_id ?? ''} 已创建，等待认领。`, 'success');
    } catch (error) {
      notify(failureCopy('创建工单', draft.title, error), 'error');
    }
  }

  /* ── 派生数据 ─────────────────────────────────────────── */

  const visibleTickets = useMemo(() => {
    const match = FILTERS.find((entry) => entry.key === filter)?.match ?? null;
    let list = match ? tickets.filter((ticket) => match.includes(ticket.status)) : tickets;
    if (sevFilter !== 'all') list = list.filter((t) => t.severity === sevFilter);
    if (sourceFilter !== 'all') list = list.filter((t) => (t.source ?? '') === sourceFilter);
    const dq = deviceFilter.trim().toLowerCase();
    if (dq) list = list.filter((t) => (t.device_id ?? '').toLowerCase().includes(dq));
    if (timeFilter !== 'all') {
      const hours = timeFilter === '24h' ? 24 : timeFilter === '7d' ? 168 : 720;
      const cutoff = Date.now() / 1000 - hours * 3600;
      list = list.filter((t) => Number(t.created_at ?? 0) >= cutoff);
    }
    if (slaOnly) list = list.filter(isSlaBreached);
    const q = query.trim().toLowerCase();
    if (!q) return list;
    return list.filter((t) =>
      [t.title, t.device_id, t.ticket_id, t.severity]
        .filter((x): x is string => typeof x === 'string')
        .join(' ')
        .toLowerCase()
        .includes(q),
    );
  }, [filter, tickets, query, sevFilter, sourceFilter, deviceFilter, timeFilter, slaOnly]);

  /** 来源选项由真实工单派生（不硬编码）。 */
  const sourceOptions = useMemo(() => {
    const set = new Set<string>();
    for (const t of tickets) if (t.source) set.add(t.source);
    return Array.from(set).sort();
  }, [tickets]);

  const hasActiveFilter =
    sevFilter !== 'all' || sourceFilter !== 'all' || deviceFilter.trim() !== '' || timeFilter !== 'all' || slaOnly;

  const filterCounts = useMemo(() => {
    const counts: Record<FilterKey, number> = {
      all: tickets.length,
      pending: 0,
      investigating: 0,
      resolved: 0,
    };
    for (const ticket of tickets) {
      if (ticket.status === 'open' || ticket.status === 'acknowledged')
        counts.pending += 1;
      else if (ticket.status === 'investigating') counts.investigating += 1;
      else counts.resolved += 1;
    }
    return counts;
  }, [tickets]);

  const highRiskOpen = tickets.filter(
    (ticket) =>
      (ticket.severity === 'critical' || ticket.severity === 'high') &&
      ticket.status !== 'resolved' &&
      ticket.status !== 'dismissed',
  ).length;


  /* ── P1 批量操作 + 快捷键 ───────────────────────────────── */
  const toggleSelect = (id: string) =>
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });

  async function batchTransition(status: TicketStatus) {
    // 终态流转（解决 / 驳回）不可逆，先经统一确认弹窗；其余状态直接执行。
    if (status === 'resolved' || status === 'dismissed') {
      setRiskConfirm({ kind: 'batchTransition', status });
      return;
    }
    await runBatchTransition(status);
  }

  async function runBatchTransition(status: TicketStatus) {
    for (const id of selected) {
      const t = tickets.find((x) => x.ticket_id === id);
      if (t) await transition(t, status);
    }
    setSelected(new Set());
  }

  /** 批量加白/观察/拉黑：对所选工单关联资产打处置标签；封禁需 admin + 二次确认（handoff P1）。 */
  async function batchLabel(disposition: 'allow' | 'monitor' | 'deny') {
    if (disposition === 'deny') {
      if (role !== 'admin') {
        notify('仅管理员可执行封禁/拉黑。', 'error');
        return;
      }
      // 拉黑会编译进签名策略下发终端 = 高影响动作，先经统一确认弹窗。
      setRiskConfirm({ kind: 'batchDeny' });
      return;
    }
    await runBatchLabel(disposition);
  }

  async function runBatchLabel(disposition: 'allow' | 'monitor' | 'deny') {
    const deviceIds = [...new Set(Array.from(selected, (id) => tickets.find((t) => t.ticket_id === id)?.device_id).filter((x): x is string => Boolean(x)))];
    // 窄类型保留：批量打标入口只处理具体资产（findingAsset 永不返回 prefix，
    // 断言收窄即可）；prefix 由处置中心单独管理。
    const assets = new Map<string, { asset_type: 'skill' | 'mcp' | 'path'; asset_key: string }>();
    // 逐设备失败必须可见：原先是 `if (!r.ok) continue;` + 空 catch，于是 Collector
    // 不可达时也会照样弹"已对 N 个资产执行拉黑"（N=0）——把失败伪装成成功。
    // 批量拉黑是破坏性操作，提示必须如实反映到底处置了什么、有什么没读到。
    const failedDevices: string[] = [];
    if (deviceIds.length === 0) {
      notify('所选工单没有关联终端，无法按设备聚合可处置资产。', 'info');
      return;
    }
    for (const did of deviceIds) {
      try {
        // P0-1 跨设备误封修复：原先打的是 /api/findings 并附带一个 device_id 查询参数，
        // 但该路由**从不读 device_id**——它只读 category / cursor / device_limit，
        // 且 limit 是 device_limit 的旧别名（每页设备数）。所以那次请求返回的是
        // 最多 200 **台设备**的跨设备聚合发现，而下面对返回值不做任何过滤就逐个
        // findingAsset 并写 deny ⇒ 勾选 1 台设备会污染最多 200 台的处置注册表。
        //
        // 改用设备级端点：服务端按 device_id 代理 collector /v1/findings，
        // 天然限定单设备，并含 allow 抑制与 suppressed 计数。
        // 该端点回传的是 collector **原始** finding 形状（无 /api/findings 那层
        // 富化出的 asset_type/asset_key/category），但本函数只依赖 findingAsset()，
        // 而 findingAsset 是从 kind/path/message 自行派生资产身份的，原始形状已足够
        // ——同文件的 LinkedFindings 早就在用同一端点 + 同一个 findingAsset(f)，
        // 故无需适配层。
        const r = await fetch(`/api/devices/${encodeURIComponent(did)}/findings?limit=200`, { cache: 'no-store' });
        if (!r.ok) {
          failedDevices.push(`${did}（HTTP ${r.status}）`);
          continue;
        }
        const d = (await r.json()) as { findings?: Array<Record<string, unknown>> };
        for (const f of d.findings ?? []) {
          const a = findingAsset(f as never);
          if (a && a.asset_type !== 'prefix') assets.set(`${a.asset_type}:${a.asset_key}`, { asset_type: a.asset_type as 'skill' | 'mcp' | 'path', asset_key: a.asset_key });
        }
      } catch {
        failedDevices.push(`${did}（网络错误）`);
      }
    }
    // 全部设备都读不到 → 没有任何依据可处置，绝不能报"成功"。
    if (failedDevices.length === deviceIds.length) {
      notify(`未能读取任何所选终端的发现（${failedDevices.length} 台全部失败：${failedDevices.slice(0, 3).join('、')}${failedDevices.length > 3 ? ' 等' : ''}），本次未执行任何处置。`, 'error');
      return;
    }
    const verb = disposition === 'allow' ? '加白' : disposition === 'monitor' ? '观察' : '拉黑';
    // 写入也要看结果：原先完全忽略 /api/labels 的响应，写失败同样会被报成成功。
    const writeFailed: string[] = [];
    for (const a of assets.values()) {
      try {
        const wr = await fetch('/api/labels', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ asset_type: a.asset_type, asset_key: a.asset_key, disposition }),
        });
        if (!wr.ok) writeFailed.push(`${a.asset_type}:${a.asset_key}（HTTP ${wr.status}）`);
      } catch {
        writeFailed.push(`${a.asset_type}:${a.asset_key}（网络错误）`);
      }
    }
    const scope = `（来自 ${deviceIds.length} 台所选终端）`;
    const caveats: string[] = [];
    if (failedDevices.length > 0) caveats.push(`${failedDevices.length} 台终端的发现读取失败，其资产未被处置：${failedDevices.slice(0, 3).join('、')}${failedDevices.length > 3 ? ' 等' : ''}`);
    if (writeFailed.length > 0) caveats.push(`${writeFailed.length} 个资产写入失败：${writeFailed.slice(0, 3).join('、')}${writeFailed.length > 3 ? ' 等' : ''}`);
    const okCount = assets.size - writeFailed.length;
    if (assets.size === 0 && caveats.length === 0) {
      notify(`所选 ${deviceIds.length} 台终端当前没有可处置的具体资产（无 skill/mcp/代码路径类发现，或均已被加白抑制）。`, 'info');
    } else if (caveats.length > 0) {
      notify(`已对 ${okCount} 个资产执行${verb}${scope}；但 ${caveats.join('；')}。`, 'error');
    } else {
      notify(`已对 ${assets.size} 个资产执行${verb}${scope}。`, 'success');
    }
    setSelected(new Set());
    void refresh();
  }

  /** 统一确认弹窗执行入口：批量终态 / 批量拉黑 / 单工单终态都在人工确认后由此分发。 */
  async function confirmRisk() {
    if (!riskConfirm || confirmBusy) return;
    setConfirmBusy(true);
    try {
      switch (riskConfirm.kind) {
        case 'batchTransition': await runBatchTransition(riskConfirm.status); break;
        case 'batchDeny': await runBatchLabel('deny'); break;
        case 'singleTransition':
          await transition(riskConfirm.ticket, riskConfirm.status);
          setDrawerTicket(null);
          break;
      }
      setRiskConfirm(null);
    } finally {
      setConfirmBusy(false);
    }
  }

  // 快捷键：/ 全局搜索、r 刷新、f 本页搜索、j/k 移动、Enter 开详情（handoff P1，含无障碍替代：均有可见按钮/输入框）。
  const refreshRef = useRef(refresh);
  refreshRef.current = refresh;
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const target = e.target as HTMLElement | null;
      if (target && (target.tagName === 'INPUT' || target.tagName === 'TEXTAREA' || target.tagName === 'SELECT' || target.isContentEditable)) return;
      const rows = paginate(visibleTickets, page, PAGE_SIZE).rows;
      if (e.key === '/') {
        e.preventDefault();
        (document.getElementById('global-search') as HTMLInputElement | null)?.focus();
      } else if (e.key === 'r') {
        e.preventDefault();
        void refreshRef.current();
      } else if (e.key === 'f') {
        e.preventDefault();
        localSearchRef.current?.focus();
      } else if (e.key === 'j') {
        e.preventDefault();
        setCursorIdx((c) => Math.min(c + 1, Math.max(rows.length - 1, 0)));
      } else if (e.key === 'k') {
        e.preventDefault();
        setCursorIdx((c) => Math.max(c - 1, 0));
      } else if (e.key === 'Enter') {
        const t = rows[cursorIdx];
        if (t) setDrawerTicket(t);
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [visibleTickets, page, cursorIdx]);

  /* ── 渲染 ─────────────────────────────────────────────── */

  const riskConfirmCopy = buildRiskConfirmCopy(riskConfirm, selected.size);

  return (
    <>
      

      <div className="page-head animate-entrance animate-entrance-1">
        <div>
          <p className="eyebrow">风险中心 / 待研判</p>
          <h1>风险中心</h1>
          <p>按风险等级与时间排序，认领后进入分级响应流程。</p>
        </div>
        <div className="head-actions" style={{ flexWrap: 'wrap' }}>
          {canMutate && (
            <>
              <Button
                variant="outline"
                title="到处置中心对涉事 Skill/MCP 加白·观察·拉黑，并发布签名策略下发终端"
                onClick={() => router.push('/dispositions')}
              >
                <ShieldAlert />
                处置高危资产
              </Button>
              <Button onClick={() => setShowCreate((prev) => !prev)}>
                {showCreate ? <X /> : <Plus />}
                {showCreate ? '收起表单' : '新建工单'}
              </Button>
            </>
          )}
        </div>
      </div>

      <RiskSignalHelp />

      {toast && (
        <div
          className="toast"
          role="status"
          style={
            toast.tone === 'error'
              ? { borderColor: 'var(--destructive)', color: 'var(--destructive)' }
              : undefined
          }
        >
          {toast.tone === 'error' ? (
            <AlertTriangle size={16} />
          ) : toast.tone === 'success' ? (
            <CircleCheck size={16} />
          ) : (
            <CircleDot size={16} />
          )}
          {toast.text}
        </div>
      )}

      <div className="detail-kpis">
        <article className="animate-entrance animate-entrance-1">
          <strong>{filterCounts.pending}</strong>
          <span>待处理工单</span>
          <small>共 {tickets.length} 张 · 需人工认领</small>
        </article>
        <article className="animate-entrance animate-entrance-2">
          <strong>{filterCounts.investigating}</strong>
          <span>调查中</span>
          <small>处理中 · 有人跟进</small>
        </article>
        <article className="animate-entrance animate-entrance-3">
          <strong>{highRiskOpen}</strong>
          <span>未闭环高危事件</span>
          <small>含严重 · 优先处置</small>
        </article>
      </div>

      {showCreate && (
        <div className="panel animate-entrance" style={{ marginBottom: 14 }}>
          <div className="panel-head">
            <div>
              <h2>新建风险工单</h2>
              <p>手工登记一起安全事件；工单编号、状态与时间线由服务端写入。</p>
            </div>
            <Button
              variant="ghost"
              size="icon-sm"
              aria-label="收起新建工单表单"
              onClick={() => setShowCreate(false)}
            >
              <X />
            </Button>
          </div>
          <CreateTicketForm onSubmit={createTicket} onCancel={() => setShowCreate(false)} />
        </div>
      )}

      <div className="panel">
        <div className="panel-head">
          <div>
            <h2>待研判事件</h2>
            <p>
              {source === 'loading'
                ? '正在读取工单队列…'
                : source === 'error'
                  ? `工单接口不可用：${notice || '无法读取队列'}（未展示工单不代表没有风险）`
                  : `${highRiskOpen} 个高危事件需要人工确认 · 共 ${tickets.length} 张工单`}
            </p>
            {fleet && (
              <p>
                接收器最新严重度：critical {fleet.latest_severity.critical} · high{' '}
                {fleet.latest_severity.high} · normal {fleet.latest_severity.normal}
              </p>
            )}
          </div>
          <Badge variant="outline">
            <span className={source === 'api' ? 'live-dot' : 'demo-dot'} />
            {source === 'api'
              ? '工单接口已连接'
              : source === 'error'
                ? '工单接口不可用'
                : '正在连接…'}
          </Badge>
        </div>

        <div
          style={{
            display: 'flex',
            flexWrap: 'wrap',
            alignItems: 'center',
            gap: 8,
            marginBottom: 14,
          }}
        >
          <Filter size={14} aria-hidden style={{ color: 'var(--muted-foreground)' }} />
          <input
            ref={localSearchRef}
            value={query}
            onChange={(e) => {
              setQuery(e.target.value);
              setPage(1);
            }}
            placeholder="搜索 标题 / 设备 / 工单号… (f)"
            aria-label="搜索工单"
            style={{ maxWidth: 220, padding: '6px 10px', borderRadius: 8, border: '1px solid var(--input)', background: 'var(--surface-2)', color: 'var(--foreground)', fontSize: 12 }}
          />
          {FILTERS.map((entry) => (
            <Button
              key={entry.key}
              size="sm"
              variant={filter === entry.key ? 'default' : 'outline'}
              aria-pressed={filter === entry.key}
              onClick={() => setFilter(entry.key)}
            >
              {entry.label}
              <span style={{ fontSize: 11, opacity: 0.75 }}>
                {filterCounts[entry.key]}
              </span>
            </Button>
          ))}
          <span style={{ flex: 1 }} />
          <Button
            variant="outline"
            size="sm"
            onClick={() => void refresh()}
            disabled={refreshing || source === 'loading'}
          >
            {refreshing ? <Spinner /> : <RefreshCw />}
            刷新
          </Button>
        </div>

        {/* 统一筛选条（handoff P0）：等级 / 来源 / 终端 / 时间窗，与状态 + 搜索叠加 */}
        <div
          role="toolbar"
          aria-label="工单统一筛选"
          style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center', marginBottom: 12 }}
        >
          <select
            className="form-input"
            style={{ width: 120, padding: '6px 8px', fontSize: 12 }}
            value={sevFilter}
            onChange={(e) => {
              setSevFilter(e.target.value as typeof sevFilter);
              setPage(1);
            }}
            aria-label="按严重度筛选"
          >
            <option value="all">全部等级</option>
            <option value="critical">严重</option>
            <option value="high">高危</option>
            <option value="medium">中危</option>
            <option value="low">低危</option>
            <option value="info">信息</option>
          </select>
          <select
            className="form-input"
            style={{ width: 150, padding: '6px 8px', fontSize: 12 }}
            value={sourceFilter}
            onChange={(e) => {
              setSourceFilter(e.target.value);
              setPage(1);
            }}
            aria-label="按来源筛选"
          >
            <option value="all">全部来源</option>
            {sourceOptions.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>
          <input
            className="form-input"
            style={{ width: 160, padding: '6px 8px', fontSize: 12 }}
            value={deviceFilter}
            onChange={(e) => {
              setDeviceFilter(e.target.value);
              setPage(1);
            }}
            placeholder="终端 ID 片段…"
            aria-label="按终端筛选"
          />
          <select
            className="form-input"
            style={{ width: 120, padding: '6px 8px', fontSize: 12 }}
            value={timeFilter}
            onChange={(e) => {
              setTimeFilter(e.target.value as typeof timeFilter);
              setPage(1);
            }}
            aria-label="按时间窗筛选"
          >
            <option value="all">全部时间</option>
            <option value="24h">近 24 小时</option>
            <option value="7d">近 7 天</option>
            <option value="30d">近 30 天</option>
          </select>
          <Button
            variant={slaOnly ? 'default' : 'outline'}
            size="sm"
            aria-pressed={slaOnly}
            onClick={() => {
              setSlaOnly((v) => !v);
              setPage(1);
            }}
            title="仅看超过分诊 SLA 仍未闭环的工单"
          >
            超 SLA
          </Button>
          {hasActiveFilter && (
            <Button
              variant="outline"
              size="sm"
              onClick={() => {
                setSevFilter('all');
                setSourceFilter('all');
                setDeviceFilter('');
                setTimeFilter('all');
                setSlaOnly(false);
                setPage(1);
              }}
            >
              清除筛选
            </Button>
          )}
          <span style={{ fontSize: 11, color: 'var(--muted-foreground)' }}>
            命中 {visibleTickets.length} / {tickets.length} 工单
          </span>
        </div>

        {selected.size > 0 && (
          <div className="batch-bar" role="toolbar" aria-label="批量操作">
            <span>已选 {selected.size} 项</span>
            <Button size="sm" variant="outline" onClick={() => void batchTransition('acknowledged')}>
              批量认领
            </Button>
            <Button size="sm" variant="outline" onClick={() => void batchTransition('investigating')}>
              批量观察
            </Button>
            <Button size="sm" variant="outline" onClick={() => void batchLabel('allow')}>
              批量加白
            </Button>
            <Button size="sm" variant="outline" onClick={() => void batchLabel('monitor')}>
              资产观察
            </Button>
            <Button
              size="sm"
              variant="outline"
              style={{ color: 'var(--sentinel-danger)', borderColor: 'color-mix(in srgb, var(--sentinel-danger) 50%, transparent)' }}
              onClick={() => void batchLabel('deny')}
            >
              批量封禁（需确认）
            </Button>
            <Button size="sm" variant="outline" onClick={() => setSelected(new Set())}>
              清除选择
            </Button>
          </div>
        )}

        <div className="risk-table">
          {source === 'loading' && <LoadingState label="加载工单…" />}

          {paginate(visibleTickets, page, PAGE_SIZE).rows.map((ticket, index) => {
            const severity = severityMeta(ticket.severity);
            const transitions = ticketTransitions(ticket.status);
            const expanded = expandedId === ticket.ticket_id;
            const busy = pendingAction?.id === ticket.ticket_id;
            // 已闭环（已解决/已驳回）属于历史处置记录：严重度徽章中性化、整行降调，
            // 避免把已处置事件继续以红/橙示警、误读为当前活跃威胁。
            const closed = ticket.status === 'resolved' || ticket.status === 'dismissed';
            return (
              <Fragment key={ticket.ticket_id}>
                <div
                  className={`risk-row wide animate-row-entrance${closed ? ' closed' : ''}`}
                  style={{
                    animationDelay: `${index * 30 + 200}ms`,
                    gridTemplateColumns: TICKET_ROW_GRID,
                    cursor: 'pointer',
                    outline: index === cursorIdx ? '1px solid var(--sentinel-cyan)' : undefined,
                    outlineOffset: -1,
                  }}
                  role="button"
                  tabIndex={0}
                  aria-label={`打开工单 ${ticket.ticket_id} 详情`}
                  onClick={() => setDrawerTicket(ticket)}
                  onKeyDown={(e) => {
                    // 行内还嵌有复选框、「查看发现」链接与 IP/MAC 折叠按钮：焦点落在这些
                    // 控件上时不得拦截按键，否则 Space/Enter 会冒泡到行、既打开抽屉又
                    // preventDefault 掉控件自身行为（复选框选不上、链接跳不走）。
                    // 写法对齐 components/scan-explorer.tsx 的可点击行，并加目标守卫。
                    if (e.target !== e.currentTarget) return;
                    if (e.key === 'Enter' || e.key === ' ') {
                      e.preventDefault();
                      setDrawerTicket(ticket);
                    }
                  }}
                >
                  <label style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
                    <input
                      type="checkbox"
                      checked={selected.has(ticket.ticket_id)}
                      onChange={() => toggleSelect(ticket.ticket_id)}
                      onClick={(e) => e.stopPropagation()}
                      aria-label={`选择工单 ${ticket.ticket_id}`}
                    />
                  </label>
                  <span
                    className={`severity ${closed ? 'closed' : severity.tone}`}
                    style={closed ? undefined : severityStyle(ticket.severity)}
                    title={
                      closed
                        ? `已${statusLabel(ticket.status)} · 严重等级仅作历史记录：${severity.hint}`
                        : `严重等级：${severity.hint}`
                    }
                  >
                    {severity.label}
                  </span>
                  <div className="risk-main">
                    <strong>{ticket.title}</strong>
                    <span>
                      {ticket.source} · {ticket.ticket_id}
                    </span>
                    <span style={statusBadgeStyle(ticket.status)}>
                      {statusLabel(ticket.status)}
                      {ticket.assignee ? ` · ${ticket.assignee}` : ''}
                    </span>
                    {isSlaBreached(ticket) && (
                      <i className="warn" style={{ fontSize: 10, marginLeft: 6 }} title="超过分诊 SLA 仍未闭环">
                        超SLA
                      </i>
                    )}
                  </div>
                  <span className="device" style={{ display: 'flex', flexDirection: 'column', gap: 3, alignItems: 'flex-start' }}>
                    {ticket.device_id ? (
                      <>
                        {/* 设备识别（用户反馈 2026-09-25 二次修正）：主机名优先（序列号不直观），
                            悬停可见 序列号/device_id；无主机名回落序列号，再回落 device_id */}
                        <span style={{ display: 'flex', gap: 6, alignItems: 'center', flexWrap: 'wrap' }}>
                          <strong
                            style={{ fontFamily: 'var(--sentinel-font-mono)' }}
                            title={[
                              deviceInfo[ticket.device_id]?.hostname ? `主机名: ${deviceInfo[ticket.device_id].hostname}` : '',
                              deviceInfo[ticket.device_id]?.serial ? `序列号: ${deviceInfo[ticket.device_id].serial}` : '',
                              `device_id: ${ticket.device_id}`,
                            ].filter(Boolean).join('\n')}
                          >
                            {deviceInfo[ticket.device_id]?.hostname
                              || deviceInfo[ticket.device_id]?.serial
                              || ticket.device_id}
                          </strong>
                          {deviceInfo[ticket.device_id]?.os_user && (
                            <i className="handle" style={{ color: 'var(--muted-foreground)' }}>
                              {deviceInfo[ticket.device_id].os_user}
                            </i>
                          )}
                          <Link
                            href={`/devices?focus=${encodeURIComponent(ticket.device_id)}`}
                            title="跳到该设备并展开其发现/封禁回执"
                            style={{ fontSize: 11, color: 'var(--ring)' }}
                          >
                            查看发现
                          </Link>
                        </span>
                        {/* IP/MAC 默认折叠（MAC 属敏感指纹，按需展开） */}
                        <button
                          type="button"
                          className="handle"
                          aria-expanded={netOpen.has(ticket.ticket_id)}
                          onClick={(e) => {
                            e.stopPropagation();
                            setNetOpen((m) => {
                              const n = new Set(m);
                              const wasOpen = n.has(ticket.ticket_id);
                              n.clear();
                              for (const x of m) if (x !== ticket.ticket_id) n.add(x);
                              if (!wasOpen) n.add(ticket.ticket_id);
                              return n;
                            });
                          }}
                          style={{ background: 'none', border: 'none', padding: 0, cursor: 'pointer', fontSize: 10, color: 'var(--muted-foreground)', display: 'inline-flex', alignItems: 'center', gap: 4 }}
                        >
                          {/* 折叠指示符统一走 lucide（此前是 U+25BE/U+25B8 文本三角，且与
                              risk-signal-help 的方向约定相反）。方向语义全站锁定：展开=朝上、
                              收起=朝下，用 ChevronDown + rotate(180deg) 实现，与本文件下方
                              工单详情展开按钮（aria-expanded 那颗）写法完全一致。 */}
                          <ChevronDown
                            size={12}
                            style={{
                              transform: netOpen.has(ticket.ticket_id) ? 'rotate(180deg)' : 'none',
                              transition: 'transform 0.2s ease',
                            }}
                          />
                          {netOpen.has(ticket.ticket_id) ? '收起 IP/MAC' : 'IP / MAC'}
                        </button>
                        {netOpen.has(ticket.ticket_id) && (
                          <span style={{ fontSize: 10, fontFamily: 'var(--sentinel-font-mono)', color: 'var(--muted-foreground)', lineHeight: 1.5 }}>
                            {(() => {
                              const n = deviceInfo[ticket.device_id]?.network;
                              const rows: string[] = [];
                              if (n?.egress_ip) rows.push(`出口 IP ${n.egress_ip}`);
                              if (n?.local_ips?.length) rows.push(`内网 IP ${n.local_ips.join(' / ')}`);
                              const macs = n?.physical_nics?.length
                                ? n.physical_nics.map((nic) => `${nic.name}:${nic.mac}`).join(', ')
                                : n?.macs?.join(', ');
                              if (macs) rows.push(`MAC ${macs}`);
                              return rows.length ? rows.join('\\n') : '（该终端未上报网络信息）';
                            })().split('\\n').map((line) => (
                              <span key={line} style={{ display: 'block' }}>{line}</span>
                            ))}
                          </span>
                        )}
                      </>
                    ) : (
                      '未关联'
                    )}
                  </span>
                  <span className="time" title={`更新于 ${formatRelativeTime(ticket.updated_at)}`}>
                    {formatRelativeTime(ticket.updated_at)}
                  </span>
                  <div
                    style={{
                      display: 'flex',
                      flexWrap: 'wrap',
                      justifyContent: 'flex-end',
                      gap: 6,
                    }}
                    onClick={(event) => event.stopPropagation()}
                  >
                    {canMutate &&
                      transitions.map((transition) => (
                        <button
                          key={transition.status}
                          className="handle"
                          style={{
                            ...handleStyle,
                            opacity: busy ? 0.55 : 1,
                            cursor: busy ? 'progress' : 'pointer',
                          }}
                          disabled={Boolean(pendingAction)}
                          onClick={() => void runTransition(ticket, transition.status)}
                        >
                          {busy && pendingAction?.status === transition.status
                            ? '处理中…'
                            : transition.label}
                        </button>
                      ))}
                    <button
                      className="handle"
                      style={handleStyle}
                      aria-expanded={expanded}
                      aria-label={expanded ? '收起工单详情' : '展开工单详情'}
                      onClick={() => setExpandedId(expanded ? null : ticket.ticket_id)}
                    >
                      <ChevronDown
                        size={12}
                        style={{
                          transform: expanded ? 'rotate(180deg)' : 'none',
                          transition: 'transform 0.2s ease',
                        }}
                      />
                    </button>
                  </div>
                </div>

                {expanded && (
                  <div className="animate-entrance" style={inlinePanelStyle}>
                    <TicketDetail
                      ticket={ticket}
                      onAction={(status, note) => transition(ticket, status, note)}
                      onClose={() => setExpandedId(null)}
                      canMutate={canMutate}
                      onRemediation={(phase, note) => remediate(ticket, phase, note)}
                    />
                    {ticket.device_id && <LinkedFindings deviceId={ticket.device_id} />}
                  </div>
                )}
              </Fragment>
            );
          })}
        </div>

        <Pagination
          page={page}
          pageCount={Math.max(1, Math.ceil(visibleTickets.length / PAGE_SIZE))}
          onPage={setPage}
          total={visibleTickets.length}
          pageSize={PAGE_SIZE}
        />

        {source === 'error' && visibleTickets.length === 0 && (
          <ErrorState label={notice || '工单接口不可用'} onRetry={() => void refresh()} />
        )}

        {source !== 'loading' && source !== 'error' && visibleTickets.length === 0 && (
          <EmptyState
            label={filter === 'all' ? '队列已清空' : '当前筛选下没有工单'}
            hint={
              filter === 'all'
                ? '没有待研判的风险事件；新的上报会自动进入该队列。'
                : '切换其他状态标签，或点击右上角「新建工单」手工登记一起事件。'
            }
          />
        )}

        <div className="flow">
          <span>终端上报</span>
          <b>→</b>
          <span>安全运营认领</span>
          <b>→</b>
          <span>厂商 EDR 隔离</span>
          <b>→</b>
          <span>基线复核</span>
          <b>→</b>
          <span className="safe">
            <ShieldCheck size={15} />
            工单关闭
          </span>
        </div>
      </div>

      {/* P1 右侧详情抽屉：发现 → 资产 → 规则信号 → 建议动作 → 审计记录 */}
      <DetailDrawer
        open={drawerTicket !== null}
        onClose={() => setDrawerTicket(null)}
        title={drawerTicket?.title ?? ''}
        subtitle={drawerTicket ? `${drawerTicket.ticket_id} · ${statusLabel(drawerTicket.status)}` : undefined}
        sections={
          drawerTicket
            ? ([
                {
                  label: '发现',
                  content: (
                    <div>
                      <div className="kv">
                        <span>严重度</span>
                        <span>{drawerTicket.severity}</span>
                      </div>
                      <div className="kv">
                        <span>状态</span>
                        <span>{statusLabel(drawerTicket.status)}</span>
                      </div>
                      <p style={{ marginTop: 6, color: 'var(--muted-foreground)' }}>{drawerTicket.description}</p>
                    </div>
                  ),
                },
                {
                  label: '资产',
                  content: (
                    // 2026-09-25 用户三轮反馈：kv 两列布局把多值 IP/MAC 挤成横向滚动
                    // （"要向右拉滑块，失去页面便利性"）→ 改纵向信息卡：标签一行、值自然换行。
                    <div className="device-ident">
                      <div className="device-ident-row">
                        <span className="device-ident-label">终端</span>
                        <span className="device-ident-value">
                          {drawerTicket.device_id
                            && (deviceInfo[drawerTicket.device_id]?.hostname
                              || deviceInfo[drawerTicket.device_id]?.serial
                              || drawerTicket.device_id)}
                          {drawerTicket.device_id && deviceInfo[drawerTicket.device_id]?.os_user
                            ? ` · ${deviceInfo[drawerTicket.device_id].os_user}`
                            : ''}
                        </span>
                      </div>
                      <div className="device-ident-row">
                        <span className="device-ident-label">序列号</span>
                        <span className="device-ident-value">
                          {(drawerTicket.device_id && deviceInfo[drawerTicket.device_id]?.serial) || '—'}
                        </span>
                      </div>
                      <div className="device-ident-row">
                        <span className="device-ident-label">互联网 IP</span>
                        <span className="device-ident-value">
                          {(drawerTicket.device_id && deviceInfo[drawerTicket.device_id]?.network?.egress_ip) || '—'}
                        </span>
                      </div>
                      <div className="device-ident-row">
                        <span className="device-ident-label">本地 IP</span>
                        <span className="device-ident-value">
                          {(drawerTicket.device_id && deviceInfo[drawerTicket.device_id]?.network?.local_ips?.join(' / ')) || '—'}
                        </span>
                      </div>
                      <div className="device-ident-row">
                        <span className="device-ident-label">MAC</span>
                        <span className="device-ident-value">
                          {(drawerTicket.device_id
                            && (deviceInfo[drawerTicket.device_id]?.network?.physical_nics?.length
                              ? deviceInfo[drawerTicket.device_id].network?.physical_nics?.map((nic) => `${nic.name}: ${nic.mac}`).join('、')
                              : deviceInfo[drawerTicket.device_id]?.network?.macs?.join('、')))
                            || '—'}
                        </span>
                      </div>
                    </div>
                  ),
                },
                {
                  label: '规则信号',
                  content: (
                    <div className="kv">
                      <span>发现引用</span>
                      <span style={{ fontFamily: 'var(--sentinel-font-mono)' }}>{drawerTicket.finding_ref || '—'}</span>
                    </div>
                  ),
                },
                {
                  label: '建议动作',
                  content: (
                    <div>
                      {ticketTransitions(drawerTicket.status).map((tr) => (
                        <button
                          key={tr.status}
                          type="button"
                          className="sentinel-button"
                          style={{ marginRight: 6, marginBottom: 6 }}
                          onClick={() => {
                            if (tr.status === 'resolved' || tr.status === 'dismissed') {
                              // 终态不可逆：打开统一确认弹窗，保留抽屉上下文，确认后再流转。
                              setRiskConfirm({ kind: 'singleTransition', ticket: drawerTicket, status: tr.status });
                            } else {
                              void transition(drawerTicket, tr.status);
                              setDrawerTicket(null);
                            }
                          }}
                        >
                          {tr.label}
                        </button>
                      ))}
                    </div>
                  ),
                },
                {
                  label: '响应 Playbook',
                  content: (
                    <ol style={{ margin: 0, paddingLeft: 18, display: 'grid', gap: 6, fontSize: 12, color: 'var(--muted-foreground)' }}>
                      {buildResponsePlaybook(drawerTicket).map((s, i) => (
                        <li key={i}>
                          {s.href ? (
                            <Link
                              href={s.href}
                              style={{ color: 'var(--ring)', textDecoration: 'none', borderBottom: '1px dashed currentColor' }}
                              title="跳转到对应控制台能力"
                            >
                              {s.text}
                            </Link>
                          ) : (
                            s.text
                          )}
                        </li>
                      ))}
                    </ol>
                  ),
                },
                {
                  label: '响应闭环',
                  content: (
                    <div className="kv">
                      <span>检测规则</span>
                      <span style={{ fontFamily: 'var(--sentinel-font-mono)' }}>{loopInfo?.kind || drawerTicket.source || '—'}</span>
                      <span>关联资产</span>
                      <span style={{ fontFamily: 'var(--sentinel-font-mono)', wordBreak: 'break-all' }}>
                        {loopInfo?.state === 'loading'
                          ? '解析中…'
                          : loopInfo?.state === 'error'
                            // 读取失败必须与"确实没有发现"可区分：此前 error 态无渲染分支，
                            // 会掉进下面两支，把失败说成"未匹配到发现"/"? 个发现"。
                            ? <span style={{ color: 'var(--sentinel-danger)' }}>{loopInfo.errorText ?? '发现明细读取失败'}</span>
                            : loopInfo?.asset_key
                              ? `${loopInfo.asset_type}:${loopInfo.asset_key}`
                              : drawerTicket.source === 'aegis-collector.auto'
                                ? <>设备级汇总工单：关联该设备全部 {loopInfo?.findingsTotal ?? '?'} 个发现
                                  {(loopInfo?.suppressed ?? 0) > 0 ? `（另有 ${loopInfo?.suppressed ?? 0} 个已加白抑制，未计入）` : ''}
                                  ，未锁定单一资产（
                                  <Link href={`/devices?focus=${encodeURIComponent(drawerTicket.device_id)}`} style={{ color: 'var(--ring)', textDecoration: 'none', borderBottom: '1px dashed currentColor' }}>
                                    点此查看该设备发现明细
                                  </Link>
                                  ，或按下方资产分类逐项处置）</>
                                : '未匹配到发现'}
                      </span>
                      <span>当前处置</span>
                      <span>
                        {loopInfo?.state === 'loading' ? (
                          '解析中…'
                        ) : loopInfo?.disposition ? (
                          <i className={loopInfo.disposition === 'deny' ? 'fail' : loopInfo.disposition === 'monitor' ? 'warn' : 'pass'} style={{ fontSize: 10 }}>
                            {loopInfo.disposition === 'deny' ? '拉黑' : loopInfo.disposition === 'monitor' ? '观察' : '加白'}
                          </i>
                        ) : loopInfo?.asset_key ? (
                          <i className="warn" style={{ fontSize: 10 }}>未处置（检测未闭环）</i>
                        ) : (
                          '—'
                        )}
                      </span>
                      {loopInfo?.asset_key && (
                        <>
                          <span>去处置</span>
                          <span>
                            <Link
                              href={`/dispositions?type=${encodeURIComponent(loopInfo.asset_type ?? 'path')}&asset=${encodeURIComponent(loopInfo.asset_key)}`}
                              style={{ color: 'var(--ring)', textDecoration: 'none', borderBottom: '1px dashed currentColor', fontSize: 12 }}
                            >
                              在处置中心打开该资产
                            </Link>
                          </span>
                        </>
                      )}
                    </div>
                  ),
                },
                {
                  // 资产处置入口（2026-09-25 用户要求："哪个 skill、哪个 mcp、哪个代码
                  // 都应该有相应的处置"）：按发现分类聚合，每类一卡，逐项直达处置中心。
                  label: '资产处置入口',
                  content: loopInfo?.perCategory && loopInfo.perCategory.length > 0 ? (
                    <div className="device-ident">
                      {loopInfo.perCategory.map((cat) => (
                        <div key={cat.asset_type} className="device-ident-row">
                          <span className="device-ident-label">
                            {cat.asset_type === 'skill' ? 'Skill' : cat.asset_type === 'mcp' ? 'MCP' : '代码路径'} · {cat.keys.length} 项可处置（规则：{cat.kinds.slice(0, 4).join('、')}{cat.kinds.length > 4 ? ' 等' : ''}）
                          </span>
                          <span className="device-ident-value" style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
                            {cat.keys.slice(0, 30).map((k) => (
                              <span key={k} style={{ display: 'flex', gap: 6, alignItems: 'baseline', flexWrap: 'wrap' }}>
                                {/* 截断保留扩展名：长路径中段省略但后缀可见，用户能分辨资产类型 */}
                                <span style={{ wordBreak: 'break-all' }}>{k.length > 80 ? k.slice(0, 72) + '…' + k.slice(k.lastIndexOf('.')) : k}</span>
                                <Link
                                  href={`/dispositions?type=${cat.asset_type}&asset=${encodeURIComponent(k)}`}
                                  style={{ color: 'var(--ring)', textDecoration: 'none', borderBottom: '1px dashed currentColor', fontSize: 11, flexShrink: 0 }}
                                >
                                  去处置 →
                                </Link>
                                {cat.asset_type === 'path' && (
                                  <Link
                                    href={`/dispositions?type=prefix&asset=${encodeURIComponent(k.slice(0, k.lastIndexOf('/') + 1))}`}
                                    title="按目录前缀批量忽略：该目录下全部文件的发现不再出现在告警与处置面（可随时删除前缀恢复）"
                                    style={{ color: 'var(--muted-foreground)', textDecoration: 'none', borderBottom: '1px dashed currentColor', fontSize: 11, flexShrink: 0 }}
                                  >
                                    忽略此目录
                                  </Link>
                                )}
                              </span>
                            ))}
                            {cat.keys.length > 30 && <span>…另有 {cat.keys.length - 30} 项，点上方「查看该设备发现明细」</span>}
                          </span>
                        </div>
                      ))}
                    </div>
                  ) : loopInfo?.state === 'loading' ? (
                    <p style={{ fontSize: 12, color: 'var(--muted-foreground)', margin: 0 }}>解析该终端的发现中…</p>
                  ) : loopInfo?.state === 'error' ? (
                    // 此前这一支被并进了"无可处置资产"，于是加载失败 / Collector 不可达
                    // 都被说成"该工单无可处置资产"——把"没读到"伪装成"读到了、确实没有"。
                    <p style={{ fontSize: 12, color: 'var(--sentinel-danger)', margin: 0 }}>
                      {loopInfo.errorText ?? '发现明细读取失败'}；因此无法判断是否存在可处置资产（不等于"没有"）。
                    </p>
                  ) : (
                    <p style={{ fontSize: 12, color: 'var(--muted-foreground)', margin: 0 }}>该工单无可处置资产（发现均无资产归属）。</p>
                  ),
                },
                {
                  label: '审计记录',
                  content: (
                    <div>
                      {(drawerTicket.history ?? []).slice(-6).map((h, i) => (
                        <div key={i} className="kv">
                          <span>{h.action}</span>
                          <span>
                            {h.actor ?? ''} {formatRelativeTime(h.at as never)}
                          </span>
                        </div>
                      ))}
                    </div>
                  ),
                },
              ] as DrawerSection[])
            : []
        }
      />

      <ActionConfirmDialog
        open={riskConfirm !== null}
        onOpenChange={(open) => {
          if (!open && !confirmBusy) setRiskConfirm(null);
        }}
        title={riskConfirmCopy?.title ?? ''}
        description={riskConfirmCopy?.description}
        impact={riskConfirmCopy?.impact}
        rollback={riskConfirmCopy?.rollback}
        operator={subject || '当前登录用户'}
        variant={riskConfirmCopy?.variant ?? 'default'}
        confirmLabel={riskConfirmCopy?.confirmLabel ?? '确认执行'}
        busy={confirmBusy}
        onConfirm={() => void confirmRisk()}
      />
    </>
  );

  /** 行内动作与详情面板共用同一个流转入口。终态流转(解决/驳回)不可逆，先经统一确认弹窗。 */
  function runTransition(ticket: Ticket, status: TicketStatus) {
    if (status === 'resolved' || status === 'dismissed') {
      setRiskConfirm({ kind: 'singleTransition', ticket, status });
      return Promise.resolve();
    }
    return transition(ticket, status);
  }
}

/* ─── 新建工单表单 ───────────────────────────────────────── */

export type TicketDraft = {
  title: string;
  severity: TicketSeverity;
  source: string;
  device_id: string;
  description: string;
};

const DEVICE_ID_PATTERN = /^[A-Za-z0-9-]{3,64}$/;

const rowStyle = { gap: 12, flexWrap: 'wrap' } as const;
const controlStyle = { width: 300, maxWidth: '100%', flexShrink: 0 } as const;
const errorStyle = { color: 'var(--destructive)', fontSize: 11 } as const;

type DraftErrors = Partial<Record<'title' | 'source' | 'device_id', string>>;

function validateDraft(draft: TicketDraft): DraftErrors {
  const errors: DraftErrors = {};
  if (!draft.title.trim()) errors.title = '标题为必填项';
  else if (draft.title.trim().length > 200) errors.title = '标题最多 200 字符';
  if (!draft.source.trim()) errors.source = '来源为必填项';
  const deviceId = draft.device_id.trim();
  if (!deviceId) errors.device_id = '设备 ID 为必填项';
  else if (!DEVICE_ID_PATTERN.test(deviceId))
    errors.device_id = '设备 ID 需为 3 至 64 位字母、数字或连字符';
  return errors;
}

function CreateTicketForm({
  onSubmit,
  onCancel,
}: {
  onSubmit: (draft: TicketDraft) => Promise<void>;
  onCancel: () => void;
}) {
  const [draft, setDraft] = useState<TicketDraft>({
    title: '',
    severity: 'high',
    source: '',
    device_id: '',
    description: '',
  });
  const [errors, setErrors] = useState<DraftErrors>({});
  const [submitting, setSubmitting] = useState(false);

  function patch(values: Partial<TicketDraft>) {
    setDraft((prev) => ({ ...prev, ...values }));
  }

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (submitting) return;
    const nextErrors = validateDraft(draft);
    setErrors(nextErrors);
    if (Object.keys(nextErrors).length > 0) return;
    setSubmitting(true);
    try {
      await onSubmit({
        title: draft.title.trim(),
        severity: draft.severity,
        source: draft.source.trim(),
        device_id: draft.device_id.trim(),
        description: draft.description.trim(),
      });
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <form className="animate-entrance" onSubmit={handleSubmit} noValidate>
      <div className="setting-row" style={rowStyle}>
        <div>
          <strong>
            <Label htmlFor="ticket-title">标题</Label>
          </strong>
          <span>一句话描述事件，最多 200 字符</span>
          {errors.title && (
            <span role="alert" style={errorStyle}>
              {errors.title}
            </span>
          )}
        </div>
        <Input
          id="ticket-title"
          value={draft.title}
          onChange={(event) => patch({ title: event.target.value })}
          placeholder="MCP Server 请求了未授权文件目录"
          autoComplete="off"
          disabled={submitting}
          required
          aria-invalid={Boolean(errors.title)}
          style={controlStyle}
        />
      </div>

      <div className="setting-row" style={rowStyle}>
        <div>
          <strong>
            <Label htmlFor="ticket-severity">严重等级</Label>
          </strong>
          <span>决定队列排序，高危事件优先展示</span>
        </div>
        <NativeSelect
          id="ticket-severity"
          value={draft.severity}
          onChange={(event) => {
            const value = event.target.value;
            const matched = SEVERITY_OPTIONS.find((option) => option.value === value);
            patch({ severity: matched ? matched.value : 'high' });
          }}
          disabled={submitting}
          style={controlStyle}
        >
          {SEVERITY_OPTIONS.map((option) => (
            <NativeSelectOption key={option.value} value={option.value}>
              {option.label}
            </NativeSelectOption>
          ))}
        </NativeSelect>
      </div>

      <div className="setting-row" style={rowStyle}>
        <div>
          <strong>
            <Label htmlFor="ticket-source">来源</Label>
          </strong>
          <span>触发该事件的检测器、Skill 或仓库路径</span>
          {errors.source && (
            <span role="alert" style={errorStyle}>
              {errors.source}
            </span>
          )}
        </div>
        <Input
          id="ticket-source"
          value={draft.source}
          onChange={(event) => patch({ source: event.target.value })}
          placeholder="cursor-mcp-filesystem"
          autoComplete="off"
          disabled={submitting}
          required
          aria-invalid={Boolean(errors.source)}
          style={controlStyle}
        />
      </div>

      <div className="setting-row" style={rowStyle}>
        <div>
          <strong>
            <Label htmlFor="ticket-device">设备 ID</Label>
          </strong>
          <span>关联终端；允许填写尚未注册的 device_id</span>
          {errors.device_id && (
            <span role="alert" style={errorStyle}>
              {errors.device_id}
            </span>
          )}
        </div>
        <Input
          id="ticket-device"
          value={draft.device_id}
          onChange={(event) => patch({ device_id: event.target.value })}
          placeholder="终端设备 ID（可选）"
          autoComplete="off"
          spellCheck={false}
          disabled={submitting}
          required
          aria-invalid={Boolean(errors.device_id)}
          style={controlStyle}
        />
      </div>

      <div className="setting-row" style={rowStyle}>
        <div>
          <strong>
            <Label htmlFor="ticket-description">描述</Label>
          </strong>
          <span>可选，最多 4000 字符，用于记录研判上下文</span>
        </div>
        <Textarea
          id="ticket-description"
          value={draft.description}
          onChange={(event) => patch({ description: event.target.value })}
          placeholder="事件经过、影响范围与已采取的措施"
          maxLength={4000}
          disabled={submitting}
          style={{ ...controlStyle, width: 340 }}
        />
      </div>

      <div
        style={{
          display: 'flex',
          flexWrap: 'wrap',
          gap: 10,
          justifyContent: 'flex-end',
          paddingTop: 16,
        }}
      >
        <Button
          type="button"
          variant="outline"
          onClick={onCancel}
          disabled={submitting}
        >
          <X />
          取消
        </Button>
        <Button type="submit" disabled={submitting}>
          {submitting ? <Spinner /> : <Plus />}
          {submitting ? '创建中…' : '创建工单'}
        </Button>
      </div>
    </form>
  );
}

/** 关联发现：按 device_id 拉取该设备最新报告的 critical/high 发现明细。 */
function LinkedFindings({ deviceId }: { deviceId: string }) {
  const [findings, setFindings] = useState<Array<Record<string, unknown>> | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    fetch(`/api/devices/${encodeURIComponent(deviceId)}/findings?limit=200`, { cache: 'no-store' })
      .then((r) => (r.ok ? r.json() : null))
      .then((d: any) => {
        if (cancelled) return;
        const all = (d?.findings ?? []) as Array<Record<string, unknown>>;
        setFindings(all.filter((f) => f.severity === 'critical' || f.severity === 'high'));
      })
      .catch(() => !cancelled && setFindings([]))
      .finally(() => !cancelled && setLoading(false));
    return () => {
      cancelled = true;
    };
  }, [deviceId]);

  return (
    <div style={{ marginTop: 16 }}>
      <h4 style={{ fontSize: 13, margin: '0 0 10px' }}>关联发现（critical/high 明细）</h4>
      {loading ? (
        <p style={{ fontSize: 12, color: 'var(--muted-foreground)' }}>加载发现明细…</p>
      ) : findings && findings.length > 0 ? (
        <div className="data-table">
          <div className="data-head">
            <span>等级</span><span>类型</span><span>路径</span><span>说明</span>
          </div>
          {findings.slice(0, 100).map((f, i) => (
            <div className="data-row" key={i}>
              <i className={f.severity === 'critical' ? 'fail' : 'warn'}>{String(f.severity)}</i>
              <span>{String(f.kind)}</span>
              <span style={{ fontSize: 11, wordBreak: 'break-all' }}>{String(f.path ?? '')}</span>
              <span style={{ fontSize: 11 }}>
                {String(f.message ?? '')}
                <br />
                <SignalSummary text={String(f.message ?? '')} />
                <SignalDetails matches={f.signal_matches} />
                {f.path ? (
                  <>
                    <br />
                    {(() => {
                      // 去处置深链接 type/asset 由 findingAsset 归一化：skill/mcp→资产名；代码质量类→
                      // path 类型+文件路径。此前硬编码 skill/mcp + f.path → /api/labels 400(重大bug)。
                      const fa = findingAsset(f) ?? { asset_type: 'path' as const, asset_key: String(f.path ?? '') };
                      return (
                        <Link
                          className="handle"
                          href={`/dispositions?type=${fa.asset_type}&asset=${encodeURIComponent(fa.asset_key)}`}
                          style={{ fontSize: 11 }}
                        >
                          去处置 →
                        </Link>
                      );
                    })()}
                  </>
                ) : null}
              </span>
            </div>
          ))}
        </div>
      ) : (
        <p style={{ fontSize: 12, color: 'var(--muted-foreground)' }}>该设备最新报告无 critical/high 发现明细。</p>
      )}
    </div>
  );
}
