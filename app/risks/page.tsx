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
import { useRole } from '@/components/role-context';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import {
  NativeSelect,
  NativeSelectOption,
} from '@/components/ui/native-select';
import { Spinner } from '@/components/ui/spinner';
import { Textarea } from '@/components/ui/textarea';
import { useCollector } from '@/components/collector-context';
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

/* ─── 展示层常量 ─────────────────────────────────────────── */

type TicketSource = 'loading' | 'api' | 'demo';
type ToastTone = 'info' | 'success' | 'error';
type FilterKey = 'all' | 'pending' | 'investigating' | 'resolved';

const JSON_HEADERS = { 'Content-Type': 'application/json' } as const;

const MINUTE = 60_000;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;

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
const TICKET_ROW_GRID = '54px minmax(0,1fr) 116px 62px auto';

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

export default function RisksPage() {
  const { fleet } = useCollector();

  const [tickets, setTickets] = useState<Ticket[]>([]);
  const [source, setSource] = useState<TicketSource>('loading');
  const [notice, setNotice] = useState('');
  const [refreshing, setRefreshing] = useState(false);
  const [filter, setFilter] = useState<FilterKey>('all');
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [showCreate, setShowCreate] = useState(false);
  const { role } = useRole();
  const canMutate = role === 'admin';
  const [pendingAction, setPendingAction] = useState<{
    id: string;
    status: TicketStatus;
  } | null>(null);
  const [toast, setToast] = useState<{ text: string; tone: ToastTone } | null>(null);
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

  /** 接口不可用：保留已有真实数据, 绝不注入演示工单; 用 notice 说明原因, 列表为空则显示空状态。 */
  const applyFallback = useCallback((message: string) => {
    setNotice(message);
    setSource('api');
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

  /** 写操作失败时的提示：实时模式下明确说明「没有真的改动」。 */
  const failureCopy = useCallback(
    (action: string, title: string, error: unknown) =>
      source === 'demo'
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
    if (!match) return tickets;
    return tickets.filter((ticket) => match.includes(ticket.status));
  }, [filter, tickets]);

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

  const noticeCopy = (() => {
    if (source === 'loading')
      return { title: '正在读取工单', body: ' 正在从 /api/tickets 拉取风险工单队列。' };
    if (source === 'api')
      return fleet
        ? {
            title: '混合只读模式',
            body: ' 工单流转为真实写操作；顶部接收器摘要为只读，未连接 EDR 前不会执行任何隔离动作。',
          }
        : {
            title: '工单接口已连接',
            body: ' 工单队列与状态流转来自 /api/tickets；接收器摘要未连接，未连接 EDR 前不会执行任何隔离动作。',
          };
    return {
      title: '接口暂不可用',
      body: ` 工单接口不可用（${notice || '未知原因'}），以下事件为界面实时，任何流转都不会持久化。`,
    };
  })();

  /* ── 渲染 ─────────────────────────────────────────────── */

  return (
    <>
      

      <div className="page-head animate-entrance animate-entrance-1">
        <div>
          <p className="eyebrow">风险中心 / 待研判</p>
          <h1>风险中心</h1>
          <p>按风险等级与时间排序，认领后进入分级响应流程。</p>
        </div>
        <div className="head-actions" style={{ flexWrap: 'wrap' }}>
          <Button
            variant="outline"
            onClick={() => notify('功能待接入：未连接 EDR 审批接口，未隔离任何对象。')}
          >
            <ShieldAlert />
            隔离全部高危
          </Button>
          <Button onClick={() => setShowCreate((prev) => !prev)}>
            {showCreate ? <X /> : <Plus />}
            {showCreate ? '收起表单' : '新建工单'}
          </Button>
        </div>
      </div>

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
          <span>待处理工单{source === 'demo' ? '' : ''}</span>
        </article>
        <article className="animate-entrance animate-entrance-2">
          <strong>{filterCounts.investigating}</strong>
          <span>调查中{source === 'demo' ? '' : ''}</span>
        </article>
        <article className="animate-entrance animate-entrance-3">
          <strong>{highRiskOpen}</strong>
          <span>未闭环高危事件{source === 'demo' ? '' : ''}</span>
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
                : `${highRiskOpen} 个高危事件需要人工确认 · 共 ${tickets.length} 张工单${
                    source === 'demo' ? '' : ''
                  }`}
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
            {source === 'api' ? '工单接口已连接' : '实时上报实时'}
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

        <div className="risk-table">
          {source === 'loading' &&
            [0, 1, 2, 3].map((index) => (
              <div className="skeleton-row" key={index} />
            ))}

          {visibleTickets.map((ticket, index) => {
            const severity = severityMeta(ticket.severity);
            const transitions = ticketTransitions(ticket.status);
            const expanded = expandedId === ticket.ticket_id;
            const busy = pendingAction?.id === ticket.ticket_id;
            return (
              <Fragment key={ticket.ticket_id}>
                <div
                  className="risk-row wide animate-row-entrance"
                  style={{
                    animationDelay: `${index * 30 + 200}ms`,
                    gridTemplateColumns: TICKET_ROW_GRID,
                    cursor: 'pointer',
                  }}
                  onClick={() => setExpandedId(expanded ? null : ticket.ticket_id)}
                >
                  <span
                    className={`severity ${severity.tone}`}
                    style={severityStyle(ticket.severity)}
                    title={`严重等级：${severity.hint}`}
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
                  </div>
                  <span className="device">{ticket.device_id || '未关联'}</span>
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
                    {transitions.map((transition) => (
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
                    />
                    {ticket.device_id && <LinkedFindings deviceId={ticket.device_id} />}
                  </div>
                )}
              </Fragment>
            );
          })}
        </div>

        {source !== 'loading' && visibleTickets.length === 0 && (
          <div className="empty-detail" style={{ minHeight: 180 }}>
            <ShieldCheck size={36} />
            <h2>{filter === 'all' ? '队列已清空' : '当前筛选下没有工单'}</h2>
            <p>
              {filter === 'all'
                ? '没有待研判的风险事件；新的上报会自动进入该队列。'
                : '切换其他状态标签，或点击右上角「新建工单」手工登记一起事件。'}
            </p>
          </div>
        )}

        <div className="flow">
          <span>终端上报</span>
          <b>→</b>
          <span>安全运营认领</span>
          <b>→</b>
          <span>深信服 EDR 隔离</span>
          <b>→</b>
          <span>基线复核</span>
          <b>→</b>
          <span className="safe">
            <ShieldCheck size={15} />
            工单关闭
          </span>
        </div>
      </div>
    </>
  );

  /** 行内动作与详情面板共用同一个流转入口。 */
  function runTransition(ticket: Ticket, status: TicketStatus) {
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
      .then((d) => {
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
              <span style={{ fontSize: 11 }}>{String(f.message ?? '')}</span>
            </div>
          ))}
        </div>
      ) : (
        <p style={{ fontSize: 12, color: 'var(--muted-foreground)' }}>该设备最新报告无 critical/high 发现明细。</p>
      )}
    </div>
  );
}
