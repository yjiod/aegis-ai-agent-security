'use client';

/**
 * 工单详情 / 行内展开面板。
 *
 * 该模块是工单领域模型的唯一出口：`Ticket` 类型、状态机（可执行的流转动作）、
 * 严重等级与状态的配色、时间格式化，以及把不可信的 `/api/tickets` 响应规范化为
 * `Ticket` 的解析函数都在此定义。`app/risks/page.tsx` 的列表行与本组件共用同一套
 * 状态机，保证「行内快捷动作」与「详情内动作」始终一致。
 */

import { useId, useState } from 'react';
import type { CSSProperties, ReactNode } from 'react';
import {
  Ban,
  Check,
  CircleDot,
  Cpu,
  FileWarning,
  Hash,
  History,
  RotateCcw,
  Search,
  User,
  UserCheck,
  X,
} from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Label } from '@/components/ui/label';
import { Spinner } from '@/components/ui/spinner';
import { Textarea } from '@/components/ui/textarea';

/* ── 领域模型 ───────────────────────────────────────────── */

export type TicketStatus =
  | 'open'
  | 'acknowledged'
  | 'investigating'
  | 'resolved'
  | 'dismissed';

export type TicketSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type TicketHistoryEntry = {
  action: string;
  actor?: string;
  note?: string;
  from_status?: TicketStatus;
  to_status?: TicketStatus;
  at: string | number | null;
};

export type Ticket = {
  ticket_id: string;
  title: string;
  severity: TicketSeverity;
  status: TicketStatus;
  source: string;
  device_id: string;
  description: string;
  assignee: string;
  finding_ref: string;
  created_at: string | number | null;
  updated_at: string | number | null;
  /** 进入终态（已解决 / 已驳回）的时间戳，重新打开后被清空。 */
  resolved_at: string | number | null;
  history: TicketHistoryEntry[];
};

/* ── 状态机与配色 ───────────────────────────────────────── */

/**
 * 状态色：open / resolved / dismissed 走主题令牌（暗色与亮色都成立），
 * acknowledged / investigating 没有对应令牌，取在两种底色下都可读的中间色。
 */
export const TICKET_STATUS_META: Record<
  TicketStatus,
  { label: string; color: string }
> = {
  open: { label: '待处理', color: 'var(--destructive)' },
  acknowledged: { label: '已认领', color: '#c98a1e' },
  investigating: { label: '调查中', color: '#4a94cc' },
  resolved: { label: '已解决', color: 'var(--primary)' },
  dismissed: { label: '已驳回', color: 'var(--muted-foreground)' },
};

export const TICKET_STATUSES = Object.keys(
  TICKET_STATUS_META,
) as TicketStatus[];

export type TicketTransition = { status: TicketStatus; label: string };

export const TICKET_TRANSITIONS: Record<TicketStatus, TicketTransition[]> = {
  open: [{ status: 'acknowledged', label: '认领' }],
  acknowledged: [{ status: 'investigating', label: '开始调查' }],
  investigating: [
    { status: 'resolved', label: '标记已解决' },
    { status: 'dismissed', label: '驳回' },
  ],
  resolved: [{ status: 'open', label: '重新打开' }],
  dismissed: [{ status: 'open', label: '重新打开' }],
};

export function ticketTransitions(status: TicketStatus): TicketTransition[] {
  return TICKET_TRANSITIONS[status] ?? [];
}

/** `.severity` 只定义了 red / orange 两种配色，低危用主题绿补齐。 */
export const SEVERITY_META: Record<
  TicketSeverity,
  { label: string; tone: 'red' | 'orange' | 'pass'; hint: string }
> = {
  critical: { label: '高危', tone: 'red', hint: '严重' },
  high: { label: '高危', tone: 'red', hint: '高' },
  medium: { label: '中危', tone: 'orange', hint: '中' },
  low: { label: '低危', tone: 'pass', hint: '低' },
  info: { label: '低危', tone: 'pass', hint: '提示' },
};

export function severityMeta(severity: TicketSeverity) {
  return SEVERITY_META[severity] ?? SEVERITY_META.low;
}

const passToneStyle: CSSProperties = {
  color: 'var(--primary)',
  background: 'color-mix(in srgb, var(--primary) 14%, transparent)',
  borderColor: 'color-mix(in srgb, var(--primary) 34%, transparent)',
};

export function severityStyle(severity: TicketSeverity): CSSProperties | undefined {
  return severityMeta(severity).tone === 'pass' ? passToneStyle : undefined;
}

export function statusBadgeStyle(status: TicketStatus): CSSProperties {
  const color = TICKET_STATUS_META[status]?.color ?? 'var(--muted-foreground)';
  return {
    display: 'inline-flex',
    alignItems: 'center',
    gap: 4,
    width: 'max-content',
    maxWidth: '100%',
    padding: '3px 8px',
    borderRadius: 6,
    border: `1px solid color-mix(in srgb, ${color} 38%, transparent)`,
    background: `color-mix(in srgb, ${color} 15%, transparent)`,
    color,
    fontSize: 10,
    fontWeight: 700,
    letterSpacing: '0.04em',
    whiteSpace: 'nowrap',
  };
}

export function statusLabel(status: TicketStatus): string {
  return TICKET_STATUS_META[status]?.label ?? status;
}

/* ── 时间格式化 ─────────────────────────────────────────── */

export function toTimestamp(value: unknown): number | null {
  if (typeof value === 'number' && Number.isFinite(value))
    return value > 1e12 ? value : value * 1000;
  if (typeof value !== 'string' || !value.trim()) return null;
  const trimmed = value.trim();
  if (/^\d+$/.test(trimmed)) {
    const numeric = Number(trimmed);
    return numeric > 1e12 ? numeric : numeric * 1000;
  }
  const parsed = Date.parse(trimmed);
  return Number.isNaN(parsed) ? null : parsed;
}

function pad(value: number): string {
  return String(value).padStart(2, '0');
}

export function formatTimestamp(value: unknown): string {
  const ms = toTimestamp(value);
  if (ms === null) return '—';
  const date = new Date(ms);
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(
    date.getDate(),
  )} ${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

export function formatRelativeTime(value: unknown): string {
  const ms = toTimestamp(value);
  if (ms === null) return '—';
  const diff = Date.now() - ms;
  if (Math.abs(diff) < 60_000) return '刚刚';
  if (diff < 0) return formatTimestamp(ms);
  const minutes = Math.floor(diff / 60_000);
  if (minutes < 60) return `${minutes} 分钟前`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours} 小时前`;
  const days = Math.floor(hours / 24);
  if (days < 30) return `${days} 天前`;
  return formatTimestamp(ms);
}

/* ── 不可信响应规范化 ───────────────────────────────────── */

function text(value: unknown, limit: number): string {
  if (typeof value !== 'string') return '';
  return value.trim().slice(0, limit);
}

function time(value: unknown): string | number | null {
  return typeof value === 'string' || typeof value === 'number' ? value : null;
}

export function normalizeTicketStatus(value: unknown): TicketStatus {
  const raw = text(value, 32)
    .toLowerCase()
    .replace(/[\s-]+/g, '_');
  if (raw === 'acknowledged' || raw === 'claimed' || raw === 'assigned')
    return 'acknowledged';
  if (raw === 'investigating' || raw === 'in_progress' || raw === 'triage')
    return 'investigating';
  if (raw === 'resolved' || raw === 'closed' || raw === 'done') return 'resolved';
  if (raw === 'dismissed' || raw === 'rejected' || raw === 'false_positive')
    return 'dismissed';
  return 'open';
}

export function normalizeTicketSeverity(value: unknown): TicketSeverity {
  const raw = text(value, 32).toLowerCase();
  if (raw === 'critical' || raw === 'urgent' || raw === '严重') return 'critical';
  if (raw === 'high' || raw === 'major' || raw === '高危') return 'high';
  if (raw === 'medium' || raw === 'med' || raw === '中危') return 'medium';
  if (raw === 'info' || raw === 'informational' || raw === '提示') return 'info';
  return 'low';
}

function parseHistoryEntry(raw: unknown): TicketHistoryEntry | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const data = raw as Record<string, unknown>;
  const action = text(data.action ?? data.event ?? data.type ?? data.kind, 64);
  const actor = text(
    data.actor ?? data.user ?? data.author ?? data.operator ?? data.by,
    128,
  );
  const note = text(
    data.note ?? data.comment ?? data.message ?? data.detail,
    512,
  );
  const from = data.from_status ?? data.from ?? data.previous_status;
  const to = data.to_status ?? data.to ?? data.status;
  const at = time(
    data.at ?? data.timestamp ?? data.created_at ?? data.time ?? data.date,
  );
  const fromStatus = parseStatusLoose(from);
  const toStatus = parseStatusLoose(to);
  if (!action && !actor && !note && !toStatus && at === null) return null;
  return {
    action,
    ...(actor ? { actor } : {}),
    ...(note ? { note } : {}),
    ...(fromStatus ? { from_status: fromStatus } : {}),
    ...(toStatus ? { to_status: toStatus } : {}),
    at,
  };
}

function parseStatusLoose(value: unknown): TicketStatus | null {
  const raw = text(value, 32)
    .toLowerCase()
    .replace(/[\s-]+/g, '_');
  if (!raw) return null;
  if (raw === 'open' || raw === 'new' || raw === 'created') return 'open';
  if (raw === 'acknowledged' || raw === 'claimed' || raw === 'assigned')
    return 'acknowledged';
  if (raw === 'investigating' || raw === 'in_progress' || raw === 'triage')
    return 'investigating';
  if (raw === 'resolved' || raw === 'closed' || raw === 'done') return 'resolved';
  if (raw === 'dismissed' || raw === 'rejected' || raw === 'false_positive')
    return 'dismissed';
  return null;
}

function parseHistory(value: unknown): TicketHistoryEntry[] {
  if (!Array.isArray(value)) return [];
  const entries: TicketHistoryEntry[] = [];
  for (const raw of value) {
    const entry = parseHistoryEntry(raw);
    if (entry) entries.push(entry);
  }
  return entries;
}

/** 把单条不可信记录规范化为 `Ticket`；缺少 ticket_id 时返回 null。 */
export function parseTicket(raw: unknown): Ticket | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const data = raw as Record<string, unknown>;
  const ticketId = text(data.ticket_id ?? data.id ?? data.ticketId, 64);
  if (!ticketId) return null;
  return {
    ticket_id: ticketId,
    title: text(data.title ?? data.summary ?? data.name, 200) || ticketId,
    severity: normalizeTicketSeverity(data.severity ?? data.level ?? data.risk),
    status: normalizeTicketStatus(data.status ?? data.state),
    source: text(data.source ?? data.origin ?? data.rule ?? data.detector, 200),
    device_id: text(data.device_id ?? data.device ?? data.deviceId, 64),
    description: text(
      data.description ?? data.detail ?? data.message ?? data.body,
      4000,
    ),
    assignee: text(data.assignee ?? data.owner ?? data.assigned_to, 128),
    finding_ref: text(
      data.finding_ref ?? data.finding ?? data.finding_id ?? data.reference,
      300,
    ),
    created_at: time(data.created_at ?? data.createdAt ?? data.opened_at),
    updated_at: time(data.updated_at ?? data.updatedAt ?? data.last_updated),
    resolved_at: time(data.resolved_at ?? data.resolvedAt ?? data.closed_at),
    history: parseHistory(data.history ?? data.timeline ?? data.events),
  };
}

/**
 * 解析 `GET /api/tickets` 载荷，容忍 `{ tickets: [] }` / `{ data: [] }` / 裸数组。
 * 结果按 ticket_id 去重，保持服务端返回顺序。
 */
export function parseTicketList(payload: unknown): Ticket[] {
  let rows: unknown[] = [];
  if (Array.isArray(payload)) {
    rows = payload;
  } else if (payload && typeof payload === 'object') {
    const data = payload as Record<string, unknown>;
    const key = ['tickets', 'data', 'items', 'results', 'records'].find(
      (candidate) => Array.isArray(data[candidate]),
    );
    rows = key ? (data[key] as unknown[]) : [];
  }
  const seen = new Set<string>();
  const tickets: Ticket[] = [];
  for (const row of rows) {
    const ticket = parseTicket(row);
    if (!ticket || seen.has(ticket.ticket_id)) continue;
    seen.add(ticket.ticket_id);
    tickets.push(ticket);
  }
  return tickets;
}

/* ── 组件 ───────────────────────────────────────────────── */

export type TicketDetailProps = {
  ticket: Ticket;
  onAction: (status: TicketStatus, note?: string) => Promise<void>;
  onClose: () => void;
};

const containerStyle: CSSProperties = {
  border: '1px solid var(--line-base)',
  borderRadius: 10,
  background: 'var(--surface-1)',
  padding: '14px 16px 16px',
  margin: '2px 0 12px',
};

const metaGridStyle: CSSProperties = {
  display: 'grid',
  gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))',
  gap: 10,
  marginTop: 14,
};

const mutedStyle: CSSProperties = {
  fontSize: 11,
  color: 'var(--muted-foreground)',
};

/**
 * `PUT /api/tickets/:id` 写入的历史动词（create / acknowledge / investigate /
 * resolve / dismiss / reopen / assign / comment），同时容忍状态名与
 * `status:<state>` 这类旧写法。
 */
const ACTION_LABELS: Record<string, string> = {
  create: '工单创建',
  created: '工单创建',
  acknowledge: '安全运营认领',
  acknowledged: '安全运营认领',
  claimed: '安全运营认领',
  investigate: '开始调查',
  investigating: '开始调查',
  in_progress: '开始调查',
  triage: '开始调查',
  resolve: '标记已解决',
  resolved: '标记已解决',
  closed: '标记已解决',
  dismiss: '工单驳回',
  dismissed: '工单驳回',
  rejected: '工单驳回',
  reopen: '工单重新打开',
  reopened: '工单重新打开',
  open: '工单重新打开',
  assign: '指派负责人',
  assigned: '指派负责人',
  comment: '添加处置备注',
  note: '添加处置备注',
  escalated: '升级处置',
  status_change: '状态更新',
};

function historyActionLabel(entry: TicketHistoryEntry): string {
  const key = entry.action
    .replace(/^status:/i, '')
    .toLowerCase()
    .replace(/[\s-]+/g, '_');
  if (key && ACTION_LABELS[key]) return ACTION_LABELS[key];
  if (entry.to_status) return `状态更新为「${statusLabel(entry.to_status)}」`;
  return entry.action || '状态更新';
}

function historyMeta(entry: TicketHistoryEntry): string {
  const parts: string[] = [];
  if (entry.actor) parts.push(`操作人 ${entry.actor}`);
  if (entry.from_status && entry.to_status)
    parts.push(`${statusLabel(entry.from_status)} → ${statusLabel(entry.to_status)}`);
  if (entry.note) parts.push(entry.note);
  return parts.join(' · ') || '系统自动记录';
}

function historyIcon(entry: TicketHistoryEntry): ReactNode {
  const key = entry.to_status ?? entry.action.toLowerCase();
  if (key === 'acknowledged' || key === 'acknowledge') return <UserCheck size={15} />;
  if (key === 'investigating' || key === 'investigate') return <Search size={15} />;
  if (key === 'resolved' || key === 'resolve') return <Check size={15} />;
  if (key === 'dismissed' || key === 'dismiss') return <Ban size={15} />;
  if (key === 'open' || key === 'reopen') return <RotateCcw size={15} />;
  if (key === 'assign' || key === 'assigned') return <User size={15} />;
  if (key === 'created' || key === 'create') return <FileWarning size={15} />;
  return <CircleDot size={15} />;
}

function sortedHistory(ticket: Ticket): TicketHistoryEntry[] {
  const entries = [...ticket.history];
  const stamps = entries.map((entry) => toTimestamp(entry.at));
  if (stamps.some((stamp) => stamp === null)) return entries;
  return entries.sort(
    (left, right) =>
      (toTimestamp(right.at) ?? 0) - (toTimestamp(left.at) ?? 0),
  );
}

function MetaItem({
  icon,
  label,
  value,
}: {
  icon: ReactNode;
  label: string;
  value: string;
}) {
  return (
    <div style={{ minWidth: 0 }}>
      <span style={{ ...mutedStyle, display: 'flex', alignItems: 'center', gap: 5 }}>
        {icon}
        {label}
      </span>
      <strong
        style={{
          display: 'block',
          marginTop: 3,
          fontSize: 12,
          color: 'var(--foreground)',
          overflowWrap: 'anywhere',
        }}
      >
        {value}
      </strong>
    </div>
  );
}

export default function TicketDetail({
  ticket,
  onAction,
  onClose,
}: TicketDetailProps) {
  const noteId = useId();
  const [note, setNote] = useState('');
  const [pending, setPending] = useState<TicketStatus | null>(null);

  const severity = severityMeta(ticket.severity);
  const transitions = ticketTransitions(ticket.status);
  const history = sortedHistory(ticket);
  const busy = pending !== null;

  async function run(status: TicketStatus) {
    if (busy) return;
    setPending(status);
    try {
      await onAction(status, note.trim() || undefined);
      setNote('');
    } finally {
      setPending(null);
    }
  }

  return (
    <div className="animate-entrance" style={containerStyle}>
      <div
        style={{
          display: 'flex',
          alignItems: 'flex-start',
          justifyContent: 'space-between',
          gap: 12,
        }}
      >
        <div style={{ minWidth: 0 }}>
          <div
            style={{
              display: 'flex',
              flexWrap: 'wrap',
              alignItems: 'center',
              gap: 8,
            }}
          >
            <span
              className={`severity ${severity.tone}`}
              style={severityStyle(ticket.severity)}
              title={`严重等级：${severity.hint}`}
            >
              {severity.label}
            </span>
            <span style={statusBadgeStyle(ticket.status)}>
              {statusLabel(ticket.status)}
            </span>
            <Badge variant="outline" style={{ fontSize: 10, gap: 4 }}>
              <Hash size={11} />
              {ticket.ticket_id}
            </Badge>
          </div>
          <strong
            style={{
              display: 'block',
              marginTop: 9,
              fontSize: 14,
              letterSpacing: '-0.01em',
              color: 'var(--foreground)',
            }}
          >
            {ticket.title}
          </strong>
        </div>
        <Button
          variant="ghost"
          size="icon-sm"
          onClick={onClose}
          aria-label="收起工单详情"
        >
          <X />
        </Button>
      </div>

      <div style={metaGridStyle}>
        <MetaItem
          icon={<Cpu size={12} />}
          label="来源"
          value={ticket.source || '未提供'}
        />
        <MetaItem
          icon={<Hash size={12} />}
          label="关联设备"
          value={ticket.device_id || '未关联'}
        />
        <MetaItem
          icon={<User size={12} />}
          label="负责人"
          value={ticket.assignee || '待认领'}
        />
        <MetaItem
          icon={<FileWarning size={12} />}
          label="关联发现"
          value={ticket.finding_ref || '未关联'}
        />
        <MetaItem
          icon={<History size={12} />}
          label="创建时间"
          value={formatTimestamp(ticket.created_at)}
        />
        <MetaItem
          icon={<CircleDot size={12} />}
          label="最近更新"
          value={formatTimestamp(ticket.updated_at)}
        />
        {ticket.resolved_at !== null && (
          <MetaItem
            icon={<Check size={12} />}
            label="闭环时间"
            value={formatTimestamp(ticket.resolved_at)}
          />
        )}
      </div>

      {ticket.description && (
        <p
          style={{
            margin: '14px 0 0',
            fontSize: 12,
            lineHeight: 1.65,
            color: 'var(--muted-foreground)',
            overflowWrap: 'anywhere',
          }}
        >
          {ticket.description}
        </p>
      )}

      <div
        style={{
          display: 'flex',
          flexWrap: 'wrap',
          alignItems: 'flex-end',
          gap: 12,
          marginTop: 14,
        }}
      >
        <div style={{ flex: '1 1 240px', minWidth: 0 }}>
          <Label htmlFor={noteId} style={{ ...mutedStyle, marginBottom: 6 }}>
            处置备注
          </Label>
          <Textarea
            id={noteId}
            value={note}
            onChange={(event) => setNote(event.target.value)}
            placeholder="记录研判结论或处置动作（可选）"
            maxLength={512}
            disabled={busy}
            style={{ fontSize: 12 }}
          />
        </div>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
          {transitions.map((transition) => (
            <Button
              key={transition.status}
              size="sm"
              variant={
                transition.status === 'dismissed'
                  ? 'destructive'
                  : transition.status === 'resolved'
                    ? 'default'
                    : 'outline'
              }
              disabled={busy}
              onClick={() => run(transition.status)}
            >
              {pending === transition.status ? <Spinner /> : null}
              {transition.label}
            </Button>
          ))}
          {transitions.length === 0 && (
            <span style={mutedStyle}>当前状态没有可执行的流转动作</span>
          )}
        </div>
      </div>

      <div style={{ marginTop: 18 }}>
        <p
          style={{
            ...mutedStyle,
            display: 'flex',
            alignItems: 'center',
            gap: 6,
            margin: 0,
            letterSpacing: '0.04em',
          }}
        >
          <History size={13} />
          处置时间线
        </p>
        {history.length === 0 ? (
          <p style={{ ...mutedStyle, margin: '10px 0 0' }}>
            暂无处置记录，认领后动作会自动写入时间线。
          </p>
        ) : (
          <div className="activity-timeline">
            {history.map((entry, index) => (
              <div
                className="timeline-entry"
                key={`${entry.action}-${entry.at ?? index}`}
              >
                <span className="timeline-icon">{historyIcon(entry)}</span>
                <div className="timeline-content">
                  <strong>{historyActionLabel(entry)}</strong>
                  <span>{historyMeta(entry)}</span>
                </div>
                <span className="timeline-time">{formatTimestamp(entry.at)}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
