'use client';

import { useCallback, useEffect, useState } from 'react';
import {
  AlertTriangle, CircleDot, Plus, X, Check, Clock,
  ShieldCheck, Search as SearchIcon,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { useCollector } from '@/components/collector-context';

/* ─── Types ─────────────────────────────────────────────── */
type TicketStatus = 'open' | 'acknowledged' | 'investigating' | 'resolved' | 'dismissed';
interface HistoryEntry { action: string; actor: string; timestamp: number; note?: string }
interface Ticket {
  ticket_id: string; title: string; severity: 'critical' | 'high' | 'medium' | 'low';
  status: TicketStatus; source: string; device_id: string; description?: string;
  finding_ref?: string; assignee?: string; created_at: number; updated_at: number;
  resolved_at?: number; history: HistoryEntry[];
}

const SEV_LABEL: Record<string, string> = { critical: '严重', high: '高危', medium: '中危', low: '低危' };
const SEV_CLASS: Record<string, string> = { critical: 'red', high: 'red', medium: 'orange', low: 'orange' };
const STATUS_LABEL: Record<TicketStatus, string> = { open: '待处理', acknowledged: '已认领', investigating: '调查中', resolved: '已解决', dismissed: '已驳回' };
const STATUS_COLOR: Record<TicketStatus, string> = { open: '#ff685f', acknowledged: '#e8b449', investigating: '#64bae7', resolved: '#49e8a5', dismissed: '#5e7c73' };
const FILTERS: { key: string; label: string }[] = [
  { key: '', label: '全部' }, { key: 'open', label: '待处理' },
  { key: 'acknowledged', label: '已认领' }, { key: 'investigating', label: '调查中' },
  { key: 'resolved', label: '已解决' },
];

function timeAgo(ts: number): string {
  const diff = Math.floor(Date.now() / 1000) - ts;
  if (diff < 60) return '刚刚';
  if (diff < 3600) return `${Math.floor(diff / 60)} 分钟前`;
  if (diff < 86400) return `${Math.floor(diff / 3600)} 小时前`;
  return `${Math.floor(diff / 86400)} 天前`;
}

/* ─── Page ──────────────────────────────────────────────── */
export default function RisksPage() {
  const { fleet } = useCollector();
  const [tickets, setTickets] = useState<Ticket[]>([]);
  const [loading, setLoading] = useState(true);
  const [toast, setToast] = useState('');
  const [filter, setFilter] = useState('');
  const [expanded, setExpanded] = useState<string | null>(null);
  const [showCreate, setShowCreate] = useState(false);

  const fetchTickets = useCallback(async () => {
    try {
      const url = filter ? `/api/tickets?status=${filter}` : '/api/tickets';
      const res = await fetch(url, { cache: 'no-store' });
      if (res.ok) { const data = await res.json(); setTickets(data.tickets ?? []); }
    } catch { /* keep current */ }
    setLoading(false);
  }, [filter]);

  useEffect(() => { fetchTickets(); }, [fetchTickets]);

  function notify(msg: string) { setToast(msg); setTimeout(() => setToast(''), 3500); }

  async function transition(ticket_id: string, status: TicketStatus, note?: string) {
    const res = await fetch(`/api/tickets/${ticket_id}`, {
      method: 'PUT', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status, note, actor: 'console_user' }),
    });
    if (res.ok) { notify(`工单 ${ticket_id} 已转为「${STATUS_LABEL[status]}」`); fetchTickets(); }
    else { const err = await res.json().catch(() => ({})); notify(`操作失败: ${err.error ?? res.status}`); }
  }

  const openCount = tickets.filter((t) => t.status === 'open').length;
  const investigatingCount = tickets.filter((t) => t.status === 'investigating' || t.status === 'acknowledged').length;
  const resolvedCount = tickets.filter((t) => t.status === 'resolved').length;

  return (
    <>
      <div className="demo-notice" role="note">
        <AlertTriangle size={16} />
        <span><strong>{fleet ? '混合模式' : '演示模式'}</strong> 工单流转为真实 CRUD 操作（内存存储）；KPI 数据来自{fleet ? '接收器摘要' : '界面样例'}。</span>
      </div>

      <div className="page-head animate-entrance animate-entrance-1">
        <div>
          <p className="eyebrow">控制台 / 风险中心</p>
          <h1>风险工单</h1>
          <p>管理安全事件的完整生命周期：发现 → 认领 → 调查 → 处置。</p>
        </div>
        <div className="head-actions">
          <Button onClick={() => setShowCreate(!showCreate)}>
            {showCreate ? <X size={16} /> : <Plus size={16} />}
            {showCreate ? '取消' : '新建工单'}
          </Button>
        </div>
      </div>

      {toast && <div className="toast" role="status"><CircleDot size={16} />{toast}</div>}

      {/* KPIs */}
      <div className="detail-kpis animate-entrance animate-entrance-2">
        <article><strong>{openCount}</strong><span>待处理工单</span></article>
        <article><strong>{investigatingCount}</strong><span>调查中</span></article>
        <article><strong>{resolvedCount}</strong><span>本周已解决</span></article>
      </div>

      {/* Create form */}
      {showCreate && <CreateTicketForm onCreated={() => { setShowCreate(false); fetchTickets(); notify('工单创建成功。'); }} notify={notify} />}

      {/* Filters */}
      <div className="panel animate-entrance animate-entrance-3" style={{ marginBottom: 14, padding: '12px 16px' }}>
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
          {FILTERS.map((f) => (
            <button key={f.key} className={`filter-btn ${filter === f.key ? 'active' : ''}`} onClick={() => { setFilter(f.key); setLoading(true); }}>
              {f.label}
              {f.key === 'open' && openCount > 0 && <b>{openCount}</b>}
            </button>
          ))}
        </div>
      </div>

      {/* Ticket list */}
      <div className="panel animate-entrance animate-entrance-4">
        <div className="panel-head">
          <div><h2>事件工单</h2><p>{loading ? '加载中...' : `共 ${tickets.length} 条`}</p></div>
        </div>

        {loading ? (
          <>{[1,2,3].map(i => <div className="skeleton-row" key={i}><div className="skeleton-cell" /><div className="skeleton-cell" /><div className="skeleton-cell" /></div>)}</>
        ) : tickets.length === 0 ? (
          <div style={{ padding: 40, textAlign: 'center', color: '#5e7c73' }}>
            <ShieldCheck size={32} style={{ margin: '0 auto 12px', display: 'block', color: '#49e8a5' }} />
            <p style={{ fontSize: 13 }}>当前筛选条件下没有工单</p>
          </div>
        ) : (
          tickets.map((t, i) => (
            <div key={t.ticket_id}>
              <div className="risk-row wide animate-row-entrance" style={{ animationDelay: `${i * 30 + 200}ms`, cursor: 'pointer' }} onClick={() => setExpanded(expanded === t.ticket_id ? null : t.ticket_id)}>
                <span className={`severity ${SEV_CLASS[t.severity]}`}>{SEV_LABEL[t.severity]}</span>
                <div className="risk-main">
                  <strong>{t.title}</strong>
                  <span>{t.source} · {t.ticket_id}</span>
                </div>
                <span className="device">{t.device_id}</span>
                <span style={{ fontSize: 10, color: STATUS_COLOR[t.status], fontWeight: 600 }}>{STATUS_LABEL[t.status]}</span>
                <span className="time">{timeAgo(t.updated_at)}</span>
              </div>

              {expanded === t.ticket_id && (
                <TicketDetail ticket={t} onTransition={transition} />
              )}
            </div>
          ))
        )}
      </div>
    </>
  );
}

/* ─── Ticket Detail Expansion ───────────────────────────── */
function TicketDetail({ ticket, onTransition }: { ticket: Ticket; onTransition: (id: string, status: TicketStatus, note?: string) => void }) {
  const [note, setNote] = useState('');
  const t = ticket;

  const actions: { status: TicketStatus; label: string; variant?: 'outline' }[] =
    t.status === 'open' ? [{ status: 'acknowledged', label: '认领工单' }] :
    t.status === 'acknowledged' ? [{ status: 'investigating', label: '开始调查' }, { status: 'dismissed', label: '驳回', variant: 'outline' }] :
    t.status === 'investigating' ? [{ status: 'resolved', label: '标记已解决' }, { status: 'dismissed', label: '驳回', variant: 'outline' }] :
    [{ status: 'open', label: '重新打开', variant: 'outline' }];

  return (
    <div style={{ padding: '16px 20px', background: '#0a1613', border: '1px solid #1e332d', borderRadius: 10, margin: '6px 0 12px', animation: 'entrance-fade-up 200ms cubic-bezier(0.2,0,0,1) both' }}>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginBottom: 14, fontSize: 12 }}>
        <div><span style={{ color: '#5e7c73' }}>工单号：</span><strong>{t.ticket_id}</strong></div>
        <div><span style={{ color: '#5e7c73' }}>设备：</span>{t.device_id}</div>
        <div><span style={{ color: '#5e7c73' }}>来源：</span>{t.source}</div>
        <div><span style={{ color: '#5e7c73' }}>指派：</span>{t.assignee ?? '未指派'}</div>
        {t.finding_ref && <div><span style={{ color: '#5e7c73' }}>发现引用：</span>{t.finding_ref}</div>}
        <div><span style={{ color: '#5e7c73' }}>创建：</span>{timeAgo(t.created_at)}</div>
      </div>
      {t.description && <p style={{ fontSize: 12, color: '#87a69c', lineHeight: 1.6, marginBottom: 14, padding: '10px 12px', background: '#07110f', borderRadius: 6, border: '1px solid #1a3129' }}>{t.description}</p>}

      {/* History timeline */}
      <div className="activity-timeline" style={{ marginBottom: 14 }}>
        {t.history.map((h, idx) => (
          <div className="timeline-entry" key={idx}>
            <div className="timeline-icon"><Clock size={12} /></div>
            <div className="timeline-content">
              <strong>{h.action.replace('status:', '状态: ')}</strong>
              <span>{h.actor} · {timeAgo(h.timestamp)}{h.note ? ` — ${h.note}` : ''}</span>
            </div>
          </div>
        ))}
      </div>

      {/* Actions */}
      <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
        <input className="form-input" style={{ flex: 1, minWidth: 160 }} placeholder="处置备注（可选）" value={note} onChange={(e) => setNote(e.target.value)} />
        {actions.map((a) => (
          <Button key={a.status} size="sm" variant={a.variant} onClick={() => onTransition(t.ticket_id, a.status, note || undefined)}>
            {a.status === 'resolved' && <Check size={14} />}
            {a.label}
          </Button>
        ))}
      </div>
    </div>
  );
}

/* ─── Create Ticket Form ────────────────────────────────── */
function CreateTicketForm({ onCreated, notify }: { onCreated: () => void; notify: (m: string) => void }) {
  const [form, setForm] = useState({ title: '', severity: 'high', source: '', device_id: '', description: '' });
  const [submitting, setSubmitting] = useState(false);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!form.title || !form.source || !form.device_id) { notify('请填写标题、来源和设备 ID。'); return; }
    setSubmitting(true);
    const res = await fetch('/api/tickets', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(form) });
    setSubmitting(false);
    if (res.status === 201) onCreated();
    else { const err = await res.json().catch(() => ({})); notify(`创建失败: ${err.error ?? res.status}`); }
  }

  return (
    <form className="panel animate-entrance" onSubmit={handleSubmit} style={{ marginBottom: 14 }}>
      <div className="panel-head"><div><h2>新建风险工单</h2><p>手动创建安全事件工单</p></div></div>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
        <div style={{ gridColumn: '1 / -1' }}>
          <label style={{ fontSize: 11, color: '#78968c', display: 'block', marginBottom: 4 }}>标题 *</label>
          <input className="form-input" value={form.title} onChange={(e) => setForm({ ...form, title: e.target.value })} placeholder="简要描述安全事件" />
        </div>
        <div>
          <label style={{ fontSize: 11, color: '#78968c', display: 'block', marginBottom: 4 }}>严重度</label>
          <select className="form-select" value={form.severity} onChange={(e) => setForm({ ...form, severity: e.target.value })}>
            <option value="critical">严重</option><option value="high">高危</option><option value="medium">中危</option><option value="low">低危</option>
          </select>
        </div>
        <div>
          <label style={{ fontSize: 11, color: '#78968c', display: 'block', marginBottom: 4 }}>设备 ID *</label>
          <input className="form-input" value={form.device_id} onChange={(e) => setForm({ ...form, device_id: e.target.value })} placeholder="ENG-MBP-1032" />
        </div>
        <div style={{ gridColumn: '1 / -1' }}>
          <label style={{ fontSize: 11, color: '#78968c', display: 'block', marginBottom: 4 }}>来源 *</label>
          <input className="form-input" value={form.source} onChange={(e) => setForm({ ...form, source: e.target.value })} placeholder="cursor-mcp-filesystem / prompt-helper.skill" />
        </div>
        <div style={{ gridColumn: '1 / -1' }}>
          <label style={{ fontSize: 11, color: '#78968c', display: 'block', marginBottom: 4 }}>描述</label>
          <textarea className="form-input" rows={3} value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} placeholder="详细描述发现的问题..." style={{ resize: 'vertical' }} />
        </div>
      </div>
      <div style={{ marginTop: 16 }}><Button type="submit" disabled={submitting}>{submitting ? '创建中...' : '创建工单'}</Button></div>
    </form>
  );
}
