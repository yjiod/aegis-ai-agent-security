'use client';

import { useCallback, useEffect, useId, useState } from 'react';
import {
  AlertTriangle, Plus, Search,
  Trash2, Pencil, X, Check,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { useCollector } from '@/components/collector-context';
import { Toast } from '@/components/toast';

/* ─── Types ─────────────────────────────────────────────── */
interface Device {
  device_id: string; hostname: string; owner: string;
  agent_type: string; agent_version: string; policy_version: string;
  status: 'online' | 'offline' | 'stale' | 'needs_attention';
  last_seen: number; registered_at: number; notes?: string;
  findings_summary?: { critical: number; high: number; medium: number; low: number };
}

const AGENT_LABELS: Record<string, string> = {
  cursor: 'Cursor', claude_code: 'Claude Code', codex_cli: 'Codex CLI', windsurf: 'Windsurf', other: '其他',
};
const STATUS_LABELS: Record<string, string> = {
  online: '在线', offline: '离线', stale: '过期', needs_attention: '需处理',
};
const STATUS_CLASS: Record<string, string> = {
  online: 'pass', offline: 'warn', stale: 'warn', needs_attention: 'fail',
};

/* ─── Page ──────────────────────────────────────────────── */
export default function DevicesPage() {
  const { fleet } = useCollector();
  const [devices, setDevices] = useState<Device[]>([]);
  const [loading, setLoading] = useState(true);
  const [toast, setToast] = useState('');
  const [search, setSearch] = useState('');
  const [showForm, setShowForm] = useState(false);
  const [editId, setEditId] = useState<string | null>(null);
  const [deleteConfirm, setDeleteConfirm] = useState<string | null>(null);

  const fetchDevices = useCallback(async (signal?: AbortSignal) => {
    try {
      const res = await fetch('/api/devices', { cache: 'no-store', signal });
      if (res.ok) {
        // `await res.json()` 静态类型是 unknown，按接口契约收窄后再取字段。
        const data = (await res.json()) as { devices?: Device[] };
        setDevices(data.devices ?? []);
      }
    } catch (error) {
      // 主动取消不是失败：effect 清理时 abort 在途请求，直接返回不触碰 state。
      if (error instanceof Error && error.name === 'AbortError') return;
      /* 其余错误保持现有数据 */
    }
    setLoading(false);
  }, []);

  // setState 全部位于 await 之后，非 effect 内同步 setState（EffectSetState）；
  // abort 保证卸载/重跑时不会有迟到的响应写回已失效的状态。
  useEffect(() => {
    const controller = new AbortController();
    // EffectSetState 是基于调用图的静态启发式：它只看到「effect 内调用了含
    // setState 的函数」，看不见 await 边界。此处 setState 全部位于 await 之后，
    // 由 React 18+ 自动批处理合并为单次渲染，不构成规则所担心的同步级联渲染；
    // AbortController 另保证迟到的响应不会写回已失效的状态。「按依赖变化取数
    // 并存入 state」是 React 标准模式，不宜为迁就静态分析而扭曲结构。
    // oxlint-disable-next-line react/react-compiler
    void fetchDevices(controller.signal);
    return () => controller.abort();
  }, [fetchDevices]);

  function notify(msg: string) { setToast(msg); setTimeout(() => setToast(''), 3500); }

  const filtered = devices.filter((d) => {
    if (!search) return true;
    const q = search.toLowerCase();
    return d.device_id.toLowerCase().includes(q) || d.hostname.toLowerCase().includes(q) || d.owner.toLowerCase().includes(q);
  });

  const totalDevices = fleet?.total_devices ?? devices.length;
  const onlineDevices = devices.filter((d) => d.status === 'online').length;
  const coverage = totalDevices ? ((fleet?.version_posture.current ?? onlineDevices) / totalDevices) * 100 : 0;

  async function handleDelete(device_id: string) {
    const res = await fetch(`/api/devices?device_id=${encodeURIComponent(device_id)}`, { method: 'DELETE' });
    if (res.ok) { notify(`设备 ${device_id} 已从注册表移除。`); await fetchDevices(); }
    else notify('删除失败，请重试。');
    setDeleteConfirm(null);
  }

  return (
    <>
      <div className="demo-notice" role="note">
        <AlertTriangle size={16} />
        <span><strong>{fleet ? '混合只读模式' : '演示模式'}</strong> 设备注册表支持 CRUD 操作；顶部 KPI 来自{fleet ? '已验证的接收器摘要' : '界面样例'}。</span>
      </div>

      <div className="page-head animate-entrance animate-entrance-1">
        <div>
          <p className="eyebrow">控制台 / 设备与 Agent</p>
          <h1>设备管理</h1>
          <p>注册、查看并管理所有受管终端上的 AI Agent 安全客户端。</p>
        </div>
        <div className="head-actions">
          <Button variant="outline" onClick={() => setShowForm(!showForm)}>
            {showForm ? <X size={16} /> : <Plus size={16} />}
            {showForm ? '取消' : '注册设备'}
          </Button>
        </div>
      </div>

      <Toast message={toast} />

      {/* KPI cards */}
      <div className="detail-kpis animate-entrance animate-entrance-2">
        <article><strong>{totalDevices}</strong><span>受管终端总数</span></article>
        <article><strong>{onlineDevices}</strong><span>当前在线</span></article>
        <article><strong>{coverage.toFixed(1)}%</strong><span>版本覆盖率</span></article>
      </div>

      {/* Registration form */}
      {showForm && <DeviceForm onCreate={() => { setShowForm(false); void fetchDevices(); notify('设备注册成功。'); }} notify={notify} />}

      {/* Search */}
      <div className="panel animate-entrance animate-entrance-3" style={{ marginBottom: 14 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <Search size={16} style={{ color: '#5e7c73', flexShrink: 0 }} />
          <input
            className="search-input"
            placeholder="搜索设备 ID、主机名或负责人..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            style={{ flex: 1, background: 'transparent', border: 'none', outline: 'none', color: '#eaf7f2', fontSize: 13 }}
          />
          {search && <button onClick={() => setSearch('')} style={{ background: 'none', border: 0, color: '#5e7c73', cursor: 'pointer' }}><X size={14} /></button>}
        </div>
      </div>

      {/* Device table */}
      <div className="panel animate-entrance animate-entrance-4">
        <div className="panel-head">
          <div>
            <h2>受管终端</h2>
            <p>{loading ? '加载中...' : `${filtered.length} 台设备${search ? ` (筛选自 ${devices.length} 台)` : ''}`}</p>
          </div>
        </div>

        {loading ? (
          <>{[1,2,3,4].map(i => <div className="skeleton-row" key={i}><div className="skeleton-cell" /><div className="skeleton-cell" /><div className="skeleton-cell" /><div className="skeleton-cell" /></div>)}</>
        ) : (
          <div className="data-table">
            <div className="data-head">
              <span>设备 ID</span><span>负责人 · 工具</span><span>Agent 版本</span><span>状态</span>
            </div>
            {filtered.map((d, i) => (
              <div key={d.device_id}>
                <div className="data-row animate-row-entrance" style={{ animationDelay: `${i * 30 + 200}ms` }}>
                  <strong>{d.device_id}</strong>
                  <span>{d.owner} · {AGENT_LABELS[d.agent_type] ?? d.agent_type}</span>
                  <span>{d.agent_version}</span>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                    <i className={STATUS_CLASS[d.status]}>{STATUS_LABELS[d.status]}</i>
                    <button className="icon-action" onClick={() => setEditId(editId === d.device_id ? null : d.device_id)} aria-label="编辑"><Pencil size={13} /></button>
                    {deleteConfirm === d.device_id ? (
                      <button className="icon-action danger" onClick={() => handleDelete(d.device_id)} aria-label="确认删除"><Check size={13} /></button>
                    ) : (
                      <button className="icon-action" onClick={() => setDeleteConfirm(d.device_id)} aria-label="删除"><Trash2 size={13} /></button>
                    )}
                  </div>
                </div>
                {editId === d.device_id && (
                  <EditPanel device={d} onSave={() => { setEditId(null); void fetchDevices(); notify('设备信息已更新。'); }} onCancel={() => setEditId(null)} notify={notify} />
                )}
                {deleteConfirm === d.device_id && (
                  <div style={{ padding: '8px 12px', fontSize: 11, color: '#ff8f88', background: '#1a1210', borderRadius: 6, margin: '4px 0' }}>
                    确认删除 {d.device_id}？此操作不可撤销。<button onClick={() => setDeleteConfirm(null)} style={{ marginLeft: 8, background: 'none', border: 0, color: '#7d9c92', cursor: 'pointer', fontSize: 11 }}>取消</button>
                  </div>
                )}
              </div>
            ))}
            {filtered.length === 0 && !loading && (
              <div style={{ padding: 32, textAlign: 'center', color: '#5e7c73', fontSize: 13 }}>
                {search ? '没有匹配的设备' : '暂无注册设备，点击「注册设备」添加'}
              </div>
            )}
          </div>
        )}
      </div>
    </>
  );
}

/* ─── Device Registration Form ──────────────────────────── */
function DeviceForm({ onCreate, notify }: { onCreate: () => void; notify: (m: string) => void }) {
  const [form, setForm] = useState({ device_id: '', hostname: '', owner: '', agent_type: 'cursor', notes: '' });
  const [submitting, setSubmitting] = useState(false);
  // useId 而非硬编码字符串：同一表单可能被多处渲染，硬编码会产生重复 id。
  const agentTypeId = useId();

  async function handleSubmit(e: React.SubmitEvent<HTMLFormElement>) {
    e.preventDefault();
    if (!form.device_id || !form.hostname || !form.owner) { notify('请填写所有必填字段。'); return; }
    setSubmitting(true);
    const res = await fetch('/api/devices', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(form) });
    setSubmitting(false);
    if (res.status === 201) { onCreate(); }
    else {
      const err = (await res.json().catch(() => ({}))) as { error?: string };
      notify(`注册失败: ${err.error ?? res.status}`);
    }
  }

  return (
    <form className="panel animate-entrance" onSubmit={handleSubmit} style={{ marginBottom: 14 }}>
      <div className="panel-head"><div><h2>注册新设备</h2><p>填写终端信息以纳入安全管理</p></div></div>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
        <Field label="设备 ID *" value={form.device_id} onChange={(v) => setForm({ ...form, device_id: v })} placeholder="ENG-MBP-1234" />
        <Field label="主机名 *" value={form.hostname} onChange={(v) => setForm({ ...form, hostname: v })} placeholder="eng-mbp-1234" />
        <Field label="负责人 *" value={form.owner} onChange={(v) => setForm({ ...form, owner: v })} placeholder="张三" />
        <div>
          <label htmlFor={agentTypeId} style={{ fontSize: 11, color: '#78968c', display: 'block', marginBottom: 4 }}>Agent 类型</label>
          <select id={agentTypeId} value={form.agent_type} onChange={(e) => setForm({ ...form, agent_type: e.target.value })} className="form-select">
            <option value="cursor">Cursor</option><option value="claude_code">Claude Code</option>
            <option value="codex_cli">Codex CLI</option><option value="windsurf">Windsurf</option><option value="other">其他</option>
          </select>
        </div>
      </div>
      <div style={{ marginTop: 12 }}>
        <Field label="备注" value={form.notes} onChange={(v) => setForm({ ...form, notes: v })} placeholder="可选备注信息" />
      </div>
      <div style={{ marginTop: 16, display: 'flex', gap: 8 }}>
        <Button type="submit" disabled={submitting}>{submitting ? '提交中...' : '注册设备'}</Button>
      </div>
    </form>
  );
}

/* ─── Inline Edit Panel ─────────────────────────────────── */
function EditPanel({ device, onSave, onCancel, notify }: { device: Device; onSave: () => void; onCancel: () => void; notify: (m: string) => void }) {
  const [form, setForm] = useState({ hostname: device.hostname, owner: device.owner, notes: device.notes ?? '' });
  const [saving, setSaving] = useState(false);

  async function handleSave() {
    setSaving(true);
    const res = await fetch('/api/devices', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ device_id: device.device_id, ...form }) });
    setSaving(false);
    if (res.ok) onSave(); else notify('更新失败，请重试。');
  }

  return (
    <div style={{ padding: '12px 16px', background: '#0a1613', border: '1px solid #1e332d', borderRadius: 8, margin: '4px 0 8px' }}>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 10 }}>
        <Field label="主机名" value={form.hostname} onChange={(v) => setForm({ ...form, hostname: v })} />
        <Field label="负责人" value={form.owner} onChange={(v) => setForm({ ...form, owner: v })} />
        <Field label="备注" value={form.notes} onChange={(v) => setForm({ ...form, notes: v })} />
      </div>
      <div style={{ marginTop: 10, display: 'flex', gap: 8 }}>
        <Button size="sm" onClick={handleSave} disabled={saving}>{saving ? '保存中...' : '保存'}</Button>
        <Button size="sm" variant="outline" onClick={onCancel}>取消</Button>
      </div>
    </div>
  );
}

/* ─── Shared Field ──────────────────────────────────────── */
function Field({ label, value, onChange, placeholder }: { label: string; value: string; onChange: (v: string) => void; placeholder?: string }) {
  const id = useId();
  return (
    <div>
      <label htmlFor={id} style={{ fontSize: 11, color: '#78968c', display: 'block', marginBottom: 4 }}>{label}</label>
      <input id={id} className="form-input" value={value} onChange={(e) => onChange(e.target.value)} placeholder={placeholder} />
    </div>
  );
}
