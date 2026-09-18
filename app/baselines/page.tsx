'use client';

/**
 * 基线管理(阶段E 真实 UI): 自定义基线导入/删除 + 上游同步 + 扫描模式切换。
 * 数据源: /api/baselines, /api/baselines/sync, /api/settings/scan-mode (PG 持久化)。
 */
import { useCallback, useEffect, useState } from 'react';
import { Trash2, RefreshCw, Upload } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { useRole } from '@/components/role-context';

interface Baseline {
  name: string;
  source: 'custom' | 'upstream';
  version: string;
  rules: Array<{ id: string; title: string; severity?: string; mode?: string }>;
  scan_modes: string[];
  updated_by: string;
  updated_at: number;
}

const MODES = ['quick', 'standard', 'custom'] as const;

const MODE_LABEL: Record<string, string> = {
  quick: '快速',
  standard: '标准',
  custom: '自定义',
};

const SOURCE_LABEL: Record<string, string> = {
  custom: '自定义',
  upstream: '上游',
};

export default function BaselinesPage() {
  const { role } = useRole();
  const isAdmin = role === 'admin';
  const [items, setItems] = useState<Baseline[] | null>(null);
  const [mode, setMode] = useState('standard');
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  // import form
  const [name, setName] = useState('');
  const [rulesText, setRulesText] = useState('[{"id":"no-eval","title":"禁止 eval","severity":"high","mode":"standard"}]');
  const [syncUrl, setSyncUrl] = useState('');
  const [upUrl, setUpUrl] = useState('');
  const [upMsg, setUpMsg] = useState('');

  const load = useCallback(async () => {
    try {
      const [b, m] = await Promise.all([
        fetch('/api/baselines', { cache: 'no-store' }).then((r) => (r.ok ? (r.json() as Promise<any>) : null)),
        fetch('/api/settings/scan-mode', { cache: 'no-store' }).then((r) => (r.ok ? (r.json() as Promise<any>) : null)),
      ]);
      setItems(Array.isArray(b?.baselines) ? b.baselines : []);
      if (m?.scan_mode) setMode(m.scan_mode);
      const st = await fetch('/api/settings', { cache: 'no-store' }).then((r) => (r.ok ? (r.json() as Promise<Record<string, unknown>>) : null)).catch(() => null);
      if (st?.upstream_baseline_url) setUpUrl(String(st.upstream_baseline_url));
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      setItems([]);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  async function doImport() {
    setError(''); setNotice('');
    let rules: unknown[] = [];
    try { rules = JSON.parse(rulesText); } catch { setError('规则 JSON 解析失败'); return; }
    const r = await fetch('/api/baselines', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name, rules }) });
    if (!r.ok) { setError(`导入失败 HTTP ${r.status}`); return; }
    setNotice(`已导入基线 ${name}`);
    setName('');
    void load();
  }

  async function doDelete(n: string) {
    setError(''); setNotice('');
    if (!window.confirm(`确认删除基线「${n}」？此操作不可撤销。`)) return;
    const r = await fetch(`/api/baselines?name=${encodeURIComponent(n)}`, { method: 'DELETE' });
    if (!r.ok) { setError(`删除失败 HTTP ${r.status}`); return; }
    setNotice(`已删除 ${n}`);
    void load();
  }

  async function saveUpUrl() {
    setUpMsg('');
    const r = await fetch('/api/settings', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ upstream_baseline_url: upUrl }) });
    setUpMsg(r.ok ? '已保存, 每6小时自动同步' : `保存失败 HTTP ${r.status}`);
  }

  async function doSync() {
    setError(''); setNotice('');
    const r = await fetch('/api/baselines/sync', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url: syncUrl || upUrl }) });
    if (!r.ok) { setError(`同步失败 HTTP ${r.status}`); return; }
    setNotice('上游基线已同步为 upstream-baseline');
    void load();
  }

  async function setScanMode(m: string) {
    setError(''); setNotice('');
    const r = await fetch('/api/settings/scan-mode', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ mode: m }) });
    if (!r.ok) { setError(`模式切换失败 HTTP ${r.status}`); return; }
    setMode(m);
    setNotice(`扫描模式已切换为 ${m}`);
  }

  return (
    <>
      <div className="page-head animate-entrance animate-entrance-1">
        <div>
          <p className="eyebrow">治理 / 编码规范基线</p>
          <h1>基线管理</h1>
          <p>支持自定义基线导入与上游同步；上游与自定义基线合并生效，同一规则以自定义为准。</p>
        </div>
      </div>

      {error && <p style={{ color: '#ff685f', marginBottom: 10, fontSize: 13 }}>{error}</p>}
      {notice && <p style={{ color: '#49e8a5', marginBottom: 10, fontSize: 13 }}>{notice}</p>}

      {/* scan mode */}
      <div className="panel animate-entrance animate-entrance-2" style={{ padding: 14, marginBottom: 14 }}>
        <strong style={{ fontSize: 14 }}>扫描模式</strong>
        <div style={{ display: 'flex', gap: 8, marginTop: 10, flexWrap: 'wrap' }}>
          {MODES.map((m) => (
            <Button key={m} variant={mode === m ? 'default' : 'outline'} disabled={!isAdmin} onClick={() => void setScanMode(m)}>
              {MODE_LABEL[m] ?? m}
            </Button>
          ))}
        </div>
        <p style={{ fontSize: 12, color: 'var(--muted-foreground)', marginTop: 8 }}>
          「快速」只检查密钥与依赖；「标准」在快速基础上增加核心代码安全与质量规则；「自定义」只包含已导入且终端可执行的基线规则（无可执行规则时不能发布）。
        </p>
      </div>

      {/* import + sync */}
      {isAdmin && (
        <div className="panel animate-entrance animate-entrance-3" style={{ padding: 14, marginBottom: 14, display: 'grid', gap: 10 }}>
          <strong style={{ fontSize: 14 }}>导入自定义基线</strong>
          <Input placeholder="基线名称(如 corp-baseline)" value={name} onChange={(e) => setName(e.target.value)} />
          <textarea
            rows={5}
            value={rulesText}
            onChange={(e) => setRulesText(e.target.value)}
            style={{ width: '100%', padding: 8, borderRadius: 8, border: '1px solid var(--border)', background: 'var(--panel)', color: 'var(--text)', fontSize: 12, fontFamily: 'monospace' }}
          />
          <div>
            <Button onClick={() => void doImport()} disabled={!name.trim()}>
              <Upload size={14} /> 导入
            </Button>
          </div>
          <strong style={{ fontSize: 14 }}>上游基线 URL(定时同步源)</strong>
          <div style={{ display: 'flex', gap: 8 }}>
            <Input placeholder="https://…/aegis-security-baseline.md" value={upUrl} onChange={(e) => setUpUrl(e.target.value)} />
            <Button variant="outline" onClick={() => void saveUpUrl()}>保存</Button>
          </div>
          {upMsg && <span style={{ fontSize: 12, color: 'var(--muted-foreground)' }}>{upMsg}</span>}
          <strong style={{ fontSize: 14 }}>立即同步</strong>
          <div style={{ display: 'flex', gap: 8 }}>
            <Input placeholder="上游基线 URL(如 https://…/aegis-security-baseline.md)" value={syncUrl} onChange={(e) => setSyncUrl(e.target.value)} />
            <Button variant="outline" onClick={() => void doSync()} disabled={!syncUrl.trim()}>
              <RefreshCw size={14} /> 同步
            </Button>
          </div>
        </div>
      )}

      {/* list */}
      <div style={{ display: 'grid', gap: 10 }}>
        {items === null ? (
          <p className="empty-hint">加载基线…</p>
        ) : items.length === 0 ? (
          <p className="empty-hint">暂无基线；导入自定义或同步上游后此处显示。</p>
        ) : (
          items.map((b) => (
            <div key={b.name} className="panel animate-entrance" style={{ padding: 14 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
                <strong>{b.name}</strong>
                <Badge variant="outline">{SOURCE_LABEL[b.source] ?? b.source}</Badge>
                <Badge variant="outline">v{b.version}</Badge>
                <span style={{ marginLeft: 'auto', fontSize: 12, color: 'var(--muted-foreground)' }}>
                  {b.updated_by} · {new Date(b.updated_at).toLocaleString()}
                </span>
                {isAdmin && b.source === 'custom' && (
                  <Button variant="outline" onClick={() => void doDelete(b.name)} aria-label="删除基线">
                    <Trash2 size={14} />
                  </Button>
                )}
              </div>
              <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginBottom: 6 }}>
                {b.scan_modes.map((m) => (
                  <Badge key={m} variant="outline">
                    {MODE_LABEL[m] ?? m}
                  </Badge>
                ))}
              </div>
              <ul style={{ fontSize: 12, color: 'var(--muted-foreground)', paddingLeft: 18, margin: 0 }}>
                {b.rules.slice(0, 8).map((r, i) => (
                  <li key={r.id ?? i}>
                    {r.title} {r.severity ? `(${r.severity})` : ''}
                  </li>
                ))}
                {b.rules.length > 8 && <li>…共 {b.rules.length} 条</li>}
              </ul>
            </div>
          ))
        )}
      </div>
      <EnterpriseMdPanel />
    </>
  );
}

/**
 * 企业级 MD 上传 + 灰度推送（用户自有基线）。发布后推送到 Collector，终端按灰度
 * 范围（全量/百分比/部门）拉取并附加进受管基线；与上游同步基线完全分离、互不影响。
 */
function EnterpriseMdPanel() {
  const [content, setContent] = useState('');
  const [mode, setMode] = useState<'all' | 'percent' | 'department'>('all');
  const [percent, setPercent] = useState(10);
  const [departments, setDepartments] = useState('');
  const [current, setCurrent] = useState<{ published: boolean; version?: number; rollout?: { mode?: string; percent?: number; departments?: string[] } } | null>(null);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState('');

  const load = useCallback(async () => {
    try {
      const r = await fetch('/api/baselines/enterprise', { cache: 'no-store' });
      if (r.ok) {
        const d = (await r.json()) as {
          published?: boolean;
          version?: number;
          content?: string;
          rollout?: { mode?: string; percent?: number; departments?: string[] };
        };
        setCurrent({ published: d.published === true, version: d.version, rollout: d.rollout });
        // 新浏览器/新会话打开时回填「已发布」的内容与灰度配置——否则编辑器为空，
        // 用户看不到自己以前写过什么（用户反馈）。仅在确有已发布内容时回填。
        if (d.published && typeof d.content === 'string') setContent(d.content);
        const ro = d.rollout;
        if (ro && (ro.mode === 'all' || ro.mode === 'percent' || ro.mode === 'department')) setMode(ro.mode);
        if (ro && typeof ro.percent === 'number') setPercent(ro.percent);
        if (ro && Array.isArray(ro.departments)) setDepartments(ro.departments.join(','));
      } else setCurrent({ published: false });
    } catch { setCurrent({ published: false }); }
  }, []);
  useEffect(() => { void load(); }, [load]);

  async function publish() {
    if (!content.trim()) { setMsg('内容不能为空'); return; }
    setBusy(true); setMsg('');
    try {
      const rollout = mode === 'percent' ? { mode, percent } : mode === 'department' ? { mode, departments: departments.split(/[,，\s]+/).filter(Boolean) } : { mode };
      const r = await fetch('/api/baselines/enterprise', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ content, rollout }) });
      const d = (await r.json().catch(() => ({}))) as { version?: number; error?: string };
      setMsg(r.ok ? `已发布 v${d.version} 并推送到 Collector（终端按灰度拉取）` : `发布失败：${d.error ?? r.status}`);
      if (r.ok) void load();
    } catch { setMsg('发布失败：网络错误'); }
    setBusy(false);
  }

  return (
    <div className="panel" style={{ marginTop: 16 }}>
      <div className="panel-head">
        <div>
          <h2>企业级 MD（自有基线）上传与灰度推送</h2>
          <p>
            {current?.published
              ? `当前 v${current.version} · 灰度=${current.rollout?.mode}${current.rollout?.mode === 'percent' ? ` ${current.rollout.percent}%` : ''}${current.rollout?.mode === 'department' ? ` ${(current.rollout.departments ?? []).join(',')}` : ''}`
              : '尚未发布企业级 MD'}
            ；与上游同步基线分离，作为附加基线下发到终端，互不覆盖。
          </p>
        </div>
      </div>
      <div style={{ display: 'grid', gap: 10 }}>
        <textarea className="form-input" rows={8} placeholder="粘贴企业级安全基线 Markdown 内容…" value={content} onChange={(e) => setContent(e.target.value)} />
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
          <label style={{ fontSize: 12 }}>灰度范围</label>
          <select className="form-input" style={{ width: 140 }} value={mode} onChange={(e) => setMode(e.target.value as typeof mode)}>
            <option value="all">全量</option>
            <option value="percent">百分比</option>
            <option value="department">部门</option>
          </select>
          {mode === 'percent' && (
            <input className="form-input" style={{ width: 90 }} type="number" min={0} max={100} value={percent} onChange={(e) => setPercent(Number(e.target.value) || 0)} />
          )}
          {mode === 'department' && (
            <input className="form-input" style={{ flex: 1 }} placeholder="部门列表，逗号分隔（如 研发,安全）" value={departments} onChange={(e) => setDepartments(e.target.value)} />
          )}
          <Button onClick={() => void publish()} disabled={busy}>{busy ? '发布中…' : '发布并推送'}</Button>
        </div>
        {msg && <p style={{ fontSize: 12, color: 'var(--muted-foreground)' }}>{msg}</p>}
      </div>
    </div>
  );
}
