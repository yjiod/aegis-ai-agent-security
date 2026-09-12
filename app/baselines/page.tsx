'use client';

/**
 * 基线管理(阶段E 真实 UI): 自定义基线导入/删除 + 上游同步 + 扫描模式切换。
 * 数据源: /api/baselines, /api/baselines/sync, /api/settings/scan-mode (PG 持久化)。
 */
import { useCallback, useEffect, useState } from 'react';
import { Plus, Trash2, RefreshCw, Upload } from 'lucide-react';
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

const MODES = ['quick', 'standard', 'deep', 'custom'] as const;

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

  const load = useCallback(async () => {
    try {
      const [b, m] = await Promise.all([
        fetch('/api/baselines', { cache: 'no-store' }).then((r) => (r.ok ? r.json() : null)),
        fetch('/api/settings/scan-mode', { cache: 'no-store' }).then((r) => (r.ok ? r.json() : null)),
      ]);
      setItems(Array.isArray(b?.baselines) ? b.baselines : []);
      if (m?.scan_mode) setMode(m.scan_mode);
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
    await fetch(`/api/baselines?name=${encodeURIComponent(n)}`, { method: 'DELETE' });
    setNotice(`已删除 ${n}`);
    void load();
  }

  async function doSync() {
    setError(''); setNotice('');
    const r = await fetch('/api/baselines/sync', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url: syncUrl }) });
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
          <p>自定义基线导入 + 上游同步 + 扫描模式；生效=upstream+custom 合并(同 id 自定义优先)。</p>
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
              {m}
            </Button>
          ))}
        </div>
        <p style={{ fontSize: 12, color: 'var(--muted)', marginTop: 8 }}>
          quick=密钥+依赖；standard=+核心 SAST；deep=+污点/CodeQL+AI 审查；custom=仅自定义规则。
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
          <strong style={{ fontSize: 14 }}>上游同步</strong>
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
                <Badge variant="outline">{b.source}</Badge>
                <Badge variant="outline">v{b.version}</Badge>
                <span style={{ marginLeft: 'auto', fontSize: 12, color: 'var(--muted)' }}>
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
                    {m}
                  </Badge>
                ))}
              </div>
              <ul style={{ fontSize: 12, color: 'var(--muted)', paddingLeft: 18, margin: 0 }}>
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
    </>
  );
}
