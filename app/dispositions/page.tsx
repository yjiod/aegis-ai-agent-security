'use client';

/**
 * 处置中心：对识别到的 Skill / MCP 打标 + 处置（加白 / 观察 / 拉黑）。
 * 数据源 = /api/labels（PG 持久化的真实注册表），非演示数据。
 * "导入策略已知 Skill" 从 /downloads/aegis-policy.json 的 allowed_skills 预置为加白。
 * "策略预览" 展示若按当前处置发布，策略的 allowed / monitor / blocked 列表将变成什么
 * （实际发布走发行级联，由管理员执行）。
 */
import { useCallback, useEffect, useMemo, useState } from 'react';
import { Tags, ShieldCheck, ShieldAlert, Eye, Plus, Trash2, Download } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { useRole } from '@/components/role-context';
import { RiskSignalHelp } from '@/components/risk-signal-help';

interface Label {
  asset_type: 'skill' | 'mcp';
  asset_key: string;
  tags: string[];
  disposition: '' | 'allow' | 'monitor' | 'deny';
  note: string;
  updated_by: string;
  updated_at: number;
}

const DISP_META: Record<Label['disposition'], { label: string; tone: string; icon: typeof Eye }> = {
  '': { label: '未处置', tone: 'outline', icon: Eye },
  allow: { label: '加白', tone: 'green', icon: ShieldCheck },
  monitor: { label: '观察', tone: 'blue', icon: Eye },
  deny: { label: '拉黑', tone: 'red', icon: ShieldAlert },
};

function relTime(ts: number): string {
  if (!ts) return '—';
  const s = Math.max(0, Math.floor((Date.now() - ts) / 1000));
  if (s < 60) return `${s} 秒前`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m} 分钟前`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h} 小时前`;
  return `${Math.floor(h / 24)} 天前`;
}

export default function DispositionsPage() {
  const { role } = useRole();
  const isAdmin = role === 'admin';
  const [labels, setLabels] = useState<Label[] | null>(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  // add form
  const [newType, setNewType] = useState<'skill' | 'mcp'>('skill');
  const [newKey, setNewKey] = useState('');

  const load = useCallback(async () => {
    try {
      const r = await fetch('/api/labels', { cache: 'no-store' });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const d = (await r.json()) as { labels?: Label[] };
      setLabels(Array.isArray(d.labels) ? d.labels : []);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      setLabels([]);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  async function save(asset: Label, patch: Partial<Label>) {
    setBusy(true);
    setError('');
    try {
      const r = await fetch('/api/labels', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ asset_type: asset.asset_type, asset_key: asset.asset_key, ...patch }),
      });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  async function addAsset() {
    const key = newKey.trim();
    if (!key) return;
    setBusy(true);
    setError('');
    try {
      const r = await fetch('/api/labels', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ asset_type: newType, asset_key: key, disposition: '', tags: [] }),
      });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      setNewKey('');
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  async function removeAsset(asset: Label) {
    setBusy(true);
    setError('');
    try {
      await fetch(`/api/labels?asset_type=${asset.asset_type}&asset_key=${encodeURIComponent(asset.asset_key)}`, { method: 'DELETE' });
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  async function importFromPolicy() {
    setBusy(true);
    setError('');
    try {
      const r = await fetch('/downloads/aegis-policy.json', { cache: 'no-store' });
      if (!r.ok) throw new Error(`policy HTTP ${r.status}`);
      const policy = (await r.json()) as { allowed_skills?: string[] };
      const skills = Array.isArray(policy.allowed_skills) ? policy.allowed_skills : [];
      for (const s of skills) {
        await fetch('/api/labels', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ asset_type: 'skill', asset_key: s, disposition: 'allow', tags: ['策略已知'] }),
        });
      }
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  const preview = useMemo(() => {
    const allow = (labels ?? []).filter((l) => l.disposition === 'allow').map((l) => l.asset_key);
    const monitor = (labels ?? []).filter((l) => l.disposition === 'monitor').map((l) => l.asset_key);
    const deny = (labels ?? []).filter((l) => l.disposition === 'deny').map((l) => l.asset_key);
    return { allow, monitor, deny };
  }, [labels]);

  return (
    <>
      <div className="page-head animate-entrance animate-entrance-1">
        <div>
          <p className="eyebrow">治理 / 处置中心</p>
          <h1>Skill / MCP 打标与处置</h1>
          <p>对识别到的资产打业务标签，并决定加白 / 观察 / 拉黑；处置持久化并可发布为策略。</p>
        </div>
        <div className="head-actions">
          {isAdmin && (
            <Button variant="outline" onClick={() => void importFromPolicy()} disabled={busy}>
              <Download size={15} />
              导入策略已知 Skill
            </Button>
          )}
        </div>
      </div>

      <RiskSignalHelp />

      {error && (
        <p style={{ color: '#ff685f', marginBottom: 12, fontSize: 13 }}>操作失败：{error}</p>
      )}

      {/* add asset */}
      {isAdmin && (
        <div className="panel animate-entrance animate-entrance-2" style={{ padding: 16, marginBottom: 16, display: 'flex', gap: 10, flexWrap: 'wrap', alignItems: 'center' }}>
          <select value={newType} onChange={(e) => setNewType(e.target.value as 'skill' | 'mcp')} style={{ padding: '6px 8px', borderRadius: 6, border: '1px solid var(--border)', background: 'var(--panel)', color: 'var(--text)' }}>
            <option value="skill">Skill</option>
            <option value="mcp">MCP</option>
          </select>
          <Input placeholder="资产标识（如 skill 名 / MCP server 或命令）" value={newKey} onChange={(e) => setNewKey(e.target.value)} style={{ maxWidth: 360 }} />
          <Button onClick={() => void addAsset()} disabled={busy || !newKey.trim()}>
            <Plus size={15} />
            添加资产
          </Button>
        </div>
      )}

      {/* labels list */}
      <div className="panel animate-entrance animate-entrance-3" style={{ padding: 8 }}>
        {labels === null ? (
          <p className="empty-hint">加载处置注册表…</p>
        ) : labels.length === 0 ? (
          <p className="empty-hint">暂无打标资产。可手动添加，或点"导入策略已知 Skill"预置加白。</p>
        ) : (
          labels.map((l) => {
            const meta = DISP_META[l.disposition];
            const Icon = meta.icon;
            return (
              <div key={`${l.asset_type}:${l.asset_key}`} style={{ display: 'flex', gap: 12, alignItems: 'center', padding: '10px 10px', borderBottom: '1px solid var(--border)', flexWrap: 'wrap' }}>
                <Badge variant="outline">{l.asset_type}</Badge>
                <strong style={{ minWidth: 180 }}>{l.asset_key}</strong>
                <span style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                  {l.tags.map((t) => (
                    <Badge key={t} variant="outline">
                      <Tags size={11} />
                      {t}
                    </Badge>
                  ))}
                </span>
                <Badge variant="outline">
                  <Icon size={12} />
                  {meta.label}
                </Badge>
                <span style={{ color: 'var(--muted)', fontSize: 12 }}>
                  {l.updated_by} · {relTime(l.updated_at)}
                </span>
                {isAdmin && (
                  <span style={{ marginLeft: 'auto', display: 'flex', gap: 6, alignItems: 'center' }}>
                    <select
                      value={l.disposition}
                      disabled={busy}
                      onChange={(e) => void save(l, { disposition: e.target.value as Label['disposition'] })}
                      style={{ padding: '4px 6px', borderRadius: 6, border: '1px solid var(--border)', background: 'var(--panel)', color: 'var(--text)', fontSize: 12 }}
                    >
                      <option value="">未处置</option>
                      <option value="allow">加白</option>
                      <option value="monitor">观察</option>
                      <option value="deny">拉黑</option>
                    </select>
                    <Input
                      placeholder="标签,逗号分隔"
                      defaultValue={l.tags.join(',')}
                      disabled={busy}
                      onBlur={(e) => {
                        const tags = e.target.value.split(',').map((s) => s.trim()).filter(Boolean);
                        if (tags.join(',') !== l.tags.join(',')) void save(l, { tags });
                      }}
                      style={{ width: 150, fontSize: 12 }}
                    />
                    <Button variant="outline" onClick={() => void removeAsset(l)} disabled={busy} aria-label="删除">
                      <Trash2 size={14} />
                    </Button>
                  </span>
                )}
              </div>
            );
          })
        )}
      </div>

      {/* policy preview */}
      <div className="panel animate-entrance animate-entrance-4" style={{ padding: 16, marginTop: 16 }}>
        <h2 style={{ fontSize: 15, marginBottom: 8 }}>策略发布预览</h2>
        <p style={{ color: 'var(--muted)', fontSize: 12, marginBottom: 10 }}>
          若按当前处置发布，策略列表将变为（实际发布走发行级联，由管理员执行）：
        </p>
        <p style={{ fontSize: 13 }}>
          <b>加白(allowed)</b>：{preview.allow.join(', ') || '（空）'}
        </p>
        <p style={{ fontSize: 13 }}>
          <b>观察(monitor)</b>：{preview.monitor.join(', ') || '（空）'}
        </p>
        <p style={{ fontSize: 13 }}>
          <b>拉黑(blocked)</b>：{preview.deny.join(', ') || '（空）'}
        </p>
      </div>
    </>
  );
}
