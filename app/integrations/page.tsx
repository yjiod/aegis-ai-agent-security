'use client';

/**
 * 接入中心(集成控制面): 列出已集成平台(Fleet/Wazuh/PacketFence/商用) + 健康 + 能力 + 策略映射。
 * 单端原则: 员工终端只推 Aegis 一个 agent; 各平台 agent 由其平台/桌管下发, Aegis 不代推。
 */
import { useCallback, useEffect, useState } from 'react';
import { Plug, ShieldCheck, AlertTriangle, HelpCircle } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';

interface Integration {
  name: string;
  role: string;
  capabilities: string[];
  health: 'ok' | 'down' | 'unconfigured';
  detail?: string;
  alerts?: number;
}

const HEALTH_META: Record<Integration['health'], { label: string; icon: typeof ShieldCheck; tone: string }> = {
  ok: { label: '在线', icon: ShieldCheck, tone: 'green' },
  down: { label: '不可达', icon: AlertTriangle, tone: 'red' },
  unconfigured: { label: '未配置', icon: HelpCircle, tone: 'outline' },
};

export default function IntegrationsPage() {
  const [items, setItems] = useState<Integration[] | null>(null);
  const [cfg, setCfg] = useState<Record<string, string>>({});
  const [cfgMsg, setCfgMsg] = useState('');
  const [error, setError] = useState('');

  const load = useCallback(async () => {
    try {
      const r = await fetch('/api/integrations', { cache: 'no-store' });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const d = (await r.json()) as { integrations?: Integration[] };
      setItems(Array.isArray(d.integrations) ? d.integrations : []);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      setItems([]);
    }
  }, []);

  useEffect(() => {
    void load();
    fetch('/api/integrations/config', { cache: 'no-store' })
      .then((r) => (r.ok ? r.json() : null))
      .then((d) => d && setCfg(d as Record<string, string>))
      .catch(() => {});
  }, [load]);

  async function saveCfg() {
    setCfgMsg('');
    const r = await fetch('/api/integrations/config', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(cfg) });
    setCfgMsg(r.ok ? '已保存' : `保存失败 HTTP ${r.status}`);
    void load();
  }

  return (
    <>
      <div className="page-head animate-entrance animate-entrance-1">
        <div>
          <p className="eyebrow">治理 / 接入中心</p>
          <h1>集成控制面</h1>
          <p>统一查看已集成的准入/EDR/桌管平台健康与能力；均经厂商中立契约接入，可替换。</p>
        </div>
      </div>

      {error && <p style={{ color: '#ff685f', marginBottom: 12, fontSize: 13 }}>加载失败：{error}</p>}

      <div className="panel animate-entrance animate-entrance-2" style={{ padding: 14, marginBottom: 14, display: 'flex', gap: 8, alignItems: 'center', fontSize: 13, color: 'var(--muted-foreground)' }}>
        <Plug size={15} />
        单端原则：员工终端只推送 <b style={{ color: 'var(--text)' }}>Aegis 一个 agent</b>；Fleet/Wazuh/PacketFence 的 agent 由各自平台或桌管下发，Aegis 不代推。
      </div>

      <div className="panel animate-entrance animate-entrance-3" style={{ padding: 14, marginBottom: 14 }}>
        <strong style={{ fontSize: 14 }}>集成配置（settings 优先, 留空回退环境变量）</strong>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit,minmax(220px,1fr))', gap: 8, marginTop: 10 }}>
          {['fleet_url','fleet_token','wazuh_url','wazuh_user','wazuh_pass','pf_url','pf_token'].map((k) => (
            <label key={k} style={{ fontSize: 12, color: 'var(--muted-foreground)', display: 'grid', gap: 4 }}>
              {k}
              <input
                value={cfg[k] ?? ''}
                onChange={(e) => setCfg((c) => ({ ...c, [k]: e.target.value }))}
                style={{ padding: 6, borderRadius: 6, border: '1px solid var(--border)', background: 'var(--panel)', color: 'var(--text)', fontSize: 12 }}
              />
            </label>
          ))}
        </div>
        <div style={{ marginTop: 10, display: 'flex', gap: 8, alignItems: 'center' }}>
          <Button onClick={() => void saveCfg()}>保存配置</Button>
          {cfgMsg && <span style={{ fontSize: 12, color: 'var(--muted-foreground)' }}>{cfgMsg}</span>}
        </div>
      </div>

      <div style={{ display: 'grid', gap: 12 }}>
        {items === null ? (
          <p className="empty-hint">加载集成列表…</p>
        ) : items.length === 0 ? (
          <p className="empty-hint">暂无集成配置。在控制台环境配置 AEGIS_INT_*_URL/TOKEN 后此处显示。</p>
        ) : (
          items.map((it) => {
            const meta = HEALTH_META[it.health];
            const Icon = meta.icon;
            return (
              <div key={it.name} className="panel animate-entrance" style={{ padding: 14 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}>
                  <strong style={{ fontSize: 15 }}>{it.name}</strong>
                  <Badge variant="outline">
                    <Icon size={12} />
                    {meta.label}
                  </Badge>
                  {(it.alerts ?? 0) > 0 && (
                    <Badge variant="outline" style={{ borderColor: '#ff685f', color: '#ff685f' }}>
                      <AlertTriangle size={12} />
                      {it.alerts} 告警
                    </Badge>
                  )}
                  <span style={{ marginLeft: 'auto', fontSize: 12, color: 'var(--muted-foreground)' }}>{it.detail ?? ''}</span>
                </div>
                <p style={{ fontSize: 13, color: 'var(--muted-foreground)', marginBottom: 8 }}>{it.role}</p>
                <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                  {it.capabilities.map((c) => (
                    <Badge key={c} variant="outline">
                      {c}
                    </Badge>
                  ))}
                </div>
              </div>
            );
          })
        )}
      </div>
    </>
  );
}
