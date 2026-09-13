'use client';

/**
 * 接入中心(集成控制面): 列出已集成平台(Fleet/Wazuh/PacketFence/商用) + 健康 + 能力 + 策略映射。
 * 单端原则: 员工终端只推 Aegis 一个 agent; 各平台 agent 由其平台/桌管下发, Aegis 不代推。
 */
import { useCallback, useEffect, useState } from 'react';
import { Plug, ShieldCheck, AlertTriangle, HelpCircle } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { useRole } from '@/components/role-context';

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

/** 明文可回显字段 vs 敏感字段（token/口令：永不回显明文，只在用户输入新值时提交）。 */
const PLAIN_KEYS = ['fleet_url', 'wazuh_url', 'wazuh_user', 'pf_url'] as const;
const SECRET_KEYS = ['fleet_token', 'wazuh_pass', 'pf_token'] as const;

const FIELD_LABEL: Record<string, string> = {
  fleet_url: 'Fleet 地址',
  fleet_token: 'Fleet Token',
  wazuh_url: 'Wazuh 地址',
  wazuh_user: 'Wazuh 用户',
  wazuh_pass: 'Wazuh 口令',
  pf_url: 'PacketFence 地址',
  pf_token: 'PacketFence Token',
};

export default function IntegrationsPage() {
  const { role } = useRole();
  const isAdmin = role === 'admin';
  const [items, setItems] = useState<Integration[] | null>(null);
  const [cfg, setCfg] = useState<Record<string, string>>({});
  const [secretConfigured, setSecretConfigured] = useState<Record<string, boolean>>({});
  const [secretDraft, setSecretDraft] = useState<Record<string, string>>({});
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
      .then((r) => (r.ok ? (r.json() as Promise<Record<string, string>>) : null))
      .then((d) => {
        if (!d) return;
        const plain: Record<string, string> = {};
        for (const k of PLAIN_KEYS) plain[k] = d[k] ?? '';
        const configured: Record<string, boolean> = {};
        for (const k of SECRET_KEYS) configured[k] = Boolean(d[k]);
        setCfg(plain);
        setSecretConfigured(configured);
      })
      .catch(() => {});
  }, [load]);

  async function saveCfg() {
    setCfgMsg('');
    // 只提交明文字段 + 管理员真正输入了新值的敏感字段；
    // 留空的敏感字段不进入 payload，避免用掩码串覆盖真实凭据。
    const payload: Record<string, string> = { ...cfg };
    for (const k of SECRET_KEYS) {
      const v = (secretDraft[k] ?? '').trim();
      if (v) payload[k] = v;
    }
    const r = await fetch('/api/integrations/config', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
    setCfgMsg(r.ok ? '已保存' : `保存失败 HTTP ${r.status}`);
    if (r.ok) setSecretDraft({});
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
        {!isAdmin && (
          <p style={{ fontSize: 12, color: 'var(--muted-foreground)', marginTop: 6 }}>
            只读身份：仅管理员可编辑集成配置。
          </p>
        )}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit,minmax(220px,1fr))', gap: 8, marginTop: 10 }}>
          {PLAIN_KEYS.map((k) => (
            <label key={k} style={{ fontSize: 12, color: 'var(--muted-foreground)', display: 'grid', gap: 4 }}>
              {FIELD_LABEL[k] ?? k}
              <input
                value={cfg[k] ?? ''}
                disabled={!isAdmin}
                onChange={(e) => setCfg((c) => ({ ...c, [k]: e.target.value }))}
                style={{ padding: 6, borderRadius: 6, border: '1px solid var(--border)', background: 'var(--panel)', color: 'var(--text)', fontSize: 12 }}
              />
            </label>
          ))}
          {SECRET_KEYS.map((k) => (
            <label key={k} style={{ fontSize: 12, color: 'var(--muted-foreground)', display: 'grid', gap: 4 }}>
              {FIELD_LABEL[k] ?? k}
              <input
                type="password"
                value={secretDraft[k] ?? ''}
                disabled={!isAdmin}
                autoComplete="new-password"
                placeholder={secretConfigured[k] ? '已配置 · 留空保持不变' : '未配置 · 输入以配置'}
                onChange={(e) => setSecretDraft((c) => ({ ...c, [k]: e.target.value }))}
                style={{ padding: 6, borderRadius: 6, border: '1px solid var(--border)', background: 'var(--panel)', color: 'var(--text)', fontSize: 12 }}
              />
            </label>
          ))}
        </div>
        {isAdmin && (
          <div style={{ marginTop: 10, display: 'flex', gap: 8, alignItems: 'center' }}>
            <Button onClick={() => void saveCfg()}>保存配置</Button>
            {cfgMsg && <span style={{ fontSize: 12, color: 'var(--muted-foreground)' }}>{cfgMsg}</span>}
          </div>
        )}
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
