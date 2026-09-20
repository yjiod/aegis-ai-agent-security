'use client';

/**
 * components/canary-panel.tsx — Agent 自更新灰度（canary）运营面板。
 *
 * 让"放量比例/通道/开关"从手改 JSON 变成控制台旋钮（admin 可改，下次发布策略生效），
 * 并把灰度分桶可视化：每台设备的桶号（sha256(device_id)%100，与终端 in_rollout 逐位
 * 一致）、是否在放量内、是否 pinned/exempt、当前版本、以及"这次到底会不会更新"的预测。
 *
 * 只读角色（auditor/viewer 等）看得到灰度态势但改不了旋钮。
 */

import { useCallback, useEffect, useMemo, useState } from 'react';
import { Gauge, Save, AlertTriangle } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { useRole } from '@/components/role-context';

interface RolloutConfig {
  enabled: boolean;
  channel: string;
  rollout_percent: number;
}
interface CohortDevice {
  device_id: string;
  hostname?: string;
  agent_version?: string;
  status?: string;
  pinned?: boolean;
  exempt?: boolean;
  rollout_bucket?: number;
  in_canary?: boolean;
  self_update?: { updated?: boolean; reason?: string; from?: string; to?: string; latest?: string; at?: number };
}

/** 自更"坏结果"：preflight 拒绝 / 自动回滚 / 应用失败。'ok'(成功更新)不算异常。 */
function isBadSelfUpdate(reason?: string): boolean {
  return !!reason && reason !== 'ok' && (reason.startsWith('preflight_failed') || reason.startsWith('rolled_back') || reason.startsWith('apply_failed'));
}

function semverNewer(candidate: string, current: string): boolean {
  const pa = String(candidate).split('.').map((n) => Number.parseInt(n, 10) || 0);
  const pb = String(current).split('.').map((n) => Number.parseInt(n, 10) || 0);
  for (let i = 0; i < 3; i += 1) {
    const x = pa[i] ?? 0;
    const y = pb[i] ?? 0;
    if (x !== y) return x > y;
  }
  return false;
}

type Prediction = 'will_update' | 'up_to_date' | 'pinned' | 'out_of_canary' | 'disabled';

function rolloutEq(a: RolloutConfig | null, b: RolloutConfig | null): boolean {
  return !!a && !!b && a.enabled === b.enabled && a.channel === b.channel && a.rollout_percent === b.rollout_percent;
}
function rolloutText(c: RolloutConfig | null): string {
  if (!c) return '—';
  return `${c.channel} ${c.rollout_percent}%${c.enabled ? '' : '·关'}`;
}

function predict(d: CohortDevice, cfg: RolloutConfig, latest: string): Prediction {
  if (!cfg.enabled) return 'disabled';
  if (d.pinned) return 'pinned';
  if (!d.in_canary) return 'out_of_canary';
  const cur = d.agent_version ?? '';
  if (latest && cur && semverNewer(latest, cur)) return 'will_update';
  return 'up_to_date';
}

const PREDICT_LABEL: Record<Prediction, { text: string; cls: string }> = {
  will_update: { text: '会更新', cls: 'pass' },
  up_to_date: { text: '已最新', cls: '' },
  pinned: { text: '自更保护·跳过', cls: 'warn' },
  out_of_canary: { text: '不在灰度', cls: '' },
  disabled: { text: '自更已关', cls: 'warn' },
};

export function CanaryPanel({ latestAgentVersion }: { latestAgentVersion?: string }) {
  const { role } = useRole();
  const isAdmin = role === 'admin';
  const latest = latestAgentVersion ?? '';

  const [cfg, setCfg] = useState<RolloutConfig | null>(null);
  const [channels, setChannels] = useState<string[]>(['pilot', 'beta', 'stable']);
  const [devices, setDevices] = useState<CohortDevice[]>([]);
  const [draft, setDraft] = useState<RolloutConfig>({ enabled: true, channel: 'pilot', rollout_percent: 50 });
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState('');
  // 当前**已发布策略**里的 agent_self_update（终端实际生效值）；null=尚无已发布策略。
  const [published, setPublished] = useState<RolloutConfig | null>(null);
  const [hasRelease, setHasRelease] = useState(false);

  const load = useCallback(async () => {
    try {
      const [r, d, p] = await Promise.all([
        fetch('/api/settings/rollout', { cache: 'no-store' }),
        fetch('/api/devices', { cache: 'no-store' }),
        fetch('/api/policy/current', { cache: 'no-store' }),
      ]);
      if (r.ok) {
        const j = (await r.json()) as { rollout?: RolloutConfig; channels?: string[] };
        if (j.rollout) { setCfg(j.rollout); setDraft(j.rollout); }
        if (Array.isArray(j.channels) && j.channels.length) setChannels(j.channels);
      }
      if (d.ok) {
        const dj = (await d.json()) as { devices?: CohortDevice[] };
        setDevices(Array.isArray(dj.devices) ? dj.devices : []);
      }
      if (p.ok) {
        const pj = (await p.json()) as { published?: boolean; policy?: { agent_self_update?: { enabled?: unknown; channel?: unknown; rollout_percent?: unknown } } };
        setHasRelease(pj.published === true);
        const su = pj.policy?.agent_self_update;
        if (pj.published && su) {
          setPublished({
            enabled: su.enabled !== false,
            channel: typeof su.channel === 'string' ? su.channel : 'pilot',
            rollout_percent: typeof su.rollout_percent === 'number' ? su.rollout_percent : 0,
          });
        } else {
          setPublished(null);
        }
      }
    } catch {
      /* 保持现状，诚实不伪造 */
    }
  }, []);

  useEffect(() => { void load(); }, [load]);

  async function save() {
    if (!isAdmin) return;
    setBusy(true);
    setMsg('');
    try {
      const res = await fetch('/api/settings/rollout', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(draft),
      });
      if (res.ok) {
        const j = (await res.json()) as { rollout?: RolloutConfig };
        if (j.rollout) { setCfg(j.rollout); setDraft(j.rollout); }
        setMsg('已保存。下次「发布策略」后对终端生效（终端按 device_id 分桶，桶号 < 放量比例才自更新）。');
      } else {
        const j = (await res.json().catch(() => ({}))) as { details?: string[]; error?: string };
        setMsg(`保存失败：${(j.details ?? []).join('；') || j.error || `HTTP ${res.status}`}`);
      }
    } catch {
      setMsg('保存失败：网络错误');
    }
    setBusy(false);
  }

  const cohort = useMemo(() => {
    const rows = devices.map((d) => ({ d, pred: predict(d, cfg ?? draft, latest) }));
    // 会更新的排前面，其次按桶号
    const order: Record<Prediction, number> = { will_update: 0, pinned: 1, out_of_canary: 2, up_to_date: 3, disabled: 4 };
    rows.sort((a, b) => order[a.pred] - order[b.pred] || (a.d.rollout_bucket ?? 0) - (b.d.rollout_bucket ?? 0));
    return rows;
  }, [devices, cfg, draft, latest]);

  const inCanaryCount = devices.filter((d) => d.in_canary).length;
  const willUpdateCount = cohort.filter((r) => r.pred === 'will_update').length;
  const pct = cfg?.rollout_percent ?? draft.rollout_percent;
  // canary 监控闭环：终端把"坏更新被 preflight 拒绝 / 自动回滚 / 应用失败"随报告上报，
  // 这里聚合展示——灰度放量期间若某台回滚/被拒，运维能立刻看到而不是只翻终端日志。
  const badUpdates = devices.filter((d) => isBadSelfUpdate(d.self_update?.reason));
  // 运营可见性：区分「未保存的本地修改」与「已保存但尚未发布生效」两种状态，
  // 避免管理员改了放量却以为已经生效（灰度设置只在发布策略时才注入签名策略下发终端）。
  const dirty = !rolloutEq(draft, cfg);
  const pendingPublish = !hasRelease || !rolloutEq(cfg, published);

  return (
    <div className="panel animate-entrance" style={{ padding: 16, marginTop: 16 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
        <Gauge size={16} />
        <h2 style={{ margin: 0, fontSize: 15 }}>自更新灰度（canary）</h2>
        <Badge variant="outline" style={{ marginLeft: 'auto', fontSize: 10 }}>
          放量 {pct}% · 灰度内 {inCanaryCount}/{devices.length} 台 · 预计更新 {willUpdateCount} 台
          {badUpdates.length > 0 ? ` · 自更异常 ${badUpdates.length} 台` : ''}
        </Badge>
      </div>
      <p style={{ fontSize: 12, color: 'var(--muted-foreground)', margin: '0 0 14px' }}>
        无桌管环境的兜底自更新按 device_id 稳定哈希分桶（桶号 &lt; 放量比例才更新）。先用小比例 canary 验证新版本，
        确认无异常再逐步放量到 100%。pinned（自更保护）设备永远跳过。改动需「发布策略」后生效。
      </p>

      {badUpdates.length > 0 && (
        <div
          style={{
            display: 'flex', alignItems: 'flex-start', gap: 8, padding: '10px 12px', marginBottom: 14,
            borderRadius: 8, background: 'color-mix(in srgb, var(--destructive) 12%, transparent)',
            border: '1px solid color-mix(in srgb, var(--destructive) 40%, transparent)', fontSize: 12, lineHeight: 1.6,
          }}
        >
          <AlertTriangle size={14} style={{ color: 'var(--destructive)', flexShrink: 0, marginTop: 2 }} />
          <span style={{ color: 'var(--foreground)' }}>
            <strong>{badUpdates.length} 台设备自更新异常</strong>（preflight 拒绝 / 自动回滚 / 应用失败）——坏更新已被终端自行拦截，未生效：
            {badUpdates.slice(0, 6).map((d) => (
              <span key={d.device_id} style={{ display: 'block', marginLeft: 4, color: 'var(--muted-foreground)' }}>
                · {d.hostname || d.device_id}：{d.self_update?.reason}
                {d.self_update?.latest ? `（目标 ${d.self_update.latest}）` : ''}
              </span>
            ))}
            {badUpdates.length > 6 ? <span style={{ display: 'block', marginLeft: 4, color: 'var(--muted-foreground)' }}>… 另有 {badUpdates.length - 6} 台</span> : null}
          </span>
        </div>
      )}

      {(dirty || pendingPublish) && (
        <div
          style={{
            display: 'flex', alignItems: 'flex-start', gap: 8, padding: '10px 12px', marginBottom: 14,
            borderRadius: 8, background: 'color-mix(in srgb, #e8b449 12%, transparent)',
            border: '1px solid color-mix(in srgb, #e8b449 38%, transparent)', fontSize: 12, lineHeight: 1.6,
          }}
        >
          <AlertTriangle size={14} style={{ color: '#e8b449', flexShrink: 0, marginTop: 2 }} />
          <span style={{ color: 'var(--foreground)' }}>
            {dirty && <>有<strong>未保存</strong>的灰度修改。 </>}
            {pendingPublish && (
              hasRelease
                ? <>已保存的灰度（<strong>{rolloutText(cfg)}</strong>）与当前<strong>生效策略</strong>（{rolloutText(published)}）不一致，需到「策略」页发布后终端才会按新放量自更新。</>
                : <>尚无已发布策略，当前灰度设置（<strong>{rolloutText(cfg)}</strong>）需发布后才对终端生效。</>
            )}
            {' '}
            <a href="/policies" style={{ color: 'var(--ring)', fontWeight: 600 }}>去发布 →</a>
          </span>
        </div>
      )}

      {/* 旋钮（admin 可改；其余只读展示当前值） */}
      <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap', alignItems: 'flex-end', marginBottom: 12 }}>
        <div>
          <div style={{ fontSize: 12, color: 'var(--muted-foreground)', marginBottom: 6 }}>开关</div>
          <button
            className={`filter-btn ${(isAdmin ? draft : cfg ?? draft).enabled ? 'active' : ''}`}
            disabled={!isAdmin}
            onClick={() => setDraft((p) => ({ ...p, enabled: !p.enabled }))}
            style={!isAdmin ? { opacity: 0.6, cursor: 'default' } : undefined}
          >
            {(isAdmin ? draft : cfg ?? draft).enabled ? '已启用自更新' : '已关闭自更新'}
          </button>
        </div>
        <div>
          <div style={{ fontSize: 12, color: 'var(--muted-foreground)', marginBottom: 6 }}>通道</div>
          <div style={{ display: 'flex', gap: 6 }}>
            {channels.map((c) => (
              <button
                key={c}
                className={`filter-btn ${(isAdmin ? draft : cfg ?? draft).channel === c ? 'active' : ''}`}
                disabled={!isAdmin}
                onClick={() => setDraft((p) => ({ ...p, channel: c }))}
                style={!isAdmin ? { opacity: 0.6, cursor: 'default' } : undefined}
              >
                {c}
              </button>
            ))}
          </div>
        </div>
        <div style={{ minWidth: 220 }}>
          <div style={{ fontSize: 12, color: 'var(--muted-foreground)', marginBottom: 6 }}>
            放量比例：<strong style={{ color: 'var(--foreground)' }}>{(isAdmin ? draft : cfg ?? draft).rollout_percent}%</strong>
          </div>
          <input
            type="range"
            min={0}
            max={100}
            step={5}
            value={(isAdmin ? draft : cfg ?? draft).rollout_percent}
            disabled={!isAdmin}
            onChange={(e) => setDraft((p) => ({ ...p, rollout_percent: Number(e.target.value) }))}
            style={{ width: 220 }}
          />
          <div style={{ display: 'flex', gap: 6, marginTop: 6 }}>
            {[0, 10, 25, 50, 100].map((v) => (
              <button
                key={v}
                className="filter-btn"
                disabled={!isAdmin}
                onClick={() => setDraft((p) => ({ ...p, rollout_percent: v }))}
                style={{ fontSize: 11, padding: '2px 8px', opacity: isAdmin ? 1 : 0.5 }}
              >
                {v}%
              </button>
            ))}
          </div>
        </div>
        {isAdmin && (
          <Button onClick={save} disabled={busy} style={{ marginBottom: 2 }}>
            <Save size={15} />
            {busy ? '保存中…' : '保存灰度设置'}
          </Button>
        )}
      </div>

      {msg && (
        <p style={{ fontSize: 12, color: 'var(--muted-foreground)', margin: '0 0 12px', lineHeight: 1.5 }}>{msg}</p>
      )}

      {/* 灰度分桶可视化 */}
      <div className="data-table" style={{ gridTemplateColumns: '1.6fr 0.5fr 0.6fr 0.7fr 0.6fr 0.9fr' }}>
        <div className="data-head" style={{ gridTemplateColumns: '1.6fr 0.5fr 0.6fr 0.7fr 0.6fr 0.9fr' }}>
          <span>设备</span><span>桶号</span><span>灰度</span><span>保护</span><span>当前版本</span><span>本次预测</span>
        </div>
        {cohort.length === 0 ? (
          <div className="data-row" style={{ gridColumn: '1 / -1', justifyContent: 'center', color: 'var(--muted-foreground)', fontSize: 12 }}>
            暂无受管终端数据（Collector 未连接或无设备上报）
          </div>
        ) : (
          cohort.map(({ d, pred }) => (
            <div className="data-row" key={d.device_id} style={{ gridTemplateColumns: '1.6fr 0.5fr 0.6fr 0.7fr 0.6fr 0.9fr' }}>
              <span style={{ fontSize: 12, overflow: 'hidden', textOverflow: 'ellipsis' }}>
                {d.hostname || d.device_id}
                <span style={{ color: 'var(--muted-foreground)', fontSize: 10, marginLeft: 6 }}>{d.device_id}</span>
              </span>
              <span style={{ fontVariantNumeric: 'tabular-nums', fontSize: 12 }}>{d.rollout_bucket ?? '—'}</span>
              <span>
                <i className={d.in_canary ? 'pass' : ''} style={{ fontSize: 11 }}>{d.in_canary ? '在放量内' : '未放量'}</i>
              </span>
              <span style={{ fontSize: 11 }}>
                {d.pinned ? <i className="warn">自更保护</i> : d.exempt ? <i className="warn">封禁豁免</i> : <span style={{ color: 'var(--muted-foreground)' }}>—</span>}
              </span>
              <span style={{ fontSize: 12 }}>{d.agent_version || '—'}</span>
              <span>
                <i className={PREDICT_LABEL[pred].cls} style={{ fontSize: 11 }}>{PREDICT_LABEL[pred].text}</i>
              </span>
            </div>
          ))
        )}
      </div>
      {latest && (
        <p style={{ fontSize: 11, color: 'var(--muted-foreground)', marginTop: 10, marginBottom: 0 }}>
          最新客户端版本 {latest}（来自更新清单）。「会更新」= 已启用 + 在放量内 + 未 pinned + 当前版本低于最新。
        </p>
      )}
    </div>
  );
}
