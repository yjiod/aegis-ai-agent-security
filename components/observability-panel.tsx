'use client';

/**
 * 统一可观测性组件（handoff P2 末条）：把「系统健康度 / 策略生效态势 / 规则更新管道」
 * 抽象为一个组件。全部真实数据；无数据时显示 — / 空态，不造假。
 *  - 系统健康度：Collector 连接 / Agent 在线率 / 上报趋势 / 审计链路 / 策略已发布 五项检查 + 环形分。
 *  - 策略生效态势：/api/policy/posture（终端真实 policy_version 分布：on_current/drifted/unknown/coverage）。
 *  - 规则更新管道：/api/policy/current（发布版本/签名键/发布人/时间）+ /api/settings/rollout（灰度）。
 */
import { useEffect, useState } from 'react';
import { useCollector } from '@/components/collector-context';

type Posture = {
  published: boolean;
  current_version?: string;
  release_version?: number;
  signing_key_id?: string;
  total_devices: number;
  on_current: number;
  drifted: number;
  unknown: number;
  coverage: number;
  connected?: boolean;
};
type PolicyCurrent = {
  published: boolean;
  version?: number;
  created_at?: string | number | null;
  created_by?: string;
  signing_key_id?: string;
};
type Rollout = { enabled: boolean; channel: string; rollout_percent: number };

export function ObservabilityPanel() {
  const { fleet, collectorState } = useCollector();
  const [posture, setPosture] = useState<Posture | null>(null);
  const [policy, setPolicy] = useState<PolicyCurrent | null>(null);
  const [rollout, setRollout] = useState<Rollout | null>(null);
  const [trendOk, setTrendOk] = useState<boolean | null>(null);
  const [auditOk, setAuditOk] = useState<boolean | null>(null);

  useEffect(() => {
    let alive = true;
    fetch('/api/policy/posture', { cache: 'no-store' })
      .then((r) => (r.ok ? (r.json() as Promise<Posture>) : null))
      .then((d) => alive && setPosture(d))
      .catch(() => alive && setPosture(null));
    fetch('/api/policy/current', { cache: 'no-store' })
      .then((r) => (r.ok ? (r.json() as Promise<PolicyCurrent>) : null))
      .then((d) => alive && setPolicy(d))
      .catch(() => alive && setPolicy(null));
    fetch('/api/settings/rollout', { cache: 'no-store' })
      .then((r) => (r.ok ? (r.json() as Promise<{ rollout?: Rollout }>) : null))
      .then((d) => alive && setRollout(d?.rollout ?? null))
      .catch(() => alive && setRollout(null));
    fetch('/api/trend?hours=24', { cache: 'no-store' })
      .then((r) => alive && setTrendOk(r.ok))
      .catch(() => alive && setTrendOk(false));
    fetch('/api/audit?limit=1', { cache: 'no-store' })
      .then((r) => alive && setAuditOk(r.ok))
      .catch(() => alive && setAuditOk(false));
    return () => {
      alive = false;
    };
  }, []);

  const totalDevices = fleet?.total_devices ?? 0;
  const activeDevices = fleet?.active_devices ?? 0;
  const currentDevices = fleet?.version_posture?.current ?? 0;
  const checks = [
    { label: 'Collector 连接', ok: collectorState === 'live' },
    { label: 'Agent 在线率', ok: totalDevices > 0 && activeDevices / totalDevices >= 0.5 },
    { label: '版本覆盖', ok: totalDevices > 0 && currentDevices / totalDevices >= 0.5 },
    { label: '上报趋势', ok: trendOk === true },
    { label: '审计链路', ok: auditOk === true },
    { label: '策略已发布', ok: posture?.published === true },
  ];
  const score = Math.round((checks.filter((c) => c.ok).length / checks.length) * 100);

  return (
    <section className="panel" style={{ padding: 16, marginBottom: 16 }}>
      <div className="panel-head">
        <div>
          <h2>可观测性</h2>
          <p>系统健康度 · 策略生效态势 · 规则更新管道（统一组件，真实数据）</p>
        </div>
        <span className="sentinel-status" data-state={collectorState === 'live' ? 'normal' : 'stale'}>
          {collectorState === 'live' ? '接收器已连接' : '接收器未连接'}
        </span>
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: 16 }}>
        {/* 系统健康度 */}
        <div>
          <h4 className="sentinel-section-title" style={{ fontSize: 13, marginBottom: 10 }}>系统健康度</h4>
          <div style={{ display: 'flex', gap: 14, alignItems: 'center' }}>
            <div style={{ position: 'relative', width: 84, height: 84, flex: '0 0 84px' }}>
              <svg viewBox="0 0 42 42" width="84" height="84" role="img" aria-label={`健康度 ${score} 分`}>
                <circle cx="21" cy="21" r="15.9" fill="none" stroke="var(--border)" strokeWidth="3.6" />
                <circle
                  cx="21"
                  cy="21"
                  r="15.9"
                  fill="none"
                  stroke={score >= 80 ? 'var(--sentinel-accent)' : score >= 50 ? 'var(--sentinel-warning)' : 'var(--sentinel-danger)'}
                  strokeWidth="3.6"
                  strokeDasharray={`${score} ${100 - score}`}
                  strokeDashoffset="25"
                  strokeLinecap="round"
                />
              </svg>
              <div style={{ position: 'absolute', inset: 0, display: 'grid', placeItems: 'center' }}>
                <strong className="sentinel-metric-value" style={{ fontSize: 20 }}>{score}</strong>
              </div>
            </div>
            <ul style={{ listStyle: 'none', margin: 0, padding: 0, display: 'grid', gap: 5, flex: 1 }}>
              {checks.map((c) => (
                <li key={c.label} className="sentinel-status" data-state={c.ok ? 'normal' : 'stale'} style={{ justifyContent: 'space-between', width: '100%', fontSize: 12 }}>
                  <span>{c.label}</span>
                  <span>{c.ok ? '正常' : '异常'}</span>
                </li>
              ))}
            </ul>
          </div>
        </div>

        {/* 策略生效态势 */}
        <div>
          <h4 className="sentinel-section-title" style={{ fontSize: 13, marginBottom: 10 }}>策略生效态势</h4>
          {posture ? (
            <table className="sentinel-table">
              <tbody>
                <tr><td>当前策略版本</td><td style={{ fontFamily: 'var(--sentinel-font-mono)' }}>{posture.current_version ?? '—'}</td></tr>
                <tr><td>覆盖率</td><td style={{ fontFamily: 'var(--sentinel-font-mono)' }}>{posture.published ? `${posture.coverage}%` : '—'}</td></tr>
                <tr><td>已生效 / 漂移 / 未知</td><td style={{ fontFamily: 'var(--sentinel-font-mono)' }}>{posture.on_current} / {posture.drifted} / {posture.unknown}</td></tr>
                <tr><td>数据源</td><td>{posture.connected ? 'Collector 实时' : '注册表回退'}</td></tr>
              </tbody>
            </table>
          ) : (
            <p style={{ fontSize: 12, color: 'var(--muted-foreground)' }}>策略态势不可用。</p>
          )}
        </div>

        {/* 规则更新管道 */}
        <div>
          <h4 className="sentinel-section-title" style={{ fontSize: 13, marginBottom: 10 }}>规则更新管道</h4>
          {policy?.published ? (
            <table className="sentinel-table">
              <tbody>
                <tr><td>发布版本</td><td style={{ fontFamily: 'var(--sentinel-font-mono)' }}>v{policy.version}</td></tr>
                <tr><td>签名键</td><td style={{ fontFamily: 'var(--sentinel-font-mono)' }}>{policy.signing_key_id ?? '—'}</td></tr>
                <tr><td>发布人 / 时间</td><td>{policy.created_by ?? '—'}{policy.created_at ? ` · ${new Date(Number(policy.created_at) > 1e12 ? Number(policy.created_at) : Number(policy.created_at) * 1000).toLocaleString('zh-CN', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' })}` : ''}</td></tr>
                <tr><td>自更新灰度</td><td>{rollout ? `${rollout.enabled ? '启用' : '关闭'} · ${rollout.channel} · ${rollout.rollout_percent}%` : '—'}</td></tr>
              </tbody>
            </table>
          ) : (
            <p style={{ fontSize: 12, color: 'var(--muted-foreground)' }}>尚无已发布策略。</p>
          )}
        </div>
      </div>
    </section>
  );
}
