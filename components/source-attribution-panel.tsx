'use client';

/**
 * 来源归因面板（handoff 原则5 / P2 地图降级增强）。
 * 无真实 GeoIP 数据时**不渲染假世界地图/攻击连线**，降级为可解释的三视图：
 *   来源排行（出口 IP → 设备数 + 严重/高危）/ 规则类型排行 / 终端分布(OS)。
 * 徽章诚实标注数据源与降级原因；接入 GeoIP 数据源后可在此组件升级为地图视图。
 * 数据全部来自 props（页面已取的 devices + findings），无额外请求、不造假。
 */
import { useMemo } from 'react';
import { maskEgress } from '@/lib/redact';

type Dev = {
  device_id: string;
  hostname?: string;
  os?: string;
  network?: { egress_ip?: string };
};
type Finding = { device_id: string; kind: string; severity: string };

function Bar({ value, max, color }: { value: number; max: number; color: string }) {
  const w = max > 0 ? Math.max(2, Math.round((value / max) * 100)) : 0;
  return (
    <div style={{ flex: 1, height: 6, borderRadius: 99, background: 'var(--sentinel-surface-3)', overflow: 'hidden' }}>
      <div style={{ width: `${w}%`, height: '100%', background: color }} />
    </div>
  );
}

export function SourceAttributionPanel({ devices, findings }: { devices: Dev[]; findings: Finding[] }) {
  const byDeviceFindings = useMemo(() => {
    const m = new Map<string, { crit: number; high: number; total: number }>();
    for (const f of findings) {
      const e = m.get(f.device_id) ?? { crit: 0, high: 0, total: 0 };
      e.total += 1;
      if (f.severity === 'critical') e.crit += 1;
      if (f.severity === 'high') e.high += 1;
      m.set(f.device_id, e);
    }
    return m;
  }, [findings]);

  const egressRank = useMemo(() => {
    const m = new Map<string, { devices: number; crit: number; high: number }>();
    for (const d of devices) {
      const ip = d.network?.egress_ip;
      if (!ip) continue;
      const key = maskEgress(ip); // 二次脱敏：宽视图按 /16 聚合，不平铺完整 IP
      const e = m.get(key) ?? { devices: 0, crit: 0, high: 0 };
      e.devices += 1;
      const f = byDeviceFindings.get(d.device_id);
      if (f) {
        e.crit += f.crit;
        e.high += f.high;
      }
      m.set(key, e);
    }
    return [...m.entries()].sort((a, b) => b[1].devices - a[1].devices).slice(0, 6);
  }, [devices, byDeviceFindings]);

  const ruleRank = useMemo(() => {
    const m = new Map<string, { total: number; crit: number; high: number }>();
    for (const f of findings) {
      const e = m.get(f.kind) ?? { total: 0, crit: 0, high: 0 };
      e.total += 1;
      if (f.severity === 'critical') e.crit += 1;
      if (f.severity === 'high') e.high += 1;
      m.set(f.kind, e);
    }
    return [...m.entries()].sort((a, b) => b[1].total - a[1].total).slice(0, 8);
  }, [findings]);

  const osDist = useMemo(() => {
    const m = new Map<string, number>();
    for (const d of devices) {
      const os = d.os ?? 'unknown';
      m.set(os, (m.get(os) ?? 0) + 1);
    }
    return [...m.entries()].sort((a, b) => b[1] - a[1]);
  }, [devices]);

  const maxEgress = Math.max(1, ...egressRank.map(([, v]) => v.devices));
  const maxRule = Math.max(1, ...ruleRank.map(([, v]) => v.total));
  const maxOs = Math.max(1, ...osDist.map(([, v]) => v));

  return (
    <section className="panel" style={{ padding: 16, marginBottom: 16 }}>
      <div className="panel-head">
        <div>
          <h2>风险来源归因</h2>
          <p>来源排行 / 规则类型 / 终端分布（Collector 真实上报）</p>
        </div>
        <span className="sentinel-badge" data-severity="low" title="无真实 GeoIP 数据源；接入后本组件可升级为世界地图视图">
          无 GeoIP · 已降级为来源排行
        </span>
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: 16 }}>
        <div>
          <h4 className="sentinel-section-title" style={{ fontSize: 13, marginBottom: 10 }}>来源排行（出口 IP）</h4>
          {egressRank.length === 0 && <p style={{ fontSize: 12, color: 'var(--muted-foreground)' }}>暂无出口 IP 数据</p>}
          <ul style={{ listStyle: 'none', margin: 0, padding: 0, display: 'grid', gap: 8 }}>
            {egressRank.map(([ip, v]) => (
              <li key={ip} style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12 }}>
                <span style={{ fontFamily: 'var(--sentinel-font-mono)', minWidth: 110 }}>{ip}</span>
                <Bar value={v.devices} max={maxEgress} color="var(--sentinel-cyan)" />
                <span style={{ fontFamily: 'var(--sentinel-font-mono)', minWidth: 64, textAlign: 'right' }}>
                  {v.devices} 台
                </span>
                <span style={{ color: 'var(--sentinel-danger)', fontFamily: 'var(--sentinel-font-mono)' }}>{v.crit}</span>
                <span style={{ color: 'var(--sentinel-warning)', fontFamily: 'var(--sentinel-font-mono)' }}>{v.high}</span>
              </li>
            ))}
          </ul>
        </div>
        <div>
          <h4 className="sentinel-section-title" style={{ fontSize: 13, marginBottom: 10 }}>规则类型排行</h4>
          {ruleRank.length === 0 && <p style={{ fontSize: 12, color: 'var(--muted-foreground)' }}>暂无发现数据</p>}
          <ul style={{ listStyle: 'none', margin: 0, padding: 0, display: 'grid', gap: 8 }}>
            {ruleRank.map(([kind, v]) => (
              <li key={kind} style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12 }}>
                <span style={{ fontFamily: 'var(--sentinel-font-mono)', minWidth: 130, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{kind}</span>
                <Bar value={v.total} max={maxRule} color={v.crit > 0 ? 'var(--sentinel-danger)' : v.high > 0 ? 'var(--sentinel-warning)' : 'var(--sentinel-accent)'} />
                <span style={{ fontFamily: 'var(--sentinel-font-mono)', minWidth: 40, textAlign: 'right' }}>{v.total}</span>
              </li>
            ))}
          </ul>
        </div>
        <div>
          <h4 className="sentinel-section-title" style={{ fontSize: 13, marginBottom: 10 }}>终端分布（OS）</h4>
          {osDist.length === 0 && <p style={{ fontSize: 12, color: 'var(--muted-foreground)' }}>暂无终端数据</p>}
          <ul style={{ listStyle: 'none', margin: 0, padding: 0, display: 'grid', gap: 8 }}>
            {osDist.map(([os, n]) => (
              <li key={os} style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12 }}>
                <span style={{ minWidth: 70 }}>{os}</span>
                <Bar value={n} max={maxOs} color="var(--sentinel-accent)" />
                <span style={{ fontFamily: 'var(--sentinel-font-mono)', minWidth: 40, textAlign: 'right' }}>{n}</span>
              </li>
            ))}
          </ul>
        </div>
      </div>
    </section>
  );
}
