'use client';

import { useEffect, useMemo, useState } from 'react';
import { Radar, ShieldAlert, ShieldCheck } from 'lucide-react';

import { Badge } from '@/components/ui/badge';
import {
  FALLBACK_RULE_SETS,
  SET_LABEL,
  TECHNIQUES,
  type RuleSet,
} from '@/lib/detection-coverage';

/**
 * 检测覆盖 / 技战法映射（AIDR「Detection」侧的覆盖矩阵）。
 *
 * 把当前**真实启用**的检测规则（优先取已发布签名策略的 skill/mcp/code 规则集，
 * 未发布时回落到出厂基座静态镜像 FALLBACK_RULE_SETS）映射到 OWASP GenAI LLM Top 10 /
 * Agentic Applications Top 10 技战法，展示「哪些技战法被哪些规则覆盖、哪些是缺口」。
 *
 * 诚实原则：缺口如实标为 gap 而非伪装成已覆盖；不使用任何演示/虚构数据。
 * 注意：本组件为客户端组件，**不得** import lib/policy（其依赖 node:crypto，进浏览器
 * 包会触发 "node:crypto externalized" 运行时崩溃）；规则集经 /api/policy/current 获取。
 */

interface CurrentPolicy {
  published?: boolean;
  policy?: {
    skill_rules?: string[];
    mcp_rules?: string[];
    code_rules?: string[];
    custom_baseline_rules?: string[];
  };
}

export function DetectionCoveragePanel() {
  const [current, setCurrent] = useState<CurrentPolicy | null>(null);
  const [loaded, setLoaded] = useState(false);
  // fleet 级 per-rule 命中（/api/findings/rule-stats）：把"覆盖"与"活跃"合一屏。
  const [ruleStats, setRuleStats] = useState<{
    connected?: boolean;
    rule_stats?: Array<{ rule_id: string; total: number; critical: number; high: number }>;
  } | null>(null);

  useEffect(() => {
    let alive = true;
    fetch('/api/findings/rule-stats', { cache: 'no-store' })
      .then((r) => (r.ok ? (r.json() as Promise<{ connected?: boolean; rule_stats?: Array<{ rule_id: string; total: number; critical: number; high: number }> }>) : null))
      .then((d) => {
        if (alive) setRuleStats(d ?? null);
      })
      .catch(() => {
        if (alive) setRuleStats(null);
      });
    fetch('/api/policy/current', { cache: 'no-store' })
      .then((r) => (r.ok ? (r.json() as Promise<CurrentPolicy>) : null))
      .then((d) => {
        if (alive) setCurrent(d);
      })
      .catch(() => {
        if (alive) setCurrent(null);
      })
      .finally(() => {
        if (alive) setLoaded(true);
      });
    return () => {
      alive = false;
    };
  }, []);

  const enabled = useMemo<Record<RuleSet, Set<string>>>(() => {
    const p = current?.policy;
    return {
      skill: new Set(p?.skill_rules?.length ? p.skill_rules : FALLBACK_RULE_SETS.skill),
      mcp: new Set(p?.mcp_rules?.length ? p.mcp_rules : FALLBACK_RULE_SETS.mcp),
      code: new Set(p?.code_rules?.length ? p.code_rules : FALLBACK_RULE_SETS.code),
    };
  }, [current]);

  const hitByRule = useMemo(() => {
    const m = new Map<string, { total: number; critHigh: number }>();
    if (ruleStats?.connected && Array.isArray(ruleStats.rule_stats)) {
      for (const r of ruleStats.rule_stats) {
        m.set(r.rule_id, { total: r.total, critHigh: r.critical + r.high });
      }
    }
    return m;
  }, [ruleStats]);
  const fleetAvailable = Boolean(ruleStats?.connected);

  const rows = useMemo(
    () =>
      TECHNIQUES.map((t) => {
        const covering = t.rules.flatMap((r) => r.ids.filter((id) => enabled[r.set].has(id)).map((id) => ({ set: r.set, id })));
        let hits = 0;
        let hitsCritHigh = 0;
        for (const r of t.rules) for (const id of r.ids) {
          const h = hitByRule.get(id);
          if (h) {
            hits += h.total;
            hitsCritHigh += h.critHigh;
          }
        }
        return { ...t, covering, covered: covering.length > 0, hits, hitsCritHigh };
      }),
    [enabled, hitByRule],
  );

  const coveredCount = rows.filter((r) => r.covered).length;
  const gaps = rows.filter((r) => !r.covered);
  const customCount = current?.policy?.custom_baseline_rules?.length ?? 0;

  return (
    <div className="panel animate-entrance animate-entrance-3" style={{ marginBottom: 14 }}>
      <div className="panel-head">
        <div>
          <h2 style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <Radar size={16} /> 检测覆盖 · 技战法映射
          </h2>
          <p>
            当前启用规则集（{current?.published ? '已发布签名策略' : '出厂基座（尚未发布）'}）对 OWASP GenAI LLM / Agentic Top 10
            技战法的覆盖情况；缺口如实标注，属规划中检测能力。
          </p>
        </div>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          <Badge variant="outline">
            <ShieldCheck size={12} /> 覆盖 {coveredCount}/{rows.length}
          </Badge>
          {gaps.length > 0 && (
            <Badge variant="outline" style={{ color: 'var(--sentinel-warning)' }}>
              <ShieldAlert size={12} /> 缺口 {gaps.length}
            </Badge>
          )}
        </div>
      </div>

      <div style={{ padding: '0 16px 8px', display: 'flex', gap: 14, flexWrap: 'wrap', fontSize: 12, color: 'var(--muted-foreground)' }}>
        <span>启用规则：Skill {enabled.skill.size} · MCP {enabled.mcp.size} · 代码 {enabled.code.size}</span>
        {customCount > 0 && <span>· 自定义基线规则 {customCount}</span>}
        <span>· fleet 命中：{fleetAvailable ? 'Collector 增量聚合（全量）' : '暂不可用（旧 Collector 无聚合端点）'}</span>
        {!loaded && <span>· 加载已发布策略…</span>}
      </div>

      <div className="data-table" style={{ margin: '0 16px 16px', width: 'auto' }}>
        <div className="data-head" style={{ gridTemplateColumns: '120px 1.3fr 1.8fr 110px 90px' }}>
          <span>技战法</span>
          <span>名称</span>
          <span>覆盖规则</span>
          <span>fleet 命中</span>
          <span>状态</span>
        </div>
        {rows.map((t) => (
          <div className="data-row" key={t.id} style={{ gridTemplateColumns: '120px 1.3fr 1.8fr 110px 90px' }}>
            <span style={{ fontFamily: 'var(--sentinel-font-mono)', fontSize: 11 }}>{t.id}</span>
            <span style={{ fontSize: 12 }}>{t.name}</span>
            <span style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
              {t.covered ? (
                t.covering.map((r) => (
                  <Badge key={`${r.set}:${r.id}`} variant="outline" style={{ fontSize: 10 }}>
                    {SET_LABEL[r.set]}·{r.id}
                  </Badge>
                ))
              ) : (
                <span style={{ fontSize: 11, color: 'var(--muted-foreground)' }}>当前规则集未覆盖</span>
              )}
            </span>
            <span style={{ fontFamily: 'var(--sentinel-font-mono)', fontSize: 11 }}>
              {fleetAvailable ? (
                <>
                  {t.hits}
                  {t.hitsCritHigh > 0 && (
                    <span style={{ color: 'var(--sentinel-danger)' }}>（严重/高危 {t.hitsCritHigh}）</span>
                  )}
                </>
              ) : (
                <span style={{ color: 'var(--muted-foreground)' }}>—</span>
              )}
            </span>
            <span>
              {t.covered ? (
                <i className="pass" style={{ fontSize: 10 }}>已覆盖</i>
              ) : (
                <i className="warn" style={{ fontSize: 10 }}>缺口</i>
              )}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

export default DetectionCoveragePanel;
