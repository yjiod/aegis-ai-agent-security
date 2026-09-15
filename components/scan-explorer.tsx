'use client';

/**
 * ScanExplorer —— Skill / MCP / 代码质量三个扫描器页共用的「真实数据」视图。
 *
 * 取代此前各页内联的伪造静态样例（曾标注"实时数据/终端 Agent 上报实时"，违反
 * "绝不伪造数据"红线）。数据来自 GET /api/findings?category=…（控制台跨设备聚合
 * Collector 真实上报）。诚实呈现四态：加载中 / 接收器未连接 / 该类暂无发现 / 真实列表。
 * 处置动作引导到「处置中心」（真正编译进签名策略下发的闭环），不再放"同步规则库"
 * 这类点了只弹"未接入"提示的假按钮。
 */
import { useCallback, useEffect, useState } from 'react';
import Link from 'next/link';
import { RefreshCw, ShieldAlert, Inbox, WifiOff, ArrowRight } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Spinner } from '@/components/ui/spinner';
import { SignalDetails } from '@/components/risk-signal-help';
import {
  severityMeta,
  severityStyle,
  formatRelativeTime,
  type TicketSeverity,
} from '@/components/ticket-detail';

type Finding = {
  device_id: string;
  kind: string;
  category: string;
  severity: string;
  path: string;
  message: string;
  signal_matches?: unknown;
  scanned_at: number;
};

type FindingsResponse = {
  connected: boolean;
  category: string;
  devices: number;
  devices_with_findings: number;
  counts: { total: number; critical: number; high: number; medium: number; low: number };
  findings: Finding[];
};

const SEVERITIES = ['critical', 'high', 'medium', 'low'] as const;

function asSeverity(value: string): TicketSeverity {
  return (SEVERITIES as readonly string[]).includes(value) ? (value as TicketSeverity) : 'low';
}

export function ScanExplorer({
  category,
  eyebrow,
  title,
  description,
}: {
  category: 'skill' | 'mcp' | 'code';
  eyebrow: string;
  title: string;
  description: string;
}) {
  const [data, setData] = useState<FindingsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState('');

  const load = useCallback(
    async (isRefresh: boolean) => {
      if (isRefresh) setRefreshing(true);
      else setLoading(true);
      try {
        const res = await fetch(`/api/findings?category=${category}&limit=200`, { cache: 'no-store' });
        if (!res.ok) throw new Error(`接口返回 ${res.status}`);
        const json = (await res.json()) as FindingsResponse;
        setData(json);
        setError('');
      } catch (e) {
        setError(e instanceof Error ? e.message : '未知错误');
      } finally {
        setLoading(false);
        setRefreshing(false);
      }
    },
    [category],
  );

  useEffect(() => {
    void load(false);
  }, [load]);

  const counts = data?.counts ?? { total: 0, critical: 0, high: 0, medium: 0, low: 0 };
  const connected = data?.connected ?? false;

  return (
    <section className="workspace">
      <div className="page-head animate-entrance animate-entrance-1">
        <div>
          <p className="eyebrow">{eyebrow}</p>
          <h1>{title}</h1>
          <p>{description}</p>
        </div>
        <div className="head-actions" style={{ flexWrap: 'wrap' }}>
          <Button variant="outline" onClick={() => void load(true)} disabled={loading || refreshing}>
            {refreshing ? <Spinner /> : <RefreshCw />}
            刷新
          </Button>
          <Link href="/dispositions" style={{ textDecoration: 'none' }}>
            <Button variant="outline" title="到处置中心对涉事 Skill/MCP 加白·观察·拉黑，并发布签名策略下发终端">
              <ShieldAlert />
              去处置
            </Button>
          </Link>
        </div>
      </div>

      <div className="detail-kpis">
        <article className="animate-entrance animate-entrance-1">
          <strong>{loading ? '—' : counts.total}</strong>
          <span>本类发现</span>
        </article>
        <article className="animate-entrance animate-entrance-2">
          <strong>{loading ? '—' : counts.critical + counts.high}</strong>
          <span>严重 / 高危</span>
        </article>
        <article className="animate-entrance animate-entrance-3">
          <strong>{loading ? '—' : (data?.devices_with_findings ?? 0)}</strong>
          <span>涉及终端</span>
        </article>
      </div>

      <div className="panel animate-entrance animate-entrance-4">
        <div className="panel-head">
          <div>
            <h2>最近扫描结果</h2>
            <p>
              {loading
                ? '正在读取终端上报…'
                : !connected
                  ? '接收器未连接——无真实扫描数据（不展示任何虚构样例）'
                  : `终端 Agent 真实上报 · 覆盖 ${data?.devices ?? 0} 台设备，按严重度与时间排序`}
            </p>
          </div>
          <Badge variant="outline">
            <span className={connected ? 'live-dot' : 'demo-dot'} />
            {loading ? '读取中…' : connected ? '实时数据' : '未连接'}
          </Badge>
        </div>

        {/* 严重度分布（真实计数；无数据时为 0，绝不编造趋势） */}
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, marginBottom: 14 }}>
          {SEVERITIES.map((s) => (
            <span
              key={s}
              className={`severity ${severityMeta(s).tone}`}
              style={{ ...severityStyle(s), display: 'inline-flex', alignItems: 'center', gap: 6 }}
            >
              {severityMeta(s).label} {loading ? '—' : counts[s]}
            </span>
          ))}
        </div>

        {loading ? (
          <div style={{ display: 'grid', gap: 8 }}>
            {[0, 1, 2, 3].map((i) => (
              <div className="skeleton-row" key={i} />
            ))}
          </div>
        ) : error ? (
          <div className="empty-detail" style={{ minHeight: 160 }}>
            <WifiOff size={32} />
            <h2>读取失败</h2>
            <p>无法从 /api/findings 读取真实发现：{error}。未展示数据不代表没有风险。</p>
            <Button variant="outline" size="sm" onClick={() => void load(true)} disabled={refreshing}>
              重试
            </Button>
          </div>
        ) : !connected ? (
          <div className="empty-detail" style={{ minHeight: 160 }}>
            <WifiOff size={32} />
            <h2>接收器未连接</h2>
            <p>
              配置服务端 Collector 后，这里会展示终端 Agent 真实上报的{title}发现。
              <br />
              当前不展示任何虚构样例。
            </p>
          </div>
        ) : counts.total === 0 ? (
          <div className="empty-detail" style={{ minHeight: 160 }}>
            <Inbox size={32} />
            <h2>暂无该类发现</h2>
            <p>已连接接收器，但当前没有{title}相关的真实发现。新的上报会自动进入此列表。</p>
          </div>
        ) : (
          <div className="data-table">
            <div className="data-head">
              <span>等级</span>
              <span>类型</span>
              <span>对象 / 终端</span>
              <span>说明</span>
              <span>时间</span>
            </div>
            {data!.findings.slice(0, 100).map((f, i) => {
              const sev = asSeverity(f.severity);
              return (
                <div className="data-row animate-row-entrance" key={`${f.device_id}-${f.kind}-${f.path}-${i}`} style={{ animationDelay: `${i * 20 + 150}ms` }}>
                  <i className={severityMeta(sev).tone === 'red' ? 'fail' : severityMeta(sev).tone === 'orange' ? 'warn' : ''}>
                    {severityMeta(sev).label}
                  </i>
                  <span style={{ fontSize: 12 }}>{f.kind}</span>
                  <span style={{ fontSize: 11, wordBreak: 'break-all' }}>
                    {f.path || '—'}
                    <br />
                    <span style={{ color: 'var(--muted-foreground)' }}>{f.device_id}</span>
                  </span>
                  <span style={{ fontSize: 11 }}>
                    {f.message}
                    {f.category === 'skill' && <SignalDetails matches={f.signal_matches} />}
                    {f.path ? (
                      <>
                        <br />
                        <Link
                          className="handle"
                          href={`/dispositions?type=${f.category === 'mcp' ? 'mcp' : 'skill'}&asset=${encodeURIComponent(f.path)}`}
                          style={{ fontSize: 11 }}
                        >
                          去处置 <ArrowRight size={10} style={{ verticalAlign: '-1px' }} />
                        </Link>
                      </>
                    ) : null}
                  </span>
                  <span style={{ fontSize: 11, color: 'var(--muted-foreground)' }}>{formatRelativeTime(f.scanned_at)}</span>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </section>
  );
}
