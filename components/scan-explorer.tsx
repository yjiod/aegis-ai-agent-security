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
  asset_type?: string;
  asset_key?: string;
  signal_matches?: unknown;
  scanned_at: number;
};

type FindingsResponse = {
  connected: boolean;
  category: string;
  devices: number;
  devices_with_findings: number;
  suppressed: number;
  counts: { total: number; critical: number; high: number; medium: number; low: number };
  findings: Finding[];
};

const SEVERITIES = ['critical', 'high', 'medium', 'low'] as const;

function asSeverity(value: string): TicketSeverity {
  return (SEVERITIES as readonly string[]).includes(value) ? (value as TicketSeverity) : 'low';
}

/**
 * 渲染前净化不可见/控制/双向格式字符（Cc 除 \n\t、Cf 如 U+200B-200F/U+202A-202E/
 * U+2060-2069/U+FEFF）。发现文本来自终端扫描的不可信文件内容；若原样渲染，双向控制符
 * 会重排/隐藏相邻 UI 文本（视觉欺骗 + 布局错乱）。替换为可见的 \uXXXX 转义，既消除
 * 渲染副作用又保留"这里有个控制字符"的信息。
 */
// 故意匹配控制/双向格式字符：渲染前净化不可信发现文本，防 bidi/零宽字符重排或隐藏相邻
// UI（视觉欺骗）。此处"匹配控制字符"即目的本身，故就近关闭 no-control-regex。
// eslint-disable-next-line no-control-regex
const INVISIBLE_CTRL = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f\u00ad\u0600-\u0605\u061c\u06dd\u070f\u08e2\u180e\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u206f\ufeff]/g;
function safeText(value: string): string {
  return value.replace(INVISIBLE_CTRL, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`);
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
  const [status, setStatus] = useState(0);

  const load = useCallback(
    async (isRefresh: boolean) => {
      if (isRefresh) setRefreshing(true);
      else setLoading(true);
      try {
        const res = await fetch(`/api/findings?category=${category}&limit=200`, { cache: 'no-store' });
        setStatus(res.status);
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
        <article className="animate-entrance animate-entrance-4" title="已在处置中心加白（disposition=allow）的同源资产发现，已自动从告警中消除，不再计入">
          <strong>{loading ? '—' : (data?.suppressed ?? 0)}</strong>
          <span>加白已消除</span>
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
            <h2>{status === 401 ? '会话已过期或未登录' : '读取失败'}</h2>
            <p>
              {status === 401
                ? '当前会话无效或已过期，请重新登录后再查看扫描发现。'
                : `暂时无法读取扫描发现：${error}。未展示数据不代表没有风险。`}
            </p>
            {status === 401 ? (
              <a href="/login" className="handle" style={{ fontSize: 12 }}>去登录</a>
            ) : (
              <Button variant="outline" size="sm" onClick={() => void load(true)} disabled={refreshing}>
                重试
              </Button>
            )}
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
          <div className="data-table cols-5">
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
                  <span style={{ fontSize: 12 }}>{safeText(f.kind)}</span>
                  <span style={{ fontSize: 11, wordBreak: 'break-all' }}>
                    {safeText(f.path) || '—'}
                    <br />
                    <span style={{ color: 'var(--muted-foreground)' }}>{f.device_id}</span>
                  </span>
                  <span style={{ fontSize: 11 }}>
                    {safeText(f.message)}
                    {f.category === 'skill' && <SignalDetails matches={f.signal_matches} />}
                    {f.asset_key || f.path ? (
                      <>
                        <br />
                        {/* inline-flex：全局 reset 令 svg 为 display:block，行内布局时箭头会
                            独自成行、在"去处置"药丸下方拖出一条错位钩线（用户反馈"歪"，
                            skill/mcp/代码质量三页同源）。flex 让文字与箭头同行居中。 */}
                        <Link
                          className="handle"
                          href={`/dispositions?type=${f.asset_type === 'mcp' || f.category === 'mcp' ? 'mcp' : 'skill'}&asset=${encodeURIComponent(f.asset_key || f.path)}`}
                          style={{ fontSize: 11, display: 'inline-flex', alignItems: 'center', gap: 4 }}
                        >
                          去处置
                          <ArrowRight size={10} />
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
