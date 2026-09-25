'use client';

import { useCallback, useEffect, useMemo, useState } from 'react';
import { AlertTriangle, RefreshCw, ScrollText, ShieldCheck } from 'lucide-react';
import { format } from 'date-fns';
import { Button } from '@/components/ui/button';
import { EvidenceDialog } from '@/components/evidence-dialog';

/* ─── Types ─────────────────────────────────────────────── */
type ResourceType = 'device' | 'ticket' | 'policy' | 'system';

interface AuditEntry {
  id: number;
  timestamp: number;
  actor: string;
  action: string;
  resource_type: ResourceType;
  resource_id?: string;
  detail?: string;
}

const PAGE_SIZE = 50;

const FILTERS: { key: '' | ResourceType; label: string }[] = [
  { key: '', label: '全部' },
  { key: 'device', label: '设备' },
  { key: 'ticket', label: '工单' },
  { key: 'policy', label: '策略' },
  { key: 'system', label: '系统' },
];

const RESOURCE_LABEL: Record<ResourceType, string> = {
  device: '设备',
  ticket: '工单',
  policy: '策略',
  system: '系统',
};

/** Verb -> Chinese label. Falls back to the raw action token. */
const VERB_LABEL: Record<string, string> = {
  create: '创建',
  update: '更新',
  delete: '删除',
  transition: '流转',
  assign: '指派',
  publish: '发布',
  register: '注册',
  sync: '同步',
};

/** Verb -> badge colour class (reuses the .pass/.warn/.fail status badges). */
const VERB_CLASS: Record<string, string> = {
  create: 'pass',
  register: 'pass',
  publish: 'pass',
  assign: 'pass',
  update: 'warn',
  transition: 'warn',
  sync: 'warn',
  delete: 'fail',
};

function verbOf(action: string): string {
  const parts = action.split(':');
  return parts.length > 1 ? parts[parts.length - 1] : action;
}

function verbLabel(action: string): string {
  const verb = verbOf(action);
  return VERB_LABEL[verb] ?? verb;
}

function verbClass(action: string): string {
  return VERB_CLASS[verbOf(action)] ?? 'warn';
}

function formatTime(ts: number): string {
  // Timestamps are epoch milliseconds (see lib/store.ts).
  const date = new Date(ts);
  if (Number.isNaN(date.getTime())) return '—';
  return format(date, 'yyyy-MM-dd HH:mm:ss');
}

/* ─── Page ──────────────────────────────────────────────── */
export default function AuditPage() {
  const [entries, setEntries] = useState<AuditEntry[]>([]);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [filter, setFilter] = useState<'' | ResourceType>('');
  const [loading, setLoading] = useState(true);
  const [loadingMore, setLoadingMore] = useState(false);
  const [denied, setDenied] = useState(false);
  /**
   * 审计源状态（审计 #33 / PM §7.4）。
   *
   * 接口已回传 `connected`（= collectorEntries !== null，即**终端**审计源是否可达）与
   * `source`（'merged' | 'console'），但页面此前 0 处消费 —— 于是"终端源没接上"与
   * "确实没有事件"在 UI 上完全同形，用户看到一张短列表会以为那就是全部审计。
   * 后端在 1ffff26 修好了 Collector 审计四层不匹配，终端审计现在真的能进来，
   * 这条状态条因此会实际发挥作用（而非永远显示"双源正常"）。
   *
   * 注意 `connected` 只描述终端源：控制台源是本地内存 store，恒可用，
   * 所以"双源皆缺"= 终端不可达 **且** 控制台也没有任何记录。
   */
  const [sources, setSources] = useState<{ connected: boolean; source: string } | null>(null);
  /** 请求本身失败（网络错误 / 非 403 的 HTTP 错误）。此前被 `catch {}` 静默吞掉。 */
  const [fetchFailed, setFetchFailed] = useState(false);
  /** 翻页失败原因（空串 = 无失败）。此前翻页失败是完全静默的。 */
  const [moreError, setMoreError] = useState('');
  const [showEvidence, setShowEvidence] = useState(false);

  const buildUrl = useCallback(
    (pageOffset: number) => {
      const params = new URLSearchParams({
        limit: String(PAGE_SIZE),
        offset: String(pageOffset),
      });
      if (filter) params.set('resource_type', filter);
      return `/api/audit?${params.toString()}`;
    },
    [filter],
  );

  // Initial load / filter change: replace the list from offset 0.
  const fetchPage = useCallback(async () => {
    setLoading(true);
    try {
      const res = await fetch(buildUrl(0), { cache: 'no-store' });
      if (res.ok) {
        const data = (await res.json()) as {
          entries?: AuditEntry[];
          total?: number;
          connected?: unknown;
          source?: unknown;
        };
        setDenied(false);
        setFetchFailed(false);
        setEntries(data.entries ?? []);
        setTotal(data.total ?? 0);
        setOffset(0);
        // 严格判定：只有明确 true 才算终端源可达。缺失/非布尔一律按不可达处理
        // （fail-closed）——把"字段没给"读成"已接入"就是 #33 要消灭的那类谎报。
        setSources({
          connected: data.connected === true,
          source: typeof data.source === 'string' ? data.source : 'unknown',
        });
      } else if (res.status === 403) {
        setDenied(true);
        setEntries([]);
        setTotal(0);
        setSources(null);
        setFetchFailed(false);
      } else {
        // 此前 500/503 会落到下面的 catch 或什么都不做，页面继续显示上一次的
        // 列表且毫无提示。改为显式失败态，由状态条如实说明"读不到"。
        setFetchFailed(true);
        setSources(null);
      }
    } catch {
      setFetchFailed(true);
      setSources(null);
    }
    setLoading(false);
  }, [buildUrl]);

  useEffect(() => {
    fetchPage();
  }, [fetchPage]);

  const loadMore = useCallback(async () => {
    const nextOffset = offset + PAGE_SIZE;
    setLoadingMore(true);
    setMoreError('');
    try {
      const res = await fetch(buildUrl(nextOffset), { cache: 'no-store' });
      if (res.ok) {
        const data = (await res.json()) as { entries?: AuditEntry[] };
        setEntries((prev) => [...prev, ...(data.entries ?? [])]);
        setOffset(nextOffset);
      } else {
        // 翻页失败此前是空 catch：列表停在原处、按钮仍可点，用户反复点也看不出
        // 出了什么事，只会以为"没有更多了"。hasMore 仍为真，于是这是个死循环按钮。
        setMoreError(`加载下一页失败（HTTP ${res.status}），已显示的 ${entries.length} 条不受影响`);
      }
    } catch {
      setMoreError(`加载下一页失败（网络错误），已显示的 ${entries.length} 条不受影响`);
    }
    setLoadingMore(false);
  }, [buildUrl, offset, entries.length]);

  const hasMore = entries.length < total;

  /**
   * PM §7.4 三态判定。
   *
   * - both        ：终端源可达（connected === true）
   * - console-only：终端源不可达，但控制台仍有记录 → 琥珀 .warn + 重试
   * - none        ：终端源不可达且控制台也无记录，或请求本身失败 → 空态
   *
   * `none` 的判据刻意带 `!filter`：total 是**筛选后**计数，所以在有筛选条件时
   * total===0 只代表"没有匹配项"，不能推断成"审计源都没接入"——那会把一次空筛选
   * 误报成基础设施故障。有筛选且无匹配时仍走原有的"当前筛选条件下没有审计记录"。
   */
  const sourceState: 'both' | 'console-only' | 'none' | null = useMemo(() => {
    if (loading || denied) return null;
    if (fetchFailed || sources === null) return 'none';
    if (sources.connected) return 'both';
    return total === 0 && !filter ? 'none' : 'console-only';
  }, [loading, denied, fetchFailed, sources, total, filter]);

  return (
    <>
      

      <div className="page-head animate-entrance animate-entrance-1">
        <div>
          <p className="eyebrow">管理 / 审计日志</p>
          <h1>审计日志</h1>
          <p>追溯每一次治理操作：谁、在何时、对哪个资源做了什么。</p>
        </div>
        {/* 4A · Accounting 合规导出：全量附件下载（服务端留审计）。 */}
        <div className="head-actions">
          <Button variant="outline" size="sm" onClick={() => setShowEvidence(true)}>
            导出证据包
          </Button>
          <a className="handle" href="/api/audit?format=csv" download style={{ fontSize: 12 }}>
            导出 CSV
          </a>
          <a className="handle" href="/api/audit?format=json" download style={{ fontSize: 12 }}>
            导出 JSON
          </a>
        </div>
      </div>

      {showEvidence && <EvidenceDialog onClose={() => setShowEvidence(false)} />}

      {/* 审计 #33 / PM §7.4：页面顶部源状态条。文案逐字照抄 PM 定稿。
          此前接口已回传 connected/source 而页面 0 处消费，导致"终端审计源没接上"
          与"确实没有终端事件"渲染完全同形——用户看到一张短列表会以为那就是全部审计，
          这在合规取证场景下是实质性误导（会据此得出"没有异常操作"的结论）。
          色彩按 PM 指定：终端源缺失用琥珀 .warn，**不用红**（源缺失是能力降级，
          不是事故告警）；双源皆缺走空态。 */}
      {sourceState === 'both' && (
        <div
          role="status"
          className="animate-entrance animate-entrance-2"
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 8,
            marginBottom: 14,
            padding: '10px 14px',
            borderRadius: 'var(--sentinel-radius-md)',
            background: 'color-mix(in srgb, var(--sentinel-accent) 8%, transparent)',
            border: '1px solid color-mix(in srgb, var(--sentinel-accent) 26%, transparent)',
            color: 'var(--sentinel-text-2)',
            fontSize: 12,
          }}
        >
          <ShieldCheck size={14} style={{ flexShrink: 0, color: 'var(--sentinel-accent)' }} />
          审计源：控制台 已接入 · 终端 已接入（本次合并 {total} 条）
        </div>
      )}

      {sourceState === 'console-only' && (
        <div
          role="alert"
          className="animate-entrance animate-entrance-2"
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 8,
            flexWrap: 'wrap',
            marginBottom: 14,
            padding: '10px 14px',
            borderRadius: 'var(--sentinel-radius-md)',
            background: 'color-mix(in srgb, var(--sentinel-warning) 10%, transparent)',
            border: '1px solid color-mix(in srgb, var(--sentinel-warning) 34%, transparent)',
            color: 'var(--sentinel-text-2)',
            fontSize: 12,
            lineHeight: 1.6,
          }}
        >
          <AlertTriangle size={14} style={{ flexShrink: 0, color: 'var(--sentinel-warning)' }} />
          <span style={{ flex: 1, minWidth: 240 }}>
            审计源：控制台 已接入 · 终端 未接入 —— 当前仅显示控制面与认证审计，终端侧事件缺失
          </span>
          {/* PM §7.4 要求终端源缺失时附「重试」入口 */}
          <Button variant="outline" size="sm" onClick={() => void fetchPage()} disabled={loading}>
            <RefreshCw size={13} className={loading ? 'spin' : undefined} />
            重试
          </Button>
        </div>
      )}

      {sourceState === 'none' && (
        <div
          role="alert"
          className="animate-entrance animate-entrance-2"
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 8,
            flexWrap: 'wrap',
            marginBottom: 14,
            padding: '10px 14px',
            borderRadius: 'var(--sentinel-radius-md)',
            background: 'color-mix(in srgb, var(--sentinel-warning) 10%, transparent)',
            border: '1px solid color-mix(in srgb, var(--sentinel-warning) 34%, transparent)',
            color: 'var(--sentinel-text-2)',
            fontSize: 12,
            lineHeight: 1.6,
          }}
        >
          <AlertTriangle size={14} style={{ flexShrink: 0, color: 'var(--sentinel-warning)' }} />
          <span style={{ flex: 1, minWidth: 240 }}>审计源均未接入，无记录可显示</span>
          <Button variant="outline" size="sm" onClick={() => void fetchPage()} disabled={loading}>
            <RefreshCw size={13} className={loading ? 'spin' : undefined} />
            重试
          </Button>
        </div>
      )}

      {/* Filters */}
      <div
        className="panel animate-entrance animate-entrance-2"
        style={{ marginBottom: 14, padding: '12px 16px' }}
      >
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
          {FILTERS.map((f) => (
            <button
              key={f.key || 'all'}
              className={`filter-btn ${filter === f.key ? 'active' : ''}`}
              onClick={() => setFilter(f.key)}
            >
              {f.label}
            </button>
          ))}
        </div>
      </div>

      {/* Audit table */}
      <div className="panel animate-entrance animate-entrance-3">
        <div className="panel-head">
          <div>
            <h2>操作记录</h2>
            <p>
              {loading
                ? '加载中…'
                : denied
                  ? '需要审计员 / 管理员权限'
                  : sourceState === 'none'
                    // PM §7.4：双源皆缺走空态，**不显示 0 条**——"共 0 条"会被读成
                    // "审计系统正常、只是确实没有操作"，而真相是一条都没读到。
                    ? '无记录可显示'
                    : `共 ${total} 条${filter ? `（筛选：${RESOURCE_LABEL[filter]}）` : ''}`}
            </p>
          </div>
        </div>

        {loading ? (
          <>
            {[1, 2, 3, 4].map((i) => (
              <div className="skeleton-row" key={i}>
                <div className="skeleton-cell" />
                <div className="skeleton-cell" />
                <div className="skeleton-cell" />
                <div className="skeleton-cell" />
              </div>
            ))}
          </>
        ) : denied ? (
          <div style={{ padding: 40, textAlign: 'center', color: 'var(--sentinel-text-3)' }}>
            <ShieldCheck
              size={32}
              style={{ margin: '0 auto 12px', display: 'block', color: 'var(--sentinel-accent)' }}
            />
            <p style={{ fontSize: 13 }}>
              审计日志仅对「审计员 / 安全管理员」开放。
              <br />
              当前身份为只读访客，如需查阅请联系管理员将你加入审计员白名单。
            </p>
          </div>
        ) : entries.length === 0 ? (
          <div style={{ padding: 40, textAlign: 'center', color: 'var(--sentinel-text-3)' }}>
            <ShieldCheck
              size={32}
              style={{
                margin: '0 auto 12px',
                display: 'block',
                // 源缺失时用琥珀而非语义绿：绿色会被读成"一切正常、确实没记录"，
                // 而这正是本条要否定的判断。
                color: sourceState === 'none' ? 'var(--sentinel-warning)' : 'var(--sentinel-accent)',
              }}
            />
            <p style={{ fontSize: 13 }}>
              {sourceState === 'none'
                ? // 源都没接上时不能沿用"筛选条件下没有记录"——那会把基础设施故障
                  // 说成一次正常的空查询。
                  '审计源均未接入，无记录可显示'
                : filter
                  ? '当前筛选条件下没有审计记录'
                  : // 无筛选、双源正常、确实 0 条：这才是真正的"没有审计记录"。
                    '暂无审计记录'}
            </p>
          </div>
        ) : (
          <>
            <div className="data-table">
              <div
                className="data-head"
                style={{ gridTemplateColumns: '160px 110px 90px 70px 150px 1fr' }}
              >
                <span>时间</span>
                <span>操作者</span>
                <span>动作</span>
                <span>类型</span>
                <span>资源 ID</span>
                <span>详情</span>
              </div>
              {entries.map((entry, i) => (
                <div
                  key={entry.id}
                  className="data-row animate-row-entrance"
                  style={{
                    gridTemplateColumns: '160px 110px 90px 70px 150px 1fr',
                    animationDelay: `${Math.min(i, 20) * 20 + 100}ms`,
                  }}
                >
                  <span style={{ fontVariantNumeric: 'tabular-nums' }}>
                    {formatTime(entry.timestamp)}
                  </span>
                  <span>{entry.actor}</span>
                  <i className={verbClass(entry.action)}>{verbLabel(entry.action)}</i>
                  <span>{RESOURCE_LABEL[entry.resource_type] ?? entry.resource_type}</span>
                  <strong>{entry.resource_id ?? '—'}</strong>
                  <span>{entry.detail ?? '—'}</span>
                </div>
              ))}
            </div>

            {hasMore && (
              <div style={{ padding: '14px 16px', textAlign: 'center' }}>
                {moreError && (
                  /* 翻页失败必须可见：此前是空 catch，按钮停在原地、点多少次都没反应，
                     用户只能理解成"没有更多了"，而实际上还有记录没读到。 */
                  <p
                    role="alert"
                    style={{
                      margin: '0 auto 10px',
                      maxWidth: 520,
                      fontSize: 12,
                      lineHeight: 1.6,
                      color: 'var(--sentinel-danger)',
                    }}
                  >
                    {moreError}
                  </p>
                )}
                <Button variant="outline" onClick={loadMore} disabled={loadingMore}>
                  <ScrollText size={16} />
                  {loadingMore ? '加载中…' : moreError ? '重试加载下一页' : '加载更多'}
                </Button>
              </div>
            )}
          </>
        )}
      </div>
    </>
  );
}
