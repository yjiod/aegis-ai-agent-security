'use client';

import { useCallback, useEffect, useState } from 'react';
import { AlertTriangle, ScrollText, ShieldCheck } from 'lucide-react';
import { format } from 'date-fns';
import { Button } from '@/components/ui/button';

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
        };
        setEntries(data.entries ?? []);
        setTotal(data.total ?? 0);
        setOffset(0);
      }
    } catch {
      /* keep current state */
    }
    setLoading(false);
  }, [buildUrl]);

  useEffect(() => {
    fetchPage();
  }, [fetchPage]);

  const loadMore = useCallback(async () => {
    const nextOffset = offset + PAGE_SIZE;
    setLoadingMore(true);
    try {
      const res = await fetch(buildUrl(nextOffset), { cache: 'no-store' });
      if (res.ok) {
        const data = (await res.json()) as { entries?: AuditEntry[] };
        setEntries((prev) => [...prev, ...(data.entries ?? [])]);
        setOffset(nextOffset);
      }
    } catch {
      /* keep current state */
    }
    setLoadingMore(false);
  }, [buildUrl, offset]);

  const hasMore = entries.length < total;

  return (
    <>
      

      <div className="page-head animate-entrance animate-entrance-1">
        <div>
          <p className="eyebrow">管理 / 审计日志</p>
          <h1>审计日志</h1>
          <p>追溯每一次治理操作：谁、在何时、对哪个资源做了什么。</p>
        </div>
      </div>

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
                ? '加载中...'
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
        ) : entries.length === 0 ? (
          <div style={{ padding: 40, textAlign: 'center', color: '#5e7c73' }}>
            <ShieldCheck
              size={32}
              style={{ margin: '0 auto 12px', display: 'block', color: '#49e8a5' }}
            />
            <p style={{ fontSize: 13 }}>当前筛选条件下没有审计记录</p>
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
                <Button variant="outline" onClick={loadMore} disabled={loadingMore}>
                  <ScrollText size={16} />
                  {loadingMore ? '加载中...' : '加载更多'}
                </Button>
              </div>
            )}
          </>
        )}
      </div>
    </>
  );
}
