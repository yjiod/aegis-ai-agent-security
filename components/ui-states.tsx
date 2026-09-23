'use client';

/**
 * 统一 empty / loading / error / stale 状态组件（handoff P1）。
 * 所有列表/面板复用，失败提示安全（不暴露堆栈、SQL、内部路径）。
 */
import { AlertTriangle, Inbox, Loader2, RefreshCw } from 'lucide-react';

export function LoadingState({ label = '加载中…' }: { label?: string }) {
  return (
    <div className="state-block" role="status" aria-live="polite">
      <Loader2 size={18} className="spin" />
      <span>{label}</span>
    </div>
  );
}

export function EmptyState({ label = '暂无数据', hint }: { label?: string; hint?: string }) {
  return (
    <div className="state-block" role="status">
      <Inbox size={18} />
      <span>{label}</span>
      {hint ? <small>{hint}</small> : null}
    </div>
  );
}

export function ErrorState({ label = '加载失败', onRetry }: { label?: string; onRetry?: () => void }) {
  return (
    <div className="state-block" role="alert">
      <AlertTriangle size={18} style={{ color: 'var(--sentinel-warning)' }} />
      <span>{label}</span>
      <small>请稍后重试；若持续失败请联系管理员（详情见审计日志）。</small>
      {onRetry ? (
        <button type="button" className="sentinel-button" onClick={onRetry} style={{ marginTop: 8 }}>
          <RefreshCw size={14} />
          重试
        </button>
      ) : null}
    </div>
  );
}

export function StaleState({ label = '数据可能已过期', since }: { label?: string; since?: string }) {
  return (
    <div className="state-block" role="status" data-tone="stale">
      <RefreshCw size={18} />
      <span>{label}</span>
      {since ? <small>最后更新 {since}</small> : null}
    </div>
  );
}
