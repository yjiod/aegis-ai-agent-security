/** Sweep output records control-plane progress, never endpoint execution. */
export interface RemediationStatus {
  deny_rules: 'not_requested' | 'saved' | 'save_failed';
  policy: 'not_attempted' | 'published' | 'blocked';
  endpoint: 'unverified';
}

export function remediationStatus(
  savedCount = 0,
  publishedVersion?: number,
  publishBlocked?: string,
  saveFailed = false,
): RemediationStatus {
  return {
    deny_rules: saveFailed ? 'save_failed' : savedCount > 0 ? 'saved' : 'not_requested',
    policy: publishBlocked ? 'blocked' : publishedVersion !== undefined ? 'published' : 'not_attempted',
    endpoint: 'unverified',
  };
}

export interface RemediationSummary {
  ran?: boolean;
  reason?: string;
  findings?: number;
  /** Legacy field: rules saved by this sweep, not confirmed endpoint blocks. */
  denied?: Array<{ asset_key: string }>;
  conflicts?: Array<{ asset_key: string }>;
  notified?: number;
  published_version?: number;
  publish_blocked?: string;
  status?: RemediationStatus;
}

/** Shared presentation contract; compatible with servers predating status. */
export function formatRemediationSummary(result: RemediationSummary): string {
  if (!result.ran) return `未执行：${result.reason ?? '未知原因'}`;
  const denied = result.denied ?? [];
  return `扫描 ${result.findings ?? 0} 条发现 → 已保存拒绝规则 ${denied.length} 项`
    + (denied.length ? `（${denied.map((d) => d.asset_key).slice(0, 5).join('、')}${denied.length > 5 ? '…' : ''}）` : '')
    + (result.status?.deny_rules === 'save_failed' ? '；规则保存失败' : '')
    + `；人工冲突 ${(result.conflicts ?? []).length}；通知 ${result.notified ?? 0}`
    + (result.published_version !== undefined ? `；策略已发布 v${result.published_version}` : '')
    + (result.publish_blocked ? `；发布被拦截：${result.publish_blocked}` : '')
    + '；终端执行未验证';
}
