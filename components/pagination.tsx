'use client';

/**
 * 通用翻页控件（规模化：几千台设备/工单/处置项时列表分页，避免一次性渲染全部）。
 * 受控组件：page(1-based) / pageCount / onPage。页码越界由调用方收敛。
 */
export function Pagination({
  page,
  pageCount,
  onPage,
  total,
  pageSize,
}: {
  page: number;
  pageCount: number;
  onPage: (p: number) => void;
  total?: number;
  pageSize?: number;
}) {
  if (pageCount <= 1) return null;
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 10, justifyContent: 'flex-end', marginTop: 12, fontSize: 12 }}>
      {total !== undefined && (
        <span style={{ color: 'var(--muted-foreground)' }}>
          共 {total} 条{pageSize ? ` · 每页 ${pageSize}` : ''}
        </span>
      )}
      <button className="handle" disabled={page <= 1} onClick={() => onPage(page - 1)} style={{ opacity: page <= 1 ? 0.4 : 1 }}>
        上一页
      </button>
      <span style={{ color: 'var(--muted-foreground)' }}>
        {page} / {pageCount}
      </span>
      <button className="handle" disabled={page >= pageCount} onClick={() => onPage(page + 1)} style={{ opacity: page >= pageCount ? 0.4 : 1 }}>
        下一页
      </button>
    </div>
  );
}

/** 客户端分页切片helper：返回当前页数据 + pageCount。 */
export function paginate<T>(items: T[], page: number, pageSize: number): { rows: T[]; pageCount: number } {
  const pageCount = Math.max(1, Math.ceil(items.length / pageSize));
  const p = Math.min(Math.max(1, page), pageCount);
  return { rows: items.slice((p - 1) * pageSize, p * pageSize), pageCount };
}
