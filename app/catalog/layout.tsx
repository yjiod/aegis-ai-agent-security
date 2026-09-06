import Link from 'next/link';
import { ArrowLeft } from 'lucide-react';

/**
 * 组件目录（/catalog）专用布局。
 *
 * 这里刻意不引入 ConsoleShell，也不订阅 CollectorProvider 的舰队数据：
 * 目录页只是组件走查工具，不需要真实业务上下文。
 *
 * 需要注意的实现约束：Next.js / vinext 的嵌套布局无法脱离根布局，
 * `app/layout.tsx` 仍然会用 ConsoleShell（顶栏 + 主侧边栏）包裹本路由，
 * 所以目录页最终渲染在 `.workspace` 主区域内。若后续希望 /catalog 完全独立，
 * 需要把 ConsoleShell 从根布局下沉到路由分组 `app/(console)/layout.tsx`，
 * 让 /catalog 留在分组之外（本次改动不涉及任何既有文件）。
 */
export default function CatalogLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <div className="catalog-layout w-full pb-6">
      <div className="mb-4 flex flex-wrap items-center gap-3">
        <Link
          href="/"
          className="handle inline-flex items-center gap-1.5 no-underline"
        >
          <ArrowLeft size={13} />
          返回控制台
        </Link>
        <span className="text-[11px] text-[#5e7c73]">
          /catalog · 仅开发环境使用
        </span>
      </div>
      {children}
    </div>
  );
}
