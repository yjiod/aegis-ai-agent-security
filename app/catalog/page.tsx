import { notFound } from 'next/navigation';
import { CatalogView } from './catalog-view';

/**
 * /catalog 服务端门禁（生产环境不可访问）。
 *
 * 组件目录页渲染的是走查用的示例数据（虚构的仓库名、KPI 数字），仅供开发期
 * 组件参考。workerd 运行时 NODE_ENV 恒为 production，故部署后本路由直接 404，
 * 避免生产控制台出现虚构数字（红线）。本地 `vinext dev`（development）正常渲染。
 *
 * 这是纯服务端组件（无 'use client'），实际的客户端视图在 ./catalog-view。
 */
export default function CatalogPage() {
  if (process.env.NODE_ENV === 'production') notFound();
  return <CatalogView />;
}
