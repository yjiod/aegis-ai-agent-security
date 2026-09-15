import { notFound } from 'next/navigation';
import { CatalogView } from './catalog-view';

/**
 * /catalog 服务端门禁（生产环境不可访问）。
 *
 * 组件目录页渲染的是走查用的示例数据（虚构的仓库名、KPI 数字），仅供开发期
 * 组件参考。workerd 运行时 NODE_ENV 恒为 production，故部署后本页调用 notFound()
 * 拦截，绝不渲染虚构数字（红线）。本地 `vinext dev`（development）正常渲染。
 *
 * 实测行为（生产已验证）：当前 vinext 对页面内 notFound() 的应答是 307 重定向到
 * 控制台首页 `/`（而非裸 404；真正不存在的路由才返回 404）。无论 307→/ 还是 404，
 * 结果一致——生产环境不会渲染 CatalogView 的示例数据。这里保留语义正确的
 * notFound()（而非硬编码 redirect('/')），若后续 vinext 将其修正为 404 亦自动跟随。
 *
 * 这是纯服务端组件（无 'use client'），实际的客户端视图在 ./catalog-view。
 */
export default function CatalogPage() {
  if (process.env.NODE_ENV === 'production') notFound();
  return <CatalogView />;
}
