import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: '组件目录 · Aegis Console',
  description: '开发参考：UI 组件与自定义模式实时预览',
};

export default function CatalogLayout({ children }: { children: React.ReactNode }) {
  return (
    <div style={{ minHeight: '100vh', background: '#07110f', color: '#eaf7f2' }}>
      <div style={{ padding: '16px 24px', borderBottom: '1px solid #1b332c', display: 'flex', alignItems: 'center', gap: 16 }}>
        <a href="/" style={{ color: '#49e8a5', fontSize: 13, textDecoration: 'none' }}>← 返回控制台</a>
        <span style={{ fontSize: 12, color: '#5e7c73' }}>组件目录 · 开发参考 · 非生产页面</span>
      </div>
      {children}
    </div>
  );
}
