'use client';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import {
  ShieldCheck, Laptop, AlertTriangle, Code2, Sparkles, Network,
  Check, CircleDot, LockKeyhole,
} from 'lucide-react';

/* NOTE: This route is for development reference only.
   Exclude from production builds via middleware or route group if needed. */

const categories = [
  { id: 'buttons', label: '按钮 Button' },
  { id: 'badges', label: '徽章 Badge' },
  { id: 'progress', label: '进度条 Progress' },
  { id: 'metrics', label: '指标卡 Metric' },
  { id: 'tables', label: '数据表 DataTable' },
  { id: 'status', label: '状态标签 Status' },
  { id: 'nav', label: '导航项 Nav' },
  { id: 'toast', label: '通知 Toast' },
  { id: 'modules', label: '能力模块 Module' },
  { id: 'severity', label: '风险等级 Severity' },
];

export default function CatalogPage() {
  return (
    <div style={{ display: 'grid', gridTemplateColumns: '180px 1fr', minHeight: 'calc(100vh - 57px)' }}>
      {/* Category nav */}
      <nav style={{ borderRight: '1px solid #1b332c', padding: '20px 12px' }}>
        <p style={{ fontSize: 10, color: '#5e7c73', fontWeight: 800, letterSpacing: '0.12em', textTransform: 'uppercase', marginBottom: 12, padding: '0 8px' }}>组件分类</p>
        {categories.map((c) => (
          <a key={c.id} href={`#${c.id}`} style={{ display: 'block', padding: '8px 12px', fontSize: 12, color: '#87a69c', textDecoration: 'none', borderRadius: 6, marginBottom: 2 }}>
            {c.label}
          </a>
        ))}
      </nav>

      {/* Component showcase */}
      <div style={{ padding: '32px 40px', maxWidth: 900 }}>
        <h1 style={{ fontSize: 24, marginBottom: 8, letterSpacing: '-0.03em' }}>组件目录</h1>
        <p style={{ color: '#78968c', fontSize: 13, marginBottom: 32 }}>
          所有 UI 组件与自定义模式的实时预览。暗色主题继承自 globals.css。
        </p>

        {/* Buttons */}
        <Section id="buttons" title="按钮 Button">
          <Row>
            <Button>默认按钮</Button>
            <Button variant="outline">轮廓按钮</Button>
            <Button variant="ghost">幽灵按钮</Button>
            <Button variant="destructive">危险按钮</Button>
          </Row>
          <Row>
            <Button size="sm">小按钮</Button>
            <Button size="lg">大按钮</Button>
            <Button disabled>禁用状态</Button>
          </Row>
        </Section>

        {/* Badges */}
        <Section id="badges" title="徽章 Badge">
          <Row>
            <Badge>默认</Badge>
            <Badge variant="outline">轮廓</Badge>
            <Badge variant="secondary">次要</Badge>
            <Badge variant="destructive">危险</Badge>
          </Row>
          <Row>
            <Badge variant="outline"><span className="live-dot" /> 已连接</Badge>
            <Badge variant="outline"><span className="demo-dot" /> 演示模式</Badge>
          </Row>
        </Section>

        {/* Progress */}
        <Section id="progress" title="进度条 Progress">
          <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
            <div><span style={{ fontSize: 11, color: '#78968c' }}>25%</span><Progress value={25} /></div>
            <div><span style={{ fontSize: 11, color: '#78968c' }}>65%</span><Progress value={65} /></div>
            <div><span style={{ fontSize: 11, color: '#78968c' }}>92%</span><Progress value={92} /></div>
          </div>
        </Section>

        {/* Metric cards */}
        <Section id="metrics" title="指标卡 Metric">
          <div className="metrics" style={{ marginBottom: 0 }}>
            <article className="metric">
              <div className="metric-top"><span>已纳管设备</span><Laptop size={18} /></div>
              <strong>312</strong>
              <p><em>284</em> 活跃 · 28 过期</p>
            </article>
            <article className="metric danger">
              <div className="metric-top"><span>高风险设备</span><AlertTriangle size={18} /></div>
              <strong>12</strong>
              <p><i>3 严重</i> · 9 高危</p>
            </article>
          </div>
        </Section>

        {/* Data table */}
        <Section id="tables" title="数据表 DataTable">
          <div className="data-table">
            <div className="data-head">
              <span>对象</span><span>策略动作</span><span>检测结果</span><span>状态</span>
            </div>
            <div className="data-row">
              <strong>filesystem-mcp</strong><span>限制</span><span>越权目录访问</span><i className="fail">高危</i>
            </div>
            <div className="data-row">
              <strong>github-mcp</strong><span>放行</span><span>OAuth 范围合规</span><i className="pass">通过</i>
            </div>
            <div className="data-row">
              <strong>postgres-mcp</strong><span>观察</span><span>出站地址未锁定</span><i className="warn">中危</i>
            </div>
          </div>
        </Section>

        {/* Status badges */}
        <Section id="status" title="状态标签 Status">
          <Row>
            <i className="pass" style={{ fontStyle: 'normal', padding: '4px 9px', borderRadius: 6, fontSize: 11 }}>通过</i>
            <i className="fail" style={{ fontStyle: 'normal', padding: '4px 9px', borderRadius: 6, fontSize: 11 }}>高危</i>
            <i className="warn" style={{ fontStyle: 'normal', padding: '4px 9px', borderRadius: 6, fontSize: 11 }}>中危</i>
          </Row>
        </Section>

        {/* Nav items */}
        <Section id="nav" title="导航项 Nav">
          <div style={{ width: 220, border: '1px solid #1b332c', borderRadius: 10, padding: 12 }}>
            <button className="nav-item active"><ShieldCheck size={18} /> 总览</button>
            <button className="nav-item"><Laptop size={18} /> 设备与 Agent <span>312</span></button>
            <button className="nav-item"><AlertTriangle size={18} /> 风险中心 <b>12</b></button>
            <button className="nav-item"><Code2 size={18} /> 编码规范基线</button>
          </div>
        </Section>

        {/* Toast */}
        <Section id="toast" title="通知 Toast">
          <div className="toast" style={{ position: 'static', display: 'inline-flex' }} role="status">
            <CircleDot size={16} />
            演示模式：未连接策略发布 API，未修改任何终端。
          </div>
        </Section>

        {/* Module cards */}
        <Section id="modules" title="能力模块 Module">
          <div className="module-grid">
            <article className="module">
              <span className="module-icon green"><ShieldCheck size={19} /></span>
              <div><h3>安全编码基线</h3><p>企业规则基线 · v4.8</p></div>
              <span className="status green"><Check size={13} /> 已打包</span>
            </article>
            <article className="module">
              <span className="module-icon blue"><Sparkles size={19} /></span>
              <div><h3>Skill 扫描器</h3><p>权限、指令与依赖</p></div>
              <span className="status blue"><Check size={13} /> 已启用</span>
            </article>
          </div>
        </Section>

        {/* Severity */}
        <Section id="severity" title="风险等级 Severity">
          <Row>
            <span className="severity red">高危</span>
            <span className="severity orange">中危</span>
            <span style={{ fontSize: 10, padding: '4px 7px', borderRadius: 5, background: '#1a3d30', color: '#5de1a9' }}>低危</span>
          </Row>
          <div style={{ marginTop: 16 }}>
            <div className="risk-row">
              <span className="severity red">高危</span>
              <div className="risk-main">
                <strong>MCP Server 请求了未授权文件目录</strong>
                <span>cursor-mcp-filesystem</span>
              </div>
              <span className="device">MKT-LT-2841</span>
              <span className="time">2 分钟前</span>
              <button className="handle">处置</button>
            </div>
          </div>
        </Section>

        {/* Footer */}
        <div style={{ marginTop: 48, padding: '20px 0', borderTop: '1px solid #1b332c', display: 'flex', alignItems: 'center', gap: 8, color: '#5e7c73', fontSize: 11 }}>
          <LockKeyhole size={14} />
          <span>组件目录仅供开发参考，不应出现在生产导航中。未来可迁移至 Storybook。</span>
        </div>
      </div>
    </div>
  );
}

function Section({ id, title, children }: { id: string; title: string; children: React.ReactNode }) {
  return (
    <section id={id} style={{ marginBottom: 40 }}>
      <h2 style={{ fontSize: 15, marginBottom: 14, color: '#dff4ed', letterSpacing: '-0.01em' }}>{title}</h2>
      <div style={{ border: '1px solid #1b332c', borderRadius: 11, padding: 20, background: '#0d1a17' }}>
        {children}
      </div>
    </section>
  );
}

function Row({ children }: { children: React.ReactNode }) {
  return <div style={{ display: 'flex', flexWrap: 'wrap', gap: 10, alignItems: 'center', marginBottom: 10 }}>{children}</div>;
}
