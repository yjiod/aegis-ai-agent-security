'use client';
import { useEffect, useState } from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import {
  Activity,
  AlertTriangle,
  Bot,
  Check,
  Code2,
  Cpu,
  Laptop,
  LockKeyhole,
  Network,
  Search,
  ScrollText,
  Settings,
  ShieldCheck,
  SlidersHorizontal,
  Sparkles,
  Users,
  Wrench,
} from 'lucide-react';
import ThemeToggle from '@/components/theme-toggle';
import {
  CollectorProvider,
  type CollectorState,
  type FleetSummary,
} from '@/components/collector-context';

type NavEntry = {
  href: string;
  label: string;
  icon: typeof Activity;
  count?: string;
  alert?: string;
};

type NavSection = {
  label: string;
  gap?: boolean;
  items: NavEntry[];
};

const navSections: NavSection[] = [
  {
    label: '控制台',
    items: [
      { href: '/', label: '总览', icon: Activity },
      { href: '/onboarding', label: '接入中心', icon: Bot },
      { href: '/devices', label: '设备与 Agent', icon: Laptop, count: '312' },
      { href: '/risks', label: '风险中心', icon: AlertTriangle, alert: '12' },
    ],
  },
  {
    label: '安全能力',
    gap: true,
    items: [
      { href: '/baseline', label: '编码规范基线', icon: Code2 },
      { href: '/skills', label: 'Skill 扫描器', icon: Sparkles },
      { href: '/mcp', label: 'MCP 扫描器', icon: Network },
      { href: '/quality', label: '代码质量', icon: Wrench },
      { href: '/engines', label: '扫描引擎', icon: Cpu },
    ],
  },
  {
    label: '管理',
    gap: true,
    items: [
      { href: '/policies', label: '策略配置', icon: SlidersHorizontal },
      { href: '/audit', label: '审计日志', icon: ScrollText },
      { href: '/team', label: '团队与权限', icon: Users },
      { href: '/settings', label: '系统设置', icon: Settings },
    ],
  },
];

type ConsoleShellProps = {
  children: React.ReactNode;
  collectorState?: CollectorState;
};

export default function ConsoleShell({
  children,
  collectorState: collectorStateProp,
}: ConsoleShellProps) {
  const pathname = usePathname();
  const [fleet, setFleet] = useState<FleetSummary | null>(null);
  const [internalState, setInternalState] = useState<CollectorState>('checking');

  useEffect(() => {
    const controller = new AbortController();
    fetch('/api/summary', { cache: 'no-store', signal: controller.signal })
      .then(async (response) => {
        if (!response.ok) throw new Error('collector unavailable');
        const value = (await response.json()) as {
          connected?: boolean;
          summary?: FleetSummary;
        };
        if (!value.connected || !value.summary)
          throw new Error('collector disconnected');
        setFleet(value.summary);
        setInternalState('live');
      })
      .catch((error: unknown) => {
        if ((error as { name?: string })?.name !== 'AbortError')
          setInternalState('demo');
      });
    return () => controller.abort();
  }, []);

  const collectorState = collectorStateProp ?? internalState;

  return (
    <CollectorProvider value={{ fleet, collectorState }}>
      <div className="min-h-screen bg-[var(--background)] text-[color:var(--foreground)]">
        <header className="topbar">
          <div className="brand">
            <span className="brandmark">
              <ShieldCheck size={19} />
            </span>
            <span>
              Aegis<span className="brand-muted"> / Agent Security</span>
            </span>
          </div>
          <div className="header-actions">
            <span className="system-ok">
              <span className={collectorState === 'live' ? 'live-dot' : 'demo-dot'} />
              {collectorState === 'live'
                ? '只读摘要已连接'
                : collectorState === 'checking'
                  ? '正在检查接收器'
                  : '演示数据 · 接收器未连接'}
            </span>
            <button className="icon-btn" aria-label="搜索">
              <Search size={18} />
            </button>
            <ThemeToggle />
            <button className="avatar" aria-label="账户菜单">
              SL
            </button>
          </div>
        </header>
        <div className="shell">
          <aside className="sidebar">
            <nav aria-label="主导航">
              {navSections.map((section) => (
                <div key={section.label}>
                  <p
                    className={
                      section.gap ? 'nav-label section-gap' : 'nav-label'
                    }
                  >
                    {section.label}
                  </p>
                  {section.items.map(({ href, label, icon: Icon, count, alert }) => (
                    <Link
                      key={href}
                      href={href}
                      className={`nav-item ${pathname === href ? 'active' : ''}`}
                    >
                      <Icon size={18} />
                      {label}
                      {count && <span>{count}</span>}
                      {alert && <b>{alert}</b>}
                    </Link>
                  ))}
                </div>
              ))}
            </nav>
            <div className="side-foot">
              <LockKeyhole size={16} />
              <div>
                <strong>企业安全策略</strong>
                <small>
                  {collectorState === 'live' ? '只读摘要已连接' : '尚未连接接收器'}
                </small>
              </div>
              <Check size={16} />
            </div>
          </aside>
          <main className="workspace">{children}</main>
        </div>
      </div>
    </CollectorProvider>
  );
}
