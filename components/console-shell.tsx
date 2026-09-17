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
  LogOut,
  Menu,
  Network,
  Package,
  Rocket,
  ScrollText,
  Settings,
  ShieldCheck,
  SlidersHorizontal,
  Sparkles,
  Tags,
  Users,
  Wrench,
} from 'lucide-react';
import ThemeToggle from '@/components/theme-toggle';
import { PasswordModal } from '@/components/password-modal';
import { RoleProvider, useFetchRole, type Role } from '@/components/role-context';
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
      { href: '/onboarding', label: '快速开始', icon: Rocket },
      { href: '/', label: '总览', icon: Activity },
      { href: '/integrations', label: '接入中心', icon: Bot },
      { href: '/devices', label: '设备与 Agent', icon: Laptop },
      { href: '/risks', label: '风险中心', icon: AlertTriangle },
      { href: '/dispositions', label: '处置中心', icon: Tags },
    ],
  },
  {
    label: '安全能力',
    gap: true,
    items: [
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
      { href: '/baselines', label: '基线管理', icon: Code2 },
      { href: '/audit', label: '审计日志', icon: ScrollText },
      { href: '/team', label: '团队与权限', icon: Users },
      { href: '/settings', label: '系统设置', icon: Settings },
      { href: '/push', label: '桌管推送包', icon: Package },
    ],
  },
];

type ConsoleShellProps = {
  children: React.ReactNode;
  collectorState?: CollectorState;
};

const ROLE_LABEL: Record<Role, string> = {
  admin: '安全管理员',
  operator: '运维工程师（终端管理）',
  developer: '开发者（仅本人设备）',
  auditor: '审计员（只读）',
  viewer: '只读访客',
};

const ROLE_BADGE: Record<Role, string> = {
  admin: '管理员',
  operator: '运维',
  developer: '开发者',
  auditor: '审计员',
  viewer: '只读',
};

function initialsOf(subject: string): string {
  const s = (subject || '').trim();
  if (!s) return '—';
  return s.slice(0, 2).toUpperCase();
}

export default function ConsoleShell({
  children,
  collectorState: collectorStateProp,
}: ConsoleShellProps) {
  const pathname = usePathname();
  const [fleet, setFleet] = useState<FleetSummary | null>(null);
  const [internalState, setInternalState] = useState<CollectorState>('checking');
  const [ticketCount, setTicketCount] = useState<number | null>(null);
  const [showPasswordModal, setShowPasswordModal] = useState(false);
  const [showUserMenu, setShowUserMenu] = useState(false);
  const [navOpen, setNavOpen] = useState(false);

  // 移动端抽屉导航：路由变化后自动收起。
  useEffect(() => {
    setNavOpen(false);
  }, [pathname]);

  useEffect(() => {
    // 侧栏「风险中心」告警角标只统计未闭环工单（open/acknowledged/investigating）。
    // 已解决/已驳回属于历史处置记录，不应继续以红色角标示警，否则会把已处置事件
    // 误读为当前活跃威胁。status 过滤在服务端完成，total 即过滤后计数。
    fetch('/api/tickets?status=open,acknowledged,investigating&limit=1', { cache: 'no-store' })
      .then((r) => (r.ok ? (r.json() as Promise<Record<string, unknown>>) : null))
      .then((d) => { if (d && typeof d.total === 'number') setTicketCount(d.total); })
      .catch(() => setTicketCount(null));
  }, []);

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
  const roleState = useFetchRole();

  return (
    <RoleProvider value={roleState}>
      <CollectorProvider value={{ fleet, collectorState }}>
      <div className="min-h-screen bg-[var(--background)] text-[color:var(--foreground)]">
        <header className="topbar">
          <button
            className="nav-toggle"
            aria-label="打开导航菜单"
            aria-expanded={navOpen}
            onClick={() => setNavOpen((v) => !v)}
          >
            <Menu size={20} />
          </button>
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
                ? '接收器已连接'
                : collectorState === 'checking'
                  ? '正在检查接收器'
                  : '接收器未连接'}
            </span>
            <span className="system-ok" style={{ fontSize: 11, padding: "3px 8px", border: "1px solid var(--border)", borderRadius: 6 }}>{ROLE_BADGE[roleState.role] ?? '只读'}</span>
            <ThemeToggle />
            <div style={{ position: 'relative' }}>
              <button className="avatar" aria-label="账户菜单" onClick={() => setShowUserMenu((v) => !v)}>
                {initialsOf(roleState.subject)}
              </button>
              {showUserMenu && (
                <div style={{ position: 'absolute', right: 0, top: 'calc(100% + 8px)', width: 200, background: 'var(--popover)', border: '1px solid var(--border)', borderRadius: 10, boxShadow: 'var(--shadow-overlay)', zIndex: 30, overflow: 'hidden' }}>
                  <div style={{ padding: '12px 14px', borderBottom: '1px solid var(--border)' }}>
                    <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--foreground)' }}>{roleState.subject || '未命名'}</div>
                    <div style={{ fontSize: 11, color: 'var(--muted-foreground)', marginTop: 2 }}>{ROLE_LABEL[roleState.role] ?? '只读访客'}</div>
                  </div>
                  <button
                    style={{ display: 'flex', alignItems: 'center', gap: 8, width: '100%', padding: '10px 14px', background: 'none', border: 0, color: 'var(--foreground)', fontSize: 12, cursor: 'pointer', textAlign: 'left' }}
                    onClick={() => { setShowUserMenu(false); setShowPasswordModal(true); }}
                  >
                    <LockKeyhole size={14} /> 修改密码
                  </button>
                  <button
                    style={{ display: 'flex', alignItems: 'center', gap: 8, width: '100%', padding: '10px 14px', background: 'none', border: 0, color: 'var(--muted-foreground)', fontSize: 12, cursor: 'pointer', textAlign: 'left' }}
                    onClick={() => {
                      // 服务端登出：记录 auth:logout 审计并使本浏览器会话 Cookie 失效。
                      // keepalive 保证导航离开时请求仍能完成；失败也不阻塞本地清 Cookie。
                      fetch('/api/auth/logout', { method: 'POST', keepalive: true }).catch(() => {});
                      document.cookie = 'aegis_session=; path=/; max-age=0';
                      window.location.href = '/login';
                    }}
                  >
                    <LogOut size={14} /> 退出登录
                  </button>
                </div>
              )}
            </div>
          </div>
        </header>
        {showPasswordModal && <PasswordModal onClose={() => setShowPasswordModal(false)} />}
        <div className={navOpen ? 'shell nav-open' : 'shell'}>
          {navOpen && (
            <div
              className="nav-backdrop"
              onClick={() => setNavOpen(false)}
              aria-hidden="true"
            />
          )}
          <aside className={navOpen ? 'sidebar open' : 'sidebar'}>
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
                  {section.items.map(({ href, label, icon: Icon }) => {
                    const deviceCount = href === '/devices' && fleet ? String(fleet.total_devices) : undefined;
                    const riskAlert = href === '/risks' && ticketCount !== null && ticketCount > 0 ? String(ticketCount) : undefined;
                    return (
                      <Link
                        key={href}
                        href={href}
                        className={`nav-item ${pathname === href ? 'active' : ''}`}
                      >
                        <Icon size={18} />
                        {label}
                        {deviceCount && <span>{deviceCount}</span>}
                        {riskAlert && <b>{riskAlert}</b>}
                      </Link>
                    );
                  })}
                </div>
              ))}
            </nav>
            <div className="side-foot">
              <LockKeyhole size={16} />
              <div>
                <strong>企业安全策略</strong>
                <small>
                  {collectorState === 'live' ? '接收器已连接' : '尚未连接接收器'}
                </small>
              </div>
              <Check size={16} />
            </div>
          </aside>
          <main className="workspace">{children}</main>
        </div>
      </div>
    </CollectorProvider>
      </RoleProvider>
  );
}
