'use client';

/**
 * 右侧详情抽屉（handoff P1）：承载"发现 → 资产 → 规则信号 → 建议动作 → 审计记录"，
 * 不强制离开列表。Escape 关闭；提供 aria 标签与焦点管理（打开时聚焦容器）。
 */
import { useEffect, useRef } from 'react';
import { X } from 'lucide-react';

export interface DrawerSection {
  label: string;
  content: React.ReactNode;
}

export function DetailDrawer({
  open,
  onClose,
  title,
  subtitle,
  sections,
}: {
  open: boolean;
  onClose: () => void;
  title: string;
  subtitle?: string;
  sections: DrawerSection[];
}) {
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    ref.current?.focus();
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [open, onClose]);

  if (!open) return null;
  return (
    <>
      <div
        className="drawer-backdrop"
        onClick={onClose}
        aria-hidden="true"
      />
      <aside
        ref={ref}
        className="drawer"
        role="dialog"
        aria-modal="true"
        aria-label={title}
        tabIndex={-1}
      >
        <header className="drawer-head">
          <div>
            <h3>{title}</h3>
            {subtitle ? <p>{subtitle}</p> : null}
          </div>
          <button type="button" className="icon-btn" onClick={onClose} aria-label="关闭详情">
            <X size={16} />
          </button>
        </header>
        <div className="drawer-body">
          {sections.map((s) => (
            <section key={s.label} className="drawer-section">
              <h4 className="sentinel-section-title" style={{ fontSize: 13 }}>
                {s.label}
              </h4>
              <div className="drawer-section-body">{s.content}</div>
            </section>
          ))}
        </div>
      </aside>
    </>
  );
}
