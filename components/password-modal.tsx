'use client';

import { useEffect, useRef, useState } from 'react';
import { Lock, X, AlertTriangle, Check } from 'lucide-react';
import { Button } from '@/components/ui/button';

export function PasswordModal({ onClose }: { onClose: () => void }) {
  const [current, setCurrent] = useState('');
  const [next, setNext] = useState('');
  const [confirm, setConfirm] = useState('');
  const [error, setError] = useState('');
  const [success, setSuccess] = useState(false);
  const [serverMsg, setServerMsg] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const panelRef = useRef<HTMLDivElement>(null);

  // 对话框契约（审计 #12），对齐项目内正例 components/detail-drawer.tsx：
  // 挂载即把焦点移入容器，并监听 Escape 关闭。没有这两件事时，弹窗对键盘用户
  // 是"焦点仍留在背后页面上"的状态——Tab 会在被遮挡的内容里游走，Esc 也无效。
  useEffect(() => {
    panelRef.current?.focus();
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError('');
    if (next.length < 8) { setError('新密码至少 8 个字符'); return; }
    if (next !== confirm) { setError('两次输入的新密码不一致'); return; }
    setSubmitting(true);
    try {
      const res = await fetch('/api/auth/change-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ current_password: current, new_password: next }),
      });
      if (res.ok) {
        // 诚实呈现服务端返回的真实结果：本环境配置只读，改密仅校验、需服务器
        // 更新 AEGIS_CONSOLE_PASSWORD 并重启后生效——不再谎称"下次登录使用新密码"。
        const data = (await res.json().catch(() => ({}))) as { message?: string };
        setServerMsg(data.message ?? '已校验当前密码；新密码需管理员在服务端更新后才会生效。');
        setSuccess(true);
      } else {
        const data = (await res.json().catch(() => ({}))) as any;
        setError(data.error === 'invalid_current_password' ? '当前密码错误' : data.error ?? '修改失败');
      }
    } catch {
      setError('网络错误，请重试');
    }
    setSubmitting(false);
  }

  // 遮罩**不**绑定 onClick 关闭：这是三段式密码表单，误点遮罩会直接丢弃已输入的
  // 当前密码/新密码。关闭入口只有右上角 X、取消按钮与 Escape（三者均可键盘到达）。
  // 注意外层这个 div 既是遮罩也是对话框的**父容器**（用 grid 居中），因此不能加
  // aria-hidden——那会把里面的 role="dialog" 一并对读屏隐藏。detail-drawer 能加是
  // 因为它的遮罩是对话框的兄弟节点，结构不同。
  return (
    // 全组件裸色收敛为 token（审计 #8b），使弹窗跟随主题切换。此前面板底是一段
    // 旧绿主题渐变 + 三处硬编码绿，亮色主题下整块仍是深色，与页面脱节。
    // 遮罩改用 --overlay-bg，与 .drawer-backdrop / evidence-dialog 同源。
    <div style={{ position: 'fixed', inset: 0, zIndex: 50, display: 'grid', placeItems: 'center', background: 'var(--overlay-bg)' }}>
      <div
        ref={panelRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby="password-modal-title"
        tabIndex={-1}
        className="animate-entrance"
        style={{ width: '100%', maxWidth: 380, background: 'var(--card)', border: '1px solid var(--border)', borderRadius: 'var(--sentinel-radius-lg)', padding: 28, boxShadow: 'var(--shadow-overlay)' }}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            {/* 头部图标用交互青蓝，与 evidence-dialog 的头部图标一致；
                旧值是一个已废弃的绿 accent。图标属非文本元素，两主题实测
                暗 7.92:1 / 亮 4.49:1，均远超 WCAG 1.4.11 非文本 3:1 门槛。 */}
            <Lock size={18} style={{ color: 'var(--sentinel-cyan)' }} />
            <h2 id="password-modal-title" style={{ fontSize: 16, color: 'var(--foreground)', margin: 0 }}>修改密码</h2>
          </div>
          <button type="button" onClick={onClose} style={{ background: 'none', border: 0, color: 'var(--muted-foreground)', cursor: 'pointer' }} aria-label="关闭">
            <X size={18} />
          </button>
        </div>

        {success ? (
          // 成功框：正文用 --foreground 而非 accent 绿。实测 accent 绿文字在亮色主题
          // 的 12% 浅绿底上只有 3.0:1（FAIL），--foreground 则是暗 12.85:1 / 亮 14.9:1。
          // 成功语义由绿色底染 + 绿色对勾图标承载，正文保持可读前景色。
          <div style={{ display: 'flex', alignItems: 'flex-start', gap: 10, padding: 16, borderRadius: 'var(--sentinel-radius-md)', background: 'color-mix(in srgb, var(--sentinel-accent) 12%, transparent)', border: '1px solid color-mix(in srgb, var(--sentinel-accent) 32%, transparent)', color: 'var(--foreground)', fontSize: 13 }}>
            <Check size={16} style={{ flexShrink: 0, marginTop: 2, color: 'var(--sentinel-accent)' }} />
            <span>{serverMsg}</span>
          </div>
        ) : (
          <form onSubmit={handleSubmit}>
            {error && (
              // 错误框：文字用 --sentinel-danger 而非审计建议的 --sentinel-danger-2。
              // danger-2 没有亮色 override，在亮色 12% 浅红底上只有 2.29:1（FAIL）；
              // danger 两主题分别为 4.63:1 / 4.54:1，均 PASS。
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '10px 12px', marginBottom: 14, borderRadius: 'var(--sentinel-radius-md)', background: 'color-mix(in srgb, var(--sentinel-danger) 12%, transparent)', border: '1px solid color-mix(in srgb, var(--sentinel-danger) 40%, transparent)', color: 'var(--sentinel-danger)', fontSize: 12 }}>
                <AlertTriangle size={14} /> {error}
              </div>
            )}
            <label style={{ display: 'block', fontSize: 12, color: 'var(--sentinel-text-2)', marginBottom: 6 }}>当前密码</label>
            <input className="form-input" type="password" value={current} onChange={(e) => setCurrent(e.target.value)} required style={{ marginBottom: 14 }} />
            <label style={{ display: 'block', fontSize: 12, color: 'var(--sentinel-text-2)', marginBottom: 6 }}>新密码（至少 8 位）</label>
            <input className="form-input" type="password" value={next} onChange={(e) => setNext(e.target.value)} required style={{ marginBottom: 14 }} />
            <label style={{ display: 'block', fontSize: 12, color: 'var(--sentinel-text-2)', marginBottom: 6 }}>确认新密码</label>
            <input className="form-input" type="password" value={confirm} onChange={(e) => setConfirm(e.target.value)} required style={{ marginBottom: 20 }} />
            <div style={{ display: 'flex', gap: 8 }}>
              <Button type="submit" disabled={submitting} style={{ flex: 1 }}>
                {submitting ? '提交中…' : '确认修改'}
              </Button>
              <Button type="button" variant="outline" onClick={onClose}>取消</Button>
            </div>
          </form>
        )}
      </div>
    </div>
  );
}
