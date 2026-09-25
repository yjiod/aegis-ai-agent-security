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
    <div style={{ position: 'fixed', inset: 0, zIndex: 50, display: 'grid', placeItems: 'center', background: '#020806b8' }}>
      <div
        ref={panelRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby="password-modal-title"
        tabIndex={-1}
        className="animate-entrance"
        style={{ width: '100%', maxWidth: 380, background: 'linear-gradient(145deg, #0d1b18, #0a1613)', border: '1px solid #1e332d', borderRadius: 14, padding: 28, boxShadow: '0 24px 64px #00000055' }}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <Lock size={18} style={{ color: '#49e8a5' }} />
            <h2 id="password-modal-title" style={{ fontSize: 16, color: '#eaf7f2', margin: 0 }}>修改密码</h2>
          </div>
          <button type="button" onClick={onClose} style={{ background: 'none', border: 0, color: '#5e7c73', cursor: 'pointer' }} aria-label="关闭">
            <X size={18} />
          </button>
        </div>

        {success ? (
          <div style={{ display: 'flex', alignItems: 'flex-start', gap: 10, padding: 16, borderRadius: 10, background: '#143329', border: '1px solid #34765f', color: '#c9f5e4', fontSize: 13 }}>
            <Check size={16} style={{ flexShrink: 0, marginTop: 2 }} />
            <span>{serverMsg}</span>
          </div>
        ) : (
          <form onSubmit={handleSubmit}>
            {error && (
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '10px 12px', marginBottom: 14, borderRadius: 8, background: '#2b1515', border: '1px solid #5c2626', color: '#ff9b94', fontSize: 12 }}>
                <AlertTriangle size={14} /> {error}
              </div>
            )}
            <label style={{ display: 'block', fontSize: 12, color: '#86a39a', marginBottom: 6 }}>当前密码</label>
            <input className="form-input" type="password" value={current} onChange={(e) => setCurrent(e.target.value)} required style={{ marginBottom: 14 }} />
            <label style={{ display: 'block', fontSize: 12, color: '#86a39a', marginBottom: 6 }}>新密码（至少 8 位）</label>
            <input className="form-input" type="password" value={next} onChange={(e) => setNext(e.target.value)} required style={{ marginBottom: 14 }} />
            <label style={{ display: 'block', fontSize: 12, color: '#86a39a', marginBottom: 6 }}>确认新密码</label>
            <input className="form-input" type="password" value={confirm} onChange={(e) => setConfirm(e.target.value)} required style={{ marginBottom: 20 }} />
            <div style={{ display: 'flex', gap: 8 }}>
              <Button type="submit" disabled={submitting} style={{ flex: 1 }}>
                {submitting ? '提交中...' : '确认修改'}
              </Button>
              <Button type="button" variant="outline" onClick={onClose}>取消</Button>
            </div>
          </form>
        )}
      </div>
    </div>
  );
}
