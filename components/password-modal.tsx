'use client';

import { useState } from 'react';
import { Lock, X, AlertTriangle, Check } from 'lucide-react';
import { Button } from '@/components/ui/button';

export function PasswordModal({ onClose }: { onClose: () => void }) {
  const [current, setCurrent] = useState('');
  const [next, setNext] = useState('');
  const [confirm, setConfirm] = useState('');
  const [error, setError] = useState('');
  const [success, setSuccess] = useState(false);
  const [submitting, setSubmitting] = useState(false);

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
        setSuccess(true);
        setTimeout(onClose, 1500);
      } else {
        const data = (await res.json().catch(() => ({}))) as any;
        setError(data.error === 'invalid_current_password' ? '当前密码错误' : data.error ?? '修改失败');
      }
    } catch {
      setError('网络错误，请重试');
    }
    setSubmitting(false);
  }

  return (
    <div style={{ position: 'fixed', inset: 0, zIndex: 50, display: 'grid', placeItems: 'center', background: '#020806b8', backdropFilter: 'blur(4px)' }} onClick={onClose}>
      <div
        className="animate-entrance"
        style={{ width: '100%', maxWidth: 380, background: 'linear-gradient(145deg, #0d1b18, #0a1613)', border: '1px solid #1e332d', borderRadius: 14, padding: 28, boxShadow: '0 24px 64px #00000055' }}
        onClick={(e) => e.stopPropagation()}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <Lock size={18} style={{ color: '#49e8a5' }} />
            <h2 style={{ fontSize: 16, color: '#eaf7f2', margin: 0 }}>修改密码</h2>
          </div>
          <button onClick={onClose} style={{ background: 'none', border: 0, color: '#5e7c73', cursor: 'pointer' }} aria-label="关闭">
            <X size={18} />
          </button>
        </div>

        {success ? (
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: 16, borderRadius: 10, background: '#143329', border: '1px solid #34765f', color: '#c9f5e4', fontSize: 13 }}>
            <Check size={16} /> 密码已修改，下次登录使用新密码
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
