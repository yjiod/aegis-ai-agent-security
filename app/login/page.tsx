'use client';

import { useEffect, useState } from 'react';
import { ShieldCheck, Lock, User, AlertTriangle, KeyRound } from 'lucide-react';
import { Button } from '@/components/ui/button';

export default function LoginPage() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [oidc, setOidc] = useState<{ enabled: boolean; url: string; label: string }>({ enabled: false, url: '', label: '统一身份登录' });

  useEffect(() => {
    fetch('/api/auth/providers', { cache: 'no-store' })
      .then((r) => (r.ok ? r.json() : null))
      .then((d) => {
        if (d && d.sso_enabled) setOidc({ enabled: true, url: d.authorize_url, label: d.idp_label || '统一身份登录' });
      })
      .catch(() => setOidc({ enabled: false, url: '', label: '统一身份登录' }));
  }, []);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError('');
    setSubmitting(true);
    try {
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
      });
      if (res.ok) {
        const params = new URLSearchParams(window.location.search);
        window.location.href = params.get('from') ?? '/';
      } else {
        const data = await res.json().catch(() => ({}));
        setError(data.error === 'invalid_credentials' ? '用户名或密码错误' : data.error === 'auth_not_configured' ? '服务端未配置登录凭据' : '登录失败');
      }
    } catch {
      setError('网络错误，请重试');
    }
    setSubmitting(false);
  }

  return (
    <main style={{ minHeight: '100vh', display: 'grid', placeItems: 'center', background: 'radial-gradient(circle at 50% -20%, #143329 0, transparent 50%), #07110f', padding: 24 }}>
      <div className="animate-entrance" style={{ width: '100%', maxWidth: 380 }}>
        {/* Brand */}
        <div style={{ textAlign: 'center', marginBottom: 32 }}>
          <div style={{ width: 56, height: 56, margin: '0 auto 16px', borderRadius: 14, background: '#49e8a5', display: 'grid', placeItems: 'center', boxShadow: '0 0 40px #49e8a533' }}>
            <ShieldCheck size={28} color="#04100c" />
          </div>
          <h1 style={{ fontSize: 22, color: '#eaf7f2', letterSpacing: '-0.02em', margin: '0 0 6px' }}>Aegis 安全控制台</h1>
          <p style={{ fontSize: 13, color: '#78968c', margin: 0 }}>企业 AI Agent 安全治理平台</p>
        </div>

        {/* OIDC unified identity login (when configured) */}
        {oidc.enabled && (
          <div style={{ marginBottom: 16 }}>
            <Button
              type="button"
              onClick={() => { window.location.href = oidc.url; }}
              style={{ width: '100%', height: 42, background: '#143329', border: '1px solid #34765f', color: '#c9f5e4' }}
            >
              <KeyRound size={16} /> {oidc.label}
            </Button>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, margin: '14px 0', color: '#5e7c73', fontSize: 11 }}>
              <span style={{ flex: 1, height: 1, background: '#1e332d' }} /> 或使用本地账号 <span style={{ flex: 1, height: 1, background: '#1e332d' }} />
            </div>
          </div>
        )}

        {/* Login form */}
        <form onSubmit={handleSubmit} style={{ background: 'linear-gradient(145deg, #0d1b18, #0a1613)', border: '1px solid #1e332d', borderRadius: 14, padding: 28, boxShadow: '0 24px 64px #00000055' }}>
          {error && (
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '10px 12px', marginBottom: 16, borderRadius: 8, background: '#2b1515', border: '1px solid #5c2626', color: '#ff9b94', fontSize: 12 }}>
              <AlertTriangle size={14} /> {error}
            </div>
          )}

          <label style={{ display: 'block', fontSize: 12, color: '#86a39a', marginBottom: 6 }}>用户名</label>
          <div style={{ position: 'relative', marginBottom: 16 }}>
            <User size={15} style={{ position: 'absolute', left: 12, top: '50%', transform: 'translateY(-50%)', color: '#5e7c73' }} />
            <input
              className="form-input"
              style={{ paddingLeft: 36 }}
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="admin"
              autoComplete="username"
              required
            />
          </div>

          <label style={{ display: 'block', fontSize: 12, color: '#86a39a', marginBottom: 6 }}>密码</label>
          <div style={{ position: 'relative', marginBottom: 24 }}>
            <Lock size={15} style={{ position: 'absolute', left: 12, top: '50%', transform: 'translateY(-50%)', color: '#5e7c73' }} />
            <input
              className="form-input"
              type="password"
              style={{ paddingLeft: 36 }}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="••••••••"
              autoComplete="current-password"
              required
            />
          </div>

          <Button type="submit" disabled={submitting} style={{ width: '100%', height: 42 }}>
            {submitting ? '验证中...' : '登录'}
          </Button>
        </form>

        <p style={{ textAlign: 'center', fontSize: 11, color: '#5e7c73', marginTop: 20 }}>
          凭据由服务端 AEGIS_CONSOLE_USER / AEGIS_CONSOLE_PASSWORD 配置
        </p>
      </div>
    </main>
  );
}
