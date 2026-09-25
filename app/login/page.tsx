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
  // 4A · MFA 第二步：密码通过后服务端下发短期挑战令牌，此处输入 TOTP 码完成登录。
  const [mfaToken, setMfaToken] = useState<string | null>(null);
  const [mfaCode, setMfaCode] = useState('');

  useEffect(() => {
    fetch('/api/auth/providers', { cache: 'no-store' })
      .then((r) => (r.ok ? (r.json() as Promise<any>) : null))
      .then((d) => {
        if (d && d.sso_enabled) setOidc({ enabled: true, url: d.authorize_url, label: d.idp_label || '统一身份登录' });
      })
      .catch(() => setOidc({ enabled: false, url: '', label: '统一身份登录' }));
  }, []);

  // Surface SSO callback errors passed via URL (?error=...)
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const err = params.get('error');
    if (err) {
      const map: Record<string, string> = {
        missing_uac_token: '统一身份登录未完成，请重试',
        not_authorized: '该账号不在管理员白名单，拒绝登录',
        uac_token_invalid: '统一身份校验失败，请重试',
        uac_not_configured: '服务端未配置统一身份登录',
        uac_unreachable: '统一身份服务暂不可达，请稍后重试',
      };
      setError(map[err] ?? '登录失败，请重试');
    }
    // SSO 通过后若需 MFA：挑战令牌经 URL fragment 送达（不进服务端日志/历史），
    // 读取后立即从地址栏清除，进入第二步输入 TOTP。
    const hash = window.location.hash;
    if (hash.startsWith('#mfa=')) {
      const token = decodeURIComponent(hash.slice('#mfa='.length));
      if (token) {
        setMfaToken(token);
        setError('');
        window.history.replaceState(null, '', window.location.pathname + window.location.search);
      }
    }
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
        const data = (await res.json().catch(() => ({}))) as { mfa_required?: boolean; mfa_token?: string };
        if (data.mfa_required && data.mfa_token) {
          // 进入第二步：输入 authenticator 的 6 位 TOTP 码。
          setMfaToken(data.mfa_token);
          setError('');
          setSubmitting(false);
          return;
        }
        const params = new URLSearchParams(window.location.search);
        const raw = params.get('from') ?? '/';
        // Only allow a same-origin relative path; block '//host' and 'scheme://…'
        // to prevent open-redirect via a crafted ?from= parameter.
        const safe = raw.startsWith('/') && !raw.startsWith('//') && !raw.includes('\\') ? raw : '/';
        window.location.href = safe;
      } else {
        const data = (await res.json().catch(() => ({}))) as any;
        setError(data.error === 'invalid_credentials' ? '用户名或密码错误' : data.error === 'auth_not_configured' ? '服务端未配置登录凭据' : '登录失败');
      }
    } catch {
      setError('网络错误，请重试');
    }
    setSubmitting(false);
  }

  /** MFA 第二步：提交 TOTP 码换取会话。 */
  async function handleMfaSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError('');
    setSubmitting(true);
    try {
      const res = await fetch('/api/auth/mfa', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'verify', mfa_token: mfaToken, code: mfaCode }),
      });
      if (res.ok) {
        const params = new URLSearchParams(window.location.search);
        const raw = params.get('from') ?? '/';
        const safe = raw.startsWith('/') && !raw.startsWith('//') && !raw.includes('\\') ? raw : '/';
        window.location.href = safe;
        return;
      }
      const data = (await res.json().catch(() => ({}))) as any;
      setError(data.error === 'invalid_mfa_code' ? '验证码错误或已过期' : data.error === 'invalid_mfa_token' ? '验证挑战已失效，请重新登录' : '验证失败');
      if (data.error === 'invalid_mfa_token') setMfaToken(null);
    } catch {
      setError('网络错误，请重试');
    }
    setSubmitting(false);
  }

  return (
    <main
      className="sentinel-grid-bg"
      style={{
        minHeight: '100vh',
        display: 'grid',
        placeItems: 'center',
        // Sentinel 深色底 + 顶部青绿微光（与全站一致），不再使用旧绿色整页晕染
        background: 'radial-gradient(circle at 50% -20%, rgba(18, 81, 92, 0.18) 0, transparent 52%), var(--sentinel-bg-deep, #040b12)',
        padding: 24,
      }}
    >
      <div className="animate-entrance" style={{ width: '100%', maxWidth: 380 }}>
        {/* Brand */}
        <div style={{ textAlign: 'center', marginBottom: 32 }}>
          <div style={{ width: 56, height: 56, margin: '0 auto 16px', borderRadius: 14, background: 'var(--sentinel-surface-2, #0d202c)', border: '1px solid var(--sentinel-line, rgba(111,173,204,0.22))', display: 'grid', placeItems: 'center' }}>
            <ShieldCheck size={28} color="var(--sentinel-accent)" />
          </div>
          <h1 style={{ fontSize: 22, color: 'var(--sentinel-text, #edf7fb)', letterSpacing: '-0.02em', margin: '0 0 6px' }}>Aegis 安全控制台</h1>
          <p style={{ fontSize: 13, color: 'var(--sentinel-text-3, #6c8796)', margin: 0 }}>企业 AI Agent 安全治理平台</p>
        </div>

        {/* OIDC unified identity login (when configured) */}
        {oidc.enabled && (
          <div style={{ marginBottom: 16 }}>
            <Button
              type="button"
              onClick={() => { window.location.href = oidc.url; }}
              style={{ width: '100%', height: 42, background: 'var(--sentinel-surface-2, #0d202c)', border: '1px solid var(--sentinel-line-strong, rgba(111,221,239,0.44))', color: 'var(--sentinel-text, #edf7fb)' }}
            >
              <KeyRound size={16} /> {oidc.label}
            </Button>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, margin: '14px 0', color: 'var(--sentinel-text-3, #6c8796)', fontSize: 11 }}>
              <span style={{ flex: 1, height: 1, background: 'var(--sentinel-line, rgba(111,173,204,0.22))' }} /> 或使用本地账号 <span style={{ flex: 1, height: 1, background: 'var(--sentinel-line, rgba(111,173,204,0.22))' }} />
            </div>
          </div>
        )}

        {/* 4A · MFA 第二步（仅当服务端下发挑战时显示） */}
        {mfaToken ? (
          <form onSubmit={handleMfaSubmit} style={{ background: 'var(--sentinel-surface)', border: '1px solid var(--sentinel-line, rgba(111,173,204,0.22))', borderRadius: 'var(--sentinel-radius-lg)', padding: 28, boxShadow: 'var(--shadow-overlay)' }}>
            {error && (
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '10px 12px', marginBottom: 16, borderRadius: 8, background: 'color-mix(in srgb, var(--sentinel-danger) 12%, transparent)', border: '1px solid color-mix(in srgb, var(--sentinel-danger) 40%, transparent)', color: 'var(--sentinel-danger)', fontSize: 12 }}>
                <AlertTriangle size={14} /> {error}
              </div>
            )}
            <label style={{ display: 'block', fontSize: 12, color: 'var(--sentinel-text-2, #a5bdc9)', marginBottom: 6 }}>两步验证码（6 位）</label>
            <input
              className="form-input"
              style={{ marginBottom: 24, textAlign: 'center', letterSpacing: '0.4em', fontSize: 18 }}
              value={mfaCode}
              onChange={(e) => setMfaCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
              placeholder="000000"
              inputMode="numeric"
              autoComplete="one-time-code"
              required
            />
            <Button type="submit" disabled={submitting} style={{ width: '100%', height: 42 }}>
              {submitting ? '验证中…' : '验证并登录'}
            </Button>
            <button
              type="button"
              onClick={() => { setMfaToken(null); setMfaCode(''); setError(''); }}
              style={{ width: '100%', marginTop: 12, background: 'none', border: 0, color: 'var(--sentinel-text-3, #6c8796)', fontSize: 12, cursor: 'pointer' }}
            >
              返回重新登录
            </button>
          </form>
        ) : (
        /* Login form */
        <form onSubmit={handleSubmit} style={{ background: 'var(--sentinel-surface)', border: '1px solid var(--sentinel-line, rgba(111,173,204,0.22))', borderRadius: 'var(--sentinel-radius-lg)', padding: 28, boxShadow: 'var(--shadow-overlay)' }}>
          {error && (
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '10px 12px', marginBottom: 16, borderRadius: 8, background: 'color-mix(in srgb, var(--sentinel-danger) 12%, transparent)', border: '1px solid color-mix(in srgb, var(--sentinel-danger) 40%, transparent)', color: 'var(--sentinel-danger)', fontSize: 12 }}>
              <AlertTriangle size={14} /> {error}
            </div>
          )}

          <label style={{ display: 'block', fontSize: 12, color: 'var(--sentinel-text-2, #a5bdc9)', marginBottom: 6 }}>用户名</label>
          <div style={{ position: 'relative', marginBottom: 16 }}>
            <User size={15} style={{ position: 'absolute', left: 12, top: '50%', transform: 'translateY(-50%)', color: 'var(--sentinel-text-3, #6c8796)' }} />
            <input
              className="form-input"
              style={{ paddingLeft: 36 }}
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="请输入工号 / 用户名"
              autoComplete="username"
              required
            />
          </div>

          <label style={{ display: 'block', fontSize: 12, color: 'var(--sentinel-text-2, #a5bdc9)', marginBottom: 6 }}>密码</label>
          <div style={{ position: 'relative', marginBottom: 24 }}>
            <Lock size={15} style={{ position: 'absolute', left: 12, top: '50%', transform: 'translateY(-50%)', color: 'var(--sentinel-text-3, #6c8796)' }} />
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
            {submitting ? '验证中…' : '登录'}
          </Button>
        </form>
        )}

        <p style={{ textAlign: 'center', fontSize: 11, color: 'var(--sentinel-text-3, #6c8796)', marginTop: 20 }}>
          仅限授权人员访问；如需账号请联系安全管理员
        </p>
      </div>
    </main>
  );
}
