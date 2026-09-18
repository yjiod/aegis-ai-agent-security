'use client';

import { useCallback, useEffect, useState } from 'react';
import { ShieldCheck, QrCode, X } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';

/**
 * 我的两步验证（TOTP）管理面板（4A · Authentication）。
 *
 * 流程：启用 → 服务端生成 base32 密钥 + otpauth:// URI（展示供 authenticator 扫码/
 * 手动录入）→ 用户提交一个当前 6 位码确认（防绑错设备）→ 启用后登录强制二次验证。
 * 停用需再提交一个有效码。所有动作服务端留审计。PG 不可用时如实报错。
 */
export function MfaPanel() {
  const [enabled, setEnabled] = useState<boolean | null>(null);
  const [secret, setSecret] = useState('');
  const [uri, setUri] = useState('');
  const [code, setCode] = useState('');
  const [msg, setMsg] = useState('');
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      const r = await fetch('/api/auth/mfa', { cache: 'no-store' });
      if (r.ok) {
        const d = (await r.json()) as { enabled?: boolean };
        setEnabled(Boolean(d.enabled));
      } else setEnabled(null);
    } catch {
      setEnabled(null);
    }
  }, []);

  useEffect(() => { void load(); }, [load]);

  async function post(action: string, extra: Record<string, string> = {}) {
    setBusy(true);
    setMsg('');
    try {
      const r = await fetch('/api/auth/mfa', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action, ...extra }),
      });
      const d = (await r.json().catch(() => ({}))) as Record<string, unknown>;
      if (!r.ok) {
        setMsg(String(d.hint ?? d.error ?? '操作失败'));
        return false;
      }
      return d;
    } catch {
      setMsg('网络错误');
      return false;
    } finally {
      setBusy(false);
    }
  }

  async function startEnroll() {
    const d = await post('enroll');
    if (d) {
      setSecret(String(d.secret ?? ''));
      setUri(String(d.otpauth_uri ?? ''));
      setMsg('');
    }
  }

  async function confirm() {
    const d = await post('confirm', { code });
    if (d) {
      setEnabled(true);
      setSecret('');
      setUri('');
      setCode('');
      setMsg('两步验证已启用，下次登录需输入验证码。');
    }
  }

  async function disable() {
    const d = await post('disable', { code });
    if (d) {
      setEnabled(false);
      setCode('');
      setMsg('两步验证已停用。');
    }
  }

  return (
    <div className="panel" style={{ marginTop: 24 }}>
      <div className="panel-head">
        <div>
          <h2>我的两步验证（TOTP）</h2>
          <p>为当前账号启用基于时间的一次性密码；启用后登录需密码 + 6 位验证码。</p>
        </div>
        <span className={`status ${enabled ? 'green' : 'blue'}`}>
          <ShieldCheck size={13} /> {enabled === null ? '状态未知' : enabled ? '已启用' : '未启用'}
        </span>
      </div>

      {msg && <p style={{ fontSize: 12, color: 'var(--muted-foreground)', margin: '0 0 10px' }}>{msg}</p>}

      {secret ? (
        <div style={{ display: 'grid', gap: 10 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12, color: 'var(--muted-foreground)' }}>
            <QrCode size={14} /> 将下列密钥录入身份验证器 App（或扫码添加）：
          </div>
          <code style={{ fontSize: 12, wordBreak: 'break-all', background: 'var(--muted)', padding: '8px 10px', borderRadius: 8 }}>{secret}</code>
          <code style={{ fontSize: 10, wordBreak: 'break-all', color: 'var(--muted-foreground)' }}>{uri}</code>
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            <Input
              value={code}
              onChange={(e) => setCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
              placeholder="当前 6 位验证码"
              inputMode="numeric"
              style={{ width: 180 }}
            />
            <Button onClick={() => void confirm()} disabled={busy || code.length !== 6}>确认启用</Button>
            <Button variant="outline" onClick={() => { setSecret(''); setUri(''); setCode(''); }} disabled={busy}>
              <X size={14} /> 取消
            </Button>
          </div>
        </div>
      ) : enabled ? (
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
          <Input
            value={code}
            onChange={(e) => setCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
            placeholder="当前 6 位验证码"
            inputMode="numeric"
            style={{ width: 180 }}
          />
          <Button variant="outline" onClick={() => void disable()} disabled={busy || code.length !== 6}>
            停用两步验证
          </Button>
        </div>
      ) : (
        <Button onClick={() => void startEnroll()} disabled={busy || enabled === null}>
          <ShieldCheck size={14} /> 启用两步验证
        </Button>
      )}
    </div>
  );
}
