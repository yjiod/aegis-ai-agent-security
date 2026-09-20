'use client';

/**
 * components/evidence-dialog.tsx — 审计/证据导出包对话框。
 *
 * 两块能力：
 *  1) 生成：选范围（全舰队/单设备）、时间窗、sections、脱敏级别 → 拼 GET /api/evidence
 *     查询串并触发附件下载（同源 cookie 鉴权，服务端会写一条 evidence:export 审计）。
 *  2) 验证：把已有证据包文件 POST /api/evidence/verify，即时核对完整性/签名结论。
 *     （权威离线验证仍是 scripts/verify-evidence-bundle.py，接收方无需控制台账号。）
 *
 * verbose 脱敏保留真实路径/IP/os_user，仅管理员可选；standard 伪名化个人标识。
 */

import { useMemo, useState } from 'react';
import { AlertTriangle, CircleCheck, Download, FileSearch, X } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { useRole } from '@/components/role-context';

const SECTION_OPTIONS: { key: string; label: string }[] = [
  { key: 'inventory', label: '终端清单' },
  { key: 'findings', label: '扫描发现' },
  { key: 'tickets', label: '风险工单' },
  { key: 'enforcement', label: '执行回执' },
  { key: 'audit', label: '审计日志' },
  { key: 'policy', label: '策略姿态' },
  { key: 'canary', label: '灰度/自更' },
];

const WINDOW_OPTIONS: { key: string; label: string; ms: number | null }[] = [
  { key: 'all', label: '全部时间', ms: null },
  { key: '24h', label: '最近 24 小时', ms: 24 * 3600_000 },
  { key: '7d', label: '最近 7 天', ms: 7 * 24 * 3600_000 },
  { key: '30d', label: '最近 30 天', ms: 30 * 24 * 3600_000 },
];

interface VerifyResult {
  ok: boolean;
  schema_ok: boolean;
  ed25519_ok: boolean | null;
  manifest_ok: boolean;
  mismatched: string[];
  reason?: string;
}

const labelStyle: React.CSSProperties = { display: 'block', fontSize: 12, color: 'var(--muted-foreground)', marginBottom: 6 };
const rowStyle: React.CSSProperties = { display: 'flex', gap: 8, flexWrap: 'wrap' };

export function EvidenceDialog({ onClose }: { onClose: () => void }) {
  const { role } = useRole();
  const isAdmin = role === 'admin';

  const [scope, setScope] = useState<'fleet' | 'device'>('fleet');
  const [deviceId, setDeviceId] = useState('');
  const [window_, setWindow] = useState('all');
  const [sections, setSections] = useState<string[]>(SECTION_OPTIONS.map((s) => s.key));
  const [redaction, setRedaction] = useState<'standard' | 'verbose'>('standard');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [note, setNote] = useState('');

  const [verifying, setVerifying] = useState(false);
  const [verifyResult, setVerifyResult] = useState<VerifyResult | null>(null);
  const [verifyError, setVerifyError] = useState('');

  const query = useMemo(() => {
    const p = new URLSearchParams();
    if (scope === 'device' && deviceId.trim()) p.set('device_id', deviceId.trim());
    const w = WINDOW_OPTIONS.find((o) => o.key === window_);
    if (w?.ms) p.set('since', String(Date.now() - w.ms));
    if (sections.length > 0 && sections.length < SECTION_OPTIONS.length) p.set('sections', sections.join(','));
    p.set('redaction', redaction);
    return p.toString();
  }, [scope, deviceId, window_, sections, redaction]);

  function toggleSection(key: string) {
    setSections((prev) => (prev.includes(key) ? prev.filter((k) => k !== key) : [...prev, key]));
  }

  async function generate() {
    setError('');
    setNote('');
    if (sections.length === 0) { setError('至少选择一个 section'); return; }
    if (scope === 'device' && !deviceId.trim()) { setError('单设备范围需要填写 device_id'); return; }
    if (redaction === 'verbose' && !isAdmin) { setError('verbose 脱敏仅管理员可用'); return; }
    setBusy(true);
    try {
      // 用隐藏 anchor 触发附件下载（同源 cookie 自动带上）；不导航离开当前页。
      const a = document.createElement('a');
      a.href = `/api/evidence?${query}`;
      a.download = '';
      document.body.appendChild(a);
      a.click();
      a.remove();
      setNote('已请求生成，浏览器将下载签名证据包（.json）。该导出已记入审计日志。');
    } catch {
      setError('生成失败，请重试');
    }
    setBusy(false);
  }

  async function verifyFile(file: File) {
    setVerifying(true);
    setVerifyError('');
    setVerifyResult(null);
    try {
      const text = await file.text();
      const res = await fetch('/api/evidence/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: text,
      });
      if (!res.ok) {
        const data = (await res.json().catch(() => ({}))) as { message?: string; error?: string };
        setVerifyError(data.message ?? data.error ?? `验证请求失败 HTTP ${res.status}`);
      } else {
        setVerifyResult((await res.json()) as VerifyResult);
      }
    } catch {
      setVerifyError('读取文件或网络错误，请重试');
    }
    setVerifying(false);
  }

  return (
    <div style={{ position: 'fixed', inset: 0, zIndex: 50, display: 'grid', placeItems: 'center', background: '#020806b8', backdropFilter: 'blur(4px)' }} onClick={onClose}>
      <div
        className="animate-entrance"
        style={{ width: '100%', maxWidth: 520, maxHeight: '88vh', overflowY: 'auto', background: 'var(--card)', border: '1px solid var(--border)', borderRadius: 14, padding: 24, boxShadow: '0 24px 64px #00000055', color: 'var(--card-foreground)' }}
        onClick={(e) => e.stopPropagation()}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <FileSearch size={18} style={{ color: 'var(--ring)' }} />
            <h2 style={{ fontSize: 16, margin: 0 }}>审计 / 证据导出包</h2>
          </div>
          <button onClick={onClose} style={{ background: 'none', border: 0, color: 'var(--muted-foreground)', cursor: 'pointer' }} aria-label="关闭">
            <X size={18} />
          </button>
        </div>

        {/* 生成 */}
        <label style={labelStyle}>范围</label>
        <div style={{ ...rowStyle, marginBottom: 14 }}>
          <button className={`filter-btn ${scope === 'fleet' ? 'active' : ''}`} onClick={() => setScope('fleet')}>全舰队</button>
          <button className={`filter-btn ${scope === 'device' ? 'active' : ''}`} onClick={() => setScope('device')}>单设备</button>
          {scope === 'device' && (
            <input className="form-input" placeholder="终端 ID（12 位小写十六进制）" value={deviceId} onChange={(e) => setDeviceId(e.target.value)} style={{ flex: 1, minWidth: 180 }} />
          )}
        </div>

        <label style={labelStyle}>时间窗</label>
        <div style={{ ...rowStyle, marginBottom: 14 }}>
          {WINDOW_OPTIONS.map((o) => (
            <button key={o.key} className={`filter-btn ${window_ === o.key ? 'active' : ''}`} onClick={() => setWindow(o.key)}>{o.label}</button>
          ))}
        </div>

        <label style={labelStyle}>包含内容（sections）</label>
        <div style={{ ...rowStyle, marginBottom: 14 }}>
          {SECTION_OPTIONS.map((s) => (
            <button key={s.key} className={`filter-btn ${sections.includes(s.key) ? 'active' : ''}`} onClick={() => toggleSection(s.key)}>{s.label}</button>
          ))}
        </div>

        <label style={labelStyle}>脱敏级别</label>
        <div style={{ ...rowStyle, marginBottom: 6 }}>
          <button className={`filter-btn ${redaction === 'standard' ? 'active' : ''}`} onClick={() => setRedaction('standard')}>standard（默认·伪名化）</button>
          <button
            className={`filter-btn ${redaction === 'verbose' ? 'active' : ''}`}
            onClick={() => isAdmin && setRedaction('verbose')}
            disabled={!isAdmin}
            style={!isAdmin ? { opacity: 0.4, cursor: 'not-allowed' } : undefined}
            title={isAdmin ? '保留真实路径/IP/os_user（secret 仍打码）' : '仅管理员可用'}
          >
            verbose（管理员）
          </button>
        </div>
        <p style={{ margin: '0 0 16px', fontSize: 11, color: 'var(--muted-foreground)', lineHeight: 1.5 }}>
          standard：os_user 伪名化为 hash、路径 ~/ 前缀、IP/MAC/序列号打码、secret 恒 [REDACTED]、证据文本截断 180。
          verbose：保留运维细节，secret 仍恒打码。整包经 ed25519 签名，公钥随包携带，可离线验证。
        </p>

        {error && (
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '10px 12px', marginBottom: 12, borderRadius: 8, background: 'color-mix(in srgb, var(--destructive) 14%, transparent)', border: '1px solid color-mix(in srgb, var(--destructive) 40%, transparent)', color: 'var(--destructive)', fontSize: 12 }}>
            <AlertTriangle size={14} /> {error}
          </div>
        )}
        {note && (
          <div style={{ display: 'flex', alignItems: 'flex-start', gap: 8, padding: '10px 12px', marginBottom: 12, borderRadius: 8, background: 'color-mix(in srgb, var(--ring) 12%, transparent)', border: '1px solid color-mix(in srgb, var(--ring) 34%, transparent)', fontSize: 12 }}>
            <CircleCheck size={14} style={{ flexShrink: 0, marginTop: 2, color: 'var(--ring)' }} /> {note}
          </div>
        )}

        <div style={{ display: 'flex', gap: 8, marginBottom: 20 }}>
          <Button onClick={generate} disabled={busy} style={{ flex: 1 }}>
            <Download size={16} />
            {busy ? '生成中…' : '生成并下载证据包'}
          </Button>
          <Button variant="outline" onClick={onClose}>关闭</Button>
        </div>

        {/* 验证 */}
        <div style={{ borderTop: '1px solid var(--border)', paddingTop: 16 }}>
          <label style={labelStyle}>验证已有证据包（控制台内便捷核对）</label>
          <input
            type="file"
            accept="application/json,.json"
            disabled={verifying}
            onChange={(e) => { const f = e.target.files?.[0]; if (f) void verifyFile(f); e.target.value = ''; }}
            style={{ fontSize: 12, color: 'var(--muted-foreground)', marginBottom: 10 }}
          />
          {verifyError && (
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '10px 12px', borderRadius: 8, background: 'color-mix(in srgb, var(--destructive) 14%, transparent)', border: '1px solid color-mix(in srgb, var(--destructive) 40%, transparent)', color: 'var(--destructive)', fontSize: 12 }}>
              <AlertTriangle size={14} /> {verifyError}
            </div>
          )}
          {verifyResult && (
            <div style={{ padding: 12, borderRadius: 8, background: 'var(--accent)', border: '1px solid var(--border)', fontSize: 12, lineHeight: 1.7 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontWeight: 600, color: verifyResult.ok ? 'var(--ring)' : 'var(--destructive)' }}>
                {verifyResult.ok ? <CircleCheck size={15} /> : <AlertTriangle size={15} />}
                {verifyResult.ok ? '完整可信，未被篡改' : '验证未通过'}
              </div>
              <div style={{ color: 'var(--muted-foreground)' }}>
                schema：{verifyResult.schema_ok ? '通过' : '失败'} ·
                manifest：{verifyResult.manifest_ok ? '通过' : `不符（${verifyResult.mismatched.join(', ') || '—'}）`} ·
                ed25519：{verifyResult.ed25519_ok === true ? '通过' : verifyResult.ed25519_ok === null ? '未签名' : '失败'}
                {verifyResult.reason ? ` · 原因：${verifyResult.reason}` : ''}
              </div>
            </div>
          )}
          <p style={{ margin: '10px 0 0', fontSize: 11, color: 'var(--muted-foreground)', lineHeight: 1.5 }}>
            交接给外部审计方时，对方无需控制台账号，直接运行
            <code style={{ margin: '0 3px' }}>python3 scripts/verify-evidence-bundle.py &lt;bundle.json&gt;</code>
            即可离线验签（退出码 0=通过 / 1=篡改 / 3=未签名）。
          </p>
        </div>
      </div>
    </div>
  );
}
