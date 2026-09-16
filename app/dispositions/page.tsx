'use client';

/**
 * 处置中心：对识别到的 Skill / MCP 打标 + 处置（加白 / 观察 / 拉黑）。
 * 数据源 = /api/labels（PG 持久化的真实注册表），非演示数据。
 * "导入策略已知 Skill" 从 /downloads/aegis-policy.json 的 allowed_skills 预置为加白。
 * "策略预览" 展示若按当前处置发布，策略的 allowed / monitor / blocked 列表将变成什么
 * （实际发布走发行级联，由管理员执行）。
 */
import { useCallback, useEffect, useState } from 'react';
import { useSearchParams } from 'next/navigation';
import Link from 'next/link';
import { Tags, ShieldCheck, ShieldAlert, Eye, Plus, Trash2, Download, Upload } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { useRole } from '@/components/role-context';
import { Pagination, paginate } from '@/components/pagination';
import { RiskSignalHelp } from '@/components/risk-signal-help';

interface Label {
  asset_type: 'skill' | 'mcp';
  asset_key: string;
  tags: string[];
  disposition: '' | 'allow' | 'monitor' | 'deny';
  note: string;
  updated_by: string;
  updated_at: number;
}

interface PolicyPreview {
  next_version: number;
  scan_mode: string;
  policy: { allowed_skills: string[]; allowed_mcp_servers: string[]; scan_mode: string };
  counts: { allow: number; monitor: number; deny: number };
}

interface CurrentRelease {
  published: boolean;
  version: number;
  created_at: number;
  created_by: string;
  signing_key_id: string;
  note: string;
  receipt: { label_counts: { allow: number; monitor: number; deny: number } };
  policy: { allowed_skills: string[]; allowed_mcp_servers: string[] };
}

const DISP_META: Record<Label['disposition'], { label: string; tone: string; icon: typeof Eye }> = {
  '': { label: '未处置', tone: 'outline', icon: Eye },
  allow: { label: '加白', tone: 'green', icon: ShieldCheck },
  monitor: { label: '观察', tone: 'blue', icon: Eye },
  deny: { label: '拉黑', tone: 'red', icon: ShieldAlert },
};

function relTime(ts: number): string {
  if (!ts) return '—';
  const s = Math.max(0, Math.floor((Date.now() - ts) / 1000));
  if (s < 60) return `${s} 秒前`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m} 分钟前`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h} 小时前`;
  return `${Math.floor(h / 24)} 天前`;
}

export default function DispositionsPage() {
  const { role } = useRole();
  const isAdmin = role === 'admin';
  const [labels, setLabels] = useState<Label[] | null>(null);
  // 规模化分页（几千处置项）：列表分页渲染。
  const [page, setPage] = useState(1);
  const PAGE_SIZE = 50;
  const [error, setError] = useState('');
  const [seedMsg, setSeedMsg] = useState('');
  const [busy, setBusy] = useState(false);
  const [preview, setPreview] = useState<PolicyPreview | null>(null);
  const [current, setCurrent] = useState<CurrentRelease | null>(null);
  const [publishing, setPublishing] = useState(false);
  const [publishMsg, setPublishMsg] = useState('');
  // 系统默认放行（原生自带）默认折叠，避免"加白"列表被非用户决策项刷屏（用户反馈）。
  const [showDefaults, setShowDefaults] = useState(false);

  // add form
  const [newType, setNewType] = useState<'skill' | 'mcp'>('skill');
  const [newKey, setNewKey] = useState('');
  const searchParams = useSearchParams();

  // 深链接：/dispositions?type=<skill|mcp>&asset=<key> 预填打标表单（来自风险中心"去处置"）。
  useEffect(() => {
    const type = searchParams.get('type');
    const asset = searchParams.get('asset');
    if (type === 'skill' || type === 'mcp') setNewType(type);
    if (asset) setNewKey(asset);
  }, [searchParams]);

  const load = useCallback(async () => {
    try {
      const r = await fetch('/api/labels', { cache: 'no-store' });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const d = (await r.json()) as { labels?: Label[] };
      setLabels(Array.isArray(d.labels) ? d.labels : []);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      setLabels([]);
    }
    // 服务端权威预览（admin）+ 当前生效发布件（任意登录身份）
    if (isAdmin) {
      fetch('/api/policy/preview', { cache: 'no-store' })
        .then((r) => (r.ok ? (r.json() as Promise<PolicyPreview>) : null))
        .then((d) => setPreview(d))
        .catch(() => setPreview(null));
    }
    fetch('/api/policy/current', { cache: 'no-store' })
      .then((r) => (r.ok ? (r.json() as Promise<CurrentRelease>) : null))
      .then((d) => setCurrent(d && d.published ? d : null))
      .catch(() => setCurrent(null));
  }, [isAdmin]);

  useEffect(() => {
    void load();
  }, [load]);

  async function save(asset: Label, patch: Partial<Label>) {
    setBusy(true);
    setError('');
    try {
      const r = await fetch('/api/labels', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ asset_type: asset.asset_type, asset_key: asset.asset_key, ...patch }),
      });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  async function addAsset() {
    const key = newKey.trim();
    if (!key) return;
    setBusy(true);
    setError('');
    try {
      const r = await fetch('/api/labels', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ asset_type: newType, asset_key: key, disposition: '', tags: [] }),
      });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      setNewKey('');
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  async function removeAsset(asset: Label) {
    const ok = window.confirm(
      `确认删除对「${asset.asset_key}」(${asset.asset_type}) 的处置打标？删除后该资产将回到"未处置"状态。`,
    );
    if (!ok) return;
    setBusy(true);
    setError('');
    try {
      const r = await fetch(`/api/labels?asset_type=${asset.asset_type}&asset_key=${encodeURIComponent(asset.asset_key)}`, { method: 'DELETE' });
      if (!r.ok) throw new Error(`删除失败 HTTP ${r.status}`);
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  async function seedDefaults() {
    setBusy(true);
    setError('');
    try {
      const r = await fetch('/api/labels/seed-defaults', { method: 'POST' });
      const d = (await r.json().catch(() => ({}))) as { seeded?: number; skipped?: number; error?: string };
      if (r.ok) setSeedMsg(`已录入默认自带白名单：新增 ${d.seeded ?? 0}，保留人工处置 ${d.skipped ?? 0}`);
      else setError(d.error ?? `录入失败 ${r.status}`);
      await load();
    } catch {
      setError('录入失败：网络错误');
    }
    setBusy(false);
  }
  async function importFromPolicy() {
    setBusy(true);
    setError('');
    try {
      const r = await fetch('/downloads/aegis-policy.json', { cache: 'no-store' });
      if (!r.ok) throw new Error(`policy HTTP ${r.status}`);
      const policy = (await r.json()) as { allowed_skills?: string[] };
      const skills = Array.isArray(policy.allowed_skills) ? policy.allowed_skills : [];
      let ok = 0;
      let failed = 0;
      for (const s of skills) {
        // 系统默认放行项已是 allow 且带 default-bundled 标签；重复导入会把它改写成
        // 用户"加白"(tags=策略已知)，重新刷屏处置中心。跳过，保持系统默认身份。
        const existing = (labels ?? []).find((l) => l.asset_type === 'skill' && l.asset_key === s);
        if (existing && existing.tags.includes('default-bundled')) continue;
        try {
          const res = await fetch('/api/labels', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ asset_type: 'skill', asset_key: s, disposition: 'allow', tags: ['策略已知'] }),
          });
          if (res.ok) ok += 1;
          else failed += 1;
        } catch {
          failed += 1;
        }
      }
      await load();
      if (failed > 0) setError(`导入完成：成功 ${ok} 条，失败 ${failed} 条。`);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  async function publishPolicy() {
    setPublishing(true);
    setPublishMsg('');
    try {
      const r = await fetch('/api/policy/publish', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({}) });
      const d = (await r.json().catch(() => ({}))) as { version?: number; error?: string };
      if (r.ok) setPublishMsg(`已发布签名策略 v${d.version}，终端下次加载即验签生效。`);
      else if (d.error === 'signing_key_not_configured') setPublishMsg('发布失败：服务端未配置签名密钥（AEGIS_POLICY_SIGNING_KEY）。');
      else setPublishMsg(`发布失败 HTTP ${r.status}`);
      await load();
    } catch (e) {
      setPublishMsg(e instanceof Error ? e.message : String(e));
    } finally {
      setPublishing(false);
    }
  }

  // 「系统默认放行」= 默认自带白名单(seed-defaults)写入、且用户未改动过(disposition 仍为
  // allow)的条目。它们仍参与抑制与策略编译，但**不在加白列表里作为用户决策展示**，
  // 单独折叠为一组，避免处置中心被非用户决策项刷屏（用户反馈"带来非常大困扰"）。
  const isSystemDefault = (l: Label) => l.tags.includes('default-bundled') && l.disposition === 'allow';
  const allLabels = labels ?? [];
  const defaultLabels = allLabels.filter(isSystemDefault);
  const userLabels = allLabels.filter((l) => !isSystemDefault(l));

  return (
    <>
      <div className="page-head animate-entrance animate-entrance-1">
        <div>
          <p className="eyebrow">治理 / 处置中心</p>
          <h1>Skill / MCP 打标与处置</h1>
          <p>对识别到的资产打业务标签，并决定加白 / 观察 / 拉黑；处置持久化并可发布为策略。</p>
        </div>
        <div className="head-actions">
          {isAdmin && (
            <Button variant="outline" onClick={() => void seedDefaults()} disabled={busy}>
              <ShieldCheck size={15} />
              录入默认自带白名单
            </Button>
          )}
          {isAdmin && (
            <Button variant="outline" onClick={() => void importFromPolicy()} disabled={busy}>
              <Download size={15} />
              导入策略已知 Skill
            </Button>
          )}
        </div>
      </div>

      {seedMsg && <p style={{ fontSize: 12, color: 'var(--primary)', margin: '0 0 10px' }}>{seedMsg}</p>}

      <RiskSignalHelp />

      {error && (
        <p style={{ color: '#ff685f', marginBottom: 12, fontSize: 13 }}>操作失败：{error}</p>
      )}

      {/* add asset */}
      {isAdmin && (
        <div className="panel animate-entrance animate-entrance-2" style={{ padding: 16, marginBottom: 16, display: 'flex', gap: 10, flexWrap: 'wrap', alignItems: 'center' }}>
          <select value={newType} onChange={(e) => setNewType(e.target.value as 'skill' | 'mcp')} style={{ padding: '6px 8px', borderRadius: 6, border: '1px solid var(--border)', background: 'var(--panel)', color: 'var(--text)' }}>
            <option value="skill">Skill</option>
            <option value="mcp">MCP</option>
          </select>
          <Input placeholder="资产标识（如 skill 名 / MCP server 或命令）" value={newKey} onChange={(e) => setNewKey(e.target.value)} style={{ maxWidth: 360 }} />
          <Button onClick={() => void addAsset()} disabled={busy || !newKey.trim()}>
            <Plus size={15} />
            添加资产
          </Button>
        </div>
      )}

      {/* 系统默认放行（默认折叠）：原生自带、自动加白，不作为用户"加白"决策展示 */}
      {defaultLabels.length > 0 && (
        <div className="panel animate-entrance animate-entrance-2" style={{ padding: 12, marginBottom: 16 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
            <Badge variant="outline">
              <ShieldCheck size={12} />
              系统默认放行 {defaultLabels.length} 项
            </Badge>
            <span style={{ fontSize: 12, color: 'var(--muted-foreground)' }}>
              AI Agent 原生自带的 skill / MCP，自动加白并参与告警抑制与策略编译；不计入你的处置决策、不在下方加白列表显示。
            </span>
            <Button variant="outline" size="sm" onClick={() => setShowDefaults((v) => !v)} style={{ marginLeft: 'auto' }}>
              {showDefaults ? '收起' : '展开查看 / 单独覆盖'}
            </Button>
          </div>
          {showDefaults && (
            <div style={{ marginTop: 10, display: 'grid', gap: 6 }}>
              {defaultLabels.map((l) => (
                <div key={`${l.asset_type}:${l.asset_key}`} style={{ display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap', fontSize: 12 }}>
                  <Badge variant="outline">{l.asset_type}</Badge>
                  <strong>{l.asset_key}</strong>
                  <Badge variant="outline">系统默认</Badge>
                  {isAdmin && (
                    <select
                      value={l.disposition}
                      disabled={busy}
                      onChange={(e) => void save(l, { disposition: e.target.value as Label['disposition'] })}
                      style={{ padding: '3px 6px', borderRadius: 6, border: '1px solid var(--border)', background: 'var(--panel)', color: 'var(--text)', fontSize: 12, marginLeft: 'auto' }}
                    >
                      <option value="allow">保持系统默认（加白）</option>
                      <option value="monitor">改为观察</option>
                      <option value="deny">改为拉黑</option>
                      <option value="">改为未处置</option>
                    </select>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* labels list（仅用户决策项；系统默认放行见上方折叠组） */}
      <div className="panel animate-entrance animate-entrance-3" style={{ padding: 8 }}>
        {labels === null ? (
          <p className="empty-hint">加载处置注册表…</p>
        ) : userLabels.length === 0 ? (
          <p className="empty-hint">暂无你的处置决策。可手动添加资产并加白 / 观察 / 拉黑；系统默认放行项见上方折叠组。</p>
        ) : (
          paginate(userLabels, page, PAGE_SIZE).rows.map((l) => {
            const meta = DISP_META[l.disposition];
            const Icon = meta.icon;
            return (
              <div key={`${l.asset_type}:${l.asset_key}`} style={{ display: 'flex', gap: 12, alignItems: 'center', padding: '10px 10px', borderBottom: '1px solid var(--border)', flexWrap: 'wrap' }}>
                <Badge variant="outline">{l.asset_type}</Badge>
                <strong style={{ minWidth: 180 }}>{l.asset_key}</strong>
                <span style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                  {l.tags.map((t) => (
                    <Badge key={t} variant="outline">
                      <Tags size={11} />
                      {t}
                    </Badge>
                  ))}
                </span>
                <Badge variant="outline">
                  <Icon size={12} />
                  {meta.label}
                </Badge>
                <span style={{ color: 'var(--muted-foreground)', fontSize: 12 }}>
                  {l.updated_by} · {relTime(l.updated_at)}
                </span>
                {isAdmin && (
                  <span style={{ marginLeft: 'auto', display: 'flex', gap: 6, alignItems: 'center' }}>
                    <select
                      value={l.disposition}
                      disabled={busy}
                      onChange={(e) => void save(l, { disposition: e.target.value as Label['disposition'] })}
                      style={{ padding: '4px 6px', borderRadius: 6, border: '1px solid var(--border)', background: 'var(--panel)', color: 'var(--text)', fontSize: 12 }}
                    >
                      <option value="">未处置</option>
                      <option value="allow">加白</option>
                      <option value="monitor">观察</option>
                      <option value="deny">拉黑</option>
                    </select>
                    <Input
                      placeholder="标签,逗号分隔"
                      defaultValue={l.tags.join(',')}
                      disabled={busy}
                      onBlur={(e) => {
                        const tags = e.target.value.split(',').map((s) => s.trim()).filter(Boolean);
                        if (tags.join(',') !== l.tags.join(',')) void save(l, { tags });
                      }}
                      style={{ width: 150, fontSize: 12 }}
                    />
                    <Button variant="outline" onClick={() => void removeAsset(l)} disabled={busy} aria-label="删除">
                      <Trash2 size={14} />
                    </Button>
                  </span>
                )}
              </div>
            );
          })
        )}
        {userLabels.length > 0 && (
          <Pagination
            page={page}
            pageCount={Math.max(1, Math.ceil(userLabels.length / PAGE_SIZE))}
            onPage={setPage}
            total={userLabels.length}
            pageSize={PAGE_SIZE}
          />
        )}
      </div>

      {/* policy publish (server-authoritative) */}
      <div className="panel animate-entrance animate-entrance-4" style={{ padding: 16, marginTop: 16 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 10, flexWrap: 'wrap' }}>
          <h2 style={{ fontSize: 15, margin: 0 }}>签名策略发布</h2>
          {current ? (
            <Badge variant="outline">
              <ShieldCheck size={12} /> 当前生效 v{current.version}
            </Badge>
          ) : (
            <Badge variant="outline">尚未发布</Badge>
          )}
          {isAdmin && preview && (
            <Button style={{ marginLeft: 'auto' }} onClick={() => void publishPolicy()} disabled={publishing}>
              <Upload size={15} />
              {publishing ? '发布中…' : `发布策略 (v${preview.next_version})`}
            </Button>
          )}
        </div>

        {current ? (
          <p style={{ color: 'var(--muted-foreground)', fontSize: 12, marginBottom: 10 }}>
            最近发布：v{current.version} · 签名密钥 {current.signing_key_id} · {current.created_by} ·{' '}
            {relTime(current.created_at)} · 回执 allow {current.receipt.label_counts.allow} / monitor{' '}
            {current.receipt.label_counts.monitor} / deny {current.receipt.label_counts.deny}
            {current.note ? ` · 备注「${current.note}」` : ''}。发布记录见{' '}
            <Link className="handle" href="/audit">审计日志</Link>。
          </p>
        ) : (
          <p style={{ color: 'var(--muted-foreground)', fontSize: 12, marginBottom: 10 }}>
            尚未发布任何策略；终端仍使用出厂默认策略。发布后，处置决定会编译成签名的 aegis.policy/v1 下发终端强制。
          </p>
        )}

        {publishMsg && (
          <p style={{ fontSize: 12, marginBottom: 10, color: publishMsg.startsWith('发布失败') ? '#ff685f' : '#49e8a5' }}>
            {publishMsg}
          </p>
        )}

        {preview ? (
          <>
            <p style={{ color: 'var(--muted-foreground)', fontSize: 12, marginBottom: 8 }}>
              服务端权威预览（与发布输出一致）：将编译 {preview.counts.allow} 加白 / {preview.counts.monitor} 观察 / {preview.counts.deny} 拉黑，扫描模式 {preview.scan_mode}。
              {defaultLabels.length > 0 && `（加白中含系统默认放行 ${defaultLabels.length} 项，它们不在上方处置列表显示）`}
            </p>
            <p style={{ fontSize: 13 }}>
              <b>加白 Skill</b>：{preview.policy.allowed_skills.join(', ') || '（空）'}
            </p>
            <p style={{ fontSize: 13 }}>
              <b>加白 MCP</b>：{preview.policy.allowed_mcp_servers.join(', ') || '（空）'}
            </p>
          </>
        ) : (
          <p className="empty-hint">{isAdmin ? '加载发布预览…' : '仅管理员可查看发布预览。'}</p>
        )}
      </div>
    </>
  );
}
