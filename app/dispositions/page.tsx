'use client';

/**
 * 处置中心：对识别到的 Skill / MCP 打标 + 处置（加白 / 观察 / 拉黑）。
 * 数据源 = /api/labels（PG 持久化的真实注册表），非演示数据。
 * "导入策略已知 Skill" 从 /downloads/aegis-policy.json 的 allowed_skills 预置为加白。
 * "策略预览" 展示若按当前处置发布，策略的 allowed / monitor / blocked 列表将变成什么
 * （实际发布走发行级联，由管理员执行）。
 */
import { useCallback, useEffect, useMemo, useState } from 'react';
import { useSearchParams } from 'next/navigation';
import Link from 'next/link';
import { Tags, ShieldCheck, ShieldAlert, Eye, Plus, Trash2, Download, Upload, ChevronDown, Library, UserCog } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { useRole } from '@/components/role-context';
import { RiskSignalHelp } from '@/components/risk-signal-help';
import { ActionConfirmDialog } from '@/components/action-confirm-dialog';

interface Label {
  asset_type: 'skill' | 'mcp' | 'path';
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
  const { role, subject } = useRole();
  const isAdmin = role === 'admin';
  const [labels, setLabels] = useState<Label[] | null>(null);
  // 规模化分页（几千处置项）：列表分页渲染。
  const [error, setError] = useState('');
  const [seedMsg, setSeedMsg] = useState('');
  const [busy, setBusy] = useState(false);
  const [pendingRemove, setPendingRemove] = useState<Label | null>(null);
  const [preview, setPreview] = useState<PolicyPreview | null>(null);
  const [current, setCurrent] = useState<CurrentRelease | null>(null);
  const [publishing, setPublishing] = useState(false);
  const [publishMsg, setPublishMsg] = useState('');
  // 封禁爆炸半径闸(PM 评审 #1): 发布被 409 拦截时展示精确影响清单 + typed override 输入。
  const [blast, setBlast] = useState<{ hint: string; impact: { device_id: string; skills: string[]; mcp: string[]; count: number; pct: number }[]; override: string } | null>(null);
  const [blastInput, setBlastInput] = useState('');
  // 发布前爆炸半径预览：客户端用 /api/devices 的 skills/mcp_assets 与当前 deny 集合预测影响，
  // 让运维在点"发布"前就看到影响面与闸判定（此前只有被 409 拦下后才看到）。
  const [devAssets, setDevAssets] = useState<
    { device_id: string; skills: string[]; mcp_assets: string[]; exempt: boolean }[]
  >([]);
  // 系统默认放行（原生自带）默认折叠，避免"加白"列表被非用户决策项刷屏（用户反馈）。
  const [showDefaults, setShowDefaults] = useState(false);

  // 2026-09 改版（处置中心 IA）：自定义库按资产类型分组折叠 + 搜索/筛选 + 组内增量加载，
  // 应对几百上千条加白时的可读性与性能（旧版为单一平铺分页列表）。
  const [query, setQuery] = useState('');
  const [typeFilter, setTypeFilter] = useState<'all' | 'skill' | 'mcp' | 'path'>('all');
  const [dispFilter, setDispFilter] = useState<'all' | 'allow' | 'monitor' | 'deny'>('all');
  const [collapsed, setCollapsed] = useState<Record<string, boolean>>({});
  const [groupLimit, setGroupLimit] = useState<Record<string, number>>({});
  const GROUP_PAGE = 20;

  // add form
  const [newType, setNewType] = useState<'skill' | 'mcp' | 'path'>('skill');
  const [newKey, setNewKey] = useState('');
  const searchParams = useSearchParams();

  // 深链接：/dispositions?type=<skill|mcp>&asset=<key> 预填打标表单（来自风险中心"去处置"）。
  useEffect(() => {
    const type = searchParams.get('type');
    const asset = searchParams.get('asset');
    if (type === 'skill' || type === 'mcp' || type === 'path') setNewType(type);
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
    // 设备可封禁资产面（skills/mcp_assets）用于发布前爆炸半径预览；失败不阻塞主流程。
    fetch('/api/devices', { cache: 'no-store' })
      .then((r) => (r.ok ? (r.json() as Promise<Record<string, unknown>>) : null))
      .then((d) => {
        const list = Array.isArray((d as { devices?: unknown[] } | null)?.devices)
          ? ((d as { devices: Array<Record<string, unknown>> }).devices)
          : [];
        setDevAssets(
          list.map((x) => ({
            device_id: String(x.device_id ?? ''),
            skills: Array.isArray(x.skills) ? (x.skills as string[]) : [],
            mcp_assets: Array.isArray(x.mcp_assets) ? (x.mcp_assets as string[]) : [],
            exempt: x.exempt === true,
          })),
        );
      })
      .catch(() => setDevAssets([]));
  }, [isAdmin]);

  useEffect(() => {
    void load();
  }, [load]);

  // 发布前爆炸半径预测（与服务端发布闸同口径：豁免设备排除；pct=该设备被 deny 的 skill 数/其 skill 总数）。
  const predicted = useMemo(() => {
    const all = labels ?? [];
    const denySkills = new Set(
      all.filter((l) => l.disposition === 'deny' && l.asset_type === 'skill').map((l) => l.asset_key),
    );
    const denyMcp = new Set(
      all.filter((l) => l.disposition === 'deny' && l.asset_type === 'mcp').map((l) => l.asset_key),
    );
    const impact = devAssets
      .filter((d) => !d.exempt)
      .map((d) => {
        const s = d.skills.filter((x) => denySkills.has(x));
        const m = d.mcp_assets.filter((x) => denyMcp.has(x));
        const denom = d.skills.length;
        return { device_id: d.device_id, skills: s, mcp: m, count: s.length + m.length, pct: denom ? Math.round((100 * s.length) / denom) : 0 };
      })
      .filter((x) => x.count > 0);
    const total = impact.reduce((a, b) => a + b.count, 0);
    const maxPct = impact.reduce((a, b) => Math.max(a, b.pct), 0);
    const bulkNames = denySkills.size + denyMcp.size;
    const absExceeded = total > 20 || impact.some((x) => x.pct > 50) || bulkNames > 20;
    const exceeded = total > 5 || impact.some((x) => x.pct > 10) || bulkNames > 5;
    return { impact, total, maxPct, bulkNames, absExceeded, exceeded };
  }, [labels, devAssets]);

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

  /** 删除处置打标 = 不可逆动作，统一经确认弹窗（影响范围 + 回滚）后执行。 */
  async function confirmRemove() {
    if (!pendingRemove || busy) return;
    await removeAsset(pendingRemove);
    setPendingRemove(null);
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

  async function publishPolicy(override?: string) {
    setPublishing(true);
    setPublishMsg('');
    try {
      const r = await fetch('/api/policy/publish', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(override ? { override } : {}) });
      const d = (await r.json().catch(() => ({}))) as { version?: number; error?: string; hint?: string; impact?: { device_id: string; skills: string[]; mcp: string[]; count: number; pct: number }[]; caps?: { override?: string } };
      if (r.ok) { setPublishMsg(`已发布签名策略 v${d.version}，终端下次加载即验签生效。`); setBlast(null); setBlastInput(''); }
      else if (d.error === 'blast_radius_exceeded') { setBlast({ hint: d.hint ?? '', impact: d.impact ?? [], override: d.caps?.override ?? '' }); setPublishMsg('发布被爆炸半径闸拦截：影响面超上限，见下方清单。'); }
      else if (d.error === 'signing_key_not_configured') setPublishMsg('发布失败：服务端未配置签名密钥（AEGIS_POLICY_SIGNING_KEY）。');
      else setPublishMsg(`发布失败 HTTP ${r.status}`);
      await load();
    } catch (e) {
      setPublishMsg(e instanceof Error ? e.message : String(e));
    } finally {
      setPublishing(false);
    }
  }

  // 一键回滚(PM 评审 #1): 把上一个被取代版本的内容以新版本号重签发布, 历史不改。
  async function rollback() {
    setPublishing(true);
    setPublishMsg('');
    try {
      const r = await fetch('/api/policy/rollback', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({}) });
      const d = (await r.json().catch(() => ({}))) as { version?: number; rolled_back_to?: number; error?: string; hint?: string };
      if (r.ok) setPublishMsg(`已回滚：新发布 v${d.version}（内容 = v${d.rolled_back_to}），终端下次加载即生效。`);
      else setPublishMsg(`回滚失败：${d.hint ?? d.error ?? `HTTP ${r.status}`}`);
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

  // 自定义库：搜索 + 类型/处置筛选 → 按资产类型分组（折叠），组内增量加载。
  const q = query.trim().toLowerCase();
  const filteredUser = userLabels.filter(
    (l) =>
      (typeFilter === 'all' || l.asset_type === typeFilter) &&
      (dispFilter === 'all' || l.disposition === dispFilter) &&
      (!q || l.asset_key.toLowerCase().includes(q) || l.tags.some((t) => t.toLowerCase().includes(q))),
  );
  const GROUP_ORDER: Array<'skill' | 'mcp' | 'path'> = ['skill', 'mcp', 'path'];
  const GROUP_NAME: Record<'skill' | 'mcp' | 'path', string> = { skill: 'Skill 库', mcp: 'MCP 库', path: '代码路径库' };
  const groups = GROUP_ORDER.map((t) => ({ type: t, items: filteredUser.filter((l) => l.asset_type === t) })).filter(
    (g) => g.items.length > 0,
  );

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
          <select value={newType} onChange={(e) => setNewType(e.target.value as 'skill' | 'mcp' | 'path')} style={{ padding: '6px 8px', borderRadius: 6, border: '1px solid var(--border)', background: 'var(--panel)', color: 'var(--text)' }}>
            <option value="skill">Skill</option>
            <option value="mcp">MCP</option>
            <option value="path">代码路径</option>
          </select>
          <Input placeholder={newType === 'path' ? '文件路径（如 ~/docker-compose-langfuse.yml）' : '资产标识（如 skill 名 / MCP server 或命令）'} value={newKey} onChange={(e) => setNewKey(e.target.value)} style={{ maxWidth: 360 }} />
          <Button onClick={() => void addAsset()} disabled={busy || !newKey.trim()}>
            <Plus size={15} />
            添加资产
          </Button>
        </div>
      )}

      {/* 双库概览：AI Agent 预制库 + 自定义库（2026-09 改版 IA） */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 12, marginBottom: 16 }}>
        <div className="metric" style={{ minHeight: 92 }}>
          <div className="metric-top"><span><Library size={13} style={{ display: 'inline', marginRight: 6, verticalAlign: -2 }} />AI Agent 预制库</span></div>
          <strong style={{ fontSize: 26 }}>{defaultLabels.length}</strong>
          <p style={{ fontSize: 12, color: 'var(--muted-foreground)', margin: '4px 0 0' }}>原生自带 skill/MCP，自动加白并参与抑制与策略编译</p>
        </div>
        <div className="metric" style={{ minHeight: 92 }}>
          <div className="metric-top"><span><UserCog size={13} style={{ display: 'inline', marginRight: 6, verticalAlign: -2 }} />自定义库</span></div>
          <strong style={{ fontSize: 26 }}>{userLabels.length}</strong>
          <p style={{ fontSize: 12, color: 'var(--muted-foreground)', margin: '4px 0 0' }}>我的加白 / 观察 / 拉黑决策，按类型分组折叠管理</p>
        </div>
      </div>

      {/* AI Agent 预制库（默认折叠）：原生自带、自动加白，不作为用户"加白"决策展示 */}
      {defaultLabels.length > 0 && (
        <div className="panel animate-entrance animate-entrance-2" style={{ padding: 12, marginBottom: 16 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
            <Badge variant="outline">
              <ShieldCheck size={12} />
              AI Agent 预制库 · 系统默认放行 {defaultLabels.length} 项
            </Badge>
            <span style={{ fontSize: 12, color: 'var(--muted-foreground)' }}>
              AI Agent 原生自带的 skill / MCP，自动加白并参与告警抑制与策略编译；不计入你的处置决策、不在下方自定义库显示。
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

      {/* 自定义库（我的处置）：搜索/筛选 + 按资产类型分组折叠 + 组内增量加载（应对数百上千条） */}
      <div className="panel animate-entrance animate-entrance-3" style={{ padding: 12 }}>
        <div className="panel-head" style={{ marginBottom: 10 }}>
          <h2><UserCog size={14} style={{ display: 'inline', marginRight: 6, verticalAlign: -2 }} />自定义库（我的处置）</h2>
          <span style={{ fontSize: 12, color: 'var(--muted-foreground)' }}>共 {userLabels.length} 项 · 筛选后 {filteredUser.length} 项</span>
        </div>
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 12 }}>
          <Input placeholder="搜索资产标识 / 标签…" value={query} onChange={(e) => setQuery(e.target.value)} style={{ maxWidth: 260, fontSize: 12 }} />
          <select value={typeFilter} onChange={(e) => setTypeFilter(e.target.value as typeof typeFilter)} style={{ padding: '5px 8px', borderRadius: 6, border: '1px solid var(--border)', background: 'var(--panel)', color: 'var(--text)', fontSize: 12 }}>
            <option value="all">全部类型</option><option value="skill">Skill</option><option value="mcp">MCP</option><option value="path">代码路径</option>
          </select>
          <select value={dispFilter} onChange={(e) => setDispFilter(e.target.value as typeof dispFilter)} style={{ padding: '5px 8px', borderRadius: 6, border: '1px solid var(--border)', background: 'var(--panel)', color: 'var(--text)', fontSize: 12 }}>
            <option value="all">全部处置</option><option value="allow">加白</option><option value="monitor">观察</option><option value="deny">拉黑</option>
          </select>
        </div>
        {labels === null ? (
          <p className="empty-hint">加载处置注册表…</p>
        ) : groups.length === 0 ? (
          <p className="empty-hint">{userLabels.length === 0 ? '暂无你的处置决策。可手动添加资产并加白 / 观察 / 拉黑；AI Agent 预制库见上方折叠组。' : '无匹配项，请调整搜索 / 筛选。'}</p>
        ) : (
          <div style={{ display: 'grid', gap: 10 }}>
            {groups.map((g) => {
              const open = !collapsed[g.type];
              const limit = groupLimit[g.type] ?? GROUP_PAGE;
              const shown = g.items.slice(0, limit);
              return (
                <section key={g.type} style={{ border: '1px solid var(--border)', borderRadius: 8, overflow: 'hidden' }}>
                  <button
                    type="button"
                    onClick={() => setCollapsed((c) => ({ ...c, [g.type]: open }))}
                    style={{ width: '100%', display: 'flex', alignItems: 'center', gap: 8, padding: '9px 12px', background: 'var(--surface-2)', border: 'none', borderBottom: open ? '1px solid var(--border)' : 'none', color: 'var(--foreground)', cursor: 'pointer', fontSize: 13, fontWeight: 600 }}
                  >
                    <ChevronDown size={14} style={{ transform: open ? 'none' : 'rotate(-90deg)', transition: 'transform .15s' }} />
                    {GROUP_NAME[g.type]}
                    <Badge variant="outline">{g.items.length}</Badge>
                    <span style={{ marginLeft: 'auto', fontSize: 11, color: 'var(--muted-foreground)', fontWeight: 400 }}>
                      加白 {g.items.filter((x) => x.disposition === 'allow').length} · 观察 {g.items.filter((x) => x.disposition === 'monitor').length} · 拉黑 {g.items.filter((x) => x.disposition === 'deny').length}
                    </span>
                  </button>
                  {open && (
                    <div>
                      {shown.map((l) => {
                      const meta = DISP_META[l.disposition];
                      const Icon = meta.icon;
                      return (
                        <div key={`${l.asset_type}:${l.asset_key}`} style={{ display: 'flex', gap: 12, alignItems: 'center', padding: '9px 12px', borderBottom: '1px solid var(--border)', flexWrap: 'wrap' }}>
                          <Badge variant="outline">{l.asset_type}</Badge>
                          <strong style={{ minWidth: 180, fontSize: 13 }}>{l.asset_key}</strong>
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
                              <Button variant="outline" onClick={() => setPendingRemove(l)} disabled={busy} aria-label="删除">
                                <Trash2 size={14} />
                              </Button>
                            </span>
                          )}
                        </div>
                      );
                      })}
                      {g.items.length > limit && (
                        <button
                          type="button"
                          onClick={() => setGroupLimit((m) => ({ ...m, [g.type]: limit + GROUP_PAGE }))}
                          style={{ width: '100%', padding: '7px', background: 'none', border: 'none', borderTop: '1px solid var(--border)', color: 'var(--primary)', cursor: 'pointer', fontSize: 12 }}
                        >
                          加载更多（还有 {g.items.length - limit} 项）
                        </button>
                      )}
                    </div>
                  )}
                </section>
              );
            })}
          </div>
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
          {isAdmin && current && (
            <Button variant="outline" onClick={() => void rollback()} disabled={publishing} title="把上一个被取代版本的内容以新版本号重新签名发布（封错了一键回到上一版）">
              回滚上一版
            </Button>
          )}
        </div>

        {/* 发布前爆炸半径预览：点发布前就能看到影响面与闸判定（豁免设备已排除） */}
        {isAdmin && predicted.bulkNames > 0 && (
          <div
            style={{
              border: `1px solid ${predicted.absExceeded ? '#7a2020' : predicted.exceeded ? '#7a4b00' : 'var(--border)'}`,
              background: predicted.absExceeded ? 'rgba(122,32,32,0.08)' : predicted.exceeded ? 'rgba(122,75,0,0.08)' : 'var(--accent)',
              borderRadius: 10,
              padding: 12,
              marginTop: 10,
            }}
          >
            <strong style={{ fontSize: 13 }}>发布前爆炸半径预览</strong>
            <p style={{ fontSize: 12, color: 'var(--muted-foreground)', margin: '6px 0' }}>
              deny 名单 {predicted.bulkNames} 项；预计影响 {predicted.total} 资产 / {predicted.impact.length} 台设备
              {predicted.impact.length > 0 ? `（单设备最高 ${predicted.maxPct}%）` : ''}。
              {predicted.absExceeded
                ? ' 超绝对上限（20 资产 / 单设备 50%），不可 override，必须拆批。'
                : predicted.exceeded
                  ? ' 超闸（5 资产 / 单设备 10%），需 typed override 才能发布。'
                  : ' 在闸内，可直接发布。'}
            </p>
            {predicted.impact.length > 0 && (
              <div className="data-table" style={{ marginBottom: 0 }}>
                <div className="data-head" style={{ gridTemplateColumns: '1.2fr 2fr 1.4fr 0.6fr 0.6fr' }}>
                  <span>设备</span><span>将隔离的 Skill</span><span>将移除的 MCP</span><span>数量</span><span>占比</span>
                </div>
                {predicted.impact.map((x) => (
                  <div className="data-row" key={x.device_id} style={{ gridTemplateColumns: '1.2fr 2fr 1.4fr 0.6fr 0.6fr' }}>
                    <span style={{ fontSize: 11, fontFamily: 'monospace' }}>{x.device_id.slice(0, 12)}</span>
                    <span style={{ fontSize: 11, wordBreak: 'break-all' }}>{x.skills.join(', ') || '—'}</span>
                    <span style={{ fontSize: 11, wordBreak: 'break-all' }}>{x.mcp.join(', ') || '—'}</span>
                    <span style={{ fontSize: 11 }}>{x.count}</span>
                    <span style={{ fontSize: 11 }}>{x.pct}%</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {blast && (
          <div style={{ border: '1px solid #7a4b00', background: 'rgba(122,75,0,0.08)', borderRadius: 10, padding: 12, marginTop: 10 }}>
            <strong style={{ fontSize: 13 }}>爆炸半径超限，发布已拦截</strong>
            <p style={{ fontSize: 12, color: 'var(--muted-foreground)', margin: '6px 0' }}>{blast.hint}</p>
            <div className="data-table" style={{ marginBottom: 8 }}>
              <div className="data-head" style={{ gridTemplateColumns: '1.2fr 2fr 1.4fr 0.6fr 0.6fr' }}>
                <span>设备</span><span>将隔离的 Skill</span><span>将移除的 MCP</span><span>数量</span><span>占比</span>
              </div>
              {blast.impact.map((x) => (
                <div className="data-row" key={x.device_id} style={{ gridTemplateColumns: '1.2fr 2fr 1.4fr 0.6fr 0.6fr' }}>
                  <span style={{ fontSize: 11, fontFamily: 'monospace' }}>{x.device_id.slice(0, 12)}</span>
                  <span style={{ fontSize: 11, wordBreak: 'break-all' }}>{x.skills.join(', ') || '—'}</span>
                  <span style={{ fontSize: 11, wordBreak: 'break-all' }}>{x.mcp.join(', ') || '—'}</span>
                  <span style={{ fontSize: 11 }}>{x.count}</span>
                  <span style={{ fontSize: 11 }}>{x.pct}%</span>
                </div>
              ))}
            </div>
            <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
              <input
                value={blastInput}
                onChange={(e) => setBlastInput(e.target.value)}
                placeholder={`输入 ${blast.override} 以确认`}
                style={{ fontSize: 12, padding: '6px 8px', borderRadius: 6, border: '1px solid var(--border)', background: 'var(--surface-1)', color: 'var(--foreground)', minWidth: 220 }}
              />
              <Button disabled={publishing || blastInput !== blast.override} onClick={() => void publishPolicy(blast.override)}>
                <Upload size={14} /> 确认超半径并发布
              </Button>
              <Button variant="outline" onClick={() => { setBlast(null); setBlastInput(''); }}>取消</Button>
            </div>
          </div>
        )}

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
            尚未发布任何策略；终端仍使用出厂默认策略。发布后，处置决定会生成签名策略并下发终端强制生效。
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

      <ActionConfirmDialog
        open={pendingRemove !== null}
        onOpenChange={(open) => {
          if (!open && !busy) setPendingRemove(null);
        }}
        title="删除处置打标"
        description={
          pendingRemove
            ? `确认删除对「${pendingRemove.asset_key}」(${pendingRemove.asset_type}) 的处置打标？`
            : undefined
        }
        impact={[
          '该资产将回到“未处置”状态，不再参与加白 / 观察 / 拉黑抑制',
          '下次发布策略时，该资产不再出现在对应清单中',
          '已产生的历史发现与工单不受影响，仍保留在审计日志',
        ]}
        rollback="如需恢复，重新对该资产打标（加白 / 观察 / 拉黑）后再发布策略即可。"
        operator={subject || '当前登录用户'}
        variant="danger"
        confirmLabel="确认删除"
        busy={busy && pendingRemove !== null}
        onConfirm={() => void confirmRemove()}
      />
    </>
  );
}
