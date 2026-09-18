'use client';
import { useCallback, useEffect, useState } from 'react';
import Link from 'next/link';
import { SlidersHorizontal, ShieldCheck, KeyRound, Download } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { useRole } from '@/components/role-context';

/**
 * 终端安全策略。
 *
 * 顶部「当前生效策略」读真实发布件（/api/policy/current）：显示已签名的策略版本、
 * 签名密钥指纹与发布回执；未发布时如实显示"尚未发布"。发布动作在「处置中心」，
 * 它把处置决定编译成签名的 aegis.policy/v1 下发终端强制。
 *
 * 下方「出厂默认策略基线」是终端在控制台首次发布之前使用的默认约束（只读说明），
 * 不做"点了翻转又自动弹回"的假反馈。
 */
const policies = [
  { name: '自动发现 AI Agent', desc: '检测主流 AI Coding 工具（Cursor、Claude Code、Codex、Windsurf）', on: true },
  { name: '强制加载安全基线', desc: '启动时注入企业编码规范，未加载则阻断 Agent 执行', on: true },
  { name: '高危 MCP 自动隔离', desc: '阻断越权文件访问与未声明外联，隔离后通知安全管理员', on: true },
  { name: '未知 Skill 默认禁用', desc: '等待签名验证与安全审批，未审批 Skill 不加载', on: false },
  { name: '代码质量门禁', desc: '阻断高危 SAST 发现合入主分支，中危需人工审批', on: true },
  { name: '离线队列加密', desc: '报告暂存时使用 AES-256-GCM 加密，防止本地窃取', on: true },
];

interface CurrentRelease {
  published: boolean;
  version: number;
  created_at: number;
  created_by: string;
  signing_key_id: string;
  receipt: { label_counts: { allow: number; monitor: number; deny: number } };
}

interface Posture {
  published: boolean;
  source?: 'collector' | 'registry';
  connected?: boolean;
  current_version?: string;
  total_devices: number;
  on_current: number;
  drifted: number;
  unknown: number;
  coverage?: number;
}

interface SigningKey {
  key_id: string;
  fingerprint: string;
  in_keyring: boolean;
  status: 'active' | 'retiring' | 'retired' | 'provisioned';
  releases: number;
  created_at?: number;
  rotated_at?: number;
  retired_at?: number;
}

interface KeysResponse {
  active_key_id: string | null;
  active_fingerprint: string;
  keys: SigningKey[];
}

export default function PoliciesPage() {
  const { role } = useRole();
  const isAdmin = role === 'admin';
  const [current, setCurrent] = useState<CurrentRelease | null>(null);
  const [posture, setPosture] = useState<Posture | null>(null);
  const [keys, setKeys] = useState<KeysResponse | null>(null);
  const [keysMsg, setKeysMsg] = useState('');
  const [busyKey, setBusyKey] = useState('');

  const reloadKeys = useCallback(() => {
    fetch('/api/policy/keys', { cache: 'no-store' })
      .then((r) => (r.ok ? (r.json() as Promise<KeysResponse>) : null))
      .then((d) => setKeys(d))
      .catch(() => setKeys(null));
  }, []);

  useEffect(() => {
    fetch('/api/policy/current', { cache: 'no-store' })
      .then((r) => (r.ok ? (r.json() as Promise<CurrentRelease>) : null))
      .then((d) => setCurrent(d && d.published ? d : null))
      .catch(() => setCurrent(null));
    fetch('/api/policy/posture', { cache: 'no-store' })
      .then((r) => (r.ok ? (r.json() as Promise<Posture>) : null))
      .then((d) => setPosture(d))
      .catch(() => setPosture(null));
    reloadKeys();
  }, [reloadKeys]);

  const ROTATE_ERR: Record<string, string> = {
    key_not_in_keyring: '目标密钥尚未启用（请先在签名密钥配置 AEGIS_POLICY_SIGNING_KEYS 中预置）',
    already_active: '该密钥已是活跃密钥',
    no_keyring: '尚未配置签名密钥（AEGIS_POLICY_SIGNING_KEYS）',
  };
  const RETIRE_ERR: Record<string, string> = {
    is_active: '不能退役当前活跃密钥',
    in_use_by_published: '当前生效策略仍由该密钥签发，请先用新活跃密钥发布一版再退役',
    not_found: '密钥不存在',
  };

  async function rotateKey(toKeyId: string) {
    if (!isAdmin || busyKey) return;
    setBusyKey(toKeyId);
    setKeysMsg('');
    try {
      const r = await fetch('/api/policy/keys', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ to_key_id: toKeyId }) });
      const d = (await r.json().catch(() => ({}))) as { error?: string; active_key_id?: string };
      if (r.ok) setKeysMsg(`已轮换：活跃签名密钥 → ${d.active_key_id}（旧钥转 retiring，重叠期内终端仍可验签）`);
      else setKeysMsg(`轮换失败：${ROTATE_ERR[d.error ?? ''] ?? d.error ?? `HTTP ${r.status}`}`);
      reloadKeys();
    } finally {
      setBusyKey('');
    }
  }

  async function retireKey(keyId: string) {
    if (!isAdmin || busyKey) return;
    if (!window.confirm(`确认退役签名密钥「${keyId}」？退役后终端将无法再用它验签（请先确认无生效策略依赖）。`)) return;
    setBusyKey(keyId);
    setKeysMsg('');
    try {
      const r = await fetch(`/api/policy/keys/${encodeURIComponent(keyId)}/retire`, { method: 'POST' });
      const d = (await r.json().catch(() => ({}))) as { error?: string };
      if (r.ok) setKeysMsg(`已退役密钥 ${keyId}。`);
      else setKeysMsg(`退役失败：${RETIRE_ERR[d.error ?? ''] ?? d.error ?? `HTTP ${r.status}`}`);
      reloadKeys();
    } finally {
      setBusyKey('');
    }
  }

  return (
    <>
      <div className="page-head animate-entrance animate-entrance-1">
        <div>
          <p className="eyebrow">管理 / 策略配置</p>
          <h1>终端安全策略</h1>
          <p>查看当前下发终端的签名策略；发布与处置在「处置中心」。</p>
        </div>
        <div className="head-actions">
          <Link href="/dispositions" style={{ textDecoration: 'none' }}>
            <Button>
              <SlidersHorizontal size={16} />
              去发布策略
            </Button>
          </Link>
        </div>
      </div>

      <div className="panel animate-entrance animate-entrance-2" style={{ padding: 16, marginBottom: 14 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
          <h2 style={{ fontSize: 15, margin: 0 }}>当前生效策略</h2>
          {current ? (
            <Badge variant="outline">
              <ShieldCheck size={12} /> 已签名 v{current.version}
            </Badge>
          ) : (
            <Badge variant="outline">尚未发布 · 终端使用出厂默认</Badge>
          )}
        </div>
        {current ? (
          <p style={{ fontSize: 13, color: 'var(--muted-foreground)', marginTop: 8 }}>
            版本 v{current.version} · 签名密钥 {current.signing_key_id} · 发布人 {current.created_by} ·{' '}
            {new Date(current.created_at).toLocaleString()} · 回执 allow {current.receipt.label_counts.allow} / monitor{' '}
            {current.receipt.label_counts.monitor} / deny {current.receipt.label_counts.deny}。终端加载时会验签，篡改则拒载并回退上一份有效策略。
          </p>
        ) : (
          <p style={{ fontSize: 13, color: 'var(--muted-foreground)', marginTop: 8 }}>
            还没有从控制台发布过签名策略。到「处置中心」对 Skill/MCP 打标后点击"发布策略"，即可生成签名策略并下发终端强制生效。
          </p>
        )}
        {posture && posture.published && (
          <p style={{ fontSize: 12, color: 'var(--muted-foreground)', marginTop: 8, borderTop: '1px solid var(--border)', paddingTop: 8 }}>
            终端生效态势：
            {posture.total_devices === 0 ? (
              <>尚无纳管终端，发布后终端首次上报即开始统计。</>
            ) : (
              <>
                <b style={{ color: 'var(--foreground)' }}>{posture.on_current}/{posture.total_devices}</b> 台在 v{posture.current_version}
                （覆盖率 {posture.coverage ?? 0}%）· {posture.drifted} 台漂移 · {posture.unknown} 台未知。
                {(posture.drifted > 0 || posture.unknown > 0) &&
                  ' 终端不会自动拉取策略：需下载下方签名策略文件，经桌管分发到终端，客户端加载时验签生效。'}
              </>
            )}
            <br />
            <span style={{ fontSize: 11 }}>
              {posture.source === 'collector'
                ? '数据源：接收器活体上报（客户端真实策略版本）'
                : '数据源：控制台注册表（接收器未连接，版本可能滞后）'}
            </span>
          </p>
        )}
        {current && (
          <div style={{ marginTop: 10, paddingTop: 8, borderTop: '1px solid var(--border)', display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
            <span style={{ fontSize: 12, color: 'var(--muted-foreground)' }}>
              分发：下载签名策略文件，经桌管分发到终端；文件含完整性校验值，客户端加载时验签。
            </span>
            <Link className="handle" href="/api/policy/artifact" style={{ marginLeft: 'auto', fontSize: 12, display: 'inline-flex', alignItems: 'center', gap: 4 }}>
              <Download size={13} /> 下载签名策略文件 v{current.version}
            </Link>
          </div>
        )}
      </div>

      <div className="panel animate-entrance" style={{ padding: 16, marginBottom: 14 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap', marginBottom: 8 }}>
          <h2 style={{ fontSize: 15, margin: 0, display: 'flex', alignItems: 'center', gap: 8 }}>
            <KeyRound size={16} /> 签名密钥
          </h2>
          {keys?.active_key_id ? (
            <Badge variant="outline">
              <ShieldCheck size={12} /> 活跃 {keys.active_key_id} · 指纹 {keys.active_fingerprint}
            </Badge>
          ) : (
            <Badge variant="outline">未配置</Badge>
          )}
        </div>
        <p style={{ fontSize: 12, color: 'var(--muted-foreground)', marginBottom: 10 }}>
          签名密钥仅保存在服务端（AEGIS_POLICY_SIGNING_KEYS），绝不入库、绝不在此展示；此处仅显示指纹与治理状态。轮换时旧钥转「退役中」，重叠期内终端仍可用它验签，确认无生效策略依赖后再退役。
        </p>
        {keysMsg && (
          <p style={{ fontSize: 12, marginBottom: 10, color: keysMsg.includes('失败') ? '#ff685f' : '#49e8a5' }}>{keysMsg}</p>
        )}
        {keys === null ? (
          <p className="empty-hint">加载签名密钥…</p>
        ) : keys.keys.length === 0 ? (
          <p className="empty-hint">尚未配置签名密钥；设置 AEGIS_POLICY_SIGNING_KEYS 后才能发布签名策略与轮换。</p>
        ) : (
          <div className="data-table">
            <div className="data-head" style={{ gridTemplateColumns: '1.4fr 1.2fr 0.9fr 0.6fr auto' }}>
              <span>密钥 ID</span><span>指纹</span><span>状态</span><span>发布数</span><span>操作</span>
            </div>
            {keys.keys.map((k) => {
              const statusLabel = k.status === 'active' ? '活跃' : k.status === 'retiring' ? '退役中(重叠验签)' : k.status === 'retired' ? '已退役' : '已预置';
              return (
                <div className="data-row" key={k.key_id} style={{ gridTemplateColumns: '1.4fr 1.2fr 0.9fr 0.6fr auto' }}>
                  <strong style={{ fontSize: 12 }}>{k.key_id}{!k.in_keyring ? '（未启用）' : ''}</strong>
                  <span style={{ fontSize: 11, color: 'var(--muted-foreground)', fontFamily: 'monospace' }}>{k.fingerprint || '—'}</span>
                  <span><i className={k.status === 'active' ? 'pass' : k.status === 'retired' ? 'warn' : ''} style={{ fontStyle: 'normal', fontSize: 11 }}>{statusLabel}</i></span>
                  <span style={{ fontSize: 12 }}>{k.releases}</span>
                  <span style={{ display: 'flex', gap: 6 }}>
                    {isAdmin && k.in_keyring && k.status !== 'active' && k.status !== 'retired' && (
                      <button className="handle" disabled={busyKey === k.key_id} onClick={() => void rotateKey(k.key_id)}>设为活跃</button>
                    )}
                    {isAdmin && k.status === 'retiring' && (
                      <button className="handle" disabled={busyKey === k.key_id} onClick={() => void retireKey(k.key_id)}>退役</button>
                    )}
                  </span>
                </div>
              );
            })}
          </div>
        )}
      </div>

      <div className="panel">
        <div className="panel-head">
          <div>
            <h2>出厂默认策略基线</h2>
            <p>终端在首次发布前使用的默认约束（只读）；共 {policies.length} 项，{policies.filter((p) => p.on).length} 项默认启用</p>
          </div>
        </div>
        {policies.map((policy, index) => (
          <div
            className="setting-row animate-row-entrance"
            key={policy.name}
            style={{ animationDelay: `${index * 30 + 200}ms` }}
          >
            <div>
              <strong>{policy.name}</strong>
              <span>{policy.desc}</span>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <i className="warn" style={{ fontSize: 11, fontStyle: 'normal' }}>只读</i>
              <button
                className={`switch ${policy.on ? 'on' : ''}`}
                disabled
                title="出厂默认基线为只读；实际生效策略以处置中心发布件为准"
                aria-label={`${policy.name}（只读）`}
              >
                <span />
              </button>
            </div>
          </div>
        ))}
      </div>
    </>
  );
}
