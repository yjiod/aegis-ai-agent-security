'use client';
import { useEffect, useState } from 'react';
import { ObservabilityPanel } from '@/components/observability-panel';
import { Settings, Send } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { useCollector } from '@/components/collector-context';
import { useRole } from '@/components/role-context';
import { ActionConfirmDialog } from '@/components/action-confirm-dialog';

/**
 * 系统设置。诚实原则：只有真正接了后端的项才呈现为"可管理/实时"，其余项
 * 明确标注"未接入"并禁用，绝不做"点了翻转又自动弹回"的假反馈，也不用
 * "变更将同步至所有终端"这类暗示真实生效的文案误导用户。
 *
 * - Collector 连接：实时（来自 collector-context 的真实探测）。
 * - 数据保留期 / 通知渠道 / 自动更新 / 审计保留 / 离线队列：后端设置 API 未接入，
 *   仅作只读说明展示（值来自当前部署约定，不可在此修改）。
 *
 * 真正可写的全局设置（扫描模式、上游基线地址）在「基线管理」页，走 /api/settings。
 * 全局配置面板（GlobalConfigPanel）已接入真实后端：保留期/审计保留/审计封顶走
 * Collector /v1/config 运行时覆盖；通知渠道/自动更新/离线队列读取真实状态。
 */

export default function SettingsPage() {
  const { collectorState } = useCollector();

  return (
    <>
      <div className="page-head">
        <div>
          <p className="eyebrow">管理 / 系统设置</p>
          <h1>系统设置</h1>
          <p>Collector 连接为实时状态；保留期 / 审计保留 / 审计封顶可读写 Collector 运行时配置，其余项读取真实状态。</p>
        </div>
        <div className="head-actions">
          <Button disabled title="全局配置已接入：保留期/审计保留/审计封顶在「全局配置」各行内保存；扫描模式与上游基线在「基线管理」">
            <Settings size={16} />
            行内保存
          </Button>
        </div>
      </div>

      <ObservabilityPanel />

      <GlobalConfigPanel collectorState={collectorState} />

      <AlertingPanel />
      <RemediationPanel />
    </>
  );
}

interface CollectorCfgValue {
  value: number;
  override: boolean;
  min: number;
  max: number;
}

/**
 * 全局配置面板（真实接入）：
 * - 数据保留期 / 审计保留期 / 审计封顶：读写 Collector /v1/config 运行时覆盖（经 /api/settings/retention）。
 * - 通知渠道：读取告警面板真实 webhook 配置状态（邮件通道需运维在控制台 env 配置 SMTP，未配置如实标注）。
 * - 自动更新：读取已发布策略的 agent_self_update 与灰度比例（写随签名策略发布生效，此处只读+说明）。
 * - 离线队列上限：读取已发布策略 limits.offline_queue_max（未随策略下发时如实标「未接入」）。
 * Collector 不可达时如实显示加载失败，绝不伪造配置值。
 */
function GlobalConfigPanel({ collectorState }: { collectorState: string }) {
  const { role } = useRole();
  const isAdmin = role === 'admin';
  const [cfg, setCfg] = useState<Record<string, CollectorCfgValue> | null>(null);
  const [cfgError, setCfgError] = useState('');
  const [draft, setDraft] = useState<Record<string, string>>({});
  const [saving, setSaving] = useState('');
  const [msg, setMsg] = useState('');
  const [webhook, setWebhook] = useState<string | null>(null);
  const [policy, setPolicy] = useState<{ agent_self_update?: { enabled?: boolean; rollout_percent?: number }; limits?: Record<string, number> } | null>(null);

  useEffect(() => {
    let alive = true;
    fetch('/api/settings/retention', { cache: 'no-store' })
      .then((r) => (r.ok ? (r.json() as Promise<{ config?: Record<string, CollectorCfgValue> }>) : Promise.reject(new Error(String(r.status)))))
      .then((d) => {
        if (alive) setCfg(d.config ?? null);
      })
      .catch((e) => {
        if (alive) setCfgError(e instanceof Error ? e.message : 'load_failed');
      });
    fetch('/api/settings/alerting', { cache: 'no-store' })
      .then((r) => (r.ok ? (r.json() as Promise<{ config?: { webhook?: string } }>) : null))
      .then((d) => {
        if (alive) setWebhook(d?.config?.webhook ?? '');
      })
      .catch(() => {
        if (alive) setWebhook('');
      });
    fetch('/api/policy/current', { cache: 'no-store' })
      .then((r) => (r.ok ? (r.json() as Promise<{ policy?: { agent_self_update?: { enabled?: boolean; rollout_percent?: number }; limits?: Record<string, number> } }>) : null))
      .then((d) => {
        if (alive) setPolicy(d?.policy ?? null);
      })
      .catch(() => {
        if (alive) setPolicy(null);
      });
    return () => {
      alive = false;
    };
  }, []);

  async function save(key: string) {
    const raw = draft[key];
    const n = Number(raw);
    if (raw === undefined || raw === '' || !Number.isInteger(n)) {
      setMsg(`${key} 需为整数`);
      return;
    }
    setSaving(key);
    setMsg('');
    try {
      const r = await fetch('/api/settings/retention', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ [key]: n }),
      });
      const d = (await r.json().catch(() => ({}))) as { config?: Record<string, CollectorCfgValue>; error?: string };
      if (r.ok && d.config) {
        setCfg(d.config);
        setMsg(`${key} 已保存并在 Collector 生效`);
      } else {
        setMsg(`保存失败：${d.error ?? r.status}`);
      }
    } catch {
      setMsg('保存失败：网络错误');
    }
    setSaving('');
  }

  const numRow = (key: string, label: string, desc: string, unit: string) => {
    const cur = cfg?.[key];
    const value = draft[key] ?? String(cur?.value ?? '');
    return (
      <div className="setting-row" key={key}>
        <div>
          <strong>{label}</strong>
          <span>{desc}</span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          {cfgError && <NotConnected />}
          <Input
            value={value}
            onChange={(e) => setDraft((p) => ({ ...p, [key]: e.target.value.replace(/\D/g, '').slice(0, 7) }))}
            disabled={!isAdmin || Boolean(cfgError)}
            style={{ width: 90, textAlign: 'right' }}
            aria-label={label}
          />
          <strong style={{ fontSize: 12, color: 'var(--muted-foreground)' }}>{unit}</strong>
          {cur && (
            <span style={{ fontSize: 11, color: 'var(--muted-foreground)' }}>
              范围 {cur.min}–{cur.max}{cur.override ? ' · 已覆盖' : ' · env 默认'}
            </span>
          )}
          <Button size="sm" onClick={() => void save(key)} disabled={!isAdmin || saving === key || Boolean(cfgError)}>
            {saving === key ? '保存中…' : '保存'}
          </Button>
        </div>
      </div>
    );
  };

  return (
    <div className="panel">
      <div className="panel-head">
        <div>
          <h2>全局配置</h2>
          <p>保留期 / 审计保留 / 审计封顶实时读写 Collector 运行时配置；其余项读取真实状态</p>
        </div>
      </div>
      <div className="setting-row">
        <div>
          <strong>Collector 连接</strong>
          <span>报告接收器地址与认证令牌</span>
        </div>
        <span className="system-ok">
          <span className={collectorState === 'live' ? 'live-dot' : 'demo-dot'} />
          {collectorState === 'live' ? '已连接' : collectorState === 'checking' ? '检测中' : '未连接'}
        </span>
      </div>
      {numRow('retention_days', '数据保留期', '报告与风险事件保留天数', '天')}
      <div className="setting-row">
        <div>
          <strong>通知渠道</strong>
          <span>高危事件推送方式</span>
        </div>
        <span style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12 }}>
          {webhook === null ? (
            <NotConnected />
          ) : webhook ? (
            <i className="pass" style={{ fontSize: 10 }}>Webhook 已接入</i>
          ) : (
            <i className="warn" style={{ fontSize: 10 }}>Webhook 未配置</i>
          )}
          <span style={{ color: 'var(--muted-foreground)' }}>在下方「告警推送」面板配置；邮件通道需运维配置 SMTP</span>
        </span>
      </div>
      <div className="setting-row">
        <div>
          <strong>自动更新</strong>
          <span>Agent 版本自动升级策略（灰度 → 全量）</span>
        </div>
        <span style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12 }}>
          {policy ? (
            <>
              <i className={policy.agent_self_update?.enabled ? 'pass' : 'warn'} style={{ fontSize: 10 }}>
                {policy.agent_self_update?.enabled ? '已启用' : '已停用'}
              </i>
              <span style={{ color: 'var(--muted-foreground)' }}>
                灰度 {policy.agent_self_update?.rollout_percent ?? 0}% · 修改随签名策略发布生效
              </span>
            </>
          ) : (
            <NotConnected />
          )}
        </span>
      </div>
      {numRow('audit_retention_days', '审计日志保留', '控制台与 Collector 审计记录保留天数（审计恒启用，基线要求不可关）', '天')}
      {numRow('audit_max_events', '审计封顶条数', '审计表保留的最大事件条数（超出按最新截断）', '条')}
      <div className="setting-row">
        <div>
          <strong>离线队列上限</strong>
          <span>终端离线时报告暂存最大条数</span>
        </div>
        <span style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12 }}>
          {policy?.limits?.offline_queue_max ? (
            <strong style={{ fontSize: 13, color: 'var(--muted-foreground)' }}>{policy.limits.offline_queue_max} 条（随签名策略下发）</strong>
          ) : (
            <NotConnected />
          )}
        </span>
      </div>
      {msg && <p style={{ fontSize: 12, color: 'var(--muted-foreground)', padding: '0 16px 12px' }}>{msg}</p>}
    </div>
  );
}

interface AlertCfg {
  enabled: boolean;
  webhook: string;
  format: 'generic' | 'dingtalk';
  offline_hours: number;
  min_interval_hours: number;
  email: string;
}

/** 告警推送配置（真实可写，admin）：存 PG settings；服务器 aegis_alert_check.py 用 Collector 令牌只读拉取。 */
function AlertingPanel() {
  const { role, subject } = useRole();
  const isAdmin = role === 'admin';
  const [cfg, setCfg] = useState<AlertCfg | null>(null);
  const [msg, setMsg] = useState('');
  const [busy, setBusy] = useState(false);
  // 测试发送会向已配置 webhook 真实外发一条消息，统一确认弹窗（不展示 webhook 原文，避免泄露凭据）。
  const [pendingTest, setPendingTest] = useState(false);
  // 投递可靠性遥测（真实发送记录，无记录时诚实不显示）。
  const [delivery, setDelivery] = useState<Array<{ ts: number; ok: boolean; latency_ms: number; detail: string }>>([]);

  useEffect(() => {
    fetch('/api/settings/alerting', { cache: 'no-store' })
      .then((r) => (r.ok ? (r.json() as Promise<{ config?: AlertCfg }>) : null))
      .then((d) => setCfg(d?.config ?? null))
      .catch(() => setCfg(null));
    fetch('/api/pipeline/telemetry', { cache: 'no-store' })
      .then((r) => (r.ok ? (r.json() as Promise<{ connected?: boolean; events?: Array<{ pipeline: string; ts: number; ok: boolean; latency_ms: number; detail: string }> }>) : null))
      .then((d) => setDelivery((d?.events ?? []).filter((e) => e.pipeline === 'alert-delivery')))
      .catch(() => setDelivery([]));
  }, []);

  async function save() {
    if (!isAdmin || !cfg) return;
    setBusy(true);
    setMsg('');
    try {
      const r = await fetch('/api/settings/alerting', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(cfg),
      });
      if (r.ok) setMsg('已保存。服务器告警评估器下次运行即按新配置生效。');
      else {
        const j = (await r.json().catch(() => ({}))) as { details?: string[]; error?: string };
        setMsg(`保存失败：${(j.details ?? []).join('；') || j.error || r.status}`);
      }
    } catch {
      setMsg('保存失败：网络错误');
    }
    setBusy(false);
  }

  async function test() {
    if (!isAdmin) return;
    setBusy(true);
    setMsg('');
    try {
      const r = await fetch('/api/settings/alerting', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ test: true }),
      });
      const j = (await r.json().catch(() => ({}))) as { sent?: boolean; status?: number; error?: string };
      setMsg(j.sent ? `测试告警已发送（webhook 返回 ${j.status}）` : `测试发送失败：${j.error ?? r.status}`);
    } catch {
      setMsg('测试发送失败：网络错误');
    }
    setBusy(false);
  }

  /** 测试发送经统一确认弹窗后执行（真实外发，人在回路）。 */
  async function confirmTest() {
    if (busy) return;
    await test();
    setPendingTest(false);
  }

  if (!cfg) return null;
  return (
    <div className="panel" style={{ marginTop: 16 }}>
      <div className="panel-head">
        <div>
          <h2>告警推送（Fleet Alerting）</h2>
          <p>服务器告警评估器（systemd timer 每 5 分钟）按此配置推送离线/坏自更/critical 告警；webhook 为空=不推送（dry-run）。配置邮件收件人且服务器已配 SMTP 后，同批告警同时发邮件。</p>
        </div>
      </div>
      <div className="setting-row">
        <div>
          <strong>启用推送</strong>
          <span>关闭后评估器跳过（不评估不推送）</span>
        </div>
        <button
          className={`switch ${cfg.enabled ? 'on' : ''}`}
          disabled={!isAdmin}
          aria-label="启用告警推送"
          onClick={() => setCfg({ ...cfg, enabled: !cfg.enabled })}
        >
          <span />
        </button>
      </div>
      <div className="setting-row">
        <div>
          <strong>Webhook URL</strong>
          <span>https://…（generic JSON 或钉钉机器人）；留空=不推送</span>
        </div>
        <Input
          value={cfg.webhook}
          disabled={!isAdmin}
          placeholder="https://example.com/webhook"
          onChange={(e) => setCfg({ ...cfg, webhook: e.target.value })}
          style={{ maxWidth: 360 }}
        />
      </div>
      <div className="setting-row">
        <div>
          <strong>格式</strong>
          <span>generic=aegis.alert/v1 JSON；dingtalk=机器人 text</span>
        </div>
        <select
          value={cfg.format}
          disabled={!isAdmin}
          onChange={(e) => setCfg({ ...cfg, format: e.target.value === 'dingtalk' ? 'dingtalk' : 'generic' })}
          style={{ background: 'var(--card)', color: 'var(--foreground)', border: '1px solid var(--border)', borderRadius: 6, padding: '4px 8px' }}
        >
          <option value="generic">generic</option>
          <option value="dingtalk">dingtalk</option>
        </select>
      </div>
      <div className="setting-row">
        <div>
          <strong>邮件收件人（可选）</strong>
          <span>逗号分隔；非空且服务器配 AEGIS_ALERT_SMTP_* 后评估器同时发邮件</span>
        </div>
        <Input
          value={cfg.email ?? ''}
          disabled={!isAdmin}
          placeholder="ops@example.com, sec@example.com"
          onChange={(e) => setCfg({ ...cfg, email: e.target.value })}
          style={{ maxWidth: 360 }}
        />
      </div>
      <div className="setting-row">
        <div>
          <strong>离线判定阈值（小时）</strong>
          <span>last_seen 超过该值且曾在线 → device_offline 告警</span>
        </div>
        <Input
          type="number"
          min={0.1}
          max={168}
          step={0.5}
          value={cfg.offline_hours}
          disabled={!isAdmin}
          onChange={(e) => setCfg({ ...cfg, offline_hours: Number(e.target.value) })}
          style={{ maxWidth: 120 }}
        />
      </div>
      <div className="setting-row">
        <div>
          <strong>同类告警最小间隔（小时）</strong>
          <span>去重节流：同类告警在该间隔内不重发</span>
        </div>
        <Input
          type="number"
          min={0.1}
          max={168}
          step={0.5}
          value={cfg.min_interval_hours}
          disabled={!isAdmin}
          onChange={(e) => setCfg({ ...cfg, min_interval_hours: Number(e.target.value) })}
          style={{ maxWidth: 120 }}
        />
      </div>
      {msg && <p style={{ fontSize: 12, color: 'var(--muted-foreground)', padding: '0 16px 12px' }}>{msg}</p>}
      {isAdmin && (
        <div style={{ display: 'flex', gap: 8, padding: '0 16px 16px' }}>
          <Button onClick={() => void save()} disabled={busy}>
            <Settings size={15} />
            保存告警配置
          </Button>
          <Button variant="outline" onClick={() => setPendingTest(true)} disabled={busy || !cfg.webhook} title="向当前 webhook 发一条测试告警">
            <Send size={15} />
            测试发送
          </Button>
        </div>
      )}

      {delivery.length > 0 && (
        <div style={{ padding: '0 16px 12px', fontSize: 12, color: 'var(--muted-foreground)' }}>
          投递可靠性（真实发送记录）：近 {delivery.length} 次中成功 {delivery.filter((d) => d.ok).length} 次
          {delivery[0] && (
            <>
              {' '}· 最近一次 {delivery[0].ok ? '成功' : '失败'}（{delivery[0].latency_ms}ms，
              {new Date(delivery[0].ts * 1000).toLocaleString('zh-CN', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' })}）
            </>
          )}
        </div>
      )}

      <ActionConfirmDialog
        open={pendingTest}
        onOpenChange={(open) => {
          if (!open && !busy) setPendingTest(false);
        }}
        title="发送测试告警"
        description="确认向当前已配置的告警 webhook 发送一条测试消息？"
        impact={[
          '会向告警通道真实外发一条测试消息（通道内成员会收到）',
          '不改动任何告警配置，也不影响终端或策略',
        ]}
        rollback="测试消息无法撤回，但不产生持久化副作用；如误发可忽略。"
        operator={subject || '当前登录用户'}
        variant="default"
        confirmLabel="确认发送"
        busy={busy}
        onConfirm={() => void confirmTest()}
      />
    </div>
  );
}

/** 自动纠偏配置（真实可写，admin）：绝对要求 #3 的总开关。 */
function RemediationPanel() {
  const { role } = useRole();
  const isAdmin = role === 'admin';
  const [cfg, setCfg] = useState<{ enabled: boolean; auto_deny: boolean; notify: boolean } | null>(null);
  const [msg, setMsg] = useState('');
  const [busy, setBusy] = useState(false);
  const [sweepResult, setSweepResult] = useState<string>('');

  useEffect(() => {
    fetch('/api/settings/remediation', { cache: 'no-store' })
      .then((r) => (r.ok ? (r.json() as Promise<{ config?: { enabled: boolean; auto_deny: boolean; notify: boolean } }>) : null))
      .then((d) => setCfg(d?.config ?? null))
      .catch(() => setCfg(null));
  }, []);

  async function save() {
    if (!isAdmin || !cfg) return;
    setBusy(true);
    setMsg('');
    try {
      const r = await fetch('/api/settings/remediation', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(cfg),
      });
      setMsg(r.ok ? '已保存。下一轮自动纠偏（约 5 分钟）即按新配置执行。' : `保存失败：HTTP ${r.status}`);
    } catch {
      setMsg('保存失败：网络错误');
    }
    setBusy(false);
  }

  async function sweepNow() {
    if (!isAdmin) return;
    setBusy(true);
    setSweepResult('');
    try {
      const r = await fetch('/api/remediation/auto-sweep', { method: 'POST' });
      const j = (await r.json().catch(() => ({}))) as {
        ran?: boolean; reason?: string; findings?: number; denied?: Array<{ asset_key: string }>;
        conflicts?: Array<{ asset_key: string }>; notified?: number; published_version?: number; publish_blocked?: string;
      };
      if (!j.ran) setSweepResult(`未执行：${j.reason ?? '未知原因'}`);
      else setSweepResult(
        `扫描 ${j.findings ?? 0} 条发现 → 自动封禁 ${(j.denied ?? []).length} 项${(j.denied ?? []).length ? `（${(j.denied ?? []).map((d) => d.asset_key).slice(0, 5).join('、')}${(j.denied ?? []).length > 5 ? '…' : ''}）` : ''}`
        + `；人工冲突 ${(j.conflicts ?? []).length}；通知 ${j.notified ?? 0}`
        + (j.published_version ? `；策略已发布 v${j.published_version}` : '')
        + (j.publish_blocked ? `；发布被拦截：${j.publish_blocked}` : ''),
      );
    } catch {
      setSweepResult('执行失败：网络错误');
    }
    setBusy(false);
  }

  if (!cfg) return null;
  return (
    <div className="panel" style={{ marginTop: 16 }}>
      <div className="panel-head">
        <div>
          <h2>自动纠偏（Auto Remediation）</h2>
          <p>每 5 分钟扫描全量发现：高置信恶意 Skill（隐藏指令/提示词覆盖/凭据访问/上下文投毒， critical|high）与不可信 MCP（critical）自动拉黑并发布策略；人工处置永不覆盖（冲突转人工裁决）；代码质量问题与中低置信信号走通知（webhook 走「告警推送」通道）。自动发布永不使用爆炸半径 override。</p>
        </div>
      </div>
      <div className="setting-row">
        <div>
          <strong>启用自动纠偏</strong>
          <span>总开关：关闭后后台循环与手动扫描都跳过</span>
        </div>
        <button
          className={`switch ${cfg.enabled ? 'on' : ''}`}
          disabled={!isAdmin}
          aria-label="启用自动纠偏"
          onClick={() => setCfg({ ...cfg, enabled: !cfg.enabled })}
        >
          <span />
        </button>
      </div>
      <div className="setting-row">
        <div>
          <strong>自动封禁（deny）</strong>
          <span>高置信恶意信号自动拉黑并发布；关闭则只通知不封</span>
        </div>
        <button
          className={`switch ${cfg.auto_deny ? 'on' : ''}`}
          disabled={!isAdmin}
          aria-label="自动封禁"
          onClick={() => setCfg({ ...cfg, auto_deny: !cfg.auto_deny })}
        >
          <span />
        </button>
      </div>
      <div className="setting-row">
        <div>
          <strong>推送通知</strong>
          <span>封禁结果/人工冲突/待修复项经告警 webhook 推送</span>
        </div>
        <button
          className={`switch ${cfg.notify ? 'on' : ''}`}
          disabled={!isAdmin}
          aria-label="纠偏通知"
          onClick={() => setCfg({ ...cfg, notify: !cfg.notify })}
        >
          <span />
        </button>
      </div>
      <div style={{ display: 'flex', gap: 10, marginTop: 12, flexWrap: 'wrap', alignItems: 'center' }}>
        <button className="handle" disabled={!isAdmin || busy} onClick={() => void save()}>保存配置</button>
        <button className="handle" disabled={!isAdmin || busy} onClick={() => void sweepNow()}>立即执行一轮</button>
        {msg && <span style={{ fontSize: 12, color: 'var(--primary)' }}>{msg}</span>}
      </div>
      {sweepResult && <p style={{ fontSize: 12, color: 'var(--muted-foreground)', margin: '8px 0 0' }}>{sweepResult}</p>}
    </div>
  );
}

function NotConnected() {
  return (
    <i className="warn" style={{ fontSize: 11, fontStyle: 'normal' }}>未接入</i>
  );
}
