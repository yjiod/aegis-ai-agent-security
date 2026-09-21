'use client';
import { useEffect, useState } from 'react';
import { Settings, Send } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { useCollector } from '@/components/collector-context';
import { useRole } from '@/components/role-context';

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
 */
type SettingRow =
  | { name: string; desc: string; type: 'status' }
  | { name: string; desc: string; type: 'text'; value: string; live: boolean }
  | { name: string; desc: string; type: 'switch'; value: boolean; live: boolean };

const settings: SettingRow[] = [
  { name: 'Collector 连接', desc: '报告接收器地址与认证令牌', type: 'status' },
  { name: '数据保留期', desc: '报告与风险事件保留天数', type: 'text', value: '90 天', live: false },
  { name: '通知渠道', desc: '高危事件推送方式', type: 'text', value: '邮件 + Webhook', live: false },
  { name: '自动更新', desc: 'Agent 版本自动升级策略（灰度 → 全量）', type: 'switch', value: true, live: false },
  { name: '审计日志', desc: '控制台操作记录，保留 180 天', type: 'switch', value: true, live: false },
  { name: '离线队列上限', desc: '终端离线时报告暂存最大条数', type: 'text', value: '500 条', live: false },
];

export default function SettingsPage() {
  const { collectorState } = useCollector();

  return (
    <>
      <div className="page-head">
        <div>
          <p className="eyebrow">管理 / 系统设置</p>
          <h1>系统设置</h1>
          <p>Collector 连接为实时状态；其余为当前部署约定的只读说明（后端设置 API 未接入）。</p>
        </div>
        <div className="head-actions">
          <Button disabled title="后端设置 API 未接入，本页暂不可写">
            <Settings size={16} />
            保存设置
          </Button>
        </div>
      </div>

      <div className="panel">
        <div className="panel-head">
          <div>
            <h2>全局配置</h2>
            <p>标「未接入」的项为只读展示，修改需接入后端设置 API</p>
          </div>
        </div>
        {settings.map((setting) => {
          if (setting.type === 'switch') {
            return (
              <div className="setting-row" key={setting.name}>
                <div>
                  <strong>{setting.name}</strong>
                  <span>{setting.desc}</span>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  {!setting.live && <NotConnected />}
                  <button
                    className={`switch ${setting.value ? 'on' : ''}`}
                    disabled
                    title="后端设置 API 未接入，暂不可切换"
                    aria-label={`${setting.name}（未接入，不可切换）`}
                  >
                    <span />
                  </button>
                </div>
              </div>
            );
          }
          return (
            <div className="setting-row" key={setting.name}>
              <div>
                <strong>{setting.name}</strong>
                <span>{setting.desc}</span>
              </div>
              {setting.type === 'status' ? (
                <span className="system-ok">
                  <span className={collectorState === 'live' ? 'live-dot' : 'demo-dot'} />
                  {collectorState === 'live' ? '已连接' : collectorState === 'checking' ? '检测中' : '未连接'}
                </span>
              ) : (
                <span style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  {!setting.live && <NotConnected />}
                  <strong style={{ fontSize: 13, color: 'var(--muted-foreground)' }}>{setting.value}</strong>
                </span>
              )}
            </div>
          );
        })}
      </div>

      <AlertingPanel />
    </>
  );
}

interface AlertCfg {
  enabled: boolean;
  webhook: string;
  format: 'generic' | 'dingtalk';
  offline_hours: number;
  min_interval_hours: number;
}

/** 告警推送配置（真实可写，admin）：存 PG settings；服务器 aegis_alert_check.py 用 Collector 令牌只读拉取。 */
function AlertingPanel() {
  const { role } = useRole();
  const isAdmin = role === 'admin';
  const [cfg, setCfg] = useState<AlertCfg | null>(null);
  const [msg, setMsg] = useState('');
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    fetch('/api/settings/alerting', { cache: 'no-store' })
      .then((r) => (r.ok ? (r.json() as Promise<{ config?: AlertCfg }>) : null))
      .then((d) => setCfg(d?.config ?? null))
      .catch(() => setCfg(null));
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

  if (!cfg) return null;
  return (
    <div className="panel" style={{ marginTop: 16 }}>
      <div className="panel-head">
        <div>
          <h2>告警推送（Fleet Alerting）</h2>
          <p>服务器告警评估器（systemd timer 每 5 分钟）按此配置推送离线/坏自更/critical 告警；webhook 为空=不推送（dry-run）。</p>
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
          <Button variant="outline" onClick={() => void test()} disabled={busy || !cfg.webhook} title="向当前 webhook 发一条测试告警">
            <Send size={15} />
            测试发送
          </Button>
        </div>
      )}
    </div>
  );
}

function NotConnected() {
  return (
    <i className="warn" style={{ fontSize: 11, fontStyle: 'normal' }}>未接入</i>
  );
}
