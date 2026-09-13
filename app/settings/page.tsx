'use client';
import { Settings } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { useCollector } from '@/components/collector-context';

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
    </>
  );
}

function NotConnected() {
  return (
    <i className="warn" style={{ fontSize: 11, fontStyle: 'normal' }}>未接入</i>
  );
}
