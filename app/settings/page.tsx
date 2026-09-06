'use client';
import { useState } from 'react';
import { AlertTriangle, Settings } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { useCollector } from '@/components/collector-context';
import { Toast } from '@/components/toast';

const settings = [
  { name: 'Collector 连接', desc: '报告接收器地址与认证令牌', value: '动态', type: 'status' as const },
  { name: '数据保留期', desc: '报告与风险事件保留天数', value: '90 天', type: 'text' as const },
  { name: '通知渠道', desc: '高危事件推送方式', value: '邮件 + Webhook', type: 'text' as const },
  { name: '自动更新', desc: 'Agent 版本自动升级策略（灰度 → 全量）', value: true, type: 'switch' as const },
  { name: '审计日志', desc: '控制台操作记录，保留 180 天', value: true, type: 'switch' as const },
  { name: '离线队列上限', desc: '终端离线时报告暂存最大条数', value: '500 条', type: 'text' as const },
];

export default function SettingsPage() {
  const [toast, setToast] = useState('');
  const { collectorState } = useCollector();
  const [switches, setSwitches] = useState([true, true]);

  function toggleSwitch(index: number) {
    const name = settings.filter((s) => s.type === 'switch')[index]?.name ?? '';
    setToast(`演示模式：「${name}」未被修改，设置 API 尚未连接。`);
    setSwitches((prev) => {
      const next = [...prev];
      next[index] = !next[index];
      return next;
    });
    setTimeout(() => setSwitches((prev) => {
      const next = [...prev];
      next[index] = !prev[index];
      return next;
    }), 600);
  }

  let switchIndex = 0;

  return (
    <>
      <div className="demo-notice" role="note">
        <AlertTriangle size={16} />
        <span>
          <strong>演示模式</strong>
          系统设置为界面样例，企业 API 接入前修改不会持久化。
        </span>
      </div>

      <div className="page-head">
        <div>
          <p className="eyebrow">管理 / 系统设置</p>
          <h1>系统设置</h1>
          <p>Collector 连接、数据保留、通知与审计配置。</p>
        </div>
        <div className="head-actions">
          <Button onClick={() => setToast('演示模式：设置未保存，后端 API 尚未连接。')}>
            <Settings size={16} />
            保存设置
          </Button>
        </div>
      </div>

      <Toast message={toast} />

      <div className="panel">
        <div className="panel-head">
          <div>
            <h2>全局配置</h2>
            <p>影响所有受管终端与控制台行为</p>
          </div>
        </div>
        {settings.map((setting) => {
          if (setting.type === 'switch') {
            const idx = switchIndex++;
            return (
              <div className="setting-row" key={setting.name}>
                <div>
                  <strong>{setting.name}</strong>
                  <span>{setting.desc}</span>
                </div>
                <button
                  className={`switch ${switches[idx] ? 'on' : ''}`}
                  onClick={() => toggleSwitch(idx)}
                  aria-label={`切换${setting.name}`}
                >
                  <span />
                </button>
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
                <strong style={{ fontSize: 13, color: '#6cebb7' }}>{setting.value}</strong>
              )}
            </div>
          );
        })}
      </div>
    </>
  );
}
