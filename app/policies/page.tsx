'use client';
import { useState } from 'react';
import { AlertTriangle, CircleDot, SlidersHorizontal } from 'lucide-react';
import { Button } from '@/components/ui/button';

const policies = [
  { name: '自动发现 AI Agent', desc: '检测主流 AI Coding 工具（Cursor、Claude Code、Codex、Windsurf）', on: true },
  { name: '强制加载安全基线', desc: '启动时注入企业编码规范，未加载则阻断 Agent 执行', on: true },
  { name: '高危 MCP 自动隔离', desc: '阻断越权文件访问与未声明外联，隔离后通知安全管理员', on: true },
  { name: '未知 Skill 默认禁用', desc: '等待签名验证与安全审批，未审批 Skill 不加载', on: false },
  { name: '代码质量门禁', desc: '阻断高危 SAST 发现合入主分支，中危需人工审批', on: true },
  { name: '离线队列加密', desc: '报告暂存时使用 AES-256-GCM 加密，防止本地窃取', on: true },
];

export default function PoliciesPage() {
  const [toast, setToast] = useState('');
  const [states, setStates] = useState(policies.map((p) => p.on));

  function toggle(index: number) {
    setToast(`演示模式：「${policies[index].name}」未被修改，设置 API 尚未连接。`);
    setStates((prev) => {
      const next = [...prev];
      next[index] = !next[index];
      return next;
    });
    setTimeout(() => setStates((prev) => {
      const next = [...prev];
      next[index] = policies[index].on;
      return next;
    }), 600);
  }

  return (
    <>
      <div className="demo-notice" role="note">
        <AlertTriangle size={16} />
        <span>
          <strong>演示模式</strong>
          策略开关状态为界面样例，企业 API 接入前不会下发至任何终端。
        </span>
      </div>

      <div className="page-head animate-entrance animate-entrance-1">
        <div>
          <p className="eyebrow">管理 / 策略配置</p>
          <h1>终端安全策略</h1>
          <p>变更将自动同步至所有在线安全 Agent，请谨慎操作。</p>
        </div>
        <div className="head-actions">
          <Button onClick={() => setToast('演示模式：未连接策略发布 API，未修改任何终端。')}>
            <SlidersHorizontal size={16} />
            发布策略
          </Button>
        </div>
      </div>

      {toast && (
        <div className="toast" role="status">
          <CircleDot size={16} />
          {toast}
        </div>
      )}

      <div className="panel">
        <div className="panel-head">
          <div>
            <h2>默认终端策略</h2>
            <p>共 {policies.length} 项策略，{policies.filter((p) => p.on).length} 项已启用</p>
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
            <button
              className={`switch ${states[index] ? 'on' : ''}`}
              onClick={() => toggle(index)}
              aria-label={`切换${policy.name}`}
            >
              <span />
            </button>
          </div>
        ))}
      </div>
    </>
  );
}
