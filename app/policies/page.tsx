'use client';
import { SlidersHorizontal } from 'lucide-react';
import { Button } from '@/components/ui/button';

/**
 * 终端安全策略（只读说明）。
 *
 * 诚实原则：策略发布 API 尚未接入，本页不再做"点了翻转又自动弹回"的假反馈，
 * 也移除了"变更将自动同步至所有在线 Agent"这类暗示真实生效的误导文案。
 * 所有开关均为禁用态并标注"未接入"，展示的是当前部署的默认策略基线。
 *
 * 真正会下发到终端的策略（Skill/MCP 加白·观察·拉黑）在「处置中心」，
 * 自定义编码基线在「基线管理」，二者均已接入真实后端。
 */
const policies = [
  { name: '自动发现 AI Agent', desc: '检测主流 AI Coding 工具（Cursor、Claude Code、Codex、Windsurf）', on: true },
  { name: '强制加载安全基线', desc: '启动时注入企业编码规范，未加载则阻断 Agent 执行', on: true },
  { name: '高危 MCP 自动隔离', desc: '阻断越权文件访问与未声明外联，隔离后通知安全管理员', on: true },
  { name: '未知 Skill 默认禁用', desc: '等待签名验证与安全审批，未审批 Skill 不加载', on: false },
  { name: '代码质量门禁', desc: '阻断高危 SAST 发现合入主分支，中危需人工审批', on: true },
  { name: '离线队列加密', desc: '报告暂存时使用 AES-256-GCM 加密，防止本地窃取', on: true },
];

export default function PoliciesPage() {
  return (
    <>
      <div className="page-head animate-entrance animate-entrance-1">
        <div>
          <p className="eyebrow">管理 / 策略配置</p>
          <h1>终端安全策略</h1>
          <p>以下为当前部署的默认策略基线（只读）。策略发布 API 未接入，本页不可修改。</p>
        </div>
        <div className="head-actions">
          <Button disabled title="策略发布 API 未接入，未修改任何终端">
            <SlidersHorizontal size={16} />
            发布策略
          </Button>
        </div>
      </div>

      <div className="panel">
        <div className="panel-head">
          <div>
            <h2>默认终端策略</h2>
            <p>共 {policies.length} 项策略，{policies.filter((p) => p.on).length} 项默认启用（未接入，不可切换）</p>
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
              <i className="warn" style={{ fontSize: 11, fontStyle: 'normal' }}>未接入</i>
              <button
                className={`switch ${policy.on ? 'on' : ''}`}
                disabled
                title="策略发布 API 未接入，暂不可切换"
                aria-label={`${policy.name}（未接入，不可切换）`}
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
