'use client';

import { useState } from 'react';
import {
  Code2,
  FileText,
  RefreshCw,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Toast } from '@/components/toast';

const coreRules = [
  ['SEC-AUTH-01', '禁止硬编码密钥与令牌', '阻断'],
  ['SEC-INJ-03', '外部输入必须参数化处理', '阻断'],
  ['SEC-LOG-02', '敏感字段不得写入日志', '阻断'],
  ['SEC-DEP-04', '高危依赖不得进入主分支', '需审批'],
];

const extendedRules = [
  ['SEC-MCP-01', 'MCP 工具必须声明最小权限', 'Skill · MCP', '阻断'],
  ['SEC-SKL-02', 'Skill 不得包含隐藏指令覆盖', 'Skill 清单', '阻断'],
  ['SEC-GEN-05', '生成代码需通过 SAST 门禁', '代码仓库', '需审批'],
  ['SEC-NET-03', '出站地址必须锁定白名单', 'MCP · Agent', '观察'],
];

function actionTone(action: string) {
  return action === '阻断' ? 'fail' : 'warn';
}

export default function BaselinePage() {
  const [toast, setToast] = useState('');

  return (
    <section className="workspace">
      

      <div className="page-head animate-entrance animate-entrance-1">
        <div>
          <p className="eyebrow">安全能力 / 编码基线</p>
          <h1>安全编码规范基线</h1>
          <p>企业规则基线随 Agent 静默加载，覆盖密钥、注入、日志与依赖。</p>
        </div>
        <div className="head-actions">
          <Button
            variant="outline"
            onClick={() =>
              setToast('功能待接入：未连接基线导出接口，未生成规则清单文件。')
            }
          >
            <FileText />
            导出规则清单
          </Button>
          <Button
            onClick={() =>
              setToast('功能待接入：未连接策略发布 API，未修改任何终端。')
            }
          >
            <RefreshCw />
            同步至终端
          </Button>
        </div>
      </div>

      <Toast message={toast} />

      <div className="baseline-banner animate-entrance animate-entrance-1">
        <div>
          <h2>企业 AI Coding 安全基线 v4.8</h2>
          <p>规则应用范围与合规率为界面实时</p>
        </div>
        <strong>
          98.2%<span>合规率</span>
        </strong>
      </div>

      <div className="policy-grid">
        {coreRules.map((rule, i) => (
          <article
            className={`panel policy-card animate-entrance animate-entrance-${i + 2}`}
            key={rule[0]}
          >
            <span>{rule[0]}</span>
            <h3>{rule[1]}</h3>
            <div>
              <i className={actionTone(rule[2])}>{rule[2]}</i>
              <button
                onClick={() => setToast(`${rule[0]} 规则详情已打开。`)}
                type="button"
              >
                配置
              </button>
            </div>
          </article>
        ))}
      </div>

      <div className="panel">
        <div className="panel-head">
          <div>
            <h2>扩展规则</h2>
            <p>面向 Skill、MCP 与生成代码的补充约束</p>
          </div>
          <Badge variant="outline">
            <Code2 size={13} />
            {coreRules.length + extendedRules.length} 条规则
          </Badge>
        </div>
        <div className="data-table">
          <div className="data-head">
            <span>规则编号</span>
            <span>规则说明</span>
            <span>适用范围</span>
            <span>动作</span>
          </div>
          {extendedRules.map((rule) => (
            <div className="data-row" key={rule[0]}>
              <strong>{rule[0]}</strong>
              <span>{rule[1]}</span>
              <span>{rule[2]}</span>
              <i className={actionTone(rule[3])}>{rule[3]}</i>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
