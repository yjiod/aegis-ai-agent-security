'use client';

import { useState } from 'react';
import {
  AlertTriangle,
  CircleDot,
  Filter,
  ShieldAlert,
  ShieldCheck,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';

type Risk = {
  severity: string;
  color: string;
  title: string;
  source: string;
  device: string;
  time: string;
};

const risks: Risk[] = [
  {
    severity: '高危',
    color: 'red',
    title: 'MCP Server 请求了未授权文件目录',
    source: 'cursor-mcp-filesystem',
    device: 'MKT-LT-2841',
    time: '2 分钟前',
  },
  {
    severity: '中危',
    color: 'orange',
    title: 'Skill 包含可疑的隐藏指令覆盖',
    source: 'prompt-helper.skill',
    device: 'ENG-MBP-1032',
    time: '18 分钟前',
  },
  {
    severity: '中危',
    color: 'orange',
    title: '生成代码使用弱随机数创建会话令牌',
    source: 'payment-service / PR #184',
    device: 'ENG-LT-0948',
    time: '31 分钟前',
  },
  {
    severity: '高危',
    color: 'red',
    title: '未签名的 MCP 出站连接被放行',
    source: 'postgres-mcp · 45.83.12.7',
    device: 'OPS-MBP-0314',
    time: '46 分钟前',
  },
  {
    severity: '低危',
    color: 'pass',
    title: '依赖包命中 CVE-2026-1847',
    source: 'data-pipeline / requirements.txt',
    device: 'ENG-LT-0948',
    time: '1 小时前',
  },
];

export default function RisksPage() {
  const [toast, setToast] = useState('');
  const highRisk = risks.filter((risk) => risk.severity === '高危').length;

  return (
    <section className="workspace">
      <div className="demo-notice" role="note">
        <AlertTriangle size={16} />
        <span>
          <strong>演示模式</strong>
          风险事件、严重等级、处置时长与工单编号均为界面样例；未连接 EDR
          与工单系统前不会执行任何隔离或阻断动作。
        </span>
      </div>

      <div className="page-head animate-entrance animate-entrance-1">
        <div>
          <p className="eyebrow">风险中心 / 待研判</p>
          <h1>风险中心</h1>
          <p>按风险等级与时间排序，认领后进入分级响应流程。</p>
        </div>
        <div className="head-actions">
          <Button
            variant="outline"
            onClick={() => setToast('演示模式：等级筛选尚未连接查询 API。')}
          >
            <Filter />
            全部等级
          </Button>
          <Button
            onClick={() =>
              setToast('演示模式：未连接 EDR 审批接口，未隔离任何对象。')
            }
          >
            <ShieldAlert />
            隔离全部高危
          </Button>
        </div>
      </div>

      {toast && (
        <div className="toast" role="status">
          <CircleDot size={16} />
          {toast}
        </div>
      )}

      <div className="detail-kpis">
        <article className="animate-entrance animate-entrance-1">
          <strong>3</strong>
          <span>待研判事件（样例）</span>
        </article>
        <article className="animate-entrance animate-entrance-2">
          <strong>17</strong>
          <span>本周已处置（样例）</span>
        </article>
        <article className="animate-entrance animate-entrance-3">
          <strong>4.2min</strong>
          <span>平均响应时间（样例）</span>
        </article>
      </div>

      <div className="panel">
        <div className="panel-head">
          <div>
            <h2>待研判事件</h2>
            <p>{highRisk} 个高危事件需要人工确认</p>
          </div>
          <Badge variant="outline">
            <span className="live-dot" />
            实时上报样例
          </Badge>
        </div>
        <div className="risk-table">
          {risks.map((risk, i) => (
            <div
              className="risk-row wide animate-row-entrance"
              key={risk.title}
              style={{ animationDelay: `${i * 30 + 200}ms` }}
            >
              <span className={`severity ${risk.color}`}>{risk.severity}</span>
              <div className="risk-main">
                <strong>{risk.title}</strong>
                <span>{risk.source}</span>
              </div>
              <span className="device">{risk.device}</span>
              <span className="time">{risk.time}</span>
              <button
                className="handle"
                onClick={() =>
                  setToast(
                    `演示模式：未连接工单接口，未认领「${risk.title}」。`,
                  )
                }
              >
                认领处置
              </button>
            </div>
          ))}
        </div>
        <div className="flow">
          <span>终端上报</span>
          <b>→</b>
          <span>安全运营认领</span>
          <b>→</b>
          <span>深信服 EDR 隔离</span>
          <b>→</b>
          <span>基线复核</span>
          <b>→</b>
          <span className="safe">
            <ShieldCheck size={15} />
            工单关闭
          </span>
        </div>
      </div>
    </section>
  );
}
