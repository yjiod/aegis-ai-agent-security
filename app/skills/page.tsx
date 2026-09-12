'use client';

import { useState } from 'react';
import { AlertTriangle, RefreshCw, Sparkles } from 'lucide-react';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  Legend,
  ResponsiveContainer,
  CartesianGrid,
} from 'recharts';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Toast } from '@/components/toast';

const scanTrend = [
  { day: '周一', scanned: 12, findings: 1 },
  { day: '周二', scanned: 18, findings: 2 },
  { day: '周三', scanned: 9, findings: 0 },
  { day: '周四', scanned: 22, findings: 3 },
  { day: '周五', scanned: 15, findings: 1 },
  { day: '周六', scanned: 6, findings: 0 },
  { day: '周日', scanned: 4, findings: 1 },
];

const scanRows = [
  ['prompt-helper.skill', '隔离', '隐藏指令覆盖', '高危'],
  ['jira-assistant.skill', '放行', '权限声明完整', '通过'],
  ['release-notes.skill', '观察', '依赖包待升级', '中危'],
  ['code-review.skill', '放行', '签名验证通过', '通过'],
  ['deploy-helper.skill', '隔离', '未授权网络出站', '高危'],
];

function statusTone(status: string) {
  if (status === '通过' || status === '受保护') return 'pass';
  if (status === '高危' || status === '需处理') return 'fail';
  return 'warn';
}

export default function SkillsPage() {
  const [toast, setToast] = useState('');
  const pending = scanRows.filter((row) => row[3] !== '通过').length;

  return (
    <section className="workspace">
      

      <div className="page-head animate-entrance animate-entrance-1">
        <div>
          <p className="eyebrow">安全能力 / Skill 扫描器</p>
          <h1>Skill 扫描器</h1>
          <p>校验 Skill 的权限声明、隐藏指令、签名与依赖清单。</p>
        </div>
        <div className="head-actions">
          <Button
            variant="outline"
            onClick={() => setToast('提示：Skill 白名单尚未连接审批系统。')}
          >
            <Sparkles />
            签名白名单
          </Button>
          <Button
            onClick={() =>
              setToast('功能待接入：未连接规则同步 API，未修改任何终端。')
            }
          >
            <RefreshCw />
            同步规则库
          </Button>
        </div>
      </div>

      <Toast message={toast} />

      <div className="detail-kpis">
        <article className="animate-entrance animate-entrance-1">
          <strong>68</strong>
          <span>已扫描对象</span>
        </article>
        <article className="animate-entrance animate-entrance-2">
          <strong>3</strong>
          <span>待处理发现</span>
        </article>
        <article className="animate-entrance animate-entrance-3">
          <strong>100%</strong>
          <span>在线终端覆盖</span>
        </article>
      </div>

      <div className="panel scan-trend animate-entrance animate-entrance-4">
        <div className="panel-head">
          <div>
            <h2>过去 7 天扫描趋势</h2>
            <p>每日扫描对象数量与新增发现</p>
          </div>
          <Badge variant="outline">
            <span className="live-dot" />
            实时数据
          </Badge>
        </div>
        <ResponsiveContainer width="100%" height={200}>
          <BarChart
            data={scanTrend}
            margin={{ top: 8, right: 8, bottom: 0, left: -20 }}
          >
            <CartesianGrid stroke="#16302a" strokeDasharray="3 3" vertical={false} />
            <XAxis
              dataKey="day"
              axisLine={false}
              tickLine={false}
              tick={{ fill: '#86a39a', fontSize: 11 }}
            />
            <YAxis
              axisLine={false}
              tickLine={false}
              tick={{ fill: '#86a39a', fontSize: 11 }}
            />
            <Tooltip
              cursor={{ fill: '#14332930' }}
              contentStyle={{
                background: '#0d1a17',
                border: '1px solid #1a2e28',
                borderRadius: 8,
                color: '#eaf7f2',
                fontSize: 12,
              }}
              labelStyle={{ color: '#86a39a' }}
            />
            <Legend wrapperStyle={{ fontSize: 11, color: '#86a39a' }} />
            <Bar
              dataKey="scanned"
              name="扫描对象"
              fill="#49e8a5"
              radius={[4, 4, 0, 0]}
              barSize={18}
            />
            <Bar
              dataKey="findings"
              name="新增发现"
              fill="#ff685f"
              radius={[4, 4, 0, 0]}
              barSize={18}
            />
          </BarChart>
        </ResponsiveContainer>
      </div>

      <div className="panel">
        <div className="panel-head">
          <div>
            <h2>最近扫描结果</h2>
            <p>终端安全 Agent 上报实时 · {pending} 项待处理</p>
          </div>
          <Button
            onClick={() =>
              setToast('功能待接入：未连接规则同步 API，未修改任何终端。')
            }
          >
            同步规则库
          </Button>
        </div>
        <div className="data-table">
          <div className="data-head">
            <span>对象</span>
            <span>策略动作</span>
            <span>检测结果</span>
            <span>状态</span>
          </div>
          {scanRows.map((row, i) => (
            <div
              className="data-row animate-row-entrance"
              key={row[0]}
              style={{ animationDelay: `${i * 30 + 200}ms` }}
            >
              <strong>{row[0]}</strong>
              <span>{row[1]}</span>
              <span>{row[2]}</span>
              <i className={statusTone(row[3])}>{row[3]}</i>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
