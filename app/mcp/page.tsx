'use client';

import { useState } from 'react';
import { AlertTriangle, CircleDot, Network, RefreshCw } from 'lucide-react';
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

const scanTrend = [
  { day: '周一', scanned: 8, findings: 1 },
  { day: '周二', scanned: 11, findings: 0 },
  { day: '周三', scanned: 6, findings: 1 },
  { day: '周四', scanned: 14, findings: 2 },
  { day: '周五', scanned: 9, findings: 1 },
  { day: '周六', scanned: 3, findings: 0 },
  { day: '周日', scanned: 5, findings: 0 },
];

const scanRows = [
  ['filesystem-mcp', '限制', '越权目录访问', '高危'],
  ['github-mcp', '放行', 'OAuth 范围合规', '通过'],
  ['postgres-mcp', '观察', '出站地址未锁定', '中危'],
  ['slack-mcp', '放行', '令牌范围最小化', '通过'],
  ['browser-mcp', '隔离', '未声明 Cookie 读取', '高危'],
];

function statusTone(status: string) {
  if (status === '通过' || status === '受保护') return 'pass';
  if (status === '高危' || status === '需处理') return 'fail';
  return 'warn';
}

export default function McpPage() {
  const [toast, setToast] = useState('');

  return (
    <section className="workspace">
      <div className="demo-notice" role="note">
        <AlertTriangle size={16} />
        <span>
          <strong>演示模式</strong>
          MCP Server 清单、工具权限、出站地址与检测结果均为界面样例；未连接规则同步与处置接口前不会限制或隔离任何
          MCP。
        </span>
      </div>

      <div className="page-head animate-entrance animate-entrance-1">
        <div>
          <p className="eyebrow">安全能力 / MCP 扫描器</p>
          <h1>MCP 扫描器</h1>
          <p>校验 MCP 工具权限、密钥来源、出站白名单与令牌范围。</p>
        </div>
        <div className="head-actions">
          <Button
            variant="outline"
            onClick={() => setToast('演示模式：出站白名单尚未连接策略下发接口。')}
          >
            <Network />
            出站白名单
          </Button>
          <Button
            onClick={() =>
              setToast('演示模式：未连接规则同步 API，未修改任何终端。')
            }
          >
            <RefreshCw />
            同步规则库
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
          <strong>41</strong>
          <span>已扫描对象（样例）</span>
        </article>
        <article className="animate-entrance animate-entrance-2">
          <strong>2</strong>
          <span>待处理发现（样例）</span>
        </article>
        <article className="animate-entrance animate-entrance-3">
          <strong>100%</strong>
          <span>在线终端覆盖（样例）</span>
        </article>
      </div>

      <div className="panel scan-trend animate-entrance animate-entrance-4">
        <div className="panel-head">
          <div>
            <h2>过去 7 天扫描趋势</h2>
            <p>每日 MCP 连接扫描量与新增发现</p>
          </div>
          <Badge variant="outline">
            <span className="live-dot" />
            样例数据
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
              name="扫描连接"
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
            <p>终端安全 Agent 上报样例 · 最近 24 小时</p>
          </div>
          <Button
            onClick={() =>
              setToast('演示模式：未连接规则同步 API，未修改任何终端。')
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
