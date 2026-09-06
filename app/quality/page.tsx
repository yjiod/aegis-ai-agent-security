'use client';

import { useState } from 'react';
import { AlertTriangle, CircleDot, RefreshCw, Wrench } from 'lucide-react';
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
  { day: '周一', scanned: 22, findings: 3 },
  { day: '周二', scanned: 31, findings: 2 },
  { day: '周三', scanned: 18, findings: 4 },
  { day: '周四', scanned: 27, findings: 1 },
  { day: '周五', scanned: 35, findings: 2 },
  { day: '周六', scanned: 12, findings: 0 },
  { day: '周日', scanned: 9, findings: 1 },
];

const scanRows = [
  ['payment-service', '阻断', '弱随机数生成令牌', '高危'],
  ['customer-portal', '放行', '质量门禁通过', '通过'],
  ['data-pipeline', '观察', '依赖存在 CVE', '中危'],
  ['auth-gateway', '放行', 'SAST 扫描通过', '通过'],
  ['notification-svc', '阻断', 'SQL 注入风险', '高危'],
  ['analytics-api', '观察', '圈复杂度超标', '中危'],
  ['config-loader', '放行', '密钥管理规范', '通过'],
];

function statusTone(status: string) {
  if (status === '通过' || status === '受保护') return 'pass';
  if (status === '高危' || status === '需处理') return 'fail';
  return 'warn';
}

export default function QualityPage() {
  const [toast, setToast] = useState('');

  return (
    <section className="workspace">
      <div className="demo-notice" role="note">
        <AlertTriangle size={16} />
        <span>
          <strong>演示模式</strong>
          仓库清单、SAST 发现、门禁通过率与阻断结果均为界面样例；未连接代码托管平台前不会阻断任何
          合并请求。
        </span>
      </div>

      <div className="page-head animate-entrance animate-entrance-1">
        <div>
          <p className="eyebrow">安全能力 / 代码质量</p>
          <h1>代码质量扫描</h1>
          <p>SAST、依赖 CVE 与密钥检测在提交与合并两个门禁点执行。</p>
        </div>
        <div className="head-actions">
          <Button
            variant="outline"
            onClick={() => setToast('演示模式：门禁阈值尚未连接代码托管平台。')}
          >
            <Wrench />
            门禁阈值
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
          <strong>126</strong>
          <span>已扫描仓库（样例）</span>
        </article>
        <article className="animate-entrance animate-entrance-2">
          <strong>7</strong>
          <span>待处理发现（样例）</span>
        </article>
        <article className="animate-entrance animate-entrance-3">
          <strong>94.4%</strong>
          <span>门禁通过率（样例）</span>
        </article>
      </div>

      <div className="panel scan-trend animate-entrance animate-entrance-4">
        <div className="panel-head">
          <div>
            <h2>过去 7 天扫描趋势</h2>
            <p>每日扫描仓库数量与新增质量发现</p>
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
              name="扫描仓库"
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
            <p>按仓库维度的门禁判定样例</p>
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
            <span>仓库</span>
            <span>门禁动作</span>
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
