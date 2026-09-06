'use client';

import { useState } from 'react';
import {
  AlertTriangle,
  Bot,
  ChevronDown,
  CircleDot,
  Download,
  Laptop,
  ShieldCheck,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { useCollector } from '@/components/collector-context';

const deviceRows = [
  ['ENG-MBP-1032', '陈昊 · Cursor', 'v3.8', '受保护'],
  ['MKT-LT-2841', '林妍 · Cursor', 'v3.7', '需处理'],
  ['ENG-LT-0948', '周航 · Codex CLI', 'v3.8', '受保护'],
  ['OPS-MBP-0314', '罗宁 · Claude Code', 'v3.8', '离线'],
  ['DESK-WIN-0521', '赵磊 · Windsurf', 'v3.8', '受保护'],
  ['MKT-MBP-0847', '吴婷 · Cursor', 'v3.6', '需处理'],
];

const toolCoverage = [
  { name: 'Cursor', total: 124, online: 100 },
  { name: 'Claude Code', total: 86, online: 78 },
  { name: 'Codex CLI', total: 64, online: 58 },
  { name: 'Windsurf', total: 38, online: 34 },
];

function statusTone(status: string) {
  if (status === '通过' || status === '受保护') return 'pass';
  if (status === '高危' || status === '需处理') return 'fail';
  return 'warn';
}

export default function DevicesPage() {
  const [toast, setToast] = useState('');
  const { fleet } = useCollector();

  const totalDevices = fleet?.total_devices ?? 312;
  const activeDevices = fleet?.active_devices ?? 284;
  const staleDevices = fleet?.stale_devices ?? 28;
  const onlineRate = fleet?.total_devices
    ? `${((fleet.active_devices / fleet.total_devices) * 100).toFixed(1)}%`
    : '91%';
  const versionCoverage = fleet?.total_devices
    ? `${((fleet.version_posture.current / fleet.total_devices) * 100).toFixed(1)}%`
    : '96.8%';

  return (
    <section className="workspace">
      <div className="demo-notice" role="note">
        <AlertTriangle size={16} />
        <span>
          <strong>{fleet ? '混合只读模式' : '演示模式'}</strong>
          {fleet
            ? ' 顶部三项指标来自已验证的接收器摘要；终端明细与工具覆盖分布仍为界面样例。'
            : ' 终端清单、在线率与版本覆盖率均为界面样例，不代表真实设备状态。'}
        </span>
      </div>

      <div className="page-head animate-entrance animate-entrance-1">
        <div>
          <p className="eyebrow">终端资产 / Agent 版本</p>
          <h1>设备与 Agent</h1>
          <p>查看受管终端、Agent 版本姿态与逐设备凭据代次。</p>
        </div>
        <div className="head-actions">
          <Button
            variant="outline"
            onClick={() => setToast('演示模式：时间范围筛选尚未连接查询 API。')}
          >
            <ChevronDown />
            过去 7 天
          </Button>
          <Button
            onClick={() =>
              setToast('演示模式：请直接下载已验证发行包，未创建外部任务。')
            }
          >
            <Download />
            生成部署包
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
          <strong>{totalDevices}</strong>
          <span>受管终端总数{fleet ? '' : '（样例）'}</span>
        </article>
        <article className="animate-entrance animate-entrance-2">
          <strong>{onlineRate}</strong>
          <span>在线率{fleet ? '' : '（样例）'}</span>
        </article>
        <article className="animate-entrance animate-entrance-3">
          <strong>{versionCoverage}</strong>
          <span>版本覆盖率{fleet ? '' : '（样例）'}</span>
        </article>
      </div>

      <div className="panel">
        <div className="panel-head">
          <div>
            <h2>受管终端</h2>
            <p>
              {fleet
                ? `${fleet.total_devices} 台设备 · ${fleet.active_devices} 台在线 · ${fleet.stale_devices} 台过期`
                : '312 台设备 · 284 台在线 · 28 台过期（样例）'}
            </p>
            <p>
              要求 Agent 版本 {fleet?.required_agent_version ?? 'v3.8'} ·
              要求策略版本 {fleet?.required_policy_version ?? 'v4.8'}
            </p>
            {fleet?.credential_posture && (
              <p>
                凭据代次：当前 {fleet.credential_posture.current} · 上一代{' '}
                {fleet.credential_posture.previous} · Legacy{' '}
                {fleet.credential_posture.legacy}
              </p>
            )}
          </div>
          <Badge variant="outline">
            <Laptop size={13} />
            {activeDevices} 台活跃
          </Badge>
        </div>
        <div className="data-table">
          <div className="data-head">
            <span>设备 ID</span>
            <span>用户 · 工具</span>
            <span>Agent 版本</span>
            <span>状态</span>
          </div>
          {deviceRows.map((row, i) => (
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
        <p className="safety-note">
          <ShieldCheck size={15} />
          终端明细为界面样例；接入报告接收器后将展示真实 device_id、版本姿态与凭据代次。
        </p>
      </div>

      <div className="panel coverage">
        <div className="panel-head">
          <div>
            <h2>按 Agent 工具覆盖</h2>
            <p>在线终端 / 已纳管终端</p>
          </div>
          <Badge variant="outline">
            <Bot size={13} />
            {staleDevices} 台待修复
          </Badge>
        </div>
        {toolCoverage.map((tool) => (
          <div className="coverage-row" key={tool.name}>
            <div className="tool-logo">{tool.name.slice(0, 1)}</div>
            <div className="coverage-data">
              <div>
                <strong>{tool.name}</strong>
                <span>
                  {tool.online}/{tool.total} 在线
                </span>
              </div>
              <Progress value={(tool.online / tool.total) * 100} />
            </div>
          </div>
        ))}
      </div>
    </section>
  );
}
