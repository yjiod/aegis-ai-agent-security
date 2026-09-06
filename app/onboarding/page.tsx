'use client';

import { useState } from 'react';
import {
  AlertTriangle,
  ChevronDown,
  CircleDot,
  Download,
  LockKeyhole,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';

const controlPlanes = [
  {
    name: 'Microsoft Intune',
    role: '主部署通道',
    desc: 'Windows Remediations 与 macOS Shell Script，负责安装、版本检测、周期修复和自定义合规。',
  },
  {
    name: '深信服 EDR',
    role: '响应处置',
    desc: '接收高危事件，按现网版本能力执行隔离、查杀或 IOC 取证。',
  },
  {
    name: '联软桌管',
    role: '资产与兜底',
    desc: '软件分发、资产核验及未安装终端的准入修复。',
  },
];

const orchestrationSteps = [
  {
    title: '自动发现',
    desc: 'Intune 周期任务检测 Cursor、Claude Code、Codex 与 Windsurf 配置。',
  },
  {
    title: '加载基线',
    desc: '为受管项目增量安装 Agent 规则，并持续扫描 Skill、MCP 与代码。',
  },
  {
    title: '联动处置',
    desc: '以 device_id 关联深信服 EDR 与联软资产，按风险等级分级响应。',
  },
];

const downloadAssets = [
  { href: '/downloads/intune-windows-detect.ps1', label: 'Windows 检测脚本' },
  { href: '/downloads/intune-windows-remediate.ps1', label: 'Windows 修复脚本' },
  { href: '/downloads/intune-macos-install.sh', label: 'macOS Intune 脚本' },
  { href: '/downloads/intune-macos-compliance.sh', label: 'macOS 合规脚本' },
  { href: '/downloads/aegis-policy.json', label: '策略基线' },
  {
    href: '/downloads/aegis_device_credentials.py',
    label: '逐设备凭据工具',
  },
  { href: '/downloads/CHECKSUMS.sha256', label: 'SHA-256 校验清单' },
];

export default function OnboardingPage() {
  const [toast, setToast] = useState('');

  return (
    <section className="workspace">
      <div className="demo-notice" role="note">
        <AlertTriangle size={16} />
        <span>
          <strong>演示模式</strong>
          部署编排、控制面联动与下载清单均为界面样例；正式接入前请以现网 Intune、深信服 EDR 与联软桌管版本核对脚本与接口授权。
        </span>
      </div>

      <div className="page-head">
        <div>
          <p className="eyebrow">接入中心 / 部署编排</p>
          <h1>接入中心</h1>
          <p>一次下载已验证发行包，由 Intune 与桌管完成静默部署。</p>
        </div>
        <div className="head-actions">
          <Button
            variant="outline"
            onClick={() =>
              setToast('演示模式：发行通道固定为 Intune + 联软桌管，未切换。')
            }
          >
            <ChevronDown />
            Intune 发行通道
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

      <div className="baseline-banner">
        <div>
          <h2>Aegis Endpoint Agent 0.30.0</h2>
          <p>Intune 部署 · 深信服 EDR 联动 · 联软桌管兜底</p>
        </div>
        <strong>
          可验证<span>本地执行</span>
        </strong>
      </div>

      <div className="panel onboarding">
        <div className="panel-head">
          <div>
            <h2>企业部署编排</h2>
            <p>三个控制面分工明确，终端永不直连厂商管理面</p>
          </div>
          <Badge variant="outline">
            <span className="live-dot" />
            发行包可用
          </Badge>
        </div>

        <div className="control-planes">
          {controlPlanes.map((plane) => (
            <article key={plane.name}>
              <b>{plane.name}</b>
              <span>{plane.role}</span>
              <p>{plane.desc}</p>
            </article>
          ))}
        </div>

        <ol>
          {orchestrationSteps.map((step) => (
            <li key={step.title}>
              <b>{step.title}</b>
              <span>{step.desc}</span>
            </li>
          ))}
        </ol>

        <div className="download-actions">
          <a
            className="download-primary"
            href="/downloads/aegis-enterprise-bundle.zip"
            download
          >
            下载完整部署包
          </a>
          <a
            className="download-primary"
            href="/downloads/DEPLOYMENT-GUIDE.md"
            download
          >
            下载部署指南
          </a>
          {downloadAssets.map((asset) => (
            <a key={asset.href} href={asset.href} download>
              {asset.label}
            </a>
          ))}
        </div>

        <p className="safety-note">
          <LockKeyhole size={15} />
          部署脚本不包含深信服或联软管理凭据；正式联动需按现网版本申请服务账号与接口授权。
        </p>
      </div>
    </section>
  );
}
