'use client';

/**
 * 快速开始（首次使用引导）。
 *
 * 数据驱动的准备清单：每一步都读真实状态（接收器是否连接、是否已有设备/工单），
 * 完成即打勾，并给出下一步该去哪。附一个术语表，把"接收器 / Agent / Skill /
 * MCP / 处置 / 基线 / 扫描模式"等行话用人话解释清楚，降低新用户心智负担。
 *
 * 不做任何虚构进度；没有数据时如实显示"待完成"。
 */
import { useEffect, useState } from 'react';
import Link from 'next/link';
import { Rocket, Check, CircleDot, ArrowRight, BookOpen } from 'lucide-react';
import { useCollector } from '@/components/collector-context';

interface Step {
  key: string;
  title: string;
  desc: string;
  href: string;
  cta: string;
  done: boolean;
}

const GLOSSARY: Array<[string, string]> = [
  ['接收器 / Collector', '部署在服务端的报告汇聚点。各终端 Agent 把扫描结果上报到这里，控制台再从接收器读取数据。顶栏的"接收器已连接/未连接"就是它的实时状态。'],
  ['终端 Agent', '装在员工电脑上、随 AI 编码工具一起运行的轻量探针。它发现本机的 Skill / MCP / 依赖风险并上报，是数据的源头。'],
  ['Skill', 'AI 编码工具（如 Claude/Codex 等）可加载的技能插件。未签名或来源不明的 Skill 可能携带恶意指令，需要研判与处置。'],
  ['MCP', 'Model Context Protocol 服务，给 AI 工具提供文件/网络/命令等能力。越权的 MCP（如任意文件读写、未声明外联）是高危面。'],
  ['处置 / 打标', '对识别到的 Skill/MCP 给出结论：加白（allow）、观察（monitor）、拉黑（deny）。处置结果会进入下发给终端的策略。'],
  ['基线', '企业自定义的安全编码规则集，可与上游基线合并后下发到终端，作为 Agent 的强制约束。'],
  ['扫描模式', 'quick / standard / custom 三档，决定终端扫描的深度与耗时（quick=密钥+依赖；standard=+核心 SAST/代码质量规则；custom=仅已导入且终端可执行的基线规则）。'],
  ['工单', '需要人工研判的风险事件。状态机：待处理 → 已认领 → 调查中 → 已解决/驳回，全程留痕可审计。'],
];

export default function OnboardingPage() {
  const { fleet, collectorState } = useCollector();
  const [deviceCount, setDeviceCount] = useState<number | null>(null);
  const [ticketCount, setTicketCount] = useState<number | null>(null);
  const [baselineCount, setBaselineCount] = useState<number | null>(null);
  const [labelCount, setLabelCount] = useState<number | null>(null);

  useEffect(() => {
    fetch('/api/devices', { cache: 'no-store' })
      .then((r) => (r.ok ? (r.json() as Promise<{ devices?: unknown[] }>) : null))
      .then((d) => setDeviceCount(Array.isArray(d?.devices) ? d!.devices!.length : 0))
      .catch(() => setDeviceCount(null));
    fetch('/api/tickets?limit=1', { cache: 'no-store' })
      .then((r) => (r.ok ? (r.json() as Promise<{ total?: number }>) : null))
      .then((d) => setTicketCount(typeof d?.total === 'number' ? d.total : 0))
      .catch(() => setTicketCount(null));
    fetch('/api/labels', { cache: 'no-store' })
      .then((r) => (r.ok ? (r.json() as Promise<{ labels?: unknown[] }>) : null))
      .then((d) => setLabelCount(Array.isArray(d?.labels) ? d.labels.length : 0))
      .catch(() => setLabelCount(null));
    fetch('/api/baselines', { cache: 'no-store' })
      .then((r) => (r.ok ? (r.json() as Promise<{ baselines?: unknown[] }>) : null))
      .then((d) => setBaselineCount(Array.isArray(d?.baselines) ? d!.baselines!.length : 0))
      .catch(() => setBaselineCount(null));
  }, []);

  const connected = collectorState === 'live';
  const steps: Step[] = [
    {
      key: 'collector',
      title: '连接接收器（Collector）',
      desc: '在服务端部署接收器并配置控制台指向它。顶栏显示"接收器已连接"即为成功。',
      href: '/integrations',
      cta: '去接入中心',
      done: connected,
    },
    {
      key: 'agents',
      title: '部署终端 Agent',
      desc: '把 Aegis 终端 Agent 分发到员工电脑（单端原则：只推 Aegis 一个 agent）。',
      href: '/devices',
      cta: '下载与设备',
      done: (deviceCount ?? 0) > 0,
    },
    {
      key: 'triage',
      title: '研判风险工单',
      desc: '在风险中心认领并研判 Agent 上报的 critical/high 发现，推进工单状态机。',
      href: '/risks',
      cta: '去风险中心',
      done: (ticketCount ?? 0) > 0,
    },
    {
      key: 'disposition',
      title: '处置 Skill / MCP',
      desc: '对识别到的技能与 MCP 服务打标：加白 / 观察 / 拉黑，形成下发策略。',
      href: '/dispositions',
      cta: '去处置中心',
      done: (labelCount ?? 0) > 0,
    },
    {
      key: 'baseline',
      title: '配置基线与扫描模式',
      desc: '导入企业自定义编码基线、设置上游同步与扫描深度，约束终端 Agent 行为。',
      href: '/baselines',
      cta: '去基线管理',
      done: (baselineCount ?? 0) > 0,
    },
  ];

  const doneCount = steps.filter((s) => s.done).length;

  return (
    <>
      <div className="page-head animate-entrance animate-entrance-1">
        <div>
          <p className="eyebrow">开始使用 / 快速上手</p>
          <h1>快速开始</h1>
          <p>五步把 Aegis 接入你的团队：连接接收器 → 部署 Agent → 研判 → 处置 → 基线下发。</p>
        </div>
      </div>

      <div className="panel animate-entrance animate-entrance-2" style={{ padding: 14, marginBottom: 14 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <Rocket size={18} />
          <strong style={{ fontSize: 14 }}>准备进度 {doneCount} / {steps.length}</strong>
          <span style={{ marginLeft: 'auto', fontSize: 12, color: 'var(--muted-foreground)' }}>
            {connected ? '接收器已连接' : '接收器未连接'}
            {fleet ? ` · ${fleet.total_devices} 台设备` : ''}
          </span>
        </div>
      </div>

      <div style={{ display: 'grid', gap: 10 }}>
        {steps.map((s, i) => (
          <div key={s.key} className="panel animate-entrance" style={{ padding: 14, display: 'flex', gap: 12, alignItems: 'flex-start' }}>
            <span
              style={{
                flex: '0 0 auto',
                width: 26,
                height: 26,
                borderRadius: '50%',
                display: 'grid',
                placeItems: 'center',
                flexShrink: 0,
                border: '1px solid var(--border)',
                color: s.done ? 'var(--sentinel-accent, #28e6a0)' : 'var(--muted-foreground)',
                background: s.done ? 'color-mix(in srgb, var(--sentinel-accent, #28e6a0) 14%, transparent)' : 'transparent',
              }}
            >
              {s.done ? <Check size={15} /> : <CircleDot size={15} />}
            </span>
            <div style={{ flex: 1, minWidth: 0 }}>
              <strong style={{ fontSize: 14 }}>
                {i + 1}. {s.title}
                {s.done && <i className="pass" style={{ marginLeft: 8 }}>已完成</i>}
              </strong>
              <p style={{ fontSize: 12, color: 'var(--muted-foreground)', margin: '4px 0 8px' }}>{s.desc}</p>
              <Link
                className="handle"
                href={s.href}
                style={{ fontSize: 12, display: 'inline-flex', alignItems: 'center', gap: 4, width: 'fit-content' }}
              >
                {s.cta} <ArrowRight size={12} />
              </Link>
            </div>
          </div>
        ))}
      </div>

      <div className="panel animate-entrance" style={{ padding: 14, marginTop: 14 }}>
        <div className="panel-head">
          <div>
            <h2 style={{ display: 'flex', alignItems: 'center', gap: 8 }}><BookOpen size={16} /> 术语表</h2>
            <p>产品里的行话，一次说清</p>
          </div>
        </div>
        <div className="data-table">
          {GLOSSARY.map(([term, meaning]) => (
            <div className="data-row" key={term} style={{ gridTemplateColumns: '160px 1fr', gap: 12 }}>
              <strong style={{ fontSize: 13 }}>{term}</strong>
              <span style={{ fontSize: 12, color: 'var(--muted-foreground)' }}>{meaning}</span>
            </div>
          ))}
        </div>
      </div>
    </>
  );
}
