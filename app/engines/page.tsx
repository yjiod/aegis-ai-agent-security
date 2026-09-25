'use client';

import { useEffect, useState } from 'react';
import { Check, Cpu, Inbox, RefreshCw, X, Zap } from 'lucide-react';
import { ObservabilityPanel } from '@/components/observability-panel';
import { DetectionCoveragePanel } from '@/components/detection-coverage-panel';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';

/* ─── Engine registry (static mirror of aegis_engine_framework.py) ─────
 * 诚实原则：这是「框架支持哪些引擎」的静态注册表（设计事实），不是对终端/本机
 * 的实时探测。因此：
 *   - 版本只在框架硬编码声明时才写死（aegis-regex 1.0.0）；semgrep/gitleaks 由
 *     框架在运行时 check_version() 探测，控制台无探测 API，故标「运行时探测」而非
 *     编造精确版本号（此前写死 1.89.0 / 8.21.2 属虚构数字，已移除）。
 *   - builtin=true 表示「框架已内置该引擎适配器」，非「已在本机安装并可用」。
 *   - rule_update_url 取自框架声明的真实上游规则源（公开地址，非个人隐私基础设施）。
 */

interface Engine {
  name: string; version: string; vendor: string; license: string;
  mode: 'local' | 'cloud' | 'hybrid'; scopes: string[];
  builtin: boolean; rule_format: string; requires_token?: boolean;
  rule_update_url?: string;
}

const ENGINES: Engine[] = [
  { name: 'aegis-regex', version: '1.0.0', vendor: 'Aegis', license: 'Proprietary', mode: 'local', scopes: ['skill', 'mcp', 'code', 'secrets'], builtin: true, rule_format: 'regex' },
  { name: 'semgrep', version: '运行时探测', vendor: 'Semgrep Inc.', license: 'LGPL-2.1 / Commons Clause', mode: 'local', scopes: ['code', 'secrets'], builtin: true, rule_format: 'yaml', rule_update_url: 'semgrep.dev/c/p/default' },
  { name: 'gitleaks', version: '运行时探测', vendor: 'Gitleaks', license: 'MIT', mode: 'local', scopes: ['secrets'], builtin: true, rule_format: 'toml', rule_update_url: 'github.com/gitleaks/gitleaks' },
  { name: 'cisco-skill-scanner', version: '运行时探测', vendor: 'Cisco', license: 'Apache-2.0', mode: 'local', scopes: ['skill', 'mcp'], builtin: true, rule_format: 'json', rule_update_url: 'github.com/cisco-ai-security/skill-scanner' },
  { name: 'osv-sca', version: '1.0', vendor: 'OSV.dev (Google)', license: 'Apache-2.0', mode: 'cloud', scopes: ['deps'], builtin: true, rule_format: 'osv-api', rule_update_url: 'osv.dev' },
  { name: 'pip-audit', version: '运行时探测', vendor: 'PyPA / Trail of Bits', license: 'Apache-2.0', mode: 'local', scopes: ['deps'], builtin: true, rule_format: 'pypi-advisory', rule_update_url: 'pypi.org/project/pip-audit' },
];

const SCOPE_LABELS: Record<string, string> = {
  skill: 'Skill 扫描', mcp: 'MCP 扫描', code: '代码 SAST', secrets: '密钥检测', deps: '依赖 SCA',
};

// 规则更新管道的门禁阶段——这是管道「设计流程」的说明图（概念），非实时管道活动数据。
const GATES = ['许可证兼容', 'SHA-256 哈希', '结构验证', '回归测试'];

interface PipelineEvent {
  ts: number;
  pipeline: string;
  source: string;
  stages: Array<{ name: string; ok: boolean; detail?: string }>;
  ok: boolean;
  latency_ms: number;
  actor: string;
  detail: string;
}

const PIPELINE_LABEL: Record<string, string> = {
  'policy-publish': '签名策略发布',
  'baseline-sync': '上游基线同步',
  'enterprise-md-publish': '企业级 MD 发布',
};

export default function EnginesPage() {
  const builtinCount = ENGINES.filter((e) => e.builtin).length;
  const pendingCount = ENGINES.filter((e) => !e.builtin).length;
  const [telemetry, setTelemetry] = useState<{ connected: boolean; events: PipelineEvent[] } | null>(null);

  useEffect(() => {
    let alive = true;
    fetch('/api/pipeline/telemetry', { cache: 'no-store' })
      .then((r) => (r.ok ? (r.json() as Promise<{ connected: boolean; events: PipelineEvent[] }>) : null))
      .then((d) => {
        if (alive) setTelemetry(d ?? { connected: false, events: [] });
      })
      .catch(() => {
        if (alive) setTelemetry({ connected: false, events: [] });
      });
    return () => {
      alive = false;
    };
  }, []);

  return (
    <>
      <div className="page-head animate-entrance animate-entrance-1">
        <div>
          <p className="eyebrow">安全能力 / 扫描引擎</p>
          <h1>多引擎扫描管理</h1>
          <p>Cisco skill-scanner · OSV.dev SCA · pip-audit · Semgrep · Gitleaks — 各自独立规则源，不强行转换语法；上游均无需 API Token。</p>
        </div>
        <div className="head-actions">
          {/* 诚实原则：未接入后端的能力不放"点了只弹提示"的活按钮，直接禁用并说明原因。 */}
          <Button variant="outline" disabled title="引擎同步 API 尚未连接：规则更新管道在引擎框架内运行，未接入控制台">
            <RefreshCw size={16} /> 同步规则库
          </Button>
          <Button disabled title="需先连接终端 Agent 才能发起全量扫描">
            <Zap size={16} /> 全量扫描
          </Button>
        </div>
      </div>

      {/* KPIs — 均由静态引擎注册表派生（设计事实），非实时探测遥测 */}
      <div className="detail-kpis animate-entrance animate-entrance-2">
        <article><strong>{ENGINES.length}</strong><span>框架支持引擎</span></article>
        <article><strong>{builtinCount}</strong><span>已内置适配器</span></article>
        <article><strong>{pendingCount}</strong><span>待集成</span></article>
      </div>

      {/* Engine Grid */}
      <ObservabilityPanel />

      {/* AIDR Detection 侧：技战法覆盖矩阵 */}
      <DetectionCoveragePanel />

      <div className="panel animate-entrance animate-entrance-3" style={{ marginBottom: 14 }}>
        <div className="panel-head">
          <div>
            <h2>已注册引擎</h2>
            <p>引擎能力清单 · 每个引擎保持原生规则语法，不强行转换 · 非本机实时探测状态</p>
          </div>
        </div>
        <div className="module-grid">
          {ENGINES.map((engine, i) => (
            <article className="module animate-entrance" key={engine.name} style={{ animationDelay: `${i * 60 + 200}ms`, gridTemplateColumns: '38px 1fr auto' }}>
              <span className={`module-icon ${engine.builtin ? 'green' : 'blue'}`}>
                <Cpu size={19} />
              </span>
              <div>
                <h3>{engine.name}</h3>
                <p>{engine.vendor} · {engine.license} · 规则: {engine.rule_format}</p>
                {/* 能力标签与规则源标签：裸色改 token（审计 #8a）。
                    两类标签靠底色**色相**区分（绿=能力范围 / 青蓝=规则源），文字统一用
                    --sentinel-text-2。刻意不用 accent/cyan 作文字色：实测 9px 字号下
                    亮色主题只有 3.0:1 / 3.85:1（FAIL），而 text-2 在 12% 色染底上
                    暗色 7.14–7.52:1、亮色 6.64–6.74:1，两套主题都稳过。
                    旧值是深绿/深青实底 + 亮字，不跟随主题——亮色下会在白页面上
                    留下两块深色标签。字号 9px 属审计 #20 范围，本轮不动。 */}
                <div style={{ display: 'flex', gap: 4, marginTop: 4, flexWrap: 'wrap' }}>
                  {engine.scopes.map((s) => (
                    <span key={s} style={{ fontSize: 9, padding: '2px 5px', borderRadius: 'var(--sentinel-radius-sm)', background: 'color-mix(in srgb, var(--sentinel-accent) 12%, transparent)', color: 'var(--sentinel-text-2)' }}>
                      {SCOPE_LABELS[s] ?? s}
                    </span>
                  ))}
                  {engine.rule_update_url ? (
                    <span style={{ fontSize: 9, padding: '2px 5px', borderRadius: 'var(--sentinel-radius-sm)', background: 'color-mix(in srgb, var(--sentinel-cyan) 12%, transparent)', color: 'var(--sentinel-text-2)' }}>
                      规则源: {engine.rule_update_url}
                    </span>
                  ) : null}
                </div>
              </div>
              <span className={`status ${engine.builtin ? 'green' : 'blue'}`}>
                {engine.builtin
                  ? <><Check size={13} /> {engine.version.startsWith('v') || /^\d/.test(engine.version) ? `v${engine.version}` : engine.version}</>
                  : <>{engine.requires_token ? '需 Token' : '待集成'}</>}
              </span>
            </article>
          ))}
        </div>
      </div>

      {/* Rule Update Pipeline — 概念流程说明 + 诚实的遥测未接入空态 */}
      <div className="panel animate-entrance animate-entrance-4">
        <div className="panel-head">
          <div>
            <h2>规则更新管道</h2>
            <p>规则更新的门禁流程（设计说明）：隔离区 → 许可证 → 哈希 → 结构 → 回归 → 发布</p>
          </div>
          <Badge variant="outline">
            <span className={telemetry?.connected ? 'live-dot' : 'demo-dot'} />
            {telemetry?.connected ? '遥测已接入' : '遥测未接入'}
          </Badge>
        </div>

        {/* Gate visualization — conceptual pipeline design, not live data */}
        {/* 审计 #23：流程箭头此前是一个极暗的旧绿裸值，实测对比 2.45:1（面板底上仅
            2.32:1），承担"门禁顺序"语义却几乎不可见 → 改 var(--sentinel-text-3)，
            暗色 5.03:1 / 亮色 4.72–5.04:1，两套主题均 PASS。

            两颗芯片此前各自内联 3 个旧绿裸值（背景 / 边框 / 文字），现改用设计系统的
            .pass 芯片类。这是对审计建议写法的刻意偏差：审计建议内联 color-mix 取
            --sentinel-accent 的 12%/32% 透明度，但该配方只在暗色成立——亮色主题下
            accent 是较深的绿，12% 混白后文字对比仅 3.0:1，10px 字号 FAIL（阈值 4.5:1）。
            而 .pass 已内置亮色 override，实测亮色 4.78:1 / 暗色 8.6:1，两套主题都达标，
            且顺带消掉 6 个裸值与两份重复的内联排版声明。

            注：本注释刻意不写出被删掉的旧色号，否则后续按色号做的 grep 门禁会命中注释
            文本、产生假阳性（本批次已实际踩到一次）。完整色号与对比度计算见实施报告。 */}
        <div style={{ display: 'flex', gap: 6, marginBottom: 18, flexWrap: 'wrap' }}>
          {GATES.map((gate, i) => (
            <div key={gate} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <span className="pass">
                {i + 1}. {gate}
              </span>
              {i < GATES.length - 1 && <span style={{ color: 'var(--sentinel-text-3)', fontSize: 12 }}>→</span>}
            </div>
          ))}
          <span style={{ color: 'var(--sentinel-text-3)', fontSize: 12 }}>→</span>
          {/* 终态芯片保留 fontWeight:700 与 inline-flex（对齐 <Check> 图标），
              其余全部由 .pass 提供。P0-1：勾号用 lucide <Check>，不用 U+2713 字符。 */}
          <span className="pass" style={{ fontWeight: 700, display: 'inline-flex', alignItems: 'center', gap: 4 }}>
            <Check size={12} />
            发布到客户端
          </span>
        </div>

        {/* 真实管道活动（策略发布/基线同步/企业 MD 发布）；无活动时诚实空态，绝不伪造 */}
        {telemetry?.connected && telemetry.events.length > 0 ? (
          <table className="sentinel-table">
            <thead>
              <tr>
                <th>管道</th>
                <th>门禁阶段</th>
                <th>结果</th>
                <th>耗时</th>
                <th>操作人</th>
                <th>时间</th>
              </tr>
            </thead>
            <tbody>
              {telemetry.events.map((ev, i) => (
                <tr key={`${ev.ts}-${i}`}>
                  <td style={{ fontSize: 12 }}>
                    {PIPELINE_LABEL[ev.pipeline] ?? ev.pipeline}
                    <div style={{ fontSize: 10, color: 'var(--muted-foreground)' }}>{ev.detail}</div>
                  </td>
                  <td>
                    <span style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                      {ev.stages.map((s) => (
                        <span
                          key={s.name}
                          title={s.detail ?? ''}
                          style={{
                            fontSize: 9,
                            padding: '2px 6px',
                            borderRadius: 4,
                            background: s.ok ? 'color-mix(in srgb, var(--sentinel-accent) 12%, transparent)' : 'color-mix(in srgb, var(--sentinel-danger) 12%, transparent)',
                            color: s.ok ? 'var(--sentinel-accent)' : 'var(--sentinel-danger)',
                            display: 'inline-flex',
                            alignItems: 'center',
                            gap: 4,
                          }}
                        >
                          {/* P0-1：勾/叉改用 lucide <Check>/<X>，不用 U+2713 / U+2717 字符作功能图标 */}
                          {s.ok ? <Check size={10} /> : <X size={10} />}
                          {s.name}
                        </span>
                      ))}
                    </span>
                  </td>
                  <td>
                    <i className={ev.ok ? 'pass' : 'fail'} style={{ fontSize: 10 }}>{ev.ok ? '成功' : '失败'}</i>
                  </td>
                  <td style={{ fontFamily: 'var(--sentinel-font-mono)', fontSize: 11 }}>{ev.latency_ms}ms</td>
                  <td style={{ fontSize: 11 }}>{ev.actor}</td>
                  <td style={{ fontSize: 11, color: 'var(--muted-foreground)' }}>
                    {new Date(ev.ts * 1000).toLocaleString('zh-CN', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' })}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <div className="empty-detail">
            <Inbox size={32} />
            <h2>{telemetry?.connected ? '暂无管道活动' : '管道遥测未接入'}</h2>
            <p>
              {telemetry?.connected
                ? '尚未发生策略发布 / 基线同步 / 企业 MD 发布；发生后此处呈现真实门禁流水。'
                : '规则更新管道尚未接入后端遥测（或未配置持久化）。此处不展示任何虚构的管道活动样例。'}
            </p>
          </div>
        )}
      </div>
    </>
  );
}
