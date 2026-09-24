'use client';

import { Check, Cpu, Inbox, RefreshCw, Zap } from 'lucide-react';
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

export default function EnginesPage() {
  const builtinCount = ENGINES.filter((e) => e.builtin).length;
  const pendingCount = ENGINES.filter((e) => !e.builtin).length;

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
                <div style={{ display: 'flex', gap: 4, marginTop: 4, flexWrap: 'wrap' }}>
                  {engine.scopes.map((s) => (
                    <span key={s} style={{ fontSize: 9, padding: '2px 5px', borderRadius: 4, background: '#143329', color: '#6cebb7' }}>
                      {SCOPE_LABELS[s] ?? s}
                    </span>
                  ))}
                  {engine.rule_update_url ? (
                    <span style={{ fontSize: 9, padding: '2px 5px', borderRadius: 4, background: '#12262a', color: '#7fb8c9' }}>
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
            <span className="demo-dot" />
            遥测未接入
          </Badge>
        </div>

        {/* Gate visualization — conceptual pipeline design, not live data */}
        <div style={{ display: 'flex', gap: 6, marginBottom: 18, flexWrap: 'wrap' }}>
          {GATES.map((gate, i) => (
            <div key={gate} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <span style={{ fontSize: 10, padding: '4px 10px', borderRadius: 6, background: '#143329', border: '1px solid #24503f', color: '#6cebb7' }}>
                {i + 1}. {gate}
              </span>
              {i < GATES.length - 1 && <span style={{ color: '#37594e', fontSize: 12 }}>→</span>}
            </div>
          ))}
          <span style={{ color: '#37594e', fontSize: 12 }}>→</span>
          <span style={{ fontSize: 10, padding: '4px 10px', borderRadius: 6, background: '#1a3d30', border: '1px solid #49e8a5', color: '#49e8a5', fontWeight: 700 }}>
            ✓ 发布到客户端
          </span>
        </div>

        {/* Honest empty state — no fabricated pipeline activity (red line: 绝不伪造数据) */}
        <div className="empty-detail" style={{ minHeight: 140 }}>
          <Inbox size={32} />
          <h2>管道遥测未接入</h2>
          <p>
            规则更新管道尚未接入后端遥测。
            <br />
            此处不展示任何虚构的管道活动样例；接入真实遥测后，会呈现真实的隔离→发布流水与规则集版本。
          </p>
        </div>
      </div>
    </>
  );
}
