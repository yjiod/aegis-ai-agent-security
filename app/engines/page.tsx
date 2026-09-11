'use client';

import { useState } from 'react';
import {
  AlertTriangle, Check, CircleDot, Cpu, Download, Lock,
  RefreshCw, ShieldCheck, X, Zap,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';

/* ─── Engine Data (mirrors aegis_engine_framework.py) ───── */

interface Engine {
  name: string; version: string; vendor: string; license: string;
  mode: 'local' | 'cloud' | 'hybrid'; scopes: string[];
  available: boolean; rule_format: string; requires_token?: boolean;
}

const ENGINES: Engine[] = [
  { name: 'aegis-regex', version: '1.0.0', vendor: 'Aegis', license: 'Proprietary', mode: 'local', scopes: ['skill', 'mcp', 'code', 'secrets'], available: true, rule_format: 'regex' },
  { name: 'semgrep', version: '1.89.0', vendor: 'Semgrep Inc.', license: 'LGPL-2.1', mode: 'local', scopes: ['code', 'secrets'], available: true, rule_format: 'yaml' },
  { name: 'gitleaks', version: '8.21.2', vendor: 'Gitleaks', license: 'MIT', mode: 'local', scopes: ['secrets'], available: true, rule_format: 'toml' },
  { name: 'cisco-skill-scanner', version: 'pending', vendor: 'Cisco', license: 'Apache-2.0', mode: 'local', scopes: ['skill', 'mcp'], available: false, rule_format: 'json' },
  { name: 'snyk-agent-scan', version: 'pending', vendor: 'Snyk', license: 'Commercial', mode: 'cloud', scopes: ['skill', 'mcp', 'deps'], available: false, rule_format: 'cloud-api', requires_token: true },
];

const SCOPE_LABELS: Record<string, string> = {
  skill: 'Skill 扫描', mcp: 'MCP 扫描', code: '代码 SAST', secrets: '密钥检测', deps: '依赖 SCA',
};

interface PipelineStage {
  id: string; engine: string; rule_version: string; status: 'quarantine' | 'license' | 'hash' | 'structure' | 'regression' | 'published' | 'rejected';
  fetched_at: string; source: string;
}

const PIPELINE: PipelineStage[] = [
  { id: 'semgrep-1789100000-a3f2', engine: 'semgrep', rule_version: 'p/default 2026-09-05', status: 'published', fetched_at: '2026-09-05 14:30', source: 'semgrep.dev/c/p/default' },
  { id: 'gitleaks-1789090000-b7c1', engine: 'gitleaks', rule_version: 'v8.21.2 builtin', status: 'published', fetched_at: '2026-09-04 09:15', source: 'github.com/gitleaks/gitleaks' },
  { id: 'semgrep-1789142000-c9d4', engine: 'semgrep', rule_version: 'p/ai-agent-security 2026-09-06', status: 'regression', fetched_at: '2026-09-06 11:42', source: 'semgrep.dev/c/p/ai-agent' },
  { id: 'cisco-1789145000-e2f8', engine: 'cisco-skill-scanner', rule_version: 'skill-rules-3.2.1', status: 'quarantine', fetched_at: '2026-09-06 12:30', source: '内部规则仓库' },
];

const STATUS_CONFIG: Record<string, { label: string; color: string; icon: typeof Check }> = {
  published: { label: '已发布', color: '#49e8a5', icon: Check },
  regression: { label: '回归测试中', color: '#64bae7', icon: RefreshCw },
  quarantine: { label: '隔离区', color: '#e8b449', icon: Lock },
  rejected: { label: '已拒绝', color: '#ff685f', icon: X },
  license: { label: '许可证审查', color: '#e8b449', icon: Lock },
  hash: { label: '哈希校验', color: '#e8b449', icon: ShieldCheck },
  structure: { label: '结构验证', color: '#e8b449', icon: Cpu },
};

const GATES = ['许可证兼容', 'SHA-256 哈希', '结构验证', '回归测试'];

export default function EnginesPage() {
  const [toast, setToast] = useState('');

  function notify(msg: string) { setToast(msg); setTimeout(() => setToast(''), 3500); }

  const availableCount = ENGINES.filter((e) => e.available).length;

  return (
    <>
      <div className="demo-notice" role="note">
        <AlertTriangle size={16} />
        <span><strong>引擎管理</strong> 多引擎独立运行，规则语法不互转。动态更新经隔离区→四道门禁→发布管道。</span>
      </div>

      <div className="page-head animate-entrance animate-entrance-1">
        <div>
          <p className="eyebrow">安全能力 / 扫描引擎</p>
          <h1>多引擎扫描管理</h1>
          <p>Cisco skill-scanner · Snyk agent-scan · Semgrep · Gitleaks — 各自独立规则源。</p>
        </div>
        <div className="head-actions">
          <Button variant="outline" onClick={() => notify('演示模式：引擎同步 API 尚未连接。')}>
            <RefreshCw size={16} /> 同步规则库
          </Button>
          <Button onClick={() => notify('演示模式：全量扫描需连接终端 Agent。')}>
            <Zap size={16} /> 全量扫描
          </Button>
        </div>
      </div>

      {toast && <div className="toast" role="status"><CircleDot size={16} />{toast}</div>}

      {/* KPIs */}
      <div className="detail-kpis animate-entrance animate-entrance-2">
        <article><strong>{availableCount}/{ENGINES.length}</strong><span>引擎可用</span></article>
        <article><strong>{PIPELINE.filter(p => p.status === 'published').length}</strong><span>已发布规则集</span></article>
        <article><strong>{PIPELINE.filter(p => p.status === 'quarantine' || p.status === 'regression').length}</strong><span>管道中待审</span></article>
      </div>

      {/* Engine Grid */}
      <div className="panel animate-entrance animate-entrance-3" style={{ marginBottom: 14 }}>
        <div className="panel-head">
          <div><h2>已注册引擎</h2><p>每个引擎保持原生规则语法，不强行转换</p></div>
        </div>
        <div className="module-grid">
          {ENGINES.map((engine, i) => (
            <article className="module animate-entrance" key={engine.name} style={{ animationDelay: `${i * 60 + 200}ms`, gridTemplateColumns: '38px 1fr auto' }}>
              <span className={`module-icon ${engine.available ? 'green' : 'blue'}`}>
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
                </div>
              </div>
              <span className={`status ${engine.available ? 'green' : 'blue'}`}>
                {engine.available ? <><Check size={13} /> v{engine.version}</> : <>{engine.requires_token ? '需 Token' : '待集成'}</>}
              </span>
            </article>
          ))}
        </div>
      </div>

      {/* Rule Update Pipeline */}
      <div className="panel animate-entrance animate-entrance-4">
        <div className="panel-head">
          <div><h2>规则更新管道</h2><p>隔离区 → 许可证 → 哈希 → 结构 → 回归 → 发布</p></div>
          <Badge variant="outline"><Download size={13} /> 自动同步</Badge>
        </div>

        {/* Gate visualization */}
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

        {/* Pipeline entries */}
        <div className="data-table">
          <div className="data-head" style={{ gridTemplateColumns: '1.2fr 1fr 0.8fr 0.8fr' }}>
            <span>规则集</span><span>来源</span><span>状态</span><span>时间</span>
          </div>
          {PIPELINE.map((entry, i) => {
            const cfg = STATUS_CONFIG[entry.status] ?? STATUS_CONFIG.quarantine;
            const Icon = cfg.icon;
            return (
              <div className="data-row animate-row-entrance" key={entry.id} style={{ gridTemplateColumns: '1.2fr 1fr 0.8fr 0.8fr', animationDelay: `${i * 30 + 300}ms` }}>
                <strong>{entry.engine} / {entry.rule_version}</strong>
                <span style={{ fontSize: 11 }}>{entry.source}</span>
                <span style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: 11, color: cfg.color }}>
                  <Icon size={12} /> {cfg.label}
                </span>
                <span style={{ fontSize: 10, color: '#5e7c73' }}>{entry.fetched_at}</span>
              </div>
            );
          })}
        </div>
      </div>
    </>
  );
}
