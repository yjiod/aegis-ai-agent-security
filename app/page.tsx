'use client';
import { useEffect, useState } from 'react';
import {
  Activity,
  AlertTriangle,
  Bot,
  Check,
  ChevronDown,
  CircleDot,
  Code2,
  Laptop,
  LockKeyhole,
  Network,
  Play,
  Search,
  Settings,
  ShieldCheck,
  SlidersHorizontal,
  Sparkles,
  Users,
  Wrench,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';

const modules = [
  {
    icon: ShieldCheck,
    title: '安全编码基线',
    desc: '企业规则基线 · 已验证发行',
    status: '已打包',
    tone: 'green',
  },
  {
    icon: Sparkles,
    title: 'Skill 扫描器',
    desc: '权限、指令与依赖',
    status: '已打包',
    tone: 'blue',
  },
  {
    icon: Network,
    title: 'MCP 扫描器',
    desc: '工具、密钥与外联',
    status: '已启用',
    tone: 'green',
  },
  {
    icon: Code2,
    title: '代码质量扫描',
    desc: 'SAST、依赖与密钥',
    status: '已启用',
    tone: 'green',
  },
];
const viewNames = {
  onboarding: '接入中心',
  devices: '设备与 Agent',
  risks: '风险中心',
  baseline: '安全编码规范基线',
  skills: 'Skill 扫描器',
  mcp: 'MCP 扫描器',
  quality: '代码质量扫描',
  policies: '策略配置',
  team: '团队与权限',
  settings: '系统设置',
} as const;
type DetailKey = keyof typeof viewNames;
type FleetSummary = {
  total_devices: number;
  active_devices: number;
  stale_devices: number;
  required_agent_version: string;
  required_policy_version: string;
  latest_severity: { critical: number; high: number; normal: number };
  version_posture: {
    current: number;
    agent_mismatch: number;
    policy_mismatch: number;
    both_mismatch: number;
    unknown: number;
  };
  credential_posture?: { current: number; previous: number; legacy: number };
  agent_coverage: Record<'cursor'|'claude_code'|'codex'|'windsurf'|'gemini_cli'|'github_copilot_cli'|'workbuddy'|'qwen_enterprise'|'tongyi_lingma'|'codebuddy',{total:number;active:number}>;
  baseline_coverage: Record<'claude_code'|'codex'|'gemini_cli'|'github_copilot_cli',{total:number;managed:number}>;
  service_health_posture: { healthy:number; degraded:number; invalid:number; missing:number };
  policy_trust_posture: { current:number; overlap:number; legacy:number; unrecognized:number };
  active_policy_key_id: string;
};
type FleetDevice = { device_id:string; last_seen:number; report_count:number; credential_generation:'current'|'previous'|'legacy'; severity:'normal'|'high'|'critical'; agent_version:string; policy_version:string; service_health_status:'healthy'|'degraded'|'invalid'|'missing' };
type DeviceHealthFilter = 'all'|'action_required'|FleetDevice['service_health_status'];
type RemediationRecommendation = { recommendation_id:string; device_id:string; reason:'risk_critical'|'risk_high'|'service_health_invalid'|'service_health_degraded'|'service_health_missing'|'version_drift'; recommended_action:'containment_pending_approval'|'access_review_pending'|'verify_integrity'|'repair_service'|'upgrade_client'; approval_state:'external_approval_required'; severity:'high'|'critical'; observed_at:number; correlation_id:string; workflow_state:'pending'|'approved'|'rejected'|'executing'|'succeeded'|'failed'; receipt_updated_at:number };
type ReleaseMetadata = { release:string; component_versions:{endpoint_agent:string;policy:string;collector:string;adapter:string} };

export default function Home() {
  const [toast, setToast] = useState('');
  const [detail, setDetail] = useState<DetailKey | null>(null);
  const [fleet, setFleet] = useState<FleetSummary | null>(null);
  const [fleetDevices, setFleetDevices] = useState<FleetDevice[] | null>(null);
  const [recommendations,setRecommendations]=useState<RemediationRecommendation[] | null>(null);
  const [releaseMetadata, setReleaseMetadata] = useState<ReleaseMetadata | null>(null);
  const [collectorState, setCollectorState] = useState<'checking' | 'live' | 'unavailable'>('checking');
  function runScan() {
    setToast('扫描任务下发接口尚未启用；请通过已签名终端部署包执行周期扫描。');
  }
  useEffect(() => {
    const controller = new AbortController();
    fetch('/api/summary', { cache: 'no-store', signal: controller.signal })
      .then(async (response) => {
        if (!response.ok) throw new Error('collector unavailable');
        const value = (await response.json()) as { connected?: boolean; summary?: FleetSummary };
        if (!value.connected || !value.summary) throw new Error('collector disconnected');
        setFleet(value.summary); setCollectorState('live');
      })
      .catch((error: unknown) => {
        if ((error as { name?: string })?.name !== 'AbortError') setCollectorState('unavailable');
      });
    fetch('/api/devices', { cache: 'no-store', signal: controller.signal })
      .then(async (response) => {
        if (!response.ok) throw new Error('collector unavailable');
        const value=(await response.json()) as {connected?:boolean;devices?:FleetDevice[]};
        if (!value.connected || !Array.isArray(value.devices)) throw new Error('collector disconnected');
        setFleetDevices(value.devices);
      }).catch(() => setFleetDevices(null));
    fetch('/api/recommendations',{cache:'no-store',signal:controller.signal}).then(async(response)=>{if(!response.ok)throw new Error('collector unavailable');const value=(await response.json()) as {connected?:boolean;recommendations?:RemediationRecommendation[]};if(!value.connected||!Array.isArray(value.recommendations))throw new Error('collector disconnected');setRecommendations(value.recommendations)}).catch(()=>setRecommendations(null));
    fetch('/downloads/release.json', { cache: 'no-store', signal: controller.signal })
      .then(async (response) => {
        if (!response.ok) throw new Error('release unavailable');
        const value=(await response.json()) as Partial<ReleaseMetadata>; const versions=value.component_versions;
        const semver=/^\d+\.\d+\.\d+$/; const component=/^\d+\.\d+(?:\.\d+)?$/;
        if (!semver.test(value.release ?? '') || !versions || Object.keys(versions).length!==4 || !component.test(versions.endpoint_agent) || !component.test(versions.policy) || !component.test(versions.collector) || !component.test(versions.adapter)) throw new Error('release invalid');
        setReleaseMetadata(value as ReleaseMetadata);
      }).catch(() => setReleaseMetadata(null));
    return () => controller.abort();
  }, []);
  const totalDevices=fleet?.total_devices ?? 0; const activeDevices=fleet?.active_devices ?? 0; const staleDevices=fleet?.stale_devices ?? 0;
  const currentDevices=fleet?.version_posture.current ?? 0; const coverage=totalDevices ? (currentDevices/totalDevices)*100 : 0;
  const highRiskDevices=fleet ? fleet.latest_severity.critical+fleet.latest_severity.high : 0; const driftDevices=fleet ? totalDevices-currentDevices : 0;
  const agentCoverage: [string,number,number,number|null,number|null][] = fleet ? [
    ['Cursor',fleet.agent_coverage.cursor.total,fleet.agent_coverage.cursor.active,null,null],['Claude Code',fleet.agent_coverage.claude_code.total,fleet.agent_coverage.claude_code.active,fleet.baseline_coverage.claude_code.managed,fleet.baseline_coverage.claude_code.total],['Codex CLI',fleet.agent_coverage.codex.total,fleet.agent_coverage.codex.active,fleet.baseline_coverage.codex.managed,fleet.baseline_coverage.codex.total],['Windsurf',fleet.agent_coverage.windsurf.total,fleet.agent_coverage.windsurf.active,null,null],['Gemini CLI',fleet.agent_coverage.gemini_cli.total,fleet.agent_coverage.gemini_cli.active,fleet.baseline_coverage.gemini_cli.managed,fleet.baseline_coverage.gemini_cli.total],['GitHub Copilot CLI',fleet.agent_coverage.github_copilot_cli.total,fleet.agent_coverage.github_copilot_cli.active,fleet.baseline_coverage.github_copilot_cli.managed,fleet.baseline_coverage.github_copilot_cli.total],['WorkBuddy',fleet.agent_coverage.workbuddy.total,fleet.agent_coverage.workbuddy.active,null,null],['千问企业版',fleet.agent_coverage.qwen_enterprise.total,fleet.agent_coverage.qwen_enterprise.active,null,null],['通义灵码',fleet.agent_coverage.tongyi_lingma.total,fleet.agent_coverage.tongyi_lingma.active,null,null],['CodeBuddy',fleet.agent_coverage.codebuddy.total,fleet.agent_coverage.codebuddy.active,null,null],
  ] : [['Cursor',0,0,null,null],['Claude Code',0,0,0,0],['Codex CLI',0,0,0,0],['Windsurf',0,0,null,null],['Gemini CLI',0,0,0,0],['GitHub Copilot CLI',0,0,0,0],['WorkBuddy',0,0,null,null],['千问企业版',0,0,null,null],['通义灵码',0,0,null,null],['CodeBuddy',0,0,null,null]];
  return (
    <main className="min-h-screen bg-[#07110f] text-[#eaf7f2]">
      <header className="topbar">
        <div className="brand">
          <span className="brandmark">
            <ShieldCheck size={19} />
          </span>
          <span>
            Sentinel<span className="brand-muted"> / Agent Security</span>
          </span>
        </div>
        <div className="header-actions">
          <span className="system-ok">
            <span className={collectorState === 'live' ? 'live-dot' : 'demo-dot'} />
            {collectorState === 'live' ? '生产 Collector 已连接' : collectorState === 'checking' ? '正在检查生产链路' : '生产 Collector 暂不可用'}
          </span>
          <button className="icon-btn" aria-label="搜索">
            <Search size={18} />
          </button>
          <button className="avatar" aria-label="账户菜单">
            SL
          </button>
        </div>
      </header>
      <div className="shell">
        <aside className="sidebar">
          <nav aria-label="主导航">
            <p className="nav-label">控制台</p>
            <button className="nav-item active" onClick={() => setDetail(null)}>
              <Activity size={18} />
              总览
            </button>
            <Nav
              icon={Bot}
              label="接入中心"
              target="onboarding"
              open={setDetail}
            />
            <Nav
              icon={Laptop}
              label="设备与 Agent"
              target="devices"
              open={setDetail}
              count={fleet ? String(fleet.total_devices) : undefined}
            />
            <Nav
              icon={AlertTriangle}
              label="风险中心"
              target="risks"
              open={setDetail}
              alert={fleet && highRiskDevices ? String(highRiskDevices) : undefined}
            />
            <p className="nav-label section-gap">安全能力</p>
            <Nav
              icon={Code2}
              label="编码规范基线"
              target="baseline"
              open={setDetail}
            />
            <Nav
              icon={Sparkles}
              label="Skill 扫描器"
              target="skills"
              open={setDetail}
            />
            <Nav
              icon={Network}
              label="MCP 扫描器"
              target="mcp"
              open={setDetail}
            />
            <Nav
              icon={Wrench}
              label="代码质量"
              target="quality"
              open={setDetail}
            />
            <p className="nav-label section-gap">管理</p>
            <Nav
              icon={SlidersHorizontal}
              label="策略配置"
              target="policies"
              open={setDetail}
            />
            <Nav
              icon={Users}
              label="团队与权限"
              target="team"
              open={setDetail}
            />
            <Nav
              icon={Settings}
              label="系统设置"
              target="settings"
              open={setDetail}
            />
          </nav>
          <div className="side-foot">
            <LockKeyhole size={16} />
            <div>
              <strong>企业安全策略</strong>
              <small>{collectorState === 'live' ? '真实数据 · 只读' : '连接状态异常'}</small>
            </div>
            <Check size={16} />
          </div>
        </aside>
        <section className="workspace" id="overview">
          <div className="demo-notice" role="note"><ShieldCheck size={16} /><span><strong>生产只读模式</strong>{fleet ? ` 指标来自生产 Collector；终端明细${fleetDevices ? '已连接' : '暂不可用'}。未接入的数据保持为空，不使用样例回退。` : ' Collector 当前不可用，所有运营指标保持为空；控制台不会用样例数据替代真实状态。'}</span></div>
          <div className="page-head">
            <div>
              <p className="eyebrow">安全态势 / 生产只读</p>
              <h1>AI Agent 安全总览</h1>
              <p>统一发现、校验并约束员工终端上的 AI Agent 行为。</p>
            </div>
            <div className="head-actions">
              <Button variant="outline">
                <ChevronDown />
                过去 24 小时
              </Button>
              <Button onClick={runScan}>
                <Play fill="currentColor" />
                扫描下发未接入
              </Button>
            </div>
          </div>
          {toast && (
            <div className="toast" role="status">
              <CircleDot size={16} />
              {toast}
            </div>
          )}
          <div className="metrics">
            <article className="metric">
              <div className="metric-top">
                <span>已纳管设备</span>
                <Laptop size={18} />
              </div>
              <strong>{totalDevices}</strong>
              <p>
                <em>{activeDevices}</em> 活跃 · {staleDevices} 过期
              </p>
            </article>
            <article className="metric">
              <div className="metric-top">
                <span>当前版本覆盖率</span>
                <Bot size={18} />
              </div>
              <strong>
                {coverage.toFixed(1)}<small>%</small>
              </strong>
              <Progress value={coverage} />
              <p>
                当前版本设备 <em>{currentDevices}</em> 台
              </p>
            </article>
            <article className="metric danger">
              <div className="metric-top">
                <span>高风险设备</span>
                <AlertTriangle size={18} />
              </div>
              <strong>{highRiskDevices}</strong>
              <p>
                <i>{fleet?.latest_severity.critical ?? 0} 严重</i> · {fleet?.latest_severity.high ?? 0} 高危
              </p>
            </article>
            <article className="metric">
              <div className="metric-top">
                <span>版本漂移设备</span>
                <ShieldCheck size={18} />
              </div>
              <strong>{driftDevices}</strong>
              <p>
                Agent 或策略版本不一致
              </p>
            </article>
          </div>
          <div className="content-grid">
            <section className="panel capabilities">
              <div className="panel-head">
                <div>
                  <h2>防护能力</h2>
                  <p>自动随企业 Agent 加载并持续更新</p>
                </div>
                <Badge variant="outline">
                  <span className="live-dot" />
                  发行包可用
                </Badge>
              </div>
              <div className="module-grid">
                {modules.map(({ icon: Icon, title, desc, status, tone }) => (
                  <article className="module" key={title}>
                    <span className={`module-icon ${tone}`}>
                      <Icon size={19} />
                    </span>
                    <div>
                      <h3>{title}</h3>
                      <p>{desc}</p>
                    </div>
                    <span className={`status ${tone}`}>
                      <Check size={13} />
                      {status}
                    </span>
                  </article>
                ))}
              </div>
              <div className="flow">
                <span>员工安装 AI Agent</span>
                <b>→</b>
                <span>安全 Agent 静默加载</span>
                <b>→</b>
                <span>策略校验 + 持续扫描</span>
                <b>→</b>
                <span className="safe">
                  <ShieldCheck size={15} />
                  安全放行
                </span>
              </div>
            </section>
            <section className="panel coverage">
              <div className="panel-head">
                <div>
                  <h2>终端覆盖</h2>
                  <p>按 Agent 工具</p>
                </div>
                <button>查看全部</button>
              </div>
              {agentCoverage.map(([name, total, online, managed, baselineTotal]) => (
                <div className="coverage-row" key={String(name)}>
                  <div className="tool-logo">{String(name).slice(0, 1)}</div>
                  <div className="coverage-data">
                    <div>
                      <strong>{name}</strong>
                      <span>
                        {online}/{total} 在线{managed===null?'':` · ${managed}/${baselineTotal} 基线受管`}
                      </span>
                    </div>
                    <Progress value={total ? (online / total) * 100 : 0} />
                  </div>
                </div>
              ))}
            </section>
            <section className="panel risks" id="risks">
              <div className="panel-head">
                <div>
                  <h2>风险事件</h2>
                  <p>事件明细接口待接入</p>
                </div>
                <button>进入风险中心 →</button>
              </div>
              <div className="empty-detail"><ShieldCheck size={32}/><h3>暂无真实事件明细</h3><p>汇总风险数量来自生产 Collector；事件内容不会使用样例填充。</p></div>
            </section>
            <section className="panel score">
              <div className="panel-head">
                <div>
                  <h2>安全评分</h2>
                  <p>评分接口待接入</p>
                </div>
              </div>
              <div className="score-body">
                <div className="score-ring">
                  <strong>—</strong>
                  <span>/ 100</span>
                </div>
                <div className="score-list">
                  <p>
                    <span>配置合规</span>
                    <b>—</b>
                  </p>
                  <p>
                    <span>Agent 行为</span>
                    <b>—</b>
                  </p>
                  <p>
                    <span>代码安全</span>
                    <b>—</b>
                  </p>
                </div>
              </div>
            </section>
          </div>
        </section>
      </div>
      {detail && (
        <DetailPanel
          view={detail}
          close={() => setDetail(null)}
          notify={setToast}
          fleet={fleet}
          fleetDevices={fleetDevices}
          recommendations={recommendations}
          releaseMetadata={releaseMetadata}
        />
      )}
    </main>
  );
}

function Nav({
  icon: Icon,
  label,
  target,
  open,
  count,
  alert,
}: {
  icon: typeof Activity;
  label: string;
  target: DetailKey;
  open: (v: DetailKey) => void;
  count?: string;
  alert?: string;
}) {
  return (
    <button className="nav-item" onClick={() => open(target)}>
      <Icon size={18} />
      {label}
      {count && <span>{count}</span>}
      {alert && <b>{alert}</b>}
    </button>
  );
}

function DetailPanel({
  view,
  close,
  notify,
  fleet,
  fleetDevices,
  recommendations,
  releaseMetadata,
}: {
  view: DetailKey;
  close: () => void;
  notify: (s: string) => void;
  fleet: FleetSummary | null;
  fleetDevices: FleetDevice[] | null;
  recommendations: RemediationRecommendation[] | null;
  releaseMetadata: ReleaseMetadata | null;
}) {
  const scanner = view === 'skills' || view === 'mcp' || view === 'quality';
  const [deviceHealthFilter,setDeviceHealthFilter]=useState<DeviceHealthFilter>('all');
  const visibleDevices=(fleetDevices ?? []).filter((device)=>deviceHealthFilter==='all' || deviceHealthFilter==='action_required' ? deviceHealthFilter==='all' || device.service_health_status!=='healthy' : device.service_health_status===deviceHealthFilter);
  return (
    <div
      className="detail-overlay"
      role="dialog"
      aria-modal="true"
      aria-label={viewNames[view]}
    >
      <button className="overlay-bg" aria-label="关闭" onClick={close} />
      <section className="detail-panel">
        <div className="detail-title">
          <div>
            <p className="eyebrow">治理工作台</p>
            <h1>{viewNames[view]}</h1>
          </div>
          <button className="close-btn" onClick={close}>
            ×
          </button>
        </div>
        <div className="demo-notice" role="note"><ShieldCheck size={16} /><span><strong>生产数据边界</strong> 已接入的 Collector 数据会实时显示；未接入的明细、评分和写操作保持为空或禁用。</span></div>
        {view === 'onboarding' && (
          <>
            <div className="baseline-banner">
              <div>
                <h2>Sentinel Endpoint Agent {releaseMetadata?.component_versions.endpoint_agent ?? '0.49.0'}</h2>
                <p>厂商无关部署 · 企业 4A 标准接口 · 可插拔兼容适配器</p>
              </div>
              <strong>可验证<span>本地执行</span></strong>
            </div>
            <div className="panel inset onboarding">
              <h2>企业部署编排</h2>
              <div className="control-planes">
                <article><b>终端部署层</b><span>负责推送 Sentinel</span><p>MDM、桌管或软件分发负责首次安装、二进制升级、回滚和卸载。</p></article>
                <article><b>企业 4A</b><span>标准主接口</span><p>以最小安全事件对接账号、认证、授权和审计平台，影响访问的动作必须经外部审批。</p></article>
                <article><b>Sentinel 内容层</b><span>只管理自身内容</span><p>拉取签名策略、规则、恶意 Skill/MCP 情报和 AI Coding 基线，不安装其他控制客户端。</p></article>
              </div>
              <ol><li><b>自动发现</b><span>周期检测 Cursor、Claude Code、Codex、Windsurf、Gemini、Copilot、WorkBuddy、千问企业版、通义灵码与 CodeBuddy。</span></li><li><b>加载基线</b><span>为受管项目增量安装 Agent 规则，并持续扫描 Skill、MCP 与代码。</span></li><li><b>4A 联动</b><span>以匿名设备主体输出标准安全姿态、待审批授权建议和可追踪审计关联号。</span></li></ol>
              <div className="download-actions">
                <a className="download-primary" href="/downloads/sentinel-enterprise-bundle.zip" download>下载完整部署包</a>
                <a className="download-primary" href="https://github.com/yjiod/sentinel-ai-agent-security/releases/download/v5.11.0/Sentinel-Agent-Windows-x64-5.11.0.msi">Windows MSI 5.11.0</a>
                <a className="download-primary" href="https://github.com/yjiod/sentinel-ai-agent-security/releases/download/v5.11.0/Sentinel-Agent-macOS-5.11.0.pkg">macOS PKG 5.11.0</a>
                <a href="https://github.com/yjiod/sentinel-ai-agent-security/releases/download/v5.11.0/SHA256SUMS.txt">安装包 SHA-256</a>
                <a className="download-primary" href="/downloads/DEPLOYMENT-GUIDE.md" download>下载部署指南</a>
                <a className="download-primary" href="/downloads/PRODUCTION-READINESS.md" download>生产就绪清单</a>
                <a className="download-primary" href="/downloads/CLIENT-ARCHITECTURE-ROADMAP.md" download>多端统一客户端规划</a>
                <a href="/downloads/sentinel-client-control-policy.json" download>客户端推送控制策略</a>
                <a href="/downloads/sentinel_client_update_planner.py" download>客户端更新决策引擎</a>
                <a href="/downloads/sentinel-service-health.schema.json" download>统一服务健康协议</a>
                <a href="/downloads/production-acceptance-evidence.example.json" download>生产验收证据模板</a>
                <a href="/downloads/sentinel_production_preflight.py" download>生产最终预检</a>
                <a href="/downloads/sentinel_production_evidence_prepare.py" download>生产验收证据准备器</a>
                <a href="/downloads/sentinel_production_evidence_sign.py" download>生产验收签名工具</a>
                <a href="/downloads/sentinel_production_keyring.py" download>生产验收密钥环工具</a>
                <a href="/downloads/intune-windows-detect.ps1" download>Windows 检测脚本</a>
                <a href="/downloads/intune-windows-remediate.ps1" download>Windows 修复脚本</a>
                <a href="/downloads/intune-macos-install.sh" download>macOS Intune 脚本</a>
                <a href="/downloads/intune-macos-compliance.sh" download>macOS 合规脚本</a>
                <a href="/downloads/sentinel-policy.json" download>策略基线</a>
                <a href="/downloads/sentinel-rule-sources.json" download>动态规则源目录</a>
                <a href="/downloads/sentinel_rule_updater.py" download>规则源隔离同步器</a>
                <a href="/downloads/RULE-UPDATE-GUIDE.md" download>动态规则更新指南</a>
                <a href="/downloads/sentinel_device_credentials.py" download>逐设备凭据工具</a>
                <a href="/downloads/sentinel_collector_probe.py" download>Collector 验收探针</a>
                <a href="/downloads/sentinel-collector.openapi.json" download>Collector API 规范</a>
                <a href="/downloads/sentinel-enterprise-4a.openapi.json" download>企业 4A OpenAPI</a>
                <a href="/downloads/ENTERPRISE-4A-INTEGRATION.md" download>企业 4A 接入指南</a>
                <a href="/downloads/ENTERPRISE-INTEGRATION-CONTRACT.md" download>统一身份 / 4A 能力契约</a>
                <a href="/downloads/sentinel_4a_interface.py" download>厂商中立接口定义</a>
                <a href="/downloads/sentinel-integration-providers.example.json" download>企业能力注册表示例</a>
                <a href="/downloads/sentinel_integration_registry.py" download>企业能力准入校验器</a>
                <a href="/downloads/sentinel_4a_probe.py" download>企业 4A 验收探针</a>
                <a href="/downloads/deployment-platform-evidence.example.json" download>通用部署验收模板</a>
                <a href="/downloads/sentinel_deployment_preflight.py" download>通用部署预检</a>
                <a href="/downloads/sentinel-vendor-contracts.json" download>厂商联动契约</a>
                <a href="/downloads/vendor-acceptance-evidence.example.json" download>厂商验收证据模板</a>
                <a href="/downloads/sentinel_vendor_preflight.py" download>厂商接入预检</a>
                <a href="/downloads/sentinel_vendor_probe.py" download>厂商安全验收探针</a>
                <a href="/downloads/sentinel_vendor_evidence_sign.py" download>厂商验收签名工具</a>
                <a href="/downloads/intune-deployment-manifest.json" download>Intune 部署清单</a>
                <a href="/downloads/sentinel-sign-intune.ps1" download>Windows 企业签名工具</a>
                <a href="/downloads/intune-rollout-evidence.example.json" download>Intune 晋级证据模板</a>
                <a href="/downloads/sentinel_intune_preflight.py" download>Intune 晋级预检</a>
                <a href="/downloads/sentinel_intune_evidence.py" download>Intune 证据生成器</a>
                <a href="/downloads/sentinel_intune_graph_normalize.py" download>Graph 导出归一化器</a>
              </div>
              <p className="safety-note"><LockKeyhole size={15}/>核心能力不依赖特定 MDM、EDR 或桌管。4A 与可选适配器凭据只从受保护运行环境注入，绝不写入部署包。</p>
            </div>
          </>
        )}
        {scanner && (
          <>
            <div className="detail-kpis">
              <article>
                <strong>
                  0
                </strong>
                <span>已扫描对象</span>
              </article>
              <article>
                <strong>
                  0
                </strong>
                <span>待处理发现</span>
              </article>
              <article>
                <strong>—</strong>
                <span>在线终端覆盖</span>
              </article>
            </div>
            <div className="panel inset">
              <div className="panel-head">
                <div>
                  <h2>最近扫描结果</h2>
                  <p>扫描明细 API 待接入</p>
                </div>
                <Button
                  onClick={() => notify('终端会通过受认证 Collector 周期拉取已发布策略；第三方更新先进入隔离区。')}
                >
                  查看同步机制
                </Button>
              </div>
              <div className="empty-detail"><ShieldCheck size={32}/><h3>暂无真实扫描明细</h3><p>终端上报后将在此显示，控制台不会填充样例记录。</p></div>
            </div>
          </>
        )}
        {view === 'devices' && (
          <div className="panel inset">
            <div className="panel-head">
              <div>
                <h2>受管终端</h2>
                <p>{fleet ? `${fleet.total_devices} 台设备 · ${fleet.active_devices} 台在线` : 'Collector 暂不可用'}</p>
                {fleet?.credential_posture && <p>凭据代次：当前 {fleet.credential_posture.current} · 上一代 {fleet.credential_posture.previous} · Legacy {fleet.credential_posture.legacy}</p>}
                {fleet?.service_health_posture && <p>统一宿主：健康 {fleet.service_health_posture.healthy} · 降级 {fleet.service_health_posture.degraded} · 无效 {fleet.service_health_posture.invalid} · 未上报 {fleet.service_health_posture.missing}</p>}
                {fleet?.policy_trust_posture && <p>策略信任：当前密钥 {fleet.policy_trust_posture.current} · 轮换重叠 {fleet.policy_trust_posture.overlap} · 旧版 {fleet.policy_trust_posture.legacy} · 未识别 {fleet.policy_trust_posture.unrecognized} · Key ID {fleet.active_policy_key_id}</p>}
              </div>
              <Button onClick={() => notify('请从接入中心下载已验证发行包；未创建外部任务。')}>
                生成部署包
              </Button>
            </div>
            <div className="device-operations" aria-label="终端健康筛选与处置指引">
              <label>宿主状态
                <select value={deviceHealthFilter} onChange={(event)=>setDeviceHealthFilter(event.target.value as DeviceHealthFilter)}>
                  <option value="all">全部终端</option><option value="action_required">需要关注</option><option value="healthy">健康</option><option value="degraded">降级</option><option value="invalid">无效</option><option value="missing">未上报</option>
                </select>
              </label>
              <p><strong>当前显示 {visibleDevices.length} 台</strong>{deviceHealthFilter==='degraded' ? '检查服务进程、最近扫描时间及上报链路，再由终端平台执行已审批修复。' : deviceHealthFilter==='invalid' ? '健康证明不可信；核验客户端完整性与版本，禁止据此自动放行。' : deviceHealthFilter==='missing' ? '旧客户端或上报链路尚未提供健康证明；优先升级并验证一次真实扫描。' : deviceHealthFilter==='action_required' ? '先完成客户端升级和上报验证；隔离、卸载或访问限制仍须通过企业审批。' : '筛选仅改变只读视图，不会向终端下发命令。'}</p>
            </div>
            <DataTable
              rows={visibleDevices.map((device)=>[
                device.device_id,
                new Date(device.last_seen*1000).toLocaleString('zh-CN'),
                `Agent ${device.agent_version} / 策略 ${device.policy_version}`,
                `${device.severity==='critical' ? '严重' : device.severity==='high' ? '高危' : '正常'} · 宿主${device.service_health_status==='healthy' ? '健康' : device.service_health_status==='degraded' ? '降级' : device.service_health_status==='invalid' ? '无效' : '未上报'} · ${device.credential_generation==='current' ? '当前凭据' : device.credential_generation==='previous' ? '上一代凭据' : 'Legacy'}`,
              ])}
            />
          </div>
        )}
        {view === 'risks' && (
          <div className="panel inset">
            <div className="panel-head">
              <div>
                <h2>待研判事件</h2>
                <p>{recommendations ? `${recommendations.length} 条确定性处置建议 · 仅基于最新终端报告` : 'Collector 处置建议暂不可用'}</p>
              </div>
              <Button onClick={() => notify('建议事件包含关联号，可提交企业 4A 审批；控制台未执行任何终端动作。')}>
                查看审批边界
              </Button>
            </div>
            {recommendations?.length ? <DataTable rows={recommendations.map((item)=>[
              item.device_id,
              item.reason==='risk_critical'?'严重发现':item.reason==='risk_high'?'高危发现':item.reason==='service_health_invalid'?'健康证明无效':item.reason==='service_health_degraded'?'统一宿主降级':item.reason==='service_health_missing'?'宿主状态未上报':'客户端或策略漂移',
              item.recommended_action==='containment_pending_approval'?'建议隔离（待审批）':item.recommended_action==='access_review_pending'?'建议访问复核（待审批）':item.recommended_action==='verify_integrity'?'核验客户端完整性':item.recommended_action==='repair_service'?'通过终端平台修复服务':'升级受管客户端',
              `${item.severity==='critical'?'严重':'高危'} · ${item.workflow_state==='pending'?'待审批':item.workflow_state==='approved'?'已批准':item.workflow_state==='rejected'?'已拒绝':item.workflow_state==='executing'?'执行中':item.workflow_state==='succeeded'?'已完成':'执行失败'} · ${item.correlation_id.slice(0,10)}`,
            ])}/> : <div className="empty-detail"><ShieldCheck size={32}/><h3>{recommendations ? '暂无待处置建议' : '处置建议暂不可用'}</h3><p>{recommendations ? '最新终端状态未触发建议；控制台不会填充样例事件。' : 'Collector 未连接或返回契约无效，未使用聚合数量伪造明细。'}</p></div>}
          </div>
        )}
        {view === 'baseline' && (
          <>
            <div className="baseline-banner">
              <div>
                <h2>企业 AI Coding 安全基线 v{releaseMetadata?.component_versions.policy ?? '5.1.0'}</h2>
                <p>20 条可热更新扩展规则 · Skill/MCP 四态处置与 deny 优先 · 摘要校验与自动回退</p>
              </div>
              <strong>
                v{releaseMetadata?.component_versions.policy ?? '5.1.0'}<span>策略版本</span>
              </strong>
            </div>
            <div className="policy-grid">
              {[
                ['SEC-AUTH-01', '禁止硬编码密钥与令牌', '阻断'],
                ['SEC-INJ-03', '外部输入必须参数化处理', '阻断'],
                ['SEC-LOG-02', '敏感字段不得写入日志', '阻断'],
                ['SEC-DEP-04', '高危依赖不得进入主分支', '需审批'],
              ].map((r) => (
                <article className="panel policy-card" key={r[0]}>
                  <span>{r[0]}</span>
                  <h3>{r[1]}</h3>
                  <div>
                    <i className={r[2] === '阻断' ? 'fail' : 'warn'}>{r[2]}</i>
                    <button onClick={() => notify(`${r[0]} 规则详情已打开。`)}>
                      配置
                    </button>
                  </div>
                </article>
              ))}
            </div>
            <div className="panel inset">
              <div className="panel-head"><div><h2>长期维护规则源</h2><p>发现新版本后先隔离，不会直接执行或覆盖生产策略</p></div><Badge>5 个引擎源 + 1 个治理源</Badge></div>
              <div className="control-planes">
                <article><b>Cisco Skill Scanner</b><span>Apache-2.0</span><p>Prompt Injection、数据外泄、恶意代码、依赖与行为数据流。</p></article>
                <article><b>Cisco MCP Scanner</b><span>Apache-2.0</span><p>工具投毒、命令与外联风险；连接型检测必须在沙箱中运行。</p></article>
                <article><b>Semgrep Community</b><span>独立规则许可</span><p>多语言 SAST 规则保持原生语义，由 Semgrep 引擎执行。</p></article>
                <article><b>Gitleaks Core</b><span>MIT</span><p>持续更新密钥检测器；不使用需要组织许可证的 Action。</p></article>
                <article><b>Snyk Agent Scan</b><span>需令牌与条款审批</span><p>仅作 Skill/MCP 风险情报源，未审批前禁止规模化云分析。</p></article>
                <article><b>OWASP Agentic 2026</b><span>治理映射</span><p>用于风险分类与基线映射，不伪装成可执行扫描规则。</p></article>
              </div>
            </div>
          </>
        )}
        {view === 'policies' && (
          <div className="panel inset">
            <div className="panel-head">
              <div>
                <h2>默认终端策略</h2>
                <p>变更将自动同步至在线安全 Agent</p>
              </div>
              <Button onClick={() => notify('策略发布 API 尚未启用，未修改任何终端。')}>
                发布策略
              </Button>
            </div>
            {[
              ['自动发现 AI Agent', '检测主流 AI Coding 工具', true],
              ['强制加载安全基线', '启动时注入企业编码规范', true],
              ['高危 MCP 自动隔离', '阻断越权文件访问与外联', true],
              ['未知 Skill 默认禁用', '等待签名与安全审批', false],
            ].map(([a, b, on]) => (
              <div className="setting-row" key={String(a)}>
                <div>
                  <strong>{a}</strong>
                  <span>{b}</span>
                </div>
                <button
                  className={`switch ${on ? 'on' : ''}`}
                  onClick={(e) => {
                    e.currentTarget.classList.toggle('on');
                    notify(`${a} 未被修改，设置 API 尚未连接。`);
                  }}
                  aria-label={`切换${a}`}
                >
                  <span />
                </button>
              </div>
            ))}
          </div>
        )}
        {(view === 'team' || view === 'settings') && (
          <div className="empty-detail">
            <ShieldCheck size={44} />
            <h2>{viewNames[view]}已接入</h2>
            <p>下一阶段可连接企业身份、通知和审计系统。</p>
            <Button onClick={() => notify('配置向导尚未连接企业后端。')}>
              打开配置向导
            </Button>
          </div>
        )}
      </section>
    </div>
  );
}
function DataTable({ rows }: { rows: string[][] }) {
  return (
    <div className="data-table">
      <div className="data-head">
        <span>对象</span>
        <span>策略动作</span>
        <span>检测结果</span>
        <span>状态</span>
      </div>
      {rows.map((r) => (
        <div className="data-row" key={r[0]}>
          <strong>{r[0]}</strong>
          <span>{r[1]}</span>
          <span>{r[2]}</span>
          <i
            className={
              r[3] === '通过' || r[3] === '受保护'
                ? 'pass'
                : r[3] === '高危' || r[3] === '需处理'
                  ? 'fail'
                  : 'warn'
            }
          >
            {r[3]}
          </i>
        </div>
      ))}
    </div>
  );
}
