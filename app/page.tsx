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
    desc: '42 条规则 · v3.8',
    status: '已强制',
    tone: 'green',
  },
  {
    icon: Sparkles,
    title: 'Skill 扫描器',
    desc: '权限、指令与依赖',
    status: '运行中',
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
const risks = [
  {
    severity: '高危',
    title: 'MCP Server 请求了未授权文件目录',
    source: 'cursor-mcp-filesystem',
    device: 'MKT-LT-2841',
    time: '2 分钟前',
    color: 'red',
  },
  {
    severity: '中危',
    title: 'Skill 包含可疑的隐藏指令覆盖',
    source: 'prompt-helper.skill',
    device: 'ENG-MBP-1032',
    time: '18 分钟前',
    color: 'orange',
  },
  {
    severity: '中危',
    title: '生成代码使用弱随机数创建会话令牌',
    source: 'payment-service / PR #184',
    device: 'ENG-LT-0948',
    time: '31 分钟前',
    color: 'orange',
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

export default function Home() {
  const [scanning, setScanning] = useState(false);
  const [toast, setToast] = useState('');
  const [detail, setDetail] = useState<DetailKey | null>(null);
  function runScan() {
    setScanning(true);
    setToast('正在向 284 台在线设备下发全量扫描…');
    window.setTimeout(() => {
      setScanning(false);
      setToast('扫描任务已下发，控制台将持续汇总结果。');
    }, 1600);
  }
  useEffect(() => {
    const controller = new AbortController();
    const modelContext = (
      document as Document & {
        modelContext?: {
          registerTool: (
            tool: unknown,
            options?: { signal?: AbortSignal },
          ) => void | Promise<void>;
        };
      }
    ).modelContext;
    if (!modelContext?.registerTool) return;
    void Promise.resolve(
      modelContext.registerTool(
        {
          name: 'start_enterprise_security_scan',
          title: '启动全量安全扫描',
          description:
            '向当前在线的企业终端下发 AI Agent、Skill、MCP 与代码质量全量扫描任务。',
          inputSchema: {
            type: 'object',
            properties: { scope: { type: 'string', enum: ['online_devices'] } },
            required: ['scope'],
            additionalProperties: false,
          },
          annotations: { readOnlyHint: false, untrustedContentHint: false },
          execute: (input: unknown) => {
            if (
              !input ||
              typeof input !== 'object' ||
              (input as { scope?: string }).scope !== 'online_devices'
            )
              throw new Error('scope 必须为 online_devices');
            runScan();
            return { status: 'dispatched', onlineDevices: 284 };
          },
        },
        { signal: controller.signal },
      ),
    ).catch(() => undefined);
    return () => controller.abort();
  }, []);
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
            <span className="live-dot" />
            系统运行正常
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
              count="312"
            />
            <Nav
              icon={AlertTriangle}
              label="风险中心"
              target="risks"
              open={setDetail}
              alert="12"
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
              <small>最后同步于 1 分钟前</small>
            </div>
            <Check size={16} />
          </div>
        </aside>
        <section className="workspace" id="overview">
          <div className="page-head">
            <div>
              <p className="eyebrow">安全态势 / 实时</p>
              <h1>AI Agent 安全总览</h1>
              <p>统一发现、校验并约束员工终端上的 AI Agent 行为。</p>
            </div>
            <div className="head-actions">
              <Button variant="outline">
                <ChevronDown />
                过去 24 小时
              </Button>
              <Button onClick={runScan} disabled={scanning}>
                <Play fill="currentColor" />
                {scanning ? '扫描下发中…' : '启动全量扫描'}
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
              <strong>312</strong>
              <p>
                <em>284</em> 在线 · 28 离线
              </p>
            </article>
            <article className="metric">
              <div className="metric-top">
                <span>Agent 覆盖率</span>
                <Bot size={18} />
              </div>
              <strong>
                96.8<small>%</small>
              </strong>
              <Progress value={96.8} />
              <p>
                较昨日 <em>+1.2%</em>
              </p>
            </article>
            <article className="metric danger">
              <div className="metric-top">
                <span>待处理风险</span>
                <AlertTriangle size={18} />
              </div>
              <strong>12</strong>
              <p>
                <i>3 高危</i> · 7 中危 · 2 低危
              </p>
            </article>
            <article className="metric">
              <div className="metric-top">
                <span>今日拦截</span>
                <ShieldCheck size={18} />
              </div>
              <strong>47</strong>
              <p>
                已自动处置 <em>43</em> 项
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
                  策略已同步
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
              {[
                ['Cursor', 124, 100],
                ['Claude Code', 86, 78],
                ['Codex CLI', 64, 58],
                ['Windsurf', 38, 34],
              ].map(([name, total, online]) => (
                <div className="coverage-row" key={String(name)}>
                  <div className="tool-logo">{String(name).slice(0, 1)}</div>
                  <div className="coverage-data">
                    <div>
                      <strong>{name}</strong>
                      <span>
                        {online}/{total} 在线
                      </span>
                    </div>
                    <Progress value={(Number(online) / Number(total)) * 100} />
                  </div>
                </div>
              ))}
            </section>
            <section className="panel risks" id="risks">
              <div className="panel-head">
                <div>
                  <h2>最新风险事件</h2>
                  <p>按风险等级与时间排序</p>
                </div>
                <button>进入风险中心 →</button>
              </div>
              <div className="risk-table">
                {risks.map((r) => (
                  <div className="risk-row" key={r.title}>
                    <span className={`severity ${r.color}`}>{r.severity}</span>
                    <div className="risk-main">
                      <strong>{r.title}</strong>
                      <span>{r.source}</span>
                    </div>
                    <span className="device">{r.device}</span>
                    <span className="time">{r.time}</span>
                    <button
                      className="handle"
                      onClick={() => setToast(`已打开「${r.title}」处置详情。`)}
                    >
                      处置
                    </button>
                  </div>
                ))}
              </div>
            </section>
            <section className="panel score">
              <div className="panel-head">
                <div>
                  <h2>安全评分</h2>
                  <p>企业基线综合得分</p>
                </div>
              </div>
              <div className="score-body">
                <div className="score-ring">
                  <strong>92</strong>
                  <span>/ 100</span>
                </div>
                <div className="score-list">
                  <p>
                    <span>配置合规</span>
                    <b>98</b>
                  </p>
                  <p>
                    <span>Agent 行为</span>
                    <b>94</b>
                  </p>
                  <p>
                    <span>代码安全</span>
                    <b>87</b>
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
}: {
  view: DetailKey;
  close: () => void;
  notify: (s: string) => void;
}) {
  const scanRows =
    view === 'skills'
      ? [
          ['prompt-helper.skill', '隔离', '隐藏指令覆盖', '高危'],
          ['jira-assistant.skill', '放行', '权限声明完整', '通过'],
          ['release-notes.skill', '观察', '依赖包待升级', '中危'],
        ]
      : view === 'mcp'
        ? [
            ['filesystem-mcp', '限制', '越权目录访问', '高危'],
            ['github-mcp', '放行', 'OAuth 范围合规', '通过'],
            ['postgres-mcp', '观察', '出站地址未锁定', '中危'],
          ]
        : [
            ['payment-service', '阻断', '弱随机数生成令牌', '高危'],
            ['customer-portal', '放行', '质量门禁通过', '通过'],
            ['data-pipeline', '观察', '依赖存在 CVE', '中危'],
          ];
  const scanner = view === 'skills' || view === 'mcp' || view === 'quality';
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
        {view === 'onboarding' && (
          <>
            <div className="baseline-banner">
              <div>
                <h2>Sentinel Endpoint Agent 0.5.0</h2>
                <p>Intune 部署 · 深信服 EDR 联动 · 联软桌管兜底</p>
              </div>
              <strong>可验证<span>本地执行</span></strong>
            </div>
            <div className="panel inset onboarding">
              <h2>企业部署编排</h2>
              <div className="control-planes">
                <article><b>Microsoft Intune</b><span>主部署通道</span><p>Windows Remediations 与 macOS Shell Script，负责安装、版本检测和周期修复。</p></article>
                <article><b>深信服 EDR</b><span>响应处置</span><p>接收高危事件，按现网版本能力执行隔离、查杀或 IOC 取证。</p></article>
                <article><b>联软桌管</b><span>资产与兜底</span><p>软件分发、资产核验及未安装终端的准入修复。</p></article>
              </div>
              <ol><li><b>自动发现</b><span>Intune 周期任务检测 Cursor、Claude Code、Codex 与 Windsurf 配置。</span></li><li><b>加载基线</b><span>为受管项目增量安装 Agent 规则，并持续扫描 Skill、MCP 与代码。</span></li><li><b>联动处置</b><span>以 device_id 关联深信服 EDR 与联软资产，按风险等级分级响应。</span></li></ol>
              <div className="download-actions">
                <a className="download-primary" href="/downloads/sentinel-enterprise-bundle.zip" download>下载完整部署包</a>
                <a className="download-primary" href="/downloads/DEPLOYMENT-GUIDE.md" download>下载部署指南</a>
                <a href="/downloads/intune-windows-detect.ps1" download>Windows 检测脚本</a>
                <a href="/downloads/intune-windows-remediate.ps1" download>Windows 修复脚本</a>
                <a href="/downloads/intune-macos-install.sh" download>macOS Intune 脚本</a>
                <a href="/downloads/sentinel-policy.json" download>策略基线</a>
              </div>
              <p className="safety-note"><LockKeyhole size={15}/>部署脚本不包含深信服或联软管理凭据；正式联动需按现网版本申请服务账号与接口授权。</p>
            </div>
          </>
        )}
        {scanner && (
          <>
            <div className="detail-kpis">
              <article>
                <strong>
                  {view === 'skills' ? 68 : view === 'mcp' ? 41 : 126}
                </strong>
                <span>已扫描对象</span>
              </article>
              <article>
                <strong>
                  {view === 'skills' ? 3 : view === 'mcp' ? 2 : 7}
                </strong>
                <span>待处理发现</span>
              </article>
              <article>
                <strong>100%</strong>
                <span>在线终端覆盖</span>
              </article>
            </div>
            <div className="panel inset">
              <div className="panel-head">
                <div>
                  <h2>最近扫描结果</h2>
                  <p>终端安全 Agent 实时上报</p>
                </div>
                <Button
                  onClick={() => notify('规则库已同步至 284 台在线终端。')}
                >
                  同步规则库
                </Button>
              </div>
              <DataTable rows={scanRows} />
            </div>
          </>
        )}
        {view === 'devices' && (
          <div className="panel inset">
            <div className="panel-head">
              <div>
                <h2>受管终端</h2>
                <p>312 台设备 · 284 台在线</p>
              </div>
              <Button onClick={() => notify('部署包生成任务已创建。')}>
                生成部署包
              </Button>
            </div>
            <DataTable
              rows={[
                ['ENG-MBP-1032', '陈昊 · Cursor', 'v3.8', '受保护'],
                ['MKT-LT-2841', '林妍 · Cursor', 'v3.7', '需处理'],
                ['ENG-LT-0948', '周航 · Codex CLI', 'v3.8', '受保护'],
                ['OPS-MBP-0314', '罗宁 · Claude Code', 'v3.8', '离线'],
              ]}
            />
          </div>
        )}
        {view === 'risks' && (
          <div className="panel inset">
            <div className="panel-head">
              <div>
                <h2>待研判事件</h2>
                <p>3 个高危事件需要人工确认</p>
              </div>
              <Button onClick={() => notify('已批量隔离 3 个高危对象。')}>
                隔离全部高危
              </Button>
            </div>
            {risks.map((r) => (
              <div className="risk-row wide" key={r.title}>
                <span className={`severity ${r.color}`}>{r.severity}</span>
                <div className="risk-main">
                  <strong>{r.title}</strong>
                  <span>{r.source}</span>
                </div>
                <span className="device">{r.device}</span>
                <span className="time">{r.time}</span>
                <button
                  className="handle"
                  onClick={() => notify(`已认领「${r.title}」。`)}
                >
                  认领处置
                </button>
              </div>
            ))}
          </div>
        )}
        {view === 'baseline' && (
          <>
            <div className="baseline-banner">
              <div>
                <h2>企业 AI Coding 安全基线 v3.8</h2>
                <p>42 条规则已强制应用于 18 个研发团队</p>
              </div>
              <strong>
                98.2%<span>合规率</span>
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
          </>
        )}
        {view === 'policies' && (
          <div className="panel inset">
            <div className="panel-head">
              <div>
                <h2>默认终端策略</h2>
                <p>变更将自动同步至在线安全 Agent</p>
              </div>
              <Button onClick={() => notify('策略已发布至 284 台在线终端。')}>
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
                    notify(`${a} 已更新，等待发布。`);
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
            <Button onClick={() => notify('配置向导已启动。')}>
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
