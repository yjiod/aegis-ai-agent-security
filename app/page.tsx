'use client';
import { useEffect, useState } from 'react';
import { Activity, AlertTriangle, Bot, Check, ChevronDown, CircleDot, Code2, Laptop, LockKeyhole, Network, Play, Search, Settings, ShieldCheck, SlidersHorizontal, Sparkles, Users, Wrench } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';

const modules = [
  { icon: ShieldCheck, title: '安全编码基线', desc: '42 条规则 · v3.8', status: '已强制', tone: 'green' },
  { icon: Sparkles, title: 'Skill 扫描器', desc: '权限、指令与依赖', status: '运行中', tone: 'blue' },
  { icon: Network, title: 'MCP 扫描器', desc: '工具、密钥与外联', status: '已启用', tone: 'green' },
  { icon: Code2, title: '代码质量扫描', desc: 'SAST、依赖与密钥', status: '已启用', tone: 'green' },
];
const risks = [
  { severity: '高危', title: 'MCP Server 请求了未授权文件目录', source: 'cursor-mcp-filesystem', device: 'MKT-LT-2841', time: '2 分钟前', color: 'red' },
  { severity: '中危', title: 'Skill 包含可疑的隐藏指令覆盖', source: 'prompt-helper.skill', device: 'ENG-MBP-1032', time: '18 分钟前', color: 'orange' },
  { severity: '中危', title: '生成代码使用弱随机数创建会话令牌', source: 'payment-service / PR #184', device: 'ENG-LT-0948', time: '31 分钟前', color: 'orange' },
];

export default function Home() {
  const [scanning, setScanning] = useState(false); const [toast, setToast] = useState('');
  function runScan(){ setScanning(true); setToast('正在向 284 台在线设备下发全量扫描…'); window.setTimeout(()=>{setScanning(false);setToast('扫描任务已下发，控制台将持续汇总结果。')},1600); }
  useEffect(()=>{
    const controller = new AbortController();
    const modelContext = (document as Document & {modelContext?: {registerTool:(tool:unknown, options?:{signal?:AbortSignal})=>void|Promise<void>}}).modelContext;
    if (!modelContext?.registerTool) return;
    void Promise.resolve(modelContext.registerTool({name:'start_enterprise_security_scan',title:'启动全量安全扫描',description:'向当前在线的企业终端下发 AI Agent、Skill、MCP 与代码质量全量扫描任务。',inputSchema:{type:'object',properties:{scope:{type:'string',enum:['online_devices']}},required:['scope'],additionalProperties:false},annotations:{readOnlyHint:false,untrustedContentHint:false},execute:(input:unknown)=>{if(!input||typeof input!=='object'||(input as {scope?:string}).scope!=='online_devices')throw new Error('scope 必须为 online_devices');runScan();return {status:'dispatched',onlineDevices:284};}},{signal:controller.signal})).catch(()=>undefined);
    return ()=>controller.abort();
  },[]);
  return <main className="min-h-screen bg-[#07110f] text-[#eaf7f2]">
    <header className="topbar"><div className="brand"><span className="brandmark"><ShieldCheck size={19}/></span><span>Sentinel<span className="brand-muted"> / Agent Security</span></span></div><div className="header-actions"><span className="system-ok"><span className="live-dot"/>系统运行正常</span><button className="icon-btn" aria-label="搜索"><Search size={18}/></button><button className="avatar" aria-label="账户菜单">SL</button></div></header>
    <div className="shell"><aside className="sidebar"><nav aria-label="主导航"><p className="nav-label">控制台</p><a className="nav-item active" href="#overview"><Activity size={18}/>总览</a><a className="nav-item" href="#devices"><Laptop size={18}/>设备与 Agent <span>312</span></a><a className="nav-item" href="#risks"><AlertTriangle size={18}/>风险中心 <b>12</b></a><p className="nav-label section-gap">安全能力</p><a className="nav-item" href="#baseline"><Code2 size={18}/>编码规范基线</a><a className="nav-item" href="#skills"><Sparkles size={18}/>Skill 扫描器</a><a className="nav-item" href="#mcp"><Network size={18}/>MCP 扫描器</a><a className="nav-item" href="#quality"><Wrench size={18}/>代码质量</a><p className="nav-label section-gap">管理</p><a className="nav-item" href="#policies"><SlidersHorizontal size={18}/>策略配置</a><a className="nav-item" href="#team"><Users size={18}/>团队与权限</a><a className="nav-item" href="#settings"><Settings size={18}/>系统设置</a></nav><div className="side-foot"><LockKeyhole size={16}/><div><strong>企业安全策略</strong><small>最后同步于 1 分钟前</small></div><Check size={16}/></div></aside>
    <section className="workspace" id="overview"><div className="page-head"><div><p className="eyebrow">安全态势 / 实时</p><h1>AI Agent 安全总览</h1><p>统一发现、校验并约束员工终端上的 AI Agent 行为。</p></div><div className="head-actions"><Button variant="outline"><ChevronDown/>过去 24 小时</Button><Button onClick={runScan} disabled={scanning}><Play fill="currentColor"/>{scanning?'扫描下发中…':'启动全量扫描'}</Button></div></div>
    {toast&&<div className="toast" role="status"><CircleDot size={16}/>{toast}</div>}
    <div className="metrics"><article className="metric"><div className="metric-top"><span>已纳管设备</span><Laptop size={18}/></div><strong>312</strong><p><em>284</em> 在线 · 28 离线</p></article><article className="metric"><div className="metric-top"><span>Agent 覆盖率</span><Bot size={18}/></div><strong>96.8<small>%</small></strong><Progress value={96.8}/><p>较昨日 <em>+1.2%</em></p></article><article className="metric danger"><div className="metric-top"><span>待处理风险</span><AlertTriangle size={18}/></div><strong>12</strong><p><i>3 高危</i> · 7 中危 · 2 低危</p></article><article className="metric"><div className="metric-top"><span>今日拦截</span><ShieldCheck size={18}/></div><strong>47</strong><p>已自动处置 <em>43</em> 项</p></article></div>
    <div className="content-grid"><section className="panel capabilities"><div className="panel-head"><div><h2>防护能力</h2><p>自动随企业 Agent 加载并持续更新</p></div><Badge variant="outline"><span className="live-dot"/>策略已同步</Badge></div><div className="module-grid">{modules.map(({icon:Icon,title,desc,status,tone})=><article className="module" key={title}><span className={`module-icon ${tone}`}><Icon size={19}/></span><div><h3>{title}</h3><p>{desc}</p></div><span className={`status ${tone}`}><Check size={13}/>{status}</span></article>)}</div><div className="flow"><span>员工安装 AI Agent</span><b>→</b><span>安全 Agent 静默加载</span><b>→</b><span>策略校验 + 持续扫描</span><b>→</b><span className="safe"><ShieldCheck size={15}/>安全放行</span></div></section>
    <section className="panel coverage"><div className="panel-head"><div><h2>终端覆盖</h2><p>按 Agent 工具</p></div><button>查看全部</button></div>{[['Cursor',124,100],['Claude Code',86,78],['Codex CLI',64,58],['Windsurf',38,34]].map(([name,total,online])=><div className="coverage-row" key={String(name)}><div className="tool-logo">{String(name).slice(0,1)}</div><div className="coverage-data"><div><strong>{name}</strong><span>{online}/{total} 在线</span></div><Progress value={Number(online)/Number(total)*100}/></div></div>)}</section>
    <section className="panel risks" id="risks"><div className="panel-head"><div><h2>最新风险事件</h2><p>按风险等级与时间排序</p></div><button>进入风险中心 →</button></div><div className="risk-table">{risks.map(r=><div className="risk-row" key={r.title}><span className={`severity ${r.color}`}>{r.severity}</span><div className="risk-main"><strong>{r.title}</strong><span>{r.source}</span></div><span className="device">{r.device}</span><span className="time">{r.time}</span><button className="handle" onClick={()=>setToast(`已打开「${r.title}」处置详情。`)}>处置</button></div>)}</div></section>
    <section className="panel score"><div className="panel-head"><div><h2>安全评分</h2><p>企业基线综合得分</p></div></div><div className="score-body"><div className="score-ring"><strong>92</strong><span>/ 100</span></div><div className="score-list"><p><span>配置合规</span><b>98</b></p><p><span>Agent 行为</span><b>94</b></p><p><span>代码安全</span><b>87</b></p></div></div></section></div></section></div>
  </main>;
}
