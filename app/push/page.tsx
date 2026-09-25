'use client';

/**
 * /push — 分发中心：首次安装（全新设备）+ 桌管热更推送包（已纳管设备）。
 *
 * 两个区解决两个完全不同的问题，别混用：
 *   ① 首次安装 —— 设备从未装过 Aegis。用双击安装器 / MSI / .pkg，会铺文件 + 建服务 +
 *      零接触入网（拿 report_token）。Windows 双击 install-aegis-windows.cmd 最省心
 *      （自动提权 → 跑已验证的一键脚本）；MSI 已修复 BUG G（wixl 把 `$Comp=3` 的 `$`
 *      吞掉导致建服务的自定义动作恒不调度 → 双击只铺文件不建服务，表现为"点了没反应"）。
 *   ② 热更推送 —— 设备已纳管，只换变化的组件（脚本/基线/host），apply 校验 sha256
 *      后替换并重启服务。不重新入网、不动凭据。
 *
 * 数据源: nginx 直供 /downloads/push/PUSH-INDEX.json（build-lite-push.sh 生成，
 * 磁盘 /opt/aegis/native-dist/push/，与 .msi/.pkg 同走 /downloads/ 前缀 alias）。
 * 安装器为服务端私有副本（部署时注入真实 origin，仓库副本恒为占位域且拒绝运行），
 * 本页只用相对 /downloads/ 链接，不含任何真实主机名（可安全提交 GitHub）。
 */
import { useCallback, useEffect, useState } from 'react';
import { Package, Download, Copy, Check, Monitor, Apple, Terminal, ShieldCheck } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { CanaryPanel } from '@/components/canary-panel';

type PushPkg = { name: string; platform: string; bytes: number; sha256: string; scenario: string };
type PushIndex = { schema: string; agent_version: string; generated_at: string; packages: PushPkg[] };

function human(bytes: number): string {
  if (bytes >= 1024 * 1024) return (bytes / 1024 / 1024).toFixed(2) + ' MB';
  if (bytes >= 1024) return (bytes / 1024).toFixed(1) + ' KB';
  return bytes + ' B';
}

const APPLY_CMD: Record<string, string> = {
  macos: 'unzip aegis-push-mac.zip -d /tmp/aegis-push && sudo bash /tmp/aegis-push/apply-mac.sh',
  'windows-x64': 'Expand-Archive aegis-push-win-x64.zip C:\\aegis-push -Force; powershell -File C:\\aegis-push\\apply-win.ps1',
  'windows-arm64': 'Expand-Archive aegis-push-win-arm64.zip C:\\aegis-push -Force; powershell -File C:\\aegis-push\\apply-win.ps1',
};

export default function PushPage() {
  const [index, setIndex] = useState<PushIndex | null>(null);
  const [error, setError] = useState('');
  const [copied, setCopied] = useState('');
  const [origin, setOrigin] = useState('');

  useEffect(() => { if (typeof window !== 'undefined') setOrigin(window.location.origin); }, []);

  const load = useCallback(async () => {
    try {
      const r = await fetch('/downloads/push/PUSH-INDEX.json', { cache: 'no-store' });
      if (!r.ok) throw new Error('HTTP ' + r.status);
      setIndex((await r.json()) as PushIndex);
      setError('');
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      setIndex(null);
    }
  }, []);
  useEffect(() => { void load(); }, [load]);

  const copy = async (text: string, key: string) => {
    try { await navigator.clipboard.writeText(text); setCopied(key); setTimeout(() => setCopied(''), 1500); } catch { /* ignore */ }
  };

  // 首次安装命令（用当前控制台 origin，复制即用；SSR 期 origin 为空则回落相对提示）
  const O = origin || 'https://<你的控制台>';
  const winPsCmd =
    `[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12\n` +
    `Invoke-WebRequest ${O}/downloads/aegis-install-windows-oneclick.ps1 -OutFile $env:TEMP\\aegis-oneclick.ps1\n` +
    `powershell -NoProfile -ExecutionPolicy Bypass -File $env:TEMP\\aegis-oneclick.ps1`;

  const dlBtn = (href: string, label: string) => (
    <a href={href} download style={{ display: 'inline-flex', alignItems: 'center', gap: 5, fontSize: 12, fontWeight: 500 }}>
      <Download size={13} /> {label}
    </a>
  );
  const cmdBlock = (text: string, key: string) => (
    <div style={{ position: 'relative', marginTop: 6 }}>
      <pre style={{
        margin: 0, padding: '8px 30px 8px 10px', fontSize: 10.5, lineHeight: 1.5, whiteSpace: 'pre-wrap',
        wordBreak: 'break-all', background: 'var(--muted)', borderRadius: 6, color: 'var(--foreground)',
        fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace',
      }}>{text}</pre>
      <button
        onClick={() => void copy(text, key)}
        title="复制命令"
        style={{ position: 'absolute', top: 6, right: 6, background: 'none', border: 0, color: 'var(--muted-foreground)', cursor: 'pointer' }}
      >
        {copied === key ? <Check size={13} /> : <Copy size={13} />}
      </button>
    </div>
  );

  return (
    <div className="workspace">
      <div className="page-head animate-entrance animate-entrance-1">
        <div>
          <p className="eyebrow">管理 / 分发</p>
          <h1>分发中心</h1>
          <p>
            全新设备用「首次安装」，会自动装好并接入控制台；已纳管设备用「热更推送」，只更新有变化的部分，不影响已有接入和凭据。
          </p>
        </div>
        <div className="head-actions">
          {index && <Badge variant="outline"><Package size={12} /> 客户端 {index.agent_version}</Badge>}
        </div>
      </div>

      {/* ① 首次安装 */}
      <div className="panel animate-entrance animate-entrance-2" style={{ padding: 16, marginBottom: 16 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
          <ShieldCheck size={16} />
          <h2 style={{ margin: 0, fontSize: 15 }}>首次安装 · 全新设备</h2>
        </div>
        <p style={{ fontSize: 12, color: 'var(--muted-foreground)', margin: '0 0 14px' }}>
          设备从未装过 Aegis 时用这里。安装器会在后台装好并启动，自动接入控制台，无需手填令牌。
        </p>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: 14 }}>
          {/* Windows */}
          <div style={{ border: '1px solid var(--border)', borderRadius: 10, padding: 14 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 7, marginBottom: 10 }}>
              <Monitor size={15} /> <strong style={{ fontSize: 13 }}>Windows</strong>
              <Badge variant="outline" style={{ marginLeft: 'auto', fontSize: 10 }}>x64 / ARM64 通用</Badge>
            </div>

            <div style={{ marginBottom: 12 }}>
              <div style={{ fontSize: 12, fontWeight: 600, marginBottom: 2 }}>
                ① 推荐 · 双击即装 <Badge variant="outline" style={{ fontSize: 9, marginLeft: 4 }}>自动提权</Badge>
              </div>
              <div style={{ fontSize: 11, color: 'var(--muted-foreground)', marginBottom: 4 }}>
                下载后双击，弹窗点「是」授予管理员权限，随后自动完成安装、启动与接入，全程有进度提示。
              </div>
              {dlBtn('/downloads/install-aegis-windows.cmd', 'install-aegis-windows.cmd')}
            </div>

            <div style={{ marginBottom: 12 }}>
              <div style={{ fontSize: 12, fontWeight: 600, marginBottom: 2 }}>
                ② 备选 · 双击 MSI 安装包
              </div>
              <div style={{ fontSize: 11, color: 'var(--muted-foreground)', marginBottom: 4 }}>
                原生安装包。双击后按提示授予管理员权限，即自动完成安装与接入。
              </div>
              {dlBtn('/downloads/aegis-agent-windows.msi', 'aegis-agent-windows.msi')}
            </div>

            <div>
              <div style={{ fontSize: 12, fontWeight: 600, marginBottom: 2 }}>③ 备选 · 管理员 PowerShell 一键</div>
              <div style={{ fontSize: 11, color: 'var(--muted-foreground)' }}>
                右键「以管理员身份运行 PowerShell」，粘贴：
              </div>
              {cmdBlock(winPsCmd, 'win-ps')}
            </div>
          </div>

          {/* macOS */}
          <div style={{ border: '1px solid var(--border)', borderRadius: 10, padding: 14 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 7, marginBottom: 10 }}>
              <Apple size={15} /> <strong style={{ fontSize: 13 }}>macOS</strong>
              <Badge variant="outline" style={{ marginLeft: 'auto', fontSize: 10 }}>Apple Silicon / Intel</Badge>
            </div>

            <div>
              <div style={{ fontSize: 12, fontWeight: 600, marginBottom: 2 }}>
                系统级 · 唯一形态 <Badge variant="outline" style={{ fontSize: 9, marginLeft: 4 }}>root 扫全部 /Users</Badge>
              </div>
              <div style={{ fontSize: 11, color: 'var(--muted-foreground)', marginBottom: 4 }}>
                下载后双击安装。以 root 扫描全部用户目录、支持连接级封禁、无需逐用户授权。
                用户级安装已取消（避免与系统级双重上报）；历史用户级安装可用 .run --uninstall 清理。
              </div>
              {dlBtn('/downloads/aegis-agent-macos.pkg', 'aegis-agent-macos.pkg')}
            </div>
          </div>
        </div>

        <p style={{ fontSize: 11, color: 'var(--muted-foreground)', marginTop: 12, marginBottom: 0, display: 'flex', alignItems: 'center', gap: 5 }}>
          <Terminal size={12} />
          装完刷新控制台即出现新设备（序列号 + 客户端版本 + 发现的 AI 工具）。首次上报需等一个扫描周期（默认 1 小时）。
        </p>
      </div>

      {/* ② 热更推送包 */}
      <div className="page-head" style={{ marginTop: 4 }}>
        <div>
          <h2 style={{ margin: 0, fontSize: 15 }}>热更推送包 · 已纳管设备</h2>
          <p style={{ fontSize: 12, color: 'var(--muted-foreground)', margin: '4px 0 0' }}>
            用于已纳管设备的增量更新：只包含有变化的部分，更新前会校验完整性，替换后自动重启服务，不会影响已有接入和凭据。
          </p>
        </div>
      </div>

      {error ? (
        <div className="panel" style={{ padding: 16 }}>
          <p style={{ color: 'var(--sentinel-danger)' }}>读取推送清单失败：{error}</p>
        </div>
      ) : !index ? (
        <div className="panel" style={{ padding: 16 }}><p>加载推送清单…</p></div>
      ) : (
        <div className="panel data-table cols-6 animate-entrance animate-entrance-3" style={{ padding: 8 }}>
          <div className="data-head">
            <span>包</span><span>平台</span><span>大小</span><span>适用场景 / 更新命令</span><span>校验值</span><span></span>
          </div>
          {index.packages.map((p) => (
            <div className="data-row" key={p.name}>
              <span style={{ fontSize: 12 }}>{p.name}</span>
              <span><Badge variant="outline">{p.platform}</Badge></span>
              <span style={{ fontSize: 12 }}>{human(p.bytes)}</span>
              <span style={{ fontSize: 11 }}>
                {p.scenario}
                <br />
                <code style={{ fontSize: 10, color: 'var(--muted-foreground)' }}>{APPLY_CMD[p.platform] ?? '见包内更新脚本'}</code>
                <button
                  onClick={() => void copy(APPLY_CMD[p.platform] ?? '', p.name)}
                  style={{ background: 'none', border: 0, color: 'var(--muted-foreground)', cursor: 'pointer', verticalAlign: '-2px' }}
                  title="复制更新命令"
                >
                  {copied === p.name ? <Check size={12} /> : <Copy size={12} />}
                </button>
              </span>
              <span style={{ fontSize: 10, fontFamily: 'monospace', wordBreak: 'break-all' }}>{p.sha256.slice(0, 16)}…</span>
              <span>
                <a href={'/downloads/push/' + p.name} download style={{ display: 'inline-flex', alignItems: 'center', gap: 4, fontSize: 12 }}>
                  <Download size={13} /> 下载
                </a>
              </span>
            </div>
          ))}
          <p style={{ fontSize: 11, color: 'var(--muted-foreground)', padding: '10px 12px' }}>
            生成时间 {index.generated_at} · 按设备平台选择对应的更新包；首次安装或重装请用上方「首次安装」。
          </p>
        </div>
      )}

      {/* ③ 自更新灰度（canary）运营面板 */}
      <CanaryPanel latestAgentVersion={index?.agent_version} />
    </div>
  );
}
