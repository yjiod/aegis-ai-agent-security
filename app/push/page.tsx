'use client';

/**
 * /push — 桌管(MDM)轻量推送包下载区。
 * 数据源: nginx 直供 /native-dist/push/PUSH-INDEX.json（build-lite-push.sh 生成）。
 * 只推"变化组件"+apply 脚本+清单，不推完整安装包；apply 先校验 sha256 再换文件并重启。
 * 体积量级: mac ~34KB / win 脚本包 ~90KB / win 含单架构 host ~5.9MB（完整 .msi 12.3MB 双架构）。
 */
import { useCallback, useEffect, useState } from 'react';
import { Package, Download, Copy, Check } from 'lucide-react';
import { Badge } from '@/components/ui/badge';

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

  const load = useCallback(async () => {
    try {
      const r = await fetch('/native-dist/push/PUSH-INDEX.json', { cache: 'no-store' });
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

  return (
    <div className="workspace">
      <div className="page-head animate-entrance animate-entrance-1">
        <div>
          <p className="eyebrow">管理 / 分发</p>
          <h1>桌管推送包</h1>
          <p>
            最小轻量包：仅变化组件 + apply 脚本 + 清单（每组件 sha256）。不推完整安装包；
            apply 先校验 sha256 再替换并重启服务。mac ≈34KB、win 脚本包 ≈90KB、win 含单架构 host ≈5.9MB（完整 .msi 12.3MB 双架构）。
          </p>
        </div>
        <div className="head-actions">
          {index && <Badge variant="outline"><Package size={12} /> agent {index.agent_version}</Badge>}
        </div>
      </div>

      {error ? (
        <div className="panel" style={{ padding: 16 }}>
          <p style={{ color: '#ff685f' }}>读取推送清单失败：{error}（部署时由 build-lite-push.sh 生成并上传）</p>
        </div>
      ) : !index ? (
        <div className="panel" style={{ padding: 16 }}><p>加载推送清单…</p></div>
      ) : (
        <div className="panel data-table cols-6 animate-entrance animate-entrance-2" style={{ padding: 8 }}>
          <div className="data-head">
            <span>包</span><span>平台</span><span>大小</span><span>适用场景 / apply</span><span>sha256</span><span></span>
          </div>
          {index.packages.map((p) => (
            <div className="data-row" key={p.name}>
              <span style={{ fontSize: 12 }}>{p.name}</span>
              <span><Badge variant="outline">{p.platform}</Badge></span>
              <span style={{ fontSize: 12 }}>{human(p.bytes)}</span>
              <span style={{ fontSize: 11 }}>
                {p.scenario}
                <br />
                <code style={{ fontSize: 10, color: 'var(--muted-foreground)' }}>{APPLY_CMD[p.platform] ?? '见包内 apply 脚本'}</code>
                <button
                  onClick={() => void copy(APPLY_CMD[p.platform] ?? '', p.name)}
                  style={{ background: 'none', border: 0, color: 'var(--muted-foreground)', cursor: 'pointer', verticalAlign: '-2px' }}
                  title="复制 apply 命令"
                >
                  {copied === p.name ? <Check size={12} /> : <Copy size={12} />}
                </button>
              </span>
              <span style={{ fontSize: 10, fontFamily: 'monospace', wordBreak: 'break-all' }}>{p.sha256.slice(0, 16)}…</span>
              <span>
                <a href={'/native-dist/push/' + p.name} download style={{ display: 'inline-flex', alignItems: 'center', gap: 4, fontSize: 12 }}>
                  <Download size={13} /> 下载
                </a>
              </span>
            </div>
          ))}
          <p style={{ fontSize: 11, color: 'var(--muted-foreground)', padding: '10px 12px' }}>
            生成时间 {index.generated_at} · 何时用哪个：仅脚本/基线变更→mac/win 脚本包；host exe(.NET/服务行为)变更→含 host 包(按设备架构)；
            MSI 结构/ACL/服务注册/首次安装→完整 .msi 或一键脚本。mac 无独立 host 二进制，永远只需 34KB 包。
          </p>
        </div>
      )}
    </div>
  );
}
