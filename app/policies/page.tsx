'use client';
import { useEffect, useState } from 'react';
import Link from 'next/link';
import { SlidersHorizontal, ShieldCheck } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';

/**
 * 终端安全策略。
 *
 * 顶部「当前生效策略」读真实发布件（/api/policy/current）：显示已签名的策略版本、
 * 签名密钥指纹与发布回执；未发布时如实显示"尚未发布"。发布动作在「处置中心」，
 * 它把处置决定编译成签名的 aegis.policy/v1 下发终端强制。
 *
 * 下方「出厂默认策略基线」是终端在控制台首次发布之前使用的默认约束（只读说明），
 * 不做"点了翻转又自动弹回"的假反馈。
 */
const policies = [
  { name: '自动发现 AI Agent', desc: '检测主流 AI Coding 工具（Cursor、Claude Code、Codex、Windsurf）', on: true },
  { name: '强制加载安全基线', desc: '启动时注入企业编码规范，未加载则阻断 Agent 执行', on: true },
  { name: '高危 MCP 自动隔离', desc: '阻断越权文件访问与未声明外联，隔离后通知安全管理员', on: true },
  { name: '未知 Skill 默认禁用', desc: '等待签名验证与安全审批，未审批 Skill 不加载', on: false },
  { name: '代码质量门禁', desc: '阻断高危 SAST 发现合入主分支，中危需人工审批', on: true },
  { name: '离线队列加密', desc: '报告暂存时使用 AES-256-GCM 加密，防止本地窃取', on: true },
];

interface CurrentRelease {
  published: boolean;
  version: number;
  created_at: number;
  created_by: string;
  signing_key_id: string;
  receipt: { label_counts: { allow: number; monitor: number; deny: number } };
}

export default function PoliciesPage() {
  const [current, setCurrent] = useState<CurrentRelease | null>(null);

  useEffect(() => {
    fetch('/api/policy/current', { cache: 'no-store' })
      .then((r) => (r.ok ? (r.json() as Promise<CurrentRelease>) : null))
      .then((d) => setCurrent(d && d.published ? d : null))
      .catch(() => setCurrent(null));
  }, []);

  return (
    <>
      <div className="page-head animate-entrance animate-entrance-1">
        <div>
          <p className="eyebrow">管理 / 策略配置</p>
          <h1>终端安全策略</h1>
          <p>查看当前下发终端的签名策略；发布与处置在「处置中心」。</p>
        </div>
        <div className="head-actions">
          <Link href="/dispositions" style={{ textDecoration: 'none' }}>
            <Button>
              <SlidersHorizontal size={16} />
              去发布策略
            </Button>
          </Link>
        </div>
      </div>

      <div className="panel animate-entrance animate-entrance-2" style={{ padding: 16, marginBottom: 14 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
          <h2 style={{ fontSize: 15, margin: 0 }}>当前生效策略</h2>
          {current ? (
            <Badge variant="outline">
              <ShieldCheck size={12} /> 已签名 v{current.version}
            </Badge>
          ) : (
            <Badge variant="outline">尚未发布 · 终端使用出厂默认</Badge>
          )}
        </div>
        {current ? (
          <p style={{ fontSize: 13, color: 'var(--muted-foreground)', marginTop: 8 }}>
            版本 v{current.version} · 签名密钥 {current.signing_key_id} · 发布人 {current.created_by} ·{' '}
            {new Date(current.created_at).toLocaleString()} · 回执 allow {current.receipt.label_counts.allow} / monitor{' '}
            {current.receipt.label_counts.monitor} / deny {current.receipt.label_counts.deny}。终端加载时会验签，篡改则拒载并回退上一份有效策略。
          </p>
        ) : (
          <p style={{ fontSize: 13, color: 'var(--muted-foreground)', marginTop: 8 }}>
            还没有从控制台发布过签名策略。到「处置中心」对 Skill/MCP 打标后点击"发布策略"，即可生成签名的 aegis.policy/v1 下发终端强制。
          </p>
        )}
      </div>

      <div className="panel">
        <div className="panel-head">
          <div>
            <h2>出厂默认策略基线</h2>
            <p>终端在首次发布前使用的默认约束（只读）；共 {policies.length} 项，{policies.filter((p) => p.on).length} 项默认启用</p>
          </div>
        </div>
        {policies.map((policy, index) => (
          <div
            className="setting-row animate-row-entrance"
            key={policy.name}
            style={{ animationDelay: `${index * 30 + 200}ms` }}
          >
            <div>
              <strong>{policy.name}</strong>
              <span>{policy.desc}</span>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <i className="warn" style={{ fontSize: 11, fontStyle: 'normal' }}>只读</i>
              <button
                className={`switch ${policy.on ? 'on' : ''}`}
                disabled
                title="出厂默认基线为只读；实际生效策略以处置中心发布件为准"
                aria-label={`${policy.name}（只读）`}
              >
                <span />
              </button>
            </div>
          </div>
        ))}
      </div>
    </>
  );
}
