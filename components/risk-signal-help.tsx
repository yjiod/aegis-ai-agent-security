'use client';

/**
 * 风险信号人话解释（#5）。
 *
 * - <RiskSignalHelp/>：可折叠的"风险信号怎么看"说明面板，嵌入风险/处置页。
 * - <SignalSummary text/>：从 finding 描述里解析 "(风险信号 exec=9, score=4)"，
 *   渲染成使用者能懂的一句话：某能力几处 + 综合分 + 档位。
 *
 * 语义（与 aegis_agent.py skill_risk_score 一致）：
 *   exec/cred/network/filewrite 的数字 = 该能力被发现的"处数"；
 *   score = 能力"有无"加权和（exec+2, cred+2, network+1, filewrite+1，各计一次，满6）；
 *   档位：score>=4 高危，2-3 中危，<2 低危。
 */
import { useState } from 'react';
import { HelpCircle, ChevronDown } from 'lucide-react';

const SIGNAL_LABEL: Record<string, string> = {
  exec: '执行命令/代码',
  cred: '读取凭据/密钥',
  network: '对外联网',
  filewrite: '写文件',
};

export function scoreBand(score: number): { label: string; tone: string } {
  if (score >= 4) return { label: '高危', tone: 'red' };
  if (score >= 2) return { label: '中危', tone: 'orange' };
  return { label: '低危', tone: 'blue' };
}

/** 从文本解析风险信号，如 "(风险信号 exec=9, score=4)"。 */
export function parseSignal(text: string): { signal?: string; count?: number; score?: number } {
  const m = /风险信号\s+([a-z_]+)\s*=\s*(\d+)\s*,\s*score\s*=\s*(\d+)/i.exec(text || '');
  if (!m) return {};
  return { signal: m[1].toLowerCase(), count: Number(m[2]), score: Number(m[3]) };
}

/** 行内友好摘要：把 exec=9, score=4 变成人话。 */
export function SignalSummary({ text }: { text: string }) {
  const { signal, count, score } = parseSignal(text);
  if (signal === undefined || count === undefined || score === undefined) return null;
  const band = scoreBand(score);
  return (
    <span style={{ fontSize: 12, color: 'var(--muted-foreground)' }} title="数字=该能力被发现几处；综合分=能力组合(执行/凭据各2分, 外联/写文件各1分)，≥4高危">
      {SIGNAL_LABEL[signal] ?? signal} 发现 <b>{count}</b> 处 · 综合分 <b>{score}</b>（{band.label}）
    </span>
  );
}

/** 可折叠的"风险信号怎么看"说明面板。 */
export function RiskSignalHelp() {
  const [open, setOpen] = useState(false);
  return (
    <div className="panel" style={{ padding: 12, marginBottom: 14 }}>
      <button
        onClick={() => setOpen((v) => !v)}
        style={{ display: 'flex', alignItems: 'center', gap: 8, background: 'none', border: 'none', color: 'var(--text)', cursor: 'pointer', fontSize: 14, fontWeight: 600, padding: 0 }}
        aria-expanded={open}
      >
        <HelpCircle size={16} />
        风险信号怎么看（exec / cred / network / filewrite / score）
        <ChevronDown size={14} style={{ transform: open ? 'rotate(180deg)' : 'none', transition: 'transform .2s' }} />
      </button>
      {open && (
        <div style={{ marginTop: 10, fontSize: 13, lineHeight: 1.8, color: 'var(--muted-foreground)' }}>
          <p>扫描器不看 Skill/MCP"坏不坏"，而是看它<b>拥有哪些能力</b>。有能力≠恶意，但能力越大、被利用危害越大。</p>
          <p>
            <b>exec</b>=会执行命令/代码；<b>cred</b>=会读凭据/密钥；<b>network</b>=会对外联网；<b>filewrite</b>=会写文件。
            后面的数字（如 exec=9）= <b>发现几处</b>该能力，不是危险度。
          </p>
          <p>
            <b>score</b> = 能力"有无"加权和：执行+2、凭据+2、外联+1、写文件+1（每类只算一次，满分6）。
            它衡量"集齐了几种危险能力"，与次数无关。所以 exec=9 但 score=4 = 9 处执行点，但执行只计一次(+2)，再加外联(+1)+写文件(+1)。
          </p>
          <p>
            档位：score <b>≥4 高危</b>、<b>2–3 中危</b>、<b>&lt;2 低危</b>。
            处置：<b>加白</b>=放行但记审计；<b>观察</b>=不阻断持续上报；<b>拉黑</b>=拦截告警。
          </p>
          <p style={{ fontStyle: 'italic' }}>速记：看 score 定危不危险，看四个信号数字知道它"会干什么、干了几次"，再用三态决定放不放行。</p>
        </div>
      )}
    </div>
  );
}

/* ─── 命中证据"详细信息"（避免误伤）───────────────────────────── */

type SignalSample = { cap: string; file: string; line: number; text: string };
type SignalMatches = { counts: Record<string, number>; score?: number; samples: SignalSample[] };

const CAP_ORDER = ['exec', 'cred', 'network', 'filewrite'] as const;

/**
 * 防御性解析 Agent 回收、经 Collector 透传的命中证据。该数据来自终端（不可信输入），
 * 逐项校验类型与边界，任何不合规字段丢弃而非渲染，绝不把原始对象直接塞进 DOM。
 */
export function parseSignalMatches(raw: unknown): SignalMatches | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const o = raw as Record<string, unknown>;
  const counts: Record<string, number> = {};
  if (o.counts && typeof o.counts === 'object' && !Array.isArray(o.counts)) {
    for (const [k, v] of Object.entries(o.counts as Record<string, unknown>)) {
      if ((CAP_ORDER as readonly string[]).includes(k) && typeof v === 'number' && Number.isFinite(v) && v >= 0)
        counts[k] = Math.floor(v);
    }
  }
  const samples: SignalSample[] = [];
  if (Array.isArray(o.samples)) {
    for (const s of o.samples.slice(0, 64)) {
      if (!s || typeof s !== 'object' || Array.isArray(s)) continue;
      const m = s as Record<string, unknown>;
      if (typeof m.cap === 'string' && typeof m.file === 'string' && typeof m.line === 'number' && typeof m.text === 'string')
        samples.push({ cap: m.cap, file: m.file.slice(0, 512), line: Math.floor(m.line), text: m.text.slice(0, 200) });
    }
  }
  const score = typeof o.score === 'number' && Number.isFinite(o.score) ? o.score : undefined;
  if (Object.keys(counts).length === 0 && samples.length === 0) return null;
  return { counts, score, samples };
}

/**
 * "详细信息"按钮：展开某条 Skill 发现的能力命中证据——四类能力各命中几处、综合分，
 * 以及每处命中到底在技能包里哪个文件的哪一行、那一行写了什么。让安全运营据此核对
 * 是真命中还是文档里的无害提及（如 README 里只是"提到"了 curl），避免误伤加白/拉黑。
 */
export function SignalDetails({ matches }: { matches?: unknown }) {
  const [open, setOpen] = useState(false);
  const data = parseSignalMatches(matches);
  if (!data) return null;
  const { counts, score, samples } = data;
  const grouped = CAP_ORDER.map((cap) => ({ cap, items: samples.filter((s) => s.cap === cap) })).filter(
    (g) => (counts[g.cap] ?? 0) > 0 || g.items.length > 0,
  );
  return (
    <span style={{ display: 'block', marginTop: 4 }}>
      <button
        className="handle"
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
        style={{ fontSize: 11, background: 'none', border: 'none', cursor: 'pointer', color: 'var(--primary)', padding: 0 }}
      >
        详细信息{open ? ' ▴' : ' ▾'}
      </button>
      {open && (
        <div
          style={{
            marginTop: 6,
            padding: 8,
            border: '1px solid var(--border)',
            borderRadius: 8,
            fontSize: 11,
            lineHeight: 1.7,
          }}
        >
          <div style={{ marginBottom: 4, color: 'var(--muted-foreground)' }}>
            能力命中处数（数字=命中几处，非危险度）：
            {CAP_ORDER.filter((c) => (counts[c] ?? 0) > 0).map((c) => (
              <span key={c} style={{ marginRight: 8 }}>
                {SIGNAL_LABEL[c]} <b>{counts[c]}</b> 处
              </span>
            ))}
            {score !== undefined && (
              <>
                · 综合分 <b>{score}</b>（{scoreBand(score).label}）
              </>
            )}
          </div>
          <div style={{ marginBottom: 4, color: 'var(--muted-foreground)' }}>
            命中位置（据此核对到底引用了哪个文件的哪一行、触发了计数；样本有界，超出部分只计处数不逐条展示）：
          </div>
          {grouped.map(({ cap, items }) => (
            <div key={cap} style={{ marginBottom: 4 }}>
              <b>
                {SIGNAL_LABEL[cap] ?? cap}
                <span style={{ fontWeight: 400, color: 'var(--muted-foreground)' }}>
                  {' '}
                  （共 {counts[cap] ?? items.length} 处，展示 {items.length} 处）
                </span>
              </b>
              {items.length > 0 ? (
                <ul style={{ margin: '2px 0 0', paddingLeft: 16 }}>
                  {items.map((m, i) => (
                    <li key={i} style={{ wordBreak: 'break-all' }}>
                      <code style={{ opacity: 0.85 }}>
                        {m.file}:{m.line}
                      </code>{' '}
                      <span style={{ color: 'var(--muted-foreground)' }}>{m.text || '（该行无可显示内容）'}</span>
                    </li>
                  ))}
                </ul>
              ) : (
                <div style={{ color: 'var(--muted-foreground)', paddingLeft: 16 }}>仅计入处数，无逐条样本。</div>
              )}
            </div>
          ))}
          {grouped.length === 0 && (
            <div style={{ color: 'var(--muted-foreground)' }}>该发现未附带可展示的命中位置。</div>
          )}
        </div>
      )}
    </span>
  );
}
