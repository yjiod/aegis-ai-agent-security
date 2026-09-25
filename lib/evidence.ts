/**
 * lib/evidence.ts — 审计/证据导出包（aegis.evidence/v1）。
 *
 * 目的：把散在审计日志、发现、工单、执行回执、终端清单、策略姿态里的证据，
 * 一次性打包成**自描述、防篡改、可离线验证**的单个 JSON 文件，用于应急响应、
 * 合规留档、向安全团队/审计方交接。
 *
 * 三条硬约束（对齐企业安全基线 SEC-AGT-04 / SEC-MCP-03 / 数据分级）：
 *   1) 字段白名单：每个 section 只映射固定字段，绝不 dump 原始 device/report 对象，
 *      签名密钥/会话密钥/Collector 令牌/PG URL/设备令牌一律不进包。
 *   2) 脱敏分级：standard（默认）伪名化个人标识（os_user→hash）、路径 ~/ 前缀、
 *      IP/MAC/序列号打码、secret→[REDACTED]、证据文本截断 180；verbose（仅管理员）
 *      保留运维细节但 secret 永远打码。
 *   3) 防篡改：整包 canonical（剔除 ed25519_* 字段）经 ed25519 签名，公钥随包携带，
 *      任何持有该文件的人都能离线验签（scripts/verify-evidence-bundle.py）。
 *
 * 签名约定与 lib/policy.ts 的策略双签一致：ed25519 覆盖「不含 ed25519_* 字段」的
 * canonicalJson，故离线验签逻辑可直接复用 agent 的 verify_policy_ed25519 形态。
 */

import { createHash } from 'node:crypto';
import { canonicalJson, ed25519PolicyFields, currentPolicyRelease, ensurePolicyReleasesLoaded } from '@/lib/policy';
import { getAuditStore, getTicketStore, type Ticket } from '@/lib/store';
import { getRollout, inRollout } from '@/lib/rollout';

export const EVIDENCE_SCHEMA = 'aegis.evidence/v1';

export type RedactionLevel = 'standard' | 'verbose';
export type EvidenceSection = 'audit' | 'findings' | 'tickets' | 'enforcement' | 'inventory' | 'policy' | 'canary';
export const EVIDENCE_SECTIONS: readonly EvidenceSection[] = ['audit', 'findings', 'tickets', 'enforcement', 'inventory', 'policy', 'canary'] as const;

/** 各 section 的条数上限，避免长生命周期 isolate 里无限膨胀 / 单包过大。 */
const CAPS: Record<EvidenceSection, number> = {
  audit: 5_000,
  findings: 5_000,
  tickets: 2_000,
  enforcement: 2_000,
  inventory: 10_000,
  policy: 1,
  canary: 1,
};

const TEXT_TRUNC = 180;

/* ─── 脱敏原语 ─────────────────────────────────────────────── */

/** secret 特征（覆盖常见云/代码托管/CI/IM/JWT/私钥），命中即整段替换。 */
const SECRET_PATTERNS: RegExp[] = [
  /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g,
  /\bAKIA[0-9A-Z]{16}\b/g,
  /\bsk-[A-Za-z0-9_-]{20,}\b/g,
  /\bghp_[A-Za-z0-9]{30,}\b/g,
  /\bgho_[A-Za-z0-9]{30,}\b/g,
  /\bgithub_pat_[A-Za-z0-9_]{20,}\b/g,
  /\bglpat-[A-Za-z0-9_-]{20,}\b/g,
  /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g,
  /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g,
];

/** key=value / key: value 形式的凭据赋值（保守：只对明确的凭据键名打码值）。 */
const KV_SECRET = /\b(password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|authorization|bearer)\b(\s*[:=]\s*)([^\s,;"]+)/gi;

/** 无论何种级别都永远打码 secret（证据包不是凭据搬运工）。 */
export function maskSecrets(input: string): string {
  let out = input;
  for (const re of SECRET_PATTERNS) out = out.replace(re, '[REDACTED]');
  out = out.replace(KV_SECRET, (_m, k: string, sep: string) => `${k}${sep}[REDACTED]`);
  return out;
}

function truncate(input: string, max = TEXT_TRUNC): string {
  return input.length > max ? `${input.slice(0, max)}…` : input;
}

/** 安全字符串化：只接受原始类型，对象/数组一律 ''（避免 '[object Object]' 污染证据）。 */
function asStr(v: unknown): string {
  if (typeof v === 'string') return v;
  if (typeof v === 'number' || typeof v === 'boolean') return String(v);
  return '';
}

/** 自由文本：永远打码 secret + 截断。路径/IP 等结构化打码由调用方按级别处理。 */
export function scrubText(input: unknown, level: RedactionLevel): string {
  const s = maskSecrets(asStr(input));
  const home = level === 'standard' ? homePrefix(s) : s;
  return truncate(home);
}

/** 用户主目录前缀化：/Users/name/… /home/name/… C:\Users\name\… → ~/…（standard）。 */
export function homePrefix(path: string): string {
  return path
    .replace(/\/Users\/[^/\s]+/g, '~')
    .replace(/\/home\/[^/\s]+/g, '~')
    .replace(/[A-Za-z]:\\Users\\[^\\\s]+/g, '~');
}

/** 个人标识伪名化：稳定 hash（同一用户跨包一致，便于关联但不泄露工号/姓名）。 */
export function pseudonymize(value: unknown): string {
  const s = asStr(value);
  if (!s) return '';
  return `user:${createHash('sha256').update(s).digest('hex').slice(0, 10)}`;
}

function maskIpv4(ip: string): string {
  const parts = ip.split('.');
  if (parts.length !== 4 || parts.some((p) => !/^\d{1,3}$/.test(p))) return ip;
  return `${parts[0]}.${parts[1]}.x.x`;
}
/** IP 打码：IPv4 保留前两段，IPv6 保留前两组（standard）。 */
export function maskIp(ip: unknown): string {
  const s = asStr(ip);
  if (!s) return '';
  if (s.includes('.')) return maskIpv4(s);
  if (s.includes(':')) return `${s.split(':').slice(0, 2).join(':')}:…`;
  return s;
}
/** MAC 打码：保留前 3 段（standard）。 */
export function maskMac(mac: unknown): string {
  const s = asStr(mac);
  const parts = s.split(/[:-]/);
  if (parts.length < 4) return s;
  return `${parts.slice(0, 3).join(':')}:xx:xx:xx`;
}
/** 序列号打码：保留前 3 + 后 2（standard）。 */
export function maskSerial(serial: unknown): string {
  const s = asStr(serial);
  if (s.length <= 5) return s;
  return `${s.slice(0, 3)}${'*'.repeat(Math.min(6, s.length - 5))}${s.slice(-2)}`;
}

function sha256(value: unknown): string {
  return createHash('sha256').update(canonicalJson(value)).digest('hex');
}

/* ─── Collector 原始数据拉取（全字段，非 lite）────────────────── */

interface RawDevice {
  device_id: string;
  hostname?: string;
  os?: string;
  os_user?: string;
  serial?: string;
  agent_version?: string;
  policy_version?: string;
  last_seen?: number;
  run_mode?: string;
  run_mode_inferred?: boolean;
  capabilities?: { pf?: boolean; es?: boolean };
  scan_root?: string;
  tools?: string[];
  network?: { physical_nics?: { name: string; mac: string; ips?: string[] }[]; macs?: string[]; local_ips?: string[]; egress_ip?: string };
  latest_severity?: { critical: number; high: number; medium: number; low: number };
  enforcement?: { asset_type: string; asset_key: string; action: string; target?: string; backup?: string; reason?: string; ok?: boolean; at?: number }[];
  exempt?: boolean;
  pinned?: boolean;
  self_update?: { updated?: boolean; reason?: string; from?: string; to?: string; latest?: string; at?: number };
}

function collectorCreds(): { url: string; token: string } | null {
  const url = process.env.AEGIS_COLLECTOR_URL;
  const token = process.env.AEGIS_COLLECTOR_TOKEN;
  return url && token ? { url: url.replace(/\/$/, ''), token } : null;
}

async function fetchRawDevices(): Promise<RawDevice[] | null> {
  const c = collectorCreds();
  if (!c) return null;
  try {
    // P1-4：游标翻页遍历全量舰队（旧实现单页 limit=10000 封顶 → 30k 证据只覆盖前 1 万台）。
    const all: RawDevice[] = [];
    let cursor = '';
    for (let page = 0; page < 200; page += 1) {
      const qs = new URLSearchParams({ limit: '10000' });
      if (cursor) qs.set('cursor', cursor);
      const res = await fetch(`${c.url}/v1/devices?${qs.toString()}`, {
        headers: { Authorization: `Bearer ${c.token}`, Accept: 'application/json' },
        cache: 'no-store',
        signal: AbortSignal.timeout(6000),
      });
      if (!res.ok) return null;
      const data = (await res.json()) as { devices?: RawDevice[]; complete?: boolean; next_cursor?: string };
      if (Array.isArray(data.devices)) all.push(...data.devices);
      cursor = typeof data.next_cursor === 'string' ? data.next_cursor : '';
      if (data.complete !== false || !cursor) break;
    }
    return all;
  } catch {
    return null;
  }
}

interface RawFinding {
  kind?: unknown; severity?: unknown; path?: unknown; message?: unknown;
  asset_type?: unknown; asset_key?: unknown;
}
async function fetchDeviceFindings(deviceId: string): Promise<{ scanned_at: number; findings: RawFinding[] } | null> {
  const c = collectorCreds();
  if (!c) return null;
  try {
    const res = await fetch(`${c.url}/v1/findings?device_id=${encodeURIComponent(deviceId)}&limit=1000`, {
      headers: { Authorization: `Bearer ${c.token}`, Accept: 'application/json' },
      cache: 'no-store',
      signal: AbortSignal.timeout(6000),
    });
    if (!res.ok) return null;
    const data = (await res.json()) as { scanned_at?: unknown; findings?: unknown };
    return {
      scanned_at: typeof data.scanned_at === 'number' ? data.scanned_at : 0,
      findings: Array.isArray(data.findings) ? (data.findings as RawFinding[]) : [],
    };
  } catch {
    return null;
  }
}

/* ─── 组装选项与包结构 ─────────────────────────────────────── */

export interface EvidenceOptions {
  actor: string;
  deviceId?: string | null;
  since?: number | null; // epoch ms
  until?: number | null; // epoch ms
  sections: EvidenceSection[];
  redaction: RedactionLevel;
  consoleVersion?: string;
}

export interface EvidenceBundle {
  schema: string;
  generated_at: number;
  generated_by: string;
  scope: { device_id: string | null; since: number | null; until: number | null };
  redaction: RedactionLevel;
  console: { collector_connected: boolean; version: string };
  sections: Record<string, unknown>;
  manifest: Record<string, { count: number; sha256: string }>;
  report_markdown: string;
  integrity?: 'unsigned';
  ed25519_signature?: string;
  ed25519_public?: string;
  ed25519_key_id?: string;
}

function inWindow(ts: number | undefined, since: number | null, until: number | null): boolean {
  if (ts === undefined || ts === null || !ts) return since === null && until === null ? true : false;
  if (since !== null && ts < since) return false;
  if (until !== null && ts > until) return false;
  return true;
}

function connectivityStatus(lastSeenSec?: number): string {
  const now = Math.floor(Date.now() / 1000);
  if (!lastSeenSec) return 'offline';
  if (now - lastSeenSec > 86400) return 'offline';
  if (now - lastSeenSec > 7200) return 'stale';
  return 'online';
}

/* ─── 各 section 映射（字段白名单 + 按级别脱敏）──────────────── */

function mapInventory(devices: RawDevice[], level: RedactionLevel, deviceId: string | null) {
  return devices
    .filter((d) => (deviceId ? d.device_id === deviceId : true))
    .slice(0, CAPS.inventory)
    .map((d) => {
      const net = d.network;
      const macs = (net?.macs ?? []).map((m) => (level === 'standard' ? maskMac(m) : m));
      const localIps = (net?.local_ips ?? []).map((ip) => (level === 'standard' ? maskIp(ip) : ip));
      return {
        device_id: d.device_id,
        hostname: level === 'standard' ? scrubText(d.hostname ?? '', level) : (d.hostname ?? ''),
        os: d.os ?? '',
        os_user: level === 'standard' ? pseudonymize(d.os_user) : (d.os_user ?? ''),
        serial: level === 'standard' ? maskSerial(d.serial) : (d.serial ?? ''),
        agent_version: d.agent_version ?? '',
        policy_version: d.policy_version ?? '',
        status: connectivityStatus(d.last_seen),
        last_seen_epoch_s: d.last_seen ?? 0,
        run_mode: d.run_mode ?? '',
        run_mode_inferred: d.run_mode_inferred === true,
        capabilities: { pf: d.capabilities?.pf === true, es: d.capabilities?.es === true },
        exempt: d.exempt === true,
        pinned: d.pinned === true,
        tools: Array.isArray(d.tools) ? d.tools.slice(0, 32) : [],
        scan_root: level === 'standard' ? homePrefix(d.scan_root ?? '') : (d.scan_root ?? ''),
        network: { macs: macs.slice(0, 8), local_ips: localIps.slice(0, 8), egress_ip: level === 'standard' ? maskIp(net?.egress_ip) : (net?.egress_ip ?? '') },
        latest_severity: d.latest_severity ?? { critical: 0, high: 0, medium: 0, low: 0 },
        // 自更非例行结果（成功更新/被 preflight 拒绝/自动回滚/应用失败）：让证据包能讲清
        // "这台机器更新发生了什么"。reason/from/to/latest 为版本/状态串，不含敏感信息。
        ...(d.self_update ? { self_update: d.self_update } : {}),
      };
    });
}

/** canary/自更态势 section：导出时刻的灰度配置 + 已发布策略的 agent_self_update + 坏自更设备清单。 */
function mapCanary(devices: RawDevice[], deviceId: string | null) {
  const rollout = getRollout();
  const rel = currentPolicyRelease();
  const publishedSu = (rel?.policy as { agent_self_update?: Record<string, unknown> } | undefined)?.agent_self_update ?? null;
  const scoped = deviceId ? devices.filter((d) => d.device_id === deviceId) : devices;
  const bad = scoped
    .filter((d) => {
      const r = d.self_update?.reason ?? '';
      return !!r && r !== 'ok' && (r.startsWith('preflight_failed') || r.startsWith('rolled_back') || r.startsWith('apply_failed'));
    })
    .map((d) => ({ device_id: d.device_id, hostname: d.hostname ?? '', reason: d.self_update?.reason ?? '', latest: d.self_update?.latest ?? '', at: d.self_update?.at ?? 0 }));
  const inCanary = scoped.filter((d) => inRollout(d.device_id, rollout.rollout_percent)).length;
  return {
    rollout,
    published_agent_self_update: publishedSu,
    total: scoped.length,
    in_canary: inCanary,
    bad_self_updates: bad,
  };
}

function mapEnforcement(devices: RawDevice[], level: RedactionLevel, deviceId: string | null, since: number | null, until: number | null) {
  const out: Array<Record<string, unknown>> = [];
  for (const d of devices) {
    if (deviceId && d.device_id !== deviceId) continue;
    for (const e of d.enforcement ?? []) {
      // enforcement.at 为 epoch ms；无时间戳的回执仅在未设时间窗时纳入。
      if ((since !== null || until !== null) && !inWindow(e.at, since, until)) continue;
      out.push({
        device_id: d.device_id,
        asset_type: String(e.asset_type ?? ''),
        asset_key: scrubText(e.asset_key ?? '', level),
        action: String(e.action ?? ''),
        target: level === 'standard' ? homePrefix(String(e.target ?? '')) : String(e.target ?? ''),
        backup: level === 'standard' ? homePrefix(String(e.backup ?? '')) : String(e.backup ?? ''),
        reason: scrubText(e.reason ?? '', level),
        ok: e.ok === true,
        at: e.at ?? 0,
      });
      if (out.length >= CAPS.enforcement) return out;
    }
  }
  return out;
}

const SEVERITY_KEEP = new Set(['critical', 'high', 'medium', 'low']);
function mapFindings(raw: Array<{ device_id: string; scanned_at: number; f: RawFinding }>, level: RedactionLevel, since: number | null, until: number | null) {
  const out: Array<Record<string, unknown>> = [];
  for (const { device_id, scanned_at, f } of raw) {
    const scannedMs = scanned_at > 1e12 ? scanned_at : scanned_at * 1000;
    if ((since !== null || until !== null) && !inWindow(scannedMs, since, until)) continue;
    const sev = typeof f.severity === 'string' && SEVERITY_KEEP.has(f.severity) ? f.severity : 'low';
    out.push({
      device_id,
      kind: typeof f.kind === 'string' ? f.kind : '',
      severity: sev,
      path: level === 'standard' ? homePrefix(asStr(f.path)) : asStr(f.path),
      message: scrubText(f.message ?? '', level),
      ...(typeof f.asset_type === 'string' ? { asset_type: f.asset_type } : {}),
      ...(typeof f.asset_key === 'string' ? { asset_key: scrubText(f.asset_key, level) } : {}),
      scanned_at: scanned_at || 0,
    });
    if (out.length >= CAPS.findings) break;
  }
  const rank: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
  out.sort((a, b) => (rank[String(a.severity)] ?? 9) - (rank[String(b.severity)] ?? 9) || Number(b.scanned_at) - Number(a.scanned_at));
  return out;
}

function mapTickets(tickets: Ticket[], level: RedactionLevel, deviceId: string | null, since: number | null, until: number | null) {
  return tickets
    .filter((t) => (deviceId ? t.device_id === deviceId : true))
    .filter((t) => (since !== null || until !== null ? inWindow(t.updated_at, since, until) || inWindow(t.created_at, since, until) : true))
    .slice(0, CAPS.tickets)
    .map((t) => ({
      ticket_id: t.ticket_id,
      title: scrubText(t.title, level),
      severity: t.severity,
      status: t.status,
      source: t.source,
      device_id: t.device_id,
      description: t.description === undefined ? undefined : scrubText(t.description, level),
      assignee: t.assignee === undefined ? undefined : (level === 'standard' ? pseudonymize(t.assignee) : t.assignee),
      created_at: t.created_at,
      updated_at: t.updated_at,
      resolved_at: t.resolved_at ?? 0,
      history: (t.history ?? []).map((h) => ({ action: h.action, actor: level === 'standard' && h.actor !== 'aegis-collector' ? pseudonymize(h.actor) : h.actor, timestamp: h.timestamp, note: h.note === undefined ? undefined : scrubText(h.note, level) })),
    }));
}

function mapAudit(level: RedactionLevel, deviceId: string | null, since: number | null, until: number | null, collectorEntries: Array<Record<string, unknown>>) {
  const consoleEntries = getAuditStore().map((e) => ({ ...e, source: 'console' }));
  const merged = [...collectorEntries.map((e) => ({ ...e, source: 'collector' })), ...consoleEntries] as Array<Record<string, unknown>>;
  return merged
    .filter((e) => (since !== null || until !== null ? inWindow(Number(e.timestamp), since, until) : true))
    .filter((e) => (deviceId ? asStr(e.resource_id).includes(deviceId) || asStr(e.detail).includes(deviceId) : true))
    .sort((a, b) => Number(b.timestamp) - Number(a.timestamp))
    .slice(0, CAPS.audit)
    .map((e) => ({
      timestamp: Number(e.timestamp ?? 0),
      actor: level === 'standard' && e.actor !== 'aegis-collector' && e.actor !== 'collector' ? pseudonymize(e.actor) : asStr(e.actor),
      action: asStr(e.action),
      resource_type: asStr(e.resource_type) || 'system',
      resource_id: e.resource_id === undefined ? undefined : asStr(e.resource_id),
      detail: e.detail === undefined ? undefined : scrubText(e.detail, level),
      source: asStr(e.source),
    }));
}

function mapPolicy(devices: RawDevice[], requiredAgent: string) {
  const rel = currentPolicyRelease();
  const reported = devices.filter((d) => (d.agent_version ?? '').trim() && (d.policy_version ?? '').trim());
  const reqPolicy = rel ? rel.policy.version : '';
  const policyDrift = reqPolicy ? reported.filter((d) => (d.policy_version ?? '') !== reqPolicy).length : 0;
  const agentDrift = requiredAgent ? reported.filter((d) => (d.agent_version ?? '') !== requiredAgent).length : 0;
  return {
    release_id: rel?.release_id ?? '',
    policy_version: rel?.policy.version ?? '',
    published_at: rel?.created_at ?? 0,
    published_by: rel?.created_by ?? '',
    signing_key_id: rel?.signing_key_id ?? '',
    label_counts: rel?.receipt.label_counts ?? { allow: 0, monitor: 0, deny: 0 },
    scan_mode: rel?.policy.scan_mode ?? '',
    enforcement: rel?.policy.enforcement ?? {},
    modules: rel?.policy.modules ?? {},
    required_agent_version: requiredAgent,
    devices_reported: reported.length,
    agent_version_drift: agentDrift,
    policy_version_drift: policyDrift,
    enforce_exempt_count: Array.isArray(rel?.policy.enforce_exempt) ? rel!.policy.enforce_exempt.length : 0,
  };
}

/* ─── 人类可读叙述（report_markdown）───────────────────────── */

function buildReport(opts: EvidenceOptions, generatedAt: number, sections: Record<string, unknown>, connected: boolean, counts: Record<string, number>): string {
  const L: string[] = [];
  const dt = new Date(generatedAt).toISOString();
  L.push(`# Aegis 证据包（${EVIDENCE_SCHEMA}）`);
  L.push('');
  L.push(`- 生成时间：${dt}`);
  L.push(`- 生成者：${opts.actor}`);
  L.push(`- 范围：${opts.deviceId ? `单设备 ${opts.deviceId}` : '全舰队'}${opts.since || opts.until ? `（时间窗 ${opts.since ?? '…'} ~ ${opts.until ?? '…'}）` : ''}`);
  L.push(`- 脱敏级别：${opts.redaction}（standard=个人标识伪名化+路径/IP 打码；verbose=保留运维细节，secret 恒打码）`);
  L.push(`- Collector：${connected ? '已连接（实时数据）' : '不可达（仅控制台侧数据）'}`);
  L.push('');
  L.push('## 内容是什么');
  L.push('');
  L.push('| Section | 条数 | 说明 |');
  L.push('|---|---|---|');
  const desc: Record<string, string> = {
    inventory: '受管终端清单（版本/运行态/能力/网络标识）',
    findings: '真实扫描发现（按严重度排序，含资产定位）',
    tickets: '风险工单及完整流转历史',
    enforcement: '终端执行回执（封禁/隔离/恢复动作与备份位置）',
    audit: '审计日志（Collector + 控制台两源合并）',
    policy: '生效策略姿态（版本/签名密钥 id/漂移计数）',
    canary: '灰度/自更态势（导出时刻放量配置 + 已发布 agent_self_update + 坏自更设备清单）',
  };
  for (const name of EVIDENCE_SECTIONS) {
    if (name in sections) L.push(`| ${name} | ${counts[name] ?? 0} | ${desc[name]} |`);
  }
  L.push('');
  L.push('## 为何需要关注');
  L.push('');
  const findings = (sections.findings ?? []) as Array<Record<string, unknown>>;
  const crit = findings.filter((f) => f.severity === 'critical').length;
  const high = findings.filter((f) => f.severity === 'high').length;
  const enf = (sections.enforcement ?? []) as Array<Record<string, unknown>>;
  const openTickets = ((sections.tickets ?? []) as Array<Record<string, unknown>>).filter((t) => t.status !== 'resolved' && t.status !== 'dismissed').length;
  L.push(`- 发现：critical ${crit} 条、high ${high} 条。`);
  L.push(`- 未闭环工单：${openTickets} 张。`);
  L.push(`- 已执行处置回执：${enf.length} 条（封禁/隔离/恢复，含备份位置，可据此回滚）。`);
  L.push('');
  L.push('## 风险判断');
  L.push('');
  if (crit > 0) L.push(`- 存在 ${crit} 条 critical 发现，须优先研判：确认是否已产生实际外泄/越权，再决定处置。`);
  else if (high > 0) L.push(`- 无 critical，但有 ${high} 条 high 发现，建议在本周期内研判。`);
  else L.push('- 无 critical/high 发现，当前为常规留档。');
  if (!connected) L.push('- Collector 不可达：本包只含控制台侧数据，终端实时发现/回执可能缺失，结论以此为限。');
  L.push('');
  L.push('## 完整性');
  L.push('');
  L.push('- 本包经 ed25519 签名，公钥随包携带（ed25519_public）。');
  L.push('- 离线验证：`python3 scripts/verify-evidence-bundle.py <bundle.json>`；任一字节被改即验签失败。');
  L.push('- 每个 section 的 sha256 记录在 manifest，可逐节核对内容未被局部替换。');
  L.push('');
  return L.join('\n');
}

/* ─── 主入口：组装并签名 ───────────────────────────────────── */

/**
 * 取 Collector 侧审计并归一化进证据包。
 *
 * 注意：这里的过滤是**签名完整性**的一部分，不是防御性冗余：证据包经 ed25519 签名，
 * 任何进入 audit 节的记录都会获得"已被权威签署"的可信外观。修复前若只修好路由 404
 * 而字段名/时间单位仍不匹配，每条 Collector 记录都会变成
 * `{action: undefined, timestamp: undefined, actor: 'collector'}` 被签进包里 ——
 * 也就是**给残缺记录以可信外观**，比取不到数据更糟（取证方会以为审计链完整）。
 *
 * 因此：动作名或时间戳缺失/非法的记录一律**丢弃**，且丢弃计数如实回传，
 * 绝不静默塞进包里，也绝不伪装成"审计就这么多"。
 *
 * 兼容新旧 Collector 两种形状（`entries`+action/timestamp 毫秒 ｜ `events`+event/occurred_at 秒），
 * 时间单位按**字段名**判定而非按数量级猜（后者会在 2286 年后静默判错）。
 */
async function fetchCollectorAudit(): Promise<{ rows: Array<Record<string, unknown>>; dropped: number }> {
  const c = collectorCreds();
  if (!c) return { rows: [], dropped: 0 };
  try {
    const res = await fetch(`${c.url}/v1/audit?limit=1000`, {
      headers: { Authorization: `Bearer ${c.token}`, Accept: 'application/json' },
      cache: 'no-store',
      signal: AbortSignal.timeout(6000),
    });
    if (!res.ok) return { rows: [], dropped: 0 };
    const data = (await res.json()) as Record<string, unknown>;
    const list = Array.isArray(data.entries)
      ? data.entries
      : Array.isArray(data.events)
        ? data.events
        : Array.isArray(data) ? data : [];
    const rows: Array<Record<string, unknown>> = [];
    let dropped = 0;
    (list as Array<Record<string, unknown>>).forEach((e, i) => {
      // 非对象记录（null / 字符串 / 数组）直接计入丢弃。必须先挡这一层：否则下面
      // 读 e.action 会抛 TypeError，而整个 fetch 包在 try/catch 里 → **一条畸形记录
      // 就会把整节审计静默清空**（return { rows: [], dropped: 0 }），签名包里
      // audit 节变成空且 dropped=0，看起来像"本来就没有审计"。那是最坏的失败形态：
      // 既丢数据又谎报完整。
      if (!e || typeof e !== 'object') { dropped += 1; return; }
      const action = typeof e.action === 'string' && e.action
        ? e.action
        : typeof e.event === 'string' ? e.event : '';
      const ms = typeof e.timestamp === 'number' && Number.isFinite(e.timestamp) ? e.timestamp : null;
      const sec = typeof e.occurred_at === 'number' && Number.isFinite(e.occurred_at) ? e.occurred_at * 1000 : null;
      const timestamp = ms ?? sec;
      // 残缺记录宁可不进包：没有动作名或没有可信时间的审计条目无法检索、无法归因、
      // 无法按区间取证，签进包里只会给出不实的"审计完整"印象。
      if (!action || timestamp === null) { dropped += 1; return; }
      const deviceId = typeof e.device_id === 'string' ? e.device_id : '';
      const resourceId = typeof e.resource_id === 'string' && e.resource_id ? e.resource_id : deviceId;
      rows.push({
        id: typeof e.id === 'number' ? e.id : i + 1,
        timestamp,
        actor: typeof e.actor === 'string' && e.actor ? e.actor : deviceId || 'collector',
        action,
        resource_type: typeof e.resource_type === 'string' && e.resource_type
          ? e.resource_type
          : deviceId ? 'device' : 'system',
        ...(resourceId ? { resource_id: resourceId } : {}),
        ...(typeof e.detail === 'string' ? { detail: e.detail } : {}),
        source: 'collector',
      });
    });
    return { rows, dropped };
  } catch {
    return { rows: [], dropped: 0 };
  }
}

/** manifest 最新 agent 版本（用于 policy section 的 required_agent_version 参考）。
 *  服务端自取需绝对 URL：用 AEGIS_PUBLIC_ORIGIN 拼 /downloads/update-manifest.json；
 *  未配置或取不到则返回 ''（agent 漂移计数随之为 0，不影响包的其余部分）。 */
async function fetchManifestAgentVersion(): Promise<string> {
  const origin = process.env.AEGIS_PUBLIC_ORIGIN;
  if (!origin) return '';
  try {
    const res = await fetch(`${origin.replace(/\/$/, '')}/downloads/update-manifest.json`, {
      cache: 'no-store',
      signal: AbortSignal.timeout(3000),
    });
    if (!res.ok) return '';
    const data = (await res.json()) as { agent_version?: unknown };
    return typeof data.agent_version === 'string' ? data.agent_version : '';
  } catch {
    return '';
  }
}

export async function buildEvidenceBundle(opts: EvidenceOptions): Promise<EvidenceBundle> {
  const want = new Set(opts.sections);
  const level = opts.redaction;
  const deviceId = opts.deviceId ?? null;
  const since = opts.since ?? null;
  const until = opts.until ?? null;

  // policy/canary section 依赖已发布策略；workerd isolate 需先水合 releases，否则
  // currentPolicyRelease() 为 null → published_agent_self_update/policy 段缺失。
  await ensurePolicyReleasesLoaded().catch(() => {});

  // 单次拉取全量终端（null=Collector 不可达）；connected 据此诚实标注。
  const devicesOrNull = await fetchRawDevices();
  const collectorConnected = devicesOrNull !== null;
  const devices = devicesOrNull ?? [];

  const rawSections: Record<string, unknown> = {};
  const counts: Record<string, number> = {};
  /** 被丢弃（未签入 audit 节）的残缺 Collector 审计记录数；0 = 无丢弃。 */
  let auditIncompleteDropped = 0;

  if (want.has('inventory')) { const v = mapInventory(devices, level, deviceId); rawSections.inventory = v; counts.inventory = v.length; }
  if (want.has('enforcement')) { const v = mapEnforcement(devices, level, deviceId, since, until); rawSections.enforcement = v; counts.enforcement = v.length; }
  if (want.has('findings')) {
    const raw: Array<{ device_id: string; scanned_at: number; f: RawFinding }> = [];
    if (deviceId) {
      // 单设备取证：一次 /v1/findings 即可（本就无扇出）。
      const res = await fetchDeviceFindings(deviceId);
      if (res) for (const f of res.findings) raw.push({ device_id: deviceId, scanned_at: res.scanned_at, f });
    } else {
      // P1-1：全舰队取证改游标翻页聚合端点，取代对每台设备各发一个 /v1/findings 的 N+1 扇出
      // （30k 下旧写法一次导出最多 1 万并发）。since/until/level 仍由 mapFindings 单一裁决，
      // 不下推服务端，保证取证语义与既有完全一致；任一页失败即停止累积（诚实反映已取部分）。
      const c = collectorCreds();
      if (c) {
        let cursor = '';
        for (let page = 0; page < 200; page += 1) {
          const qs = new URLSearchParams({ limit: '1000' });
          if (cursor) qs.set('cursor', cursor);
          let data: { complete?: boolean; next_cursor?: string; findings?: Array<{ device_id: string; scanned_at: number; finding: RawFinding }> };
          try {
            const res = await fetch(`${c.url}/v1/findings/aggregate?${qs.toString()}`, {
              headers: { Authorization: `Bearer ${c.token}`, Accept: 'application/json' },
              cache: 'no-store',
              signal: AbortSignal.timeout(8000),
            });
            if (!res.ok) break;
            data = (await res.json()) as typeof data;
          } catch {
            break;
          }
          for (const item of data.findings ?? []) raw.push({ device_id: item.device_id, scanned_at: item.scanned_at, f: item.finding });
          cursor = typeof data.next_cursor === 'string' ? data.next_cursor : '';
          if (data.complete !== false || !cursor) break;
        }
      }
    }
    const v = mapFindings(raw, level, since, until); rawSections.findings = v; counts.findings = v.length;
  }
  if (want.has('tickets')) { const v = mapTickets([...getTicketStore().values()], level, deviceId, since, until); rawSections.tickets = v; counts.tickets = v.length; }
  if (want.has('audit')) {
    const coll = await fetchCollectorAudit();
    // 因缺动作名/缺可信时间戳而被丢弃、未签入 audit 节的 Collector 记录数（见
    // fetchCollectorAudit 的说明）。非 0 即说明 Collector 契约再次漂移，必须披露。
    auditIncompleteDropped = coll.dropped;
    const v = mapAudit(level, deviceId, since, until, coll.rows); rawSections.audit = v; counts.audit = v.length;
  }
  if (want.has('policy')) {
    const reqAgent = await fetchManifestAgentVersion();
    const scoped = deviceId ? devices.filter((d) => d.device_id === deviceId) : devices;
    const v = mapPolicy(scoped, reqAgent); rawSections.policy = [v]; counts.policy = 1;
  }
  if (want.has('canary')) {
    const v = mapCanary(devices, deviceId); rawSections.canary = v; counts.canary = 1;
  }

  const manifest: Record<string, { count: number; sha256: string }> = {};
  // 归一化：JSON 往返一次，剔除值为 undefined 的键（mapper 用条件字段会产生）。
  // 否则 build 期对"含 undefined 键"的对象算哈希，而传输(JSON.stringify)会丢这些键，
  // 接收方 verify 期对"无 undefined 键"的对象重算 → manifest 必然不符。归一化后
  // 「被哈希的 sections」与「被传输/接收的 sections」逐字节一致。
  const sections = JSON.parse(JSON.stringify(rawSections)) as Record<string, unknown>;
  for (const [name, value] of Object.entries(sections)) manifest[name] = { count: counts[name] ?? 0, sha256: sha256(value) };

  const generatedAt = Date.now();
  const core = {
    schema: EVIDENCE_SCHEMA,
    generated_at: generatedAt,
    generated_by: opts.actor,
    scope: { device_id: deviceId, since, until },
    redaction: level,
    console: { collector_connected: collectorConnected, version: opts.consoleVersion ?? '' },
    // 诚实披露：**仅在有丢弃时**才出现该键，正常包（dropped=0）字节保持不变，
    // 因此既有证据包与离线验签脚本完全不受影响。
    // 非 0 表示有 Collector 审计记录因缺动作名或缺可信时间戳被剔除、未签入 audit 节
    // —— 通常意味着 Collector 契约再次漂移（字段名 / 时间单位）。取证方必须知道
    // audit 节因此不完整；绝不能把"过滤后的残缺审计"包装成"完整审计"。
    ...(auditIncompleteDropped > 0 ? { audit_incomplete_dropped: auditIncompleteDropped } : {}),
    sections,
    manifest,
    report_markdown: buildReport(opts, generatedAt, sections, collectorConnected, counts),
  };

  const canonical = canonicalJson(core);
  const ed = await ed25519PolicyFields(canonical);
  return ed
    ? { ...core, ed25519_signature: ed.ed25519_signature, ed25519_public: ed.ed25519_public, ed25519_key_id: ed.ed25519_key_id }
    : { ...core, integrity: 'unsigned' };
}

/* ─── 验签（TS 侧，供 /api/evidence/verify 便捷入口）────────────
 * 与 scripts/verify-evidence-bundle.py 逻辑一致：剔除 ed25519_* 字段后重算
 * canonical，用包内公钥验签；再逐 section 重算 sha256 与 manifest 比对。
 */

/** 纯 TS ed25519 验签委托给 lib/ed25519-runtime（原生实现，避免手写曲线）。 */
export async function verifyEvidenceBundle(bundle: unknown): Promise<{
  ok: boolean; schema_ok: boolean; ed25519_ok: boolean | null; manifest_ok: boolean; mismatched: string[]; reason?: string;
}> {
  const result = { ok: false, schema_ok: false, ed25519_ok: null as boolean | null, manifest_ok: false, mismatched: [] as string[], reason: '' };
  if (!bundle || typeof bundle !== 'object' || Array.isArray(bundle)) { result.reason = 'not_an_object'; return result; }
  const b = bundle as Record<string, unknown>;
  result.schema_ok = b.schema === EVIDENCE_SCHEMA;
  if (!result.schema_ok) { result.reason = `bad_schema:${String(b.schema)}`; return result; }

  // manifest 逐节校验
  const sections = (b.sections ?? {}) as Record<string, unknown>;
  const manifest = (b.manifest ?? {}) as Record<string, { count?: number; sha256?: string }>;
  result.mismatched = [];
  for (const [name, meta] of Object.entries(manifest)) {
    if (!(name in sections)) { result.mismatched.push(`${name}:missing`); continue; }
    if (sha256(sections[name]) !== meta?.sha256) result.mismatched.push(name);
  }
  result.manifest_ok = result.mismatched.length === 0;

  // ed25519 验签
  const { ed25519Verify, b64ToBytes } = await import('@/lib/ed25519-runtime');
  const core: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(b)) if (!['ed25519_signature', 'ed25519_public', 'ed25519_key_id'].includes(k)) core[k] = v;
  const pubB64 = typeof b.ed25519_public === 'string' ? b.ed25519_public : '';
  const sigB64 = typeof b.ed25519_signature === 'string' ? b.ed25519_signature : '';
  if (!pubB64 || !sigB64) { result.ed25519_ok = null; result.reason = b.integrity === 'unsigned' ? 'unsigned_bundle' : 'missing_signature'; }
  else {
    const pub = b64ToBytes(pubB64); const sig = b64ToBytes(sigB64);
    if (!pub || !sig) { result.ed25519_ok = false; result.reason = 'bad_base64'; }
    else {
      const v = await ed25519Verify(pub, new TextEncoder().encode(canonicalJson(core)), sig);
      result.ed25519_ok = v === true;
      if (v !== true) result.reason = 'ed25519_invalid';
    }
  }

  result.ok = result.schema_ok && result.manifest_ok && result.ed25519_ok === true;
  return result;
}
