/**
 * lib/auto-remediation.ts — 全自动纠偏闭环（绝对要求 #3）。
 *
 * 恶意 skill 封禁 / MCP 拒连 / 代码质量问题 → 自动通知相关用户与 Agent + 自动阻断：
 *   1) 拉取 Collector 跨设备聚合发现；
 *   2) 置信度门禁（对齐安全基线 §4.3：阻断类自动操作须高置信）——只有
 *      「高置信恶意信号」才自动 deny：skill 类 hidden_instruction / prompt_override /
 *      credential_access / context_poisoning（critical|high）；
 *      MCP 类 unapproved_mcp_transport / incomplete_mcp_server（critical）。
 *      代码质量问题（dynamic_eval / hardcoded_secret / empty_exception_handler…）
 *      没有可封禁资产 → 只通知（通知相关用户和 Agent 修复），绝不封代码。
 *   3) 人工处置神圣不可覆盖：已有人工 allow/monitor/deny 的资产一律不改写——
 *      人工 allow 但出现恶意信号 → 记冲突并通知管理员人工裁决（自定义处置 > 自动纠偏，
 *      与绝对要求 #4「自定义封禁 > 预置白名单」同一优先级链）。
 *   4) 自动发布签名策略：复用发布闸（爆炸半径）；自动路径**永不**使用
 *      override——超闸即中止发布并降级为人工通知。
 *   5) 通知：走告警 webhook（aegis.remediation/v1），内容含被拒资产、发布版本、
 *      冲突与代码质量待办；终端侧通过签名策略收到 deny 名单即执行隔离/拒连
 *      （modules.skill_enforce / mcp_enforce 打开时）。
 *
 * 配置（PG settings `remediation_json`）：{enabled, auto_deny, notify}，默认全开
 * （用户要求"全自动纠偏"；可在设置页关闭）。
 */
import { ensureLabelsLoaded, listLabels, setLabelInMemory, persistLabelsDurable, findingAsset, type AssetLabel, type AssetType } from '@/lib/labels';
import { getSetting } from '@/lib/baselines';
import { logAudit } from '@/lib/store';
import { getAlertConfig } from '@/lib/alerting';
import {
  ensurePolicyReleasesLoaded, ensureSigningKeysLoaded, publishPolicyRelease,
  BLAST_CAP_ASSETS, BLAST_CAP_PCT, BLAST_ABS_CAP_ASSETS, BLAST_ABS_CAP_PCT,
} from '@/lib/policy';
import { moduleOverrides } from '@/lib/modules';
import { exemptDevices, pinnedDevices } from '@/lib/exempt';
import { getRollout } from '@/lib/rollout';
import { getScanMode, effectiveRules, ensureBaselinesLoaded } from '@/lib/baselines';
import { enforceableRuleIds } from '@/lib/policy';

/**
 * 高置信恶意信号 → skill 资产自动 deny（severity critical|high）。
 *
 * ⚠️ 诚实边界：这四个 kind **全部**由 aegis_agent.py 的 `scan_text()` 产出
 * （prompt_override:303、credential_access:303、context_poisoning:336、
 * hidden_instruction:345，均在 scan_text 的 302-406 行内），而 `scan_text` 的每个
 * 调用点都被 `if m_code:` 门控（agent:550、:1032、:1068），`m_code` 即
 * `modules.code_scan`，出厂默认 **false**。⇒ 现网终端根本不产生这些信号，
 * **skill 自动封禁路径当前是零动作**。真正修复需把 scan_text 拆成
 * "治理组恒开 / 代码质量组受 code_scan 门控"，属 Task #6（会触发 release 级联 +
 * 冻结二进制 CI + 舰队自更，须在干净边界单独做）。
 * **因此不得声称"绝对要求 #3（全自动纠偏）已达成"——它目前只达成 MCP 这一半。**
 */
export const AUTO_DENY_SKILL_KINDS = new Set(['hidden_instruction', 'prompt_override', 'credential_access', 'context_poisoning']);
/**
 * 高置信恶意信号 → mcp 资产自动 deny（severity critical|high，见下方 mcpHit）。
 *
 * 名单依 PM 产品体检 §P0-2 修法2 裁定，三个 kind 的**终端实际产出严重度**为：
 *   - `unapproved_mcp_transport` → high（agent:370；windows ps1 同口径）
 *   - `literal_mcp_secret`       → critical（agent:383 与 :420；ps1 同）
 *   - `mcp_url_credentials`      → critical（agent:390；ps1 同）
 * 后两者是明文凭据外泄面，正是最该自动封禁的；前者是"传输不可信"，high 即足够置信。
 *
 * 修复前本名单是 `{unapproved_mcp_transport, incomplete_mcp_server}` 且门禁要求
 * `severity === 'critical'` —— 而这两个 kind 终端实发 high / medium，**永远不等于
 * critical**，故 mcpHit 恒 false、MCP 自动封禁在生产中一次都没触发过；单测却因为
 * 夹具把 `incomplete_mcp_server` 编成 `critical`（终端从不产出该值）而全绿。
 * tests/test_aegis.py 的跨语言奇偶断言现已把"名单内每个 kind 的终端真实严重度必须
 * 满足门禁判据"钉死，两边脱钩即刻报红。
 */
export const AUTO_DENY_MCP_KINDS = new Set(['unapproved_mcp_transport', 'literal_mcp_secret', 'mcp_url_credentials']);
/**
 * 配置缺陷类（**非**恶意信号）→ 只通知，绝不自动封禁。
 *
 * PM §P0-2 修法2 裁定：`incomplete_mcp_server` 是"未配置命令或 URL"的配置错误
 * （agent:404 实发 medium），自动 deny 一个只是配错的 MCP 属误伤——它未必有害。
 * 故从 AUTO_DENY_MCP_KINDS 移出。
 *
 * 但移出封禁名单**不等于可以忽略**：它仍必须进通知队列。因为下方通知分支的条件是
 * "critical/high 或命中封禁名单"，而它是 medium 且已不在任何封禁名单里 —— 若不在此
 * 显式列出，这条发现会被整个静默丢弃（既不封也不通知）。
 */
export const NOTIFY_ONLY_KINDS = new Set(['incomplete_mcp_server']);
/** 代码质量问题 → 仅通知（无资产可封，通知用户/Agent 修复）。 */
export const CODE_QUALITY_KINDS = new Set([
  'dynamic_eval', 'empty_exception_handler', 'hardcoded_secret', 'weak_random_token',
  'insecure_tls_verification', 'dependency_unpinned', 'missing_lockfile', 'unbounded_shell',
  'unvalidated_llm_execution', 'oversized_file_skipped', 'project_scan_truncated',
]);

export interface RemediationFinding {
  device_id: string;
  kind: string;
  severity: string;
  path?: string;
  message?: string;
  asset_type?: string;
  asset_key?: string;
}

export interface RemediationDecision {
  denies: Array<{ asset_type: AssetType; asset_key: string; kind: string; severity: string }>;
  /** 人工 allow/monitor 与恶意信号冲突 → 不覆盖，通知管理员裁决。 */
  conflicts: Array<{ asset_type: AssetType; asset_key: string; disposition: string; kind: string }>;
  /** 代码质量/无法归资产的恶意发现 → 通知相关用户与 Agent。 */
  notifies: Array<{ device_id: string; kind: string; severity: string; asset_key?: string; message: string }>;
}

/**
 * 纯决策核心（esbuild 可单测）：输入发现 + 当前处置注册表，输出三类动作。
 * 规则见文件头；同资产多发现去重（按 asset+kind）。
 */
export function decideRemediation(findings: RemediationFinding[], labels: AssetLabel[]): RemediationDecision {
  const byKey = new Map<string, AssetLabel>();
  for (const l of labels) byKey.set(`${l.asset_type}:${l.asset_key}`, l);
  const denySeen = new Set<string>();
  const conflictSeen = new Set<string>();
  const notifySeen = new Set<string>();
  const out: RemediationDecision = { denies: [], conflicts: [], notifies: [] };
  for (const f of findings) {
    const kind = String(f.kind ?? '');
    const severity = String(f.severity ?? 'low');
    const asset = findingAsset(f as Parameters<typeof findingAsset>[0]);
    const skillHit = asset?.asset_type === 'skill' && AUTO_DENY_SKILL_KINDS.has(kind)
      && (severity === 'critical' || severity === 'high');
    // 门槛与 skill 路径对齐为 ≥high（原为 `=== 'critical'`）。原写法使整条 MCP 自动
    // 封禁路径恒不触发：名单里的 kind 终端实发 high/medium，永远不等于 critical。
    // 见 AUTO_DENY_MCP_KINDS 的说明与 PM §P0-2 修法2。
    const mcpHit = asset?.asset_type === 'mcp' && AUTO_DENY_MCP_KINDS.has(kind)
      && (severity === 'critical' || severity === 'high');
    if (skillHit || mcpHit) {
      const a = asset as { asset_type: AssetType; asset_key: string };
      const prev = byKey.get(`${a.asset_type}:${a.asset_key}`);
      if (prev && prev.disposition) {
        // 人工已有处置（含 allow/monitor/deny）：自动纠偏绝不覆盖。
        if (prev.disposition === 'deny') continue; // 已封禁，无事可做
        const ck = `${a.asset_type}:${a.asset_key}:${prev.disposition}`;
        if (!conflictSeen.has(ck)) {
          conflictSeen.add(ck);
          out.conflicts.push({ asset_type: a.asset_type, asset_key: a.asset_key, disposition: prev.disposition, kind });
        }
        continue;
      }
      const dk = `${a.asset_type}:${a.asset_key}:${kind}`;
      if (!denySeen.has(dk)) {
        denySeen.add(dk);
        out.denies.push({ asset_type: a.asset_type, asset_key: a.asset_key, kind, severity });
      }
      continue;
    }
    // 其余发现 → 通知相关用户与 Agent：critical/high（代码质量问题为主），以及
    // 任何恶意信号类命中（含 medium——置信度门禁只限制"自动封禁"，不限制"通知"），
    // 以及配置缺陷类（NOTIFY_ONLY_KINDS：不封但必须通知，否则 medium 级会被静默丢弃）。
    if (
      severity === 'critical' || severity === 'high'
      || AUTO_DENY_SKILL_KINDS.has(kind) || AUTO_DENY_MCP_KINDS.has(kind)
      || NOTIFY_ONLY_KINDS.has(kind)
    ) {
      const nk = `${f.device_id}:${kind}:${asset?.asset_key ?? f.path ?? ''}`;
      if (!notifySeen.has(nk)) {
        notifySeen.add(nk);
        out.notifies.push({
          device_id: f.device_id,
          kind,
          severity,
          ...(asset?.asset_key ? { asset_key: asset.asset_key } : {}),
          message: String(f.message ?? '').slice(0, 180),
        });
      }
    }
  }
  return out;
}

/** 自动纠偏配置（PG settings `remediation_json`；默认全开=用户"全自动纠偏"要求）。 */
export interface RemediationConfig {
  enabled: boolean;
  auto_deny: boolean;
  notify: boolean;
}
export function remediationConfig(): RemediationConfig {
  try {
    const raw = getSetting('remediation_json');
    if (!raw) return { enabled: true, auto_deny: true, notify: true };
    const p = JSON.parse(raw) as Partial<RemediationConfig>;
    return {
      enabled: typeof p.enabled === 'boolean' ? p.enabled : true,
      auto_deny: typeof p.auto_deny === 'boolean' ? p.auto_deny : true,
      notify: typeof p.notify === 'boolean' ? p.notify : true,
    };
  } catch {
    return { enabled: true, auto_deny: true, notify: true };
  }
}

interface AggregateItem { device_id?: string; scanned_at?: number; finding?: Record<string, unknown> }

/** 拉取 Collector 全量聚合发现（有界翻页，30k 设备护栏）。 */
async function fetchAllFindings(): Promise<RemediationFinding[]> {
  const base = (process.env.AEGIS_COLLECTOR_URL ?? '').replace(/\/$/, '');
  const token = process.env.AEGIS_COLLECTOR_TOKEN ?? '';
  if (!base || !token) return [];
  const out: RemediationFinding[] = [];
  let cursor = '';
  for (let i = 0; i < 60; i += 1) { // 60 页 × 500 设备 = 3 万设备
    const qs = new URLSearchParams({ limit: '500' });
    if (cursor) qs.set('cursor', cursor);
    const res = await fetch(`${base}/v1/findings/aggregate?${qs.toString()}`, {
      headers: { Authorization: `Bearer ${token}`, Accept: 'application/json' },
      cache: 'no-store',
      signal: AbortSignal.timeout(15_000),
    });
    if (!res.ok) break;
    const data = (await res.json()) as { findings?: AggregateItem[]; next_cursor?: string; complete?: boolean };
    for (const item of data.findings ?? []) {
      const f = item.finding ?? {};
      out.push({
        device_id: String(item.device_id ?? ''),
        kind: typeof f.kind === 'string' ? f.kind : '',
        severity: typeof f.severity === 'string' ? f.severity : 'low',
        path: typeof f.path === 'string' ? f.path : undefined,
        message: typeof f.message === 'string' ? f.message : undefined,
        asset_type: typeof f.asset_type === 'string' ? f.asset_type : undefined,
        asset_key: typeof f.asset_key === 'string' ? f.asset_key : undefined,
      });
    }
    cursor = data.next_cursor ?? '';
    if (data.complete !== false || !cursor) break;
  }
  return out;
}

/** 爆炸半径预检（与发布闸同口径；自动路径永不 override，超闸即放弃自动发布）。 */
async function blastRadiusOk(denySkills: string[], denyMcp: string[]): Promise<{ ok: boolean; total: number }> {
  if (!denySkills.length && !denyMcp.length) return { ok: true, total: 0 };
  const mods = moduleOverrides();
  if (!(mods.skill_enforce || mods.mcp_enforce)) return { ok: true, total: 0 }; // 未开执行，发布无封禁影响
  const base = (process.env.AEGIS_COLLECTOR_URL ?? '').replace(/\/$/, '');
  const token = process.env.AEGIS_COLLECTOR_TOKEN ?? '';
  if (!base || !token) return { ok: false, total: 0 }; // 评估不了就当超闸（fail-closed）
  try {
    const r = await fetch(`${base}/v1/devices?limit=500`, {
      headers: { Authorization: `Bearer ${token}`, Accept: 'application/json' },
      cache: 'no-store', signal: AbortSignal.timeout(15_000),
    });
    if (!r.ok) return { ok: false, total: 0 };
    const d = (await r.json()) as { devices?: Array<{ device_id?: string; skills?: string[]; mcp_assets?: string[] }> };
    const exempt = new Set(exemptDevices().map((x) => x.toLowerCase()));
    const impact = (d.devices ?? [])
      .filter((dev) => !exempt.has(String(dev.device_id ?? '').toLowerCase()))
      .map((dev) => {
        const s = (dev.skills ?? []).filter((x) => denySkills.includes(x));
        const m = (dev.mcp_assets ?? []).filter((x) => denyMcp.includes(x));
        const denom = (dev.skills ?? []).length;
        return { count: s.length + m.length, pct: denom ? Math.round((100 * s.length) / denom) : 0 };
      });
    const total = impact.reduce((a, b) => a + b.count, 0);
    const ok = total <= BLAST_ABS_CAP_ASSETS && !impact.some((x) => x.pct > BLAST_ABS_CAP_PCT)
      && denySkills.length + denyMcp.length <= BLAST_ABS_CAP_ASSETS
      && (total <= BLAST_CAP_ASSETS && !impact.some((x) => x.pct > BLAST_CAP_PCT));
    return { ok, total };
  } catch {
    return { ok: false, total: 0 };
  }
}

export interface SweepResult {
  ran: boolean;
  reason?: string;
  findings: number;
  denied: Array<{ asset_type: string; asset_key: string }>;
  conflicts: Array<{ asset_type: string; asset_key: string; disposition: string }>;
  notified: number;
  published_version?: number;
  publish_blocked?: string;
}

/** 执行一轮自动纠偏（API 手动触发 + 后台循环共用）。 */
export async function runAutoRemediationSweep(actor = 'auto-remediation'): Promise<SweepResult> {
  const cfg = remediationConfig();
  if (!cfg.enabled) return { ran: false, reason: 'disabled', findings: 0, denied: [], conflicts: [], notified: 0 };
  const base = (process.env.AEGIS_COLLECTOR_URL ?? '').replace(/\/$/, '');
  const token = process.env.AEGIS_COLLECTOR_TOKEN ?? '';
  if (!base || !token) return { ran: false, reason: 'collector_unconfigured', findings: 0, denied: [], conflicts: [], notified: 0 };

  await ensureLabelsLoaded().catch(() => {});
  const findings = await fetchAllFindings();
  const decision = decideRemediation(findings, listLabels());
  const denied: SweepResult['denied'] = [];
  let publishedVersion: number | undefined;
  let publishBlocked: string | undefined;

  if (cfg.auto_deny && decision.denies.length > 0) {
    // 持久化优先（2026-09-25 事故修复）：deny 先批量落库（单事务、可等待），
    // 落库失败绝不进入发布——绝不带着半套标签签发策略。
    const denyRows: AssetLabel[] = decision.denies.map((d) =>
      setLabelInMemory({
        asset_type: d.asset_type,
        asset_key: d.asset_key,
        disposition: 'deny',
        tags: ['auto-remediated'],
        note: `自动纠偏：${d.kind}(${d.severity})`,
        updated_by: actor,
      }),
    );
    try {
      await persistLabelsDurable(denyRows);
    } catch (e) {
      logAudit({
        actor,
        action: 'remediation:auto_sweep',
        resource_type: 'policy',
        detail: `deny 落库失败，本轮不发布：${e instanceof Error ? e.message : String(e)}`,
      });
      return {
        ran: true,
        findings: findings.length,
        denied: [],
        conflicts: decision.conflicts,
        notified: 0,
        publish_blocked: `deny 落库失败（${e instanceof Error ? e.message : String(e)}）——已放弃自动发布，等待下轮重试`,
      };
    }
    for (const d of decision.denies) {
      denied.push({ asset_type: d.asset_type, asset_key: d.asset_key });
    }
    // 自动发布（永不 override；超闸降级人工）
    const denySkills = listLabels().filter((l) => l.asset_type === 'skill' && l.disposition === 'deny').map((l) => l.asset_key);
    const denyMcp = listLabels().filter((l) => l.asset_type === 'mcp' && l.disposition === 'deny').map((l) => l.asset_key);
    const blast = await blastRadiusOk(denySkills, denyMcp);
    if (!blast.ok) {
      publishBlocked = `blast_radius（预计影响 ${blast.total} 资产）——自动纠偏不 override，已留人工发布`;
    } else {
      await ensureBaselinesLoaded().catch(() => {});
      await ensurePolicyReleasesLoaded().catch(() => {});
      await ensureSigningKeysLoaded().catch(() => {});
      const rel = publishPolicyRelease({
        scanMode: getScanMode(),
        by: actor,
        note: `auto-remediation: denied ${denied.length} asset(s)`,
        customRuleIds: enforceableRuleIds(effectiveRules().map((r) => r.id)),
        modules: moduleOverrides(),
        enforceOverride: false,
        exempt: exemptDevices(),
        pinned: pinnedDevices(),
        rollout: getRollout(),
      });
      if (rel) publishedVersion = rel.version;
      else publishBlocked = 'signing_key_not_configured';
    }
  }

  // 通知（webhook，复用告警通道配置；未配置则只留审计）
  let notified = 0;
  if (cfg.notify && (denied.length > 0 || decision.conflicts.length > 0 || decision.notifies.length > 0)) {
    const alertCfg = getAlertConfig();
    if (alertCfg.webhook) {
      const payload =
        alertCfg.format === 'dingtalk'
          ? {
              msgtype: 'text',
              text: {
                content: [
                  'Aegis 自动纠偏',
                  ...denied.map((d) => `- 已封禁 ${d.asset_type}: ${d.asset_key}`),
                  ...decision.conflicts.map((c) => `- 冲突待裁决: ${c.asset_key}（人工${c.disposition}，检测到恶意信号）`),
                  ...decision.notifies.slice(0, 10).map((n) => `- 待修复[${n.severity}] ${n.device_id.slice(0, 12)} ${n.kind}${n.asset_key ? ` ${n.asset_key}` : ''}`),
                  ...(publishedVersion ? [`- 策略已发布 v${publishedVersion}`] : []),
                  ...(publishBlocked ? [`- 发布被拦截: ${publishBlocked}`] : []),
                ].join('\n'),
              },
            }
          : {
              schema: 'aegis.remediation/v1',
              at: Date.now(),
              denied,
              conflicts: decision.conflicts,
              notifies: decision.notifies.slice(0, 50),
              published_version: publishedVersion,
              publish_blocked: publishBlocked,
            };
      try {
        const r = await fetch(alertCfg.webhook, {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload), signal: AbortSignal.timeout(15_000),
        });
        notified = r.ok ? 1 : 0;
      } catch {
        notified = 0;
      }
    }
  }

  logAudit({
    actor,
    action: 'remediation:auto_sweep',
    resource_type: 'policy',
    detail: `发现 ${findings.length} → 自动封禁 ${denied.length}（${denied.map((d) => `${d.asset_type}:${d.asset_key}`).slice(0, 10).join(', ')}）冲突 ${decision.conflicts.length} 通知项 ${decision.notifies.length} 发布 ${publishedVersion ?? '—'}${publishBlocked ? ` 拦截=${publishBlocked}` : ''}`,
  });

  return {
    ran: true,
    findings: findings.length,
    denied,
    conflicts: decision.conflicts,
    notified,
    ...(publishedVersion ? { published_version: publishedVersion } : {}),
    ...(publishBlocked ? { publish_blocked: publishBlocked } : {}),
  };
}

/* ── 后台循环（middleware 启动，模式对齐 startUpstreamSyncLoop）────── */
const SWEEP_INTERVAL_MS = 5 * 60 * 1000;
let sweepLoopStarted = false;

export function startAutoRemediationLoop(): void {
  if (sweepLoopStarted) return;
  sweepLoopStarted = true;
  const tick = () => {
    const cfg = remediationConfig();
    if (!cfg.enabled) return;
    if (!process.env.AEGIS_COLLECTOR_URL || !process.env.AEGIS_COLLECTOR_TOKEN) return;
    runAutoRemediationSweep('auto-remediation-loop').catch(() => {});
  };
  setInterval(tick, SWEEP_INTERVAL_MS);
  setTimeout(tick, 90_000); // 启动后 90s 首扫（避开冷启动高峰）
}
