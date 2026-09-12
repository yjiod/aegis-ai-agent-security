/**
 * lib/integrations.ts — 集成控制面(阶段F)共享逻辑。
 *
 * 配置来源优先级: settings 表(integration.* 键) > 环境变量(AEGIS_INT_*)。
 * 探针: 任何 HTTP 响应=在线; 告警=各平台非健康对象数(Fleet 非 online 主机 /
 * Wazuh 非 active agent / PacketFence 非 reg 节点)。
 * syncIntegrationAlerts(): 把各平台告警去重后自动建工单(source=integration:<name>),
 * 同一 integration+key 已有未闭环工单则跳过, 防刷屏。
 */
import { getSetting, setSetting } from './baselines';
import { getTicketStore, nextTicketId, logAudit, type Ticket, type TicketSeverity } from './store';

interface HostRow {
  status?: string;
  hostname?: string;
  uuid?: string;
  id?: string | number;
  name?: string;
  mac?: string;
}

export interface IntegrationConfig {
  fleet_url: string;
  fleet_token: string;
  wazuh_url: string;
  wazuh_user: string;
  wazuh_pass: string;
  pf_url: string;
  pf_token: string;
}

export interface IntegrationStatus {
  name: string;
  role: string;
  capabilities: string[];
  health: 'ok' | 'down' | 'unconfigured';
  detail?: string;
  alerts: number;
  alert_keys: string[];
}

const env = () => process.env;

export function getIntegrationsConfig(): IntegrationConfig {
  const g = (k: string, envKey: string) => getSetting(`integration.${k}`) || env()[envKey] || '';
  return {
    fleet_url: g('fleet_url', 'AEGIS_INT_FLEET_URL'),
    fleet_token: g('fleet_token', 'AEGIS_INT_FLEET_TOKEN'),
    wazuh_url: g('wazuh_url', 'AEGIS_INT_WAZUH_URL'),
    wazuh_user: g('wazuh_user', 'AEGIS_INT_WAZUH_USER'),
    wazuh_pass: g('wazuh_pass', 'AEGIS_INT_WAZUH_PASS'),
    pf_url: g('pf_url', 'AEGIS_INT_PF_URL'),
    pf_token: g('pf_token', 'AEGIS_INT_PF_TOKEN'),
  };
}

export function setIntegrationConfig(patch: Partial<IntegrationConfig>, updatedBy: string): void {
  for (const [k, v] of Object.entries(patch)) {
    if (typeof v === 'string') setSetting(`integration.${k}`, v, updatedBy);
  }
}

async function fetchJson(url: string, headers: Record<string, string> = {}): Promise<Record<string, unknown> | null> {
  try {
    const r = await fetch(url, { headers, cache: 'no-store', signal: AbortSignal.timeout(6000) });
    if (!r.ok) return null;
    return await r.json();
  } catch {
    return null;
  }
}

async function probe(url: string, headers: Record<string, string> = {}): Promise<{ up: boolean; status?: number }> {
  try {
    const r = await fetch(url, { headers, cache: 'no-store', signal: AbortSignal.timeout(6000) });
    return { up: true, status: r.status };
  } catch {
    return { up: false };
  }
}

/** 探测三个平台 + 告警对象列表。 */
export async function probeIntegrations(): Promise<IntegrationStatus[]> {
  const c = getIntegrationsConfig();
  const out: IntegrationStatus[] = [];

  if (c.fleet_url) {
    const base = c.fleet_url.replace(/\/$/, '');
    const h: Record<string, string> = c.fleet_token ? { Authorization: `Bearer ${c.fleet_token}` } : {};
    const p = await probe(`${base}/api/latest/me`, h);
    let keys: string[] = [];
    if (p.up) {
      const d = await fetchJson(`${base}/api/latest/fleet/hosts`, h);
      keys = (((d?.hosts as HostRow[] | undefined) ?? []) as HostRow[]).filter((x) => x.status !== 'online').map((x) => String(x.hostname || x.uuid || x.id));
    }
    out.push({ name: 'Fleet', role: '桌管/MDM + osquery telemetry', capabilities: ['asset_inventory', 'device_management', 'policy_distribution', 'software_dist'], health: p.up ? 'ok' : 'down', detail: `${c.fleet_url} (http ${p.status ?? 'n/a'})`, alerts: keys.length, alert_keys: keys });
  } else out.push({ name: 'Fleet', role: '桌管/MDM + osquery telemetry', capabilities: ['asset_inventory', 'device_management', 'policy_distribution', 'software_dist'], health: 'unconfigured', alerts: 0, alert_keys: [] });

  if (c.wazuh_url) {
    const base = c.wazuh_url.replace(/\/$/, '');
    const h: Record<string, string> = c.wazuh_user && c.wazuh_pass ? { Authorization: `Basic ${Buffer.from(`${c.wazuh_user}:${c.wazuh_pass}`).toString('base64')}` } : {};
    const p = await probe(`${base}/manager/info`, h);
    let keys: string[] = [];
    if (p.up) {
      const d = await fetchJson(`${base}/agents`, h);
      const data = (d?.data as { affected_items?: HostRow[] } | undefined);
      keys = ((data?.affected_items ?? []) as HostRow[]).filter((x) => x.status !== 'active').map((x) => String(x.name || x.id));
    }
    out.push({ name: 'Wazuh', role: 'EDR / SIEM / active-response', capabilities: ['asset_inventory', 'event_forwarding', 'incident_response', 'compliance_check'], health: p.up ? 'ok' : 'down', detail: `${c.wazuh_url} (http ${p.status ?? 'n/a'})`, alerts: keys.length, alert_keys: keys });
  } else out.push({ name: 'Wazuh', role: 'EDR / SIEM / active-response', capabilities: ['asset_inventory', 'event_forwarding', 'incident_response', 'compliance_check'], health: 'unconfigured', alerts: 0, alert_keys: [] });

  if (c.pf_url) {
    const base = c.pf_url.replace(/\/$/, '');
    const h: Record<string, string> = c.pf_token ? { Authorization: `Bearer ${c.pf_token}` } : {};
    const p = await probe(`${base}/api/v1/config/switches`, h);
    let keys: string[] = [];
    if (p.up) {
      const d = await fetchJson(`${base}/api/v1/nodes`, h);
      keys = (((d?.items as HostRow[] | undefined) ?? []) as HostRow[]).filter((x) => x.status !== 'reg').map((x) => String(x.mac || x.hostname || x.id));
    }
    out.push({ name: 'PacketFence', role: '准入 NAC(需办公网)', capabilities: ['access_control', 'device_identity', 'asset_inventory'], health: p.up ? 'ok' : 'down', detail: `${c.pf_url} (http ${p.status ?? 'n/a'})`, alerts: keys.length, alert_keys: keys });
  } else out.push({ name: 'PacketFence', role: '准入 NAC(需办公网)', capabilities: ['access_control', 'device_identity', 'asset_inventory'], health: 'unconfigured', alerts: 0, alert_keys: [] });

  out.push({ name: 'Aegis(本端)', role: 'AI-Agent 安全治理(单端)', capabilities: ['ai_agent_discovery', 'skill_mcp_scan', 'policy_enforcement', 'reporting'], health: 'ok', alerts: 0, alert_keys: [] });
  return out;
}

/** 各平台告警去重自动建工单; 同 integration+key 已有未闭环工单则跳过。 */
export async function syncIntegrationAlerts(): Promise<number> {
  const statuses = await probeIntegrations();
  const store = getTicketStore();
  let created = 0;
  for (const st of statuses) {
    if (st.health !== 'ok' || st.alert_keys.length === 0) continue;
    for (const key of st.alert_keys.slice(0, 50)) {
      const ref = `${st.name}:${key}`;
      const hasOpen = [...store.values()].some(
        (t) => t.source === `integration:${st.name}` && t.finding_ref === ref && t.status !== 'resolved' && t.status !== 'dismissed',
      );
      if (hasOpen) continue;
      const now = Date.now();
      const severity: TicketSeverity = 'high';
      const ticket: Ticket = {
        ticket_id: nextTicketId(store, now),
        title: `${st.name} 告警: ${key} 非健康状态`,
        severity,
        status: 'open',
        source: `integration:${st.name}`,
        device_id: key,
        description: `${st.role} 上报对象 ${key} 处于非健康状态, 自动生成工单待研判。`,
        finding_ref: ref,
        created_at: now,
        updated_at: now,
        history: [{ action: 'create', actor: `integration:${st.name}`, timestamp: now, note: '集成告警自动生成' }],
      };
      store.set(ticket.ticket_id, ticket);
      logAudit({ actor: `integration:${st.name}`, action: 'ticket:create', resource_type: 'ticket', resource_id: ticket.ticket_id, detail: `auto from integration alert ${ref}` });
      created += 1;
    }
  }
  return created;
}

let alertLoopStarted = false;
const ALERT_SYNC_INTERVAL_MS = 10 * 60 * 1000;

/** 每 10 分钟把集成告警同步为工单(每 isolate 一个定时器)。 */
export function startIntegrationAlertSync(): void {
  if (alertLoopStarted) return;
  alertLoopStarted = true;
  setInterval(() => {
    syncIntegrationAlerts().catch(() => {});
  }, ALERT_SYNC_INTERVAL_MS);
}
