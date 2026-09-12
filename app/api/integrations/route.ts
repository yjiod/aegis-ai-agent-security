import { NextResponse } from 'next/server';
import { requireAdmin } from '@/lib/auth';

export const dynamic = 'force-dynamic';
const NO_STORE = { 'Cache-Control': 'no-store' } as const;

interface Integration {
  name: string;
  role: string;
  capabilities: string[];
  health: 'ok' | 'down' | 'unconfigured';
  detail?: string;
  alerts?: number;
}

async function fetchJson(url: string, headers: Record<string, string> = {}): Promise<any> {
  try {
    const r = await fetch(url, { headers, cache: 'no-store', signal: AbortSignal.timeout(6000) });
    if (!r.ok) return null;
    return await r.json();
  } catch {
    return null;
  }
}

async function probe(url: string, opts: RequestInit = {}): Promise<{ up: boolean; status?: number }> {
  try {
    const r = await fetch(url, { ...opts, cache: 'no-store', signal: AbortSignal.timeout(6000) });
    return { up: true, status: r.status }; // 任何 HTTP 响应=服务在; 401/403=凭据问题另见 status
  } catch {
    return { up: false };
  }
}

/**
 * GET /api/integrations — 集成控制面(admin): 列出已配置平台 + 健康 + 能力。
 * 配置来自环境变量 AEGIS_INT_<NAME>_{URL,TOKEN,USER,PASS}; 单端原则: 这些平台的
 * agent 由各自平台/桌管下发, Aegis bundle 只含 Aegis 单端。
 */
export async function GET(request: Request) {
  const denied = requireAdmin(request);
  if (denied) return denied;
  const env = process.env;
  const out: Integration[] = [];

  const fleetUrl = env.AEGIS_INT_FLEET_URL ?? '';
  const fleetTok = env.AEGIS_INT_FLEET_TOKEN ?? '';
  if (fleetUrl) {
    const pr = await probe(`${fleetUrl.replace(/\/$/, '')}/api/latest/me`, { headers: fleetTok ? { Authorization: `Bearer ${fleetTok}` } : {} });
    out.push({ name: 'Fleet', role: '桌管/MDM + osquery telemetry', capabilities: ['asset_inventory', 'device_management', 'policy_distribution', 'software_dist'], health: pr.up ? 'ok' : 'down', detail: `${fleetUrl} (http ${pr.status ?? 'n/a'})`, alerts: pr.up ? ((await fetchJson(`${fleetUrl.replace(/\/$/, '')}/api/latest/fleet/hosts`, fleetTok ? { Authorization: `Bearer ${fleetTok}` } : {}))?.hosts ?? []).filter((h: any) => h.status !== 'online').length : 0 });
  } else out.push({ name: 'Fleet', role: '桌管/MDM + osquery telemetry', capabilities: ['asset_inventory', 'device_management', 'policy_distribution', 'software_dist'], health: 'unconfigured' });

  const wazuhUrl = env.AEGIS_INT_WAZUH_URL ?? '';
  const wazuhUser = env.AEGIS_INT_WAZUH_USER ?? '';
  const wazuhPass = env.AEGIS_INT_WAZUH_PASS ?? '';
  if (wazuhUrl) {
    const auth = wazuhUser && wazuhPass ? `Basic ${Buffer.from(`${wazuhUser}:${wazuhPass}`).toString('base64')}` : '';
    const pr = await probe(`${wazuhUrl.replace(/\/$/, '')}/manager/info`, { headers: auth ? { Authorization: auth } : {} });
    out.push({ name: 'Wazuh', role: 'EDR / SIEM / active-response', capabilities: ['asset_inventory', 'event_forwarding', 'incident_response', 'compliance_check'], health: pr.up ? 'ok' : 'down', detail: `${wazuhUrl} (http ${pr.status ?? 'n/a'})`, alerts: pr.up ? ((await fetchJson(`${wazuhUrl.replace(/\/$/, '')}/agents`, auth ? { Authorization: auth } : {}))?.data?.affected_items ?? []).filter((a: any) => a.status !== 'active').length : 0 });
  } else out.push({ name: 'Wazuh', role: 'EDR / SIEM / active-response', capabilities: ['asset_inventory', 'event_forwarding', 'incident_response', 'compliance_check'], health: 'unconfigured' });

  const pfUrl = env.AEGIS_INT_PF_URL ?? '';
  const pfTok = env.AEGIS_INT_PF_TOKEN ?? '';
  if (pfUrl) {
    const pr = await probe(`${pfUrl.replace(/\/$/, '')}/api/v1/config/switches`, { headers: pfTok ? { Authorization: `Bearer ${pfTok}` } : {} });
    out.push({ name: 'PacketFence', role: '准入 NAC(需办公网)', capabilities: ['access_control', 'device_identity', 'asset_inventory'], health: pr.up ? 'ok' : 'down', detail: `${pfUrl} (http ${pr.status ?? 'n/a'})`, alerts: pr.up ? ((await fetchJson(`${pfUrl.replace(/\/$/, '')}/api/v1/nodes`, pfTok ? { Authorization: `Bearer ${pfTok}` } : {}))?.items ?? []).filter((n: any) => n.status !== 'reg').length : 0 });
  } else out.push({ name: 'PacketFence', role: '准入 NAC(需办公网)', capabilities: ['access_control', 'device_identity', 'asset_inventory'], health: 'unconfigured' });

  out.push({ name: 'Aegis(本端)', role: 'AI-Agent 安全治理(单端)', capabilities: ['ai_agent_discovery', 'skill_mcp_scan', 'policy_enforcement', 'reporting'], health: 'ok', detail: '员工终端唯一推送端' });

  return NextResponse.json({ integrations: out }, { headers: NO_STORE });
}
