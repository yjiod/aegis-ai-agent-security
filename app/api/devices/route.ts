/**
 * app/api/devices/route.ts — Device registry backed by REAL Collector data.
 *
 * GET    /api/devices              -> real device list from Collector /v1/devices
 * POST   /api/devices              -> register device (console-side registry)
 * PUT    /api/devices              -> update device metadata
 * DELETE /api/devices?device_id=ID -> remove from registry
 *
 * Production: reads live fleet data from the Collector (same-host HTTP).
 * Falls back to empty list (NOT demo data) when Collector is unreachable.
 */

import { NextResponse } from 'next/server';
import { requireDeviceWriter, getSession, roleReadsAllDevices, unauthenticated } from '@/lib/auth';
import { fetchCollectorDevices } from '@/lib/collector-devices';
import { getDeviceStore, logAudit } from '@/lib/store';
import { exemptDevices, pinnedDevices } from '@/lib/exempt';
import { getRollout, rolloutBucket, inRollout } from '@/lib/rollout';
import { ensureBaselinesLoaded } from '@/lib/baselines';
import type { Device } from '@/components/device-form';

export const dynamic = 'force-dynamic';

const HEADERS = { 'Cache-Control': 'no-store' };

function json(data: unknown, status = 200) {
  return NextResponse.json(data, { status, headers: HEADERS });
}

interface DeviceNetwork {
  physical_nics?: { name: string; mac: string; ips?: string[] }[];
  macs?: string[];
  local_ips?: string[];
  egress_ip?: string;
}

/**
 * 本路由消费的 Collector 设备**视图类型**（字段比 lib/collector-devices.ts 的
 * CollectorDeviceLite 宽）。数据拉取一律走 lib/collector-devices.ts（单一真源），
 * 本接口只用于描述这里要读的字段形状，不再对应任何本地抓取实现。
 */
interface CollectorDevice {
  device_id: string;
  last_seen: number;
  report_count: number;
  generation?: number;
  agent_version?: string;
  policy_version?: string;
  latest_severity?: { critical: number; high: number; medium: number; low: number };
  tools?: string[];
  network?: DeviceNetwork;
  enforcement?: Device['enforcement'];
}

/**
 * 单一真源适配层：lib/collector-devices.ts 的 fetchCollectorDevices 已实现
 * cursor **全量**翻页（MAX_PAGES=200 × 每页 10000）+ 30s TTL 缓存，返回的运行时
 * 对象保留 Collector 的全部字段（该模块只是把静态类型标窄为 CollectorDeviceLite，
 * 并未裁剪字段），故此处断言成本路由的宽视图类型是安全的，且**不改动其对外契约**
 * （它同时被 summary / search / posture 消费）。这里不发第二次请求。
 *
 * 修复前本文件内另有一份同名的本地抓取实现：单页硬编码 200 台上限、无游标续页，
 * 并且忽略调用方传入的 limit —— 舰队超过 200 台时 /api/devices 会**静默只返回前
 * 200 台**（总览页请求 2000 条时也一样被内部那个 200 覆盖），设备清单与 total
 * 双双失真。删除本地实现、统一走游标全量版本，消除双实现漂移。
 */
async function fetchFleetDevices(): Promise<CollectorDevice[] | null> {
  const devices = await fetchCollectorDevices();
  return devices === null ? null : (devices as unknown as CollectorDevice[]);
}

/**
 * 连接态（connectivity）与关注态（attention）分离：
 * - status 只反映"是否在线/过期/离线"（由 last_seen 推导），不被发现严重度覆盖；
 *   否则一台在线但有高危发现的终端会被标 needs_attention 而"在线数"恒为 0（用户反馈 bug）。
 * - attention 单独布尔：有 critical/high 发现需人工研判。
 */
function connectivityStatus(lastSeen?: number): string {
  const now = Math.floor(Date.now() / 1000);
  if (!lastSeen) return 'offline';
  if (now - lastSeen > 86400) return 'offline';
  if (now - lastSeen > 7200) return 'stale';
  return 'online';
}
function hasAttention(sev?: { critical: number; high: number; medium: number; low: number }): boolean {
  return Boolean(sev && (sev.critical > 0 || sev.high > 0));
}

export async function GET(request: Request) {
  const url = new URL(request.url);
  const search = url.searchParams.get('q')?.toLowerCase() ?? '';
  const statusFilter = url.searchParams.get('status');

  // 会话验签闸（契约 lib/openapi.ts 声明 /devices = session）。middleware 只校验
  // Cookie 的存在性+三段式+expiry，**不验签**（见 middleware.ts 末尾注释），
  // 伪造 `aegis_session=<任意subject>.<未来expiry>.<任意sig>` 能穿过它；真正的
  // HMAC-SHA256 验签只发生在 getSession -> parseSession -> verifySessionSignature。
  //
  // capability RBAC：developer 档仅可读"本人"设备（owner/os_user == subject）。
  //
  // ⚠️ 这里刻意**不使用** `session ? ... : false` 这类把 null 当"不受限"的写法：
  // 修复前正是那个三元把"验签失败"静默降级成"无需收窄"，于是伪造 Cookie 既读到
  // **全量舰队**（device_id / hostname / owner / os_user / serial / local_ips /
  // egress_ip / agent_version / skills / mcp_assets），又绕过了 developer 档的
  // "仅本人设备"规则。POST/PUT/DELETE 走 requireDeviceWriter 一直有 401，
  // 唯独 GET 是洞 —— 因为它调了 getSession 却没把它当门禁用。
  // fail-closed：会话缺失一律 401，绝不回落成全量读。
  const session = getSession(request);
  if (!session) return unauthenticated();
  const scopeToSelf = !roleReadsAllDevices(session.role);
  const applyScope = <T extends { owner: string; os_user?: string }>(list: T[]): T[] =>
    scopeToSelf
      ? list.filter((d) => d.owner === session.subject || (d.os_user ?? '') === session.subject)
      : list;

  // Try real Collector data first（游标全量，无 200 台截断）
  const collectorDevices = await fetchFleetDevices();

  if (collectorDevices && collectorDevices.length > 0) {
    await ensureBaselinesLoaded().catch(() => {});
    const exemptSet = new Set(exemptDevices().map((x) => x.toLowerCase()));
    const pinnedSet = new Set(pinnedDevices().map((x) => x.toLowerCase()));
    const rollout = getRollout();
    let devices = collectorDevices.map((d) => ({
      device_id: d.device_id,
      hostname: (d as any).hostname as string ?? d.device_id,
      owner: ((d as any).owner as string) || ((d as any).os_user as string) || '待分配',
      os_user: ((d as any).os_user as string) || '',
      os: ((d as any).os as string) || '',
      serial: ((d as any).serial as string) || '',
      network: (d as any).network as DeviceNetwork | undefined,
      enforcement: (d as any).enforcement as Device['enforcement'] | undefined,
      run_mode: (d as any).run_mode as string | undefined,
      run_mode_inferred: (d as any).run_mode_inferred === true,
      capabilities: (d as any).capabilities as { pf?: boolean; es?: boolean } | undefined,
      scan_root: (d as any).scan_root as string | undefined,
      exempt: exemptSet.has(String(d.device_id).toLowerCase()),
      pinned: pinnedSet.has(String(d.device_id).toLowerCase()),
      // 灰度（canary）可视化：桶号与终端 aegis_self_update.in_rollout 逐位一致；
      // in_canary=该设备是否落在当前放量内；will_update 再叠加 enabled/未 pinned 才是真会更新。
      rollout_bucket: rolloutBucket(String(d.device_id)),
      in_canary: inRollout(String(d.device_id), rollout.rollout_percent),
      // 自更非例行结果（preflight_failed/rolled_back:*/apply_failed:*/updated）：让"坏更新被
      // preflight 拒绝/自动回滚"在控制台可观测（canary 监控闭环）。例行结果终端不上报，此处为 undefined。
      self_update: (d as any).self_update as { updated?: boolean; reason?: string; from?: string; to?: string; latest?: string; at?: number } | undefined,
      agent_type: d.tools?.[0] ?? 'unknown',
      tools: d.tools ?? [],
      // 该设备可被 deny 的资产面（skill 名 / MCP server 名）：供控制台做封禁影响预览/透明化，
      // 让运维在发布 deny 前看清"这台机器有什么可被封"，呼应爆炸半径可控的诉求。
      skills: (d as any).skills as string[] | undefined,
      mcp_assets: (d as any).mcp_assets as string[] | undefined,
      agent_version: d.agent_version ?? '0.0.0',
      policy_version: d.policy_version ?? '0.0.0',
      status: connectivityStatus(d.last_seen),
      attention: hasAttention(d.latest_severity),
      last_seen: d.last_seen,
      registered_at: d.last_seen,
      report_count: d.report_count ?? 0,
      findings_summary: d.latest_severity ?? { critical: 0, high: 0, medium: 0, low: 0 },
    }));

    if (search) {
      devices = devices.filter(
        (d) => d.device_id.toLowerCase().includes(search) || d.hostname.toLowerCase().includes(search) || ((d as any).serial as string || '').toLowerCase().includes(search),
      );
    }
    if (statusFilter) {
      devices = devices.filter((d) => d.status === statusFilter);
    }
    devices = applyScope(devices);

    return json({ devices, total: devices.length, connected: true, source: 'collector' });
  }

  // Collector unreachable or empty: return console-side registry (may be empty)
  await ensureBaselinesLoaded().catch(() => {});
  const rolloutReg = getRollout();
  const store = getDeviceStore();
  let devices = [...store.values()].map((d) => ({
    ...d,
    rollout_bucket: rolloutBucket(String(d.device_id)),
    in_canary: inRollout(String(d.device_id), rolloutReg.rollout_percent),
  }));
  if (search) {
    devices = devices.filter(
      (d) => d.device_id.toLowerCase().includes(search) || d.hostname.toLowerCase().includes(search) || d.owner.toLowerCase().includes(search) || ((d as any).serial as string || '').toLowerCase().includes(search),
    );
  }
  if (statusFilter) devices = devices.filter((d) => d.status === statusFilter);
  devices = applyScope(devices);

  return json({ devices, total: devices.length, connected: false, source: 'registry' });
}

export async function POST(request: Request) {
  const __denied = requireDeviceWriter(request);
  if (__denied) return __denied;
  let body: Record<string, unknown>;
  try { body = await request.json(); } catch { return json({ error: 'invalid_json' }, 400); }

  const device_id = String(body.device_id ?? '').trim();
  const hostname = String(body.hostname ?? '').trim();
  const owner = String(body.owner ?? '').trim();
  const agent_type = String(body.agent_type ?? 'other');

  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$/.test(device_id)) return json({ error: 'invalid_device_id' }, 400);
  if (!hostname || hostname.length > 128) return json({ error: 'invalid_hostname' }, 400);
  if (!owner || owner.length > 64) return json({ error: 'invalid_owner' }, 400);

  const store = getDeviceStore();
  if (store.has(device_id)) return json({ error: 'device_already_exists' }, 409);

  const now = Math.floor(Date.now() / 1000);
  const device = {
    device_id, hostname, owner,
    agent_type: agent_type as 'cursor' | 'claude_code' | 'codex_cli' | 'windsurf' | 'other',
    agent_version: '0.0.0', policy_version: '0.0.0',
    status: 'offline' as const, last_seen: now, registered_at: now,
    notes: body.notes ? String(body.notes).slice(0, 500) : undefined,
    findings_summary: { critical: 0, high: 0, medium: 0, low: 0 },
  };
  store.set(device_id, device);
  logAudit({ actor: getSession(request)?.subject ?? 'console', action: 'device:create', resource_type: 'device', resource_id: device_id, detail: `注册终端 ${hostname}（负责人 ${owner}）` });
  return json({ device }, 201);
}

export async function PUT(request: Request) {
  const __denied = requireDeviceWriter(request);
  if (__denied) return __denied;
  let body: Record<string, unknown>;
  try { body = await request.json(); } catch { return json({ error: 'invalid_json' }, 400); }

  const device_id = String(body.device_id ?? '').trim();
  if (!device_id) return json({ error: 'missing_device_id' }, 400);

  const store = getDeviceStore();
  const now = Math.floor(Date.now() / 1000);

  // Upsert: Collector-discovered devices get an overlay entry on first edit.
  const existing = store.get(device_id) ?? {
    device_id,
    hostname: device_id,
    owner: '待分配',
    agent_type: 'other' as const,
    agent_version: '0.0.0',
    policy_version: '0.0.0',
    status: 'online' as const,
    last_seen: now,
    registered_at: now,
    findings_summary: { critical: 0, high: 0, medium: 0, low: 0 },
  };

  if (body.hostname) existing.hostname = String(body.hostname).slice(0, 128);
  if (body.owner) existing.owner = String(body.owner).slice(0, 64);
  if (body.agent_type) existing.agent_type = String(body.agent_type) as typeof existing.agent_type;
  if (body.notes !== undefined) existing.notes = String(body.notes).slice(0, 500) || undefined;

  store.set(device_id, existing);
  logAudit({ actor: getSession(request)?.subject ?? 'console', action: 'device:update', resource_type: 'device', resource_id: device_id, detail: `更新终端 ${device_id} 登记信息` });
  return json({ device: existing });
}

export async function DELETE(request: Request) {
  const __denied = requireDeviceWriter(request);
  if (__denied) return __denied;
  const url = new URL(request.url);
  const device_id = url.searchParams.get('device_id')?.trim();
  if (!device_id) return json({ error: 'missing_device_id' }, 400);

  const store = getDeviceStore();
  const inRegistry = store.has(device_id);
  if (inRegistry) store.delete(device_id);
  // 同时清除 Collector 侧该设备的报告/每设备令牌/认证代次（硬件ID化后用于清理旧
  // hostname 派生的重复设备；设备若仍在线会继续上报并重新出现）。
  let purged = false;
  const collectorUrl = process.env.AEGIS_COLLECTOR_URL;
  const collectorToken = process.env.AEGIS_COLLECTOR_TOKEN;
  if (collectorUrl && collectorToken) {
    try {
      const r = await fetch(`${collectorUrl.replace(/\/$/, '')}/v1/devices?device_id=${encodeURIComponent(device_id)}`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${collectorToken}` },
        cache: 'no-store',
        signal: AbortSignal.timeout(5000),
      });
      purged = r.ok;
    } catch {
      purged = false;
    }
  }
  if (!inRegistry && !purged) return json({ error: 'device_not_found' }, 404);
  logAudit({ actor: getSession(request)?.subject ?? 'console', action: 'device:delete', resource_type: 'device', resource_id: device_id, detail: `移除终端 ${device_id}（注册表=${inRegistry} collector清除=${purged}）` });
  return json({ deleted: true, device_id, purged });
}
