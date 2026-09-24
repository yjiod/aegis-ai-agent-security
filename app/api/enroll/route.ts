import { NextResponse } from 'next/server';
import { ensurePgHydrated, logAudit } from '@/lib/store';
import { ensurePolicyReleasesLoaded, currentPolicyRelease } from '@/lib/policy';

export const dynamic = 'force-dynamic';

const NO_STORE = { 'Cache-Control': 'no-store' } as const;

/**
 * 向 Collector 注册每设备上报令牌（批4；以 Collector 管理令牌鉴权）。
 * Collector 存 sha256(token) 并在 report_authentication 双接受（全局∪每设备）。
 * 失败（Collector 不可达等）返回 false → enroll 回落全局令牌保可用性。
 */
async function registerDeviceToken(deviceId: string, token: string, signingSecret: string): Promise<boolean> {
  const url = process.env.AEGIS_COLLECTOR_URL;
  const admin = process.env.AEGIS_COLLECTOR_TOKEN;
  if (!url || !admin) return false;
  try {
    const res = await fetch(`${url.replace(/\/$/, '')}/v1/device-tokens`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${admin}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ device_id: deviceId, report_token: token, signing_secret: signingSecret }),
      cache: 'no-store',
      signal: AbortSignal.timeout(5000),
    });
    return res.ok;
  } catch {
    return false;
  }
}

/**
 * POST /api/enroll — 终端零接触自动入网。
 *
 * 目标：拿到客户端的人，只要连到正确的服务器地址，就自动获得"被纳管"所需的一切——
 * 上报令牌、每设备独立的上报签名密钥、以及当前已发布策略——无需管理员手动下发令牌。
 *
 * 返回（aegis.enrollment/v1）：
 *   report_url       终端上报地址（公网 /aegis/v1/reports，由请求 origin 推导）
 *   report_token     上报 Bearer 令牌
 *   signing_secret   每设备独立、CSPRNG 生成；满足 Agent 上报契约（Collector 处于
 *                    显式允许未签名模式时只验 Bearer、忽略报告签名）
 *   policy           当前已发布策略体（**去签名**，version 如 4.11.0）。Agent 以
 *                    require_signature=false 经 TLS 信任加载——既不暴露 HMAC 验签/签名
 *                    密钥（杜绝策略伪造），又让终端跑到当前策略而非出厂 4.8.0。
 *   policy_version   策略版本（无已发布策略时省略 policy，终端回退包内出厂策略）
 *
 * 安全权衡（开放零接触）：默认任何能访问本端点的客户端都可入网并取到上报令牌+策略。
 * 兜底：① 每 IP 限流；② 全量审计（device:enroll）；③ 令牌可用 scripts/rotate-collector-token.sh
 * 轮换、单台可吊销；④ 可选 AEGIS_ENROLLMENT_SECRET 门（配置后要求 X-Aegis-Enrollment-Key）。
 * 服务器地址即访问边界——不要把它当公网开放服务暴露。后续可升级为每设备令牌+非对称签名策略。
 */

const RATE_LIMIT_PER_MIN = 30;
const RATE_WINDOW_MS = 60_000;
// 单 workerd 实例内的 best-effort 限流（非跨实例强一致，足够挡住误用/扫描）。
const hits = new Map<string, number[]>();

function rateLimited(key: string): boolean {
  const now = Date.now();
  const arr = (hits.get(key) ?? []).filter((t) => now - t < RATE_WINDOW_MS);
  arr.push(now);
  hits.set(key, arr);
  if (hits.size > 5000) for (const [k, v] of hits) if (v.length === 0) hits.delete(k);
  return arr.length > RATE_LIMIT_PER_MIN;
}

function randomHex(bytes: number): string {
  const a = new Uint8Array(bytes);
  crypto.getRandomValues(a);
  return Array.from(a, (b) => b.toString(16).padStart(2, '0')).join('');
}

function boundedString(value: unknown, max: number): string {
  return typeof value === 'string' ? value.slice(0, max) : '';
}

export async function POST(request: Request) {
  // 可选入网密钥门：配置 AEGIS_ENROLLMENT_SECRET 后要求请求头匹配；未配置则开放零接触。
  const enrollSecret = process.env.AEGIS_ENROLLMENT_SECRET;
  if (enrollSecret) {
    const supplied = request.headers.get('x-aegis-enrollment-key') ?? '';
    if (supplied !== enrollSecret)
      return NextResponse.json({ error: 'enrollment_key_invalid' }, { status: 403, headers: NO_STORE });
  }

  const ip =
    request.headers.get('x-forwarded-for')?.split(',')[0].trim() ||
    request.headers.get('x-real-ip') ||
    'unknown';
  if (rateLimited(ip))
    return NextResponse.json({ error: 'rate_limited' }, { status: 429, headers: { ...NO_STORE, 'Retry-After': '60' } });

  const globalToken = process.env.AEGIS_COLLECTOR_TOKEN;
  if (!globalToken)
    return NextResponse.json({ error: 'enrollment_not_configured' }, { status: 503, headers: NO_STORE });

  let body: Record<string, unknown> = {};
  try {
    const parsed = await request.json();
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) body = parsed as Record<string, unknown>;
  } catch {
    /* 允许空体入网 */
  }
  const hostname = boundedString(body.hostname, 253);
  const deviceId = boundedString(body.device_id, 64);
  const agentVersion = boundedString(body.agent_version, 32);

  await ensurePgHydrated().catch(() => {});
  await ensurePolicyReleasesLoaded().catch(() => {});
  const rel = currentPolicyRelease();

  // report_url 必须是 https（Agent 的 load_reporting_config 强制 report_url scheme=https，
  // 否则判为契约无效拒绝上报）。控制台位于 TLS 终止反代之后，request.url 是内部 http，
  // 故按 X-Forwarded-Proto/Host 还原对外的真实 origin（生产 https://<host>）。
  const reqUrl = new URL(request.url);
  const fwdProto = request.headers.get('x-forwarded-proto')?.split(',')[0].trim();
  const fwdHost = request.headers.get('x-forwarded-host')?.split(',')[0].trim();
  const proto = fwdProto || reqUrl.protocol.replace(':', '');
  const host = fwdHost || reqUrl.host;
  const origin = `${proto}://${host}`;

  // 批4 每设备可吊销上报令牌：为每台设备签发独立 report_token 并向 Collector 注册
  // （Collector 双接受 全局∪每设备 过渡）。Collector 不可达时回落全局令牌保可用。
  const signingSecret = randomHex(32);
  let reportToken = globalToken;
  let tokenMode: 'per-device' | 'global' = 'global';
  if (deviceId && /^[0-9a-f]{12}$/.test(deviceId)) {
    const perDevice = randomHex(32);
    const registered = await registerDeviceToken(deviceId, perDevice, signingSecret);
    if (registered) {
      reportToken = perDevice;
      tokenMode = 'per-device';
    }
  }

  const payload: Record<string, unknown> = {
    schema: 'aegis.enrollment/v1',
    report_url: `${origin}/aegis/v1/reports`,
    report_token: reportToken,
    signing_secret: signingSecret,
    ...(deviceId ? { device_id: deviceId } : {}),
  };
  if (rel) {
    // 去签名的已发布策略体：终端 require_signature=false 经 TLS 信任加载，不暴露签名/验签密钥。
    payload.policy = rel.policy;
    payload.policy_version = rel.policy.version;
    // 带外信任锚：控制台 ed25519 公钥（公开信息）。安装器据此写 ed25519-public.b64 缓存，
    // 使终端在"策略带 signature 但无 HMAC 验签环"的正常态下可非对称验签（防 2026-09-24 停报事故复发）。
    const rp = rel.policy as unknown as Record<string, unknown>;
    if (typeof rp.ed25519_public === 'string' && rp.ed25519_public) {
      payload.ed25519_public = rp.ed25519_public;
      payload.ed25519_key_id = rp.ed25519_key_id ?? '';
    }
  }

  logAudit({
    actor: 'enroll-endpoint',
    action: 'device:enroll',
    resource_type: 'device',
    resource_id: deviceId || hostname || ip,
    detail: `自动入网下发上报凭据(token=${tokenMode})${rel ? ` + 策略 v${rel.policy.version}` : '（无已发布策略，终端回退出厂策略）'} hostname=${hostname || '?'} agent=${agentVersion || '?'} ip=${ip}`,
  });

  return NextResponse.json(payload, { headers: NO_STORE });
}
