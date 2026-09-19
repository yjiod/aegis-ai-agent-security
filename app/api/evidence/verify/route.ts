/**
 * app/api/evidence/verify/route.ts — 控制台内证据包验签（便捷入口）。
 *
 * POST /api/evidence/verify  body: 完整证据包 JSON
 *   -> { ok, schema_ok, ed25519_ok, manifest_ok, mismatched[], reason? }
 *
 * 权威验签路径是离线的 scripts/verify-evidence-bundle.py（接收方无需控制台账号）；
 * 本路由只是给已登录的审计员/管理员一个"拖进来点一下"的便捷核对，逻辑与脚本一致：
 * 剔除 ed25519_* 字段后重算 canonical 验签 + 逐 section 重算 sha256 比对 manifest。
 *
 * 只读、无副作用（不写审计、不改状态）。权限：审计员/管理员。
 */

import { NextResponse } from 'next/server';
import { requireAuditor } from '@/lib/auth';
import { apiError, jsonResponse, readJsonObject } from '@/lib/api';
import { verifyEvidenceBundle } from '@/lib/evidence';

export const dynamic = 'force-dynamic';

/** 证据包可含数千条发现，放宽到 8MB（仍是有界读取，超限 413）。 */
const MAX_VERIFY_BYTES = 8_000_000;

export async function POST(request: Request): Promise<NextResponse> {
  const denied = requireAuditor(request);
  if (denied) return denied;

  const parsed = await readJsonObject(request, MAX_VERIFY_BYTES);
  if (!parsed.ok) return parsed.response;

  const result = await verifyEvidenceBundle(parsed.value);
  // 验签结论本身不是秘密，但只回给已授权角色；200 表示"已完成验证"，ok 字段表示结论。
  return jsonResponse(result);
}

export function GET(): NextResponse {
  return apiError('method_not_allowed', 'Use POST with an evidence bundle body to verify.', 405);
}
