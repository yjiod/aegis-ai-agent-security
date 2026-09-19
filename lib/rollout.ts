/**
 * lib/rollout.ts — Agent 自更新灰度（canary）设置 + 分桶计算。
 *
 * 背景：agent_self_update.{enabled,channel,rollout_percent} 此前是 BASE_POLICY 里的
 * 静态常量，只能改代码+发版才能调整灰度——canary 既不可运营也无可视。本模块把这三项
 * 变成 settings 持久化的可配项（与 exempt/pinned 同一套 PG settings 机制），发布策略时
 * 注入 agent_self_update，使"放量比例/通道/开关"成为控制台一键可调、下次发布即生效的
 * 运营旋钮。
 *
 * 分桶算法必须与终端 aegis_self_update.in_rollout 逐位一致：
 *   bucket = int(sha256(device_id).hexdigest(), 16) % 100 ; in = bucket < rollout_percent
 * 否则控制台预览的"谁在灰度桶"与终端真实行为不符，canary 可视化就失去意义。
 * （跨语言一致性由 e2e 的对拍向量锁定。）
 */
import { createHash } from 'node:crypto';
import { getSetting, setSetting } from '@/lib/baselines';
import { BASE_POLICY } from '@/lib/policy';

export const ROLLOUT_CHANNELS = ['pilot', 'beta', 'stable'] as const;
export type RolloutChannel = (typeof ROLLOUT_CHANNELS)[number];

export interface RolloutConfig {
  enabled: boolean;
  channel: RolloutChannel;
  rollout_percent: number;
}

const SETTING_KEY = 'agent_rollout_json';

function isChannel(v: unknown): v is RolloutChannel {
  return typeof v === 'string' && (ROLLOUT_CHANNELS as readonly string[]).includes(v);
}

function clampPercent(n: number): number {
  if (!Number.isFinite(n)) return 0;
  return Math.max(0, Math.min(100, Math.round(n)));
}

/** 出厂默认（与 BASE_POLICY.agent_self_update 对齐）。 */
export function defaultRollout(): RolloutConfig {
  const s = BASE_POLICY.agent_self_update as { enabled?: unknown; channel?: unknown; rollout_percent?: unknown };
  return {
    enabled: s.enabled !== false,
    channel: isChannel(s.channel) ? s.channel : 'pilot',
    rollout_percent: typeof s.rollout_percent === 'number' ? clampPercent(s.rollout_percent) : 100,
  };
}

/** 读取灰度设置；缺省/损坏回落出厂默认（逐字段兜底，绝不抛）。 */
export function getRollout(): RolloutConfig {
  const def = defaultRollout();
  try {
    const raw = getSetting(SETTING_KEY);
    if (!raw) return def;
    const parsed = JSON.parse(raw) as Record<string, unknown>;
    if (!parsed || typeof parsed !== 'object') return def;
    return {
      enabled: typeof parsed.enabled === 'boolean' ? parsed.enabled : def.enabled,
      channel: isChannel(parsed.channel) ? parsed.channel : def.channel,
      rollout_percent: typeof parsed.rollout_percent === 'number' ? clampPercent(parsed.rollout_percent) : def.rollout_percent,
    };
  } catch {
    return def;
  }
}

export interface RolloutValidation {
  ok: boolean;
  problems: string[];
  value: RolloutConfig;
}

/** 校验并归一化一份灰度配置（不持久化）。供 PUT 路由与 setRollout 共用。 */
export function validateRollout(body: Record<string, unknown>): RolloutValidation {
  const def = defaultRollout();
  const problems: string[] = [];
  const enabled = typeof body.enabled === 'boolean' ? body.enabled : def.enabled;
  let channel: RolloutChannel = def.channel;
  if (body.channel !== undefined) {
    if (isChannel(body.channel)) channel = body.channel;
    else problems.push(`channel must be one of ${ROLLOUT_CHANNELS.join(', ')}`);
  }
  let rollout_percent = def.rollout_percent;
  if (body.rollout_percent !== undefined) {
    const n = body.rollout_percent;
    if (typeof n !== 'number' || !Number.isFinite(n) || n < 0 || n > 100) problems.push('rollout_percent must be a number between 0 and 100');
    else rollout_percent = clampPercent(n);
  }
  return { ok: problems.length === 0, problems, value: { enabled, channel, rollout_percent } };
}

/** 校验并持久化灰度设置；返回归一化后的值（调用方应在 validateRollout.ok 时调用）。 */
export function setRollout(value: RolloutConfig, by: string): RolloutConfig {
  const clean: RolloutConfig = {
    enabled: value.enabled === true,
    channel: isChannel(value.channel) ? value.channel : 'pilot',
    rollout_percent: clampPercent(value.rollout_percent),
  };
  setSetting(SETTING_KEY, JSON.stringify(clean), by);
  return clean;
}

/**
 * 灰度分桶：sha256(device_id) 的 256bit 大整数 % 100。与 aegis_self_update.in_rollout 一致。
 * 不用 BigInt（构建 target < ES2020）：按十六进制位迭代取模 (acc*16+digit)%100，
 * 数学上等价于 int(hex,16)%100，且全程在 Number 安全整数范围内（acc<100）。
 */
export function rolloutBucket(deviceId: string): number {
  const hex = createHash('sha256').update(String(deviceId)).digest('hex');
  let acc = 0;
  for (let i = 0; i < hex.length; i += 1) acc = (acc * 16 + Number.parseInt(hex[i], 16)) % 100;
  return acc;
}

/** 是否落在灰度放量内（pct<=0 不放量，>=100 全量），与终端判定一致。 */
export function inRollout(deviceId: string, rolloutPercent: number): boolean {
  const pct = clampPercent(rolloutPercent);
  if (pct >= 100) return true;
  if (pct <= 0) return false;
  return rolloutBucket(deviceId) < pct;
}
