/**
 * lib/alerting.ts — 舰队告警推送配置（PG settings 持久化，键 alert_config）。
 *
 * 控制台（admin）可写；服务器侧 aegis_alert_check.py 用 Collector bearer 令牌只读拉取
 * （见 /api/settings/alerting GET 的双鉴权），无需 SSH 改 collector.env。
 * 配置项：enabled / webhook(https 或空) / format(generic|dingtalk) / offline_hours /
 * min_interval_hours。webhook 为空 = 不推送（评估器 dry-run）。
 */
import { getSetting, setSetting } from '@/lib/baselines';

export interface AlertConfig {
  enabled: boolean;
  webhook: string;
  format: 'generic' | 'dingtalk';
  offline_hours: number;
  min_interval_hours: number;
}

const KEY = 'alert_config';

export const ALERT_DEFAULTS: AlertConfig = {
  enabled: true,
  webhook: '',
  format: 'generic',
  offline_hours: 2,
  min_interval_hours: 6,
};

function clampNum(v: unknown, def: number, min: number, max: number): number {
  const n = typeof v === 'number' && Number.isFinite(v) ? v : def;
  return Math.min(max, Math.max(min, n));
}

export function getAlertConfig(): AlertConfig {
  try {
    const raw = getSetting(KEY);
    if (!raw) return { ...ALERT_DEFAULTS };
    const p = JSON.parse(raw) as Record<string, unknown>;
    return {
      enabled: typeof p.enabled === 'boolean' ? p.enabled : ALERT_DEFAULTS.enabled,
      webhook: typeof p.webhook === 'string' ? p.webhook : '',
      format: p.format === 'dingtalk' ? 'dingtalk' : 'generic',
      offline_hours: clampNum(p.offline_hours, ALERT_DEFAULTS.offline_hours, 0.1, 168),
      min_interval_hours: clampNum(p.min_interval_hours, ALERT_DEFAULTS.min_interval_hours, 0.1, 168),
    };
  } catch {
    return { ...ALERT_DEFAULTS };
  }
}

export interface AlertConfigValidation {
  ok: boolean;
  problems: string[];
  value: AlertConfig;
}

export function validateAlertConfig(body: Record<string, unknown>): AlertConfigValidation {
  const problems: string[] = [];
  const enabled = typeof body.enabled === 'boolean' ? body.enabled : ALERT_DEFAULTS.enabled;
  let webhook = typeof body.webhook === 'string' ? body.webhook.trim() : '';
  if (webhook && !/^https:\/\/[^\s]+$/.test(webhook)) {
    problems.push('webhook must be an https:// URL or empty');
    webhook = '';
  }
  let format: 'generic' | 'dingtalk' = 'generic';
  if (body.format === 'dingtalk') format = 'dingtalk';
  else if (body.format === 'generic') format = 'generic';
  else problems.push('format must be generic|dingtalk');
  const offline_hours = clampNum(body.offline_hours, ALERT_DEFAULTS.offline_hours, 0.1, 168);
  if (body.offline_hours !== undefined && (typeof body.offline_hours !== 'number' || !Number.isFinite(body.offline_hours) || body.offline_hours < 0.1 || body.offline_hours > 168))
    problems.push('offline_hours must be a number in [0.1, 168]');
  const min_interval_hours = clampNum(body.min_interval_hours, ALERT_DEFAULTS.min_interval_hours, 0.1, 168);
  if (body.min_interval_hours !== undefined && (typeof body.min_interval_hours !== 'number' || !Number.isFinite(body.min_interval_hours) || body.min_interval_hours < 0.1 || body.min_interval_hours > 168))
    problems.push('min_interval_hours must be a number in [0.1, 168]');
  return { ok: problems.length === 0, problems, value: { enabled, webhook, format, offline_hours, min_interval_hours } };
}

export function setAlertConfig(c: AlertConfig, by: string): AlertConfig {
  setSetting(KEY, JSON.stringify(c), by);
  return c;
}
