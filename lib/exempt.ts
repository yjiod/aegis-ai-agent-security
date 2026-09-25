/**
 * 封禁豁免设备清单（开发主机等）：这些设备只报告不拦截，且发布影响面计算排除它们。
 * 运行时存于 PG settings（键 exempt_devices_json），不硬编码进仓库（设备标识不入库）。
 * 同时作为 agent_self_update.pinned 下发：豁免设备永不自动更新，只接受人工/桌管更新。
 */
import { getSetting, setSetting } from '@/lib/baselines';

export function exemptDevices(): string[] {
  try {
    const raw = getSetting('exempt_devices_json');
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed.filter((x): x is string => typeof x === 'string') : [];
  } catch {
    return [];
  }
}

export function setExemptDevices(ids: string[], by: string): string[] {
  const clean = [...new Set(ids.map((s) => String(s).trim().toLowerCase()).filter((s) => /^[0-9a-f]{8,64}$/.test(s)))].slice(0, 50);
  setSetting('exempt_devices_json', JSON.stringify(clean), by);
  return clean;
}

/**
 * 自更保护名单(pinned)：与封禁豁免(exempt)分离。pinned 只影响自更新(保护主力开发机不被坏更新打到)，
 * 不豁免封禁；exempt 只豁免封禁，不阻止自更新。两者独立配置避免"豁免了却也不更新"的耦合
 * （真机教训：4090 因与豁免同名单被 pinned，导致停在 0.35.1、run_mode/网卡/主板序列号全缺）。
 */
export function pinnedDevices(): string[] {
  try {
    const raw = getSetting('pinned_devices_json');
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed.filter((x): x is string => typeof x === 'string') : [];
  } catch {
    return [];
  }
}

export function setPinnedDevices(ids: string[], by: string): string[] {
  const clean = [...new Set(ids.map((s) => String(s).trim().toLowerCase()).filter((s) => /^[0-9a-f]{8,64}$/.test(s)))].slice(0, 50);
  setSetting('pinned_devices_json', JSON.stringify(clean), by);
  return clean;
}
