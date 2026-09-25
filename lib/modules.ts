/**
 * 模块开关（真实可开关）的服务端持久化。
 * 存于 PG settings 键 `modules_json`（JSON：{module_key: boolean}），与 scan_mode 同机制。
 * 发布签名策略时由 computePolicyBody 叠加进 policy.modules 下发终端；终端按开关
 * 启停对应扫描/执行模块。执行类开关(skill_enforce/mcp_enforce)缺省 false——封禁是
 * 不可逆倾向操作，必须管理员显式打开（人工审批语义）。
 */
import { getSetting, setSetting } from '@/lib/baselines';

export const MODULE_KEYS = [
  'skill_scan',
  'mcp_scan',
  'code_scan',
  'deps_scan',
  'baseline_install',
  'network_collect',
  'self_update',
  'skill_enforce',
  'mcp_enforce',
] as const;

export type ModuleKey = (typeof MODULE_KEYS)[number];

/** 控制台持久化的模块覆盖值（仅合法键、仅布尔）。 */
export function moduleOverrides(): Partial<Record<ModuleKey, boolean>> {
  try {
    const raw = getSetting('modules_json');
    if (!raw) return {};
    const parsed = JSON.parse(raw) as Record<string, unknown>;
    const out: Partial<Record<ModuleKey, boolean>> = {};
    for (const k of MODULE_KEYS) if (typeof parsed?.[k] === 'boolean') out[k] = parsed[k] as boolean;
    return out;
  } catch {
    return {};
  }
}

/** 写入模块覆盖（admin 调用），返回落库后的覆盖值。 */
export function setModuleOverrides(mods: Record<string, unknown>, updatedBy: string): Partial<Record<ModuleKey, boolean>> {
  const clean: Partial<Record<ModuleKey, boolean>> = {};
  for (const k of MODULE_KEYS) if (typeof mods?.[k] === 'boolean') clean[k] = mods[k] as boolean;
  setSetting('modules_json', JSON.stringify(clean), updatedBy);
  return clean;
}

/** 模块的中文展示名（控制台开关列表用）。 */
export const MODULE_LABELS: Record<ModuleKey, string> = {
  skill_scan: 'Skill 扫描',
  mcp_scan: 'MCP 扫描',
  code_scan: '代码 / 密钥扫描',
  deps_scan: '依赖供应链扫描',
  baseline_install: '安全基线注入',
  network_collect: '物理网卡采集',
  self_update: '客户端自更新',
  skill_enforce: 'Skill 封禁执行',
  mcp_enforce: 'MCP 封禁执行',
};

/** 模块说明（控制台开关列表用）。 */
export const MODULE_HINTS: Record<ModuleKey, string> = {
  skill_scan: '扫描各 AI 工具技能目录，产出未知/高危 Skill 发现',
  mcp_scan: '扫描 MCP 配置（传输/命令/域名/凭据），产出未批准 MCP 发现',
  code_scan: '代码 / 密钥扫描（默认关：代码扫描交给专业扫描器，终端不上报代码类发现；打开即恢复终端扫描）',
  deps_scan: '扫描依赖清单的未固定版本与不可信来源',
  baseline_install: '向仓库/用户目录注入 Aegis 安全基线文件',
  network_collect: '采集物理网卡 MAC 与本机 IP（不含虚拟网卡）',
  self_update: '无桌管环境的客户端自更新兜底（主通道为桌管推送）',
  skill_enforce: '按 deny.skills 真封禁 Skill：从工具可加载位置移除，且每个执行周期自动再执行（复发即再封，无需人工反复操作）；备份仅供管理员回滚；关闭则只报不封',
  mcp_enforce: '按 deny.mcp 真封禁 MCP：从配置删除 + 终止在跑进程 + 禁止该二进制再执行 +（Windows）防火墙出站封禁其 host；每周期自动再执行；解封自动还原；关闭则只报不封',
};
