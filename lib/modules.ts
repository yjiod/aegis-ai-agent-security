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

/**
 * 模块开关的**出厂默认** —— 全仓单一真源（P0 #38）。
 *
 * 此前存在三份副本且已漂移：本文件只有键没有默认值、lib/policy.ts 的
 * BASE_POLICY.modules、以及 app/policies/page.tsx 的本地 MODULE_DEFAULTS。
 * 第三份写着 code_scan: true，而两个权威源都是 false —— 后果是管理员在 /policies
 * 操作面板看到「代码 / 密钥扫描 = 开」，而终端实际收到的是关，即**管理决策面误报
 * 安全控制状态**（比单纯的显示错误严重：它会让管理员基于错误前提做放行决策）。
 *
 * 类型刻意写成 `Record<ModuleKey, boolean>`（不是 Partial、也不是
 * Record<string, boolean>）：这样往 MODULE_KEYS 里新增一个模块却忘了给默认值时，
 * `tsc` 会在**编译期**报错。漂移因此在源头被类型系统挡住，而不是依赖测试或人肉
 * 审查事后发现 —— 这是本文件能当"单一真源"的真正原因。
 *
 * 注意：本文件被客户端组件（app/policies/page.tsx）import。MODULE_DEFAULTS 与
 * effectiveModules 都是**纯数据 / 纯函数**：不做任何 I/O，也不引入新的 import，
 * 对客户端安全。默认值**绝不要**挪进 lib/policy.ts —— 那个文件 import 了
 * node:crypto，被客户端组件拉进去会直接崩溃。
 */
export const MODULE_DEFAULTS: Record<ModuleKey, boolean> = {
  // 扫描类全开。
  skill_scan: true,
  mcp_scan: true,
  // code_scan 出厂默认 false（2026-09-25 用户决策）：代码扫描交给专业扫描器负责，
  // 终端不做代码质量扫描、也不上报代码类发现；需要时在设置页打开开关即可恢复。
  code_scan: false,
  deps_scan: true,
  baseline_install: true,
  network_collect: true,
  self_update: true,
  // 执行类开关默认 false：封禁是不可逆倾向操作，deny 名单只报告不拦截，
  // 必须管理员显式打开才真封禁（人工审批语义）。
  skill_enforce: false,
  mcp_enforce: false,
};

/**
 * 出厂默认叠加控制台持久化的覆盖值 → 终端将实际收到的**有效**模块开关。
 *
 * 这是"有效值"的唯一计算处，供需要展示/判断**有效状态**的调用方使用（/policies
 * 面板的开关列表、以及任何要回答"这个模块现在到底开没开"的地方）。调用方不得各自
 * `{...MODULE_DEFAULTS, ...overrides}` 手搓展开 —— 手搓正是三份副本得以漂移的成因。
 *
 * 注意：lib/policy.ts 编译签名策略体时走的是 BASE_POLICY.modules（其值即
 * MODULE_DEFAULTS 的浅拷贝）再叠加覆盖值，与本函数**取值等价**；那里刻意保持原有
 * 展开写法未改，因为 modules 参与策略签名，改动其计算路径会影响已发布策略的
 * 规范化字节。两者的默认值同源于 MODULE_DEFAULTS，故不会再漂移。
 *
 * 纯函数，不读库、不做 I/O，客户端/服务端皆可安全调用。逐键校验
 * `typeof === 'boolean'`，因此即使喂进未清洗的原始 JSON（而非 moduleOverrides()
 * 的输出）也不会把非布尔值渗进有效值里。
 */
export function effectiveModules(
  overrides: Partial<Record<ModuleKey, boolean>> = {},
): Record<ModuleKey, boolean> {
  const out: Record<ModuleKey, boolean> = { ...MODULE_DEFAULTS };
  for (const k of MODULE_KEYS) {
    const v = overrides?.[k];
    if (typeof v === 'boolean') out[k] = v;
  }
  return out;
}

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
  // 文案收窄为**当前实际行为**（OD-8 A 方案，PM 定稿）：本开关出厂为 true，但
  // dependency_unpinned / missing_lockfile 在终端被归入 CODE_QUALITY_KINDS
  // （aegis_agent.py:1588-1591），code_scan=false 时经 build_report 兜底过滤
  // **不上报**（agent:1596-1599）。原文案承诺"未固定版本"⇒ UI 承诺了一个默认
  // 拿不到的能力，与 #32 同源（虚假状态）。此处只陈述现状与交叉影响，
  // **不承诺将来会恢复**——那属 Task #6 拆分 scan_text 后的事，未做就不写。
  deps_scan: '扫描依赖清单的供应链风险：不可信或远程来源、引用外部清单、清单无法安全解析。注意：「未固定版本」与「缺失锁文件」在终端归类为代码质量发现，受「代码 / 密钥扫描」开关（默认关闭）交叉影响，当前默认不上报。',
  baseline_install: '向仓库/用户目录注入 Aegis 安全基线文件',
  network_collect: '采集物理网卡 MAC 与本机 IP（不含虚拟网卡）',
  self_update: '无桌管环境的客户端自更新兜底（主通道为桌管推送）',
  skill_enforce: '按 deny.skills 真封禁 Skill：从工具可加载位置移除，且每个执行周期自动再执行（复发即再封，无需人工反复操作）；备份仅供管理员回滚；关闭则只报告不拦截',
  mcp_enforce: '按 deny.mcp 真封禁 MCP：从配置删除 + 终止在跑进程 + 禁止该二进制再执行 +（Windows）防火墙出站封禁其 host；每周期自动再执行；解封自动还原；关闭则只报告不拦截',
};
