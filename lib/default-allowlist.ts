/**
 * 默认自带白名单（default-bundled allowlist）—— 2026-09-24 用户口径（绝对要求 #4）：
 *
 * **主流 AI Agent 的内置 skill、内置 MCP、内置市场技能（含 workbuddy 专家团/技能）
 * 全量预置允许**——包括原生核心、连接器、专家套件、社区商店技能。
 *
 * 优先级（编译进签名策略时强制保证，见 lib/policy.ts computePolicyBody）：
 *   自定义封禁(deny) > 预置白名单(preset allow) — deny 项会从 allowed_* 中剔除并进入
 *   显式 deny.* 隔离名单，终端执行器据此隔离 Skill / 移除 MCP。
 *   即：预置允许绝不能压制人工封禁；管理员 deny 一个预置技能即刻生效。
 *
 * 控制台「录入默认自带白名单」写入全部预置项（disposition=allow, tags=default-bundled）；
 * 已有人工处置（含 deny）的条目**不覆盖**——人工封禁优先于预置白名单在写入层即保证。
 */

import { MAINSTREAM_MARKET_SKILLS } from './mainstream-market-skills';

/** 第 1) 类：各 AI Agent 原生核心 skill（自动加白）。 */
export const DEFAULT_BUNDLED_SKILLS: string[] = [
  // QwenWork（千问办公）默认内置 skill（当前版本）
  'xlsx', 'pdf', 'pptx', 'docx', 'qw-pages', 'qw-pages-supabase', 'media-generation',
  'create-skill', 'create-command', 'plugin-creator', 'find-skills', 'qwenwork-guidance',
  'html-markdown', 'mini-program-dev', 'ai-dev-tools',
];

/**
 * 第 1b) 类：主流 Agent 内置市场技能全量预置（Codex 市场 / Claude Code 插件 /
 * superpowers 系 / QwenWork 技能库社区技能），来源=真实舰队上报清单，
 * 见 lib/mainstream-market-skills.ts（2026-09-24，541 项）。
 */
export const DEFAULT_MARKETPLACE_SKILLS: string[] = MAINSTREAM_MARKET_SKILLS;

/**
 * 第 1) 类：各 AI Agent 原生/内置 MCP（自动加白）。
 * `<agent>-built-in` 为 Agent 内置工具集命名约定；node_repl/cua_repl/computer-use
 * 为舰队真实上报的 Codex 内置 MCP server 名（生产 Collector 全量报告提取）。
 */
export const DEFAULT_BUNDLED_MCP: string[] = [
  'qw-builtin', // QwenWork lazy-loading 内置工具集
  'cursor-built-in', 'codex-built-in', 'claude-code-built-in', 'codebuddy-built-in',
  'windsurf-built-in', 'gemini-built-in', 'github-copilot-built-in', 'lingma-built-in',
  'workbuddy-built-in',
  'doubao-built-in', 'deepseek-built-in', 'trae-built-in', 'qwen-built-in',
  // 舰队实测内置 MCP server（Codex 等原生命名，非市场安装）
  'node_repl', 'cua_repl', 'computer-use',
];

/**
 * 第 2) 类：可选加白组 —— 不自动加白，由管理员在处置中心手工决策。
 * 仅导出作参考/展示，defaultBundledEntries() 不包含它们。
 */
export const OPTIONAL_REVIEW_GROUPS: Readonly<Record<string, string[]>> = {
  // 连接器（connectors）：与外部系统打通，是否放行由管理员按合规需要决定
  connectors: [
    'dingtalk-mail', 'dingtalk-chat', 'dingtalk-doc', 'dingtalk-wiki', 'dingtalk-drive',
    'dingtalk-contact', 'dingtalk-aisearch', 'dingtalk-calendar', 'dingtalk-todo',
    'dingtalk-minutes', 'dingtalk-event', 'dingtalk-misc', 'dingtalk-shared', 'dingtalk-aitable',
  ],
  // 专家套件（expert suites）：plugin 形式的能力包，按需启用
  expert_suites: [
    'product-design:frame', 'product-design:scope', 'product-design:audit', 'product-design:probe',
    'product-design:bench', 'product-design:signal', 'product-design:brief', 'product-design:stories',
    'product-design:sitemap', 'product-design:journey', 'product-design:board', 'product-design:flow-web',
    'product-design:flow-mobile', 'product-design:edge', 'product-design:chart', 'product-design:avatar',
    'product-design:poster', 'product-design:pitch', 'product-design:motion-plan', 'product-design:motion-apply',
    'product-design:check', 'product-design:access', 'product-design:test', 'product-design:metric',
    'product-design:qa', 'product-design:prd', 'product-design:retro', 'product-design:extract',
  ],
  // 技能库 / 社区商店（skill library / community store）：第三方或自装技能，默认进审查
  community_store: [
    'aiskillstore-create-adaptable-composable', 'aiskillstore-working-with-documents', 'aiskillstore-java-pro',
    'diegosouzapw-web-app-testing', 'diegosouzapw-python-testing-andyhsutw',
    'diegosouzapw-database-expert-advisor-majiayu000', 'diegosouzapw-enterprise-python-majiayu000',
    'majiayu000-intelligent-debugger', 'majiayu000-deeplearningcoder', 'majiayu000-frontend-code-quality',
    'majiayu000-java-concurrency', 'majiayu000-fix-markdown-lint',
    'michaelboeding-feature-council', 'majesticlabs-dev-python-debugger', 'b33eep-standards-javascript',
    'fwrite0920-project-bootstrapping', 'l-mb-py-modernize', 'claude-dev-suite-java-quality',
  ],
};

export interface DefaultAllowEntry {
  asset_type: 'skill' | 'mcp';
  asset_key: string;
}

/** 展开为处置注册表条目（disposition=allow 由调用方设置）。含原生核心 + 内置市场全量。 */
export function defaultBundledEntries(): DefaultAllowEntry[] {
  // 绝对要求 #4（2026-09-24）：内置 + 内置市场（专家团/连接器/社区商店/主流 Agent
  // 市场技能）全量预置允许；跨组可能重名（如 QwenWork 技能同时出现在核心与市场组），
  // 用 Set 去重保证单一条目。
  const marketSkills = Object.values(OPTIONAL_REVIEW_GROUPS).flat();
  const allSkills = [...DEFAULT_BUNDLED_SKILLS, ...DEFAULT_MARKETPLACE_SKILLS, ...marketSkills];
  const seen = new Set<string>();
  const entries: DefaultAllowEntry[] = [];
  for (const k of allSkills) {
    if (seen.has(k)) continue;
    seen.add(k);
    entries.push({ asset_type: 'skill', asset_key: k });
  }
  for (const k of DEFAULT_BUNDLED_MCP) {
    if (seen.has(`mcp:${k}`)) continue;
    seen.add(`mcp:${k}`);
    entries.push({ asset_type: 'mcp', asset_key: k });
  }
  return entries;
}
