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

/** 第 1) 类：各 AI Agent 原生核心 skill（自动加白）。 */
export const DEFAULT_BUNDLED_SKILLS: string[] = [
  // QwenWork（千问办公）默认内置 skill（当前版本）
  'xlsx', 'pdf', 'pptx', 'docx', 'qw-pages', 'qw-pages-supabase', 'media-generation',
  'create-skill', 'create-command', 'plugin-creator', 'find-skills', 'qwenwork-guidance',
  'html-markdown', 'mini-program-dev', 'ai-dev-tools',
];

/** 第 1) 类：各 AI Agent 原生/内置 MCP（自动加白）。命名约定 `<agent>-built-in`。 */
export const DEFAULT_BUNDLED_MCP: string[] = [
  'qw-builtin', // QwenWork lazy-loading 内置工具集
  'cursor-built-in', 'codex-built-in', 'claude-code-built-in', 'codebuddy-built-in',
  'windsurf-built-in', 'gemini-built-in', 'github-copilot-built-in', 'lingma-built-in',
  'workbuddy-built-in',
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

/** 展开为处置注册表条目（disposition=allow 由调用方设置）。仅含第 1) 类原生核心。 */
export function defaultBundledEntries(): DefaultAllowEntry[] {
  // 绝对要求 #4（2026-09-24）：内置 + 内置市场（专家团/连接器/社区商店）全量预置允许。
  const marketSkills = Object.values(OPTIONAL_REVIEW_GROUPS).flat();
  return [
    ...DEFAULT_BUNDLED_SKILLS.map((k) => ({ asset_type: 'skill' as const, asset_key: k })),
    ...marketSkills.map((k) => ({ asset_type: 'skill' as const, asset_key: k })),
    ...DEFAULT_BUNDLED_MCP.map((k) => ({ asset_type: 'mcp' as const, asset_key: k })),
  ];
}
