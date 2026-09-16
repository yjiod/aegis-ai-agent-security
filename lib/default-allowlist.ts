/**
 * 默认自带白名单（default-bundled allowlist）—— 按用户最新口径分两类：
 *
 * 1) **原生核心（自动加白进库）**：每种 AI Agent 默认自带、开箱即用的 skill / MCP
 *    （workbuddy、cursor、codex、千问办公/QwenWork 等）。录入处置注册表
 *    disposition=allow，随签名策略发布为 allowed_skills / allowed_mcp_servers，
 *    终端不再对它们产生 unknown_skill / unknown_mcp 发现。
 *
 * 2) **可选项（不自动加白，由管理员手工决策）**：技能库 / 专家套件 / 连接器 /
 *    社区商店技能。见 OPTIONAL_REVIEW_GROUPS（仅作文档与处置中心参考，不进入
 *    defaultBundledEntries()，因此不会被自动加白）。管理员在处置中心逐项
 *    allow / monitor / deny 后才生效。
 *
 * 控制台「录入默认自带白名单」只写入第 1) 类；第 2) 类保持待审查，交用户拍板。
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
  return [
    ...DEFAULT_BUNDLED_SKILLS.map((k) => ({ asset_type: 'skill' as const, asset_key: k })),
    ...DEFAULT_BUNDLED_MCP.map((k) => ({ asset_type: 'mcp' as const, asset_key: k })),
  ];
}
