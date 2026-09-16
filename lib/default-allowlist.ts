/**
 * 默认自带白名单（default-bundled allowlist）。
 *
 * 用户要求：各 AI Agent **默认自带**的 skill / MCP 直接录入白名单库（默认允许），
 * 只有**额外加载**的才进入审查/处置流程。本文件维护"默认自带"清单常量；
 * 控制台「录入默认自带白名单」动作把它写入处置注册表（disposition=allow,
 * note=默认自带），随签名策略发布为 allowed_skills / allowed_mcp，终端即不再对
 * 这些资产产生 unknown_skill / unknown_mcp 发现。未来 Agent 新增默认自带项时，
 * 更新本常量并重新执行录入即可。
 *
 * 清单来源：QwenWork（本企业 AI Agent）当前默认内置 skill 与内置 MCP；其余 Agent
 * （cursor/codex/claude/codebuddy 等）的内置项以产品内置名为准补充。
 */

export const DEFAULT_BUNDLED_SKILLS: string[] = [
  // QwenWork 默认内置 skill（当前版本）
  'xlsx', 'pdf', 'pptx', 'docx', 'qw-pages', 'qw-pages-supabase', 'media-generation',
  'create-skill', 'create-command', 'plugin-creator', 'find-skills', 'qwenwork-guidance',
  'html-markdown', 'mini-program-dev', 'ai-dev-tools',
  // QwenWork 钉钉集成套件（默认随附）
  'dingtalk-mail', 'dingtalk-chat', 'dingtalk-doc', 'dingtalk-wiki', 'dingtalk-drive',
  'dingtalk-contact', 'dingtalk-aisearch', 'dingtalk-calendar', 'dingtalk-todo',
  'dingtalk-minutes', 'dingtalk-event', 'dingtalk-misc', 'dingtalk-shared', 'dingtalk-aitable',
  // 产品设计套件（plugin 默认随附）
  'product-design:frame', 'product-design:scope', 'product-design:audit', 'product-design:probe',
  'product-design:bench', 'product-design:signal', 'product-design:brief', 'product-design:stories',
  'product-design:sitemap', 'product-design:journey', 'product-design:board', 'product-design:flow-web',
  'product-design:flow-mobile', 'product-design:edge', 'product-design:chart', 'product-design:avatar',
  'product-design:poster', 'product-design:pitch', 'product-design:motion-plan', 'product-design:motion-apply',
  'product-design:check', 'product-design:access', 'product-design:test', 'product-design:metric',
  'product-design:qa', 'product-design:prd', 'product-design:retro', 'product-design:extract',
];

export const DEFAULT_BUNDLED_MCP: string[] = [
  // QwenWork 内置 MCP（lazy-loading 内置工具集）
  'qw-builtin',
  // 常见 Agent 内置/官方 MCP
  'cursor-built-in', 'codex-built-in', 'claude-code-built-in', 'codebuddy-built-in',
];

export interface DefaultAllowEntry {
  asset_type: 'skill' | 'mcp';
  asset_key: string;
}

/** 展开为处置注册表条目（disposition=allow 由调用方设置）。 */
export function defaultBundledEntries(): DefaultAllowEntry[] {
  return [
    ...DEFAULT_BUNDLED_SKILLS.map((k) => ({ asset_type: 'skill' as const, asset_key: k })),
    ...DEFAULT_BUNDLED_MCP.map((k) => ({ asset_type: 'mcp' as const, asset_key: k })),
  ];
}
