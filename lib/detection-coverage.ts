/**
 * 检测覆盖 / 技战法映射的静态模型（客户端安全，不引入任何 node:* 依赖）。
 *
 * - TECHNIQUES：技战法（OWASP GenAI LLM Top 10 / Agentic Top 10）→ 检测它的规则 ID。
 *   规则 ID 必须真实存在于策略规则集；映射本身是产品内置的覆盖模型。
 * - FALLBACK_RULE_SETS：出厂基座规则集的静态镜像（与 lib/policy.ts 的 BASE_POLICY
 *   skill/mcp/code_rules 对齐）。仅当控制台**尚未发布**签名策略时用作回退；已发布时
 *   组件以 /api/policy/current 的真实规则集为准。修改 BASE_POLICY 规则集时需同步此处。
 */

export type RuleSet = 'skill' | 'mcp' | 'code';

export const SET_LABEL: Record<RuleSet, string> = {
  skill: 'Skill',
  mcp: 'MCP',
  code: '代码',
};

export interface TechniqueRule {
  set: RuleSet;
  ids: string[];
}

export interface Technique {
  id: string;
  name: string;
  framework: 'OWASP LLM' | 'OWASP AGT';
  rules: TechniqueRule[];
}

export const FALLBACK_RULE_SETS: Record<RuleSet, string[]> = {
  skill: ['unknown_skill', 'prompt_override', 'hidden_instruction', 'credential_access', 'unbounded_shell', 'skill_symlink_escape'],
  mcp: [
    'unknown_mcp',
    'unapproved_mcp_transport',
    'ambiguous_mcp_transport',
    'unapproved_mcp_domain',
    'unapproved_mcp_command_path',
    'unapproved_mcp_invocation',
    'invalid_mcp_arguments',
    'invalid_mcp_server',
    'invalid_mcp_environment',
    'mcp_url_credentials',
    'broad_filesystem_scope',
    'literal_mcp_secret',
  ],
  code: [
    'hardcoded_secret',
    'shell_true',
    'dynamic_eval',
    'weak_random_token',
    'blocked_command',
    'insecure_tls_verification',
    'unsafe_deserialization',
    'debug_mode_enabled',
    'empty_exception_handler',
    'oversized_file_skipped',
    'dependency_unpinned',
    'dependency_untrusted_source',
    'missing_lockfile',
  ],
};

export const TECHNIQUES: Technique[] = [
  {
    id: 'LLM01 / AGT01',
    name: '提示注入 · Agent 目标劫持',
    framework: 'OWASP LLM',
    rules: [{ set: 'skill', ids: ['prompt_override', 'hidden_instruction'] }],
  },
  {
    id: 'LLM02 / AGT05',
    name: '不安全输出处理 · 意外代码执行',
    framework: 'OWASP LLM',
    rules: [{ set: 'code', ids: ['dynamic_eval', 'shell_true', 'unsafe_deserialization'] }],
  },
  {
    id: 'LLM05 / AGT04',
    name: '供应链 · Agentic 供应链投毒',
    framework: 'OWASP LLM',
    rules: [
      { set: 'code', ids: ['dependency_unpinned', 'dependency_untrusted_source', 'missing_lockfile'] },
      { set: 'skill', ids: ['unknown_skill', 'skill_symlink_escape'] },
      { set: 'mcp', ids: ['unknown_mcp'] },
    ],
  },
  {
    id: 'LLM06',
    name: '敏感信息泄露（凭据 / 密钥）',
    framework: 'OWASP LLM',
    rules: [
      { set: 'code', ids: ['hardcoded_secret'] },
      { set: 'mcp', ids: ['literal_mcp_secret', 'mcp_url_credentials'] },
      { set: 'skill', ids: ['credential_access'] },
    ],
  },
  {
    id: 'LLM07 / AGT02',
    name: '不安全插件设计 · 工具滥用',
    framework: 'OWASP LLM',
    rules: [
      { set: 'mcp', ids: ['broad_filesystem_scope', 'unapproved_mcp_command_path', 'unapproved_mcp_invocation', 'invalid_mcp_arguments'] },
      { set: 'skill', ids: ['unbounded_shell'] },
      { set: 'code', ids: ['blocked_command'] },
    ],
  },
  {
    id: 'LLM08 / AGT03',
    name: '过度授权 · 身份/权限滥用',
    framework: 'OWASP LLM',
    rules: [
      { set: 'mcp', ids: ['broad_filesystem_scope', 'unapproved_mcp_domain', 'unapproved_mcp_transport', 'ambiguous_mcp_transport'] },
      { set: 'skill', ids: ['unbounded_shell'] },
    ],
  },
  {
    id: 'SEC-CODE-03',
    name: '传输安全（TLS 校验被禁用）',
    framework: 'OWASP LLM',
    rules: [{ set: 'code', ids: ['insecure_tls_verification'] }],
  },
  {
    id: 'LLM04',
    name: '模型 / Agent 拒绝服务',
    framework: 'OWASP LLM',
    rules: [{ set: 'code', ids: ['oversized_file_skipped'] }],
  },
  {
    id: 'AGT06',
    name: '记忆 / 上下文投毒',
    framework: 'OWASP AGT',
    rules: [],
  },
  {
    id: 'AGT07',
    name: '不安全的 Agent 间通信',
    framework: 'OWASP AGT',
    rules: [],
  },
  {
    id: 'LLM09 / AGT08',
    name: '过度依赖 · 级联幻觉',
    framework: 'OWASP AGT',
    rules: [],
  },
];
