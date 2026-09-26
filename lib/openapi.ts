/**
 * lib/openapi.ts — 全系统 API 契约（绝对要求 #2：预留整个系统的所有 API）。
 *
 * 单一可信源：本文件以紧凑表驱动描述控制台全部路由（方法/标签/鉴权/摘要），
 * 生成 OpenAPI 3.1 文档，经 GET /api/openapi 输出，供后续把本系统作为其它
 * 系统的功能模块对接（"预留接口，不做强制对接"）。
 *
 * 约束（tests/test_aegis.py::test_openapi_parity 奇偶校验）：
 *   app/api 下每个 route.ts 路由与其导出的 HTTP 方法，必须在本表逐一登记；
 *   新增路由漏登记 → 测试红。反向（表里有、磁盘没有）同样红。
 *
 * 预留端点（reserved=true）：真实存在的 501 桩，外部系统可先按契约开发，
 * 后续点亮实现即可，不需要再改契约。
 */

export type ApiAccess = 'public' | 'session' | 'admin' | 'device';

/** [path, methods, tag, summary, access, reserved?] */
type Row = [string, string[], string, string, ApiAccess, boolean?];

const ROWS: Row[] = [
  // ── 认证（4A）──
  ['/auth/login', ['POST', 'GET'], 'auth', '密码登录（MFA 启用时返回 mfa_token 挑战，不发会话）', 'public'],
  ['/auth/logout', ['POST'], 'auth', '注销当前会话', 'session'],
  ['/auth/me', ['GET'], 'auth', '当前会话身份与角色', 'session'],
  ['/auth/change-password', ['POST'], 'auth', '修改密码（需重新认证）', 'session'],
  ['/auth/mfa', ['GET', 'POST'], 'auth', 'TOTP 两步验证生命周期（enroll/confirm/verify/disable）', 'session'],
  ['/auth/providers', ['GET'], 'auth', '已启用的 SSO/IdP 提供方列表', 'public'],
  ['/auth/oidc/callback', ['GET'], 'auth', 'OIDC 回调（MFA 启用时同样先发挑战）', 'public'],
  ['/auth/uac/callback', ['GET'], 'auth', 'UAC（4A 统一认证）回调', 'public'],
  ['/auth/revoke', ['POST'], 'auth', '吊销指定会话', 'admin'],
  // ── 团队与权限（RBAC）──
  ['/admins', ['GET', 'POST', 'DELETE'], 'team', '管理员名单管理', 'admin'],
  ['/auditors', ['GET', 'POST', 'DELETE'], 'team', '审计员名单管理', 'admin'],
  ['/operators', ['GET', 'POST', 'DELETE'], 'team', '运营员名单管理', 'admin'],
  ['/developers', ['GET', 'POST', 'DELETE'], 'team', '开发者名单管理', 'admin'],
  ['/admin/pg-status', ['GET'], 'team', 'PG 存储健康状态', 'admin'],
  // ── 设备与接入 ──
  ['/devices', ['GET', 'POST', 'PUT', 'DELETE'], 'devices', '设备清单/注册/更新/删除（含 skills/mcp_assets 资产面）', 'session'],
  ['/devices/{id}/findings', ['GET'], 'devices', '单设备原始发现（含抑制前全量）', 'session'],
  ['/devices/{id}/revoke-token', ['POST'], 'devices', '吊销设备接入令牌', 'admin'],
  ['/enroll', ['POST'], 'devices', '零接触注册：签发设备令牌 + 下发未签名策略（免会话）', 'public'],
  // ── 发现与风险 ──
  ['/findings', ['GET'], 'findings', '跨设备聚合发现（加白抑制在查询期过滤，cursor 翻页）', 'session'],
  ['/findings/rule-stats', ['GET'], 'findings', '按规则的发现计数统计', 'session'],
  ['/search', ['GET'], 'findings', '全局搜索（资产/IP/工单/资产标识）', 'session'],
  ['/summary', ['GET'], 'findings', '总览摘要（设备/风险/策略版本态势）', 'session'],
  ['/trend', ['GET'], 'findings', '风险趋势时序', 'session'],
  // ── 处置注册表 ──
  ['/labels', ['GET', 'POST', 'DELETE'], 'labels', '资产处置打标（加白/观察/拉黑）CRUD', 'session'],
  ['/labels/seed-defaults', ['POST'], 'labels', '录入默认自带白名单（不覆盖人工处置）', 'admin'],
  // ── 签名策略 ──
  ['/policy/preview', ['GET'], 'policy', '发布前服务端权威预览（计数与编译输出一致）', 'admin'],
  ['/policy/publish', ['POST', 'GET'], 'policy', '编译处置→签名→发布（爆炸半径闸 + typed override）', 'admin'],
  ['/policy/rollback', ['POST'], 'policy', '回滚上一版（以新版本号重签）', 'admin'],
  ['/policy/current', ['GET'], 'policy', '当前生效发布件', 'session'],
  ['/policy/artifact', ['GET'], 'policy', '当前策略工件下载（终端免会话拉取）', 'public'],
  ['/policy/verify-key', ['GET'], 'policy', '策略验签公钥（公开）', 'public'],
  ['/policy/verify-public', ['GET'], 'policy', '验签公钥（兼容别名）', 'public'],
  ['/policy/posture', ['GET'], 'policy', '策略版本覆盖态势（设备侧加载版本分布）', 'session'],
  ['/policy/keys', ['GET', 'POST'], 'policy', '签名密钥环管理', 'admin'],
  ['/policy/keys/{id}/retire', ['POST'], 'policy', '退役签名密钥', 'admin'],
  // ── 工单 ──
  ['/tickets', ['GET', 'POST'], 'tickets', '风险工单列表/创建', 'session'],
  ['/tickets/{id}', ['GET', 'PUT', 'DELETE'], 'tickets', '工单详情/流转/删除', 'session'],
  ['/tickets/{id}/remediation', ['GET', 'POST'], 'tickets', '工单处置向导（建议动作与执行）', 'session'],
  // ── 基线 ──
  ['/baselines', ['GET', 'POST', 'DELETE'], 'baselines', '安全基线规则集管理', 'admin'],
  ['/baselines/enterprise', ['GET', 'POST'], 'baselines', '企业基线下发/查看', 'admin'],
  ['/baselines/sync', ['POST'], 'baselines', '手动触发上游基线同步', 'admin'],
  // ── 设置 ──
  ['/settings', ['GET', 'PUT'], 'settings', '通用设置读写', 'admin'],
  ['/settings/alerting', ['GET', 'PUT', 'POST'], 'settings', '告警推送配置（webhook/邮件/离线阈值；POST=test 发送）', 'admin'],
  ['/settings/modules', ['GET', 'PUT'], 'settings', '终端模块开关（扫描/执行类，随策略下发）', 'admin'],
  ['/settings/scan-mode', ['GET', 'PUT'], 'settings', '扫描模式（standard/custom）', 'admin'],
  ['/settings/exempt', ['GET', 'PUT'], 'settings', '豁免设备名单（不执行封禁）', 'admin'],
  ['/settings/pinned', ['GET', 'PUT'], 'settings', '钉住版本设备名单', 'admin'],
  ['/settings/retention', ['GET', 'PUT'], 'settings', '数据保留策略', 'admin'],
  ['/settings/rollout', ['GET', 'PUT'], 'settings', '灰度发布（通道/比例）', 'admin'],
  // ── 集成（现有 + 预留桩）──
  ['/integrations', ['GET'], 'integrations', '集成连接状态总览', 'session'],
  ['/integrations/config', ['GET', 'PUT'], 'integrations', '集成配置读写', 'admin'],
  ['/integrations/sync', ['POST'], 'integrations', '手动触发集成同步', 'admin'],
  ['/integrations/health', ['GET'], 'integrations', '集成健康探针（模块存活检查，公开）', 'public', true],
  ['/integrations/events', ['POST'], 'integrations', '【预留】外部模块推送安全事件入风险中心', 'session', true],
  ['/integrations/inventory', ['GET'], 'integrations', '【预留】拉取设备/资产清单（其它系统消费）', 'session', true],
  ['/integrations/subscribe', ['POST'], 'integrations', '【预留】订阅策略/工单/纠偏事件 webhook', 'admin', true],
  ['/integrations/remediate', ['POST'], 'integrations', '【预留】外部 SOAR/编排系统触发纠偏动作', 'admin', true],
  // ── 自动纠偏（绝对要求 #3）──
  ['/remediation/auto-sweep', ['POST'], 'remediation', '立即执行一轮自动纠偏扫描（发现→自动 deny→发布→通知）', 'admin'],
  ['/settings/remediation', ['GET', 'PUT'], 'settings', '自动纠偏配置（开关/自动封禁/通知）', 'admin'],
  // ── 其它 ──
  ['/audit', ['GET'], 'audit', '审计日志查询', 'session'],
  ['/evidence', ['GET'], 'audit', '证据包检索', 'session'],
  ['/evidence/verify', ['POST'], 'audit', '证据包验签', 'session'],
  ['/pipeline/telemetry', ['GET'], 'audit', '管道遥测（发布/投递各阶段门禁结果）', 'session'],
  ['/debug/sync', ['GET'], 'system', '调试：同步状态（生产禁用）', 'admin'],
  ['/openapi', ['GET'], 'system', '本契约文档（OpenAPI 3.1）', 'session'],
];

export interface OpenApiDoc {
  openapi: string;
  info: { title: string; version: string; description: string };
  servers: Array<{ url: string; description: string }>;
  tags: Array<{ name: string; description: string }>;
  paths: Record<string, Record<string, unknown>>;
}

const TAG_DESC: Record<string, string> = {
  auth: '认证与 4A（密码/TOTP/OIDC/UAC）',
  team: '团队与 RBAC（admin/auditor/operator/developer）',
  devices: '设备接入与资产面',
  findings: '发现聚合与风险视图',
  labels: '资产处置注册表（加白/观察/拉黑）',
  policy: '签名策略发布与验签',
  tickets: '风险工单',
  baselines: '安全基线规则',
  settings: '控制台设置',
  integrations: '系统集成（含预留桩，501 直到点亮）',
  remediation: '全自动纠偏闭环（绝对要求 #3）',
  audit: '审计与证据',
  system: '系统级',
};

/** 生成完整 OpenAPI 3.1 文档（GET /api/openapi 输出体）。 */
export function openApiDoc(): OpenApiDoc {
  const paths: Record<string, Record<string, unknown>> = {};
  for (const [path, methods, tag, summary, access, reserved] of ROWS) {
    paths[path] ??= {};
    for (const m of methods) {
      paths[path][m.toLowerCase()] = {
        summary,
        tags: [tag],
        ...(reserved ? { 'x-reserved': true } : {}),
        security: access === 'public' ? [] : access === 'device' ? [{ deviceToken: [] }] : [{ sessionCookie: [] }],
        'x-access': access,
        responses: {
          '200': { description: '成功' },
          ...(access === 'public' ? {} : { '401': { description: '未认证/权限不足' } }),
        },
      };
    }
  }
  // Label provenance is server-owned and is not a publisher verification claim.
  const labelProperties = {
    asset_type: { type: 'string', enum: ['skill', 'mcp', 'path', 'prefix'] },
    asset_key: { type: 'string' },
    tags: { type: 'array', items: { type: 'string' } },
    disposition: { type: 'string', enum: ['', 'allow', 'monitor', 'deny'] },
    note: { type: 'string' },
  };
  const labelSchema = {
    type: 'object',
    required: ['asset_type', 'asset_key', 'tags', 'disposition', 'note', 'decision_source', 'updated_by', 'updated_at'],
    properties: {
      ...labelProperties,
      decision_source: { type: 'string', enum: ['manual', 'preset', 'automatic', 'legacy'], readOnly: true,
        description: 'Server-owned decision origin; preset grants admission only, not a behavioral exception or publisher verification.' },
      updated_by: { type: 'string', readOnly: true },
      updated_at: { type: 'integer', readOnly: true },
    },
  };
  const jsonResponse = (schema: unknown) => ({ description: '成功', content: { 'application/json': { schema } } });
  const errors = {
    '400': { description: '输入无效，或试图写入只读 decision_source' },
    '401': { description: '未认证' }, '403': { description: '权限不足' },
    '503': { description: '标签不可用，包括数据库迁移尚未应用' },
  };
  Object.assign(paths['/labels'].get as object, {
    responses: { ...errors, '200': jsonResponse({ type: 'object', required: ['labels'], properties: {
      labels: { type: 'array', items: labelSchema },
    } }) },
  });
  Object.assign(paths['/labels'].post as object, {
    'x-access': 'admin',
    requestBody: { required: true, content: { 'application/json': { schema: {
      type: 'object', required: ['asset_type', 'asset_key'], properties: labelProperties,
      not: { required: ['decision_source'] },
      description: 'Explicit disposition records a manual decision; editing tags or note alone preserves the existing origin.',
    } } } },
    responses: { ...errors, '200': jsonResponse({ type: 'object', required: ['label'], properties: { label: labelSchema } }) },
  });
  Object.assign(paths['/labels'].delete as object, {
    'x-access': 'admin',
    parameters: ['asset_type', 'asset_key'].map(name => ({ name, in: 'query', required: true,
      schema: name === 'asset_type' ? labelProperties.asset_type : labelProperties.asset_key })),
    responses: { ...errors, '200': jsonResponse({ type: 'object', required: ['removed'], properties: { removed: { type: 'boolean' } } }) },
  });
  return {
    openapi: '3.1.0',
    info: {
      title: 'Aegis Sentinel Console API',
      version: '1.0.0',
      description:
        'AI Agent 安全治理控制台的完整 API 契约。路径均相对控制台根（生产为 https://<origin>/api）。' +
        '预留端点（x-reserved=true）当前返回 501 not_implemented，供外部系统按契约先行动开发，' +
        '后续点亮实现不破坏契约。终端侧 Collector API（/aegis/v1/*）独立于本契约。',
    },
    servers: [{ url: '/api', description: '控制台 API（会话 Cookie 或未来服务令牌）' }],
    tags: Object.entries(TAG_DESC).map(([name, description]) => ({ name, description })),
    paths,
  };
}

/** 预留桩统一响应体（点亮前的稳定契约）。 */
export const RESERVED_STUB_BODY = {
  schema: 'aegis.integration/v1',
  reserved: true,
  error: 'not_implemented',
  hint: '该端点为预留契约（见 GET /api/openapi 的 x-reserved），当前未启用；对接方请按契约先行开发。',
} as const;
