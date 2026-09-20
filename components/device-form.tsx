'use client';

/**
 * 设备注册 / 编辑表单。
 *
 * 同时服务于 `app/devices/page.tsx` 的两个场景：
 *   - `mode="create"`：顶部可折叠的「注册新终端」面板；
 *   - `mode="edit"`：点击终端行后展开的行内编辑面板。
 *
 * 该模块也是设备领域模型的唯一出口：`Device` 类型、Agent 工具枚举、
 * 以及把不可信的 `/api/devices` 响应规范化为 `Device` 的解析函数都在此定义，
 * 页面只负责编排状态与请求。
 */

import { useId, useState } from 'react';
import type { SubmitEvent } from 'react';
import { Check, X } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import {
  NativeSelect,
  NativeSelectOption,
} from '@/components/ui/native-select';
import { Spinner } from '@/components/ui/spinner';
import { Textarea } from '@/components/ui/textarea';

/* ── 领域模型 ───────────────────────────────────────────── */

export type AgentType =
  | 'cursor'
  | 'claude_code'
  | 'codex_cli'
  | 'windsurf'
  | 'gemini_cli'
  | 'github_copilot_cli'
  | 'qwen_enterprise'
  | 'tongyi_lingma'
  | 'codebuddy'
  | 'workbuddy'
  | 'other';

export type DeviceStatus = 'online' | 'offline' | 'stale' | 'needs_attention';

/** 该终端上尚未闭环的发现项，按严重等级汇总。 */
export type FindingsSummary = {
  critical: number;
  high: number;
  medium: number;
  low: number;
};

export type Device = {
  device_id: string;
  hostname: string;
  owner: string;
  agent_type: AgentType;
  agent_version: string;
  policy_version: string;
  status: DeviceStatus;
  /** 最近一次上报时间（epoch 毫秒），0 表示从未上报。 */
  last_seen: number;
  /** 注册时间（epoch 毫秒）。 */
  registered_at: number;
  notes?: string;
  findings_summary?: FindingsSummary;
  /** 该设备最新报告检出的已安装 AI Agent 清单（Collector 从 inventory 提取）。 */
  tools?: string[];
  /** 上报的操作系统用户（用于"谁在用这台机器"）。 */
  os_user?: string;
  /** 操作系统类型（macos/windows/linux），用于设备类型列。 */
  os?: string;
  /** 真实硬件序列号（mac/win 上报），作为终端主标识便于定位设备。 */
  serial?: string;
  /** 物理网卡采集（MAC + 本机 IP）+ Collector 观测的互联网出口 IP；仅物理网卡，不含虚拟口。 */
  network?: {
    physical_nics?: { name: string; mac: string; ips?: string[] }[];
    macs?: string[];
    local_ips?: string[];
    egress_ip?: string;
  };
  /** 运行态：system(root 守护)/user(用户级, 已废止形态)。能力诚实化标注用。 */
  run_mode?: string;
  run_mode_inferred?: boolean;
  /** 真实封禁能力：pf=连接级封禁可用; es=ES AUTH_EXEC 已点亮。未具备=false, 不夸大。 */
  capabilities?: { pf?: boolean; es?: boolean };
  scan_root?: string;
  /** 封禁豁免设备（开发主机等）：只报不封。 */
  /** 自更保护(pinned)：不自动更新，只接受人工/桌管更新。与豁免分离。 */
  pinned?: boolean;
  exempt?: boolean;
  /** 自更非例行结果（preflight_failed / rolled_back:* / apply_failed:* / updated）。
   *  例行结果终端不上报，故常缺省。用于 canary 监控闭环（坏更新被拒/回滚可见）。 */
  self_update?: { updated?: boolean; reason?: string; from?: string; to?: string; latest?: string; at?: number };
  /** 该设备可被 deny 的资产面（skill 名 / MCP server 名），供封禁影响预览/透明化。 */
  skills?: string[];
  mcp_assets?: string[];
  /** 终端执行器回执（封禁/隔离/恢复动作及备份位置），最近若干条。 */
  enforcement?: {
    asset_type: string;
    asset_key: string;
    action: string;
    target?: string;
    backup?: string;
    reason?: string;
    ok?: boolean;
    at?: number;
  }[];
};

/** 表单提交给 `/api/devices` 的载荷。 */
export type DeviceFormData = {
  device_id: string;
  hostname: string;
  owner: string;
  agent_type: AgentType;
  notes: string;
};

export const AGENT_TYPE_OPTIONS: readonly {
  value: AgentType;
  label: string;
}[] = [
  { value: 'cursor', label: 'Cursor' },
  { value: 'claude_code', label: 'Claude Code' },
  { value: 'codex_cli', label: 'Codex CLI' },
  { value: 'windsurf', label: 'Windsurf' },
  { value: 'gemini_cli', label: 'Gemini CLI' },
  { value: 'github_copilot_cli', label: 'GitHub Copilot' },
  { value: 'qwen_enterprise', label: 'QwenWork / 通义千问' },
  { value: 'tongyi_lingma', label: '通义灵码' },
  { value: 'codebuddy', label: 'CodeBuddy' },
  { value: 'workbuddy', label: 'WorkBuddy' },
  { value: 'other', label: '其他工具' },
];

export function agentTypeLabel(value: string | undefined): string {
  return (
    AGENT_TYPE_OPTIONS.find((option) => option.value === value)?.label ??
    '未识别'
  );
}

/* ── 不可信响应规范化 ───────────────────────────────────── */

const DEVICE_ID_PATTERN = /^[A-Za-z0-9-]{3,64}$/;

function text(value: unknown, limit: number): string {
  if (typeof value !== 'string') return '';
  return value.trim().slice(0, limit);
}

export function normalizeAgentType(value: unknown): AgentType {
  const raw = text(value, 64)
    .toLowerCase()
    .replace(/[\s.]+/g, '_');
  const exact = AGENT_TYPE_OPTIONS.find((option) => option.value === raw);
  if (exact) return exact.value;
  if (raw.includes('cursor')) return 'cursor';
  if (raw.includes('claude')) return 'claude_code';
  if (raw.includes('codex')) return 'codex_cli';
  if (raw.includes('windsurf') || raw.includes('surf')) return 'windsurf';
  return 'other';
}

export function normalizeDeviceStatus(value: unknown): DeviceStatus {
  const raw = text(value, 32).toLowerCase().replace(/[\s.]+/g, '_');
  if (raw === 'online' || raw === 'active' || raw === 'protected') return 'online';
  if (raw === 'stale' || raw === 'expired' || raw === 'outdated') return 'stale';
  if (
    raw === 'needs_attention' ||
    raw === 'attention' ||
    raw === 'non_compliant' ||
    raw === 'at_risk' ||
    raw === 'critical'
  )
    return 'needs_attention';
  return 'offline';
}

/** 接口用 `unreported` 占位「注册后还没上报过版本」的终端。 */
const UNREPORTED = 'unreported';

function count(value: unknown): number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0
    ? value
    : 0;
}

/** 接口返回 epoch 毫秒；同时容忍秒级时间戳与 ISO 字符串，无法解析时为 0。 */
function timestamp(value: unknown): number {
  if (typeof value === 'number')
    return Number.isFinite(value) && value > 0 ? (value > 1e12 ? value : value * 1000) : 0;
  if (typeof value !== 'string') return 0;
  const trimmed = value.trim();
  if (!trimmed) return 0;
  if (/^\d+$/.test(trimmed)) return timestamp(Number(trimmed));
  const parsed = Date.parse(trimmed);
  return Number.isNaN(parsed) ? 0 : parsed;
}

function version(value: unknown): string {
  const raw = text(value, 64);
  return raw || UNREPORTED;
}

/** Agent 版本列的展示值：把服务端占位符翻译成中文。 */
export function agentVersionLabel(value: string | undefined): string {
  if (!value || value === UNREPORTED) return '未上报';
  return value;
}

function parseFindings(value: unknown): FindingsSummary | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const data = value as Record<string, unknown>;
  return {
    critical: count(data.critical),
    high: count(data.high),
    medium: count(data.medium),
    low: count(data.low),
  };
}

/** BIOS/CSProduct 占位序列号（白牌机/部分主板返回的字面垃圾值）。当作真实序列号会显示
 *  垃圾且可能跨机碰撞；命中则视为"无有效序列号"，界面回落设备 ID 标识。 */
const PLACEHOLDER_SERIALS = new Set([
  '', 'to be filled by o.e.m.', 'none', 'default string', 'unknown', 'o.e.m.', 'not specified',
  'system serial number', 'serial number', 'n/a', 'na', 'empty', 'to be filled',
]);

/** 收敛不可信的 network 采集载荷：只保留形态合法的物理网卡/MAC/IP/出口 IP，丢弃非法项。 */
function parseNetwork(raw: unknown): Device['network'] | undefined {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return undefined;
  const n = raw as Record<string, unknown>;
  const strList = (v: unknown): string[] | undefined =>
    Array.isArray(v)
      ? v.filter((x): x is string => typeof x === 'string' && x.length > 0 && x.length <= 64).slice(0, 64)
      : undefined;
  const macs = strList(n.macs);
  const localIps = strList(n.local_ips);
  const egress = text(n.egress_ip, 64);
  const pn = Array.isArray(n.physical_nics)
    ? n.physical_nics
        .filter((x): x is Record<string, unknown> => !!x && typeof x === 'object' && !Array.isArray(x))
        .slice(0, 64)
        .map((x) => ({ name: text(x.name, 64), mac: text(x.mac, 64), ips: strList(x.ips) ?? [] }))
        .filter((x) => x.name && x.mac)
    : undefined;
  if (!macs && !localIps && !egress && !(pn && pn.length > 0)) return undefined;
  return {
    ...(pn && pn.length > 0 ? { physical_nics: pn } : {}),
    ...(macs ? { macs } : {}),
    ...(localIps ? { local_ips: localIps } : {}),
    ...(egress ? { egress_ip: egress } : {}),
  };
}

/** 把单条不可信记录规范化为 `Device`；缺少 device_id 时返回 null。 */
export function parseDevice(raw: unknown): Device | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const data = raw as Record<string, unknown>;
  const deviceId = text(data.device_id ?? data.id ?? data.deviceId, 64);
  if (!deviceId) return null;
  const hostname = text(data.hostname ?? data.host ?? data.name, 253);
  const notes = text(data.notes ?? data.note ?? data.comment, 2000);
  const findings = parseFindings(data.findings_summary ?? data.findings);
  const rawTools = Array.isArray(data.tools) ? data.tools : [];
  const tools = rawTools.filter((t): t is string => typeof t === 'string' && t.length > 0).slice(0, 50);
  const osUser = text(data.os_user ?? data.osuser, 64);
  return {
    device_id: deviceId,
    hostname: hostname || deviceId,
    owner: text(data.owner ?? data.user ?? data.owner_name, 128),
    agent_type: normalizeAgentType(data.agent_type ?? data.agentType ?? data.tool),
    agent_version: version(data.agent_version ?? data.agentVersion),
    policy_version: version(data.policy_version ?? data.policyVersion),
    status: normalizeDeviceStatus(data.status ?? data.state),
    last_seen: timestamp(data.last_seen ?? data.lastSeen),
    registered_at: timestamp(data.registered_at ?? data.registeredAt),
    ...(notes ? { notes } : {}),
    ...(findings ? { findings_summary: findings } : {}),
    ...(tools.length > 0 ? { tools } : {}),
    ...(osUser ? { os_user: osUser } : {}),
    ...(() => { const o = text(data.os ?? data.platform, 16); return o ? { os: o } : {}; })(),
    // 序列号必须透传：设备页以它为主标识并支持搜索；此前 parseDevice 未取该字段，
    // 导致前端拿不到序列号（列表回落 device_id、编辑面板显示占位）。
    // 但 BIOS 占位垃圾值（如 "System Serial Number"）视为无序列号，回落设备 ID。
    ...(() => {
      const s = text(data.serial ?? data.serial_number, 64);
      return s && !PLACEHOLDER_SERIALS.has(s.toLowerCase()) ? { serial: s } : {};
    })(),
    // 物理网卡/出口 IP 必须透传：设备页要展示 MAC、本机 IP、互联网出口；此前未取会静默丢字段。
    ...(() => { const n = parseNetwork(data.network); return n ? { network: n } : {}; })(),
    ...(() => { const rm = text(data.run_mode, 16); return rm ? { run_mode: rm, ...(data.run_mode_inferred === true ? { run_mode_inferred: true } : {}) } : {}; })(),
    ...(() => {
      const c = data.capabilities as Record<string, unknown> | undefined;
      if (!c || typeof c !== 'object') return {};
      return { capabilities: { pf: Boolean(c.pf), es: Boolean(c.es) } };
    })(),
    ...(() => { const sr = text(data.scan_root, 64); return sr ? { scan_root: sr } : {}; })(),
    ...(data.exempt === true ? { exempt: true } : {}),
    ...(data.pinned === true ? { pinned: true } : {}),
    // 自更非例行结果透传（收敛形态：只保留已知字段，丢弃非法项）。
    ...(() => {
      const su = data.self_update as Record<string, unknown> | undefined;
      if (!su || typeof su !== 'object' || typeof su.reason !== 'string') return {};
      return {
        self_update: {
          updated: su.updated === true,
          reason: String(su.reason).slice(0, 64),
          ...(typeof su.from === 'string' ? { from: su.from.slice(0, 32) } : {}),
          ...(typeof su.to === 'string' ? { to: su.to.slice(0, 32) } : {}),
          ...(typeof su.latest === 'string' ? { latest: su.latest.slice(0, 32) } : {}),
          ...(typeof su.at === 'number' ? { at: su.at } : {}),
        },
      };
    })(),
    // 可封禁资产面透传（收敛：只保留字符串、限长限量）。
    ...(() => {
      const s = data.skills;
      return Array.isArray(s) ? { skills: s.filter((x): x is string => typeof x === 'string' && x.length <= 128).slice(0, 200) } : {};
    })(),
    ...(() => {
      const s = data.mcp_assets;
      return Array.isArray(s) ? { mcp_assets: s.filter((x): x is string => typeof x === 'string' && x.length <= 128).slice(0, 200) } : {};
    })(),
    // 执行器回执透传（收敛形态，丢弃非法项），设备页展示封禁/隔离/恢复动作。
    ...(() => {
      const raw = data.enforcement;
      if (!Array.isArray(raw)) return {};
      const list = raw
        .filter((x): x is Record<string, unknown> => !!x && typeof x === 'object' && !Array.isArray(x))
        .slice(0, 10)
        .map((x) => ({
          asset_type: text(x.asset_type, 64),
          asset_key: text(x.asset_key, 64),
          action: text(x.action, 64),
          ...(typeof x.target === 'string' ? { target: x.target.slice(0, 512) } : {}),
          ...(typeof x.backup === 'string' ? { backup: x.backup.slice(0, 512) } : {}),
          ...(typeof x.reason === 'string' ? { reason: x.reason.slice(0, 120) } : {}),
          ...(typeof x.ok === 'boolean' ? { ok: x.ok } : {}),
          ...(typeof x.at === 'number' ? { at: x.at } : {}),
        }))
        .filter((x) => x.asset_type && x.asset_key && x.action);
      return list.length > 0 ? { enforcement: list } : {};
    })(),
  };
}

/**
 * 解析 `GET /api/devices` 载荷，容忍 `{ devices: [] }` / `{ data: [] }` / 裸数组。
 * 结果按 device_id 去重，保持服务端返回顺序。
 */
export function parseDeviceList(payload: unknown): Device[] {
  let rows: unknown[] = [];
  if (Array.isArray(payload)) {
    rows = payload;
  } else if (payload && typeof payload === 'object') {
    const data = payload as Record<string, unknown>;
    const key = ['devices', 'data', 'items', 'results', 'records'].find(
      (candidate) => Array.isArray(data[candidate]),
    );
    rows = key ? (data[key] as unknown[]) : [];
  }
  const seen = new Set<string>();
  const devices: Device[] = [];
  for (const row of rows) {
    const device = parseDevice(row);
    if (!device || seen.has(device.device_id)) continue;
    seen.add(device.device_id);
    devices.push(device);
  }
  return devices;
}

/* ── 表单校验 ───────────────────────────────────────────── */

export type DeviceFormErrors = Partial<
  Record<'device_id' | 'hostname' | 'owner', string>
>;

/** 与 `POST/PUT /api/devices` 的 HOSTNAME_PATTERN 保持一致。 */
const HOSTNAME_PATTERN = /^[A-Za-z0-9._-]{1,253}$/;

export function validateDeviceForm(values: {
  device_id: string;
  hostname: string;
  owner: string;
}): DeviceFormErrors {
  const errors: DeviceFormErrors = {};
  const deviceId = values.device_id.trim();
  if (!deviceId) errors.device_id = '设备 ID 为必填项';
  else if (!DEVICE_ID_PATTERN.test(deviceId))
    errors.device_id = '设备 ID 需为 3 至 64 位字母、数字或连字符';
  const hostname = values.hostname.trim();
  if (!hostname) errors.hostname = '主机名为必填项';
  else if (!HOSTNAME_PATTERN.test(hostname))
    errors.hostname = '主机名只能包含字母、数字、点、下划线与连字符';
  if (!values.owner.trim()) errors.owner = '负责人为必填项';
  return errors;
}

/* ── 组件 ───────────────────────────────────────────────── */

export type DeviceFormProps = {
  mode: 'create' | 'edit';
  initialData?: Partial<Device>;
  onSubmit: (data: DeviceFormData) => Promise<void>;
  onCancel: () => void;
};

/** `.setting-row` 是横向两端对齐布局，这里允许窄屏换行并留出间距。 */
const rowStyle = { gap: 12, flexWrap: 'wrap' } as const;
const controlStyle = { width: 264, maxWidth: '100%', flexShrink: 0 } as const;
const errorStyle = { color: 'var(--destructive)', fontSize: 11 } as const;

export default function DeviceForm({
  mode,
  initialData,
  onSubmit,
  onCancel,
}: DeviceFormProps) {
  const uid = useId();
  const isEdit = mode === 'edit';

  const [deviceId, setDeviceId] = useState(initialData?.device_id ?? '');
  const [hostname, setHostname] = useState(initialData?.hostname ?? '');
  const [owner, setOwner] = useState(initialData?.owner ?? '');
  const [agentType, setAgentType] = useState<AgentType>(
    initialData?.agent_type ?? 'cursor',
  );
  const [notes, setNotes] = useState(initialData?.notes ?? '');
  const [errors, setErrors] = useState<DeviceFormErrors>({});
  const [submitting, setSubmitting] = useState(false);

  async function handleSubmit(event: SubmitEvent<HTMLFormElement>) {
    event.preventDefault();
    if (submitting) return;
    const nextErrors = validateDeviceForm({
      device_id: deviceId,
      hostname,
      owner,
    });
    setErrors(nextErrors);
    if (Object.keys(nextErrors).length > 0) return;
    setSubmitting(true);
    try {
      await onSubmit({
        device_id: deviceId.trim(),
        hostname: hostname.trim(),
        owner: owner.trim(),
        agent_type: agentType,
        notes: notes.trim(),
      });
    } finally {
      setSubmitting(false);
    }
  }

  const ids = {
    deviceId: `${uid}-device-id`,
    hostname: `${uid}-hostname`,
    owner: `${uid}-owner`,
    agentType: `${uid}-agent-type`,
    notes: `${uid}-notes`,
  };

  return (
    <form className="animate-entrance" onSubmit={handleSubmit} noValidate>
      <div className="setting-row" style={rowStyle}>
        <div>
          <strong>
            <Label htmlFor={ids.deviceId}>设备 ID</Label>
          </strong>
          <span>
            {isEdit
              ? '唯一标识，注册后不可修改'
              : '3 至 64 位字母、数字或连字符，例如 ENG-MBP-1032'}
          </span>
          {errors.device_id && (
            <span id={`${ids.deviceId}-error`} role="alert" style={errorStyle}>
              {errors.device_id}
            </span>
          )}
        </div>
        <Input
          id={ids.deviceId}
          value={deviceId}
          onChange={(event) => setDeviceId(event.target.value)}
          placeholder="ENG-MBP-1032"
          autoComplete="off"
          spellCheck={false}
          disabled={submitting || isEdit}
          readOnly={isEdit}
          required={!isEdit}
          aria-invalid={Boolean(errors.device_id)}
          aria-describedby={errors.device_id ? `${ids.deviceId}-error` : undefined}
          style={controlStyle}
        />
      </div>

      <div className="setting-row" style={rowStyle}>
        <div>
          <strong>
            <Label htmlFor={ids.hostname}>主机名</Label>
          </strong>
          <span>终端在 MDM / 域内登记的主机名，仅支持字母、数字、点、下划线与连字符</span>
          {errors.hostname && (
            <span id={`${ids.hostname}-error`} role="alert" style={errorStyle}>
              {errors.hostname}
            </span>
          )}
        </div>
        <Input
          id={ids.hostname}
          value={hostname}
          onChange={(event) => setHostname(event.target.value)}
          placeholder="mbp-eng-1032"
          autoComplete="off"
          disabled={submitting}
          required
          aria-invalid={Boolean(errors.hostname)}
          aria-describedby={errors.hostname ? `${ids.hostname}-error` : undefined}
          style={controlStyle}
        />
      </div>

      <div className="setting-row" style={rowStyle}>
        <div>
          <strong>
            <Label htmlFor={ids.owner}>负责人</Label>
          </strong>
          <span>终端使用人，风险事件将通知到该负责人</span>
          {errors.owner && (
            <span id={`${ids.owner}-error`} role="alert" style={errorStyle}>
              {errors.owner}
            </span>
          )}
        </div>
        <Input
          id={ids.owner}
          value={owner}
          onChange={(event) => setOwner(event.target.value)}
          placeholder="张三"
          autoComplete="off"
          disabled={submitting}
          required
          aria-invalid={Boolean(errors.owner)}
          aria-describedby={errors.owner ? `${ids.owner}-error` : undefined}
          style={controlStyle}
        />
      </div>

      <div className="setting-row" style={rowStyle}>
        <div>
          <strong>
            <Label htmlFor={ids.agentType}>Agent 工具</Label>
          </strong>
          <span>该终端上受管的 AI Coding 工具类型</span>
        </div>
        <NativeSelect
          id={ids.agentType}
          value={agentType}
          onChange={(event) => setAgentType(normalizeAgentType(event.target.value))}
          disabled={submitting}
          style={controlStyle}
        >
          {AGENT_TYPE_OPTIONS.map((option) => (
            <NativeSelectOption key={option.value} value={option.value}>
              {option.label}
            </NativeSelectOption>
          ))}
        </NativeSelect>
      </div>

      <div className="setting-row" style={rowStyle}>
        <div>
          <strong>
            <Label htmlFor={ids.notes}>备注</Label>
          </strong>
          <span>可选，最多 1000 字符，仅控制台可见</span>
        </div>
        <Textarea
          id={ids.notes}
          value={notes}
          onChange={(event) => setNotes(event.target.value)}
          placeholder="例如：试点组第一批，允许访问 payment-service 仓库"
          maxLength={1000}
          disabled={submitting}
          style={{ ...controlStyle, width: 320 }}
        />
      </div>

      <div
        style={{
          display: 'flex',
          flexWrap: 'wrap',
          gap: 10,
          justifyContent: 'flex-end',
          paddingTop: 16,
        }}
      >
        <Button
          type="button"
          variant="outline"
          onClick={onCancel}
          disabled={submitting}
        >
          <X />
          取消
        </Button>
        <Button type="submit" disabled={submitting}>
          {submitting ? <Spinner /> : <Check />}
          {submitting
            ? isEdit
              ? '保存中…'
              : '注册中…'
            : isEdit
              ? '保存修改'
              : '注册设备'}
        </Button>
      </div>
    </form>
  );
}
