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
import type { FormEvent } from 'react';
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
  | 'other';

export type DeviceStatus = 'online' | 'offline' | 'stale' | 'needs_attention';

export type Device = {
  device_id: string;
  hostname: string;
  owner: string;
  agent_type: AgentType;
  agent_version?: string;
  policy_version?: string;
  status?: DeviceStatus;
  notes?: string;
  last_seen?: string | number | null;
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

/** 把单条不可信记录规范化为 `Device`；缺少 device_id 时返回 null。 */
export function parseDevice(raw: unknown): Device | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const data = raw as Record<string, unknown>;
  const deviceId = text(data.device_id ?? data.id ?? data.deviceId, 64);
  if (!deviceId) return null;
  const hostname = text(data.hostname ?? data.host ?? data.name, 128);
  const agentVersion = text(data.agent_version ?? data.agentVersion, 32);
  const policyVersion = text(data.policy_version ?? data.policyVersion, 32);
  const notes = text(data.notes ?? data.note ?? data.comment, 512);
  const lastSeen = data.last_seen ?? data.lastSeen ?? null;
  return {
    device_id: deviceId,
    hostname: hostname || deviceId,
    owner: text(data.owner ?? data.user ?? data.owner_name, 128),
    agent_type: normalizeAgentType(data.agent_type ?? data.agentType ?? data.tool),
    ...(agentVersion ? { agent_version: agentVersion } : {}),
    ...(policyVersion ? { policy_version: policyVersion } : {}),
    status: normalizeDeviceStatus(data.status ?? data.state),
    ...(notes ? { notes } : {}),
    last_seen:
      typeof lastSeen === 'string' || typeof lastSeen === 'number'
        ? lastSeen
        : null,
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
  if (!values.hostname.trim()) errors.hostname = '主机名为必填项';
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

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
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
          <span>终端在 MDM / 域内登记的主机名</span>
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
          placeholder="陈昊"
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
          <span>可选，最多 512 字符，仅控制台可见</span>
        </div>
        <Textarea
          id={ids.notes}
          value={notes}
          onChange={(event) => setNotes(event.target.value)}
          placeholder="例如：试点组第一批，允许访问 payment-service 仓库"
          maxLength={512}
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
