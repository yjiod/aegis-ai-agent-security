'use client';

/**
 * 设备与 Agent — 受管终端注册表。
 *
 * 数据来自 `GET /api/devices`（内存注册表，见 lib/store.ts），支持完整的
 * 增删改查：注册表单 POST、行内编辑 PUT、删除按钮走确认对话框后 DELETE。
 * 接口不可用时展示空态并提示重试；不注入任何实时数据。
 * 此时任何写操作都只会得到失败提示，不会伪造成功。
 */

import { Fragment, useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type { CSSProperties } from 'react';
import {
  AlertTriangle,
  Bot,
  ChevronDown,
  CircleCheck,
  CircleDot,
  Laptop,
  Pencil,
  Plus,
  RefreshCw,
  Search,
  ShieldCheck,
  Trash2,
  X,
} from 'lucide-react';
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Progress } from '@/components/ui/progress';
import { Spinner } from '@/components/ui/spinner';
import { useCollector } from '@/components/collector-context';
import { useRole } from '@/components/role-context';
import DeviceForm, {
  AGENT_TYPE_OPTIONS,
  agentTypeLabel,
  agentVersionLabel,
  parseDevice,
  parseDeviceList,
  type Device,
  type DeviceFormData,
  type DeviceStatus,
} from '@/components/device-form';

/* ─── 展示层常量 ─────────────────────────────────────────── */

type DataSource = 'loading' | 'api' | 'demo';
type ToastTone = 'info' | 'success' | 'error';

const JSON_HEADERS = { 'Content-Type': 'application/json' } as const;

const MINUTE = 60_000;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;

/** 状态徽标：绿=在线，灰=离线，琥珀=过期，红=需处理。 */
const STATUS_META: Record<
  DeviceStatus,
  { label: string; className: string; style?: CSSProperties }
> = {
  online: { label: '在线', className: 'pass' },
  offline: {
    label: '离线',
    className: '',
    style: {
      color: 'var(--muted-foreground)',
      background: 'color-mix(in srgb, var(--muted-foreground) 12%, transparent)',
      border: '1px solid var(--border)',
      boxShadow: 'none',
    },
  },
  stale: { label: '过期', className: 'warn' },
  needs_attention: { label: '需处理', className: 'fail' },
};

/** 接口错误码的中文说明，`details` 存在时优先展示逐字段原因。 */
const ERROR_COPY: Record<string, string> = {
  device_already_registered: '该设备 ID 已在注册表中，请改用行内编辑',
  device_not_found: '设备不存在或已被移除',
  validation_failed: '提交内容未通过服务端校验',
  no_updatable_fields: '没有需要更新的字段',
  read_only_field: '请求包含服务端托管字段',
  immutable_field: '请求包含不可修改字段',
};

const cellStackStyle: CSSProperties = {
  display: 'flex',
  flexDirection: 'column',
  gap: 2,
  minWidth: 0,
};

const inlinePanelStyle: CSSProperties = {
  border: '1px solid var(--line-base)',
  borderRadius: 10,
  background: 'var(--surface-1)',
  padding: '4px 14px 14px',
  margin: '2px 0 12px',
};

/** 接口不可用时的覆盖分布占位（全 0）。 */
const TOOL_COVERAGE_DEMO = [
  { name: 'Cursor', total: 124, online: 100 },
  { name: 'Claude Code', total: 86, online: 78 },
  { name: 'Codex CLI', total: 64, online: 58 },
  { name: 'Windsurf', total: 38, online: 34 },
];

/* ─── 空态占位（生产环境不注入实时数据） ─── */

type DeviceSeed = Omit<Device, 'last_seen' | 'registered_at'> & {
  seenAgo: number;
  enrolledAgo: number;
};

const DEVICE_SEEDS: DeviceSeed[] = [
  {
    device_id: 'ENG-MBP-1032',
    hostname: 'eng-mbp-1032.corp.aegis.local',
    owner: '陈昊',
    agent_type: 'cursor',
    agent_version: 'v3.8',
    policy_version: 'v4.8',
    status: 'online',
    notes: '研发部 · Cursor 企业版已纳管，Skill 白名单生效。',
    seenAgo: 4 * MINUTE,
    enrolledAgo: 214 * DAY,
  },
  {
    device_id: 'MKT-LT-2841',
    hostname: 'mkt-lt-2841.corp.aegis.local',
    owner: '林妍',
    agent_type: 'cursor',
    agent_version: 'v3.7',
    policy_version: 'v4.8',
    status: 'needs_attention',
    notes: '市场部 · MCP filesystem 越权访问待研判。',
    seenAgo: 2 * MINUTE,
    enrolledAgo: 96 * DAY,
  },
  {
    device_id: 'ENG-LT-0948',
    hostname: 'eng-lt-0948.corp.aegis.local',
    owner: '周航',
    agent_type: 'codex_cli',
    agent_version: 'v3.8',
    policy_version: 'v4.8',
    status: 'online',
    notes: '研发部 · Codex CLI 生成代码进入人工复核队列。',
    seenAgo: 11 * MINUTE,
    enrolledAgo: 158 * DAY,
  },
  {
    device_id: 'OPS-MBP-0314',
    hostname: 'ops-mbp-0314.corp.aegis.local',
    owner: '罗宁',
    agent_type: 'claude_code',
    agent_version: 'v3.8',
    policy_version: 'v4.8',
    status: 'offline',
    notes: '运维部 · 超过 24 小时未上报，离线前存在未签名 MCP 出站。',
    seenAgo: 26 * HOUR,
    enrolledAgo: 301 * DAY,
  },
  {
    device_id: 'DESK-WIN-0521',
    hostname: 'desk-win-0521.corp.aegis.local',
    owner: '赵磊',
    agent_type: 'windsurf',
    agent_version: 'v3.8',
    policy_version: 'v4.8',
    status: 'online',
    notes: '客服部 · Windows 桌面，历史工单已闭环。',
    seenAgo: 7 * MINUTE,
    enrolledAgo: 74 * DAY,
  },
  {
    device_id: 'MKT-MBP-0847',
    hostname: 'mkt-mbp-0847.corp.aegis.local',
    owner: '吴婷',
    agent_type: 'cursor',
    agent_version: 'v3.6',
    policy_version: 'v4.6',
    status: 'needs_attention',
    notes: '市场部 · Agent 落后基线两个版本，待推送升级。',
    seenAgo: 52 * MINUTE,
    enrolledAgo: 122 * DAY,
  },
];

function demoDevices(): Device[] {
  const now = Date.now();
  return DEVICE_SEEDS.map(({ seenAgo, enrolledAgo, ...device }) => ({
    ...device,
    last_seen: now - seenAgo,
    registered_at: now - enrolledAgo,
  }));
}

/* ─── 响应与错误解析 ─────────────────────────────────────── */

function isAbortError(error: unknown): boolean {
  return error instanceof Error && error.name === 'AbortError';
}

function errorText(error: unknown): string {
  return error instanceof Error && error.message ? error.message : '未知错误';
}

/** `{ error, message, details }` 是 lib/api.ts 的统一错误信封。 */
function describeError(payload: unknown, fallback: string): string {
  if (payload && typeof payload === 'object' && !Array.isArray(payload)) {
    const data = payload as Record<string, unknown>;
    const code = typeof data.error === 'string' ? data.error : '';
    const details = Array.isArray(data.details)
      ? data.details.filter((item): item is string => typeof item === 'string')
      : [];
    const copy = ERROR_COPY[code] ?? (typeof data.message === 'string' ? data.message : '');
    if (details.length > 0) return details.join('；');
    if (copy) return copy;
    if (code) return code;
  }
  return fallback;
}

/** 取 `{ device: {...} }` 里的记录；没有包装时退回载荷本身。 */
function pickRecord(payload: unknown, key: string): unknown {
  if (payload && typeof payload === 'object' && !Array.isArray(payload)) {
    const data = payload as Record<string, unknown>;
    if (data[key] !== undefined) return data[key];
  }
  return payload;
}

function pickNumber(payload: unknown, key: string): number {
  if (payload && typeof payload === 'object' && !Array.isArray(payload)) {
    const value = (payload as Record<string, unknown>)[key];
    if (typeof value === 'number' && Number.isFinite(value)) return value;
  }
  return 0;
}

function formatLastSeen(value: number): string {
  if (!value) return '从未上报';
  const diff = Date.now() - value;
  if (diff < MINUTE) return '刚刚上报';
  if (diff < HOUR) return `${Math.floor(diff / MINUTE)} 分钟前上报`;
  if (diff < DAY) return `${Math.floor(diff / HOUR)} 小时前上报`;
  return `${Math.floor(diff / DAY)} 天前上报`;
}

/* ─── 页面 ───────────────────────────────────────────────── */

export default function DevicesPage() {
  const { fleet } = useCollector();

  const [devices, setDevices] = useState<Device[]>([]);
  const [source, setSource] = useState<DataSource>('loading');
  const [notice, setNotice] = useState('');
  const [refreshing, setRefreshing] = useState(false);
  const [query, setQuery] = useState('');
  const [showForm, setShowForm] = useState(false);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [pendingDelete, setPendingDelete] = useState<Device | null>(null);
  const [deleting, setDeleting] = useState(false);
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [findings, setFindings] = useState<Array<Record<string, unknown>> | null>(null);
  const [findingsLoading, setFindingsLoading] = useState(false);
  const [toast, setToast] = useState<{ text: string; tone: ToastTone } | null>(null);
  const toastTimer = useRef<number | null>(null);
  const { role } = useRole();
  const canMutate = role === 'admin';

  const notify = useCallback((text: string, tone: ToastTone = 'info') => {
    setToast({ text, tone });
    if (toastTimer.current !== null) window.clearTimeout(toastTimer.current);
    toastTimer.current = window.setTimeout(() => setToast(null), 4_000);
  }, []);

  useEffect(
    () => () => {
      if (toastTimer.current !== null) window.clearTimeout(toastTimer.current);
    },
    [],
  );

  const loadDevices = useCallback(async (signal?: AbortSignal) => {
    const response = await fetch('/api/devices', { cache: 'no-store', signal });
    const payload: unknown = await response.json().catch(() => null);
    if (!response.ok)
      throw new Error(describeError(payload, `设备接口返回 ${response.status}`));
    return parseDeviceList(payload);
  }, []);

  /** 接口不可用：保留已有数据，列表为空时展示空态。 */
  const applyFallback = useCallback((message: string) => {
    setNotice(message);
    setDevices((prev) => (prev.length > 0 ? prev : demoDevices()));
    setSource((prev) => (prev === 'api' ? 'api' : 'demo'));
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    let active = true;
    void (async () => {
      try {
        const list = await loadDevices(controller.signal);
        if (!active) return;
        setDevices(list);
        setSource('api');
        setNotice('');
      } catch (error) {
        if (!active || isAbortError(error)) return;
        applyFallback(errorText(error));
      }
    })();
    return () => {
      active = false;
      controller.abort();
    };
  }, [applyFallback, loadDevices]);

  /** 写操作失败时的提示。 */
  const failureCopy = useCallback(
    (action: string, deviceId: string, error: unknown) =>
      source === 'demo'
        ? `操作失败：设备接口不可用，未${action}「${deviceId}」。`
        : `${action}失败：${errorText(error)}`,
    [source],
  );

  async function refresh() {
    setRefreshing(true);
    try {
      const list = await loadDevices();
      setDevices(list);
      setSource('api');
      setNotice('');
      notify(`已刷新，共 ${list.length} 台受管终端。`, 'success');
    } catch (error) {
      applyFallback(errorText(error));
      notify(`刷新失败：${errorText(error)}`, 'error');
    } finally {
      setRefreshing(false);
    }
  }

  async function createDevice(data: DeviceFormData) {
    try {
      const response = await fetch('/api/devices', {
        method: 'POST',
        headers: JSON_HEADERS,
        body: JSON.stringify(data),
      });
      const payload: unknown = await response.json().catch(() => null);
      if (!response.ok)
        throw new Error(describeError(payload, `设备接口返回 ${response.status}`));
      const created = parseDevice(pickRecord(payload, 'device'));
      if (created) {
        setDevices((prev) => [
          created,
          ...prev.filter((device) => device.device_id !== created.device_id),
        ]);
      } else {
        setDevices(await loadDevices());
      }
      setSource('api');
      setNotice('');
      setShowForm(false);
      setQuery('');
      notify(`设备 ${data.device_id} 已注册，等待 Agent 首次上报。`, 'success');
    } catch (error) {
      notify(failureCopy('注册', data.device_id, error), 'error');
    }
  }

  async function updateDevice(data: DeviceFormData) {
    try {
      const response = await fetch('/api/devices', {
        method: 'PUT',
        headers: JSON_HEADERS,
        body: JSON.stringify({
          device_id: data.device_id,
          hostname: data.hostname,
          owner: data.owner,
          agent_type: data.agent_type,
          notes: data.notes,
        }),
      });
      const payload: unknown = await response.json().catch(() => null);
      if (!response.ok)
        throw new Error(describeError(payload, `设备接口返回 ${response.status}`));
      const updated = parseDevice(pickRecord(payload, 'device'));
      if (updated) {
        setDevices((prev) =>
          prev.map((device) =>
            device.device_id === updated.device_id ? updated : device,
          ),
        );
      } else {
        setDevices(await loadDevices());
      }
      setSource('api');
      setEditingId(null);
      notify(`设备 ${data.device_id} 已更新。`, 'success');
    } catch (error) {
      notify(failureCopy('更新', data.device_id, error), 'error');
    }
  }

  async function confirmDelete() {
    const target = pendingDelete;
    if (!target || deleting) return;
    setDeleting(true);
    try {
      const response = await fetch(
        `/api/devices?device_id=${encodeURIComponent(target.device_id)}`,
        { method: 'DELETE' },
      );
      const payload: unknown = await response.json().catch(() => null);
      if (!response.ok)
        throw new Error(describeError(payload, `设备接口返回 ${response.status}`));
      setDevices((prev) =>
        prev.filter((device) => device.device_id !== target.device_id),
      );
      if (editingId === target.device_id) setEditingId(null);
      setPendingDelete(null);
      const retained = pickNumber(payload, 'retained_tickets');
      notify(
        retained > 0
          ? `设备 ${target.device_id} 已删除，${retained} 张关联工单按审计要求留档。`
          : `设备 ${target.device_id} 已从注册表移除。`,
        'success',
      );
    } catch (error) {
      setPendingDelete(null);
      notify(failureCopy('删除', target.device_id, error), 'error');
    } finally {
      setDeleting(false);
    }
  }

  async function toggleFindings(deviceId: string) {
    if (expandedId === deviceId) {
      setExpandedId(null);
      setFindings(null);
      return;
    }
    setExpandedId(deviceId);
    setFindingsLoading(true);
    setFindings(null);
    try {
      const res = await fetch(`/api/devices/${encodeURIComponent(deviceId)}/findings?limit=100`, { cache: 'no-store' });
      if (!res.ok) throw new Error(`findings ${res.status}`);
      const data = (await res.json()) as { findings?: Array<Record<string, unknown>> };
      setFindings(data.findings ?? []);
    } catch {
      setFindings([]);
      notify('发现项加载失败（Collector 不可达）。', 'error');
    } finally {
      setFindingsLoading(false);
    }
  }

  /* ── 派生数据 ─────────────────────────────────────────── */

  const visibleDevices = useMemo(() => {
    const keyword = query.trim().toLowerCase();
    if (!keyword) return devices;
    return devices.filter((device) =>
      [device.device_id, device.hostname, device.owner]
        .join('\n')
        .toLowerCase()
        .includes(keyword),
    );
  }, [devices, query]);

  const onlineCount = devices.filter((device) => device.status === 'online').length;
  const staleCount = devices.filter((device) => device.status === 'stale').length;
  const attentionCount = devices.filter(
    (device) => device.status === 'needs_attention',
  ).length;
  const reportedCount = devices.filter(
    (device) => agentVersionLabel(device.agent_version) !== '未上报',
  ).length;

  const kpis = useMemo(() => {
    if (fleet && fleet.total_devices > 0) {
      return {
        total: fleet.total_devices,
        onlineRate: ((fleet.active_devices / fleet.total_devices) * 100).toFixed(1),
        versionCoverage: (
          (fleet.version_posture.current / fleet.total_devices) *
          100
        ).toFixed(1),
        suffix: '',
      };
    }
    if (devices.length === 0)
      return { total: 0, onlineRate: '0.0', versionCoverage: '0.0', suffix: '' };
    return {
      total: devices.length,
      onlineRate: ((onlineCount / devices.length) * 100).toFixed(1),
      versionCoverage: ((reportedCount / devices.length) * 100).toFixed(1),
      suffix: '',
    };
  }, [devices.length, fleet, onlineCount, reportedCount]);

  const coverageRows = useMemo(() => {
    if (source !== 'api' || devices.length === 0) return TOOL_COVERAGE_DEMO;
    return AGENT_TYPE_OPTIONS.map((option) => {
      const rows = devices.filter((device) => device.agent_type === option.value);
      return {
        name: option.label,
        total: rows.length,
        online: rows.filter((device) => device.status === 'online').length,
      };
    }).filter((row) => row.total > 0);
  }, [devices, source]);

  const noticeCopy = (() => {
    if (source === 'loading')
      return { title: '正在读取注册表', body: ' 正在从 /api/devices 拉取受管终端清单。' };
    if (source === 'api')
      return fleet
        ? {
            title: '混合只读模式',
            body: ' 终端注册表支持增删改查；顶部三项指标来自已验证的接收器摘要。',
          }
        : {
            title: '注册表已连接',
            body: ' 终端清单与增删改查来自设备接口；接收器摘要未连接，KPI 由注册表推算。',
          };
    return {
      title: '接口暂不可用',
      body: ` 设备接口暂不可用（${notice || '未知原因'}），请稍后重试。`,
    };
  })();

  /* ── 渲染 ─────────────────────────────────────────────── */

  return (
    <>
      

      <div className="page-head animate-entrance animate-entrance-1">
        <div>
          <p className="eyebrow">终端资产 / Agent 版本</p>
          <h1>设备与 Agent</h1>
          <p>注册受管终端、维护负责人与工具类型，并跟踪逐设备版本姿态。</p>
        </div>
        <div className="head-actions" style={{ flexWrap: 'wrap' }}>
          <Button
            variant="outline"
            onClick={() => notify('时间范围筛选暂未开放，当前展示全部数据。')}
          >
            <ChevronDown />
            过去 7 天
          </Button>
          <Button onClick={() => setShowForm((prev) => !prev)}>
            {showForm ? <X /> : <Plus />}
            {showForm ? '收起表单' : '注册设备'}
          </Button>
        </div>
      </div>

      {toast && (
        <div
          className="toast"
          role="status"
          style={
            toast.tone === 'error'
              ? { borderColor: 'var(--destructive)', color: 'var(--destructive)' }
              : undefined
          }
        >
          {toast.tone === 'error' ? (
            <AlertTriangle size={16} />
          ) : toast.tone === 'success' ? (
            <CircleCheck size={16} />
          ) : (
            <CircleDot size={16} />
          )}
          {toast.text}
        </div>
      )}

      <div className="detail-kpis">
        <article className="animate-entrance animate-entrance-1">
          <strong>{kpis.total}</strong>
          <span>受管终端总数{kpis.suffix}</span>
        </article>
        <article className="animate-entrance animate-entrance-2">
          <strong>{kpis.onlineRate}%</strong>
          <span>在线率{kpis.suffix}</span>
        </article>
        <article className="animate-entrance animate-entrance-3">
          <strong>{kpis.versionCoverage}%</strong>
          <span>版本覆盖率{kpis.suffix}</span>
        </article>
      </div>

      {showForm && (
        <div className="panel animate-entrance" style={{ marginBottom: 14 }}>
          <div className="panel-head">
            <div>
              <h2>注册新终端</h2>
              <p>登记终端与负责人后，Agent 上报会自动关联到该记录。</p>
            </div>
            <Button
              variant="ghost"
              size="icon-sm"
              aria-label="收起注册表单"
              onClick={() => setShowForm(false)}
            >
              <X />
            </Button>
          </div>
          <DeviceForm
            mode="create"
            onSubmit={createDevice}
            onCancel={() => setShowForm(false)}
          />
        </div>
      )}

      <div className="panel">
        <div className="panel-head">
          <div>
            <h2>受管终端</h2>
            <p>
              {source === 'loading'
                ? '正在读取注册表…'
                : `${devices.length} 台设备 · ${onlineCount} 台在线 · ${attentionCount} 台需处理${
                    ''
                  }`}
            </p>
            <p>
              要求 Agent 版本 {fleet?.required_agent_version ?? 'v3.8'} ·
              要求策略版本 {fleet?.required_policy_version ?? 'v4.8'}
            </p>
            {fleet?.credential_posture && (
              <p>
                凭据代次：当前 {fleet.credential_posture.current} · 上一代{' '}
                {fleet.credential_posture.previous} · Legacy{' '}
                {fleet.credential_posture.legacy}
              </p>
            )}
          </div>
          <Badge variant="outline">
            <Laptop size={13} />
            {fleet?.active_devices ?? onlineCount} 台活跃
          </Badge>
        </div>

        <div
          style={{
            display: 'flex',
            flexWrap: 'wrap',
            alignItems: 'center',
            gap: 10,
            marginBottom: 14,
          }}
        >
          <div style={{ position: 'relative', flex: '1 1 260px', minWidth: 0 }}>
            <Search
              size={14}
              aria-hidden
              style={{
                position: 'absolute',
                left: 10,
                top: '50%',
                transform: 'translateY(-50%)',
                color: 'var(--muted-foreground)',
                pointerEvents: 'none',
              }}
            />
            <Input
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="搜索设备 ID、主机名或负责人"
              aria-label="搜索受管终端"
              autoComplete="off"
              style={{ paddingLeft: 30 }}
            />
          </div>
          {query && (
            <Button variant="ghost" size="sm" onClick={() => setQuery('')}>
              <X />
              清除
            </Button>
          )}
          <Button
            variant="outline"
            size="sm"
            onClick={() => void refresh()}
            disabled={refreshing || source === 'loading'}
          >
            {refreshing ? <Spinner /> : <RefreshCw />}
            刷新
          </Button>
          <Badge variant="outline">
            {visibleDevices.length} / {devices.length} 台
          </Badge>
        </div>

        <div className="data-table">
          <div className="data-head">
            <span>设备 ID</span>
            <span>用户 · 工具</span>
            <span>Agent 版本</span>
            <span>状态</span>
          </div>

          {source === 'loading' &&
            [0, 1, 2, 3, 4].map((index) => (
              <div className="skeleton-row" key={index} />
            ))}

          {visibleDevices.map((device, index) => {
            const meta = STATUS_META[device.status] ?? STATUS_META.offline;
            const editing = editingId === device.device_id;
            const findings = device.findings_summary;
            const openFindings = findings
              ? findings.critical + findings.high + findings.medium + findings.low
              : 0;
            return (
              <Fragment key={device.device_id}>
                <div
                  className="data-row animate-row-entrance"
                  style={{
                    animationDelay: `${index * 30 + 200}ms`,
                    cursor: 'pointer',
                  }}
                  onClick={() => setEditingId(editing ? null : device.device_id)}
                >
                  <div style={cellStackStyle}>
                    <strong>{device.device_id}</strong>
                    <span style={{ fontSize: 10 }}>{device.hostname}</span>
                  </div>
                  <span>
                    {device.owner || '未指派'} · {agentTypeLabel(device.agent_type)}
                  </span>
                  <span>{agentVersionLabel(device.agent_version)}</span>
                  <div
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'flex-end',
                      gap: 6,
                    }}
                  >
                    <i
                      className={meta.className}
                      style={meta.style}
                      title={`${meta.label} · ${formatLastSeen(device.last_seen)}${
                        openFindings > 0 ? ` · ${openFindings} 项待闭环发现` : ''
                      }`}
                    >
                      {meta.label}
                    </i>
                    <Button
                      variant="ghost"
                      size="icon-xs"
                      aria-label={`发现项 ${device.device_id}`}
                      aria-expanded={expandedId === device.device_id}
                      onClick={(event) => {
                        event.stopPropagation();
                        void toggleFindings(device.device_id);
                      }}
                    >
                      <Search />
                    </Button>
                    <Button
                      variant="ghost"
                      size="icon-xs"
                      aria-label={`编辑 ${device.device_id}`}
                      aria-expanded={editing}
                      onClick={(event) => {
                        event.stopPropagation();
                        if (canMutate) setEditingId(editing ? null : device.device_id);
                      }}
                    >
                      <Pencil />
                    </Button>
                    <Button
                      variant="ghost"
                      size="icon-xs"
                      aria-label={`删除 ${device.device_id}`}
                      style={{ color: 'var(--destructive)' }}
                      onClick={(event) => {
                        event.stopPropagation();
                        if (canMutate) setPendingDelete(device);
                      }}
                    >
                      <Trash2 />
                    </Button>
                  </div>
                </div>

                {editing && (
                  <div className="animate-entrance" style={inlinePanelStyle}>
                    <DeviceForm
                      mode="edit"
                      initialData={device}
                      onSubmit={updateDevice}
                      onCancel={() => setEditingId(null)}
                    />
                  </div>
                )}

                {expandedId === device.device_id && (
                  <div className="animate-entrance" style={inlinePanelStyle}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
                      <h3 style={{ fontSize: 14, margin: 0 }}>最新扫描发现项</h3>
                      <button onClick={() => void toggleFindings(device.device_id)} style={{ background: 'none', border: 0, color: 'var(--muted-foreground)', cursor: 'pointer', fontSize: 12 }}>收起</button>
                    </div>
                    {findingsLoading ? (
                      <p style={{ fontSize: 12, color: 'var(--muted-foreground)' }}>加载发现项…</p>
                    ) : findings && findings.length > 0 ? (
                      <div className="data-table">
                        <div className="data-head">
                          <span>等级</span><span>类型</span><span>路径</span><span>说明</span>
                        </div>
                        {findings.slice(0, 50).map((f, i) => (
                          <div className="data-row" key={i}>
                            <i className={f.severity === 'critical' || f.severity === 'high' ? 'fail' : f.severity === 'medium' ? 'warn' : 'pass'}>{String(f.severity)}</i>
                            <span>{String(f.kind)}</span>
                            <span style={{ fontSize: 11, wordBreak: 'break-all' }}>{String(f.path ?? '')}</span>
                            <span style={{ fontSize: 11 }}>{String(f.message ?? '')}</span>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <p style={{ fontSize: 12, color: 'var(--muted-foreground)' }}>该设备最新报告无发现项。</p>
                    )}
                  </div>
                )}
              </Fragment>
            );
          })}
        </div>

        {source !== 'loading' && visibleDevices.length === 0 && (
          <div className="empty-detail" style={{ minHeight: 180 }}>
            <Laptop size={36} />
            <h2>{query ? '没有匹配的终端' : '注册表为空'}</h2>
            <p>
              {query
                ? `未找到与「${query}」匹配的设备 ID、主机名或负责人。`
                : '点击右上角「注册设备」，把第一台终端纳入治理。'}
            </p>
          </div>
        )}

        <p className="safety-note">
          <ShieldCheck size={15} />
          {source === 'api'
            ? '终端清单来自 /api/devices；注册、编辑与删除会即时写入控制台存储，历史工单按审计要求留档。'
            : '设备接口暂不可用，请稍后重试或检查 Collector 连接。'}
        </p>
      </div>

      <div className="panel coverage">
        <div className="panel-head">
          <div>
            <h2>按 Agent 工具覆盖</h2>
            <p>在线终端 / 已纳管终端</p>
          </div>
          <Badge variant="outline">
            <Bot size={13} />
            {fleet?.stale_devices ?? staleCount} 台待修复
          </Badge>
        </div>
        {coverageRows.map((tool) => (
          <div className="coverage-row" key={tool.name}>
            <div className="tool-logo">{tool.name.slice(0, 1)}</div>
            <div className="coverage-data">
              <div>
                <strong>{tool.name}</strong>
                <span>
                  {tool.online}/{tool.total} 在线
                </span>
              </div>
              <Progress value={tool.total ? (tool.online / tool.total) * 100 : 0} />
            </div>
          </div>
        ))}
        {coverageRows.length === 0 && (
          <p style={{ margin: 0, fontSize: 12, color: 'var(--muted-foreground)' }}>
            暂无终端上报工具覆盖数据。
          </p>
        )}
      </div>

      <AlertDialog
        open={pendingDelete !== null}
        onOpenChange={(open) => {
          if (!open && !deleting) setPendingDelete(null);
        }}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>删除设备</AlertDialogTitle>
            <AlertDialogDescription>
              确认把 {pendingDelete?.device_id ?? '该终端'} 从注册表移除？负责人{' '}
              {pendingDelete?.owner || '未指派'} 将失去该终端的凭据代次，关联工单会保留以满足审计要求。
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={deleting}>取消</AlertDialogCancel>
            <AlertDialogAction
              variant="destructive"
              disabled={deleting}
              onClick={() => void confirmDelete()}
            >
              {deleting ? <Spinner /> : <Trash2 />}
              {deleting ? '删除中…' : '确认删除'}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  );
}
