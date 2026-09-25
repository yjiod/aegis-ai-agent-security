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
import { useSearchParams } from 'next/navigation';
import { useRole } from '@/components/role-context';
import { Pagination, paginate } from '@/components/pagination';
import type { CSSProperties } from 'react';
import {
  AlertTriangle,
  Bot,
  ChevronDown,
  CircleCheck,
  CircleDot,
  Eye,
  Laptop,
  Pencil,
  Plus,
  RefreshCw,
  Search,
  ShieldCheck,
  Trash2,
  X,
} from 'lucide-react';
import { DetailDrawer, type DrawerSection } from '@/components/detail-drawer';
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
import DeviceForm, {
  agentTypeLabel,
  agentVersionLabel,
  parseDevice,
  parseDeviceList,
  type Device,
  type DeviceFormData,
  type DeviceStatus,
} from '@/components/device-form';
import { semverGte } from '@/lib/collector-devices';
const MINUTE = 60_000;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;

/* ─── 展示层常量 ─────────────────────────────────────────── */

type DataSource = 'loading' | 'api' | 'error';
type ToastTone = 'info' | 'success' | 'error';

const JSON_HEADERS = { 'Content-Type': 'application/json' } as const;


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

/** 主表 5 列网格：序列号/ID · 用户·工具 · Agent 版本 · 网络(MAC/IP) · 状态。 */
const deviceGridStyle: CSSProperties = {
  gridTemplateColumns: '1.5fr 0.9fr 0.7fr 1.4fr 0.5fr',
};

const inlinePanelStyle: CSSProperties = {
  border: '1px solid var(--line-base)',
  borderRadius: 10,
  background: 'var(--surface-1)',
  padding: '4px 14px 14px',
  margin: '2px 0 12px',
};

/* ─── 无演示数据 ───────────────────────────────────────────
 * 接口失败或为空时，一律展示真实的错误态/空态，绝不注入虚构设备或
 * 虚构覆盖率数字（曾经的 DEVICE_SEEDS / demoDevices / TOOL_COVERAGE_DEMO
 * 已移除）。对一个安全治理产品，把"没有数据"伪装成"有数据"是信任问题。
 * 覆盖率(coverageRows)一律由真实 devices 聚合得出。
 */

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

function osLabel(os?: string): string {
  const o = (os ?? '').toLowerCase();
  if (o.includes('darwin') || o.includes('mac')) return 'Mac';
  if (o.includes('win')) return 'Windows';
  if (o.includes('linux')) return 'Linux';
  return o || '未知';
}

export default function DevicesPage() {
  const { fleet } = useCollector();

  const [devices, setDevices] = useState<Device[]>([]);
  const [source, setSource] = useState<DataSource>('loading');
  const [notice, setNotice] = useState('');
  const { role } = useRole();
  const searchParams = useSearchParams();
  const canMutate = role === 'admin';
  const [refreshing, setRefreshing] = useState(false);
  const [query, setQuery] = useState('');
  const [showForm, setShowForm] = useState(false);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [pendingDelete, setPendingDelete] = useState<Device | null>(null);
  // 视觉迭代：设备详情抽屉（与风险/扫描页一致），数据来自行内 Device 对象，无额外请求。
  const [selectedDevice, setSelectedDevice] = useState<Device | null>(null);
  const [deleting, setDeleting] = useState(false);
  const [expandedId, setExpandedId] = useState<string | null>(null);
  // 规模化分页（几千台设备）：列表与覆盖矩阵各自分页，避免一次性渲染全部行。
  const [page, setPage] = useState(1);
  const [matrixPage, setMatrixPage] = useState(1);
  const PAGE_SIZE = 50;
  const [findings, setFindings] = useState<Array<Record<string, unknown>> | null>(null);
  const [findingsLoading, setFindingsLoading] = useState(false);
  const [toast, setToast] = useState<{ text: string; tone: ToastTone } | null>(null);
  const toastTimer = useRef<number | null>(null);

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

  /** 接口不可用：诚实进入 error 态，保留上一次成功加载的数据，绝不注入假设备。 */
  const applyFallback = useCallback((message: string) => {
    setNotice(message);
    setSource((prev) => (prev === 'api' ? 'api' : 'error'));
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

  // 深链接：/devices?focus=<device_id> 自动展开该设备并加载其发现/回执（风险中心工单跳转用），
  // 让"从工单跳到具体设备看发现与封禁回执"一步到位，不必手动找设备再展开。
  useEffect(() => {
    const focus = searchParams.get('focus');
    if (focus) {
      setExpandedId(focus);
      void toggleFindings(focus);
    }
    // toggleFindings 为组件内函数声明（hoisted），此处仅依赖 searchParams。
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [searchParams]);

  /** 写操作失败时的提示。 */
  const failureCopy = useCallback(
    (action: string, deviceId: string, error: unknown) =>
      source === 'error'
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

  // 封禁豁免切换(开发主机等): 豁免设备只报不封、不自更; 清单存服务端 settings。
  async function toggleExempt(dev: Device) {
    try {
      const r = await fetch('/api/settings/exempt', { cache: 'no-store' });
      const cur = r.ok ? (((await r.json()) as { exempt?: string[] }).exempt ?? []) : [];
      const id = dev.device_id.toLowerCase();
      const next = cur.includes(id) ? cur.filter((x) => x !== id) : [...cur, id];
      const p = await fetch('/api/settings/exempt', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ devices: next }) });
      if (p.ok) notify(next.includes(id) ? '已加入封禁豁免：该设备只报不封、不自更' : '已移出封禁豁免', 'info');
      else notify(`豁免设置失败 HTTP ${p.status}`, 'error');
      await refresh();
    } catch (e) {
      notify(e instanceof Error ? e.message : String(e), 'error');
    }
  }

  // 自更保护切换(pinned, 与豁免分离): pinned 设备不自动更新, 只接受人工/桌管更新。
  async function togglePinned(dev: Device) {
    try {
      const r = await fetch('/api/settings/pinned', { cache: 'no-store' });
      const cur = r.ok ? (((await r.json()) as { pinned?: string[] }).pinned ?? []) : [];
      const id = dev.device_id.toLowerCase();
      const next = cur.includes(id) ? cur.filter((x) => x !== id) : [...cur, id];
      const p = await fetch('/api/settings/pinned', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ devices: next }) });
      if (p.ok) notify(next.includes(id) ? '已加入自更保护：该设备不自动更新' : '已移出自更保护：恢复自动更新', 'info');
      else notify(`自更保护设置失败 HTTP ${p.status}`, 'error');
      await refresh();
    } catch (e) {
      notify(e instanceof Error ? e.message : String(e), 'error');
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

  // 列表分页（规模化）；筛选/搜索变化时页码由 paginate 内部收敛。
  const paged = useMemo(() => paginate(visibleDevices, page, PAGE_SIZE), [visibleDevices, page]);
  const matrixPaged = useMemo(() => paginate(devices, matrixPage, PAGE_SIZE), [devices, matrixPage]);

  const onlineCount = devices.filter((device) => device.status === 'online').length;
  const staleCount = devices.filter((device) => device.status === 'stale').length;
  // 关注态：collector 源用独立 attention 布尔（连接态与关注态分离）；注册表源沿用 needs_attention。
  const attentionCount = devices.filter(
    (device) => (device as { attention?: boolean }).attention === true || device.status === 'needs_attention',
  ).length;
  const reportedCount = devices.filter(
    (device) => agentVersionLabel(device.agent_version) !== '未上报',
  ).length;
  const offlineCount = devices.filter((device) => device.status === 'offline').length;
  const exemptCount = devices.filter((device) => device.exempt === true).length;
  const pinnedCount = devices.filter((device) => device.pinned === true).length;
  /** 自更异常（preflight 拒绝 / 自动回滚 / 应用失败）台数——canary 监控闭环的舰队级信号。 */
  const badSelfUpdateCount = devices.filter((device) => {
    const r = device.self_update?.reason;
    return !!r && r !== 'ok' && (r.startsWith('preflight_failed') || r.startsWith('rolled_back') || r.startsWith('apply_failed'));
  }).length;

  /**
   * 版本漂移：已上报且 agent_version **低于**要求版本的设备数（semver 比较，与仪表盘
   * computeVersionPosture 同源）。这是"某台机器悄悄掉队/自更失败"的核心信号——之前离线
   * 13h 无人察觉即因缺少此类聚合告警。
   * 注意：高于 required 属正常升级（不应计漂移）。旧实现用 `!==` 精确不等，把"领先于
   * required"的终端也标成漂移（required 为陈旧下限 0.33.0 时全员误报），已修正为 semver 低于。
   */
  const driftDevices = useMemo(() => {
    const required = fleet?.required_agent_version;
    if (!required) return [] as Device[];
    return devices.filter((device) => {
      const v = agentVersionLabel(device.agent_version);
      return v !== '未上报' && !semverGte(v, required);
    });
  }, [devices, fleet?.required_agent_version]);

  /** 策略版本与要求不一致的终端（与 Agent 漂移并列的第二维漂移）。 */
  const policyDriftDevices = useMemo(() => {
    const required = fleet?.required_policy_version;
    if (!required) return [] as Device[];
    return devices.filter((device) => {
      const p = (device.policy_version ?? '').trim();
      return p !== '' && p !== required;
    });
  }, [devices, fleet?.required_policy_version]);

  /** 漂移影响面 = Agent 漂移 ∪ 策略漂移（去重），handoff P1 的"影响面"视图数据源。 */
  const impactDevices = useMemo(() => {
    const seen = new Set<string>();
    const out: Device[] = [];
    for (const d of [...driftDevices, ...policyDriftDevices]) {
      if (seen.has(d.device_id)) continue;
      seen.add(d.device_id);
      out.push(d);
    }
    return out;
  }, [driftDevices, policyDriftDevices]);

  /** 预计修复动作：区分 Agent 漂移 / 策略漂移 / 两者，并考虑 pinned 与在线状态。 */
  function repairAction(d: Device): string {
    const requiredAgent = fleet?.required_agent_version;
    const requiredPolicy = fleet?.required_policy_version;
    const v = agentVersionLabel(d.agent_version);
    const agentDrift = Boolean(requiredAgent) && v !== '未上报' && !semverGte(v, requiredAgent ?? '');
    const policyDrift = Boolean(requiredPolicy) && (d.policy_version ?? '').trim() !== '' && (d.policy_version ?? '').trim() !== requiredPolicy;
    const parts: string[] = [];
    if (agentDrift) {
      if (d.pinned) parts.push('Agent 已 pin：人工 / 桌管更新（不自更）');
      else if (d.status === 'online') parts.push(`Agent 在线：自更新至 ${requiredAgent}（未收敛请查 rollout / 自更保护）`);
      else parts.push('Agent 离线 / 陈旧：上线后自更收敛；若旧二进制启动即崩溃需一次性安装器解锁');
    }
    if (policyDrift) parts.push(`策略不一致：重新下发签名策略 v${requiredPolicy}，终端下次拉取生效`);
    return parts.join('；') || '—';
  }

  /** 离线/过期设备里最久未上报的一台，用于告警横幅点名（"XX 已 N 小时未上报"）。 */
  const longestUnseen = useMemo(() => {
    const candidates = devices.filter(
      (device) => device.status === 'offline' || device.status === 'stale',
    );
    if (candidates.length === 0) return null;
    return candidates.reduce((oldest, device) =>
      device.last_seen < oldest.last_seen ? device : oldest,
    );
  }, [devices]);

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

  // 按 AI 工具覆盖：聚合每台设备上报的**全部** ai_agent 工具（device.tools），
  // 而非单一 agent_type（此前只取 tools[0]，导致多工具终端只显示一个工具——用户反馈 bug）。
  const coverageRows = useMemo(() => {
    if (source !== 'api' || devices.length === 0) return [];
    const map = new Map<string, { total: number; online: number }>();
    for (const device of devices) {
      const tools = ((device as { tools?: string[] }).tools ?? []) as string[];
      // 无检测到的 AI 工具时归入本地化占位桶（此前是英文 'unknown'，与全站中文 UI 不一致，
      // 用户反馈"上报者是 unknown"）。老扫描器（如 Windows 0.34.4）inventory 为空会落这里；
      // Agent 更新到当前版本、上报完整 inventory 后即归位到真实工具名。
      const list = tools.length > 0 ? tools : [device.agent_type ?? '未识别工具'];
      for (const tool of list) {
        const cur = map.get(tool) ?? { total: 0, online: 0 };
        cur.total += 1;
        if (device.status === 'online') cur.online += 1;
        map.set(tool, cur);
      }
    }
    return [...map.entries()]
      .map(([name, v]) => ({ name, total: v.total, online: v.online }))
      .sort((a, b) => b.total - a.total || a.name.localeCompare(b.name));
  }, [devices, source]);


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

      {source === 'api' &&
        (offlineCount > 0 || staleCount > 0 || driftDevices.length > 0 || badSelfUpdateCount > 0) && (
          <div
            className="animate-entrance animate-entrance-1"
            role="status"
            style={{
              display: 'flex',
              alignItems: 'flex-start',
              gap: 12,
              margin: '0 0 14px',
              padding: '14px 16px',
              borderRadius: 11,
              background: 'var(--card)',
              border: '1px solid color-mix(in srgb, #e8b449 40%, var(--border))',
              borderLeft: '3px solid #e8b449',
            }}
          >
            <AlertTriangle size={18} style={{ color: '#e8b449', flexShrink: 0, marginTop: 1 }} />
            <div style={{ minWidth: 0 }}>
              <strong style={{ display: 'block', marginBottom: 4 }}>舰队健康告警</strong>
              <p style={{ margin: 0, color: 'var(--muted-foreground)', fontSize: 13, lineHeight: 1.6 }}>
                {[
                  offlineCount > 0 ? `${offlineCount} 台离线` : '',
                  staleCount > 0 ? `${staleCount} 台上报过期` : '',
                  driftDevices.length > 0
                    ? `${driftDevices.length} 台版本漂移（要求 ${fleet?.required_agent_version ?? '—'}）`
                    : '',
                  badSelfUpdateCount > 0 ? `${badSelfUpdateCount} 台自更异常（已被终端拦截/回滚）` : '',
                ]
                  .filter(Boolean)
                  .join(' · ')}
                {longestUnseen && (
                  <>
                    ；最久未上报：{longestUnseen.hostname || longestUnseen.device_id}{' '}
                    {formatLastSeen(longestUnseen.last_seen)}
                  </>
                )}
                。
              </p>
            </div>
          </div>
        )}

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
                    exemptCount > 0 ? ` · ${exemptCount} 台封禁豁免` : ''
                  }${pinnedCount > 0 ? ` · ${pinnedCount} 台自更保护` : ''}`}
            </p>
            <p>
              要求 Agent 版本 {fleet?.required_agent_version ?? '—'} ·
              要求策略版本 {fleet?.required_policy_version ?? '—'}
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
              placeholder="搜索序列号、设备 ID、主机名或负责人"
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
          <div className="data-head" style={deviceGridStyle}>
            <span>序列号 / 设备 ID</span>
            <span>用户 · 工具</span>
            <span>Agent 版本</span>
            <span>网络（MAC / IP）</span>
            <span>状态</span>
          </div>

          {source === 'loading' &&
            [0, 1, 2, 3, 4].map((index) => (
              <div className="skeleton-row" key={index} />
            ))}

          {paged.rows.map((device, index) => {
            const meta = STATUS_META[device.status] ?? STATUS_META.offline;
            const editing = editingId === device.device_id;
            const openFindings = findings
              ? (device.findings_summary?.critical ?? 0) + (device.findings_summary?.high ?? 0) + (device.findings_summary?.medium ?? 0) + (device.findings_summary?.low ?? 0)
              : 0;
            return (
              <Fragment key={device.device_id}>
                {/* 行点击是 admin 专属的「行内编辑开关」，不是打开详情——详情入口是行内的
                    Eye 按钮，编辑/删除是行内的 Pencil/Trash 按钮。因此键盘可达性按真实语义
                    提供（aria-expanded 表达展开态），且 role/tabIndex 仅在 canMutate 时挂载：
                    否则非 admin 会得到一个按了没反应的死 Tab 停靠点。 */}
                <div
                  className="data-row animate-row-entrance"
                  style={{
                    ...deviceGridStyle,
                    animationDelay: `${index * 30 + 200}ms`,
                    cursor: canMutate ? 'pointer' : 'default',
                  }}
                  role={canMutate ? 'button' : undefined}
                  tabIndex={canMutate ? 0 : undefined}
                  aria-label={canMutate ? `${editing ? '收起' : '展开'} ${device.hostname || device.device_id} 的行内编辑` : undefined}
                  aria-expanded={canMutate ? editing : undefined}
                  onKeyDown={canMutate ? (e) => {
                    // 行内嵌有 Eye/Pencil/Trash 等真实按钮：焦点落在控件上时不拦截按键，
                    // 否则 Space/Enter 会冒泡到行并 preventDefault 掉按钮自身行为。
                    if (e.target !== e.currentTarget) return;
                    if (e.key === 'Enter' || e.key === ' ') {
                      e.preventDefault();
                      setEditingId(editing ? null : device.device_id);
                    }
                  } : undefined}
                  onClick={() => {
                    if (canMutate) setEditingId(editing ? null : device.device_id);
                  }}
                >
                  <div style={cellStackStyle}>
                    {/* 主标识=真实硬件序列号（用户要求"把设备ID直接换成序列号"）；
                        无序列号（极老终端）时回落 device_id。device_id 降为次行小字。 */}
                    <strong>{(device as { serial?: string }).serial || device.device_id}</strong>
                    <span style={{ fontSize: 10 }}>
                      {(device as { serial?: string }).serial ? `${device.device_id} · ` : ''}
                      {device.hostname} · {osLabel(device.os)}
                    </span>
                    {/* 能力诚实化标注: 运行态 + 真实封禁能力 + 豁免, 全部来自终端自报, 不夸大 */}
                    <span style={{ fontSize: 10, color: 'var(--muted-foreground)' }}>
                      {device.run_mode === 'system' ? (device.run_mode_inferred ? '系统级(推断)' : '系统级') : device.run_mode === 'user' ? '用户级(已废止形态)' : '运行态未知'}
                      {device.capabilities ? ` · 连接封禁:${device.capabilities.pf ? '有' : '无'} · 执行预防:${device.capabilities.es ? '有' : '无'}` : ''}
                      {device.exempt ? ' · 封禁豁免(开发主机)' : ''}
                      {device.pinned ? ' · 自更保护' : ''}
                    </span>
                  </div>
                  <span>
                    {device.owner || '未指派'} · {(((device as { tools?: string[] }).tools ?? []).length > 0
                      ? ((device as { tools?: string[] }).tools as string[]).slice(0, 3).join(' / ') +
                        (((device as { tools?: string[] }).tools as string[]).length > 3 ? ' …' : '')
                      : agentTypeLabel(device.agent_type))}
                  </span>
                  <span>
                    {/* 版本前缀操作系统（用户要求：Agent 版本前标明是 mac 还是 windows） */}
                    {device.os ? (
                      <b style={{ marginRight: 4, color: 'var(--muted-foreground)', fontWeight: 600 }}>{osLabel(device.os)}</b>
                    ) : null}
                    {agentVersionLabel(device.agent_version)}
                    {(() => {
                      const v = agentVersionLabel(device.agent_version);
                      const required = fleet?.required_agent_version;
                      // 漂移 = 低于要求版本（semver，与仪表盘同源）；高于 required 属正常升级不标漂移。
                      const drift = !!required && v !== '未上报' && !semverGte(v, required);
                      if (!drift) return null;
                      return (
                        <span
                          title={`低于要求版本 ${required}，当前 ${v}（掉队/自更失败信号）`}
                          style={{
                            marginLeft: 6,
                            padding: '0 5px',
                            borderRadius: 5,
                            fontSize: 10,
                            color: '#e8b449',
                            background: 'color-mix(in srgb, #e8b449 14%, transparent)',
                            border: '1px solid color-mix(in srgb, #e8b449 40%, transparent)',
                          }}
                        >
                          漂移
                        </span>
                      );
                    })()}
                  </span>
                  {/* 网络列：物理网卡 MAC + 本机 IP + 互联网出口（终端上报/Collector 观测） */}
                  <span style={{ ...cellStackStyle, fontSize: 10, color: 'var(--muted-foreground)' }}>
                    {(() => {
                      const net = (device as { network?: { macs?: string[]; local_ips?: string[]; egress_ip?: string } }).network;
                      if (!net) return <span>—</span>;
                      const v4 = (net.local_ips ?? []).filter((i) => i.includes('.'));
                      return (
                        <>
                          <span style={{ fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace' }}>
                            MAC {net.macs?.[0] ?? '—'}
                            {(net.macs?.length ?? 0) > 1 ? ` +${(net.macs?.length ?? 0) - 1}` : ''}
                          </span>
                          <span>本机 {v4.slice(0, 2).join(' / ') || '—'}</span>
                          <span>出口 {net.egress_ip || '—'}</span>
                        </>
                      );
                    })()}
                  </span>
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
                    {(device as { attention?: boolean }).attention === true && (
                      <i className="fail" title="有 critical/high 发现待人工研判">需处理</i>
                    )}
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
                      <ChevronDown
                        style={{
                          transform:
                            expandedId === device.device_id
                              ? 'rotate(180deg)'
                              : 'none',
                          transition: 'transform 150ms ease',
                        }}
                      />
                    </Button>
                    <Button
                      variant="ghost"
                      size="icon-xs"
                      aria-label={`详情 ${device.device_id}`}
                      onClick={(event) => {
                        event.stopPropagation();
                        setSelectedDevice(device);
                      }}
                    >
                      <Eye />
                    </Button>
                    {canMutate && (
                      <>
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
                      </>
                    )}
                  </div>
                </div>

                {editing && (
                  <div className="animate-entrance" style={inlinePanelStyle}>
                    {/* 只读硬件/身份信息：序列号便于定位设备（用户要求可见）；不可编辑 */}
                    <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap', marginBottom: 12, fontSize: 12, color: 'var(--muted-foreground)' }}>
                      <span>
                        序列号：
                        <b style={{ color: 'var(--text)' }}>
                          {(device as { serial?: string }).serial || '（未读到有效序列号，以设备 ID 标识）'}
                        </b>
                      </span>
                      <span>
                        操作系统：<b style={{ color: 'var(--text)' }}>{osLabel(device.os)}</b>
                      </span>
                      <span>
                        上报用户：<b style={{ color: 'var(--text)' }}>{(device as { os_user?: string }).os_user || '—'}</b>
                      </span>
                    </div>
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
                    {/* 本机已安装 AI Agent 与受控设备绑定（用户反馈：要知道哪台机器装了什么 Agent） */}
                    <div style={{ marginBottom: 12 }}>
                      <h4 style={{ fontSize: 12, margin: '0 0 6px', color: 'var(--muted-foreground)' }}>
                        本机已安装 AI Agent（与该受控设备绑定）
                      </h4>
                      {(((device as { tools?: string[] }).tools ?? []) as string[]).length > 0 ? (
                        <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                          {(((device as { tools?: string[] }).tools ?? []) as string[]).map((t) => (
                            <span key={t} style={{ fontSize: 11, padding: '3px 8px', borderRadius: 6, background: 'var(--muted)', border: '1px solid var(--border)' }}>
                              {t}
                            </span>
                          ))}
                        </div>
                      ) : (
                        <p style={{ fontSize: 12, color: 'var(--muted-foreground)', margin: 0 }}>
                          该设备最新报告未包含 AI Agent 清单。
                        </p>
                      )}
                    </div>
                    {/* 物理网卡采集：MAC + 本机 IP（终端上报，仅物理网卡）+ 互联网出口（Collector 观测请求源 IP） */}
                    {(() => {
                      const net = (
                        device as {
                          network?: { physical_nics?: { name: string; mac: string; ips?: string[] }[]; macs?: string[]; local_ips?: string[]; egress_ip?: string };
                        }
                      ).network;
                      if (!net) {
                        return (
                          <div style={{ marginBottom: 12 }}>
                            <h4 style={{ fontSize: 12, margin: '0 0 6px', color: 'var(--muted-foreground)' }}>网络（仅物理网卡）</h4>
                            <p style={{ fontSize: 12, color: 'var(--muted-foreground)', margin: 0 }}>
                              该设备最近一次上报未包含网卡信息（客户端版本较旧，升级后显示）。
                            </p>
                          </div>
                        );
                      }
                      return (
                        <div style={{ marginBottom: 12 }}>
                          <h4 style={{ fontSize: 12, margin: '0 0 6px', color: 'var(--muted-foreground)' }}>网络（仅物理网卡）</h4>
                          <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap', fontSize: 12, color: 'var(--muted-foreground)', marginBottom: 6 }}>
                            <span>
                              互联网出口：<b style={{ color: 'var(--text)' }}>{net.egress_ip || '—'}</b>
                            </span>
                            <span>
                              本机地址：<b style={{ color: 'var(--text)' }}>{(net.local_ips ?? []).join('、') || '—'}</b>
                            </span>
                          </div>
                          {(net.physical_nics ?? []).length > 0 ? (
                            <div className="data-table">
                              <div className="data-head">
                                <span>网卡</span><span>MAC</span><span>本机 IP</span>
                              </div>
                              {(net.physical_nics ?? []).map((n) => (
                                <div className="data-row" key={n.name + n.mac}>
                                  <span style={{ fontSize: 12 }}>{n.name}</span>
                                  <span style={{ fontSize: 11, fontFamily: 'monospace' }}>{n.mac}</span>
                                  <span style={{ fontSize: 11 }}>{(n.ips ?? []).join('、') || '—'}</span>
                                </div>
                              ))}
                            </div>
                          ) : (
                            <p style={{ fontSize: 12, color: 'var(--muted-foreground)', margin: 0 }}>未检出物理网卡 MAC（客户端采集为空）。</p>
                          )}
                        </div>
                      );
                    })()}
                    {canMutate && (
                      <div style={{ marginBottom: 10, display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
                        <Button variant="outline" onClick={() => void toggleExempt(device)}>
                          {device.exempt ? '移出封禁豁免' : '加入封禁豁免（开发主机）'}
                        </Button>
                        <Button variant="outline" onClick={() => void togglePinned(device)}>
                          {device.pinned ? '移出自更保护' : '加入自更保护'}
                        </Button>
                        <span style={{ fontSize: 11, color: 'var(--muted-foreground)' }}>
                          豁免=只报不封；自更保护=不自动更新；两者独立配置，随签名策略下发。
                        </span>
                      </div>
                    )}
                    {/* 自更新结果：终端最近一次非例行自更（成功更新 / 被 preflight 拒绝 / 自动回滚 / 应用失败） */}
                    {device.self_update && (
                      <div style={{ marginBottom: 12 }}>
                        <h4 style={{ fontSize: 12, margin: '0 0 6px', color: 'var(--muted-foreground)' }}>自更新结果（最近一次非例行）</h4>
                        <div style={{ fontSize: 12, lineHeight: 1.6 }}>
                          <i
                            className={device.self_update.updated ? 'pass' : 'fail'}
                          >
                            {device.self_update.updated ? '已更新' : '未更新'}
                          </i>{' '}
                          <code style={{ fontSize: 11 }}>{device.self_update.reason}</code>
                          {device.self_update.from || device.self_update.to
                            ? ` · ${device.self_update.from ?? ''} → ${device.self_update.to ?? ''}`
                            : ''}
                          {device.self_update.latest ? ` · 目标 ${device.self_update.latest}` : ''}
                          {device.self_update.at ? ` · ${new Date(device.self_update.at * 1000).toLocaleString()}` : ''}
                        </div>
                      </div>
                    )}
                    {/* 执行器回执：封禁/隔离/恢复动作及备份位置（终端自报，最近若干条） */}
                    {(((device as { enforcement?: { asset_type: string; asset_key: string; action: string; target?: string; backup?: string; reason?: string; ok?: boolean; at?: number }[] }).enforcement ?? []).length > 0) && (
                      <div style={{ marginBottom: 12 }}>
                        <h4 style={{ fontSize: 12, margin: '0 0 6px', color: 'var(--muted-foreground)' }}>封禁 / 隔离执行回执</h4>
                        <div className="data-table">
                          <div className="data-head" style={{ gridTemplateColumns: '0.7fr 1.2fr 1fr 1.6fr' }}>
                            <span>类型</span><span>对象</span><span>动作</span><span>备份 / 原因</span>
                          </div>
                          {((device as { enforcement?: { asset_type: string; asset_key: string; action: string; target?: string; backup?: string; reason?: string; ok?: boolean; at?: number }[] }).enforcement ?? []).map((e, i) => (
                            <div className="data-row" key={i} style={{ gridTemplateColumns: '0.7fr 1.2fr 1fr 1.6fr' }}>
                              <span style={{ fontSize: 11 }}>{e.asset_type}</span>
                              <span style={{ fontSize: 11, wordBreak: 'break-all' }}>{e.asset_key}</span>
                              <span>
                                <i className={e.action === 'restored' || e.action === 'config_restored' ? 'pass' : 'warn'}>{e.action}</i>
                              </span>
                              <span style={{ fontSize: 10, color: 'var(--muted-foreground)', wordBreak: 'break-all' }}>
                                {e.backup || e.target || '—'}{e.reason ? ` · ${e.reason}` : ''}
                              </span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
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

        <Pagination page={page} pageCount={paged.pageCount} onPage={setPage} total={visibleDevices.length} pageSize={PAGE_SIZE} />

        {source === 'error' && visibleDevices.length === 0 && (
          <div className="empty-detail" style={{ minHeight: 180 }}>
            <AlertTriangle size={36} />
            <h2>设备接口暂不可用</h2>
            <p>
              {notice || '暂时无法获取终端清单。'}
              <br />
              未展示任何终端不代表没有终端——请重试，或检查数据采集服务是否正常。
            </p>
            <Button variant="outline" size="sm" onClick={() => void refresh()} disabled={refreshing}>
              {refreshing ? <Spinner /> : <RefreshCw />}
              重试
            </Button>
          </div>
        )}

        {source !== 'loading' && source !== 'error' && visibleDevices.length === 0 && (
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
            ? '终端清单实时同步；注册、编辑与删除会即时保存，历史工单按审计要求留档。'
            : '设备接口暂不可用，请稍后重试，或检查数据采集服务是否正常。'}
        </p>
      </div>

      {/* Agent 覆盖 · 受控设备绑定（独立窗口）：每台受控设备 ↔ 其已安装 AI Agent。
          用户反馈：要能直接看出"哪台机器装了什么 Agent"，而非仅 fleet 级汇总。 */}
      <div className="panel" style={{ marginTop: 16 }}>
        <div className="panel-head">
          <div>
            <h2>Agent 覆盖 · 受控设备绑定</h2>
            <p>每台受控设备最新报告检出的已安装 AI Agent；设备 ID 现基于硬件序列/机器 ID（稳定）。</p>
          </div>
          <span className="status green">{devices.length} 台受控</span>
        </div>
        <div className="data-table">
          <div className="data-head" style={{ gridTemplateColumns: '1.1fr 1.1fr 0.8fr 2.2fr 90px' }}>
            <span>序列号 / 设备 ID</span><span>主机名</span><span>用户</span><span>已安装 AI Agent</span><span>状态</span>
          </div>
          {matrixPaged.rows.map((d) => {
            const tools = ((d as { tools?: string[] }).tools ?? []) as string[];
            const meta = STATUS_META[d.status] ?? STATUS_META.offline;
            const who = d.owner || (d as { os_user?: string }).os_user || '';
            return (
              <div className="data-row" key={d.device_id} style={{ gridTemplateColumns: '1.1fr 1.1fr 0.8fr 2.2fr 90px' }}>
                <strong>{(d as { serial?: string }).serial || d.device_id}</strong>
                <span style={{ fontSize: 11 }}>{(d as { serial?: string }).serial ? `${d.device_id} · ` : ''}{d.hostname} · {osLabel(d.os)}</span>
                <span style={{ fontSize: 11 }}>{who || '未知'}</span>
                <span style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                  {tools.length > 0 ? (
                    tools.map((t) => (
                      <span key={t} style={{ fontSize: 10, padding: '2px 6px', borderRadius: 5, background: 'var(--muted)', border: '1px solid var(--border)' }}>
                        {t}
                      </span>
                    ))
                  ) : (
                    <span style={{ fontSize: 11, color: 'var(--muted-foreground)' }}>未检出 AI Agent</span>
                  )}
                </span>
                <i className={meta.className} style={meta.style}>{meta.label}</i>
              </div>
            );
          })}
          {matrixPaged.rows.length === 0 && (
            <div style={{ padding: '12px 10px', color: 'var(--muted-foreground)', fontSize: 12 }}>暂无受控设备</div>
          )}
        </div>
        <Pagination page={matrixPage} pageCount={matrixPaged.pageCount} onPage={setMatrixPage} total={devices.length} pageSize={PAGE_SIZE} />
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

      {/* P1 版本漂移影响面：设备 / Agent 版本 / 状态 / 预计修复动作 / 更新时间 */}
      {impactDevices.length > 0 && (
        <section className="panel" style={{ padding: 16, margin: '16px 0' }}>
          <div className="panel-head">
            <div>
              <h2>版本漂移影响面</h2>
              <p>
                Agent 低于要求 {fleet?.required_agent_version ?? '—'} 或策略不等于要求 {fleet?.required_policy_version ?? '—'} 的终端及预计修复动作
              </p>
            </div>
            <Badge variant="outline">{impactDevices.length} 台</Badge>
          </div>
          <table className="sentinel-table">
            <thead>
              <tr>
                <th>设备</th>
                <th>Agent</th>
                <th>策略</th>
                <th>状态</th>
                <th>预计修复动作</th>
                <th>更新</th>
              </tr>
            </thead>
            <tbody>
              {impactDevices.map((d) => {
                const policyMismatch =
                  Boolean(fleet?.required_policy_version) &&
                  (d.policy_version ?? '').trim() !== '' &&
                  (d.policy_version ?? '').trim() !== fleet?.required_policy_version;
                return (
                  <tr key={d.device_id}>
                    <td>
                      <b>{d.hostname || d.device_id}</b>
                      <div style={{ fontSize: 11, color: 'var(--muted-foreground)', fontFamily: 'var(--sentinel-font-mono)' }}>{d.device_id}</div>
                    </td>
                    <td style={{ fontFamily: 'var(--sentinel-font-mono)' }}>{d.agent_version ?? '—'}</td>
                    <td style={{ fontFamily: 'var(--sentinel-font-mono)' }}>
                      {d.policy_version ?? '—'}
                      {policyMismatch && (
                        <i className="warn" style={{ fontSize: 10, marginLeft: 6 }}>≠要求</i>
                      )}
                    </td>
                    <td>
                      <span className="sentinel-status" data-state={d.status === 'online' ? 'normal' : d.status === 'stale' ? 'warning' : 'offline'}>
                        {d.status ?? '—'}
                      </span>
                    </td>
                    <td>{repairAction(d)}</td>
                    <td style={{ color: 'var(--muted-foreground)' }}>
                      {d.last_seen ? new Date(d.last_seen * 1000).toLocaleString('zh-CN', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' }) : '—'}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
          <div style={{ margin: '12px 16px 4px', padding: '10px 12px', borderRadius: 8, background: 'var(--sentinel-surface-2, #0d202c)', border: '1px solid var(--sentinel-line, rgba(111,173,204,0.22))', fontSize: 12, color: 'var(--sentinel-text-2, #a5bdc9)' }}>
            <strong style={{ color: 'var(--sentinel-text, #edf7fb)' }}>无法自动更新的终端（旧二进制在自更新前崩溃/离线）</strong>
            <p style={{ margin: '6px 0', color: 'var(--sentinel-text-3, #6c8796)' }}>
              在该终端上以管理员身份运行一次一键脚本即可解锁自更新（保留既有入网配置；之后恢复自动热更）：
            </p>
            <code style={{ display: 'block', fontSize: 11, wordBreak: 'break-all', background: 'var(--sentinel-surface-3, #102a37)', padding: '6px 8px', borderRadius: 6 }}>
              {`curl -fsSL ${typeof window !== 'undefined' ? window.location.origin : ''}/downloads/aegis-install-macos-oneclick.sh | bash`}
            </code>
            <code style={{ display: 'block', marginTop: 6, fontSize: 11, wordBreak: 'break-all', background: 'var(--sentinel-surface-3, #102a37)', padding: '6px 8px', borderRadius: 6 }}>
              {`powershell -ExecutionPolicy Bypass -Command "iwr ${typeof window !== 'undefined' ? window.location.origin : ''}/downloads/aegis-install-windows-oneclick.ps1 -OutFile $env:TEMP\\a.ps1; & $env:TEMP\\a.ps1"`}
            </code>
          </div>
        </section>
      )}

      {/* 视觉迭代：设备详情抽屉（数据来自行内 Device 对象，无额外请求） */}
      <DetailDrawer
        open={selectedDevice !== null}
        onClose={() => setSelectedDevice(null)}
        title={selectedDevice ? selectedDevice.hostname || selectedDevice.device_id : ''}
        subtitle={selectedDevice ? `${selectedDevice.device_id} · ${selectedDevice.status}` : undefined}
        sections={
          selectedDevice
            ? ([
                {
                  label: '基本信息',
                  content: (
                    <div>
                      <div className="kv"><span>负责人</span><span>{selectedDevice.owner || '未指派'}</span></div>
                      <div className="kv"><span>系统 / 用户</span><span>{selectedDevice.os ?? '—'} / {selectedDevice.os_user ?? '—'}</span></div>
                      <div className="kv"><span>序列号</span><span style={{ fontFamily: 'var(--sentinel-font-mono)' }}>{selectedDevice.serial ?? '—'}</span></div>
                      <div className="kv"><span>运行态</span><span>{selectedDevice.run_mode ?? '—'}{selectedDevice.run_mode_inferred ? '（推断）' : ''}</span></div>
                      <div className="kv"><span>扫描根</span><span style={{ wordBreak: 'break-all' }}>{selectedDevice.scan_root ?? '—'}</span></div>
                    </div>
                  ),
                },
                {
                  label: '版本与漂移',
                  content: (
                    <div>
                      <div className="kv"><span>Agent</span><span style={{ fontFamily: 'var(--sentinel-font-mono)' }}>{selectedDevice.agent_version}</span></div>
                      <div className="kv"><span>策略</span><span style={{ fontFamily: 'var(--sentinel-font-mono)' }}>{selectedDevice.policy_version}</span></div>
                      <div className="kv"><span>要求版本</span><span style={{ fontFamily: 'var(--sentinel-font-mono)' }}>{fleet?.required_agent_version ?? '—'}</span></div>
                      <div className="kv"><span>自更保护 / 封禁豁免</span><span>{selectedDevice.pinned ? '已 pin' : '否'} / {selectedDevice.exempt ? '是' : '否'}</span></div>
                    </div>
                  ),
                },
                {
                  label: '网络',
                  content: (
                    <div>
                      <div className="kv"><span>MAC</span><span style={{ fontFamily: 'var(--sentinel-font-mono)' }}>{(selectedDevice.network?.macs ?? []).join(', ') || '—'}</span></div>
                      <div className="kv"><span>本机 IP</span><span style={{ fontFamily: 'var(--sentinel-font-mono)' }}>{(selectedDevice.network?.local_ips ?? []).join(', ') || '—'}</span></div>
                      <div className="kv"><span>出口 IP</span><span style={{ fontFamily: 'var(--sentinel-font-mono)' }}>{selectedDevice.network?.egress_ip ?? '—'}</span></div>
                    </div>
                  ),
                },
                {
                  label: '发现摘要 / 工具',
                  content: (
                    <div>
                      <div className="kv"><span>严重 / 高危</span><span>{selectedDevice.findings_summary?.critical ?? 0} / {selectedDevice.findings_summary?.high ?? 0}</span></div>
                      <div className="kv"><span>中危 / 低危</span><span>{selectedDevice.findings_summary?.medium ?? 0} / {selectedDevice.findings_summary?.low ?? 0}</span></div>
                      <div className="kv"><span>AI 工具</span><span>{(selectedDevice.tools ?? []).join(', ') || '—'}</span></div>
                      <div className="kv"><span>封禁能力</span><span>pf={selectedDevice.capabilities?.pf ? '是' : '否'} es={selectedDevice.capabilities?.es ? '是' : '否'}</span></div>
                    </div>
                  ),
                },
              ] as DrawerSection[])
            : []
        }
      />

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
