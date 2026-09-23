'use client';
import { useEffect, useState } from 'react';
import { ShieldCheck, Users } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Toast } from '@/components/toast';
import { MfaPanel } from '@/components/mfa-panel';
import { ActionConfirmDialog, type ActionConfirmVariant } from '@/components/action-confirm-dialog';
import { useRole } from '@/components/role-context';

/** 团队页所有不可逆动作（移除角色 / 吊销会话）统一走确认弹窗。 */
type TeamActionKind = 'revoke' | 'delAdmin' | 'delAuditor' | 'delOperator' | 'delDeveloper';
type PendingTeamAction = { kind: TeamActionKind; emp: string } | null;

const ROLE_LABEL: Record<Exclude<TeamActionKind, 'revoke'>, string> = {
  delAdmin: '管理员',
  delAuditor: '审计员',
  delOperator: '运维工程师',
  delDeveloper: '开发者',
};

function teamActionCopy(pending: PendingTeamAction): {
  title: string;
  description: string;
  impact: string[];
  rollback: string;
  variant: ActionConfirmVariant;
  confirmLabel: string;
} | null {
  if (!pending) return null;
  const { kind, emp } = pending;
  if (kind === 'revoke') {
    return {
      title: '吊销既有会话',
      description: `强制下线工号「${emp}」当前所有已登录会话。`,
      impact: [
        '该工号已签发的登录会话立即失效，需重新登录',
        '不改动其白名单 / 角色，权限本身保持不变',
      ],
      rollback: '无需回滚：该用户重新登录即可获得新会话。',
      variant: 'warning',
      confirmLabel: '确认吊销',
    };
  }
  const label = ROLE_LABEL[kind];
  return {
    title: `移除${label}`,
    description: `把工号「${emp}」从${label}白名单中移除。`,
    impact: [
      `该工号将立即失去${label}对应的权限与登录准入`,
      '其名下已执行的处置 / 发布 / 变更记录仍保留在审计日志中',
    ],
    rollback: `如需恢复，重新在上方输入该工号并点击“添加${label}”即可。`,
    variant: 'danger',
    confirmLabel: '确认移除',
  };
}

const plannedRoles: Array<[string, string, string, string]> = [
  ['安全管理员', '全部权限', '策略发布、事件处置、设备管理、审计导出', '已启用'],
  ['审计员', '只读 + 审计查阅', '查看风险事件与审计日志、导出合规报告、无法修改策略', '已启用'],
  ['运维工程师', '设备管理 + 策略查看', '部署 Agent、查看设备状态、无法发布策略', '规划中'],
  ['开发者', '个人设备查看', '仅查看自己设备的扫描结果与风险通知', '规划中'],
];

export default function TeamPage() {
  const [toast, setToast] = useState('');
  const [admins, setAdmins] = useState<string[]>([]);
  const [newAdmin, setNewAdmin] = useState('');
  const [auditors, setAuditors] = useState<string[]>([]);
  const [newAuditor, setNewAuditor] = useState('');
  const [operators, setOperators] = useState<string[]>([]);
  const [envOperators, setEnvOperators] = useState<string[]>([]);
  const [developers, setDevelopers] = useState<string[]>([]);
  const [envDevelopers, setEnvDevelopers] = useState<string[]>([]);
  const [newDeveloper, setNewDeveloper] = useState('');
  const [newOperator, setNewOperator] = useState('');
  const { subject } = useRole();
  const [pending, setPending] = useState<PendingTeamAction>(null);
  const [confirmBusy, setConfirmBusy] = useState(false);

  async function loadAdmins() {
    try {
      const r = await fetch('/api/admins', { cache: 'no-store' });
      if (r.ok) { const d = (await r.json()) as any; setAdmins(d.admins ?? []); }
    } catch { /* ignore */ }
  }
  async function loadAuditors() {
    try {
      const r = await fetch('/api/auditors', { cache: 'no-store' });
      if (r.ok) { const d = (await r.json()) as any; setAuditors(d.auditors ?? []); }
    } catch { /* ignore */ }
  }
  async function loadOperators() {
    try {
      const r = await fetch('/api/operators', { cache: 'no-store' });
      if (r.ok) { const d = (await r.json()) as any; setOperators(d.operators ?? []); setEnvOperators(d.env_operators ?? []); }
    } catch { /* ignore */ }
  }
  async function addOperator() {
    const v = newOperator.trim();
    if (!v) return;
    const r = await fetch('/api/operators', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ employeeNo: v }) });
    setToast(r.ok ? `已添加运维工程师 ${v}` : '添加失败（可能无权限或工号格式错）');
    setNewOperator('');
    void loadOperators();
  }
  async function delOperator(emp: string) {
    const r = await fetch(`/api/operators?employeeNo=${encodeURIComponent(emp)}`, { method: 'DELETE' });
    setToast(r.ok ? `已移除运维工程师 ${emp}` : '移除失败（可能无权限）');
    void loadOperators();
  }
  async function loadDevelopers() {
    try {
      const r = await fetch('/api/developers', { cache: 'no-store' });
      if (r.ok) { const d = (await r.json()) as any; setDevelopers(d.developers ?? []); setEnvDevelopers(d.env_developers ?? []); }
    } catch { /* ignore */ }
  }
  async function addDeveloper() {
    const v = newDeveloper.trim();
    if (!v) return;
    const r = await fetch('/api/developers', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ employeeNo: v }) });
    setToast(r.ok ? `已添加开发者 ${v}` : '添加失败（可能无权限或工号格式错）');
    setNewDeveloper('');
    void loadDevelopers();
  }
  async function delDeveloper(emp: string) {
    const r = await fetch(`/api/developers?employeeNo=${encodeURIComponent(emp)}`, { method: 'DELETE' });
    setToast(r.ok ? `已移除开发者 ${emp}` : '移除失败（可能无权限）');
    void loadDevelopers();
  }
  useEffect(() => { void loadAdmins(); void loadAuditors(); void loadOperators(); void loadDevelopers(); }, []);

  async function addAdmin() {
    const v = newAdmin.trim();
    if (!v) return;
    const r = await fetch('/api/admins', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ employeeNo: v }) });
    setToast(r.ok ? `已添加管理员 ${v}` : '添加失败（可能无权限或工号格式错）');
    setNewAdmin('');
    void loadAdmins();
  }
  async function delAdmin(emp: string) {
    const r = await fetch(`/api/admins?employeeNo=${encodeURIComponent(emp)}`, { method: 'DELETE' });
    setToast(r.ok ? `已移除管理员 ${emp}` : '移除失败（本地 admin 不可移除）');
    void loadAdmins();
  }

  async function addAuditor() {
    const v = newAuditor.trim();
    if (!v) return;
    const r = await fetch('/api/auditors', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ employeeNo: v }) });
    setToast(r.ok ? `已添加审计员 ${v}` : '添加失败（可能无权限或工号格式错）');
    setNewAuditor('');
    void loadAuditors();
  }
  async function delAuditor(emp: string) {
    const r = await fetch(`/api/auditors?employeeNo=${encodeURIComponent(emp)}`, { method: 'DELETE' });
    setToast(r.ok ? `已移除审计员 ${emp}` : '移除失败（可能无权限）');
    void loadAuditors();
  }

  /** 4A · 会话生命周期：强制下线某工号的全部既有会话（不改白名单/角色）。 */
  async function revokeSessionsFor(emp: string) {
    const r = await fetch('/api/auth/revoke', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ subject: emp }) });
    setToast(r.ok ? `已吊销 ${emp} 的既有会话` : '吊销失败（可能无权限或凭据存储不可用）');
  }

  /** 统一确认弹窗的执行入口：所有不可逆动作都在人工确认后由此分发。 */
  async function confirmRun() {
    if (!pending || confirmBusy) return;
    setConfirmBusy(true);
    try {
      switch (pending.kind) {
        case 'revoke': await revokeSessionsFor(pending.emp); break;
        case 'delAdmin': await delAdmin(pending.emp); break;
        case 'delAuditor': await delAuditor(pending.emp); break;
        case 'delOperator': await delOperator(pending.emp); break;
        case 'delDeveloper': await delDeveloper(pending.emp); break;
      }
      setPending(null);
    } finally {
      setConfirmBusy(false);
    }
  }

  const confirmCopy = teamActionCopy(pending);

  return (
    <>
      

      <div className="page-head">
        <div>
          <p className="eyebrow">管理 / 团队与权限</p>
          <h1>团队与权限</h1>
          <p>连接企业身份源，实现基于角色的访问控制与操作审计。</p>
        </div>
        <div className="head-actions">
          {/* 诚实原则：配置向导未接入企业后端，不放"点了只弹提示"的活按钮。 */}
          <Button disabled title="配置向导尚未连接企业身份源后端；当前 SSO 通过服务端环境变量/白名单配置">
            <Users size={16} />
            打开配置向导
          </Button>
        </div>
      </div>

      <Toast message={toast} />

      <div className="panel" style={{ marginBottom: 16 }}>
        <div className="panel-head">
          <div><h2>SSO 管理员</h2><p>白名单工号可通过统一身份登录并获管理员权限；其余工号拒绝登录。</p></div>
        </div>
        <div style={{ display: 'flex', gap: 8, marginBottom: 12 }}>
          <input className="form-input" style={{ flex: 1 }} placeholder="工号" value={newAdmin} onChange={(e) => setNewAdmin(e.target.value)} />
          <Button onClick={() => void addAdmin()}>添加管理员</Button>
        </div>
        <div className="data-table">
          <div className="data-head"><span>工号</span><span>来源</span><span>操作</span><span /></div>
          {admins.map((a) => (
            <div className="data-row" key={a}>
              <strong>{a}</strong>
              <span>{a === 'admin' ? '本地' : '白名单'}</span>
              <span>{a === 'admin' ? '恒为管理员' : '管理员'}</span>
              <span>{a !== 'admin' && <><button className="handle" onClick={() => setPending({ kind: 'revoke', emp: a })}>吊销会话</button> <button className="handle" onClick={() => setPending({ kind: 'delAdmin', emp: a })}>移除</button></>}</span>
            </div>
          ))}
        </div>
      </div>

      <div className="panel" style={{ marginBottom: 16 }}>
        <div className="panel-head">
          <div><h2>审计员（只读）</h2><p>审计员可查阅风险事件与审计日志、导出合规报告，但不能修改任何策略或处置。</p></div>
        </div>
        <div style={{ display: 'flex', gap: 8, marginBottom: 12 }}>
          <input className="form-input" style={{ flex: 1 }} placeholder="工号" value={newAuditor} onChange={(e) => setNewAuditor(e.target.value)} />
          <Button onClick={() => void addAuditor()}>添加审计员</Button>
        </div>
        <div className="data-table">
          <div className="data-head"><span>工号</span><span>来源</span><span>角色</span><span>操作</span></div>
          {auditors.length === 0 ? (
            <div className="data-row"><span style={{ gridColumn: '1 / -1', color: 'var(--muted-foreground)' }}>尚未配置审计员</span></div>
          ) : auditors.map((a) => (
            <div className="data-row" key={a}>
              <strong>{a}</strong>
              <span>白名单</span>
              <span>只读审计</span>
              <span><button className="handle" onClick={() => setPending({ kind: 'revoke', emp: a })}>吊销会话</button> <button className="handle" onClick={() => setPending({ kind: 'delAuditor', emp: a })}>移除</button></span>
            </div>
          ))}
        </div>
      </div>

      <div className="panel" style={{ marginBottom: 16 }}>
        <div className="panel-head">
          <div><h2>开发者（仅本人设备）</h2><p>仅可读本人名下设备；无写权限、不能发布策略/处置/管用户/读审计。</p></div>
        </div>
        <div style={{ display: 'flex', gap: 8, marginBottom: 12 }}>
          <input className="form-input" style={{ flex: 1 }} placeholder="工号" value={newDeveloper} onChange={(e) => setNewDeveloper(e.target.value)} />
          <Button onClick={() => void addDeveloper()}>添加开发者</Button>
        </div>
        <div className="data-table">
          <div className="data-head"><span>工号</span><span>来源</span><span>操作</span></div>
          {developers.length === 0 && envDevelopers.length === 0 ? (
            <div className="data-row"><span style={{ gridColumn: '1 / -1', color: 'var(--muted-foreground)' }}>尚未配置开发者</span></div>
          ) : (
            <>
              {developers.map((a) => (
                <div className="data-row" key={a}><strong>{a}</strong><span>手动添加</span><span><button className="handle" onClick={() => setPending({ kind: 'delDeveloper', emp: a })}>移除</button></span></div>
              ))}
              {envDevelopers.map((a) => (
                <div className="data-row" key={`env-${a}`}><strong>{a}</strong><span>系统预置</span><span><span style={{ fontSize: 11, color: 'var(--muted-foreground)' }}>系统预置，不可在此移除</span></span></div>
              ))}
            </>
          )}
        </div>
      </div>

      <div className="panel" style={{ marginBottom: 16 }}>
        <div className="panel-head">
          <div><h2>运维工程师（终端管理）</h2><p>仅可登记/更新/移除终端；不能发布策略、处置打标、管用户或读审计。</p></div>
        </div>
        <div style={{ display: 'flex', gap: 8, marginBottom: 12 }}>
          <input className="form-input" style={{ flex: 1 }} placeholder="工号" value={newOperator} onChange={(e) => setNewOperator(e.target.value)} />
          <Button onClick={() => void addOperator()}>添加运维工程师</Button>
        </div>
        <div className="data-table">
          <div className="data-head"><span>工号</span><span>来源</span><span>角色</span><span>操作</span></div>
          {operators.length === 0 && envOperators.length === 0 ? (
            <div className="data-row"><span style={{ gridColumn: '1 / -1', color: 'var(--muted-foreground)' }}>尚未配置运维工程师</span></div>
          ) : (
            <>
              {operators.map((a) => (
                <div className="data-row" key={a}>
                  <strong>{a}</strong>
                  <span>手动添加</span>
                  <span>终端管理</span>
                  <span><button className="handle" onClick={() => setPending({ kind: 'revoke', emp: a })}>吊销会话</button> <button className="handle" onClick={() => setPending({ kind: 'delOperator', emp: a })}>移除</button></span>
                </div>
              ))}
              {envOperators.map((a) => (
                <div className="data-row" key={`env-${a}`}>
                  <strong>{a}</strong>
                  <span>系统预置</span>
                  <span>终端管理</span>
                  <span><button className="handle" onClick={() => setPending({ kind: 'revoke', emp: a })}>吊销会话</button> <span style={{ fontSize: 11, color: 'var(--muted-foreground)' }}>系统预置，不可在此移除</span></span>
                </div>
              ))}
            </>
          )}
        </div>
      </div>

      <div className="empty-detail">
        <ShieldCheck size={44} />
        <h2>统一身份与权限已启用</h2>
        <p>
          已支持企业 SSO（OIDC / UAC 工号白名单）+ 服务端推导的四档 RBAC（管理员 / 运维 / 审计员 / 只读）+ 全量操作审计。
          <br />
          下一阶段（规划中）：细粒度角色（运维工程师 / 开发者）、跨设备会话吊销与多租户隔离。
        </p>
      </div>

      <div className="panel" style={{ marginTop: 24 }}>
        <div className="panel-head">
          <div>
            <h2>角色模型</h2>
            <p>安全管理员与审计员已启用；运维工程师、开发者接入身份源后生效</p>
          </div>
        </div>
        <div className="data-table">
          <div className="data-head">
            <span>角色</span>
            <span>权限级别</span>
            <span>能力范围</span>
            <span>状态</span>
          </div>
          {plannedRoles.map(([role, level, scope, status]) => (
            <div className="data-row" key={role}>
              <strong>{role}</strong>
              <span>{level}</span>
              <span>{scope}</span>
              <i className={status === '已启用' ? 'pass' : 'warn'}>{status}</i>
            </div>
          ))}
        </div>
      </div>

      <MfaPanel />

      <ActionConfirmDialog
        open={pending !== null}
        onOpenChange={(open) => {
          if (!open && !confirmBusy) setPending(null);
        }}
        title={confirmCopy?.title ?? ''}
        description={confirmCopy?.description}
        impact={confirmCopy?.impact}
        rollback={confirmCopy?.rollback}
        operator={subject || '当前登录用户'}
        variant={confirmCopy?.variant ?? 'default'}
        confirmLabel={confirmCopy?.confirmLabel ?? '确认执行'}
        busy={confirmBusy}
        onConfirm={() => void confirmRun()}
      />
    </>
  );
}
