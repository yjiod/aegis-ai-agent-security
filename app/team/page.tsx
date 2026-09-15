'use client';
import { useEffect, useState } from 'react';
import { ShieldCheck, Users } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Toast } from '@/components/toast';
import { MfaPanel } from '@/components/mfa-panel';

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
  useEffect(() => { void loadAdmins(); void loadAuditors(); }, []);

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
              <span>{a !== 'admin' && <button className="handle" onClick={() => void delAdmin(a)}>移除</button>}</span>
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
              <span><button className="handle" onClick={() => void delAuditor(a)}>移除</button></span>
            </div>
          ))}
        </div>
      </div>

      <div className="empty-detail">
        <ShieldCheck size={44} />
        <h2>统一身份与权限已启用</h2>
        <p>
          已支持企业 SSO（OIDC / UAC 工号白名单）+ 服务端推导的三档 RBAC（管理员 / 审计员 / 只读）+ 全量操作审计。
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
    </>
  );
}
