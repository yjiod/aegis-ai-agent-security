'use client';
import { useEffect, useState } from 'react';
import { AlertTriangle, ShieldCheck, Users } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Toast } from '@/components/toast';

const plannedRoles = [
  ['安全管理员', '全部权限', '策略发布、事件处置、设备管理、审计导出'],
  ['审计员', '只读 + 报告导出', '查看风险事件、导出合规报告、无法修改策略'],
  ['运维工程师', '设备管理 + 策略查看', '部署 Agent、查看设备状态、无法发布策略'],
  ['开发者', '个人设备查看', '仅查看自己设备的扫描结果与风险通知'],
];

export default function TeamPage() {
  const [toast, setToast] = useState('');
  const [admins, setAdmins] = useState<string[]>([]);
  const [newAdmin, setNewAdmin] = useState('');

  async function loadAdmins() {
    try {
      const r = await fetch('/api/admins', { cache: 'no-store' });
      if (r.ok) { const d = await r.json(); setAdmins(d.admins ?? []); }
    } catch { /* ignore */ }
  }
  useEffect(() => { void loadAdmins(); }, []);

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

  return (
    <>
      

      <div className="page-head">
        <div>
          <p className="eyebrow">管理 / 团队与权限</p>
          <h1>团队与权限</h1>
          <p>连接企业身份源，实现基于角色的访问控制与操作审计。</p>
        </div>
        <div className="head-actions">
          <Button onClick={() => setToast('提示：配置向导尚未连接企业后端。')}>
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

      <div className="empty-detail">
        <ShieldCheck size={44} />
        <h2>团队与权限已接入</h2>
        <p>
          下一阶段可连接企业身份源（Azure AD / LDAP / SAML），
          <br />
          实现 RBAC 角色管理、操作审计与多租户隔离。
        </p>
        <Button onClick={() => setToast('提示：配置向导尚未连接企业后端。')}>
          打开配置向导
        </Button>
      </div>

      <div className="panel" style={{ marginTop: 24 }}>
        <div className="panel-head">
          <div>
            <h2>规划中的角色模型</h2>
            <p>RBAC 四级角色，接入身份源后自动生效</p>
          </div>
        </div>
        <div className="data-table">
          <div className="data-head">
            <span>角色</span>
            <span>权限级别</span>
            <span>能力范围</span>
            <span>状态</span>
          </div>
          {plannedRoles.map(([role, level, scope]) => (
            <div className="data-row" key={role}>
              <strong>{role}</strong>
              <span>{level}</span>
              <span>{scope}</span>
              <i className="warn">规划中</i>
            </div>
          ))}
        </div>
      </div>
    </>
  );
}
