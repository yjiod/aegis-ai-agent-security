'use client';
import { useState } from 'react';
import { AlertTriangle, CircleDot, ShieldCheck, Users } from 'lucide-react';
import { Button } from '@/components/ui/button';

const plannedRoles = [
  ['安全管理员', '全部权限', '策略发布、事件处置、设备管理、审计导出'],
  ['审计员', '只读 + 报告导出', '查看风险事件、导出合规报告、无法修改策略'],
  ['运维工程师', '设备管理 + 策略查看', '部署 Agent、查看设备状态、无法发布策略'],
  ['开发者', '个人设备查看', '仅查看自己设备的扫描结果与风险通知'],
];

export default function TeamPage() {
  const [toast, setToast] = useState('');

  return (
    <>
      <div className="demo-notice" role="note">
        <AlertTriangle size={16} />
        <span>
          <strong>演示模式</strong>
          团队与权限管理尚未连接企业身份源，以下为规划中的 RBAC 角色模型。
        </span>
      </div>

      <div className="page-head">
        <div>
          <p className="eyebrow">管理 / 团队与权限</p>
          <h1>团队与权限</h1>
          <p>连接企业身份源，实现基于角色的访问控制与操作审计。</p>
        </div>
        <div className="head-actions">
          <Button onClick={() => setToast('演示模式：配置向导尚未连接企业后端。')}>
            <Users size={16} />
            打开配置向导
          </Button>
        </div>
      </div>

      {toast && (
        <div className="toast" role="status">
          <CircleDot size={16} />
          {toast}
        </div>
      )}

      <div className="empty-detail">
        <ShieldCheck size={44} />
        <h2>团队与权限已接入</h2>
        <p>
          下一阶段可连接企业身份源（Azure AD / LDAP / SAML），
          <br />
          实现 RBAC 角色管理、操作审计与多租户隔离。
        </p>
        <Button onClick={() => setToast('演示模式：配置向导尚未连接企业后端。')}>
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
