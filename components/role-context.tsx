'use client';
import { createContext, useContext, useEffect, useState } from 'react';

export type Role = 'admin' | 'operator' | 'auditor' | 'viewer';
const RoleCtx = createContext<{ role: Role; subject: string }>({ role: 'viewer', subject: '' });
export const useRole = () => useContext(RoleCtx);
export const RoleProvider = RoleCtx.Provider;

export function useFetchRole() {
  const [state, setState] = useState<{ role: Role; subject: string }>({ role: 'viewer', subject: '' });
  useEffect(() => {
    fetch('/api/auth/me', { cache: 'no-store' })
      .then((r) => (r.ok ? (r.json() as Promise<{ authenticated?: boolean; role?: Role; subject?: string }>) : null))
      .then((d) => {
        if (d && d.authenticated) setState({ role: d.role ?? 'viewer', subject: d.subject ?? '' });
      })
      .catch(() => setState({ role: 'viewer', subject: '' }));
  }, []);
  return state;
}
