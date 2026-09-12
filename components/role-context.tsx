'use client';
import { createContext, useContext, useEffect, useState } from 'react';

export type Role = 'admin' | 'viewer';
const RoleCtx = createContext<{ role: Role; subject: string }>({ role: 'viewer', subject: '' });
export const useRole = () => useContext(RoleCtx);
export const RoleProvider = RoleCtx.Provider;

export function useFetchRole() {
  const [state, setState] = useState<{ role: Role; subject: string }>({ role: 'viewer', subject: '' });
  useEffect(() => {
    fetch('/api/auth/me', { cache: 'no-store' })
      .then((r) => (r.ok ? (r.json() as Promise<any>) : null))
      .then((d) => {
        if (d && d.authenticated) setState({ role: d.role, subject: d.subject });
      })
      .catch(() => setState({ role: 'viewer', subject: '' }));
  }, []);
  return state;
}
