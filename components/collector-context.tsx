'use client';
import { createContext, useContext } from 'react';

export type FleetSummary = {
  total_devices: number;
  active_devices: number;
  stale_devices: number;
  required_agent_version: string;
  required_policy_version: string;
  latest_severity: { critical: number; high: number; normal: number };
  version_posture: {
    current: number;
    agent_mismatch: number;
    policy_mismatch: number;
    both_mismatch: number;
    unknown: number;
  };
  credential_posture?: { current: number; previous: number; legacy: number };
  /** 计数层(stage-1)：fleet 发现总数（device_state 计数列 SUM，零 body 解析）。旧 collector 无此字段 → optional。 */
  finding_totals?: { critical: number; high: number; medium: number; low: number };
};

export type CollectorState = 'checking' | 'live' | 'demo';

export type CollectorContextValue = {
  fleet: FleetSummary | null;
  collectorState: CollectorState;
};

const Ctx = createContext<CollectorContextValue>({
  fleet: null,
  collectorState: 'checking',
});

export const useCollector = () => useContext(Ctx);
export const CollectorProvider = Ctx.Provider;
