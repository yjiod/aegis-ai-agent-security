'use client';

import { ScanExplorer } from '@/components/scan-explorer';

/**
 * Skill 扫描器页。数据源 = GET /api/findings?category=skill（跨设备聚合 Collector 真实上报）。
 * 此前本页内联伪造的 scanTrend / scanRows 静态样例却标注"实时数据/终端 Agent 上报实时"，
 * 违反"绝不伪造数据"红线，已整体替换为共享 ScanExplorer（诚实加载/断连/空态 + 真实严重度计数）。
 */
export default function SkillsPage() {
  return (
    <ScanExplorer
      category="skill"
      eyebrow="安全能力 / Skill 扫描器"
      title="Skill 扫描器"
      description="校验 Skill 的权限声明、隐藏指令、签名与依赖清单。"
    />
  );
}
