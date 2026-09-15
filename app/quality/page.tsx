'use client';

import { ScanExplorer } from '@/components/scan-explorer';

/**
 * 代码质量扫描页。数据源 = GET /api/findings?category=code（跨设备聚合 Collector 真实上报：
 * hardcoded_secret / dynamic_eval / weak_random_token / insecure_tls_verification 等）。
 * 此前本页内联伪造的 scanTrend / scanRows（payment-service、notification-svc 等看似真实的
 * 仓库名 + "门禁通过率 94.4%"）却标注"实时数据"，违反"绝不伪造数据"红线，已整体替换为共享
 * ScanExplorer（诚实加载/断连/空态 + 真实严重度计数 + 链到处置中心）。
 */
export default function QualityPage() {
  return (
    <ScanExplorer
      category="code"
      eyebrow="安全能力 / 代码质量"
      title="代码质量扫描"
      description="SAST、依赖 CVE 与密钥检测在提交与合并两个门禁点执行。"
    />
  );
}
