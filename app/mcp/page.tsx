'use client';

import { ScanExplorer } from '@/components/scan-explorer';

/**
 * MCP 扫描器页。数据源 = GET /api/findings?category=mcp（跨设备聚合 Collector 真实上报）。
 * 此前本页内联伪造的 scanTrend / scanRows 静态样例（filesystem-mcp/browser-mcp 等）却标注
 * "实时数据 / 终端安全 Agent 上报实时"，违反"绝不伪造数据"红线，已整体替换为共享
 * ScanExplorer（诚实加载/断连/空态 + 真实严重度计数 + 链到处置中心）。
 */
export default function McpPage() {
  return (
    <ScanExplorer
      category="mcp"
      eyebrow="安全能力 / MCP 扫描器"
      title="MCP 扫描器"
      description="校验 MCP 工具权限、密钥来源、出站白名单与令牌范围。"
    />
  );
}
