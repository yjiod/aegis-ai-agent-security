/**
 * 二次脱敏（handoff P0）统一策略：宽列表 / 排行视图默认不平铺终端真实路径与出口 IP；
 * 完整值仅在有权限的详情抽屉 / 研判上下文展示。掩码仍保留可解释性
 * （basename 可定位文件、/16 可定位来源网段），不把视图变成无信息黑块。
 */

/** 路径 → …/basename（完整路径留给详情抽屉）。 */
export function maskPath(p: string): string {
  const parts = p.split('/');
  const base = parts[parts.length - 1] || p;
  return parts.length > 1 ? `…/${base}` : base;
}

/** 出口 IP → /16 掩码（v4）或前缀掩码（v6/其它）。 */
export function maskEgress(ip: string): string {
  const v4 = ip.split('.');
  if (v4.length === 4) return `${v4[0]}.${v4[1]}.x.x`;
  return ip.length > 8 ? `${ip.slice(0, 8)}…` : ip;
}
