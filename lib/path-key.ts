/**
 * path 资产键归一化——纯函数、零依赖，可被 console
 * 与外部系统（OpenAPI 消费方）直接复用。
 *
 * 将兼容格式的文件路径折叠为同一键：事件 ID/行号/盘符大小写/
 * 用户主目录前缀（~ 与绝对路径）/尾部斜杠的差异不得产生不同资产键，否则加白后
 * 同文件的新发现（ID 不同）仍会重复告警。
 * 本函数不处理分类、实际片段或租户作用域，不能用作问题级例外指纹。
 */
export function normalizePathKey(rawPath: string): string {
  let p = rawPath.trim();
  // 1) 统一反斜杠为 /（Windows），丢弃查询串/锚点
  p = p.replace(/\\/g, '/').split('?')[0].split('#')[0];
  // 2) 丢弃行号/列号后缀（:123、:12:34）。仅匹配整个路径末尾，不破坏盘符 c:/。
  p = p.replace(/[\w./-][::]\d+(?::\d+)?$/, (m) => m.replace(/[::]\d+(?::\d+)?$/, ''));
  // 3) 用户主目录折叠：/users/<who>/、/home/<who>/ → ~/（大小写不敏感，覆盖 C:/Users）
  p = p.replace(/^\/users\/[^/]+\//i, '~/');
  p = p.replace(/^[a-z]:\/users\/[^/]+\//i, '~/');
  p = p.replace(/^\/home\/[^/]+\//, '~/');
  // 4) 大小写不敏感（Windows 文件系统）
  p = p.toLowerCase();
  // 5) 折叠 ./ 与尾部斜杠
  p = p.replace(/(^|\/)\.\/(?!$)/g, '$1').replace(/\/+$/, '');
  return p;
}
