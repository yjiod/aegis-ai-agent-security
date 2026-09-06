import { CircleDot } from 'lucide-react';

/**
 * 全局轻提示（toast）。
 *
 * WHY 抽出组件：12 个页面此前各自内联同一段
 * `<div className="toast" role="status"><CircleDot/>{toast}</div>`，复制粘贴使得
 * 同一处 a11y 缺陷要改 12 遍、也必然再次漂移。收敛到此单一定义。
 *
 * WHY `<output>` 而不是 `<div role="status">`：HTML-AAM 规定 output 元素的隐式
 * ARIA 角色即 `status`，二者对辅助技术完全等价，而 output 不需要显式 role
 * （jsx-a11y/prefer-tag-over-role 要求的正是「有语义标签就别用 role 模拟」）。
 * 注意不要再补 `role="status"`，那会触发 no-redundant-roles。
 *
 * 视觉安全性：app/globals.css 的 `.toast` 已显式声明 position:fixed 与
 * display:flex，且亮色主题与窄屏断点均按类名覆盖，与元素标签无关，
 * 因此 output 默认的 inline 显示不会改变既有渲染结果。
 */
export function Toast({ message }: { message: string }) {
  if (!message) return null;
  return (
    <output className="toast">
      <CircleDot size={16} />
      {message}
    </output>
  );
}
