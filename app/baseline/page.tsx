import { redirect } from 'next/navigation';

/**
 * /baseline（旧「编码规范基线」静态页）已并入真实的「基线管理」页 /baselines。
 * 两个仅差复数 s、同一图标、一真一假的入口曾让用户无法分辨，故此处直接重定向，
 * 消除重复入口与页内虚构的 v4.8 / 98.2% 合规率等演示数字。
 */
export default function BaselineRedirect() {
  redirect('/baselines');
}
