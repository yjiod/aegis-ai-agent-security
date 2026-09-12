import { redirect } from 'next/navigation';

/** 接入中心已升级为集成控制面 /integrations; 旧入口重定向。 */
export default function OnboardingPage() {
  redirect('/integrations');
}
