# 单端推送原则（阶段 F）

> 员工终端**只推送 Aegis 一个 agent**。其余平台（Fleet/Wazuh/PacketFence/商用 EDR/桌管）的 agent
> 由**各自平台或桌管/MDM 下发**，Aegis 不代推、不编排安装第三方 agent。

## 一、边界
- **Aegis bundle 内容**：Aegis 跨平台 agent + 策略/基线/扫描器 + 上报/自更新（兜底）。**不含** osquery/wazuh/pf 等第三方 agent 安装包。
- **第三方 agent 归属**：Fleet 下发 orbit/osquery；Wazuh 下发 wazuh agent；PacketFence 走 802.1X/Portal（无 agent 或 supplicant）；商用 EDR/桌管由其控制台下发。
- **Aegis 与平台的关系**：服务端经厂商中立契约（FourAInterface）对接，做资产/告警/合规/准入的**汇聚与联动**，不做终端安装编排。

## 二、集成控制面（/integrations）
- 列出已配置平台 + 健康（在线/不可达/未配置）+ 能力集 + 端点。
- 配置经环境变量 `AEGIS_INT_<NAME>_{URL,TOKEN,USER,PASS}` 注入（console.env，chmod 600，不进 Git）。
- 告警汇聚：各平台事件经适配器归一为 Aegis SecurityEvent 进风险中心（阶段 D 已验证 forward_event 链路）。

## 三、替换/扩展
- 换厂商 = 换适配器实现 + 改 `AEGIS_INT_*` 配置；核心代码零改动。
- 新增平台 = 新写一个 FourAInterface 适配器 + 在控制面注册一项。
