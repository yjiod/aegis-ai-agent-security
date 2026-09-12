# 联合开发指南

1. 从 `main` 创建分支，PR 说明威胁场景、安全不变量和验证证据。
2. 行为变更必须带回归测试；跨平台能力需同时评估 Python 与 PowerShell。
3. 不得降低默认安全级别或扩大厂商自动处置动作，除非有书面风险接受与审计设计。
4. 不得提交真实凭据、客户 URL、人员/设备数据、生产报告、证书或 `.env`。
5. 合并前必须通过 GitHub Actions 与离线发行验证器。

PR 建议包含变更摘要、威胁模型、兼容性与回滚影响、测试证据，以及 MDM/EDR/联软验收需求。

## Lint 约定

- Lint 使用 oxlint（type-aware，配置见 `.oxlintrc.json`），门禁标准是 **0 error**。CI 的 `verify` 作业会执行 `npm run lint` 与 `npx tsc --noEmit`，两者必须全绿。
- 业务代码优先改代码而非关规则；确需豁免时用 `oxlint-disable-next-line <plugin>/<rule>` 并附理由，且该指令必须紧贴被豁免代码的上一行——中间隔了其他注释会失效（oxlint 的 "next line" 是字面意义的下一行）。
- `components/ui/**` 与 `hooks/use-mobile.ts` 是 shadcn/ui 生成的 vendored 代码，会被 CLI 重新生成覆盖，手改无意义且可能破坏样式。`.oxlintrc.json` 的 `overrides` 仅对这两个路径关闭其生成产物必然触发的少数规则（`prefer-tag-over-role`、`react-compiler`、`restrict-template-expressions` 等）。不要把该豁免扩大到业务代码。
