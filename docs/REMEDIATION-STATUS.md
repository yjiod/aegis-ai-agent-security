# 自动纠偏结果与部署验证

自动纠偏扫描输出控制台处理进度。拒绝规则保存、策略发布、终端执行是三个独立阶段；扫描接口不读取终端执行回执，因此不能证明工具已被阻断。

`POST /api/remediation/auto-sweep` 和 JSON webhook `aegis.remediation/v1` 增加 `status` 字段：

| 字段 | 值 | 含义 |
| --- | --- | --- |
| `deny_rules` | `not_requested` | 本轮未保存新的拒绝规则，不表示历史规则不存在 |
| `deny_rules` | `saved` | 本轮规则保存调用已成功；沿用存储模式，无 PG 的开发环境仅有内存状态 |
| `deny_rules` | `save_failed` | 保存失败，本轮没有继续发布 |
| `policy` | `not_attempted` | 本轮未尝试发布 |
| `policy` | `blocked` | 保存失败、发布门禁拦截或缺少签名密钥 |
| `policy` | `published` | 现有发布函数返回策略版本；不代表终端已接收或执行 |
| `endpoint` | `unverified` | 本接口未验证终端执行 |

兼容字段 `denied` 继续表示本轮保存的拒绝规则列表。消费者不得把其数量用作“已成功阻断”的终端数。已有 `published_version`、`publish_blocked`、`notified` 字段保留；`notified` 表示 webhook 请求成功数量，不代表用户已阅读。

控制台、钉钉文本与审计使用“已保存拒绝规则”和“终端执行未验证”。保存失败返回固定错误码 `deny_persistence_failed`，不返回底层数据库异常内容。

## 部署与回滚

本变更只涉及控制台结果表达，不改变处置条件、发布门禁或 macOS/Windows 执行动作。控制台按常规人工评审与 CI 门禁部署；端点无需升级。JSON 接收方如拒绝未知字段，应先兼容新增 `status`，再升级控制台。滚动升级期间新页面兼容不含 `status` 的旧响应。回滚控制台会恢复旧的结果文案与响应形状。

验证应覆盖保存失败、发布门禁拦截、缺少签名密钥、正常发布和 webhook 失败。即使策略正常发布、执行模块关闭，也必须显示“终端执行未验证”。本次自动化测试使用合成数据与模拟边界，不连接生产 Collector、数据库或 webhook；跨平台真实执行验收仍需终端回执及工具行为证据。

现有发布函数的数据库写入与终端回执关联不在本变更范围内；`published` 沿用其控制台发布语义，不新增持久化或执行成功保证。
