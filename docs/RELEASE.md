# 发行与部署流程

1. 更新代码、测试、部署文档和版本元数据。
2. 重算四项运行时 SHA-256，更新全部哈希消费者。
3. 按 `aegis_release_verify.py` 的 `BUNDLE_FILES` 重建 `aegis-enterprise-bundle.zip`。
4. 执行 Python 测试、Shell 语法检查、前端构建、离线验证和 `git diff --check`。
5. 提交并推送 GitHub 私有仓库。
6. 从同一提交生成 Sites 归档、保存版本、部署私有站点并轮询到成功。
7. 记录提交 SHA、站点版本和 URL；再在 Intune 试点组更新并逐步扩大。

版本位置：产品版本在 `release.json`；Agent 版本在 Python/Windows 报告；策略版本在策略和两份 Intune 合规 JSON；Collector/Adapter 在各自服务标识中。

回滚以 SYSTEM/root 下发脚本。快照必须恰好包含三项运行文件，恢复前后均验证哈希；失败时不重启周期任务。Collector 使用在线备份生成全新候选库，经 `quick_check` 与摘要验证后在审批窗口切换。

完整演进过程保存在 Git 提交历史和 `release.json` feature 列表中。
