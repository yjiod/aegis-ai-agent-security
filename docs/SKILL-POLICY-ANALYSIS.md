# Skill 策略分析（unknown_skill 细化）

基于终端 51 个 unknown_skill 发现，对 50 个 distinct Skill 做风险信号扫描
（exec/subprocess/eval、network curl/fetch/http、credential api_key/secret/token、filewrite rm/unlink），
按 score 分级：score>=4 = deny（高危），2-3 = monitor（中危），<2 = allow（低危/可加白）。

## 分级结果
- allow (低危, 建议加白): 12 个
- monitor (中危, 保持告警观察): 28 个
- deny (高危, 保持 high 告警/考虑禁用): 10 个

## ALLOW（建议加入 allowed_skills 白名单，消除误报）
- claude-dev-suite-java-quality
- dingtalk-aisearch
- fwrite0920-project-bootstrapping
- l-mb-py-modernize
- majesticlabs-dev-python-debugger
- majiayu000-deeplearningcoder
- majiayu000-fix-markdown-lint
- majiayu000-frontend-code-quality
- michaelboeding-feature-council
- mini-program-dev
- godot-headless-game-pipeline
- handwritten-form-to-excel

## MONITOR（保持 medium 告警，人工研判后决定加白或禁用）
- ai-dev-tools
- aiskillstore-create-adaptable-composable
- aiskillstore-java-pro
- b33eep-standards-javascript
- create-skill
- diegosouzapw-database-expert-advisor-majiayu000
- diegosouzapw-enterprise-python-majiayu000
- diegosouzapw-web-app-testing
- dingtalk-chat
- dingtalk-contact
- dingtalk-doc
- dingtalk-drive
- dingtalk-event
- dingtalk-mail
- dingtalk-shared
- dingtalk-todo
- dingtalk-wiki
- find-skills
- html-markdown
- majiayu000-intelligent-debugger
- majiayu000-java-concurrency
- media-generation
- plugin-creator
- qw-pages
- qw-pages-supabase
- qwenwork-guidance
- harmonyos-headless-hap-pipeline
- xrmesh-device-ops

## DENY（high 告警；含 exec+cred+filewrite 组合，建议禁用或严格审批）
- aiskillstore-working-with-documents
- diegosouzapw-python-testing-andyhsutw
- dingtalk-aitable
- dingtalk-calendar
- dingtalk-minutes
- dingtalk-misc
- docx
- pdf
- pptx
- xlsx

## 细化告警规则（已实现于 aegis_agent.skill_risk_score）
- unknown_skill 严重度不再统一 high/medium，按风险信号 score 分级：
  score>=4 → high；2-3 → medium；<2 → low
- 告警消息附带主导风险信号（exec/cred/network/filewrite）与 score，便于研判
- 加白后（allowed_skills）不再产生 unknown_skill 告警

## 建议操作
1. 将 ALLOW 列表加入 aegis-policy.json 的 allowed_skills（消除 13 个低危误报）
2. MONITOR 保持告警，安全运营逐个研判（钉钉类 skill 多为 exec+cred，属正常 CLI 调用，可酌情加白）
3. DENY 中 pdf/pptx/xlsx/docx 为文档处理 skill（exec+net+cred+fw 高），若业务必需则加白并监控；否则禁用

---

## 六、monitor 类分类 + 标签 + 预制规则（不批量加白）

monitor 类不做批量加白，而是**按类别打标签 + 预制规则**，逐类研判：

| 类别 | 标签 | 数量 | 预制规则（action/severity） | 成员示例 |
|---|---|---|---|---|
| 钉钉 CLI 集成类 | cli, network, credential-pass | 9 | monitor / medium；记录每次调用审计；只读子能力个案加白，写操作保持告警 | dingtalk-chat/doc/mail/calendar |
| 文档处理类 | filewrite, network-deps | 1 | monitor / medium；锁版本 + 监控文件写范围；业务必需加白+监控 | html-markdown |
| 云服务/平台类 | network, cloud-api | 3 | monitor / medium；监控外联域名白名单 | qw-pages, media-generation |
| 开发辅助/方法论类 | read-mostly | 15 | monitor / low；研判后可批量加白 | *-debugger, *-testing, standards-* |

告警消息现在带 `[类别:xxx]` 标签 + 该类别预制规则说明，运营按类别批量研判而非逐个。
类别判定在 aegis_agent.skill_category()，预制规则在 SKILL_CATEGORY_RULES。
