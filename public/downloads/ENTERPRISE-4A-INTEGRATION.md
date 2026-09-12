# 企业 4A 标准接口接入指南

Aegis 核心不依赖 Intune、深信服或联软。终端报告先进入 Collector，只有服务端 Adapter Worker 可以向企业 4A 平台发送最小安全姿态事件。原有三类适配器默认关闭，可按需保留或移除配置。

## 4A 能力映射

- 账号（Account）：`subject.type=device` 与企业租户内的匿名设备主体关联；不传用户名、代码正文或本地路径。
- 认证（Authentication）：生产端点仅允许 HTTPS；服务凭据从 `AEGIS_4A_*` 环境变量读取，不进入配置、队列、日志或 Git。
- 授权（Authorization）：Aegis 只输出 `observe`、`alert`、`access_review_pending`、`containment_pending_approval`。所有影响访问的动作均标记 `external_approval_required`，由企业 4A 策略引擎审批执行。
- 审计（Audit）：`event_id` 作为 `audit.correlation_id`；HTTP `Idempotency-Key` 是规范化请求体的 SHA-256。接收端同时记录二者，前者串联审批/执行/回滚，后者用于精确请求去重。

## 接口约束

机器契约见 `aegis-enterprise-4a.openapi.json`。接收方实现 `POST /api/v1/security-events`，使用 Bearer 服务令牌认证并按 `Idempotency-Key` 去重；首次接收和重复接收都返回 2xx。载荷上限 2 MB，但正常事件远小于该值。

从 `aegis-adapters.example.json` 复制配置，替换精确 HTTPS 主机、租户标识和令牌变量名，只启用 `enterprise_4a`。令牌变量必须以 `AEGIS_4A_` 开头。先运行：

```bash
python3 aegis_adapter.py report.json --config adapters.json --dry-run
```

双方确认字段、脱敏和待审批语义后，在隔离测试端点验证重复请求、超时、非 2xx、凭据轮换和离线补发，再启用 Worker。接收端不得把 `*_pending*` 自动解释为封禁指令。

正式联调使用 `python3 aegis_4a_probe.py --config adapters.json --live`。探针会覆盖动作映射并强制发送两份完全相同的 `observe` 事件；两个请求都被 2xx 接受时，回执才将 `idempotent_replay_accepted` 标记为 true。标准输出不包含令牌、设备 ID 或事件正文。

## 演进建议

当前传输层采用预置 Bearer 服务令牌，适配绝大多数内部 API 网关。后续可在不改变事件 Schema 的前提下增加 OAuth 2.0 Client Credentials、mTLS、OIDC 工作负载身份或消息总线传输；身份获取应作为独立凭据提供器实现，不应把客户端密钥写入适配器 JSON。
