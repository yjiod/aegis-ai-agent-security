# 企业统一身份与 4A 厂商中立契约

Sentinel 不假设“4A”是一套固定产品。企业可以把认证、账号、授权、审计、准入、桌管和安全响应组合在一个平台，也可以由多个系统共同提供。

## 能力而非厂商

所有接入先声明 `sentinel.integration/v1` 能力：

- `identity.authentication`：统一身份认证、OIDC/SAML/企业 SSO。
- `identity.resolution`：把企业主体映射到稳定人员或服务身份。
- `authorization.decision`、`authorization.access_review`：授权判定和访问复核。
- `audit.accounting`：不可抵赖审计或计费记录。
- `device.posture`：接收终端安全姿态。
- `device.policy_distribution`、`device.software_distribution`：策略和客户端分发。
- `security.incident_notification`、`security.containment_request`：安全事件与待审批处置。

核心系统只依赖能力集合和标准事件，不导入厂商 SDK、URL、字段名或认证方式。统一身份可以使用 OIDC/SAML；4A 可以是商用产品、自建平台、API 网关或多个适配器的组合。

## 强制边界

1. 影响账号、访问或终端状态的能力必须声明 `approval_enforced=true`；适配器只能提交待审批建议，不能绕过企业授权系统直接封禁或隔离。
2. Windows/macOS 上只新增 Sentinel Endpoint Agent。MDM、桌管或软件分发系统负责安装与升级；EDR、NAC、4A 均在服务端通过适配器协作。
3. 终端强制加载安全编码基线，不能通过“快速扫描”或用户设置关闭关键规则。
4. Skill/MCP 使用 `allow / monitor / deny / unknown` 四态。`deny` 优先级最高；未知项按企业策略失败关闭。
5. MCP 除名称外还支持规范化配置 SHA-256 指纹拉黑，防止同名或重命名绕过。

## 适配器准入

适配器必须通过：精确 HTTPS 主机、凭据不入 URL、最小事件、幂等、超时/重试、敏感字段最小化、审批边界、审计关联、失效关闭和回滚测试。缺少所需能力时由核心拒绝启用，而不是猜测产品行为。

生产服务器使用 `sentinel_integration_registry.py` 校验 `/etc/sentinel/integration-providers.json`。适配器服务通过 `sentinel-integration-registry.conf` 在启动前执行校验；注册表格式错误、端点不安全、能力未知或特权能力未声明审批时，适配器不得启动。
