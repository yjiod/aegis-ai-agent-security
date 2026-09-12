# 厂商适配器集成指南

> **厂商中立说明**：本文一律使用通用代称（厂商 EDR / 厂商桌管 / `vendor_edr` / `vendor_mdm`），
> 不指向任何具体商用或开源产品，避免在公开仓库暴露现网安全栈。这些是**适配器角色**，
> 经厂商中立契约 `aegis_4a_interface.py`（FourAInterface）绑定；每个部署在本地配置中
> 把角色映射到自家实际产品（商用或开源均可），替换产品无需改核心代码。

## 架构概览

```
终端 Agent → Collector (验证+存储) → Adapter Worker (派发) → 厂商 API
                                          ├─ 厂商 EDR (事件响应)
                                          ├─ 厂商桌管 (合规姿态)
                                          └─ Security Webhook (通用 SOC)
```

Adapter Worker 从 Collector 的已验证报告生成最小厂商事件，以派发账本、稳定幂等键和有界失败队列连接各目标。各厂商相互隔离，单目标故障不影响其他。

## 厂商 EDR 接口契约

### 现网版本 (2026-09-06 确认)

| 项目 | 值 |
|------|-----|
| 软件版本 | **6.0.2.18163.1R4** |
| 病毒库 | 20260522182136 |
| 漏洞规则库 | 20260514204011 |
| SAVE 模型库 | 20260324104142 |
| 防勒索规则库 | 20260516181214 |
| IOC 规则库 | 1.124536 |
| 已安装补丁 | TD-2024081300348-54105 (2025-08-12) |

### 6.x 系列 API 适配要点

厂商 EDR 6.x 与 5.x 的主要差异：

1. **API 基础路径**：6.x 使用 `/api/edr/open/v1/` 前缀（5.x 为 `/api/edr/v1/`）
2. **鉴权方式**：6.x 支持 `Authorization: Bearer <token>` 和 HMAC 签名双模式；
   推荐使用 Bearer token（需在管理面「系统管理 → API 接口」中申请）
3. **事件上报端点**：`POST /api/edr/open/v1/event/custom`（自定义安全事件）
4. **设备查询端点**：`GET /api/edr/open/v1/device/list`（用于 device_id 关联验证）
5. **响应处置端点**：`POST /api/edr/open/v1/response/isolate`（隔离，需审批权限）
6. **速率限制**：6.x 默认 100 req/min/token，超限返回 429
7. **TLS 要求**：管理面强制 TLS 1.2+，自签证书需配置 CA bundle

### 接入前仍需确认

- [ ] 管理面 HTTPS 地址（如 `https://edr.internal.example.com:8443`）
- [ ] API Token（在管理面「系统管理 → API 接口管理」中创建服务账号）
- [ ] 是否启用了 API 白名单 IP 限制
- [ ] 隔离/阻断操作是否需要二级审批（影响 `recommended_action` 映射）
- [ ] 管理面是否使用自签证书（需配置 `SSL_CERT_FILE` 环境变量）

### Aegis 请求格式 (兼容 6.x)

```
POST https://{edr-host}/api/edr/open/v1/event/custom
Authorization: Bearer {VENDOR_EDR_TOKEN}
Content-Type: application/json

{
  "event_type": "ai_agent_security_finding",
  "source": "aegis",
  "device_id": "ENG-MBP-1032",
  "severity": "critical|high|medium|low|normal",
  "recommended_action": "observe|alert|isolate_pending_approval|block_pending_approval",
  "finding_count": 3,
  "policy_version": "4.8.0",
  "occurred_at": 1725600000
}
```

### 响应 (期望)

```json
{"accepted": true, "event_id": "edr-xxx", "action_taken": "logged|isolated|blocked"}
```

### 严重度→动作映射 (可配置)

| 严重度 | 默认动作 | 说明 |
|--------|----------|------|
| critical | isolate_pending_approval | 需审批后隔离 |
| high | alert | 告警通知安全管理员 |
| medium | observe | 仅记录观察 |
| low | observe | 仅记录 |
| normal | observe | 无需动作 |

### 接入步骤

1. 向厂商 EDR 管理员申请服务账号 + API Token
2. 确认现网 EDR 版本号（不同版本 API 路径可能不同）
3. 确认 EDR 管理面 HTTPS 地址，加入 `allowed_hosts`
4. 设置环境变量 `VENDOR_EDR_TOKEN=<实际token>`
5. 修改 `aegis-adapters.json` 中 `vendor_edr.enabled: true`
6. 先用 `--dry-run` 验证配置，再正式启用

## 厂商桌管接口契约

### 请求

```
POST https://{vendor_mdm-host}/api/aegis/posture
Authorization: Bearer {VENDOR_MDM_TOKEN}
Content-Type: application/json

{
  "source": "aegis",
  "device_id": "ENG-MBP-1032",
  "compliant": true|false,
  "risk_level": "critical|high|medium|low|normal",
  "policy_version": "4.8.0",
  "last_scan": 1725600000,
  "reason": "policy_pass|critical_or_high_finding"
}
```

### 响应 (期望)

```json
{"accepted": true, "compliance_updated": true}
```

### 合规判定逻辑

- `risk_level` 为 critical 或 high → `compliant: false`, `reason: "critical_or_high_finding"`
- 其他 → `compliant: true`, `reason: "policy_pass"`

### 接入步骤

1. 向厂商桌管管理员申请 API 服务账号
2. 确认厂商桌管控制台 版本及 API 端点路径
3. 确认 HTTPS 地址，加入 `allowed_hosts`
4. 设置环境变量 `VENDOR_MDM_TOKEN=<实际token>`
5. 修改 `aegis-adapters.json` 中 `vendor_mdm.enabled: true`
6. 配置 `compliance.max_policy_age_hours` (默认 24h)

## Security Webhook (通用 SOC)

转发完整报告到任意 HTTPS Webhook 端点（SIEM/SOAR/企微/钉钉/飞书）。

```
POST https://{soc-host}/hooks/aegis
Authorization: Bearer {AEGIS_WEBHOOK_SECRET}
Content-Type: application/json

{完整 aegis.report/v1 报告体}
```

## 本地 Mock 测试

无需真实厂商凭据即可测试完整适配器管道：

```bash
# 1. 启动 mock 厂商服务器
python3 scripts/mock-vendor-server.py --port 9443 --write-env

# 2. 加载 mock 凭据
source .dev/vendor.env

# 3. 启动 Collector
scripts/dev-collector.sh

# 4. 配置适配器指向 mock (修改 aegis-adapters.json)
#    allowed_hosts: ["127.0.0.1"]
#    vendor_edr.url: "http://127.0.0.1:9443/api/aegis/events"
#    vendor_mdm.url: "http://127.0.0.1:9443/api/aegis/posture"
#    注意: 本地测试需设置 AEGIS_ADAPTER_ALLOW_HTTP=1

# 5. 运行 Adapter Worker
python3 public/downloads/aegis_adapter_worker.py \
  --config aegis-adapters.json \
  --collector-url http://127.0.0.1:8931 \
  --dry-run

# 6. 查看 mock 服务器收到的事件
curl http://127.0.0.1:9443/events | python3 -m json.tool
```

## 安全边界

- 终端永不直连 EDR/桌管管理面
- Adapter 只允许精确 HTTPS 主机（`allowed_hosts` 白名单）
- 凭据通过环境变量注入，不写入配置文件或 Git
- 所有动作限于 `SAFE_ACTIONS` 集合，无直接隔离/阻断权限
- 派发账本保证幂等，有界失败队列防止无限重试
- 各厂商目标相互隔离，单目标超时/失败不阻塞其他

## 生产部署检查清单

- [ ] 厂商 EDR 正式 API 路径、鉴权方式已确认
- [ ] 厂商桌管正式 API 端点、服务账号已申请
- [ ] `allowed_hosts` 仅包含正式管理面域名
- [ ] 环境变量通过 商用 MDM/Secret Manager 注入，非明文
- [ ] Adapter Worker 以 systemd service 运行（见 aegis-adapter-worker.service）
- [ ] 派发账本目录权限 700，定期备份
- [ ] 监控：Adapter 健康检查 + 失败队列深度告警
- [ ] 回滚：禁用适配器只需设 enabled: false，不影响 Collector
