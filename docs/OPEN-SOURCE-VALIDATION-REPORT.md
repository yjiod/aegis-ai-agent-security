# 开源候选验证报告（阶段 D）— 准入 / EDR / 桌管

> 验证宿主：10.100.1.132（x86_64 / 30GB / 与 tx.yjiod.com 同 easytier）
> 适配器：`public/downloads/aegis_4a_reference_adapters.py`（Fleet/Wazuh/PacketFence 三参考实现，均满足厂商中立 `FourAInterface`）
> 结论用途：定集成取舍；所有集成经 FourAInterface，厂商可替换、核心零改动。

## 一、验证结果总览

| 候选 | 角色 | 部署方式 | 适配器 e2e | 真实能力边界 |
|---|---|---|---|---|
| **Fleet** | 桌管/MDM + osquery telemetry | docker（mysql+redis+fleet，原生 amd64） | ✅ health/hosts/pack 下发/deploy 任务 | 软件分发、osquery 查询/标签、MDM（Apple）；策略下发=packs/profiles |
| **Wazuh** | EDR/SIEM | 原生 apt（wazuh-manager 4.14.7） | ✅ health/agents/active-response 转发/合规判定 | 资产 inventory、告警/规则、active-response；合规=cis/策略状态 |
| **PacketFence** | 准入 NAC | 契约 mock（arm/x86 均无官方可用镜像） | ✅ 节点列表/合规/状态回写+复读 | **真实准入（802.1X/Portal/VLAN 隔离）需办公网位置**，云上验不了 |

## 二、每家"能做什么 / 不能做什么"

### Fleet（建议：桌管/资产/telemetry 主选）
- 能：主机 inventory（osquery）、标签/pack 策略下发、Apple MDM、enroll secret 分发、API 完整（/api/latest/*）。
- 不能：不做网络准入；EDR 级进程/文件监控弱于 Wazuh；Linux/Windows MDM 有限（主要 Apple MDM + osquery 配置）。
- 集成点：`ASSET_INVENTORY / DEVICE_MANAGEMENT / POLICY_DISTRIBUTION / SOFTWARE_DISTRIBUTION`。

### Wazuh（建议：EDR/告警/响应主选）
- 能：agent 资产 inventory、规则告警、active-response（可挂 Aegis 事件触发隔离审批）、FIM/rootcheck、API（/agents、/active-response、/manager/info）。
- 不能：不做软件分发/MDM；不做网络准入；UI/索引需另装 indexer+dashboard（验证期仅 manager）。
- 集成点：`ASSET_INVENTORY / EVENT_FORWARDING / INCIDENT_RESPONSE / COMPLIANCE_CHECK`。

### PacketFence（建议：准入专用，办公网部署）
- 能：节点注册/状态、category/VLAN 隔离、802.1X/Portal、RADIUS/REST。
- 不能：云上/无网络位置时无意义；无官方 arm64/易用 docker 镜像；部署重（Perl+DB+网络服务）。
- 集成点：`ACCESS_CONTROL / DEVICE_IDENTITY / ASSET_INVENTORY`；Aegis 合规结论回写驱动隔离（report_compliance → node status/category）。

## 三、集成建议（厂商中立）
- 三家都只作为 **FourAInterface 适配器**接入；Aegis 核心不依赖任何厂商 SDK/接口。
- 现网商用（现网商用 EDR / 桌管 / MDM）与开源候选**地位对等**：换厂商=换适配器+改配置。
- 单端原则：员工终端只推 **Aegis 一个 agent**；Fleet/Wazuh/PacketFence 的 agent 由各自平台在**验证/服务端**使用，生产是否下发由桌管统一编排（Aegis 不代推）。

## 四、关键 ops 坑（已踩并记录）
- Fleet v4.91：setup 无 `--server-address/--org` flag；先 `fleetctl config set --address` 再 `fleetctl setup --org-name`；API 路径 `/api/latest/*`（非 /v1）；token 在 `/root/.fleet/config`(YAML)。
- Wazuh 4.14：登录=`POST /security/user/authenticate`；默认凭据明文种子在 `wazuh/rbac/default/users.yaml`（wazuh/wazuh、wazuh-wui/wazuh-wui）；1514 易被 docker-proxy 占用致 remoted/modulesd 起不来（`docker compose rm -f wazuh-manager` 释放后 systemd 重启）；rbac 改 admin 密码报 5011、factory-reset 需输入 "RESET"。
- 国内网络：Docker Hub 被墙（镜像源 hub.rat.dev/1panel/daocloud/aliyun；DaoCloud 有白名单）；packages.wazuh.com 在 mac 直连 403、服务器侧可下载（pkg 由服务器下载后 scp）。

## 五、mac 客户端验证步骤（sudo 在你侧）
1. 服务器备 pkg：wazuh `curl -sL -o /tmp/wazuh-agent.pkg https://packages.wazuh.com/4.x/macos/wazuh-agent-<ver>-<rev>.pkg`；fleet `fleetctl package --type orbit --macos --fleet-url http://10.100.1.132:18080 --enroll-secret <SECRET> --insecure`。
2. scp pkg 到 mac，mac 上：`./mac-enroll.sh wazuh /tmp/wazuh-agent.pkg 10.100.1.132` / `./mac-enroll.sh fleet /tmp/orbit.pkg`。
3. 验证：Wazuh `GET /agents` 出现本机；Fleet `list_devices` 出现本机。
4. PacketFence：办公网侧配 802.1X/Portal（见 mac-enroll.sh packetfence 分支）。
