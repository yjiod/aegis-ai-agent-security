#!/bin/bash
# macOS 验证客户端安装/注册（三开源候选）。用法:
#   ./mac-enroll.sh fleet     <FLEET_URL> <ENROLL_SECRET>
#   ./mac-enroll.sh wazuh     <WAZUH_MANAGER_IP>
#   ./mac-enroll.sh packetfence <PF_PORTAL_URL>
# 仅用于验证；生产分发走桌管/MDM 推送 Aegis 单端，不推这些 agent。
set -euo pipefail
PRODUCT="${1:-}"; shift || true

case "$PRODUCT" in
  fleet)
    URL="${1:?fleet url}"; SECRET="${2:?enroll secret}"
    echo "== 安装 osquery (brew) 并注册到 Fleet =="
    brew install --cask osquery 2>/dev/null || brew install osquery
    # orbit/osquery 以 enroll secret 注册；验证用 tls 端点
    sudo osqueryctl --version || true
    echo "osquery 已安装。用 fleetctl 或 Fleet UI 以 secret 注册:"
    echo "  fleetctl package --type pkg --fleet-url=$URL --enroll-secret=$SECRET  # 生成 pkg 后安装"
    ;;
  wazuh)
    MGR="${1:?wazuh manager ip}"
    echo "== 安装 Wazuh agent (macOS pkg) 并指向 manager =="
    curl -so /tmp/wazuh-agent.pkg "https://packages.wazuh.com/4.x/macos/wazuh-agent-4.9.0-1.pkg" || { echo "请下载官方 pkg"; exit 1; }
    sudo installer -pkg /tmp/wazuh-agent.pkg -target /
    sudo /Library/Ossec/bin/manage_agents -a || true
    echo "WAZUH_MANAGER=$MGR" | sudo tee -a /Library/Ossec/etc/preloaded-vars.conf
    sudo /Library/Ossec/bin/wazuh-control restart
    ;;
  packetfence)
    PORTAL="${1:?pf portal url}"
    echo "== PacketFence 准入验证: 配置 802.1X supplicant / 或 Portal 注册 =="
    echo "有线/无线 802.1X: 在 系统设置>网络>802.1X 配置 EAP-TLS/PEAP, 指向 RADIUS=$PORTAL"
    echo "或 Portal 注册: 浏览器打开 $PORTAL 完成设备注册(验证节点状态回写)"
    ;;
  *)
    echo "usage: $0 fleet|wazuh|packetfence [args]"; exit 2 ;;
esac
echo "done: $PRODUCT"
