#!/bin/bash
# macOS 验证客户端安装（三开源候选）。pkg 由验证服务器下载后 scp 到 mac（mac 直连 packages.wazuh.com 会 403）。
# 用法（需 sudo，密码在你侧输入）:
#   ./mac-enroll.sh wazuh  /tmp/wazuh-agent.pkg <MANAGER_IP>
#   ./mac-enroll.sh fleet  /tmp/orbit.pkg
#   ./mac-enroll.sh packetfence <PF_PORTAL_URL>   # 仅办公网侧有意义
# 服务器侧准备 pkg:
#   wazuh:  curl -sL -o /tmp/wazuh-agent.pkg https://packages.wazuh.com/4.x/macos/wazuh-agent-<ver>-<rev>.pkg
#   fleet:  fleetctl package --type orbit --macos --fleet-url http://<LAB_IP>:18080 --enroll-secret <SECRET> --insecure  (产出 orbit.pkg)
# 仅用于验证；生产分发走桌管/MDM 推送 Aegis 单端，不推这些 agent。
set -euo pipefail
PRODUCT="${1:-}"; PKG="${2:-}"; EXTRA="${3:-}"

case "$PRODUCT" in
  wazuh)
    [ -f "$PKG" ] || { echo "pkg not found: $PKG (先在服务器下载再 scp)"; exit 2; }
    MGR="${EXTRA:-10.100.1.132}"
    sudo WAZUH_MANAGER="$MGR" installer -pkg "$PKG" -target /
    echo "wazuh agent installed -> manager $MGR"
    ;;
  fleet)
    [ -f "$PKG" ] || { echo "orbit pkg not found: $PKG (先在服务器 fleetctl package 生成再 scp)"; exit 2; }
    sudo installer -pkg "$PKG" -target /
    echo "orbit installed -> Fleet"
    ;;
  packetfence)
    echo "PacketFence 准入需办公网位置: 系统设置>网络 配 802.1X(EAP-TLS/PEAP) 指向 RADIUS, 或浏览器打开 ${EXTRA:-<PF_PORTAL_URL>} 做 Portal 注册"
    ;;
  *)
    echo "usage: $0 wazuh <pkg> [manager_ip] | fleet <orbit.pkg> | packetfence [portal_url]"; exit 2 ;;
esac
echo "done: $PRODUCT"
