#!/bin/bash
# Lab 主机一键 bootstrap：安装 docker + 拉起 Fleet/Wazuh/PacketFence 验证栈 + 输出对接信息。
# 在**全新 Ubuntu/Debian lab VM** 上以 root 运行：
#   curl -fsSL <raw-url>/lab-bootstrap.sh | bash     或   bash lab-bootstrap.sh
# 跑完会打印：三件服务端端点、Fleet enroll secret 获取方式、Wazuh/PacketFence 初始凭据位置、
# 以及 mac 客户端注册命令（mac-enroll.sh）。生产 VPS 不跑本脚本。
set -euo pipefail

echo "== [1/4] 安装 docker =="
if ! command -v docker >/dev/null; then
  curl -fsSL https://get.docker.com | bash
fi
systemctl enable --now docker

echo "== [2/4] 拉取验证栈 compose =="
WORK=/opt/aegis-validation
mkdir -p "$WORK"
# 从仓库取 compose（若已在仓库内运行则用本地文件）
if [ -f deploy/validation/docker-compose.validation.yml ]; then
  cp deploy/validation/docker-compose.validation.yml "$WORK/docker-compose.yml"
  cp deploy/validation/mac-enroll.sh "$WORK/mac-enroll.sh" 2>/dev/null || true
else
  echo "请在仓库根目录运行本脚本，或手动将 deploy/validation/docker-compose.validation.yml 放到 $WORK/docker-compose.yml"
fi

echo "== [3/4] 启动三件服务端（限容） =="
cd "$WORK"
docker compose -f docker-compose.yml up -d
sleep 20
docker compose ps

echo "== [4/4] 对接信息 =="
LAB_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "<lab-ip>")
cat <<EOF

── Fleet (MDM/osquery) ──
  API:  http://$LAB_IP:18080   (首次访问设置 admin)
  enroll secret: 登录 Fleet UI → Hosts → Add host → 复制 enroll secret
  mac 注册:  ./mac-enroll.sh fleet http://$LAB_IP:18080 <ENROLL_SECRET>

── Wazuh (EDR) ──
  API:  https://$LAB_IP:15500  (默认用户 wazuh-wui / 安装时生成; 或 API_USERNAME=aegis)
  mac agent: ./mac-enroll.sh wazuh $LAB_IP

── PacketFence (NAC) ──
  Portal/Admin: https://$LAB_IP:18443  (初始 admin 见容器日志: docker compose logs packetfence | grep -i password)
  REST API:     https://$LAB_IP:18443/api/v1  (token 在 Admin → Configuration → API)
  准入验证:    ./mac-enroll.sh packetfence https://$LAB_IP:18443
  注意: 真实 802.1X/Portal 准入需把 lab 接入办公网或模拟 VLAN; 纯云上仅验证 REST/节点契约。

── Aegis 适配器对接（在 Aegis 侧配置） ──
  vendor_mdm  -> fleet       base_url=http://$LAB_IP:18080  token_env=VENDOR_MDM_TOKEN
  vendor_edr  -> wazuh       base_url=https://$LAB_IP:15500 token_env=VENDOR_EDR_TOKEN
  vendor_nac  -> packetfence base_url=https://$LAB_IP:18443 token_env=VENDOR_NAC_TOKEN
EOF
echo "bootstrap done."
