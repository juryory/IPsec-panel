#!/usr/bin/env bash
# 卸载 IPsec Panel（原生安装）
#   bash uninstall.sh          # 移除面板，保留数据库、证书和 strongSwan
#   bash uninstall.sh --purge  # 同时删除数据目录和配置（不可恢复）
# strongSwan 软件包本身不会被卸载。
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "请使用 root 运行"; exit 1; }

PURGE=0
[ "${1:-}" = "--purge" ] && PURGE=1

SWANCTL_DIR=/etc/swanctl
STRONGSWAN_D=/etc/strongswan.d
if [ -f /etc/ipsec-panel/panel.env ]; then
  set -a; . /etc/ipsec-panel/panel.env; set +a
fi
[ -d /etc/strongswan/swanctl ] && [ ! -d /etc/swanctl ] && SWANCTL_DIR=/etc/strongswan/swanctl
[ -d /etc/strongswan/strongswan.d ] && STRONGSWAN_D=/etc/strongswan/strongswan.d

echo "==> 停止面板"
systemctl disable --now ipsec-panel >/dev/null 2>&1 || true
rm -f /etc/systemd/system/ipsec-panel.service /usr/local/bin/ipsec-panel
systemctl daemon-reload

echo "==> 移除面板生成的 strongSwan 配置"
rm -f "$SWANCTL_DIR/conf.d/ipsec-panel.conf" \
      "$SWANCTL_DIR/x509/ipsec-panel-server.pem" \
      "$SWANCTL_DIR/private/ipsec-panel-server.pem" \
      "$SWANCTL_DIR/x509crl/ipsec-panel.crl" \
      "$SWANCTL_DIR"/x509ca/ipsec-panel-*.pem \
      "$STRONGSWAN_D/ipsec-panel.conf"
swanctl --load-all --noprompt >/dev/null 2>&1 || true

echo "==> 清理 iptables 规则和 Hub 地址"
del_chain() {
  local table=$1 parent=$2 chain=$3
  while iptables -w -t "$table" -D "$parent" -j "$chain" 2>/dev/null; do :; done
  iptables -w -t "$table" -F "$chain" 2>/dev/null || true
  iptables -w -t "$table" -X "$chain" 2>/dev/null || true
}
del_chain filter INPUT IPSP-IN
del_chain filter FORWARD IPSP-FWD
del_chain mangle FORWARD IPSP-MSS
del_chain nat POSTROUTING IPSP-POST
ip link del "${HUB_INTERFACE:-ipsp0}" 2>/dev/null || true

rm -rf /opt/ipsec-panel
rm -f /etc/sysctl.d/90-ipsec-panel.conf

if [ $PURGE = 1 ]; then
  echo "==> 删除数据与配置"
  rm -rf /var/lib/ipsec-panel /etc/ipsec-panel /var/log/ipsec-panel
else
  echo "数据保留在 /var/lib/ipsec-panel，配置保留在 /etc/ipsec-panel（重新安装后自动恢复）"
fi
echo "卸载完成。strongSwan 仍在运行，如不需要可自行卸载。"
