#!/usr/bin/env bash
# Docker 方式一键部署：bash scripts/docker-install.sh [--cn]
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

command -v docker >/dev/null || { echo "请先安装 Docker：https://docs.docker.com/engine/install/"; exit 1; }
docker compose version >/dev/null 2>&1 || { echo "需要 Docker Compose v2（docker compose 命令）"; exit 1; }

ARGS=()
if [ "${1:-}" = "--cn" ]; then
  ARGS=(--build-arg APT_MIRROR=mirrors.aliyun.com --build-arg NPM_REGISTRY=https://registry.npmmirror.com)
fi

# 宿主机上如果已有 strongSwan / libreswan 在运行，会占用 UDP 500/4500
for svc in strongswan strongswan-starter ipsec; do
  if systemctl is-active --quiet "$svc" 2>/dev/null; then
    echo "[警告] 宿主机上的 $svc 正在运行，会与容器争用 UDP 500/4500，建议先 systemctl disable --now $svc"
  fi
done

sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true
echo 'net.ipv4.ip_forward = 1' > /etc/sysctl.d/90-ipsec-panel.conf 2>/dev/null || true

docker compose build ${ARGS[@]+"${ARGS[@]}"}
docker compose up -d

echo "等待面板启动..."
for _ in $(seq 1 30); do
  sleep 1
  [ -f data/initial-password.txt ] && break
  docker compose logs ipsec-panel 2>/dev/null | grep -q "IPsec Panel 已启动" && break
done
echo
echo "=================================================================="
echo " 面板地址: https://<服务器公网IP>:8443 （自签证书，浏览器提示不安全时选择继续访问）"
[ -f data/initial-password.txt ] && sed 's/^/  /' data/initial-password.txt
echo " 请在云服务器安全组放行 UDP 500、UDP 4500、TCP 8443"
echo " 查看日志: docker compose logs -f"
echo "=================================================================="
