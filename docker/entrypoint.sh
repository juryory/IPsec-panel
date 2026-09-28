#!/bin/bash
# 容器入口：启动并守护 charon，然后运行面板
set -euo pipefail

log() { echo "[entrypoint] $*"; }

# 选择与宿主机一致的 iptables 后端：宿主机用 legacy 时，写到 nft 的规则不会生效（反之亦然）
if command -v iptables-legacy >/dev/null 2>&1 && command -v iptables-nft >/dev/null 2>&1; then
  legacy=$(iptables-legacy-save 2>/dev/null | grep -c '^-' || true)
  nft=$(iptables-nft-save 2>/dev/null | grep -c '^-' || true)
  if [ "${legacy:-0}" -gt "${nft:-0}" ]; then
    update-alternatives --set iptables /usr/sbin/iptables-legacy >/dev/null 2>&1 || true
    log "iptables 后端: legacy"
  else
    update-alternatives --set iptables /usr/sbin/iptables-nft >/dev/null 2>&1 || true
    log "iptables 后端: nft"
  fi
fi

if [ "$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo 0)" != "1" ]; then
  sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || log "警告：无法开启 IP 转发，请在宿主机执行 sysctl -w net.ipv4.ip_forward=1"
fi

mkdir -p "${DATA_DIR:-/data}" /var/log/ipsec-panel /etc/swanctl/conf.d /etc/swanctl/x509 /etc/swanctl/x509ca /etc/swanctl/x509crl /etc/swanctl/private
chmod 700 /etc/swanctl/private

CHARON=""
for p in /usr/lib/ipsec/charon /usr/libexec/ipsec/charon /usr/libexec/strongswan/charon; do
  if [ -x "$p" ]; then CHARON="$p"; break; fi
done
if [ -z "$CHARON" ]; then
  log "找不到 charon 可执行文件"
  exit 1
fi

# 守护 charon：面板“重启 strongSwan”会 pkill charon，这里负责拉起
(
  while true; do
    rm -f /var/run/charon.pid /var/run/charon.vici
    log "启动 charon ($CHARON)"
    "$CHARON" || true
    log "charon 已退出，2 秒后重启"
    sleep 2
  done
) &

exec node /app/src/server.js
