FROM node:22-bookworm-slim

# 国内构建可传入镜像源：
#   docker compose build --build-arg APT_MIRROR=mirrors.aliyun.com --build-arg NPM_REGISTRY=https://registry.npmmirror.com
ARG APT_MIRROR=
ARG NPM_REGISTRY=

RUN set -eux; \
    if [ -n "$APT_MIRROR" ]; then sed -i "s|deb.debian.org|$APT_MIRROR|g" /etc/apt/sources.list.d/debian.sources; fi; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
      strongswan-charon strongswan-swanctl \
      libcharon-extauth-plugins libcharon-extra-plugins \
      libstrongswan-standard-plugins libstrongswan-extra-plugins \
      iptables iproute2 openssl procps ca-certificates; \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY package.json package-lock.json ./
RUN set -eux; \
    if [ -n "$NPM_REGISTRY" ]; then npm config set registry "$NPM_REGISTRY"; fi; \
    npm ci --omit=dev; \
    npm cache clean --force

COPY src ./src
COPY public ./public
COPY deploy/strongswan-panel.conf /etc/strongswan.d/ipsec-panel.conf
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENV DATA_DIR=/data \
    SWANCTL_DIR=/etc/swanctl \
    VICI_SOCKET=/var/run/charon.vici \
    CHARON_LOG=/var/log/ipsec-panel/charon.log \
    STRONGSWAN_RESTART_CMD="pkill -x charon" \
    PANEL_HOST=0.0.0.0 \
    PANEL_PORT=8443 \
    PANEL_TLS=auto \
    NODE_ENV=production

VOLUME ["/data"]
ENTRYPOINT ["/entrypoint.sh"]
