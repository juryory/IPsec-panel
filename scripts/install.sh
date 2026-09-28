#!/usr/bin/env bash
# IPsec Panel 原生（Node.js）一键安装 / 升级脚本
# 支持：Debian 11+ / Ubuntu 20.04+ / CentOS Stream / Rocky / AlmaLinux 8+
#
# 用法：
#   bash scripts/install.sh                 # 默认：面板监听 0.0.0.0:8443，自签 HTTPS
#   bash scripts/install.sh --cn            # 使用国内镜像下载 Node.js 和 npm 依赖
#   bash scripts/install.sh --behind-proxy  # 面板只监听 127.0.0.1:8088（HTTP），由 Nginx/宝塔反代
#   bash scripts/install.sh --port 9443
#   bash scripts/install.sh --no-service    # 只安装 strongSwan 和系统设置，面板由宝塔 Node 项目等自行运行
# 重复执行即为升级，数据和配置会保留。
set -euo pipefail

INSTALL_DIR=/opt/ipsec-panel
DATA_DIR=/var/lib/ipsec-panel
ETC_DIR=/etc/ipsec-panel
ENV_FILE=$ETC_DIR/panel.env
LOG_DIR=/var/log/ipsec-panel
REPO_URL=${REPO_URL:-https://github.com/juryory/IPsec-panel.git}
NODE_MAJOR=${NODE_MAJOR:-22}
NODE_MIRROR=${NODE_MIRROR:-https://nodejs.org/dist}
NPM_REGISTRY=${NPM_REGISTRY:-}
PANEL_HOST=0.0.0.0
PANEL_PORT=8443
PANEL_TLS=auto
TRUST_PROXY=0
NO_SERVICE=0

c_green='\033[32m'; c_yellow='\033[33m'; c_red='\033[31m'; c_off='\033[0m'
info() { echo -e "${c_green}==>${c_off} $*"; }
warn() { echo -e "${c_yellow}[警告]${c_off} $*"; }
die() { echo -e "${c_red}[错误]${c_off} $*" >&2; exit 1; }

PORT_SET=0
while [ $# -gt 0 ]; do
  case "$1" in
    --cn) NODE_MIRROR=https://npmmirror.com/mirrors/node; NPM_REGISTRY=https://registry.npmmirror.com ;;
    --behind-proxy) PANEL_HOST=127.0.0.1; PANEL_TLS=off; TRUST_PROXY=1; [ $PORT_SET = 1 ] || PANEL_PORT=8088 ;;
    --port) PANEL_PORT="$2"; PORT_SET=1; shift ;;
    --host) PANEL_HOST="$2"; shift ;;
    --no-service) NO_SERVICE=1; PANEL_HOST=127.0.0.1; PANEL_TLS=off; TRUST_PROXY=1; [ $PORT_SET = 1 ] || PANEL_PORT=8088 ;;
    -h|--help) sed -n '2,13p' "$0"; exit 0 ;;
    *) die "未知参数: $1" ;;
  esac
  shift
done

[ "$(id -u)" = 0 ] || die "请使用 root 运行"
[ -r /etc/os-release ] || die "无法识别操作系统"
. /etc/os-release
OS_FAMILY=""
case " ${ID} ${ID_LIKE:-} " in
  *" debian "*|*" ubuntu "*) OS_FAMILY=debian ;;
  *" rhel "*|*" centos "*|*" fedora "*|*" rocky "*|*" almalinux "*) OS_FAMILY=rhel ;;
  *) die "暂不支持的系统: ${PRETTY_NAME:-$ID}" ;;
esac
info "系统: ${PRETTY_NAME:-$ID}"

# ---------------------------------------------------------------- strongSwan
if [ "$OS_FAMILY" = debian ]; then
  export DEBIAN_FRONTEND=noninteractive
  info "安装 strongSwan（swanctl / charon-systemd）"
  apt-get update -y
  apt-get install -y --no-install-recommends curl ca-certificates xz-utils tar git openssl iptables iproute2 \
    charon-systemd strongswan-swanctl
  for p in libcharon-extauth-plugins libcharon-extra-plugins libstrongswan-standard-plugins libstrongswan-extra-plugins; do
    if apt-cache show "$p" >/dev/null 2>&1; then apt-get install -y --no-install-recommends "$p"; fi
  done
  SWANCTL_DIR=/etc/swanctl
  STRONGSWAN_D=/etc/strongswan.d
else
  info "安装 strongSwan（EPEL）"
  if ! rpm -q epel-release >/dev/null 2>&1; then
    dnf install -y epel-release || yum install -y epel-release
  fi
  (dnf install -y strongswan openssl iptables iproute curl tar xz git) || (yum install -y strongswan openssl iptables iproute curl tar xz git)
  SWANCTL_DIR=/etc/strongswan/swanctl
  STRONGSWAN_D=/etc/strongswan/strongswan.d
fi
command -v swanctl >/dev/null || die "未找到 swanctl，strongSwan 安装失败"

# charon-systemd 对应的服务名（新版本为 strongswan，老版本为 strongswan-swanctl）
SS_SERVICE=strongswan
if ! systemctl list-unit-files 2>/dev/null | grep -q '^strongswan.service'; then
  if systemctl list-unit-files 2>/dev/null | grep -q '^strongswan-swanctl.service'; then SS_SERVICE=strongswan-swanctl; fi
fi
# 老的 ipsec.conf 方式（starter）会与 swanctl 抢端口，停掉
for legacy in strongswan-starter ipsec; do
  if systemctl list-unit-files 2>/dev/null | grep -q "^${legacy}.service" && [ "$legacy" != "$SS_SERVICE" ]; then
    systemctl disable --now "$legacy" >/dev/null 2>&1 || true
  fi
done

mkdir -p "$STRONGSWAN_D" "$LOG_DIR" "$SWANCTL_DIR"/{conf.d,x509,x509ca,x509crl,private}
chmod 700 "$SWANCTL_DIR/private"
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." 2>/dev/null && pwd || true)"

# ---------------------------------------------------------------- 源码
if [ -n "$SRC_DIR" ] && [ -f "$SRC_DIR/src/server.js" ] && [ -f "$SRC_DIR/deploy/ipsec-panel.service" ]; then
  info "使用本地源码: $SRC_DIR"
else
  SRC_DIR=$(mktemp -d)
  info "从 $REPO_URL 下载源码"
  git clone --depth 1 "$REPO_URL" "$SRC_DIR"
fi

install -m 644 "$SRC_DIR/deploy/strongswan-panel.conf" "$STRONGSWAN_D/ipsec-panel.conf"
SWANCTL_CONF="$SWANCTL_DIR/swanctl.conf"
if [ ! -f "$SWANCTL_CONF" ]; then
  echo 'include conf.d/*.conf' > "$SWANCTL_CONF"
elif ! grep -Eq '^[[:space:]]*include[[:space:]]+conf\.d/\*\.conf' "$SWANCTL_CONF"; then
  echo 'include conf.d/*.conf' >> "$SWANCTL_CONF"
fi

# ---------------------------------------------------------------- 系统设置（函数）
setup_system() {
  cat > /etc/sysctl.d/90-ipsec-panel.conf <<EOF
net.ipv4.ip_forward = 1
EOF
  sysctl -p /etc/sysctl.d/90-ipsec-panel.conf >/dev/null || true

  if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
    info "放行 ufw 端口"
    ufw allow 500/udp >/dev/null; ufw allow 4500/udp >/dev/null
    [ "$PANEL_HOST" = 127.0.0.1 ] || ufw allow "$PANEL_PORT/tcp" >/dev/null
  fi
  if command -v firewall-cmd >/dev/null && firewall-cmd --state >/dev/null 2>&1; then
    info "放行 firewalld 端口"
    firewall-cmd --permanent --add-service=ipsec >/dev/null
    [ "$PANEL_HOST" = 127.0.0.1 ] || firewall-cmd --permanent --add-port="$PANEL_PORT/tcp" >/dev/null
    firewall-cmd --reload >/dev/null
    warn "firewalld 可能拦截转发流量，如站点之间或用户到站点不通，可执行：firewall-cmd --permanent --zone=trusted --add-source=<隧道网段与各站点网段> && firewall-cmd --reload"
  fi

  info "启动 strongSwan（$SS_SERVICE）"
  systemctl daemon-reload
  systemctl enable "$SS_SERVICE" >/dev/null 2>&1 || true
  systemctl restart "$SS_SERVICE"
}

# ---------------------------------------------------------------- 仅系统环境（宝塔 Node 项目等）
if [ $NO_SERVICE = 1 ]; then
  setup_system
  # 之前用 systemd 方式装过的面板要停掉，避免两个面板同时管理 strongSwan、抢端口
  if systemctl list-unit-files 2>/dev/null | grep -q '^ipsec-panel.service'; then
    info "停用 systemd 方式运行的面板（数据保留）"
    systemctl disable --now ipsec-panel >/dev/null 2>&1 || true
    rm -f /etc/systemd/system/ipsec-panel.service
    systemctl daemon-reload
  fi
  mkdir -p "$DATA_DIR"; chmod 700 "$DATA_DIR"
  if [ ! -f "$SRC_DIR/.env" ]; then
    cat > "$SRC_DIR/.env" <<EOF
# IPsec Panel 运行配置（宝塔 Node 项目会读取此文件，修改后在宝塔中重启项目）
PANEL_HOST=$PANEL_HOST
PANEL_PORT=$PANEL_PORT
PANEL_TLS=$PANEL_TLS
TRUST_PROXY=$TRUST_PROXY
DATA_DIR=$DATA_DIR
SWANCTL_DIR=$SWANCTL_DIR
VICI_SOCKET=/var/run/charon.vici
STRONGSWAN_RESTART_CMD="systemctl restart $SS_SERVICE"
JOURNAL_UNIT=$SS_SERVICE
CHARON_LOG=$LOG_DIR/charon.log
POLL_INTERVAL=30
EOF
    chmod 600 "$SRC_DIR/.env"
    info "已生成 $SRC_DIR/.env"
  else
    info "保留已有 $SRC_DIR/.env"
  fi
  NODE_CMD="$(command -v node || echo node)"
  cat > /usr/local/bin/ipsec-panel <<EOF
#!/usr/bin/env bash
# IPsec Panel 命令行：ipsec-panel status | reload | reset-password [密码]
exec $NODE_CMD $SRC_DIR/src/cli.js "\$@"
EOF
  chmod 755 /usr/local/bin/ipsec-panel
  echo
  echo "=================================================================="
  echo " strongSwan 与系统环境已就绪，接下来在宝塔中添加 Node 项目："
  echo "   项目目录:  $SRC_DIR"
  echo "   启动选项:  npm run start（或启动文件 src/server.js）"
  echo "   项目端口:  $PANEL_PORT"
  echo "   运行用户:  root   ← 必须是 root"
  echo "   Node 版本: 22.13 及以上"
  echo "   然后绑定域名、开启 SSL，宝塔会自动反代到 127.0.0.1:$PANEL_PORT"
  echo
  echo " 首次启动后的管理员密码：cat $DATA_DIR/initial-password.txt"
  echo " 还需要：在云服务器安全组和宝塔安全中放行 UDP 500、UDP 4500"
  echo "=================================================================="
  exit 0
fi

# ---------------------------------------------------------------- Node.js
node_ok() {
  local bin="$1"
  [ -x "$bin" ] || return 1
  "$bin" -e 'const [a,b]=process.versions.node.split(".").map(Number);process.exit(a>22||(a===22&&b>=13)?0:1)' 2>/dev/null
}
NODE_BIN=""
if command -v node >/dev/null && node_ok "$(command -v node)"; then
  NODE_BIN="$(command -v node)"
  info "使用系统 Node.js $($NODE_BIN -v)"
elif node_ok "$INSTALL_DIR/runtime/bin/node"; then
  NODE_BIN="$INSTALL_DIR/runtime/bin/node"
  info "使用已安装的 Node.js $($NODE_BIN -v)"
else
  case "$(uname -m)" in
    x86_64) NARCH=x64 ;;
    aarch64|arm64) NARCH=arm64 ;;
    *) die "不支持的架构 $(uname -m)" ;;
  esac
  info "下载 Node.js ${NODE_MAJOR}.x（$NODE_MIRROR）"
  SUMS=$(curl -fsSL "$NODE_MIRROR/latest-v${NODE_MAJOR}.x/SHASUMS256.txt")
  FILE=$(echo "$SUMS" | awk '{print $2}' | grep -E "^node-v[0-9.]+-linux-${NARCH}\.tar\.xz$" | head -1)
  [ -n "$FILE" ] || die "无法获取 Node.js 版本列表"
  SUM=$(echo "$SUMS" | awk -v f="$FILE" '$2==f{print $1}')
  TMP=$(mktemp -d)
  curl -fL --progress-bar "$NODE_MIRROR/latest-v${NODE_MAJOR}.x/$FILE" -o "$TMP/$FILE"
  echo "$SUM  $TMP/$FILE" | sha256sum -c - >/dev/null || die "Node.js 校验失败"
  rm -rf "$INSTALL_DIR/runtime"
  mkdir -p "$INSTALL_DIR/runtime"
  tar -xJf "$TMP/$FILE" -C "$INSTALL_DIR/runtime" --strip-components=1
  rm -rf "$TMP"
  NODE_BIN="$INSTALL_DIR/runtime/bin/node"
  info "Node.js $($NODE_BIN -v) 已安装到 $INSTALL_DIR/runtime"
fi
NPM_BIN="$(dirname "$NODE_BIN")/npm"
[ -x "$NPM_BIN" ] || NPM_BIN="$(command -v npm || true)"
[ -n "$NPM_BIN" ] || die "未找到 npm"

# ---------------------------------------------------------------- 安装面板
info "安装面板到 $INSTALL_DIR"
mkdir -p "$INSTALL_DIR"
if [ "$SRC_DIR" != "$INSTALL_DIR" ]; then
  rm -rf "$INSTALL_DIR/src" "$INSTALL_DIR/public"
  cp -r "$SRC_DIR/src" "$SRC_DIR/public" "$SRC_DIR/deploy" "$SRC_DIR/scripts" "$INSTALL_DIR/"
  cp "$SRC_DIR/package.json" "$SRC_DIR/package-lock.json" "$INSTALL_DIR/"
fi
(
  cd "$INSTALL_DIR"
  export PATH="$(dirname "$NODE_BIN"):$PATH"
  REG=()
  [ -n "$NPM_REGISTRY" ] && REG=(--registry "$NPM_REGISTRY")
  "$NPM_BIN" ci --omit=dev --no-audit --no-fund ${REG[@]+"${REG[@]}"}
)

mkdir -p "$ETC_DIR" "$DATA_DIR"
chmod 700 "$ETC_DIR" "$DATA_DIR"
if [ ! -f "$ENV_FILE" ]; then
  cat > "$ENV_FILE" <<EOF
# IPsec Panel 运行配置（修改后 systemctl restart ipsec-panel）
PANEL_HOST=$PANEL_HOST
PANEL_PORT=$PANEL_PORT
# off | auto(自签 HTTPS) | custom(配合 PANEL_TLS_CERT / PANEL_TLS_KEY)
PANEL_TLS=$PANEL_TLS
TRUST_PROXY=$TRUST_PROXY
DATA_DIR=$DATA_DIR
SWANCTL_DIR=$SWANCTL_DIR
VICI_SOCKET=/var/run/charon.vici
STRONGSWAN_RESTART_CMD="systemctl restart $SS_SERVICE"
JOURNAL_UNIT=$SS_SERVICE
CHARON_LOG=$LOG_DIR/charon.log
POLL_INTERVAL=30
EOF
  chmod 600 "$ENV_FILE"
else
  # 修复旧版本写入的未加引号的值（bash source 时会把空格后的内容当成命令）
  sed -i -E 's/^(STRONGSWAN_RESTART_CMD)=([^"].* .*)$/\1="\2"/' "$ENV_FILE"
  info "保留已有配置 $ENV_FILE（--port/--behind-proxy 等参数只在首次安装时生效，如需修改请编辑该文件）"
fi

sed -e "s#__INSTALL_DIR__#$INSTALL_DIR#g" -e "s#__NODE_BIN__#$NODE_BIN#g" -e "s#__STRONGSWAN_SERVICE__#$SS_SERVICE#g" \
  "$SRC_DIR/deploy/ipsec-panel.service" > /etc/systemd/system/ipsec-panel.service

cat > /usr/local/bin/ipsec-panel <<EOF
#!/usr/bin/env bash
# IPsec Panel 命令行：ipsec-panel status | reload | reset-password [密码]
set -a; . $ENV_FILE; set +a
exec $NODE_BIN $INSTALL_DIR/src/cli.js "\$@"
EOF
chmod 755 /usr/local/bin/ipsec-panel

# ---------------------------------------------------------------- 系统设置
setup_system

# ---------------------------------------------------------------- 启动
info "启动面板"
systemctl daemon-reload
systemctl enable ipsec-panel >/dev/null
systemctl restart ipsec-panel

for _ in $(seq 1 20); do
  sleep 1
  systemctl is-active --quiet ipsec-panel && break
done
systemctl is-active --quiet ipsec-panel || { journalctl -u ipsec-panel -n 50 --no-pager; die "面板启动失败"; }

set -a; . "$ENV_FILE"; set +a
SCHEME=http; [ "${PANEL_TLS}" != off ] && SCHEME=https
PUB_IP=$(curl -fsS --max-time 5 https://api.ipify.org 2>/dev/null || hostname -I | awk '{print $1}')
echo
echo "=================================================================="
echo " IPsec Panel 安装完成"
if [ "$PANEL_HOST" = 127.0.0.1 ]; then
  echo "  面板地址: http://127.0.0.1:${PANEL_PORT}（请在 Nginx/宝塔中反代到此地址，并开启 HTTPS）"
else
  echo "  面板地址: ${SCHEME}://${PUB_IP}:${PANEL_PORT}"
fi
if [ -f "$DATA_DIR/initial-password.txt" ]; then
  sed 's/^/  /' "$DATA_DIR/initial-password.txt"
else
  echo "  管理员账号沿用之前的设置（忘记密码：ipsec-panel reset-password）"
fi
echo
if [ "$PANEL_HOST" = 127.0.0.1 ]; then
  echo "  还需要：在云服务器安全组放行 UDP 500、UDP 4500"
else
  echo "  还需要：在云服务器安全组放行 UDP 500、UDP 4500 和 TCP ${PANEL_PORT}"
fi
echo "  命令行：ipsec-panel status | reload | reset-password"
echo "=================================================================="
