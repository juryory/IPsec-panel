'use strict';
// 运行时配置：全部来自环境变量（systemd EnvironmentFile / docker-compose environment）。
// 业务设置（公网地址、隧道网段等）保存在数据库，可在面板里修改。
const fs = require('node:fs');
const path = require('node:path');

// 支持项目根目录下的 .env（宝塔 Node 项目等无法方便设置环境变量的场景）；已存在的环境变量优先
const envFile = path.join(__dirname, '..', '.env');
if (fs.existsSync(envFile)) {
  try {
    process.loadEnvFile(envFile);
  } catch (e) {
    console.error(`读取 ${envFile} 失败: ${e.message}`);
  }
}

const env = process.env;
const mock = env.MOCK === '1' || process.argv.includes('--mock');
const defaultData = mock ? path.join(__dirname, '..', 'data') : '/var/lib/ipsec-panel';

function bool(v, def) {
  if (v === undefined || v === '') return def;
  return ['1', 'true', 'yes', 'on'].includes(String(v).toLowerCase());
}

const dataDir = env.DATA_DIR || defaultData;

module.exports = {
  mock,
  host: env.PANEL_HOST || '127.0.0.1',
  // 开发模式默认 18088：Windows 上 8088 常落在 Hyper-V/WinNAT 保留端口段内，监听会报 EACCES
  port: parseInt(env.PANEL_PORT || (mock ? '18088' : '8088'), 10),
  // off: 纯 HTTP（放在 Nginx 反代后面）；auto: 自签 HTTPS；custom: 使用 PANEL_TLS_CERT / PANEL_TLS_KEY
  tls: env.PANEL_TLS || 'off',
  tlsCert: env.PANEL_TLS_CERT || '',
  tlsKey: env.PANEL_TLS_KEY || '',
  trustProxy: bool(env.TRUST_PROXY, false),

  dataDir,
  dbPath: path.join(dataDir, 'panel.db'),
  pkiDir: path.join(dataDir, 'pki'),

  swanctlDir: env.SWANCTL_DIR || (mock ? path.join(dataDir, 'swanctl') : '/etc/swanctl'),
  swanctlBin: env.SWANCTL_BIN || 'swanctl',
  viciSocket: env.VICI_SOCKET || '/var/run/charon.vici',
  restartCmd: env.STRONGSWAN_RESTART_CMD || 'systemctl restart strongswan',
  charonLog: env.CHARON_LOG || '/var/log/ipsec-panel/charon.log',
  journalUnit: env.JOURNAL_UNIT || 'strongswan',
  opensslBin: env.OPENSSL_BIN || 'openssl',

  manageNetwork: bool(env.MANAGE_NETWORK, true),
  hubInterface: env.HUB_INTERFACE || 'ipsp0',
  pollInterval: Math.max(10, parseInt(env.POLL_INTERVAL || '30', 10)),

  adminUser: env.ADMIN_USER || 'admin',
  adminPassword: env.ADMIN_PASSWORD || '',
};
