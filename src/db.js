'use strict';
const fs = require('node:fs');
const path = require('node:path');
const config = require('./config');

// node:sqlite 在 Node 22 上会打印 ExperimentalWarning，这里静默掉，其它警告照常输出
const origEmitWarning = process.emitWarning;
process.emitWarning = function (warning, ...args) {
  if (String(warning && warning.message ? warning.message : warning).includes('SQLite')) return;
  return origEmitWarning.call(process, warning, ...args);
};
const { DatabaseSync } = require('node:sqlite');

fs.mkdirSync(path.dirname(config.dbPath), { recursive: true, mode: 0o700 });
const db = new DatabaseSync(config.dbPath);
try {
  fs.chmodSync(config.dbPath, 0o600);
} catch {}

db.exec(`
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS admin (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  username TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  updated_at INTEGER
);

CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  ip TEXT
);

CREATE TABLE IF NOT EXISTS login_attempts (
  ip TEXT NOT NULL,
  ts INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS sites (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT UNIQUE NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  enabled INTEGER NOT NULL DEFAULT 1,
  device_type TEXT NOT NULL DEFAULT 'comware7',
  ike_version INTEGER NOT NULL DEFAULT 1,
  crypto_preset TEXT NOT NULL DEFAULT 'strong',
  local_id TEXT NOT NULL,
  psk TEXT NOT NULL,
  subnets TEXT NOT NULL,
  lan_ip TEXT NOT NULL DEFAULT '',
  wan_interface TEXT NOT NULL DEFAULT 'GigabitEthernet0/0',
  acl_number INTEGER NOT NULL DEFAULT 3100,
  keepalive INTEGER NOT NULL DEFAULT 1,
  mesh INTEGER NOT NULL DEFAULT 1,
  allow_users INTEGER NOT NULL DEFAULT 1,
  ssh_enabled INTEGER NOT NULL DEFAULT 0,
  ssh_host TEXT NOT NULL DEFAULT '',
  ssh_port INTEGER NOT NULL DEFAULT 22,
  ssh_user TEXT NOT NULL DEFAULT '',
  ssh_password TEXT NOT NULL DEFAULT '',
  applied_hash TEXT NOT NULL DEFAULT '',
  applied_at INTEGER,
  applied_by TEXT,
  psk_rotated_at INTEGER,
  last_seen INTEGER,
  created_at INTEGER,
  updated_at INTEGER
);

CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  display_name TEXT NOT NULL DEFAULT '',
  auth_type TEXT NOT NULL DEFAULT 'eap',
  nt_hash TEXT NOT NULL DEFAULT '',
  enabled INTEGER NOT NULL DEFAULT 1,
  cert_serial TEXT NOT NULL DEFAULT '',
  cert_not_after INTEGER,
  cert_revoked INTEGER NOT NULL DEFAULT 0,
  last_seen INTEGER,
  created_at INTEGER,
  updated_at INTEGER
);

-- 已作废（重新签发/删除用户）的证书，用于生成 CRL
CREATE TABLE IF NOT EXISTS revoked_certs (
  serial TEXT PRIMARY KEY,
  subject TEXT NOT NULL,
  not_after INTEGER NOT NULL,
  revoked_at INTEGER NOT NULL
);

-- 5 分钟粒度的流量桶，entity 形如 site:hq / user:alice
CREATE TABLE IF NOT EXISTS traffic (
  entity TEXT NOT NULL,
  bucket INTEGER NOT NULL,
  rx INTEGER NOT NULL DEFAULT 0,
  tx INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (entity, bucket)
);
CREATE INDEX IF NOT EXISTS traffic_bucket ON traffic (bucket);

CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts INTEGER NOT NULL,
  type TEXT NOT NULL,
  entity TEXT NOT NULL DEFAULT '',
  detail TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS events_ts ON events (ts);
`);

// node:sqlite 不接受 undefined / boolean，这里统一转换
function norm(params) {
  return params.map((p) => (p === undefined ? null : typeof p === 'boolean' ? (p ? 1 : 0) : p));
}

const stmtCache = new Map();
function prep(sql) {
  let s = stmtCache.get(sql);
  if (!s) {
    s = db.prepare(sql);
    stmtCache.set(sql, s);
  }
  return s;
}

const q = {
  all: (sql, ...params) => prep(sql).all(...norm(params)),
  get: (sql, ...params) => prep(sql).get(...norm(params)),
  run: (sql, ...params) => prep(sql).run(...norm(params)),
  tx(fn) {
    db.exec('BEGIN');
    try {
      const r = fn();
      db.exec('COMMIT');
      return r;
    } catch (e) {
      db.exec('ROLLBACK');
      throw e;
    }
  },
};

function logEvent(type, entity, detail) {
  q.run('INSERT INTO events (ts, type, entity, detail) VALUES (?, ?, ?, ?)', Math.floor(Date.now() / 1000), type, entity || '', detail || '');
}

module.exports = { db, q, logEvent };
