'use strict';
// 单管理员认证：scrypt 哈希、HttpOnly 会话、登录限速（10 分钟内失败 5 次锁定）
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const config = require('./config');
const { q, logEvent } = require('./db');
const { now, randomPassword, HttpError } = require('./util');

const COOKIE = 'ipsp_sid';
const SESSION_TTL = 12 * 3600;
const MAX_FAILS = 5;
const FAIL_WINDOW = 600;

function hashPassword(pw) {
  const salt = crypto.randomBytes(16);
  const N = 16384, r = 8, p = 1;
  const hash = crypto.scryptSync(pw, salt, 32, { N, r, p });
  return `scrypt$${N}$${r}$${p}$${salt.toString('base64')}$${hash.toString('base64')}`;
}

function verifyPassword(pw, stored) {
  const parts = String(stored).split('$');
  if (parts[0] !== 'scrypt' || parts.length !== 6) return false;
  const [, N, r, p, salt, hash] = parts;
  const expected = Buffer.from(hash, 'base64');
  const got = crypto.scryptSync(pw, Buffer.from(salt, 'base64'), expected.length, { N: +N, r: +r, p: +p });
  return crypto.timingSafeEqual(expected, got);
}

// 首次启动：创建管理员。未指定密码时随机生成，并写到数据目录的 initial-password.txt
function ensureAdmin() {
  const row = q.get('SELECT * FROM admin WHERE id = 1');
  if (row) return null;
  const pw = config.adminPassword || randomPassword();
  q.run('INSERT INTO admin (id, username, password_hash, updated_at) VALUES (1, ?, ?, ?)', config.adminUser, hashPassword(pw), now());
  if (!config.adminPassword) {
    const f = path.join(config.dataDir, 'initial-password.txt');
    fs.writeFileSync(f, `用户名: ${config.adminUser}\n密码: ${pw}\n`, { mode: 0o600 });
    return { username: config.adminUser, password: pw, file: f };
  }
  return { username: config.adminUser, password: null };
}

function setAdminPassword(username, password) {
  if (!password || password.length < 8) throw new HttpError(400, '密码至少 8 位');
  q.run('UPDATE admin SET username = ?, password_hash = ?, updated_at = ? WHERE id = 1', username, hashPassword(password), now());
  q.run('DELETE FROM sessions');
  const f = path.join(config.dataDir, 'initial-password.txt');
  fs.rmSync(f, { force: true });
}

const tokenHash = (t) => crypto.createHash('sha256').update(t).digest('hex');

function parseCookies(header) {
  const out = {};
  for (const part of String(header || '').split(';')) {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}

function isSecure(req) {
  return req.secure || (config.trustProxy && req.headers['x-forwarded-proto'] === 'https');
}

function setCookie(req, res, value, maxAge) {
  const attrs = [`${COOKIE}=${value}`, 'Path=/', 'HttpOnly', 'SameSite=Strict', `Max-Age=${maxAge}`];
  if (isSecure(req)) attrs.push('Secure');
  res.setHeader('Set-Cookie', attrs.join('; '));
}

function login(req, res, username, password) {
  const ip = req.ip;
  const t = now();
  const fails = q.get('SELECT COUNT(*) AS n FROM login_attempts WHERE ip = ? AND ts > ?', ip, t - FAIL_WINDOW).n;
  if (fails >= MAX_FAILS) throw new HttpError(429, '登录失败次数过多，请 10 分钟后再试');
  const admin = q.get('SELECT * FROM admin WHERE id = 1');
  const ok = admin && username === admin.username && verifyPassword(String(password || ''), admin.password_hash);
  if (!ok) {
    q.run('INSERT INTO login_attempts (ip, ts) VALUES (?, ?)', ip, t);
    logEvent('admin', '', `登录失败：${String(username).slice(0, 64)} 来自 ${ip}`);
    throw new HttpError(401, '用户名或密码错误');
  }
  q.run('DELETE FROM login_attempts WHERE ip = ?', ip);
  const token = crypto.randomBytes(32).toString('base64url');
  q.run('INSERT INTO sessions (token_hash, created_at, expires_at, ip) VALUES (?, ?, ?, ?)', tokenHash(token), t, t + SESSION_TTL, ip);
  setCookie(req, res, token, SESSION_TTL);
  logEvent('admin', '', `管理员登录 来自 ${ip}`);
  return { username: admin.username };
}

function logout(req, res) {
  const token = parseCookies(req.headers.cookie)[COOKIE];
  if (token) q.run('DELETE FROM sessions WHERE token_hash = ?', tokenHash(token));
  setCookie(req, res, '', 0);
}

function currentSession(req) {
  const token = parseCookies(req.headers.cookie)[COOKIE];
  if (!token) return null;
  const s = q.get('SELECT * FROM sessions WHERE token_hash = ? AND expires_at > ?', tokenHash(token), now());
  return s || null;
}

// API 鉴权 + 简单 CSRF 防护（写操作必须带自定义请求头，跨站表单无法伪造）
function requireAuth(req, res, next) {
  if (!currentSession(req)) return res.status(401).json({ error: '未登录或会话已过期' });
  if (!['GET', 'HEAD', 'OPTIONS'].includes(req.method) && req.headers['x-requested-with'] !== 'ipsec-panel') {
    return res.status(403).json({ error: '缺少请求头' });
  }
  next();
}

function adminName() {
  const a = q.get('SELECT username FROM admin WHERE id = 1');
  return a ? a.username : '';
}

module.exports = { ensureAdmin, setAdminPassword, verifyPassword, hashPassword, login, logout, currentSession, requireAuth, adminName };
