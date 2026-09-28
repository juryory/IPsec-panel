'use strict';
const crypto = require('node:crypto');
const { execFile } = require('node:child_process');

// ---------- 校验 ----------
const SITE_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9-]{0,31}$/;
const USER_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/;
const FQDN_ID_RE = /^[A-Za-z0-9][A-Za-z0-9.-]{0,62}$/;
const HOST_RE = /^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$/;
const PSK_RE = /^[A-Za-z0-9_\-.@%+=]{8,128}$/;
const IFACE_RE = /^[A-Za-z][A-Za-z0-9\/:.-]{0,63}$/;
const IPV4_RE = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}
const bad = (msg) => new HttpError(400, msg);

function isIPv4(s) {
  return typeof s === 'string' && IPV4_RE.test(s);
}

function ipToInt(ip) {
  return ip.split('.').reduce((acc, o) => ((acc << 8) >>> 0) + parseInt(o, 10), 0) >>> 0;
}

function intToIp(n) {
  return [24, 16, 8, 0].map((s) => (n >>> s) & 255).join('.');
}

// 解析 CIDR，返回规范化后的网络；host 位不为 0 时自动归一到网络地址
function parseCidr(str) {
  if (typeof str !== 'string') return null;
  const m = str.trim().match(/^(\d+\.\d+\.\d+\.\d+)(?:\/(\d{1,2}))?$/);
  if (!m || !isIPv4(m[1])) return null;
  const prefix = m[2] === undefined ? 32 : parseInt(m[2], 10);
  if (prefix < 0 || prefix > 32) return null;
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  const network = (ipToInt(m[1]) & mask) >>> 0;
  const broadcast = (network | (~mask >>> 0)) >>> 0;
  return {
    prefix,
    network,
    broadcast,
    mask,
    cidr: `${intToIp(network)}/${prefix}`,
    address: intToIp(network),
    netmask: intToIp(mask),
    wildcard: intToIp(~mask >>> 0),
  };
}

function cidrOverlap(a, b) {
  const A = typeof a === 'string' ? parseCidr(a) : a;
  const B = typeof b === 'string' ? parseCidr(b) : b;
  return A.network <= B.broadcast && B.network <= A.broadcast;
}

function cidrContainsIp(cidr, ip) {
  const c = typeof cidr === 'string' ? parseCidr(cidr) : cidr;
  const n = ipToInt(ip);
  return n >= c.network && n <= c.broadcast;
}

// 隧道网段：.1 给云端 Hub 自己用，.10 起分配给远程用户
function tunnelInfo(tunnelNet) {
  const c = parseCidr(tunnelNet);
  if (!c || c.prefix > 28) throw bad('隧道网段必须是 /28 或更大的 IPv4 网段');
  return {
    cidr: c.cidr,
    hubIp: intToIp(c.network + 1),
    poolStart: intToIp(c.network + 10),
    poolEnd: intToIp(c.broadcast - 1),
    poolRange: `${intToIp(c.network + 10)}-${intToIp(c.broadcast - 1)}`,
  };
}

// ---------- 随机 ----------
const ALNUM = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789';
function randomString(len, alphabet = ALNUM) {
  const out = [];
  while (out.length < len) {
    const buf = crypto.randomBytes(len * 2);
    for (const b of buf) {
      // 拒绝采样，避免取模偏差
      if (b < 256 - (256 % alphabet.length)) out.push(alphabet[b % alphabet.length]);
      if (out.length === len) break;
    }
  }
  return out.join('');
}

const randomPsk = () => randomString(32);
const randomPassword = () => randomString(14);

function sha256(s) {
  return crypto.createHash('sha256').update(s).digest('hex');
}

// ---------- 进程 ----------
function run(cmd, args = [], opts = {}) {
  return new Promise((resolve, reject) => {
    const child = execFile(
      cmd,
      args,
      { timeout: opts.timeout || 60000, maxBuffer: 32 * 1024 * 1024, env: opts.env ? { ...process.env, ...opts.env } : process.env, encoding: opts.encoding || 'utf8' },
      (err, stdout, stderr) => {
        if (err) {
          err.stdout = stdout;
          err.stderr = stderr;
          err.message = `${cmd} ${args.join(' ')} 失败: ${(stderr || err.message || '').toString().trim()}`;
          return reject(err);
        }
        resolve({ stdout, stderr });
      },
    );
    if (opts.input !== undefined) {
      child.stdin.end(opts.input);
    }
  });
}

// 把 "systemctl restart strongswan" 这类配置拆成参数数组（不经过 shell）
function splitCommand(str) {
  return String(str).trim().split(/\s+/).filter(Boolean);
}

// 串行执行，避免并发写配置/重载
function createMutex() {
  let tail = Promise.resolve();
  return (fn) => {
    const p = tail.then(fn, fn);
    tail = p.catch(() => {});
    return p;
  };
}

function now() {
  return Math.floor(Date.now() / 1000);
}

function formatBytes(n) {
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  let v = Number(n) || 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(i ? 1 : 0)} ${units[i]}`;
}

module.exports = {
  SITE_NAME_RE,
  USER_NAME_RE,
  FQDN_ID_RE,
  HOST_RE,
  PSK_RE,
  IFACE_RE,
  HttpError,
  bad,
  isIPv4,
  ipToInt,
  intToIp,
  parseCidr,
  cidrOverlap,
  cidrContainsIp,
  tunnelInfo,
  randomString,
  randomPsk,
  randomPassword,
  sha256,
  run,
  splitCommand,
  createMutex,
  now,
  formatBytes,
};
