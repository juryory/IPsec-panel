'use strict';
const { q } = require('./db');
const { bad, isIPv4, HOST_RE, FQDN_ID_RE, parseCidr, tunnelInfo } = require('./util');

const DEFAULTS = {
  public_host: '', // 云服务器公网 IP 或域名（H3C 和客户端连接的地址）
  hub_id: 'ipsec-hub', // 站点隧道中云端的 IKE 身份（FQDN）
  tunnel_net: '10.10.0.0/24', // 隧道网段：.1 = Hub，.10 起 = 远程用户地址池
  client_dns: '', // 下发给远程用户的 DNS，逗号分隔
  site_mesh: '1', // 站点之间互通（经云端中转）
  users_full_tunnel: '0', // 远程用户所有流量都走云端（需要 NAT）
  vpn_name: '公司 VPN', // 客户端里显示的连接名
  cert_mode: 'selfsigned', // selfsigned | custom
  custom_cert_path: '',
  custom_key_path: '',
  custom_chain_path: '',
  traffic_retention_days: '30',
  events_retention_days: '90',
};

const BOOL_KEYS = ['site_mesh', 'users_full_tunnel'];

function getAll() {
  const rows = q.all('SELECT key, value FROM settings');
  const out = { ...DEFAULTS };
  for (const r of rows) if (r.key in DEFAULTS || r.key.startsWith('_')) out[r.key] = r.value;
  return out;
}

function get(key) {
  const r = q.get('SELECT value FROM settings WHERE key = ?', key);
  return r ? r.value : DEFAULTS[key];
}

function set(key, value) {
  q.run('INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value', key, String(value));
}

// 校验并保存面板里提交的设置
function update(input) {
  const cur = getAll();
  const next = { ...cur };
  for (const key of Object.keys(DEFAULTS)) {
    if (input[key] === undefined) continue;
    let v = input[key];
    if (BOOL_KEYS.includes(key)) v = v === true || v === '1' || v === 1 ? '1' : '0';
    next[key] = typeof v === 'string' ? v.trim() : String(v);
  }

  if (next.public_host && !isIPv4(next.public_host) && !HOST_RE.test(next.public_host)) {
    throw bad('公网地址格式不正确，应为 IPv4 地址或域名');
  }
  if (!FQDN_ID_RE.test(next.hub_id) || isIPv4(next.hub_id)) throw bad('Hub 身份标识应为 FQDN 格式，例如 ipsec-hub');
  const t = parseCidr(next.tunnel_net);
  if (!t) throw bad('隧道网段格式不正确');
  tunnelInfo(t.cidr);
  next.tunnel_net = t.cidr;
  if (next.client_dns) {
    const list = next.client_dns.split(/[\s,]+/).filter(Boolean);
    if (!list.every(isIPv4)) throw bad('DNS 必须是 IPv4 地址，多个用逗号分隔');
    next.client_dns = list.join(',');
  }
  if (!['selfsigned', 'custom'].includes(next.cert_mode)) throw bad('证书模式不正确');
  if (next.cert_mode === 'custom' && (!next.custom_cert_path || !next.custom_key_path)) {
    throw bad('自定义证书模式需要填写证书和私钥路径');
  }
  if (!next.vpn_name || next.vpn_name.length > 64) throw bad('连接名称长度应为 1-64');
  for (const k of ['traffic_retention_days', 'events_retention_days']) {
    const n = parseInt(next[k], 10);
    if (!(n >= 1 && n <= 3650)) throw bad('保留天数应为 1-3650');
    next[k] = String(n);
  }

  for (const key of Object.keys(DEFAULTS)) if (next[key] !== cur[key]) set(key, next[key]);
  return { before: cur, after: getAll() };
}

module.exports = { DEFAULTS, getAll, get, set, update };
