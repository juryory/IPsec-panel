'use strict';
const express = require('express');
const config = require('./config');
const { q, logEvent } = require('./db');
const settings = require('./settings');
const auth = require('./auth');
const strongswan = require('./strongswan');
const monitor = require('./monitor');
const pki = require('./pki');
const h3c = require('./h3c');
const h3cpush = require('./h3cpush');
const profiles = require('./profiles');
const netsetup = require('./netsetup');
const { PRESETS } = require('./proposals');
const { ntHash } = require('./md4');
const { maskSecrets } = require('./swanconf');
const { loadState, parseSite, publicSite, userNets, hubNetsForSite } = require('./model');
const U = require('./util');

const router = express.Router();
const { bad, HttpError, now } = U;

// ---------- 公共工具 ----------
const toBool = (v) => v === true || v === 1 || v === '1' || v === 'true' || v === 'on';

async function applyChanges(reason) {
  try {
    const r = await strongswan.sync(reason);
    const netErr = netsetup.getLastError();
    return { applied: true, warning: netErr || undefined, output: r.output };
  } catch (e) {
    logEvent('system', '', `配置加载失败：${e.message}`);
    return { applied: false, warning: `配置已保存，但加载到 strongSwan 失败：${e.message}` };
  }
}

async function terminateEntity(entity) {
  try {
    const conns = await monitor.connections();
    for (const c of conns) if (c.entity === entity) await strongswan.terminate(c.ikeId).catch(() => {});
  } catch {}
}

function getSiteOr404(id) {
  const s = parseSite(q.get('SELECT * FROM sites WHERE id = ?', Number(id)));
  if (!s) throw new HttpError(404, '站点不存在');
  return s;
}

function getUserOr404(id) {
  const u = q.get('SELECT * FROM users WHERE id = ?', Number(id));
  if (!u) throw new HttpError(404, '用户不存在');
  return u;
}

function onlineMap() {
  const snap = monitor.snapshot();
  const m = new Map();
  for (const c of snap.conns) if (c.up) m.set(c.entity, c);
  return m;
}

// ---------- 登录 ----------
router.post('/login', (req, res) => {
  const { username, password } = req.body || {};
  res.json(auth.login(req, res, String(username || ''), String(password || '')));
});

router.post('/logout', (req, res) => {
  auth.logout(req, res);
  res.json({ ok: true });
});

router.get('/session', (req, res) => {
  const s = auth.currentSession(req);
  res.json({ loggedIn: !!s, username: s ? auth.adminName() : null, mock: config.mock });
});

router.use(auth.requireAuth);

// ---------- 概览 ----------
router.get('/overview', async (req, res) => {
  const state = loadState();
  const status = await strongswan.status();
  const online = onlineMap();
  const dayStart = now() - 86400;
  const traffic = q.get('SELECT COALESCE(SUM(rx),0) AS rx, COALESCE(SUM(tx),0) AS tx FROM traffic WHERE bucket >= ?', dayStart);
  const warnings = [];
  if (!state.settings.public_host) warnings.push({ level: 'error', text: '尚未设置云服务器公网地址，远程用户功能和 H3C 配置都需要它。', link: '#/settings' });
  if (!status.running) warnings.push({ level: 'error', text: `strongSwan 未运行：${status.error || ''}`, link: '#/logs' });
  const netErr = netsetup.getLastError();
  if (netErr) warnings.push({ level: 'warn', text: netErr, link: '#/settings' });
  const sites = state.sites.map((s) => {
    const hash = h3c.configHash(state, s);
    const outdated = s.enabled && s.applied_hash !== hash;
    if (outdated) warnings.push({ level: 'warn', text: `站点 ${s.name} 的 H3C 配置${s.applied_hash ? '已变更，需要重新下发' : '尚未下发'}`, link: `#/sites/${s.id}` });
    return { id: s.id, name: s.name, description: s.description, enabled: !!s.enabled, online: online.has(`site:${s.name}`), outdated, subnets: s.subnets };
  });
  const users = state.users;
  const snapErr = monitor.snapshot().error;
  res.json({
    status,
    publicHost: state.settings.public_host,
    tunnel: state.tunnel,
    sites,
    counts: {
      sites: sites.filter((s) => s.enabled).length,
      sitesOnline: sites.filter((s) => s.online).length,
      users: users.filter((u) => u.enabled).length,
      usersOnline: [...online.keys()].filter((k) => k.startsWith('user:')).length,
    },
    traffic24h: traffic,
    warnings,
    snapshotError: snapErr,
    events: q.all('SELECT * FROM events ORDER BY id DESC LIMIT 12'),
  });
});

// ---------- 设置 ----------
router.get('/settings', (req, res) => {
  const s = settings.getAll();
  res.json({ settings: s, tunnel: U.tunnelInfo(s.tunnel_net), admin: auth.adminName() });
});

router.put('/settings', async (req, res) => {
  const body = req.body || {};
  if (body.tunnel_net) {
    const t = U.parseCidr(body.tunnel_net);
    if (!t) throw bad('隧道网段格式不正确');
    for (const s of loadState().sites) {
      for (const n of s.subnets) if (U.cidrOverlap(n, t)) throw bad(`隧道网段与站点 ${s.name} 的网段 ${n} 重叠`);
    }
  }
  const { before, after } = settings.update(body);
  const changed = Object.keys(after).filter((k) => before[k] !== after[k]);
  if (changed.length) logEvent('admin', '', `修改设置：${changed.join(', ')}`);
  const r = changed.length ? await applyChanges('设置变更') : { applied: true };
  res.json({ settings: after, ...r });
});

router.put('/admin', (req, res) => {
  const { username, current_password, new_password } = req.body || {};
  const admin = q.get('SELECT * FROM admin WHERE id = 1');
  if (!auth.verifyPassword(String(current_password || ''), admin.password_hash)) throw bad('当前密码不正确');
  const name = String(username || admin.username).trim();
  if (!/^[A-Za-z0-9_.-]{1,32}$/.test(name)) throw bad('用户名只能包含字母、数字、_ . -');
  auth.setAdminPassword(name, String(new_password || ''));
  logEvent('admin', '', '管理员账号/密码已修改');
  auth.logout(req, res);
  res.json({ ok: true });
});

// ---------- 站点 ----------
function validateSite(input, existing) {
  const state = loadState();
  const cur = existing || {};
  const s = {};
  const pick = (k, def) => (input[k] !== undefined ? input[k] : cur[k] !== undefined ? cur[k] : def);

  s.name = existing ? existing.name : String(input.name || '').trim();
  if (!U.SITE_NAME_RE.test(s.name)) throw bad('站点名称只能包含字母、数字和 -，最长 32 位');
  if (!existing && q.get('SELECT id FROM sites WHERE name = ?', s.name)) throw bad('站点名称已存在');

  s.description = String(pick('description', '')).slice(0, 200);
  s.enabled = toBool(pick('enabled', 1)) ? 1 : 0;
  s.device_type = String(pick('device_type', 'comware7'));
  if (!h3c.DEVICE_TYPES[s.device_type]) throw bad('设备类型不正确');
  s.ike_version = Number(pick('ike_version', 1)) === 2 ? 2 : 1;
  if (s.device_type === 'comware5') s.ike_version = 1;
  s.crypto_preset = String(pick('crypto_preset', 'strong'));
  if (!PRESETS[s.crypto_preset]) throw bad('算法预设不正确');

  s.local_id = String(pick('local_id', `${s.name.toLowerCase()}.ipsec`)).trim();
  if (!U.FQDN_ID_RE.test(s.local_id) || U.isIPv4(s.local_id)) throw bad('站点身份标识应为 FQDN 格式（如 hq.ipsec）');
  if (s.local_id === state.settings.hub_id) throw bad('站点身份标识不能与 Hub 身份相同');
  const dupId = q.get('SELECT name FROM sites WHERE local_id = ? AND id != ?', s.local_id, cur.id || 0);
  if (dupId) throw bad(`身份标识已被站点 ${dupId.name} 使用`);

  s.psk = input.psk ? String(input.psk).trim() : cur.psk || U.randomPsk();
  if (!U.PSK_RE.test(s.psk)) throw bad('预共享密钥 8-128 位，只能包含字母、数字和 _-.@%+=');

  let subnets = pick('subnets', []);
  if (typeof subnets === 'string') subnets = subnets.split(/[\s,，;]+/).filter(Boolean);
  if (!Array.isArray(subnets) || !subnets.length) throw bad('至少填写一个内网网段');
  const parsed = subnets.map((n) => {
    const c = U.parseCidr(String(n));
    if (!c) throw bad(`网段格式不正确：${n}`);
    if (c.prefix < 8) throw bad(`网段太大：${n}`);
    return c;
  });
  for (let i = 0; i < parsed.length; i++) {
    for (let j = i + 1; j < parsed.length; j++) if (U.cidrOverlap(parsed[i], parsed[j])) throw bad(`网段 ${parsed[i].cidr} 与 ${parsed[j].cidr} 重叠`);
    if (U.cidrOverlap(parsed[i], state.tunnel.cidr)) throw bad(`网段 ${parsed[i].cidr} 与隧道网段 ${state.tunnel.cidr} 重叠`);
    for (const other of state.sites) {
      if (other.id === cur.id) continue;
      for (const n of other.subnets) if (U.cidrOverlap(parsed[i], n)) throw bad(`网段 ${parsed[i].cidr} 与站点 ${other.name} 的 ${n} 重叠`);
    }
  }
  s.subnets = JSON.stringify(parsed.map((c) => c.cidr));

  s.lan_ip = String(pick('lan_ip', '')).trim();
  if (s.lan_ip) {
    if (!U.isIPv4(s.lan_ip)) throw bad('LAN 地址格式不正确');
    if (!parsed.some((c) => U.cidrContainsIp(c, s.lan_ip))) throw bad('LAN 地址必须在站点内网网段中');
  }
  s.wan_interface = String(pick('wan_interface', 'GigabitEthernet0/0')).trim();
  if (!U.IFACE_RE.test(s.wan_interface)) throw bad('WAN 接口名称不正确');
  s.acl_number = Number(pick('acl_number', 3100));
  if (!(s.acl_number >= 3000 && s.acl_number <= 3999)) throw bad('ACL 编号应在 3000-3999');
  s.keepalive = toBool(pick('keepalive', 1)) ? 1 : 0;
  s.mesh = toBool(pick('mesh', 1)) ? 1 : 0;
  s.allow_users = toBool(pick('allow_users', 1)) ? 1 : 0;

  s.ssh_enabled = toBool(pick('ssh_enabled', 0)) ? 1 : 0;
  s.ssh_host = String(pick('ssh_host', '')).trim();
  if (s.ssh_host && !U.isIPv4(s.ssh_host) && !U.HOST_RE.test(s.ssh_host)) throw bad('SSH 地址格式不正确');
  s.ssh_port = Number(pick('ssh_port', 22));
  if (!(s.ssh_port >= 1 && s.ssh_port <= 65535)) throw bad('SSH 端口不正确');
  s.ssh_user = String(pick('ssh_user', '')).trim().slice(0, 64);
  // 密码留空表示不修改
  s.ssh_password = input.ssh_password ? String(input.ssh_password) : cur.ssh_password || '';
  if (input.ssh_password_clear) s.ssh_password = '';
  if (s.ssh_enabled && (!s.ssh_user || !s.ssh_password)) throw bad('启用 SSH 下发需要填写用户名和密码');
  if (s.device_type === 'er') s.ssh_enabled = 0;
  return s;
}

function siteView(state, site, online) {
  const hash = h3c.configHash(state, site);
  return {
    ...publicSite(site),
    online: online.has(`site:${site.name}`),
    configHash: hash,
    outdated: site.applied_hash !== hash,
    hubNets: hubNetsForSite(state, site),
  };
}

router.get('/sites', (req, res) => {
  const state = loadState();
  const online = onlineMap();
  res.json({
    sites: state.sites.map((s) => siteView(state, s, online)),
    deviceTypes: h3c.DEVICE_TYPES,
    presets: Object.fromEntries(Object.entries(PRESETS).map(([k, v]) => [k, v.label])),
    hubId: state.settings.hub_id,
  });
});

router.get('/sites/:id', (req, res) => {
  const state = loadState();
  const site = state.sites.find((s) => s.id === Number(req.params.id));
  if (!site) throw new HttpError(404, '站点不存在');
  const online = onlineMap();
  const conn = online.get(`site:${site.name}`) || null;
  res.json({ site: { ...siteView(state, site, online), psk: site.psk }, conn, deviceTypes: h3c.DEVICE_TYPES, presets: Object.fromEntries(Object.entries(PRESETS).map(([k, v]) => [k, v.label])) });
});

router.post('/sites', async (req, res) => {
  const s = validateSite(req.body || {}, null);
  const t = now();
  const cols = Object.keys(s);
  const r = q.run(
    `INSERT INTO sites (${cols.join(', ')}, created_at, updated_at, psk_rotated_at) VALUES (${cols.map(() => '?').join(', ')}, ?, ?, ?)`,
    ...cols.map((c) => s[c]),
    t,
    t,
    t,
  );
  logEvent('admin', `site:${s.name}`, '新增站点');
  const result = await applyChanges(`新增站点 ${s.name}`);
  res.json({ id: Number(r.lastInsertRowid), ...result });
});

router.put('/sites/:id', async (req, res) => {
  const cur = getSiteOr404(req.params.id);
  const s = validateSite(req.body || {}, { ...cur, subnets: cur.subnets });
  const cols = Object.keys(s).filter((c) => c !== 'name');
  q.run(`UPDATE sites SET ${cols.map((c) => `${c} = ?`).join(', ')}, updated_at = ? WHERE id = ?`, ...cols.map((c) => s[c]), now(), cur.id);
  logEvent('admin', `site:${cur.name}`, '修改站点');
  const result = await applyChanges(`修改站点 ${cur.name}`);
  if (!s.enabled && cur.enabled) await terminateEntity(`site:${cur.name}`);
  res.json(result);
});

router.delete('/sites/:id', async (req, res) => {
  const cur = getSiteOr404(req.params.id);
  q.run('DELETE FROM sites WHERE id = ?', cur.id);
  logEvent('admin', `site:${cur.name}`, '删除站点');
  const result = await applyChanges(`删除站点 ${cur.name}`);
  await terminateEntity(`site:${cur.name}`);
  res.json(result);
});

router.get('/sites/:id/h3c', (req, res) => {
  const state = loadState();
  const site = state.sites.find((s) => s.id === Number(req.params.id));
  if (!site) throw new HttpError(404, '站点不存在');
  const g = h3c.generate(state, site);
  res.json({ ...g, commands: undefined, applied: site.applied_hash === g.hash, appliedAt: site.applied_at, appliedBy: site.applied_by });
});

router.post('/sites/:id/mark-applied', (req, res) => {
  const state = loadState();
  const site = state.sites.find((s) => s.id === Number(req.params.id));
  if (!site) throw new HttpError(404, '站点不存在');
  const hash = h3c.configHash(state, site);
  q.run('UPDATE sites SET applied_hash = ?, applied_at = ?, applied_by = ? WHERE id = ?', hash, now(), 'manual', site.id);
  logEvent('admin', `site:${site.name}`, `标记 H3C 配置已手动下发（指纹 ${hash}）`);
  res.json({ ok: true });
});

async function pushSite(site, state) {
  if (!site.ssh_enabled) throw bad('该站点未启用 SSH 下发');
  if (!state.settings.public_host) throw bad('请先设置云服务器公网地址');
  const g = h3c.generate(state, site);
  const host = site.ssh_host || site.lan_ip || h3c.defaultLanIp(site);
  let result;
  try {
    result = await h3cpush.push({ host, port: site.ssh_port, username: site.ssh_user, password: site.ssh_password, commands: g.commands });
  } catch (e) {
    logEvent('push', `site:${site.name}`, `SSH 下发失败：${e.message}`);
    return { ok: false, error: e.message, transcript: e.result ? e.result.transcript : '', errors: e.result ? e.result.errors : [] };
  }
  if (result.ok) {
    q.run('UPDATE sites SET applied_hash = ?, applied_at = ?, applied_by = ? WHERE id = ?', g.hash, now(), 'ssh', site.id);
    logEvent('push', `site:${site.name}`, `SSH 下发成功（${host}，指纹 ${g.hash}）`);
  } else {
    logEvent('push', `site:${site.name}`, `SSH 下发有 ${result.errors.length} 条命令报错`);
  }
  return result;
}

router.post('/sites/:id/push', async (req, res) => {
  const state = loadState();
  const site = state.sites.find((s) => s.id === Number(req.params.id));
  if (!site) throw new HttpError(404, '站点不存在');
  res.json(await pushSite(site, state));
});

// 轮换预共享密钥：如启用 SSH，先经（旧密钥建立的）隧道把新密钥推给 H3C，再更新云端
router.post('/sites/:id/rotate-psk', async (req, res) => {
  const cur = getSiteOr404(req.params.id);
  const psk = U.randomPsk();
  q.run('UPDATE sites SET psk = ?, psk_rotated_at = ?, updated_at = ? WHERE id = ?', psk, now(), now(), cur.id);
  logEvent('admin', `site:${cur.name}`, '轮换预共享密钥');
  let push = null;
  if (toBool((req.body || {}).push) && cur.ssh_enabled) {
    const state = loadState();
    push = await pushSite(state.sites.find((s) => s.id === cur.id), state);
  }
  const result = await applyChanges(`轮换站点 ${cur.name} 密钥`);
  res.json({ ...result, push });
});

// ---------- 远程用户 ----------
function userView(u, online) {
  const { nt_hash, ...rest } = u;
  return { ...rest, online: online.has(`user:${u.username}`), has_password: !!nt_hash };
}

async function crlChanged(reason) {
  return applyChanges(reason);
}

router.get('/users', (req, res) => {
  const online = onlineMap();
  res.json({ users: q.all('SELECT * FROM users ORDER BY id').map((u) => userView(u, online)) });
});

router.post('/users', async (req, res) => {
  const b = req.body || {};
  const username = String(b.username || '').trim();
  if (!U.USER_NAME_RE.test(username)) throw bad('用户名只能包含字母、数字和 _ . -');
  if (q.get('SELECT id FROM users WHERE username = ?', username)) throw bad('用户名已存在');
  const authType = b.auth_type === 'cert' ? 'cert' : 'eap';
  const displayName = String(b.display_name || '').slice(0, 64);
  let password = null;
  let nt = '';
  if (authType === 'eap') {
    password = b.password ? String(b.password) : U.randomPassword();
    if (password.length < 8) throw bad('密码至少 8 位');
    nt = ntHash(password);
  }
  let cert = { serial: '', notAfter: null };
  if (authType === 'cert') cert = await pki.issueUserCert(username);
  const t = now();
  const r = q.run(
    'INSERT INTO users (username, display_name, auth_type, nt_hash, enabled, cert_serial, cert_not_after, created_at, updated_at) VALUES (?, ?, ?, ?, 1, ?, ?, ?, ?)',
    username,
    displayName,
    authType,
    nt,
    cert.serial,
    cert.notAfter,
    t,
    t,
  );
  logEvent('admin', `user:${username}`, `新增用户（${authType === 'eap' ? '账号密码' : '证书'}认证）`);
  const result = await applyChanges(`新增用户 ${username}`);
  res.json({ id: Number(r.lastInsertRowid), password, ...result });
});

router.put('/users/:id', async (req, res) => {
  const u = getUserOr404(req.params.id);
  const b = req.body || {};
  const displayName = b.display_name !== undefined ? String(b.display_name).slice(0, 64) : u.display_name;
  const enabled = b.enabled !== undefined ? (toBool(b.enabled) ? 1 : 0) : u.enabled;
  q.run('UPDATE users SET display_name = ?, enabled = ?, updated_at = ? WHERE id = ?', displayName, enabled, now(), u.id);
  if (enabled !== u.enabled) logEvent('admin', `user:${u.username}`, enabled ? '启用用户' : '禁用用户');
  const result = enabled !== u.enabled ? await crlChanged(`${enabled ? '启用' : '禁用'}用户 ${u.username}`) : { applied: true };
  if (!enabled && u.enabled) await terminateEntity(`user:${u.username}`);
  res.json(result);
});

router.post('/users/:id/password', async (req, res) => {
  const u = getUserOr404(req.params.id);
  if (u.auth_type !== 'eap') throw bad('证书认证的用户没有密码');
  const password = (req.body || {}).password ? String(req.body.password) : U.randomPassword();
  if (password.length < 8) throw bad('密码至少 8 位');
  q.run('UPDATE users SET nt_hash = ?, updated_at = ? WHERE id = ?', ntHash(password), now(), u.id);
  logEvent('admin', `user:${u.username}`, '重置密码');
  const result = await applyChanges(`重置用户 ${u.username} 密码`);
  res.json({ password, ...result });
});

// 重新签发证书：旧证书进入 CRL，并断开当前连接
router.post('/users/:id/reissue', async (req, res) => {
  const u = getUserOr404(req.params.id);
  if (u.auth_type !== 'cert') throw bad('该用户不是证书认证');
  if (u.cert_serial) {
    q.run('INSERT OR IGNORE INTO revoked_certs (serial, subject, not_after, revoked_at) VALUES (?, ?, ?, ?)', u.cert_serial, u.username, u.cert_not_after || now() + 86400, now());
  }
  const cert = await pki.issueUserCert(u.username);
  q.run('UPDATE users SET cert_serial = ?, cert_not_after = ?, cert_revoked = 0, updated_at = ? WHERE id = ?', cert.serial, cert.notAfter, now(), u.id);
  logEvent('admin', `user:${u.username}`, '重新签发证书，旧证书已吊销');
  const result = await crlChanged(`重新签发用户 ${u.username} 证书`);
  await terminateEntity(`user:${u.username}`);
  res.json(result);
});

router.delete('/users/:id', async (req, res) => {
  const u = getUserOr404(req.params.id);
  if (u.auth_type === 'cert' && u.cert_serial) {
    q.run('INSERT OR IGNORE INTO revoked_certs (serial, subject, not_after, revoked_at) VALUES (?, ?, ?, ?)', u.cert_serial, u.username, u.cert_not_after || now() + 86400, now());
  }
  q.run('DELETE FROM users WHERE id = ?', u.id);
  pki.removeUserFiles(u.username);
  logEvent('admin', `user:${u.username}`, '删除用户');
  const result = await applyChanges(`删除用户 ${u.username}`);
  await terminateEntity(`user:${u.username}`);
  res.json(result);
});

// 生成客户端配置：返回 base64 内容，前端负责保存；证书用户的 p12 每次随机生成新的导入密码
router.post('/users/:id/bundle', async (req, res) => {
  const u = getUserOr404(req.params.id);
  const kind = String((req.body || {}).kind || '');
  const state = loadState();
  if (kind === 'ca') {
    await pki.ensureCA();
    return res.json({ filename: 'ipsec-panel-ca.crt', mime: 'application/x-x509-ca-cert', data: Buffer.from(pki.caPem()).toString('base64') });
  }
  if (!state.settings.public_host) throw bad('请先在设置中填写云服务器公网地址');
  if (!u.enabled) throw bad('用户已禁用');
  await pki.ensureCA();
  const opts = {};
  if (u.auth_type === 'cert') {
    opts.p12Password = U.randomPassword();
    opts.p12 = await pki.buildP12(u.username, opts.p12Password, `ipsec-${u.username}`);
  }
  let out;
  switch (kind) {
    case 'apple':
      out = { filename: `${u.username}.mobileconfig`, mime: 'application/x-apple-aspen-config', data: Buffer.from(profiles.mobileconfig(state, u, opts)).toString('base64') };
      break;
    case 'windows':
      out = { filename: `${u.username}-vpn.ps1`, mime: 'text/plain', data: profiles.windowsScript(state, u, opts).toString('base64') };
      break;
    case 'android':
      out = { filename: `${u.username}.sswan`, mime: 'application/vnd.strongswan.profile', data: Buffer.from(profiles.sswan(state, u, opts)).toString('base64') };
      break;
    case 'p12':
      if (u.auth_type !== 'cert') throw bad('该用户不是证书认证');
      out = { filename: `${u.username}.p12`, mime: 'application/x-pkcs12', data: opts.p12.toString('base64') };
      break;
    default:
      throw bad('未知的配置类型');
  }
  if (opts.p12Password) out.password = opts.p12Password;
  logEvent('admin', `user:${u.username}`, `下载客户端配置（${kind}）`);
  res.json(out);
});

// ---------- 在线连接 ----------
router.get('/connections', async (req, res) => {
  const conns = await monitor.connections();
  res.json({ conns, ts: now() });
});

router.post('/connections/:ikeId/terminate', async (req, res) => {
  const id = String(req.params.ikeId);
  if (!/^\d+$/.test(id)) throw bad('连接 ID 不正确');
  await strongswan.terminate(id);
  logEvent('admin', '', `手动断开连接 #${id}`);
  setTimeout(() => monitor.poll().catch(() => {}), 1500);
  res.json({ ok: true });
});

// ---------- 流量 ----------
const RANGES = {
  '24h': { span: 86400, step: 300 },
  '7d': { span: 7 * 86400, step: 3600 },
  '30d': { span: 30 * 86400, step: 86400 },
};

router.get('/traffic', (req, res) => {
  const range = RANGES[req.query.range] ? req.query.range : '24h';
  const { span, step } = RANGES[range];
  const entity = String(req.query.entity || '');
  const end = Math.floor(now() / step) * step + step;
  const start = end - span;
  const rows = entity
    ? q.all('SELECT (bucket / ?) * ? AS t, SUM(rx) AS rx, SUM(tx) AS tx FROM traffic WHERE entity = ? AND bucket >= ? GROUP BY t', step, step, entity, start)
    : q.all('SELECT (bucket / ?) * ? AS t, SUM(rx) AS rx, SUM(tx) AS tx FROM traffic WHERE bucket >= ? GROUP BY t', step, step, start);
  const map = new Map(rows.map((r) => [r.t, r]));
  const points = [];
  for (let t = start; t < end; t += step) {
    const r = map.get(t);
    points.push({ t, rx: r ? r.rx : 0, tx: r ? r.tx : 0 });
  }
  res.json({ range, step, points });
});

router.get('/traffic/top', (req, res) => {
  const range = RANGES[req.query.range] ? req.query.range : '24h';
  const start = now() - RANGES[range].span;
  res.json({
    range,
    items: q.all('SELECT entity, SUM(rx) AS rx, SUM(tx) AS tx FROM traffic WHERE bucket >= ? GROUP BY entity ORDER BY SUM(rx) + SUM(tx) DESC LIMIT 50', start),
  });
});

// ---------- 事件与日志 ----------
router.get('/events', (req, res) => {
  const limit = Math.min(Number(req.query.limit) || 200, 1000);
  const where = [];
  const params = [];
  if (req.query.type) {
    where.push('type = ?');
    params.push(String(req.query.type));
  }
  if (req.query.entity) {
    where.push('entity = ?');
    params.push(String(req.query.entity));
  }
  if (req.query.before) {
    where.push('id < ?');
    params.push(Number(req.query.before));
  }
  const sql = `SELECT * FROM events ${where.length ? 'WHERE ' + where.join(' AND ') : ''} ORDER BY id DESC LIMIT ${limit}`;
  res.json({ events: q.all(sql, ...params) });
});

router.get('/logs/charon', async (req, res) => {
  res.json(await strongswan.readLog(req.query.lines));
});

// ---------- 服务控制 ----------
router.get('/service', async (req, res) => {
  const state = loadState();
  res.json({
    status: await strongswan.status(),
    config: maskSecrets(strongswan.generatedConf()),
    network: netsetup.getLastError(),
    userNets: userNets(state),
    tunnel: state.tunnel,
    paths: { swanctlDir: config.swanctlDir, vici: config.viciSocket, log: config.charonLog, data: config.dataDir },
  });
});

router.post('/service/reload', async (req, res) => {
  logEvent('admin', '', '手动重新加载配置');
  const r = await applyChanges('手动重新加载');
  res.json(r);
});

router.post('/service/restart', async (req, res) => {
  logEvent('admin', '', '手动重启 strongSwan');
  try {
    await strongswan.restart();
    res.json({ applied: true });
  } catch (e) {
    res.json({ applied: false, warning: e.message });
  }
});

// ---------- 证书 ----------
router.get('/pki', async (req, res) => {
  const s = settings.getAll();
  await pki.ensureCA();
  const server = s.cert_mode === 'custom' ? pki.certInfo(s.custom_cert_path) : pki.certInfo(pki.paths.serverCrt);
  res.json({ ca: pki.certInfo(pki.paths.caCrt), server, certMode: s.cert_mode, crl: q.get('SELECT COUNT(*) AS n FROM revoked_certs').n });
});

router.post('/pki/renew-server', async (req, res) => {
  const s = settings.getAll();
  if (!s.public_host) throw bad('请先设置公网地址');
  if (s.cert_mode === 'custom') throw bad('当前使用自定义证书，请自行更新证书文件后点“重新加载”');
  await pki.issueServerCert(s.public_host);
  logEvent('admin', '', '重新签发服务器证书');
  res.json(await applyChanges('重新签发服务器证书'));
});

router.get('/pki/ca.crt', async (req, res) => {
  await pki.ensureCA();
  res.setHeader('Content-Type', 'application/x-x509-ca-cert');
  res.setHeader('Content-Disposition', 'attachment; filename="ipsec-panel-ca.crt"');
  res.send(pki.caPem());
});

module.exports = router;
