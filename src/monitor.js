'use strict';
// 定时采集：在线状态、上下线事件、流量累计（5 分钟一个桶）
const config = require('./config');
const strongswan = require('./strongswan');
const { q, logEvent } = require('./db');
const settings = require('./settings');
const { now } = require('./util');

const BUCKET = 300;

// 把 VICI 返回的 IKE_SA 转成面板使用的结构
function describeSa(sa) {
  let kind = 'other';
  let entity = sa.name;
  let label = sa.name;
  if (sa.name.startsWith('site-')) {
    kind = 'site';
    label = sa.name.slice(5);
    entity = `site:${label}`;
  } else if (sa.name === 'rw-eap' || sa.name === 'rw-cert') {
    kind = 'user';
    let id = sa['remote-eap-id'] || sa['remote-id'] || '';
    const cn = id.match(/CN=([^,]+)/);
    if (cn) id = cn[1];
    label = id;
    entity = `user:${id}`;
  }
  const children = Object.values(sa['child-sas'] || {}).map((c) => ({
    name: c.name,
    uniqueid: c.uniqueid,
    state: c.state,
    bytesIn: Number(c['bytes-in'] || 0),
    bytesOut: Number(c['bytes-out'] || 0),
    packetsIn: Number(c['packets-in'] || 0),
    packetsOut: Number(c['packets-out'] || 0),
    installTime: Number(c['install-time'] || 0),
    localTs: c['local-ts'] || [],
    remoteTs: c['remote-ts'] || [],
    encr: [c['encr-alg'], c['encr-keysize']].filter(Boolean).join('-'),
    integ: c['integ-alg'] || '',
  }));
  return {
    ikeId: sa.uniqueid,
    conn: sa.name,
    kind,
    entity,
    label,
    state: sa.state,
    version: sa.version,
    remoteHost: sa['remote-host'],
    remotePort: sa['remote-port'],
    remoteId: sa['remote-id'],
    eapId: sa['remote-eap-id'] || '',
    vips: sa['remote-vips'] || [],
    established: Number(sa.established || 0),
    ike: [sa['encr-alg'], sa['encr-keysize'], sa['integ-alg'] || sa['prf-alg'], sa['dh-group']].filter(Boolean).join(' / '),
    children,
    bytesIn: children.reduce((a, c) => a + c.bytesIn, 0),
    bytesOut: children.reduce((a, c) => a + c.bytesOut, 0),
    up: sa.state === 'ESTABLISHED' && children.some((c) => c.state === 'INSTALLED'),
  };
}

async function connections() {
  return (await strongswan.listSas()).map(describeSa);
}

// ---------- 采集 ----------
const lastCounters = new Map(); // `${ikeId}/${childId}` -> { in, out }
let lastIkes = new Map(); // ikeId -> { entity, remoteHost, vips }
let lastSnapshot = { ts: 0, conns: [], error: null };
let firstPoll = true;

async function poll() {
  let conns;
  try {
    conns = await connections();
  } catch (e) {
    lastSnapshot = { ts: now(), conns: [], error: e.message };
    return;
  }
  const ts = now();
  const bucket = Math.floor(ts / BUCKET) * BUCKET;
  const seenCounters = new Set();
  const ikes = new Map();
  const add = new Map(); // entity -> {rx, tx}

  for (const c of conns) {
    if (c.kind === 'other') continue;
    ikes.set(c.ikeId, { entity: c.entity, remoteHost: c.remoteHost, vips: c.vips });
    for (const ch of c.children) {
      const key = `${c.ikeId}/${ch.uniqueid}`;
      seenCounters.add(key);
      const prev = lastCounters.get(key);
      let dIn = ch.bytesIn;
      let dOut = ch.bytesOut;
      if (prev) {
        dIn = ch.bytesIn >= prev.in ? ch.bytesIn - prev.in : ch.bytesIn;
        dOut = ch.bytesOut >= prev.out ? ch.bytesOut - prev.out : ch.bytesOut;
      } else if (firstPoll) {
        // 面板刚启动时不知道之前采集到哪了，第一轮只记录基线，避免把历史流量算进当前 5 分钟
        dIn = 0;
        dOut = 0;
      }
      lastCounters.set(key, { in: ch.bytesIn, out: ch.bytesOut });
      if (dIn || dOut) {
        const a = add.get(c.entity) || { rx: 0, tx: 0 };
        a.rx += dIn;
        a.tx += dOut;
        add.set(c.entity, a);
      }
    }
  }
  for (const key of lastCounters.keys()) if (!seenCounters.has(key)) lastCounters.delete(key);

  q.tx(() => {
    for (const [entity, a] of add) {
      q.run(
        'INSERT INTO traffic (entity, bucket, rx, tx) VALUES (?, ?, ?, ?) ON CONFLICT(entity, bucket) DO UPDATE SET rx = rx + excluded.rx, tx = tx + excluded.tx',
        entity,
        bucket,
        a.rx,
        a.tx,
      );
    }
    // 上下线事件
    if (!firstPoll) {
      for (const [id, info] of ikes) {
        if (!lastIkes.has(id)) logEvent('up', info.entity, `来自 ${info.remoteHost}${info.vips.length ? `，分配 ${info.vips.join(', ')}` : ''}`);
      }
      for (const [id, info] of lastIkes) {
        if (!ikes.has(id)) logEvent('down', info.entity, `来自 ${info.remoteHost}`);
      }
    }
    for (const info of ikes.values()) {
      const [type, name] = info.entity.split(':');
      if (type === 'site') q.run('UPDATE sites SET last_seen = ? WHERE name = ?', ts, name);
      else if (type === 'user') q.run('UPDATE users SET last_seen = ? WHERE username = ?', ts, name);
    }
  });

  lastIkes = ikes;
  firstPoll = false;
  lastSnapshot = { ts, conns, error: null };
}

function snapshot() {
  return lastSnapshot;
}

function housekeeping() {
  const s = settings.getAll();
  const t = now();
  q.run('DELETE FROM traffic WHERE bucket < ?', t - Number(s.traffic_retention_days) * 86400);
  q.run('DELETE FROM events WHERE ts < ?', t - Number(s.events_retention_days) * 86400);
  q.run('DELETE FROM sessions WHERE expires_at < ?', t);
  q.run('DELETE FROM login_attempts WHERE ts < ?', t - 86400);
  q.run('DELETE FROM revoked_certs WHERE not_after < ?', t);
}

let timers = [];
function start() {
  const tick = () => poll().catch((e) => console.error('采集失败:', e.message));
  tick();
  timers.push(setInterval(tick, config.pollInterval * 1000));
  housekeeping();
  timers.push(
    setInterval(() => {
      try {
        housekeeping();
      } catch (e) {
        console.error('清理失败:', e.message);
      }
      strongswan.rotateLog();
    }, 3600 * 1000),
  );
  // 每天重新同步一次：刷新 CRL（有效期 30 天）并检查服务器证书是否需要续签
  timers.push(setInterval(() => strongswan.sync().catch((e) => console.error('每日同步失败:', e.message)), 86400 * 1000));
}

function stop() {
  timers.forEach(clearInterval);
  timers = [];
}

module.exports = { start, stop, poll, connections, describeSa, snapshot, BUCKET };
