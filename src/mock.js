'use strict';
// 开发模式（npm run dev / MOCK=1）下模拟 strongSwan，方便在没有 charon 的机器上调界面
const { activeSites, hubNetsForSite, userNets } = require('./model');

const t0 = Math.floor(Date.now() / 1000);
const killed = new Set();

function status() {
  return { running: true, version: 'charon 5.9.13 (mock)', system: 'Linux mock x86_64', since: new Date(t0 * 1000).toISOString(), ikeSas: 0, halfOpen: 0 };
}

function counter(seed, rate) {
  const el = Math.floor(Date.now() / 1000) - t0;
  return String(Math.floor(el * rate * (1 + Math.sin(el / 60 + seed) * 0.5)) + seed * 1000);
}

function listSas(state) {
  const out = [];
  let id = 1;
  activeSites(state).forEach((s, i) => {
    const uid = id++;
    if (i % 3 === 2 || killed.has(String(uid))) return;
    out.push({
      name: `site-${s.name}`,
      uniqueid: String(uid),
      version: String(s.ike_version),
      state: 'ESTABLISHED',
      'remote-host': `113.${10 + i}.${20 + i}.${30 + i}`,
      'remote-port': '4500',
      'remote-id': s.local_id,
      established: String(Math.floor(Date.now() / 1000) - t0 + 120),
      'child-sas': {
        [`site-${s.name}-1`]: {
          name: `site-${s.name}`,
          uniqueid: String(uid * 10),
          state: 'INSTALLED',
          'bytes-in': counter(uid, 20000),
          'bytes-out': counter(uid + 7, 50000),
          'install-time': '300',
          'local-ts': hubNetsForSite(state, s),
          'remote-ts': s.subnets,
        },
      },
    });
  });
  state.users
    .filter((u) => u.enabled)
    .forEach((u, i) => {
      const uid = 100 + i;
      if (i % 2 === 1 || killed.has(String(uid))) return;
      out.push({
        name: u.auth_type === 'cert' ? 'rw-cert' : 'rw-eap',
        uniqueid: String(uid),
        version: '2',
        state: 'ESTABLISHED',
        'remote-host': `223.5.${i}.${8 + i}`,
        'remote-port': '4500',
        'remote-id': u.auth_type === 'cert' ? u.username : `192.168.31.${10 + i}`,
        'remote-eap-id': u.auth_type === 'eap' ? u.username : undefined,
        'remote-vips': [`${state.tunnel.poolStart.replace(/\d+$/, '')}${10 + i}`],
        established: String(Math.floor(Date.now() / 1000) - t0 + 30),
        'child-sas': {
          'rw-1': {
            name: 'rw',
            uniqueid: String(uid * 10),
            state: 'INSTALLED',
            'bytes-in': counter(uid, 3000),
            'bytes-out': counter(uid + 3, 12000),
            'install-time': '60',
            'local-ts': userNets(state),
            'remote-ts': [`${state.tunnel.poolStart.replace(/\d+$/, '')}${10 + i}/32`],
          },
        },
      });
    });
  return out;
}

function terminate(ikeId) {
  killed.add(String(ikeId));
  setTimeout(() => killed.delete(String(ikeId)), 60000);
  return { success: 'yes' };
}

function log() {
  return [
    '2026-01-01 00:00:00 00[DMN] Starting IKE charon daemon (strongSwan 5.9.13, mock)',
    '2026-01-01 00:00:01 08[CFG] loaded IKE shared key with id \'ike-1\' for: \'ipsec-hub\', \'hq.ipsec\'',
    '2026-01-01 00:00:05 12[IKE] <site-hq|1> IKE_SA site-hq[1] established between 10.0.0.4[ipsec-hub]...113.10.20.30[hq.ipsec]',
  ].join('\n');
}

module.exports = { status, listSas, terminate, log };
