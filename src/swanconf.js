'use strict';
// 生成 swanctl.conf 片段（纯函数，方便测试）
const { swanIke, swanEsp, RW_IKE, RW_ESP } = require('./proposals');
const { activeSites, hubNetsForSite, userNets } = require('./model');

const FILES = {
  conf: 'ipsec-panel.conf',
  serverCert: 'ipsec-panel-server.pem',
  serverKey: 'ipsec-panel-server.pem',
  ca: 'ipsec-panel-ca.pem',
  crl: 'ipsec-panel.crl',
};

const quote = (s) => `"${String(s).replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;

class Writer {
  constructor() {
    this.lines = [];
    this.depth = 0;
  }
  line(s = '') {
    this.lines.push(s ? '  '.repeat(this.depth) + s : '');
  }
  kv(k, v) {
    this.line(`${k} = ${v}`);
  }
  open(name) {
    this.line(`${name} {`);
    this.depth++;
  }
  close() {
    this.depth--;
    this.line('}');
  }
  toString() {
    return this.lines.join('\n') + '\n';
  }
}

function siteConnName(site) {
  return `site-${site.name}`;
}

// 所有连接都监听 %any，charon 在知道对端身份之前就要按地址选 IKE 配置，
// 所以每个连接的 IKE 提议都附带其它连接用到的提议（自己的排在最前），避免选错配置导致 NO_PROPOSAL_CHOSEN
function ikeProposals(state, own) {
  const all = [...own.split(/,\s*/), ...activeSites(state).map((s) => swanIke(s.crypto_preset)), ...RW_IKE.split(/,\s*/)];
  const uniq = [...new Set(all.filter((p) => p !== 'default'))];
  return [...uniq, 'default'].join(', ');
}

function writeSite(w, state, site) {
  const hubNets = hubNetsForSite(state, site);
  const conn = siteConnName(site);
  w.open(conn);
  w.kv('version', site.ike_version);
  if (site.ike_version === 1) w.kv('aggressive', 'yes');
  w.kv('local_addrs', '%any');
  w.kv('remote_addrs', '%any');
  w.kv('proposals', ikeProposals(state, swanIke(site.crypto_preset)));
  w.kv('dpd_delay', '30s');
  // H3C 是发起方，负责重协商；云端不主动 rekey，避免两边同时 rekey 冲突
  w.kv('rekey_time', '0s');
  if (site.ike_version === 1) w.kv('reauth_time', '0s');
  w.open('local');
  w.kv('auth', 'psk');
  w.kv('id', state.settings.hub_id);
  w.close();
  w.open('remote');
  w.kv('auth', 'psk');
  w.kv('id', site.local_id);
  w.close();
  w.open('children');
  const child = (name, local, remote) => {
    w.open(name);
    w.kv('local_ts', local.join(', '));
    w.kv('remote_ts', remote.join(', '));
    w.kv('esp_proposals', swanEsp(site.crypto_preset));
    w.kv('mode', 'tunnel');
    w.kv('dpd_action', 'clear');
    w.kv('rekey_time', '0s');
    w.close();
  };
  if (site.ike_version === 1) {
    // IKEv1 每个 CHILD_SA 只能协商一对网段，H3C 也是每条 ACL 规则一个 SA，所以按网段对展开
    let i = 1;
    for (const l of hubNets) for (const r of site.subnets) child(`${conn}-${i++}`, [l], [r]);
  } else {
    child(conn, hubNets, site.subnets);
  }
  w.close();
  w.close();
}

function writeRoadWarrior(w, state, name, remoteAuth, opts) {
  w.open(name);
  w.kv('version', 2);
  w.kv('local_addrs', '%any');
  w.kv('remote_addrs', '%any');
  w.kv('pools', 'rw-pool');
  w.kv('proposals', ikeProposals(state, RW_IKE));
  w.kv('send_cert', 'always');
  w.kv('fragmentation', 'yes');
  w.kv('dpd_delay', '60s');
  w.kv('rekey_time', '0s');
  if (remoteAuth === 'eap') w.kv('send_certreq', 'no');
  w.open('local');
  w.kv('auth', 'pubkey');
  w.kv('certs', FILES.serverCert);
  w.kv('id', state.settings.public_host);
  w.close();
  w.open('remote');
  if (remoteAuth === 'eap') {
    w.kv('auth', 'eap-mschapv2');
    w.kv('eap_id', '%any');
  } else {
    w.kv('auth', 'pubkey');
    w.kv('cacerts', FILES.ca);
    w.kv('revocation', 'relaxed');
  }
  w.close();
  w.open('children');
  w.open('rw');
  w.kv('local_ts', opts.nets.join(', '));
  w.kv('esp_proposals', RW_ESP);
  w.kv('dpd_action', 'clear');
  w.kv('rekey_time', '0s');
  w.close();
  w.close();
  w.close();
}

/**
 * @param state loadState() 的结果
 * @param opts { rwEnabled: 是否已有服务器证书（没有公网地址时不生成远程用户连接） }
 */
function buildSwanctlConf(state, opts = {}) {
  const w = new Writer();
  w.line('# 由 IPsec Panel 自动生成，手动修改会被覆盖');
  w.open('connections');
  for (const site of activeSites(state)) writeSite(w, state, site);
  if (opts.rwEnabled) {
    const nets = userNets(state);
    // 证书认证放前面：客户端不带 AUTH 载荷（要走 EAP）时 charon 会自动切换到 rw-eap
    writeRoadWarrior(w, state, 'rw-cert', 'cert', { nets });
    writeRoadWarrior(w, state, 'rw-eap', 'eap', { nets });
  }
  w.close();
  w.line();

  if (opts.rwEnabled) {
    w.open('pools');
    w.open('rw-pool');
    w.kv('addrs', state.tunnel.poolRange);
    const dns = (state.settings.client_dns || '').split(',').filter(Boolean);
    if (dns.length) w.kv('dns', dns.join(', '));
    w.close();
    w.close();
    w.line();
  }

  w.open('secrets');
  let n = 1;
  for (const site of activeSites(state)) {
    w.open(`ike-${n++}`);
    w.kv('id-hub', state.settings.hub_id);
    w.kv('id-peer', site.local_id);
    w.kv('secret', quote(site.psk));
    w.close();
  }
  if (opts.rwEnabled) {
    n = 1;
    for (const u of state.users) {
      if (!u.enabled || u.auth_type !== 'eap' || !u.nt_hash) continue;
      w.open(`ntlm-${n++}`);
      w.kv('id', u.username);
      w.kv('secret', `0x${u.nt_hash}`);
      w.close();
    }
  }
  w.close();
  return w.toString();
}

// 给前端展示用：隐藏密钥
function maskSecrets(text) {
  return text.replace(/(secret = ).*/g, '$1******');
}

module.exports = { buildSwanctlConf, maskSecrets, siteConnName, FILES };
