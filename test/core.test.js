'use strict';
const test = require('node:test');
const assert = require('node:assert');
const os = require('node:os');
const fs = require('node:fs');
const path = require('node:path');

// 使用临时数据目录，避免碰到真实数据库
process.env.DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'ipsp-test-'));
process.env.MOCK = '1';

const { md4, ntHash } = require('../src/md4');
const vici = require('../src/vici');
const U = require('../src/util');
const { buildSwanctlConf } = require('../src/swanconf');
const h3c = require('../src/h3c');
const { DEFAULTS } = require('../src/settings');

test('md4 / NT hash 标准向量', () => {
  assert.strictEqual(md4('').toString('hex'), '31d6cfe0d16ae931b73c59d7e0c089c0');
  assert.strictEqual(md4('abc').toString('hex'), 'a448017aaf21d8525fc10ae87aa6729d');
  assert.strictEqual(md4('message digest').toString('hex'), 'd9130a8164549fe818874806e1c7014b');
  assert.strictEqual(ntHash('password'), '8846f7eaee8fb117ad06bdd830b7586c');
});

test('VICI 消息编解码往返', () => {
  const msg = { a: '1', sec: { b: 'x', list: ['p', 'q'], inner: { c: '' } }, l2: [] };
  const back = vici.decodeMessage(vici.encodeMessage(msg));
  assert.deepStrictEqual(back, msg);
  const pkt = vici.encodePacket(vici.PKT.CMD_REQUEST, 'version', vici.encodeMessage({ k: 'v' }));
  assert.strictEqual(pkt.readUInt32BE(0), pkt.length - 4);
  const dec = vici.decodePacket(pkt.subarray(4));
  assert.strictEqual(dec.name, 'version');
  assert.deepStrictEqual(dec.message, { k: 'v' });
});

test('CIDR 工具', () => {
  assert.strictEqual(U.parseCidr('192.168.1.5/24').cidr, '192.168.1.0/24');
  assert.strictEqual(U.parseCidr('10.0.0.0/8').wildcard, '0.255.255.255');
  assert.strictEqual(U.parseCidr('300.1.1.1/24'), null);
  assert.ok(U.cidrOverlap('192.168.0.0/16', '192.168.5.0/24'));
  assert.ok(!U.cidrOverlap('192.168.1.0/24', '192.168.2.0/24'));
  const t = U.tunnelInfo('10.10.0.0/24');
  assert.strictEqual(t.hubIp, '10.10.0.1');
  assert.strictEqual(t.poolRange, '10.10.0.10-10.10.0.254');
  assert.throws(() => U.tunnelInfo('10.10.0.0/30'));
});

function fakeState(extra = {}) {
  const settings = { ...DEFAULTS, public_host: '203.0.113.10', ...extra };
  return {
    settings,
    tunnel: U.tunnelInfo(settings.tunnel_net),
    sites: [
      { id: 1, name: 'hq', enabled: 1, device_type: 'comware7', ike_version: 1, crypto_preset: 'strong', local_id: 'hq.ipsec', psk: 'pskHQ12345', subnets: ['192.168.1.0/24'], lan_ip: '', wan_interface: 'GigabitEthernet0/0', acl_number: 3100, keepalive: 1, mesh: 1, allow_users: 1 },
      { id: 2, name: 'br', enabled: 1, device_type: 'comware7', ike_version: 2, crypto_preset: 'standard', local_id: 'br.ipsec', psk: 'pskBR12345', subnets: ['192.168.2.0/24', '192.168.3.0/24'], lan_ip: '192.168.2.254', wan_interface: 'Dialer0', acl_number: 3200, keepalive: 1, mesh: 1, allow_users: 0 },
      { id: 3, name: 'off', enabled: 0, device_type: 'er', ike_version: 1, crypto_preset: 'compat', local_id: 'off.ipsec', psk: 'pskOFF1234', subnets: ['192.168.9.0/24'], lan_ip: '', wan_interface: 'WAN1', acl_number: 3100, keepalive: 1, mesh: 1, allow_users: 1 },
    ],
    users: [
      { id: 1, username: 'alice', auth_type: 'eap', nt_hash: ntHash('password'), enabled: 1 },
      { id: 2, username: 'bob', auth_type: 'eap', nt_hash: ntHash('x'), enabled: 0 },
    ],
  };
}

test('swanctl 配置：站点、互通、远程用户', () => {
  const conf = buildSwanctlConf(fakeState(), { rwEnabled: true });
  // IKEv1 站点按网段对展开 child，含互通网段
  assert.match(conf, /site-hq \{\n\s+version = 1\n\s+aggressive = yes/);
  assert.match(conf, /site-hq-1 \{\n\s+local_ts = 10\.10\.0\.0\/24\n\s+remote_ts = 192\.168\.1\.0\/24/);
  assert.match(conf, /local_ts = 192\.168\.2\.0\/24\n\s+remote_ts = 192\.168\.1\.0\/24/);
  // IKEv2 站点一个 child 多网段
  assert.match(conf, /site-br \{\n\s+local_ts = 10\.10\.0\.0\/24, 192\.168\.1\.0\/24\n\s+remote_ts = 192\.168\.2\.0\/24, 192\.168\.3\.0\/24/);
  // 禁用站点不出现
  assert.doesNotMatch(conf, /site-off/);
  // 远程用户：不允许访问 br
  assert.match(conf, /rw-eap[\s\S]+local_ts = 10\.10\.0\.0\/24, 192\.168\.1\.0\/24\n/);
  // 禁用用户没有密钥
  assert.match(conf, /id = alice\n\s+secret = 0x8846f7eaee8fb117ad06bdd830b7586c/);
  assert.doesNotMatch(conf, /id = bob/);
  assert.match(conf, /addrs = 10\.10\.0\.10-10\.10\.0\.254/);
  // PSK 用引号包裹
  assert.match(conf, /secret = "pskHQ12345"/);
});

test('swanctl 配置：关闭互通 / 无公网地址', () => {
  const conf = buildSwanctlConf(fakeState({ site_mesh: '0' }), { rwEnabled: false });
  assert.doesNotMatch(conf, /rw-eap/);
  assert.doesNotMatch(conf, /pools/);
  assert.match(conf, /site-br \{\n\s+local_ts = 10\.10\.0\.0\/24\n/);
});

test('H3C Comware V7 IKEv1 配置', () => {
  const state = fakeState();
  const g = h3c.generate(state, state.sites[0]);
  assert.strictEqual(g.format, 'cli');
  assert.match(g.text, /rule 5 permit ip source 192\.168\.1\.0 0\.0\.0\.255 destination 10\.10\.0\.0 0\.0\.0\.255/);
  assert.match(g.text, /rule 10 permit ip source 192\.168\.1\.0 0\.0\.0\.255 destination 192\.168\.2\.0 0\.0\.0\.255/);
  assert.match(g.text, /pre-shared-key address 203\.0\.113\.10 255\.255\.255\.255 key simple pskHQ12345/);
  assert.match(g.text, /exchange-mode aggressive/);
  assert.match(g.text, /local-identity fqdn hq\.ipsec/);
  assert.match(g.text, /match remote identity fqdn ipsec-hub/);
  assert.match(g.text, /destination ip 10\.10\.0\.1\n\s+source ip 192\.168\.1\.1/);
  assert.ok(g.commands.every((c) => !c.cmd.startsWith('#')));
  assert.ok(g.commands.find((c) => c.cmd.startsWith('undo acl')).tolerate);
});

test('H3C Comware V7 IKEv2 与指纹变化', () => {
  const state = fakeState();
  const g = h3c.generate(state, state.sites[1]);
  assert.match(g.text, /ikev2 profile ipsp-hub/);
  assert.match(g.text, /identity local fqdn br\.ipsec/);
  assert.match(g.text, /interface Dialer0\n ipsec apply policy ipsp-hub/);
  assert.match(g.text, /source ip 192\.168\.2\.254/);
  const h1 = h3c.configHash(state, state.sites[1]);
  state.settings.site_mesh = '0';
  assert.notStrictEqual(h3c.configHash(state, state.sites[1]), h1);
});

test('H3C ER 指南', () => {
  const state = fakeState();
  const site = { ...state.sites[2], enabled: 1 };
  const g = h3c.generate(state, site);
  assert.strictEqual(g.format, 'guide');
  assert.ok(g.sections.length >= 4);
  assert.match(g.text, /野蛮模式/);
  assert.match(g.text, /group2/);
});
