'use strict';
// 用一个假的 charon VICI 服务端验证客户端的流式命令处理（list-sas）
const test = require('node:test');
const assert = require('node:assert');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');

const sock = process.platform === 'win32' ? `\\\\.\\pipe\\ipsp-vici-test-${process.pid}` : path.join(os.tmpdir(), `ipsp-vici-${process.pid}.sock`);
process.env.VICI_SOCKET = sock;
process.env.DATA_DIR = path.join(os.tmpdir(), `ipsp-vici-data-${process.pid}`);

const vici = require('../src/vici');
const { PKT, encodePacket, encodeMessage, decodePacket } = vici;

function fakeCharon() {
  return net.createServer((c) => {
    let buf = Buffer.alloc(0);
    let registered = null;
    c.on('data', (d) => {
      buf = Buffer.concat([buf, d]);
      while (buf.length >= 4) {
        const len = buf.readUInt32BE(0);
        if (buf.length < 4 + len) break;
        const pkt = decodePacket(buf.subarray(4, 4 + len));
        buf = buf.subarray(4 + len);
        if (pkt.type === PKT.EVENT_REGISTER) {
          registered = pkt.name;
          c.write(encodePacket(PKT.EVENT_CONFIRM));
        } else if (pkt.type === PKT.CMD_REQUEST && pkt.name === 'list-sas') {
          assert.strictEqual(registered, 'list-sa');
          // 分片写入，验证客户端的拼包逻辑
          const e1 = encodePacket(PKT.EVENT, 'list-sa', encodeMessage({ 'site-hq': { uniqueid: '1', state: 'ESTABLISHED', 'child-sas': { 'site-hq-1-5': { uniqueid: '5', 'bytes-in': '100', 'local-ts': ['10.10.0.0/24'] } } } }));
          const e2 = encodePacket(PKT.EVENT, 'list-sa', encodeMessage({ 'rw-eap': { uniqueid: '2', 'remote-eap-id': 'alice', 'remote-vips': ['10.10.0.10'] } }));
          const all = Buffer.concat([e1, e2, encodePacket(PKT.CMD_RESPONSE, null, encodeMessage({}))]);
          c.write(all.subarray(0, 7));
          setTimeout(() => c.write(all.subarray(7)), 20);
        } else if (pkt.type === PKT.CMD_REQUEST && pkt.name === 'version') {
          c.write(encodePacket(PKT.CMD_RESPONSE, null, encodeMessage({ daemon: 'charon', version: '5.9.13' })));
        } else if (pkt.type === PKT.CMD_REQUEST) {
          c.write(encodePacket(PKT.CMD_UNKNOWN));
        }
      }
    });
  });
}

test('VICI 客户端：普通命令、流式命令、未知命令', async () => {
  const server = fakeCharon();
  await new Promise((r) => server.listen(sock, r));
  try {
    const v = await vici.version();
    assert.strictEqual(v.version, '5.9.13');
    const sas = await vici.listSas();
    assert.strictEqual(sas.length, 2);
    assert.strictEqual(sas[0].name, 'site-hq');
    assert.deepStrictEqual(sas[0]['child-sas']['site-hq-1-5']['local-ts'], ['10.10.0.0/24']);
    assert.strictEqual(sas[1]['remote-eap-id'], 'alice');
    await assert.rejects(vici.call('no-such-cmd'), /不支持命令/);
  } finally {
    server.close();
  }
});
