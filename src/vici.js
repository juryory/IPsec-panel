'use strict';
// strongSwan VICI 协议客户端（纯 JS 实现，无需 python/davici）
// 协议说明: https://github.com/strongswan/strongswan/blob/master/src/libcharon/plugins/vici/README.md
const net = require('node:net');
const config = require('./config');

const PKT = {
  CMD_REQUEST: 0,
  CMD_RESPONSE: 1,
  CMD_UNKNOWN: 2,
  EVENT_REGISTER: 3,
  EVENT_UNREGISTER: 4,
  EVENT_CONFIRM: 5,
  EVENT_UNKNOWN: 6,
  EVENT: 7,
};
const EL = {
  SECTION_START: 1,
  SECTION_END: 2,
  KEY_VALUE: 3,
  LIST_START: 4,
  LIST_ITEM: 5,
  LIST_END: 6,
};

function nameBuf(name) {
  const b = Buffer.from(name, 'utf8');
  if (b.length > 255) throw new Error('VICI name too long');
  return Buffer.concat([Buffer.from([b.length]), b]);
}

function valueBuf(value) {
  const b = Buffer.isBuffer(value) ? value : Buffer.from(String(value), 'utf8');
  if (b.length > 65535) throw new Error('VICI value too long');
  const len = Buffer.alloc(2);
  len.writeUInt16BE(b.length);
  return Buffer.concat([len, b]);
}

function encodeMessage(obj) {
  const parts = [];
  for (const [k, v] of Object.entries(obj || {})) {
    if (v === undefined || v === null) continue;
    if (Array.isArray(v)) {
      parts.push(Buffer.from([EL.LIST_START]), nameBuf(k));
      for (const item of v) parts.push(Buffer.from([EL.LIST_ITEM]), valueBuf(item));
      parts.push(Buffer.from([EL.LIST_END]));
    } else if (typeof v === 'object' && !Buffer.isBuffer(v)) {
      parts.push(Buffer.from([EL.SECTION_START]), nameBuf(k), encodeMessage(v), Buffer.from([EL.SECTION_END]));
    } else {
      parts.push(Buffer.from([EL.KEY_VALUE]), nameBuf(k), valueBuf(v));
    }
  }
  return Buffer.concat(parts);
}

function decodeMessage(buf) {
  const root = {};
  const stack = [root];
  let list = null;
  let i = 0;
  const readName = () => {
    const len = buf[i++];
    const s = buf.toString('utf8', i, i + len);
    i += len;
    return s;
  };
  const readValue = () => {
    const len = buf.readUInt16BE(i);
    i += 2;
    const s = buf.toString('utf8', i, i + len);
    i += len;
    return s;
  };
  while (i < buf.length) {
    const type = buf[i++];
    const cur = stack[stack.length - 1];
    switch (type) {
      case EL.SECTION_START: {
        const name = readName();
        const sec = {};
        cur[name] = sec;
        stack.push(sec);
        break;
      }
      case EL.SECTION_END:
        if (stack.length > 1) stack.pop();
        break;
      case EL.KEY_VALUE: {
        const name = readName();
        cur[name] = readValue();
        break;
      }
      case EL.LIST_START: {
        const name = readName();
        list = [];
        cur[name] = list;
        break;
      }
      case EL.LIST_ITEM:
        if (list) list.push(readValue());
        else readValue();
        break;
      case EL.LIST_END:
        list = null;
        break;
      default:
        throw new Error(`VICI: unknown element type ${type}`);
    }
  }
  return root;
}

function encodePacket(type, name, message) {
  const parts = [Buffer.from([type])];
  if (name !== null && name !== undefined) parts.push(nameBuf(name));
  if (message) parts.push(message);
  const payload = Buffer.concat(parts);
  const len = Buffer.alloc(4);
  len.writeUInt32BE(payload.length);
  return Buffer.concat([len, payload]);
}

function decodePacket(payload) {
  const type = payload[0];
  let i = 1;
  let name = null;
  if (type === PKT.CMD_REQUEST || type === PKT.EVENT_REGISTER || type === PKT.EVENT_UNREGISTER || type === PKT.EVENT) {
    const len = payload[i++];
    name = payload.toString('utf8', i, i + len);
    i += len;
  }
  let message = null;
  if (type === PKT.CMD_REQUEST || type === PKT.CMD_RESPONSE || type === PKT.EVENT) {
    message = decodeMessage(payload.subarray(i));
  }
  return { type, name, message };
}

// 发一条命令；streamEvent 用于 list-sas 这类流式命令（先注册事件，再收集事件直到命令响应）
function call(command, message = {}, { streamEvent = null, timeout = 15000 } = {}) {
  return new Promise((resolve, reject) => {
    const sock = net.createConnection(config.viciSocket);
    let buf = Buffer.alloc(0);
    const events = [];
    let stage = streamEvent ? 'register' : 'command';
    let done = false;

    const finish = (err, val) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      sock.destroy();
      if (err) reject(err);
      else resolve(val);
    };
    const timer = setTimeout(() => finish(new Error(`VICI ${command} 超时`)), timeout);

    sock.on('connect', () => {
      if (streamEvent) sock.write(encodePacket(PKT.EVENT_REGISTER, streamEvent));
      else sock.write(encodePacket(PKT.CMD_REQUEST, command, encodeMessage(message)));
    });
    sock.on('error', (e) => finish(new Error(`无法连接 strongSwan VICI (${config.viciSocket}): ${e.message}`)));
    sock.on('close', () => finish(new Error('VICI 连接意外关闭')));
    sock.on('data', (chunk) => {
      buf = Buffer.concat([buf, chunk]);
      while (buf.length >= 4) {
        const len = buf.readUInt32BE(0);
        if (buf.length < 4 + len) break;
        const pkt = decodePacket(buf.subarray(4, 4 + len));
        buf = buf.subarray(4 + len);
        try {
          if (stage === 'register') {
            if (pkt.type === PKT.EVENT_CONFIRM) {
              stage = 'command';
              sock.write(encodePacket(PKT.CMD_REQUEST, command, encodeMessage(message)));
            } else if (pkt.type === PKT.EVENT_UNKNOWN) {
              return finish(new Error(`VICI 不支持事件 ${streamEvent}`));
            }
          } else if (pkt.type === PKT.EVENT) {
            if (pkt.name === streamEvent) events.push(pkt.message);
          } else if (pkt.type === PKT.CMD_RESPONSE) {
            return finish(null, { response: pkt.message, events });
          } else if (pkt.type === PKT.CMD_UNKNOWN) {
            return finish(new Error(`VICI 不支持命令 ${command}`));
          }
        } catch (e) {
          return finish(e);
        }
      }
    });
  });
}

// ---------- 常用命令封装 ----------
async function version() {
  return (await call('version')).response;
}

async function stats() {
  return (await call('stats')).response;
}

// 返回 [{ name, ...ikeSa }]
async function listSas() {
  const { events } = await call('list-sas', {}, { streamEvent: 'list-sa', timeout: 20000 });
  const out = [];
  for (const ev of events) {
    for (const [name, sa] of Object.entries(ev)) out.push({ name, ...sa });
  }
  return out;
}

async function terminateIke(ikeId) {
  const { response } = await call('terminate', { 'ike-id': String(ikeId), force: 'yes', timeout: '3000' });
  if (response.success !== 'yes') throw new Error(response.errmsg || '断开失败');
  return response;
}

async function reloadSettings() {
  return (await call('reload-settings')).response;
}

module.exports = { call, version, stats, listSas, terminateIke, reloadSettings, encodeMessage, decodeMessage, encodePacket, decodePacket, PKT };
