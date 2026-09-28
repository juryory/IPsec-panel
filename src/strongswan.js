'use strict';
// strongSwan 操作：写配置、加载、重启、状态、日志。面板只是“薄壳”，停掉面板不影响 VPN。
const fs = require('node:fs');
const path = require('node:path');
const config = require('./config');
const vici = require('./vici');
const pki = require('./pki');
const mock = require('./mock');
const netsetup = require('./netsetup');
const { buildSwanctlConf, FILES } = require('./swanconf');
const { loadState } = require('./model');
const { run, splitCommand, createMutex } = require('./util');
const { logEvent } = require('./db');

const lock = createMutex();
const D = (sub) => path.join(config.swanctlDir, sub);

function writeFileSecure(file, content, mode = 0o600) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const tmp = `${file}.tmp`;
  fs.writeFileSync(tmp, content, { mode });
  fs.renameSync(tmp, file);
  try {
    fs.chmodSync(file, mode);
  } catch {}
}

// 生成 CRL 所需的吊销条目：已吊销/禁用的证书用户 + 历史作废证书
function crlEntries(state) {
  const { q } = require('./db');
  const entries = q.all('SELECT serial, subject, not_after AS notAfter, revoked_at AS revokedAt FROM revoked_certs');
  for (const u of state.users) {
    if (u.auth_type === 'cert' && u.cert_serial && (!u.enabled || u.cert_revoked)) {
      entries.push({ serial: u.cert_serial, subject: u.username, notAfter: u.cert_not_after, revokedAt: u.updated_at });
    }
  }
  return entries;
}

async function preparePki(state) {
  const s = state.settings;
  if (!s.public_host) return false;
  await pki.ensureCA();
  if (s.cert_mode === 'custom') {
    if (!fs.existsSync(s.custom_cert_path) || !fs.existsSync(s.custom_key_path)) {
      throw new Error('自定义证书文件不存在，请检查设置中的路径');
    }
  } else {
    await pki.ensureServerCert(s.public_host);
  }
  await pki.generateCrl(crlEntries(state));
  return true;
}

function installCredentials(state) {
  const s = state.settings;
  writeFileSecure(D(`x509ca/${FILES.ca}`), fs.readFileSync(pki.paths.caCrt), 0o644);
  writeFileSecure(D(`x509crl/${FILES.crl}`), fs.readFileSync(pki.paths.crl), 0o644);
  // 清掉旧的证书链文件
  const caDir = D('x509ca');
  for (const f of fs.readdirSync(caDir)) if (f.startsWith('ipsec-panel-chain-')) fs.rmSync(path.join(caDir, f));
  if (s.cert_mode === 'custom') {
    writeFileSecure(D(`x509/${FILES.serverCert}`), fs.readFileSync(s.custom_cert_path), 0o644);
    writeFileSecure(D(`private/${FILES.serverKey}`), fs.readFileSync(s.custom_key_path));
    if (s.custom_chain_path && fs.existsSync(s.custom_chain_path)) {
      const chain = fs.readFileSync(s.custom_chain_path, 'utf8').match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g) || [];
      chain.forEach((pem, i) => writeFileSecure(D(`x509ca/ipsec-panel-chain-${i + 1}.pem`), pem + '\n', 0o644));
    }
  } else {
    writeFileSecure(D(`x509/${FILES.serverCert}`), fs.readFileSync(pki.paths.serverCrt), 0o644);
    writeFileSecure(D(`private/${FILES.serverKey}`), fs.readFileSync(pki.paths.serverKey));
  }
}

async function swanctl(args) {
  if (config.mock) return { stdout: `[mock] swanctl ${args.join(' ')}`, stderr: '' };
  return run(config.swanctlBin, args, { timeout: 60000 });
}

// 根据数据库重新生成全部配置并加载到 charon
function sync(reason = '') {
  return lock(async () => {
    const state = loadState();
    const rwEnabled = await preparePki(state);
    if (rwEnabled) installCredentials(state);
    const text = buildSwanctlConf(state, { rwEnabled });
    writeFileSecure(D(`conf.d/${FILES.conf}`), text);
    await netsetup.apply(state);
    const { stdout } = await swanctl(['--load-all', '--noprompt']);
    if (reason) logEvent('system', '', `配置已重新加载：${reason}`);
    return { output: stdout, rwEnabled };
  });
}

// 等待 charon 的 VICI 套接字就绪
async function waitReady(timeoutMs = 30000) {
  if (config.mock) return true;
  const t0 = Date.now();
  while (Date.now() - t0 < timeoutMs) {
    try {
      await vici.version();
      return true;
    } catch {
      await new Promise((r) => setTimeout(r, 1000));
    }
  }
  return false;
}

async function restart() {
  if (!config.mock) {
    const [cmd, ...args] = splitCommand(config.restartCmd);
    await run(cmd, args, { timeout: 60000 });
    await new Promise((r) => setTimeout(r, 1500));
    if (!(await waitReady(30000))) throw new Error('strongSwan 重启后 30 秒内未就绪，请查看日志');
  }
  logEvent('system', '', 'strongSwan 已重启');
  return sync();
}

async function status() {
  if (config.mock) return mock.status();
  try {
    const [ver, st] = await Promise.all([vici.version(), vici.stats()]);
    return {
      running: true,
      version: `${ver.daemon} ${ver.version}`,
      system: `${ver.sysname} ${ver.release} ${ver.machine}`,
      since: st.uptime && st.uptime.since,
      running_for: st.uptime && st.uptime.running,
      ikeSas: st.ikesas ? Number(st.ikesas.total) : 0,
      halfOpen: st.ikesas ? Number(st.ikesas['half-open']) : 0,
    };
  } catch (e) {
    return { running: false, error: e.message };
  }
}

async function listSas() {
  if (config.mock) return mock.listSas(loadState());
  return vici.listSas();
}

async function terminate(ikeId) {
  if (config.mock) return mock.terminate(ikeId);
  return vici.terminateIke(ikeId);
}

// 读取 charon 日志：优先读面板配置的日志文件，没有则尝试 journalctl
async function readLog(lines = 300) {
  lines = Math.min(Math.max(parseInt(lines, 10) || 300, 10), 5000);
  if (fs.existsSync(config.charonLog)) {
    const stat = fs.statSync(config.charonLog);
    const size = Math.min(stat.size, lines * 400);
    const fd = fs.openSync(config.charonLog, 'r');
    const buf = Buffer.alloc(size);
    fs.readSync(fd, buf, 0, size, stat.size - size);
    fs.closeSync(fd);
    const all = buf.toString('utf8').split('\n');
    if (size < stat.size) all.shift();
    return { source: config.charonLog, text: all.slice(-lines).join('\n') };
  }
  if (config.mock) return { source: 'mock', text: mock.log() };
  try {
    const { stdout } = await run('journalctl', ['-u', config.journalUnit, '-n', String(lines), '--no-pager', '-o', 'short-iso']);
    return { source: `journalctl -u ${config.journalUnit}`, text: stdout };
  } catch (e) {
    return { source: 'none', text: `无法读取日志：${e.message}` };
  }
}

// 日志文件超过 20MB 时轮转，并通知 charon 重新打开日志文件
async function rotateLog() {
  try {
    if (!fs.existsSync(config.charonLog)) return;
    if (fs.statSync(config.charonLog).size < 20 * 1024 * 1024) return;
    fs.renameSync(config.charonLog, `${config.charonLog}.1`);
    if (!config.mock) await vici.reloadSettings();
  } catch (e) {
    console.error('日志轮转失败:', e.message);
  }
}

function generatedConf() {
  const file = D(`conf.d/${FILES.conf}`);
  return fs.existsSync(file) ? fs.readFileSync(file, 'utf8') : '';
}

module.exports = { sync, restart, status, listSas, terminate, readLog, rotateLog, waitReady, generatedConf };
