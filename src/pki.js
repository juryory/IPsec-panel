'use strict';
// 证书管理：通过 openssl 命令行生成 CA / 服务器证书 / 用户证书 / CRL
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const config = require('./config');
const { run, isIPv4, randomString } = require('./util');

const dir = config.pkiDir;
const P = {
  caKey: path.join(dir, 'ca.key'),
  caCrt: path.join(dir, 'ca.crt'),
  serverKey: path.join(dir, 'server.key'),
  serverCrt: path.join(dir, 'server.crt'),
  users: path.join(dir, 'users'),
  tmp: path.join(dir, 'tmp'),
  index: path.join(dir, 'index.txt'),
  crlnumber: path.join(dir, 'crlnumber'),
  crl: path.join(dir, 'crl.pem'),
  caCnf: path.join(dir, 'openssl-ca.cnf'),
};

const CA_CN = 'IPsec Panel CA';
const SERVER_DAYS = 825; // Apple 对证书有效期有限制，825 天最稳妥；到期前 30 天自动续签
const USER_DAYS = 3650;

// openssl 配置文件里反斜杠是转义符，Windows 调试时统一换成正斜杠
const fwd = (p) => p.replace(/\\/g, '/');

function ensureDirs() {
  for (const d of [dir, P.users, P.tmp]) fs.mkdirSync(d, { recursive: true, mode: 0o700 });
}

function openssl(args, opts) {
  return run(config.opensslBin, args, opts);
}

function randomSerial() {
  // 8 字节，最高字节限定在 0x10-0x7f：保证为正数且没有前导 0，这样和 openssl 输出的格式一致
  const b = crypto.randomBytes(8);
  b[0] = 0x10 + (b[0] % 0x70);
  return b.toString('hex').toUpperCase();
}

function tmpFile(ext) {
  return path.join(P.tmp, `${Date.now()}-${randomString(8)}${ext}`);
}

async function withTmp(files, fn) {
  try {
    return await fn();
  } finally {
    for (const f of files) fs.rmSync(f, { force: true });
  }
}

function readCert(file) {
  if (!fs.existsSync(file)) return null;
  try {
    return new crypto.X509Certificate(fs.readFileSync(file));
  } catch {
    return null;
  }
}

function certInfo(file) {
  const c = readCert(file);
  if (!c) return null;
  return {
    subject: c.subject,
    issuer: c.issuer,
    san: c.subjectAltName || '',
    serial: c.serialNumber,
    validFrom: Math.floor(new Date(c.validFrom).getTime() / 1000),
    validTo: Math.floor(new Date(c.validTo).getTime() / 1000),
    fingerprint: c.fingerprint256,
  };
}

async function ensureCA() {
  ensureDirs();
  if (fs.existsSync(P.caKey) && fs.existsSync(P.caCrt)) return false;
  await openssl([
    'req', '-x509', '-new', '-newkey', 'rsa:3072', '-nodes', '-sha256',
    '-keyout', P.caKey, '-out', P.caCrt, '-days', '7300',
    '-subj', `/CN=${CA_CN}`,
    '-addext', 'basicConstraints=critical,CA:TRUE',
    '-addext', 'keyUsage=critical,keyCertSign,cRLSign',
    '-addext', 'subjectKeyIdentifier=hash',
  ]);
  fs.chmodSync(P.caKey, 0o600);
  if (!fs.existsSync(P.index)) fs.writeFileSync(P.index, '');
  fs.writeFileSync(P.crlnumber, '1000\n');
  return true;
}

async function signCsr(csrFile, crtFile, days, extLines) {
  const serial = randomSerial();
  const ext = tmpFile('.ext');
  fs.writeFileSync(ext, extLines.join('\n') + '\n');
  await withTmp([ext], () =>
    openssl([
      'x509', '-req', '-in', csrFile, '-CA', P.caCrt, '-CAkey', P.caKey,
      '-set_serial', `0x${serial}`, '-days', String(days), '-sha256',
      '-extfile', ext, '-out', crtFile,
    ]),
  );
  return serial;
}

// 服务器证书：SAN 必须包含客户端连接用的地址（IP 或域名），EKU 带 serverAuth + ikeIntermediate（macOS 需要）
function serverCertNeedsRenew(publicHost) {
  const info = certInfo(P.serverCrt);
  if (!info || !fs.existsSync(P.serverKey)) return true;
  const want = isIPv4(publicHost) ? `IP Address:${publicHost}` : `DNS:${publicHost}`;
  if (!info.san.split(/,\s*/).includes(want)) return true;
  if (info.validTo - Date.now() / 1000 < 30 * 86400) return true;
  return false;
}

async function issueServerCert(publicHost) {
  await ensureCA();
  const csr = tmpFile('.csr');
  const key = tmpFile('.key');
  await withTmp([csr, key], async () => {
    await openssl(['req', '-new', '-newkey', 'rsa:3072', '-nodes', '-keyout', key, '-out', csr, '-subj', `/CN=${publicHost}`]);
    const san = isIPv4(publicHost) ? `IP:${publicHost}` : `DNS:${publicHost}`;
    const crt = tmpFile('.crt');
    await withTmp([crt], async () => {
      await signCsr(csr, crt, SERVER_DAYS, [
        'basicConstraints=CA:FALSE',
        'keyUsage=critical,digitalSignature,keyEncipherment',
        'extendedKeyUsage=serverAuth,1.3.6.1.5.5.8.2.2',
        `subjectAltName=${san}`,
        'subjectKeyIdentifier=hash',
        'authorityKeyIdentifier=keyid,issuer',
      ]);
      fs.copyFileSync(key, P.serverKey);
      fs.chmodSync(P.serverKey, 0o600);
      fs.copyFileSync(crt, P.serverCrt);
    });
  });
  return certInfo(P.serverCrt);
}

async function ensureServerCert(publicHost) {
  if (!publicHost) return false;
  await ensureCA();
  if (!serverCertNeedsRenew(publicHost)) return false;
  await issueServerCert(publicHost);
  return true;
}

// 用户证书：CN 和 SAN(DNS) 都是用户名，IKE 身份用用户名即可
function userPaths(username) {
  return { key: path.join(P.users, `${username}.key`), crt: path.join(P.users, `${username}.crt`) };
}

async function issueUserCert(username) {
  await ensureCA();
  const up = userPaths(username);
  const csr = tmpFile('.csr');
  const key = tmpFile('.key');
  const crt = tmpFile('.crt');
  let serial;
  await withTmp([csr, key, crt], async () => {
    await openssl(['req', '-new', '-newkey', 'rsa:2048', '-nodes', '-keyout', key, '-out', csr, '-subj', `/CN=${username}`]);
    serial = await signCsr(csr, crt, USER_DAYS, [
      'basicConstraints=CA:FALSE',
      'keyUsage=critical,digitalSignature,keyEncipherment',
      'extendedKeyUsage=clientAuth',
      `subjectAltName=DNS:${username}`,
      'subjectKeyIdentifier=hash',
      'authorityKeyIdentifier=keyid,issuer',
    ]);
    fs.copyFileSync(key, up.key);
    fs.chmodSync(up.key, 0o600);
    fs.copyFileSync(crt, up.crt);
  });
  const info = certInfo(up.crt);
  return { serial, notAfter: info.validTo };
}

function removeUserFiles(username) {
  const up = userPaths(username);
  fs.rmSync(up.key, { force: true });
  fs.rmSync(up.crt, { force: true });
}

// 导出 p12；使用 3DES/SHA1 算法，兼容 Windows、macOS、iOS、Android 的导入
async function buildP12(username, password, friendlyName) {
  const up = userPaths(username);
  if (!fs.existsSync(up.crt) || !fs.existsSync(up.key)) throw new Error('用户证书不存在，请重新签发');
  const out = tmpFile('.p12');
  return withTmp([out], async () => {
    await openssl(
      [
        'pkcs12', '-export', '-inkey', up.key, '-in', up.crt, '-certfile', P.caCrt,
        '-name', friendlyName || username,
        '-keypbe', 'PBE-SHA1-3DES', '-certpbe', 'PBE-SHA1-3DES', '-macalg', 'sha1',
        '-passout', 'env:P12_PASS', '-out', out,
      ],
      { env: { P12_PASS: password } },
    );
    return fs.readFileSync(out);
  });
}

function asn1Time(sec) {
  const d = new Date(sec * 1000);
  const p = (n) => String(n).padStart(2, '0');
  return `${p(d.getUTCFullYear() % 100)}${p(d.getUTCMonth() + 1)}${p(d.getUTCDate())}${p(d.getUTCHours())}${p(d.getUTCMinutes())}${p(d.getUTCSeconds())}Z`;
}

// 根据数据库里的吊销列表重写 index.txt 并生成 CRL（禁用用户 = 临时吊销，启用后自动移出）
async function generateCrl(entries) {
  await ensureCA();
  const nowSec = Math.floor(Date.now() / 1000);
  const lines = entries
    .filter((e) => e.serial && e.notAfter > nowSec)
    .map((e) => ['R', asn1Time(e.notAfter), asn1Time(e.revokedAt || nowSec), e.serial.toUpperCase(), 'unknown', `/CN=${e.subject}`].join('\t'));
  fs.writeFileSync(P.index, lines.length ? lines.join('\n') + '\n' : '');
  fs.writeFileSync(P.index + '.attr', 'unique_subject = no\n');
  if (!fs.existsSync(P.crlnumber)) fs.writeFileSync(P.crlnumber, '1000\n');
  fs.writeFileSync(
    P.caCnf,
    [
      '[ ca ]',
      'default_ca = panel_ca',
      '[ panel_ca ]',
      `database = ${fwd(P.index)}`,
      `crlnumber = ${fwd(P.crlnumber)}`,
      `certificate = ${fwd(P.caCrt)}`,
      `private_key = ${fwd(P.caKey)}`,
      'default_md = sha256',
      'default_crl_days = 30',
      'unique_subject = no',
      'crl_extensions = crl_ext',
      '[ crl_ext ]',
      'authorityKeyIdentifier = keyid:always',
      '',
    ].join('\n'),
  );
  await openssl(['ca', '-config', P.caCnf, '-gencrl', '-out', P.crl]);
  return P.crl;
}

function caPem() {
  return fs.readFileSync(P.caCrt, 'utf8');
}

function pemToDer(pem) {
  const b64 = pem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
  return Buffer.from(b64, 'base64');
}

function caDer() {
  return pemToDer(caPem());
}

module.exports = {
  paths: P,
  CA_CN,
  ensureCA,
  ensureServerCert,
  issueServerCert,
  serverCertNeedsRenew,
  issueUserCert,
  removeUserFiles,
  userPaths,
  buildP12,
  generateCrl,
  certInfo,
  caPem,
  caDer,
  pemToDer,
};
