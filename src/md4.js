'use strict';
// MD4 (RFC 1320)。OpenSSL 3 默认不再提供 MD4，而 EAP-MSCHAPv2 需要 NT Hash = MD4(UTF-16LE(password))，
// 所以这里自己实现，这样数据库里只保存 NT Hash，不保存明文密码。

function md4(input) {
  const buf = Buffer.isBuffer(input) ? input : Buffer.from(input);
  const len = buf.length;
  const nBlocks = ((len + 8) >>> 6) + 1;
  const words = new Uint32Array(nBlocks * 16);
  for (let i = 0; i < len; i++) words[i >> 2] |= buf[i] << ((i % 4) * 8);
  words[len >> 2] |= 0x80 << ((len % 4) * 8);
  const bitLen = len * 8;
  words[nBlocks * 16 - 2] = bitLen >>> 0;
  words[nBlocks * 16 - 1] = Math.floor(bitLen / 0x100000000);

  const rotl = (x, n) => (x << n) | (x >>> (32 - n));
  const F = (x, y, z) => (x & y) | (~x & z);
  const G = (x, y, z) => (x & y) | (x & z) | (y & z);
  const H = (x, y, z) => x ^ y ^ z;

  let a = 0x67452301;
  let b = 0xefcdab89 | 0;
  let c = 0x98badcfe | 0;
  let d = 0x10325476;

  for (let i = 0; i < words.length; i += 16) {
    const X = words.subarray(i, i + 16);
    const aa = a, bb = b, cc = c, dd = d;

    for (const k of [0, 4, 8, 12]) {
      a = rotl((a + F(b, c, d) + X[k]) | 0, 3);
      d = rotl((d + F(a, b, c) + X[k + 1]) | 0, 7);
      c = rotl((c + F(d, a, b) + X[k + 2]) | 0, 11);
      b = rotl((b + F(c, d, a) + X[k + 3]) | 0, 19);
    }
    for (const k of [0, 1, 2, 3]) {
      a = rotl((a + G(b, c, d) + X[k] + 0x5a827999) | 0, 3);
      d = rotl((d + G(a, b, c) + X[k + 4] + 0x5a827999) | 0, 5);
      c = rotl((c + G(d, a, b) + X[k + 8] + 0x5a827999) | 0, 9);
      b = rotl((b + G(c, d, a) + X[k + 12] + 0x5a827999) | 0, 13);
    }
    for (const k of [0, 2, 1, 3]) {
      a = rotl((a + H(b, c, d) + X[k] + 0x6ed9eba1) | 0, 3);
      d = rotl((d + H(a, b, c) + X[k + 8] + 0x6ed9eba1) | 0, 9);
      c = rotl((c + H(d, a, b) + X[k + 4] + 0x6ed9eba1) | 0, 11);
      b = rotl((b + H(c, d, a) + X[k + 12] + 0x6ed9eba1) | 0, 15);
    }

    a = (a + aa) | 0;
    b = (b + bb) | 0;
    c = (c + cc) | 0;
    d = (d + dd) | 0;
  }

  const out = Buffer.alloc(16);
  out.writeInt32LE(a, 0);
  out.writeInt32LE(b, 4);
  out.writeInt32LE(c, 8);
  out.writeInt32LE(d, 12);
  return out;
}

function ntHash(password) {
  return md4(Buffer.from(String(password), 'utf16le')).toString('hex');
}

module.exports = { md4, ntHash };
