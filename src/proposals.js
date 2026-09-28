'use strict';
// 站点隧道的算法预设：strongSwan 与 H3C 两边使用同一份定义，避免手工填错

const PRESETS = {
  strong: {
    label: '高强度（AES-256 / SHA-256 / DH14 + PFS）',
    ike: { enc: 'aes256', integ: 'sha256', dh: 14 },
    esp: { enc: 'aes256', integ: 'sha256', pfs: 14 },
  },
  standard: {
    label: '标准（AES-128 / SHA-256 / DH14，无 PFS）',
    ike: { enc: 'aes128', integ: 'sha256', dh: 14 },
    esp: { enc: 'aes128', integ: 'sha256', pfs: null },
  },
  compat: {
    label: '兼容老设备（AES-128 / SHA-1 / DH2，无 PFS）',
    ike: { enc: 'aes128', integ: 'sha1', dh: 2 },
    esp: { enc: 'aes128', integ: 'sha1', pfs: null },
  },
};

const DH_MODP = { 2: 'modp1024', 5: 'modp1536', 14: 'modp2048' };

// strongSwan 提议字符串
function swanIke(preset) {
  const p = PRESETS[preset].ike;
  return `${p.enc}-${p.integ}-${DH_MODP[p.dh]}`;
}

function swanEsp(preset) {
  const p = PRESETS[preset].esp;
  return p.pfs ? `${p.enc}-${p.integ}-${DH_MODP[p.pfs]}` : `${p.enc}-${p.integ}`;
}

// H3C 命名
const H3C = {
  enc7: { aes128: 'aes-cbc-128', aes256: 'aes-cbc-256' }, // Comware V7 IKE / ESP / IKEv2 通用
  enc5Ike: { aes128: 'aes-cbc 128', aes256: 'aes-cbc 256' },
  enc5Esp: { aes128: 'aes 128', aes256: 'aes 256' },
  ikeAuth7: { sha1: 'sha', sha256: 'sha256' }, // V7 ike proposal 里 SHA-1 写作 sha
  ikeAuth5: { sha1: 'sha', sha256: 'sha256' },
  espAuth: { sha1: 'sha1', sha256: 'sha256' },
  ikev2Integ: { sha1: 'sha1', sha256: 'sha256' },
  label: { aes128: 'AES-128', aes256: 'AES-256', sha1: 'SHA1', sha256: 'SHA256' },
};

// 远程用户：需要兼容 Windows / macOS / iOS / Android 原生客户端，所以放得比较宽
const RW_IKE = 'aes256-sha256-modp2048, aes256-sha256-ecp256, aes256gcm16-prfsha256-ecp256, aes128-sha256-modp2048, aes256-sha1-modp2048, aes256-sha1-modp1024, default';
const RW_ESP = 'aes256-sha256, aes256gcm16, aes128-sha256, aes256-sha1, aes128-sha1, default';

module.exports = { PRESETS, DH_MODP, swanIke, swanEsp, H3C, RW_IKE, RW_ESP };
