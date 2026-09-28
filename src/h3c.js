'use strict';
// 生成 H3C 侧配置：Comware V7 / Comware V5 命令行，或 ER 系列 Web 界面填写指南
const { PRESETS, H3C } = require('./proposals');
const { hubNetsForSite } = require('./model');
const { parseCidr, isIPv4, sha256, intToIp } = require('./util');

const DEVICE_TYPES = {
  comware7: 'H3C MSR/Comware V7（命令行）',
  comware5: 'H3C MSR/Comware V5（命令行）',
  er: 'H3C ER 系列（Web 界面）',
};

const NAME = 'ipsp-hub';
const IKE_PROPOSAL_NO = 99;

// 决定配置内容的全部参数；它的哈希用来判断“H3C 上的配置是否已过期”
function siteParams(state, site) {
  return {
    device: site.device_type,
    ike: site.ike_version,
    preset: site.crypto_preset,
    localId: site.local_id,
    psk: site.psk,
    hubId: state.settings.hub_id,
    hubAddr: state.settings.public_host,
    hubIp: state.tunnel.hubIp,
    local: site.subnets,
    remote: hubNetsForSite(state, site),
    wan: site.wan_interface,
    lanIp: site.lan_ip,
    acl: site.acl_number,
    keepalive: !!site.keepalive,
  };
}

function configHash(state, site) {
  return sha256(JSON.stringify(siteParams(state, site))).slice(0, 16);
}

function aclRules(p) {
  const rules = [];
  let n = 5;
  for (const src of p.local) {
    for (const dst of p.remote) {
      const s = parseCidr(src);
      const d = parseCidr(dst);
      rules.push(`rule ${n} permit ip source ${s.address} ${s.wildcard} destination ${d.address} ${d.wildcard}`);
      n += 5;
    }
  }
  return rules;
}

// 默认 NQA 源地址：站点第一个网段的 .1
function defaultLanIp(site) {
  const c = parseCidr(site.subnets[0]);
  return c ? intToIp(c.network + 1) : '';
}

class Script {
  constructor() {
    this.items = []; // { text, kind: 'cmd' | 'comment' | 'blank', tolerate }
  }
  c(text, tolerate = false) {
    this.items.push({ text, kind: 'cmd', tolerate });
  }
  note(text) {
    this.items.push({ text: `# ${text}`, kind: 'comment' });
  }
  blank() {
    this.items.push({ text: '#', kind: 'blank' });
  }
  text() {
    return this.items.map((i) => i.text).join('\n') + '\n';
  }
  commands() {
    return this.items.filter((i) => i.kind === 'cmd').map((i) => ({ cmd: i.text, tolerate: i.tolerate }));
  }
}

function header(sc, state, site, p, title) {
  sc.note(`IPsec Panel 生成 · 站点 ${site.name} · ${title}`);
  sc.note(`配置指纹 ${configHash(state, site)}（面板据此判断设备配置是否过期）`);
  sc.note('以 # 开头的是注释，粘贴时可以一并粘贴，也可以只复制命令（面板“复制命令”按钮会去掉注释）');
  sc.note(`本端网段: ${p.local.join(', ')}  ->  经云端可访问: ${p.remote.join(', ')}`);
  sc.blank();
}

function footerNotes(sc, p, site) {
  sc.blank();
  sc.note('【重要】如果 WAN 口配置了 nat outbound，要让 VPN 流量不做 NAT，');
  sc.note('否则报文会先被 NAT 成公网地址而匹配不上 IPsec ACL。在 NAT 使用的 ACL 中、permit 规则之前加入：');
  let n = 1;
  for (const src of p.local) {
    for (const dst of p.remote) {
      const s = parseCidr(src);
      const d = parseCidr(dst);
      sc.note(`  rule ${n} deny ip source ${s.address} ${s.wildcard} destination ${d.address} ${d.wildcard}`);
      n++;
    }
  }
  if (site.keepalive) {
    sc.note(`NQA 每 10 秒从 ${p.lanIp || '(LAN 网关地址)'} ping 云端 ${p.hubIp}，用于自动建立并保持隧道（云端无法主动连 H3C）。`);
  }
}

function genComware7(state, site) {
  const p = siteParams(state, site);
  p.lanIp = p.lanIp || defaultLanIp(site);
  const pre = PRESETS[p.preset];
  const sc = new Script();
  const hubIsIp = isIPv4(p.hubAddr);
  header(sc, state, site, p, `Comware V7 · ${p.ike === 1 ? 'IKEv1 野蛮模式' : 'IKEv2'}`);

  sc.c('system-view');
  sc.blank();
  sc.note('1. 感兴趣流 ACL（先删除再重建，保证和面板一致）');
  sc.c(`undo acl advanced ${p.acl}`, true);
  sc.c(`acl advanced ${p.acl}`);
  sc.c(` description IPsec-Panel-${site.name}`);
  for (const r of aclRules(p)) sc.c(` ${r}`);
  sc.c('quit');
  sc.blank();

  if (p.ike === 1) {
    sc.note('2. IKE 提议 / 密钥 / 策略');
    sc.c(`ike proposal ${IKE_PROPOSAL_NO}`);
    sc.c(` encryption-algorithm ${H3C.enc7[pre.ike.enc]}`);
    sc.c(` authentication-algorithm ${H3C.ikeAuth7[pre.ike.integ]}`);
    sc.c(` dh group${pre.ike.dh}`);
    sc.c(' authentication-method pre-share');
    sc.c(' sa duration 86400');
    sc.c('quit');
    sc.c(`ike keychain ${NAME}`);
    if (hubIsIp) sc.c(` pre-shared-key address ${p.hubAddr} 255.255.255.255 key simple ${p.psk}`);
    else sc.c(` pre-shared-key hostname ${p.hubAddr} key simple ${p.psk}`);
    sc.c('quit');
    sc.c(`ike profile ${NAME}`);
    sc.c(` keychain ${NAME}`);
    sc.c(' exchange-mode aggressive');
    sc.c(` local-identity fqdn ${p.localId}`);
    sc.c(` match remote identity fqdn ${p.hubId}`);
    sc.c(` proposal ${IKE_PROPOSAL_NO}`);
    sc.c(' dpd interval 10 retry 3 periodic');
    sc.c('quit');
    sc.c('ike nat-keepalive 20');
  } else {
    sc.note('2. IKEv2 提议 / 策略 / 密钥 / profile');
    sc.c(`ikev2 proposal ${NAME}`);
    sc.c(` encryption ${H3C.enc7[pre.ike.enc]}`);
    sc.c(` integrity ${H3C.ikev2Integ[pre.ike.integ]}`);
    sc.c(` prf ${H3C.ikev2Integ[pre.ike.integ]}`);
    sc.c(` dh group${pre.ike.dh}`);
    sc.c('quit');
    sc.c(`ikev2 policy ${NAME}`);
    sc.c(` proposal ${NAME}`);
    sc.c('quit');
    sc.c(`ikev2 keychain ${NAME}`);
    sc.c(' peer hub');
    if (hubIsIp) sc.c(`  address ${p.hubAddr} 32`);
    else sc.c(`  hostname ${p.hubAddr}`);
    sc.c(`  identity fqdn ${p.hubId}`);
    sc.c(`  pre-shared-key plaintext ${p.psk}`);
    sc.c(' quit');
    sc.c('quit');
    sc.c(`ikev2 profile ${NAME}`);
    sc.c(' authentication-method local pre-share');
    sc.c(' authentication-method remote pre-share');
    sc.c(` keychain ${NAME}`);
    sc.c(` identity local fqdn ${p.localId}`);
    sc.c(` match remote identity fqdn ${p.hubId}`);
    sc.c(' dpd interval 10 periodic');
    sc.c('quit');
    sc.c('ikev2 nat-keepalive 20');
  }
  sc.blank();

  sc.note('3. IPsec 安全提议与策略');
  sc.c(`ipsec transform-set ${NAME}`);
  sc.c(' encapsulation-mode tunnel');
  sc.c(' protocol esp');
  sc.c(` esp encryption-algorithm ${H3C.enc7[pre.esp.enc]}`);
  sc.c(` esp authentication-algorithm ${H3C.espAuth[pre.esp.integ]}`);
  if (pre.esp.pfs) sc.c(` pfs dh-group${pre.esp.pfs}`);
  else sc.c(' undo pfs', true);
  sc.c('quit');
  sc.c(`ipsec policy ${NAME} 10 isakmp`);
  sc.c(` transform-set ${NAME}`);
  sc.c(` security acl ${p.acl}`);
  sc.c(` remote-address ${p.hubAddr}`);
  if (p.ike === 1) {
    sc.c(' undo ikev2-profile', true);
    sc.c(` ike-profile ${NAME}`);
  } else {
    sc.c(' undo ike-profile', true);
    sc.c(` ikev2-profile ${NAME}`);
  }
  sc.c(' sa duration time-based 3600');
  sc.c('quit');
  sc.blank();

  sc.note('4. 在 WAN 口应用 IPsec 策略');
  sc.c(`interface ${p.wan}`);
  sc.c(` ipsec apply policy ${NAME}`);
  sc.c('quit');

  if (site.keepalive) {
    sc.blank();
    sc.note('5. NQA 保活：定期 ping 云端，隧道断开后自动重建');
    sc.c('undo nqa schedule ipsp keepalive', true);
    sc.c('nqa entry ipsp keepalive');
    sc.c(' type icmp-echo');
    sc.c(`  destination ip ${p.hubIp}`);
    sc.c(`  source ip ${p.lanIp}`);
    sc.c('  frequency 10000');
    sc.c(' quit');
    sc.c('quit');
    sc.c('nqa schedule ipsp keepalive start-time now lifetime forever');
  }
  sc.blank();
  sc.c('return');
  sc.c('save force');
  footerNotes(sc, p, site);
  return sc;
}

function genComware5(state, site) {
  const p = siteParams(state, site);
  p.lanIp = p.lanIp || defaultLanIp(site);
  const pre = PRESETS[p.preset];
  const sc = new Script();
  header(sc, state, site, p, 'Comware V5 · IKEv1 野蛮模式');
  if (pre.ike.integ === 'sha256' || pre.esp.integ === 'sha256') {
    sc.note('提示：部分 V5 版本不支持 SHA256，若命令报错请把站点算法改为“兼容老设备”');
    sc.blank();
  }

  sc.c('system-view');
  sc.blank();
  sc.note('1. 感兴趣流 ACL');
  sc.c(`undo acl number ${p.acl}`, true);
  sc.c(`acl number ${p.acl}`);
  for (const r of aclRules(p)) sc.c(` ${r}`);
  sc.c('quit');
  sc.blank();

  sc.note('2. IKE');
  sc.c(`ike local-name ${p.localId}`);
  sc.c(`ike proposal ${IKE_PROPOSAL_NO}`);
  sc.c(` encryption-algorithm ${H3C.enc5Ike[pre.ike.enc]}`);
  sc.c(` authentication-algorithm ${H3C.ikeAuth5[pre.ike.integ]}`);
  sc.c(` dh group${pre.ike.dh}`);
  sc.c(' authentication-method pre-share');
  sc.c(' sa duration 86400');
  sc.c('quit');
  sc.c(`ike dpd ${NAME}`);
  sc.c(' interval-time 10');
  sc.c(' time-out 5');
  sc.c('quit');
  sc.c(`ike peer ${NAME}`);
  sc.c(' exchange-mode aggressive');
  sc.c(` proposal ${IKE_PROPOSAL_NO}`);
  sc.c(` pre-shared-key simple ${p.psk}`);
  sc.c(' id-type name');
  sc.c(` remote-name ${p.hubId}`);
  sc.c(` remote-address ${p.hubAddr}`);
  sc.c(' nat traversal');
  sc.c(` dpd ${NAME}`);
  sc.c('quit');
  sc.blank();

  sc.note('3. IPsec 安全提议与策略');
  sc.c(`ipsec proposal ${NAME}`);
  sc.c(' encapsulation-mode tunnel');
  sc.c(' transform esp');
  sc.c(` esp encryption-algorithm ${H3C.enc5Esp[pre.esp.enc]}`);
  sc.c(` esp authentication-algorithm ${H3C.espAuth[pre.esp.integ]}`);
  sc.c('quit');
  sc.c(`ipsec policy ${NAME} 10 isakmp`);
  sc.c(` security acl ${p.acl}`);
  sc.c(` ike-peer ${NAME}`);
  sc.c(` proposal ${NAME}`);
  if (pre.esp.pfs) sc.c(` pfs dh-group${pre.esp.pfs}`);
  else sc.c(' undo pfs', true);
  sc.c(' sa duration time-based 3600');
  sc.c('quit');
  sc.blank();

  sc.note('4. 在 WAN 口应用 IPsec 策略');
  sc.c(`interface ${p.wan}`);
  sc.c(` ipsec policy ${NAME}`);
  sc.c('quit');

  if (site.keepalive) {
    sc.blank();
    sc.note('5. NQA 保活');
    sc.c('undo nqa schedule ipsp keepalive', true);
    sc.c('nqa entry ipsp keepalive');
    sc.c(' type icmp-echo');
    sc.c(`  destination ip ${p.hubIp}`);
    sc.c(`  source ip ${p.lanIp}`);
    sc.c('  frequency 10000');
    sc.c(' quit');
    sc.c('quit');
    sc.c('nqa schedule ipsp keepalive start-time now lifetime forever');
  }
  sc.blank();
  sc.c('return');
  sc.c('save force');
  footerNotes(sc, p, site);
  return sc;
}

// ER 系列：生成 Web 界面逐项填写指南
function genErGuide(state, site) {
  const p = siteParams(state, site);
  const pre = PRESETS[p.preset];
  const L = H3C.label;
  const sections = [
    {
      title: '基本设置（虚拟专网 → IPsec VPN → 新增）',
      rows: [
        ['名称', NAME],
        ['绑定接口', `${p.wan}（连接外网的 WAN 口）`],
        ['组网模式', '分支节点 / 站点到站点（本端主动连接）'],
        ['对端网关地址', p.hubAddr || '（请先在设置中填写公网地址）'],
        ['认证方式', '预共享密钥'],
        ['预共享密钥', p.psk],
      ],
    },
    {
      title: '受保护的网段（每一行建一条）',
      rows: p.local.flatMap((l) => p.remote.map((r) => ['本端网段 → 对端网段', `${l}  →  ${r}`])),
    },
    {
      title: 'IKE / 第一阶段（高级设置）',
      rows: [
        ['IKE 版本', p.ike === 1 ? 'IKEv1' : 'IKEv2'],
        ...(p.ike === 1 ? [['协商模式', '野蛮模式']] : []),
        ['本端身份类型', 'FQDN'],
        ['本端身份', p.localId],
        ['对端身份类型', 'FQDN'],
        ['对端身份', p.hubId],
        ['加密算法', L[pre.ike.enc]],
        ['验证算法', L[pre.ike.integ]],
        ['DH 组', `group${pre.ike.dh}`],
        ['SA 生存时间', '86400 秒'],
        ['DPD', '开启，间隔 10 秒'],
        ['NAT 穿越', '开启'],
      ],
    },
    {
      title: 'IPsec / 第二阶段（高级设置）',
      rows: [
        ['安全协议', 'ESP'],
        ['封装模式', '隧道模式'],
        ['加密算法', L[pre.esp.enc]],
        ['验证算法', L[pre.esp.integ]],
        ['PFS', pre.esp.pfs ? `group${pre.esp.pfs}` : '不启用'],
        ['SA 生存时间', '3600 秒'],
      ],
    },
    {
      title: '保活（可选，但强烈建议）',
      rows: [
        ['说明', `云端无法主动连接 H3C。请在 ER 上开启“隧道保活/自动连接”，或在内网放一台设备定时 ping ${p.hubIp}`],
      ],
    },
  ];
  const text = sections
    .map((s) => [`【${s.title}】`, ...s.rows.map(([k, v]) => `  ${k}: ${v}`)].join('\n'))
    .join('\n\n');
  return { sections, text: `# IPsec Panel 生成 · 站点 ${site.name} · ER 系列 Web 配置指南\n# 配置指纹 ${configHash(state, site)}\n\n${text}\n` };
}

function generate(state, site) {
  const hash = configHash(state, site);
  const base = { hash, deviceType: site.device_type, deviceLabel: DEVICE_TYPES[site.device_type] };
  if (!state.settings.public_host) {
    base.warning = '尚未设置云服务器公网地址，请先到“设置”页填写';
  }
  if (site.device_type === 'er') {
    const g = genErGuide(state, site);
    return { ...base, format: 'guide', text: g.text, sections: g.sections, commands: [] };
  }
  const sc = site.device_type === 'comware5' ? genComware5(state, site) : genComware7(state, site);
  const commands = sc.commands();
  return { ...base, format: 'cli', text: sc.text(), commandText: commands.map((c) => c.cmd).join('\n') + '\n', commands };
}

module.exports = { DEVICE_TYPES, generate, configHash, siteParams, defaultLanIp };
