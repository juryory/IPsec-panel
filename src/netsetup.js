'use strict';
// 主机网络设置：IP 转发、Hub 隧道地址、iptables 规则（全部放在自有链里，幂等可重复执行）
const fs = require('node:fs');
const config = require('./config');
const { run } = require('./util');

const CH = {
  in: 'IPSP-IN',
  fwd: 'IPSP-FWD',
  mss: 'IPSP-MSS',
  nat: 'IPSP-POST',
};

async function ipt(table, args, { ignore = false } = {}) {
  try {
    return await run('iptables', ['-w', '5', '-t', table, ...args], { timeout: 15000 });
  } catch (e) {
    if (ignore) return null;
    throw e;
  }
}

async function ensureChain(table, chain, parent) {
  await ipt(table, ['-N', chain], { ignore: true });
  await ipt(table, ['-F', chain]);
  const exists = await ipt(table, ['-C', parent, '-j', chain], { ignore: true });
  if (!exists) await ipt(table, ['-I', parent, '1', '-j', chain]);
}

function buildRules(state) {
  const t = state.tunnel.cidr;
  const full = state.settings.users_full_tunnel === '1';
  const rules = { filterIn: [], filterFwd: [], mangle: [], nat: [] };

  rules.filterIn.push(['-p', 'udp', '-m', 'multiport', '--dports', '500,4500', '-j', 'ACCEPT']);
  rules.filterIn.push(['-p', 'esp', '-j', 'ACCEPT']);
  rules.filterIn.push(['-m', 'policy', '--pol', 'ipsec', '--dir', 'in', '-j', 'ACCEPT']);

  // 禁止远程用户访问“不允许用户访问”的站点
  for (const s of state.sites) {
    if (!s.enabled || s.allow_users) continue;
    for (const net of s.subnets) rules.filterFwd.push(['-s', t, '-d', net, '-j', 'DROP']);
  }
  rules.filterFwd.push(['-m', 'policy', '--pol', 'ipsec', '--dir', 'in', '-j', 'ACCEPT']);
  rules.filterFwd.push(['-m', 'policy', '--pol', 'ipsec', '--dir', 'out', '-j', 'ACCEPT']);
  if (full) {
    rules.filterFwd.push(['-s', t, '-j', 'ACCEPT']);
    rules.filterFwd.push(['-d', t, '-m', 'conntrack', '--ctstate', 'RELATED,ESTABLISHED', '-j', 'ACCEPT']);
  }

  // 隧道内 TCP MSS 钳制，避免大包分片导致网页打不开
  for (const dir of ['in', 'out']) {
    rules.mangle.push(['-m', 'policy', '--pol', 'ipsec', '--dir', dir, '-p', 'tcp', '--tcp-flags', 'SYN,RST', 'SYN', '-m', 'tcpmss', '--mss', '1361:1536', '-j', 'TCPMSS', '--set-mss', '1360']);
  }

  // 走隧道的流量不做 NAT（防止被主机上其它 MASQUERADE 规则改写）
  rules.nat.push(['-m', 'policy', '--pol', 'ipsec', '--dir', 'out', '-j', 'ACCEPT']);
  if (full) rules.nat.push(['-s', t, '-m', 'policy', '--pol', 'none', '--dir', 'out', '-j', 'MASQUERADE']);
  return rules;
}

async function ensureHubAddress(hubIp) {
  const dev = config.hubInterface;
  const show = await run('ip', ['link', 'show', dev]).catch(() => null);
  if (!show) await run('ip', ['link', 'add', dev, 'type', 'dummy']);
  await run('ip', ['link', 'set', dev, 'up']);
  const { stdout } = await run('ip', ['-4', '-o', 'addr', 'show', 'dev', dev]);
  const want = `${hubIp}/32`;
  const have = [...stdout.matchAll(/inet (\S+)/g)].map((m) => m[1]);
  for (const a of have) if (a !== want) await run('ip', ['addr', 'del', a, 'dev', dev]);
  if (!have.includes(want)) await run('ip', ['addr', 'add', want, 'dev', dev]);
}

let lastError = '';

async function apply(state) {
  if (!config.manageNetwork || config.mock) return { skipped: true };
  const errors = [];
  try {
    fs.writeFileSync('/proc/sys/net/ipv4/ip_forward', '1');
  } catch (e) {
    const cur = fs.existsSync('/proc/sys/net/ipv4/ip_forward') ? fs.readFileSync('/proc/sys/net/ipv4/ip_forward', 'utf8').trim() : '?';
    if (cur !== '1') errors.push(`无法开启 IP 转发（请在宿主机执行 sysctl -w net.ipv4.ip_forward=1）: ${e.message}`);
  }
  try {
    await ensureHubAddress(state.tunnel.hubIp);
  } catch (e) {
    errors.push(`配置 Hub 地址失败: ${e.message}`);
  }
  try {
    const r = buildRules(state);
    await ensureChain('filter', CH.in, 'INPUT');
    for (const rule of r.filterIn) await ipt('filter', ['-A', CH.in, ...rule]);
    await ensureChain('filter', CH.fwd, 'FORWARD');
    for (const rule of r.filterFwd) await ipt('filter', ['-A', CH.fwd, ...rule]);
    await ensureChain('mangle', CH.mss, 'FORWARD');
    for (const rule of r.mangle) await ipt('mangle', ['-A', CH.mss, ...rule]);
    await ensureChain('nat', CH.nat, 'POSTROUTING');
    for (const rule of r.nat) await ipt('nat', ['-A', CH.nat, ...rule]);
  } catch (e) {
    errors.push(`iptables 规则设置失败: ${e.message}`);
  }
  lastError = errors.join('\n');
  if (errors.length) console.error(lastError);
  return { errors };
}

function getLastError() {
  return lastError;
}

module.exports = { apply, buildRules, getLastError };
