'use strict';
// 拓扑计算：每个站点经云端能访问哪些网段、远程用户能访问哪些网段。
// swanctl 配置生成和 H3C 配置生成都基于这里，保证两端流量选择器一致。
const { q } = require('./db');
const settings = require('./settings');
const { tunnelInfo } = require('./util');

function parseSite(row) {
  if (!row) return null;
  return { ...row, subnets: JSON.parse(row.subnets || '[]') };
}

function loadSites() {
  return q.all('SELECT * FROM sites ORDER BY id').map(parseSite);
}

function loadUsers() {
  return q.all('SELECT * FROM users ORDER BY id');
}

function loadState() {
  const s = settings.getAll();
  return {
    settings: s,
    tunnel: tunnelInfo(s.tunnel_net),
    sites: loadSites(),
    users: loadUsers(),
  };
}

const activeSites = (state) => state.sites.filter((x) => x.enabled);

// 云端这一侧对某站点提供的网段（即站点 ACL 里的“目的网段”）
function hubNetsForSite(state, site) {
  const nets = [state.tunnel.cidr];
  if (state.settings.site_mesh === '1' && site.mesh) {
    for (const other of activeSites(state)) {
      if (other.id !== site.id && other.mesh) nets.push(...other.subnets);
    }
  }
  return nets;
}

// 远程用户能访问的网段
function userNets(state) {
  if (state.settings.users_full_tunnel === '1') return ['0.0.0.0/0'];
  const nets = [state.tunnel.cidr];
  for (const s of activeSites(state)) if (s.allow_users) nets.push(...s.subnets);
  return nets;
}

// 用于前端展示的站点对象（隐藏敏感字段）
function publicSite(site) {
  const { ssh_password, psk, ...rest } = site;
  return { ...rest, ssh_has_password: !!ssh_password };
}

module.exports = { parseSite, loadSites, loadUsers, loadState, activeSites, hubNetsForSite, userNets, publicSite };
