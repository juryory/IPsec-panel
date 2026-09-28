'use strict';
/* IPsec Panel 前端：无构建步骤的单页应用 */

// ================= 工具 =================
const $ = (s, el = document) => el.querySelector(s);
const $$ = (s, el = document) => [...el.querySelectorAll(s)];
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

function fmtBytes(n) {
  n = Number(n) || 0;
  const u = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return `${n.toFixed(i && n < 100 ? 1 : 0)} ${u[i]}`;
}
function fmtTime(ts) {
  if (!ts) return '-';
  const d = new Date(ts * 1000);
  const p = (x) => String(x).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}
function fmtDuration(sec) {
  sec = Math.max(0, Math.floor(Number(sec) || 0));
  const d = Math.floor(sec / 86400), h = Math.floor((sec % 86400) / 3600), m = Math.floor((sec % 3600) / 60);
  if (d) return `${d}天${h}小时`;
  if (h) return `${h}小时${m}分`;
  if (m) return `${m}分${sec % 60}秒`;
  return `${sec}秒`;
}
function fmtAgo(ts) {
  if (!ts) return '从未';
  const diff = Date.now() / 1000 - ts;
  if (diff < 90) return '刚刚';
  return `${fmtDuration(diff)}前`;
}

async function api(method, url, body) {
  const opt = { method, headers: { 'X-Requested-With': 'ipsec-panel' }, credentials: 'same-origin' };
  if (body !== undefined) {
    opt.headers['Content-Type'] = 'application/json';
    opt.body = JSON.stringify(body);
  }
  const res = await fetch(`/api${url}`, opt);
  let data = {};
  try { data = await res.json(); } catch { /* ignore */ }
  if (res.status === 401 && url !== '/login') {
    showLogin();
    throw new Error(data.error || '请先登录');
  }
  if (!res.ok) throw new Error(data.error || `请求失败 (${res.status})`);
  return data;
}
const GET = (u) => api('GET', u);
const POST = (u, b = {}) => api('POST', u, b);
const PUT = (u, b = {}) => api('PUT', u, b);
const DEL = (u) => api('DELETE', u);

function toast(msg, type = '') {
  const el = document.createElement('div');
  el.className = `toast ${type}`;
  el.textContent = msg;
  $('#toasts').appendChild(el);
  setTimeout(() => el.remove(), type === 'error' || type === 'warn' ? 8000 : 3500);
}

// 统一处理写操作的结果（配置加载失败时后端会返回 warning）
function afterSave(r, okMsg) {
  if (r && r.warning) toast(r.warning, 'warn');
  else if (okMsg) toast(okMsg, 'ok');
}

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    const ta = document.createElement('textarea');
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    ta.remove();
  }
  toast('已复制到剪贴板', 'ok');
}

function downloadBlob(filename, data, mime = 'application/octet-stream') {
  const blob = data instanceof Blob ? data : new Blob([data], { type: mime });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 1000);
}
function b64ToBytes(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// ================= 弹窗 =================
function modal({ title, body, wide = false, actions = [] }) {
  const mask = document.createElement('div');
  mask.className = 'modal-mask';
  mask.innerHTML = `
    <div class="modal ${wide ? 'wide' : ''}" role="dialog">
      <div class="modal-head"><span>${esc(title)}</span><button class="x" type="button" aria-label="关闭">×</button></div>
      <div class="modal-body">${body}</div>
      ${actions.length ? '<div class="modal-foot"></div>' : ''}
    </div>`;
  const close = () => mask.remove();
  $('.x', mask).addEventListener('click', close);
  mask.addEventListener('mousedown', (e) => { if (e.target === mask) close(); });
  const foot = $('.modal-foot', mask);
  for (const a of actions) {
    const b = document.createElement('button');
    b.type = 'button';
    b.className = `btn ${a.cls || ''}`;
    b.textContent = a.label;
    b.addEventListener('click', async () => {
      if (!a.onClick) return close();
      b.disabled = true;
      try {
        const keep = await a.onClick(mask, close);
        if (keep !== true) close();
      } catch (e) {
        toast(e.message, 'error');
      } finally {
        b.disabled = false;
      }
    });
    foot.appendChild(b);
  }
  $('#modal-root').appendChild(mask);
  const first = $('input:not([type=hidden]):not([disabled]), select, textarea', mask);
  if (first) setTimeout(() => first.focus(), 30);
  return { el: mask, close };
}

function confirmBox(text, { okText = '确定', danger = false } = {}) {
  return new Promise((resolve) => {
    const m = modal({
      title: '请确认',
      body: `<div>${text}</div>`,
      actions: [
        { label: '取消', onClick: () => resolve(false) },
        { label: okText, cls: danger ? 'danger solid' : 'primary', onClick: () => resolve(true) },
      ],
    });
    $('.x', m.el).addEventListener('click', () => resolve(false));
    m.el.addEventListener('mousedown', (e) => { if (e.target === m.el) resolve(false); });
  });
}

function formData(root) {
  const out = {};
  for (const el of $$('input, select, textarea', root)) {
    if (!el.name) continue;
    if (el.type === 'checkbox') out[el.name] = el.checked;
    else out[el.name] = el.value;
  }
  return out;
}

function secretReveal(value) {
  return `<span class="secret" data-secret="${esc(value)}">••••••••••••</span> <button class="btn sm" data-act="reveal">显示</button> <button class="btn sm" data-act="copy" data-text="${esc(value)}">复制</button>`;
}

// ================= 图表 =================
// 先输出占位，插入页面后按容器实际宽度绘制，避免 SVG 拉伸导致文字变形
const chartStore = new Map();
let chartSeq = 0;
function lineChart(points, step) {
  const id = `c${++chartSeq}`;
  chartStore.set(id, { points, step });
  return `<div class="chart-slot" data-cid="${id}"></div>`;
}
function drawCharts() {
  for (const el of $$('.chart-slot[data-cid]')) {
    const data = chartStore.get(el.dataset.cid);
    if (!data) continue;
    el.innerHTML = renderChart(data.points, data.step, Math.max(320, el.clientWidth || 600));
    el.dataset.w = el.clientWidth;
  }
  if (chartStore.size > 50) for (const k of [...chartStore.keys()].slice(0, chartStore.size - 50)) chartStore.delete(k);
}
new MutationObserver(() => drawCharts()).observe(document.getElementById('main'), { childList: true, subtree: false });
window.addEventListener('resize', () => drawCharts());

function renderChart(points, step, W) {
  const H = 260, L = 64, R = 12, T = 12, B = 28;
  const max = Math.max(1, ...points.map((p) => Math.max(p.rx, p.tx)));
  const nice = niceMax(max);
  const x = (i) => L + (i / Math.max(1, points.length - 1)) * (W - L - R);
  const y = (v) => T + (1 - v / nice) * (H - T - B);
  const path = (k) => points.map((p, i) => `${i ? 'L' : 'M'}${x(i).toFixed(1)},${y(p[k]).toFixed(1)}`).join('');
  const area = (k) => `${path(k)}L${x(points.length - 1).toFixed(1)},${y(0)}L${x(0)},${y(0)}Z`;
  let grid = '';
  for (let i = 0; i <= 4; i++) {
    const v = (nice / 4) * i;
    grid += `<line class="grid-line" x1="${L}" x2="${W - R}" y1="${y(v)}" y2="${y(v)}"/><text class="axis" x="${L - 8}" y="${y(v) + 4}" text-anchor="end">${fmtBytes(v)}</text>`;
  }
  const labels = 6;
  for (let i = 0; i < labels; i++) {
    const idx = Math.round((i / (labels - 1)) * (points.length - 1));
    const p = points[idx];
    if (!p) continue;
    const d = new Date(p.t * 1000);
    const pad = (n) => String(n).padStart(2, '0');
    const txt = step >= 86400 ? `${d.getMonth() + 1}/${d.getDate()}` : step >= 3600 ? `${d.getMonth() + 1}/${d.getDate()} ${pad(d.getHours())}时` : `${pad(d.getHours())}:${pad(d.getMinutes())}`;
    grid += `<text class="axis" x="${x(idx)}" y="${H - 8}" text-anchor="${i === 0 ? 'start' : i === labels - 1 ? 'end' : 'middle'}">${txt}</text>`;
  }
  return `<svg class="chart" viewBox="0 0 ${W} ${H}" width="${W}" height="${H}">${grid}
    <path class="rx-a" d="${area('rx')}"/><path class="tx-a" d="${area('tx')}"/>
    <path class="rx" d="${path('rx')}" vector-effect="non-scaling-stroke"/><path class="tx" d="${path('tx')}" vector-effect="non-scaling-stroke"/></svg>
    <div class="legend"><span><i style="background:var(--rx)"></i>云端接收（上行）${fmtBytes(points.reduce((a, p) => a + p.rx, 0))}</span><span><i style="background:var(--tx)"></i>云端发送（下行）${fmtBytes(points.reduce((a, p) => a + p.tx, 0))}</span></div>`;
}
function niceMax(v) {
  const exp = Math.pow(1024, Math.floor(Math.log(v) / Math.log(1024)));
  const n = v / exp;
  const steps = [1, 2, 4, 5, 8, 10, 20, 40, 50, 80, 100, 200, 400, 500, 800, 1024];
  return (steps.find((s) => s >= n) || 1024) * exp;
}

// ================= 路由 =================
let refreshTimer = null;
let meta = { deviceTypes: {}, presets: {} };

const routes = {
  overview: pageOverview,
  sites: pageSites,
  site: pageSite,
  users: pageUsers,
  connections: pageConnections,
  traffic: pageTraffic,
  logs: pageLogs,
  settings: pageSettings,
};

async function route() {
  clearInterval(refreshTimer);
  refreshTimer = null;
  pageActions = {};
  $('#modal-root').innerHTML = '';
  const parts = location.hash.replace(/^#\/?/, '').split('/');
  let page = parts[0] || 'overview';
  const arg = parts[1];
  if (page === 'sites' && arg) page = 'site';
  if (!routes[page]) page = 'overview';
  $$('#nav a').forEach((a) => a.classList.toggle('active', a.dataset.page === (page === 'site' ? 'sites' : page)));
  const main = $('#main');
  try {
    await routes[page](main, arg);
  } catch (e) {
    main.innerHTML = `<div class="alert error">${esc(e.message)}</div>`;
  }
}

function autoRefresh(fn, ms) {
  clearInterval(refreshTimer);
  refreshTimer = setInterval(() => {
    if (!document.hidden && !$('.modal-mask')) fn().catch(() => {});
  }, ms);
}

function statusBadge(online, enabled = true) {
  if (!enabled) return '<span class="badge">已禁用</span>';
  return online ? '<span class="badge ok"><span class="dot ok"></span>在线</span>' : '<span class="badge"><span class="dot"></span>离线</span>';
}

function entityLabel(entity) {
  const [t, n] = String(entity).split(':');
  if (t === 'site') return `站点 ${n}`;
  if (t === 'user') return `用户 ${n}`;
  return entity || '系统';
}

const EVENT_TYPES = { up: ['上线', 'ok'], down: ['下线', ''], admin: ['管理', 'info'], system: ['系统', ''], push: ['下发', 'warn'] };
function eventList(events) {
  if (!events.length) return '<div class="empty">暂无事件</div>';
  return `<ul class="events">${events
    .map((e) => {
      const [label, cls] = EVENT_TYPES[e.type] || [e.type, ''];
      return `<li><time>${fmtTime(e.ts)}</time><span class="badge ${cls}">${label}</span><span>${e.entity ? `<b>${esc(entityLabel(e.entity))}</b> ` : ''}${esc(e.detail)}</span></li>`;
    })
    .join('')}</ul>`;
}

// ================= 概览 =================
async function pageOverview(main) {
  const render = async () => {
    const [d, tr] = await Promise.all([GET('/overview'), GET('/traffic?range=24h')]);
    const st = d.status;
    main.innerHTML = `
      <div class="page-head"><div><h1>概览</h1><div class="sub">云端 ${esc(d.publicHost || '未设置公网地址')} · 隧道网段 ${esc(d.tunnel.cidr)} · Hub ${esc(d.tunnel.hubIp)}</div></div></div>
      ${d.warnings.map((w) => `<div class="alert ${w.level === 'error' ? 'error' : 'warn'}"><span>${esc(w.text)}</span>${w.link ? `<a href="${w.link}">前往 →</a>` : ''}</div>`).join('')}
      <div class="grid stats">
        <div class="stat"><div class="label">strongSwan</div><div class="value" style="font-size:18px">${st.running ? '<span class="dot ok"></span> 运行中' : '<span class="dot err"></span> 未运行'}</div><div class="hint">${esc(st.version || st.error || '')}</div></div>
        <div class="stat"><div class="label">在线站点</div><div class="value">${d.counts.sitesOnline} / ${d.counts.sites}</div><div class="hint">H3C 路由器</div></div>
        <div class="stat"><div class="label">在线用户</div><div class="value">${d.counts.usersOnline} / ${d.counts.users}</div><div class="hint">远程接入</div></div>
        <div class="stat"><div class="label">24 小时流量</div><div class="value">${fmtBytes(d.traffic24h.rx + d.traffic24h.tx)}</div><div class="hint">↑ ${fmtBytes(d.traffic24h.rx)} · ↓ ${fmtBytes(d.traffic24h.tx)}</div></div>
      </div>
      <div class="card"><div class="card-head"><h2>站点</h2><a class="btn sm" href="#/sites">管理站点</a></div>
        ${d.sites.length ? `<div class="tiles">${d.sites.map((s) => `
          <a class="tile" href="#/sites/${s.id}">
            <div class="t-name"><span class="dot ${s.enabled && s.online ? 'ok' : ''}"></span>${esc(s.name)} ${s.outdated ? '<span class="badge warn">待下发</span>' : ''}</div>
            <div class="t-sub">${esc(s.description || '')}</div>
            <div class="t-sub mono">${esc(s.subnets.join(', '))}</div>
          </a>`).join('')}</div>` : '<div class="empty">还没有站点，<a href="#/sites">添加第一个 H3C 站点</a></div>'}
      </div>
      <div class="grid two">
        <div class="card"><div class="card-head"><h2>最近 24 小时流量</h2><a class="btn sm" href="#/traffic">详情</a></div>${lineChart(tr.points, tr.step)}</div>
        <div class="card"><div class="card-head"><h2>最近事件</h2><a class="btn sm" href="#/logs">全部</a></div>${eventList(d.events)}</div>
      </div>`;
  };
  await render();
  autoRefresh(render, 15000);
}

// ================= 站点 =================
async function loadMeta() {
  if (Object.keys(meta.deviceTypes).length) return meta;
  const d = await GET('/sites');
  meta = { deviceTypes: d.deviceTypes, presets: d.presets, hubId: d.hubId };
  return meta;
}

async function pageSites(main) {
  const render = async () => {
    const d = await GET('/sites');
    meta = { deviceTypes: d.deviceTypes, presets: d.presets, hubId: d.hubId };
    main.innerHTML = `
      <div class="page-head">
        <div><h1>站点（H3C）</h1><div class="sub">每个站点是一台主动连接云端的 H3C 路由器，云端身份标识：<code>${esc(d.hubId)}</code></div></div>
        <div class="toolbar"><button class="btn primary" data-act="site-new">+ 新增站点</button></div>
      </div>
      <div class="card flush"><div class="table-wrap"><table>
        <thead><tr><th>站点</th><th>状态</th><th>设备 / 协议</th><th>内网网段</th><th>H3C 配置</th><th>最后在线</th><th></th></tr></thead>
        <tbody>${d.sites.length ? d.sites.map((s) => `
          <tr>
            <td><a href="#/sites/${s.id}"><b>${esc(s.name)}</b></a><div class="small">${esc(s.description)}</div></td>
            <td>${statusBadge(s.online, s.enabled)}</td>
            <td>${esc(d.deviceTypes[s.device_type] || s.device_type)}<div class="small">${s.ike_version === 1 ? 'IKEv1 野蛮模式' : 'IKEv2'} · ${esc(s.crypto_preset)}</div></td>
            <td class="mono">${s.subnets.map(esc).join('<br>')}</td>
            <td>${!s.enabled ? '-' : s.outdated ? `<span class="badge warn">${s.applied_hash ? '已变更，待下发' : '未下发'}</span>` : `<span class="badge ok">已同步</span><div class="small">${s.applied_by === 'ssh' ? 'SSH 下发' : '手动'} · ${fmtTime(s.applied_at)}</div>`}</td>
            <td class="small">${fmtAgo(s.last_seen)}</td>
            <td class="right"><a class="btn sm" href="#/sites/${s.id}">详情</a></td>
          </tr>`).join('') : '<tr><td colspan="7" class="empty">还没有站点。点击右上角“新增站点”，填写 H3C 所在公司的内网网段即可。</td></tr>'}
        </tbody></table></div></div>`;
  };
  await render();
  autoRefresh(render, 20000);
}

function siteForm(s = {}) {
  const isNew = !s.id;
  const dt = Object.entries(meta.deviceTypes).map(([k, v]) => `<option value="${k}" ${s.device_type === k ? 'selected' : ''}>${esc(v)}</option>`).join('');
  const pr = Object.entries(meta.presets).map(([k, v]) => `<option value="${k}" ${(s.crypto_preset || 'strong') === k ? 'selected' : ''}>${esc(v)}</option>`).join('');
  const chk = (name, val, title, help) => `<label class="check"><input type="checkbox" name="${name}" ${val ? 'checked' : ''}><span><b>${title}</b><span class="small">${help}</span></span></label>`;
  return `<form class="form" autocomplete="off">
    <label>站点名称 ${isNew ? '<span class="help">字母数字和 -，创建后不可改</span>' : ''}<input name="name" value="${esc(s.name || '')}" ${isNew ? 'required' : 'disabled'} placeholder="hq"></label>
    <label>备注<input name="description" value="${esc(s.description || '')}" placeholder="总部 / 上海分公司"></label>
    <label>设备类型<select name="device_type">${dt}</select></label>
    <label>IKE 版本<select name="ike_version">
      <option value="1" ${s.ike_version !== 2 ? 'selected' : ''}>IKEv1 野蛮模式（兼容性最好）</option>
      <option value="2" ${s.ike_version === 2 ? 'selected' : ''}>IKEv2（推荐，V7 设备）</option></select></label>
    <label class="full">内网网段 <span class="help">H3C 后面的公司内网，多个用逗号或换行分隔，例如 192.168.1.0/24</span>
      <textarea name="subnets" required placeholder="192.168.1.0/24">${esc((s.subnets || []).join('\n'))}</textarea></label>
    <label>算法<select name="crypto_preset">${pr}</select></label>
    <label>站点身份标识（FQDN）<span class="help">留空自动生成</span><input name="local_id" value="${esc(s.local_id || '')}" placeholder="hq.ipsec"></label>
    <label>WAN 接口 <span class="help">H3C 上连外网的接口</span><input name="wan_interface" value="${esc(s.wan_interface || 'GigabitEthernet0/0')}"></label>
    <label>LAN 网关地址 <span class="help">NQA 保活源地址，留空取网段 .1</span><input name="lan_ip" value="${esc(s.lan_ip || '')}" placeholder="192.168.1.1"></label>
    <label>ACL 编号<input name="acl_number" type="number" min="3000" max="3999" value="${esc(s.acl_number || 3100)}"></label>
    <label>预共享密钥 <span class="help">${isNew ? '留空自动生成 32 位随机密钥' : '留空保持不变'}</span><input name="psk" placeholder="自动生成"></label>
    ${chk('enabled', s.enabled ?? 1, '启用', '禁用后云端不再接受该站点连接')}
    ${chk('keepalive', s.keepalive ?? 1, 'NQA 保活', 'H3C 定时 ping 云端，隧道断开后自动重建')}
    ${chk('mesh', s.mesh ?? 1, '参与站点互通', '可以访问其它站点的内网（需在设置中开启）')}
    ${chk('allow_users', s.allow_users ?? 1, '允许远程用户访问', '远程用户可以访问该站点内网')}
    <h3>SSH 自动下发（仅 Comware 命令行设备）</h3>
    ${chk('ssh_enabled', s.ssh_enabled, '启用 SSH 下发', '首次需手动配置；隧道建立后，面板可经隧道登录 H3C 自动更新配置')}
    <label>SSH 地址 <span class="help">留空使用 LAN 网关地址</span><input name="ssh_host" value="${esc(s.ssh_host || '')}"></label>
    <label>SSH 端口<input name="ssh_port" type="number" value="${esc(s.ssh_port || 22)}"></label>
    <label>SSH 用户名<input name="ssh_user" value="${esc(s.ssh_user || '')}" autocomplete="off"></label>
    <label>SSH 密码 <span class="help">${s.ssh_has_password ? '已保存，留空不修改' : ''}</span><input name="ssh_password" type="password" autocomplete="new-password"></label>
  </form>`;
}

function readSiteForm(root) {
  const f = formData(root);
  f.ike_version = Number(f.ike_version);
  f.acl_number = Number(f.acl_number);
  f.ssh_port = Number(f.ssh_port);
  if (!f.psk) delete f.psk;
  if (!f.ssh_password) delete f.ssh_password;
  if (!f.local_id) delete f.local_id;
  return f;
}

async function openSiteForm(site) {
  await loadMeta();
  modal({
    title: site ? `编辑站点 ${site.name}` : '新增站点',
    body: siteForm(site || {}),
    wide: true,
    actions: [
      { label: '取消' },
      {
        label: '保存',
        cls: 'primary',
        onClick: async (m) => {
          const f = readSiteForm(m);
          if (site) {
            afterSave(await PUT(`/sites/${site.id}`, f), '已保存');
            route();
          } else {
            const r = await POST('/sites', f);
            afterSave(r, '站点已创建，请按页面中的配置设置 H3C');
            location.hash = `#/sites/${r.id}`;
          }
        },
      },
    ],
  });
}

async function pageSite(main, id) {
  await loadMeta();
  const render = async () => {
    const [d, cfg] = await Promise.all([GET(`/sites/${id}`), GET(`/sites/${id}/h3c`)]);
    const s = d.site;
    const tr2 = await GET(`/traffic?range=24h&entity=${encodeURIComponent('site:' + s.name)}`);
    const c = d.conn;
    main.innerHTML = `
      <div class="page-head">
        <div><h1>${esc(s.name)} ${statusBadge(s.online, s.enabled)}</h1><div class="sub">${[s.description, d.deviceTypes[s.device_type]].filter(Boolean).map(esc).join(' · ')}</div></div>
        <div class="toolbar">
          <a class="btn" href="#/sites">← 返回</a>
          <button class="btn" data-act="site-edit">编辑</button>
          <button class="btn" data-act="site-rotate">轮换密钥</button>
          <button class="btn" data-act="site-toggle">${s.enabled ? '禁用' : '启用'}</button>
          <button class="btn danger" data-act="site-delete">删除</button>
        </div>
      </div>
      <div class="grid two">
        <div class="card"><h2>隧道参数</h2><dl class="kv">
          <dt>协议</dt><dd>${s.ike_version === 1 ? 'IKEv1 野蛮模式' : 'IKEv2'} · ${esc(meta.presets[s.crypto_preset] || s.crypto_preset)}</dd>
          <dt>站点身份</dt><dd class="mono">${esc(s.local_id)}</dd>
          <dt>云端身份</dt><dd class="mono">${esc(meta.hubId || '')}</dd>
          <dt>预共享密钥</dt><dd>${secretReveal(s.psk)}</dd>
          <dt>内网网段</dt><dd class="mono">${s.subnets.map(esc).join('<br>')}</dd>
          <dt>经云端可访问</dt><dd class="mono">${s.hubNets.map(esc).join('<br>')}</dd>
          <dt>密钥更新时间</dt><dd>${fmtTime(s.psk_rotated_at)}</dd>
          <dt>最后在线</dt><dd>${fmtAgo(s.last_seen)}</dd>
        </dl></div>
        <div class="card"><h2>当前连接</h2>${c ? `<dl class="kv">
          <dt>公网地址</dt><dd class="mono">${esc(c.remoteHost)}:${esc(c.remotePort)}</dd>
          <dt>已连接</dt><dd>${fmtDuration(c.established)}</dd>
          <dt>IKE 算法</dt><dd class="mono">${esc(c.ike || '-')}</dd>
          <dt>流量</dt><dd>↑ ${fmtBytes(c.bytesIn)} · ↓ ${fmtBytes(c.bytesOut)}</dd>
          <dt>子隧道</dt><dd class="mono">${c.children.map((ch) => `${esc(ch.remoteTs.join(','))} ⇄ ${esc(ch.localTs.join(','))}`).join('<br>')}</dd>
        </dl><div class="mt"><button class="btn sm danger" data-act="conn-kill" data-id="${esc(c.ikeId)}">断开（H3C 会自动重连）</button></div>` : '<div class="empty">当前没有连接。H3C 配置完成后，内网有流量或 NQA 保活触发时会自动建立隧道。</div>'}</div>
      </div>
      <div class="card">
        <div class="card-head">
          <h2>H3C 配置 ${cfg.applied ? `<span class="badge ok">已同步 · ${cfg.appliedBy === 'ssh' ? 'SSH' : '手动'} ${fmtTime(cfg.appliedAt)}</span>` : `<span class="badge warn">${s.applied_hash ? '配置已变更，需要重新下发' : '尚未下发'}</span>`}</h2>
          <div class="toolbar">
            ${cfg.format === 'cli' ? '<button class="btn sm" data-act="cfg-copy-cmd">复制命令</button>' : ''}
            <button class="btn sm" data-act="cfg-copy-all">复制全文</button>
            <button class="btn sm" data-act="cfg-download">下载</button>
            ${!cfg.applied ? '<button class="btn sm" data-act="cfg-mark">我已手动配置</button>' : ''}
            ${s.ssh_enabled ? '<button class="btn sm primary" data-act="cfg-push">SSH 下发到设备</button>' : ''}
          </div>
        </div>
        ${cfg.warning ? `<div class="alert error">${esc(cfg.warning)}</div>` : ''}
        ${cfg.format === 'guide' ? erGuide(cfg) : `<pre class="code">${highlightCli(cfg.text)}</pre>`}
      </div>
      <div class="card"><div class="card-head"><h2>最近 24 小时流量</h2></div>${lineChart(tr2.points, tr2.step)}</div>`;

    const acts = {
      'site-edit': () => openSiteForm(s),
      'site-rotate': async () => {
        const push = s.ssh_enabled && s.online;
        const ok = await confirmBox(`生成新的预共享密钥？<br><br>${push ? '将先通过 SSH 把新密钥推送到 H3C，再更新云端。' : '更新后需要在 H3C 上同步修改密钥，否则下次重新协商时隧道会断开。'}`);
        if (!ok) return;
        const r = await POST(`/sites/${s.id}/rotate-psk`, { push });
        if (r.push && !r.push.ok) toast(`SSH 下发失败：${r.push.error || '有命令报错'}`, 'error');
        afterSave(r, '密钥已更新');
        render();
      },
      'site-toggle': async () => {
        afterSave(await PUT(`/sites/${s.id}`, { enabled: !s.enabled }), s.enabled ? '已禁用' : '已启用');
        render();
      },
      'site-delete': async () => {
        if (!(await confirmBox(`确定删除站点 <b>${esc(s.name)}</b>？云端将立即断开该站点。`, { okText: '删除', danger: true }))) return;
        afterSave(await DEL(`/sites/${s.id}`), '已删除');
        location.hash = '#/sites';
      },
      'cfg-copy-cmd': () => copyText(cfg.commandText),
      'cfg-copy-all': () => copyText(cfg.text),
      'cfg-download': () => downloadBlob(`h3c-${s.name}.txt`, cfg.text, 'text/plain'),
      'cfg-mark': async () => {
        if (!(await confirmBox('确认已经把当前配置应用到 H3C 设备上？'))) return;
        await POST(`/sites/${s.id}/mark-applied`);
        toast('已标记', 'ok');
        render();
      },
      'cfg-push': () => pushDialog(s, render),
    };
    pageActions = acts;
  };
  await render();
  autoRefresh(render, 30000);
}

function highlightCli(text) {
  return text.split('\n').map((l) => (l.startsWith('#') ? `<span class="c">${esc(l)}</span>` : esc(l))).join('\n');
}

function erGuide(cfg) {
  return cfg.sections
    .map((sec) => `<h2 class="mt">${esc(sec.title)}</h2><div class="table-wrap"><table><tbody>${sec.rows.map(([k, v]) => `<tr><td style="width:200px" class="muted">${esc(k)}</td><td class="mono">${esc(v)}</td></tr>`).join('')}</tbody></table></div>`)
    .join('');
}

function pushDialog(site, done) {
  const m = modal({
    title: `SSH 下发到 ${site.name}`,
    wide: true,
    body: `<div class="alert info">将登录 <b>${esc(site.ssh_host || site.lan_ip || '(LAN 网关)')}:${esc(site.ssh_port)}</b>，执行面板生成的命令并 <code>save force</code>。首次配置请先手动粘贴，之后的变更可以经隧道自动下发。</div>
      <pre class="code log" id="push-out" hidden></pre>`,
    actions: [
      { label: '关闭', onClick: () => done() },
      {
        label: '开始下发',
        cls: 'primary',
        onClick: async (el) => {
          const out = $('#push-out', el);
          out.hidden = false;
          out.textContent = '正在连接设备并执行命令，可能需要 1 分钟……';
          const r = await POST(`/sites/${site.id}/push`);
          out.textContent = (r.transcript || '') + (r.error ? `\n\n[错误] ${r.error}` : '');
          if (r.errors && r.errors.length) out.textContent += `\n\n[报错的命令]\n${r.errors.map((e) => `${e.command}\n  => ${e.message}`).join('\n')}`;
          out.scrollTop = out.scrollHeight;
          toast(r.ok ? '下发成功' : '下发未完全成功，请查看输出', r.ok ? 'ok' : 'error');
          return true;
        },
      },
    ],
  });
  return m;
}

// ================= 远程用户 =================
async function pageUsers(main) {
  const render = async () => {
    const d = await GET('/users');
    main.innerHTML = `
      <div class="page-head">
        <div><h1>远程用户</h1><div class="sub">员工在外通过 IKEv2 连接云端，再经隧道访问公司内网。Windows / macOS / iOS / Android 均可使用系统自带客户端。</div></div>
        <div class="toolbar"><button class="btn primary" data-act="user-new">+ 新增用户</button></div>
      </div>
      <div class="card flush"><div class="table-wrap"><table>
        <thead><tr><th>用户</th><th>认证方式</th><th>状态</th><th>最后在线</th><th>创建时间</th><th></th></tr></thead>
        <tbody>${d.users.length ? d.users.map((u) => `
          <tr>
            <td><b>${esc(u.username)}</b><div class="small">${esc(u.display_name)}</div></td>
            <td>${u.auth_type === 'cert' ? '<span class="badge info">证书</span>' : '<span class="badge">账号密码</span>'}${u.auth_type === 'cert' && u.cert_not_after ? `<div class="small">证书到期 ${fmtTime(u.cert_not_after).slice(0, 10)}</div>` : ''}</td>
            <td>${statusBadge(u.online, u.enabled)}</td>
            <td class="small">${fmtAgo(u.last_seen)}</td>
            <td class="small">${fmtTime(u.created_at)}</td>
            <td class="right"><div class="row-actions" style="justify-content:flex-end">
              <button class="btn sm primary" data-act="user-download" data-id="${u.id}">客户端配置</button>
              ${u.auth_type === 'eap' ? `<button class="btn sm" data-act="user-password" data-id="${u.id}">重置密码</button>` : `<button class="btn sm" data-act="user-reissue" data-id="${u.id}">重签证书</button>`}
              <button class="btn sm" data-act="user-toggle" data-id="${u.id}">${u.enabled ? '禁用' : '启用'}</button>
              <button class="btn sm danger" data-act="user-delete" data-id="${u.id}">删除</button>
            </div></td>
          </tr>`).join('') : '<tr><td colspan="6" class="empty">还没有用户</td></tr>'}
        </tbody></table></div></div>`;
    const find = (el) => d.users.find((u) => String(u.id) === el.dataset.id);
    pageActions = {
      'user-download': (el) => downloadDialog(find(el)),
      'user-password': async (el) => {
        const u = find(el);
        modal({
          title: `重置 ${u.username} 的密码`,
          body: '<form class="form"><label class="full">新密码 <span class="help">留空随机生成</span><input name="password" type="text" autocomplete="off"></label></form>',
          actions: [
            { label: '取消' },
            {
              label: '重置',
              cls: 'primary',
              onClick: async (m) => {
                const r = await POST(`/users/${u.id}/password`, formData(m));
                afterSave(r);
                showPassword(u.username, r.password);
              },
            },
          ],
        });
      },
      'user-reissue': async (el) => {
        const u = find(el);
        if (!(await confirmBox(`重新签发 <b>${esc(u.username)}</b> 的证书？旧证书将被吊销，需要重新下载客户端配置。`))) return;
        afterSave(await POST(`/users/${u.id}/reissue`), '已重新签发');
        render();
      },
      'user-toggle': async (el) => {
        const u = find(el);
        afterSave(await PUT(`/users/${u.id}`, { enabled: !u.enabled }), u.enabled ? '已禁用并断开' : '已启用');
        render();
      },
      'user-delete': async (el) => {
        const u = find(el);
        if (!(await confirmBox(`确定删除用户 <b>${esc(u.username)}</b>？`, { okText: '删除', danger: true }))) return;
        afterSave(await DEL(`/users/${u.id}`), '已删除');
        render();
      },
    };
  };
  await render();
  autoRefresh(render, 30000);
}

function showPassword(username, password) {
  modal({
    title: '请保存密码',
    body: `<div class="alert warn">密码只显示这一次，面板只保存哈希，无法再次查看。</div>
      <dl class="kv"><dt>用户名</dt><dd class="mono">${esc(username)}</dd><dt>密码</dt><dd><span class="secret">${esc(password)}</span> <button class="btn sm" data-act="copy" data-text="${esc(password)}">复制</button></dd></dl>`,
    actions: [{ label: '我已保存', cls: 'primary' }],
  });
}

function openUserForm() {
  modal({
    title: '新增远程用户',
    body: `<form class="form" autocomplete="off">
      <label>用户名 <span class="help">登录名，字母数字 _ . -</span><input name="username" required placeholder="zhangsan"></label>
      <label>姓名 / 备注<input name="display_name" placeholder="张三"></label>
      <label class="full">认证方式<select name="auth_type">
        <option value="eap">账号密码（EAP-MSCHAPv2，所有系统原生支持，推荐）</option>
        <option value="cert">证书（更安全，需要导入证书文件）</option></select></label>
      <label class="full" data-eap>密码 <span class="help">留空随机生成</span><input name="password" type="text" autocomplete="off"></label>
    </form>`,
    actions: [
      { label: '取消' },
      {
        label: '创建',
        cls: 'primary',
        onClick: async (m) => {
          const f = formData(m);
          const r = await POST('/users', f);
          afterSave(r, '用户已创建');
          if (r.password) showPassword(f.username, r.password);
          route();
        },
      },
    ],
  }).el.addEventListener('change', (e) => {
    if (e.target.name === 'auth_type') $('[data-eap]', e.currentTarget).hidden = e.target.value !== 'eap';
  });
}

const PLATFORMS = [
  { kind: 'apple', name: 'iPhone / iPad / Mac', desc: '.mobileconfig 描述文件', help: 'iOS：用 Safari 打开或 AirDrop 到手机 → 设置 → 已下载描述文件 → 安装。macOS：双击 → 系统设置 → 隐私与安全性 → 描述文件 → 安装。' },
  { kind: 'windows', name: 'Windows 10 / 11', desc: 'PowerShell 一键脚本', help: '以管理员身份打开 PowerShell，执行 powershell -ExecutionPolicy Bypass -File .\\脚本.ps1，完成后在“设置 → 网络 → VPN”中连接。' },
  { kind: 'android', name: 'Android', desc: 'strongSwan 客户端 .sswan', help: '安装 strongSwan VPN Client（应用商店或 F-Droid），打开 → 右上角菜单 → 导入 VPN 配置 → 选择该文件。' },
  { kind: 'p12', name: '证书文件', desc: '.p12（仅证书用户）', help: '适用于手动配置或其它客户端。导入密码见下方。', certOnly: true },
  { kind: 'ca', name: 'CA 根证书', desc: 'ipsec-panel-ca.crt', help: '手动配置客户端时需要信任此 CA（使用自定义证书时通常不需要）。' },
];

function downloadDialog(u) {
  const items = PLATFORMS.filter((p) => !p.certOnly || u.auth_type === 'cert');
  const m = modal({
    title: `${u.username} 的客户端配置`,
    wide: true,
    body: `<div class="platforms">${items.map((p) => `<button class="platform" type="button" data-kind="${p.kind}"><b>${p.name}</b><span>${p.desc}</span></button>`).join('')}</div>
      <div id="dl-result" class="mt"></div>`,
    actions: [{ label: '关闭' }],
  });
  m.el.addEventListener('click', async (e) => {
    const btn = e.target.closest('.platform');
    if (!btn) return;
    const p = PLATFORMS.find((x) => x.kind === btn.dataset.kind);
    try {
      const r = await POST(`/users/${u.id}/bundle`, { kind: p.kind });
      downloadBlob(r.filename, b64ToBytes(r.data), r.mime);
      $('#dl-result', m.el).innerHTML = `<div class="alert info" style="display:block"><b>${esc(p.name)}：</b>${esc(p.help)}
        ${r.password ? `<div class="mt">证书导入密码：<span class="secret">${esc(r.password)}</span> <button class="btn sm" data-act="copy" data-text="${esc(r.password)}">复制</button>（每次下载都会生成新密码${p.kind === 'windows' || p.kind === 'apple' ? '，已写入文件中' : ''}）</div>` : ''}
        ${u.auth_type === 'eap' && p.kind !== 'ca' ? `<div class="mt">连接时输入用户名 <b>${esc(u.username)}</b> 和密码。</div>` : ''}</div>`;
    } catch (err) {
      toast(err.message, 'error');
    }
  });
}

// ================= 在线连接 =================
async function pageConnections(main) {
  const render = async () => {
    const d = await GET('/connections');
    const rows = d.conns.sort((a, b) => (a.kind + a.label).localeCompare(b.kind + b.label));
    main.innerHTML = `
      <div class="page-head"><div><h1>在线连接</h1><div class="sub">每 10 秒自动刷新 · 共 ${rows.length} 个 IKE SA</div></div>
        <div class="toolbar"><button class="btn" data-act="refresh">刷新</button></div></div>
      <div class="card flush"><div class="table-wrap"><table>
        <thead><tr><th>类型</th><th>名称</th><th>远端地址</th><th>隧道地址 / 网段</th><th>已连接</th><th>接收 / 发送</th><th>算法</th><th></th></tr></thead>
        <tbody>${rows.length ? rows.map((c) => `
          <tr>
            <td>${c.kind === 'site' ? '<span class="badge info">站点</span>' : c.kind === 'user' ? '<span class="badge">用户</span>' : `<span class="badge">${esc(c.conn)}</span>`}</td>
            <td><b>${esc(c.label)}</b><div class="small">${c.up ? '' : esc(c.state)} IKEv${esc(c.version)}</div></td>
            <td class="mono">${esc(c.remoteHost)}:${esc(c.remotePort)}</td>
            <td class="mono small">${c.vips.length ? esc(c.vips.join(', ')) : c.children.map((ch) => esc(ch.remoteTs.join(', '))).join('<br>')}</td>
            <td class="num">${fmtDuration(c.established)}</td>
            <td class="num">↑ ${fmtBytes(c.bytesIn)}<br>↓ ${fmtBytes(c.bytesOut)}</td>
            <td class="small mono">${esc(c.ike)}${c.children[0] ? `<br>${esc([c.children[0].encr, c.children[0].integ].filter(Boolean).join('/'))}` : ''}</td>
            <td class="right"><button class="btn sm danger" data-act="conn-kill" data-id="${esc(c.ikeId)}">断开</button></td>
          </tr>`).join('') : '<tr><td colspan="8" class="empty">当前没有连接</td></tr>'}
        </tbody></table></div></div>`;
    pageActions = { refresh: render };
  };
  await render();
  autoRefresh(render, 10000);
}

// ================= 流量 =================
async function pageTraffic(main) {
  let range = '24h';
  let entity = '';
  const [sites, users] = await Promise.all([GET('/sites'), GET('/users')]);
  const options = [['', '全部'], ...sites.sites.map((s) => [`site:${s.name}`, `站点 ${s.name}`]), ...users.users.map((u) => [`user:${u.username}`, `用户 ${u.username}`])];
  const render = async () => {
    const [tr, top] = await Promise.all([GET(`/traffic?range=${range}&entity=${encodeURIComponent(entity)}`), GET(`/traffic/top?range=${range}`)]);
    main.innerHTML = `
      <div class="page-head"><div><h1>流量统计</h1><div class="sub">每 ${30} 秒采集一次，按 5 分钟汇总</div></div>
        <div class="toolbar">
          <select id="tr-entity" style="width:auto">${options.map(([v, l]) => `<option value="${esc(v)}" ${v === entity ? 'selected' : ''}>${esc(l)}</option>`).join('')}</select>
          <div class="seg">${['24h', '7d', '30d'].map((r) => `<button data-range="${r}" class="${r === range ? 'active' : ''}">${{ '24h': '24 小时', '7d': '7 天', '30d': '30 天' }[r]}</button>`).join('')}</div>
        </div></div>
      <div class="card">${lineChart(tr.points, tr.step)}</div>
      <div class="card flush"><div class="table-wrap"><table>
        <thead><tr><th>对象</th><th class="right">云端接收（上行）</th><th class="right">云端发送（下行）</th><th class="right">合计</th></tr></thead>
        <tbody>${top.items.length ? top.items.map((i) => `<tr><td>${esc(entityLabel(i.entity))}</td><td class="num right">${fmtBytes(i.rx)}</td><td class="num right">${fmtBytes(i.tx)}</td><td class="num right"><b>${fmtBytes(i.rx + i.tx)}</b></td></tr>`).join('') : '<tr><td colspan="4" class="empty">暂无数据</td></tr>'}</tbody>
      </table></div></div>`;
    $('#tr-entity').addEventListener('change', (e) => { entity = e.target.value; render(); });
    $$('[data-range]').forEach((b) => b.addEventListener('click', () => { range = b.dataset.range; render(); }));
  };
  await render();
  autoRefresh(render, 60000);
}

// ================= 日志 =================
async function pageLogs(main) {
  let tab = 'events';
  let type = '';
  let lines = 300;
  const render = async () => {
    let body;
    if (tab === 'events') {
      const d = await GET(`/events?limit=300${type ? `&type=${type}` : ''}`);
      body = `<div class="toolbar" style="margin-bottom:12px"><div class="seg">${[['', '全部'], ['up', '上线'], ['down', '下线'], ['push', '下发'], ['admin', '管理'], ['system', '系统']]
        .map(([v, l]) => `<button data-type="${v}" class="${v === type ? 'active' : ''}">${l}</button>`).join('')}</div></div>${eventList(d.events)}`;
    } else {
      const d = await GET(`/logs/charon?lines=${lines}`);
      body = `<div class="toolbar" style="margin-bottom:12px"><span class="small">来源：${esc(d.source)}</span>
        <select id="log-lines" style="width:auto">${[100, 300, 1000, 3000].map((n) => `<option ${n === lines ? 'selected' : ''}>${n}</option>`).join('')}</select>
        <button class="btn sm" data-act="refresh">刷新</button></div><pre class="code log" id="log-pre">${esc(d.text)}</pre>`;
    }
    main.innerHTML = `
      <div class="page-head"><div><h1>日志</h1></div>
        <div class="seg"><button data-tab="events" class="${tab === 'events' ? 'active' : ''}">面板事件</button><button data-tab="charon" class="${tab === 'charon' ? 'active' : ''}">strongSwan 日志</button></div></div>
      <div class="card">${body}</div>`;
    $$('[data-tab]').forEach((b) => b.addEventListener('click', () => { tab = b.dataset.tab; render(); }));
    $$('[data-type]').forEach((b) => b.addEventListener('click', () => { type = b.dataset.type; render(); }));
    const sel = $('#log-lines');
    if (sel) sel.addEventListener('change', () => { lines = Number(sel.value); render(); });
    const pre = $('#log-pre');
    if (pre) pre.scrollTop = pre.scrollHeight;
    pageActions = { refresh: render };
  };
  await render();
}

// ================= 设置 =================
async function pageSettings(main) {
  const [d, pk, svc] = await Promise.all([GET('/settings'), GET('/pki'), GET('/service')]);
  const s = d.settings;
  const st = svc.status;
  const chk = (name, title, help) => `<label class="check full"><input type="checkbox" name="${name}" ${s[name] === '1' ? 'checked' : ''}><span><b>${title}</b><span class="small">${help}</span></span></label>`;
  const certRow = (label, c) => (c ? `<dt>${label}</dt><dd>${esc(c.subject.replace(/\n/g, ', '))}<div class="small">${esc(c.san || '')} · 到期 ${fmtTime(c.validTo)}</div></dd>` : `<dt>${label}</dt><dd class="muted">未生成</dd>`);
  main.innerHTML = `
    <div class="page-head"><div><h1>设置</h1></div></div>
    <div class="card"><h2>网络</h2>
      <form class="form" id="f-net" autocomplete="off">
        <label>云服务器公网地址 <span class="help">H3C 与客户端连接的地址，IP 或域名</span><input name="public_host" value="${esc(s.public_host)}" placeholder="1.2.3.4 或 vpn.example.com"></label>
        <label>Hub 身份标识 <span class="help">站点隧道中云端的 IKE ID（FQDN）</span><input name="hub_id" value="${esc(s.hub_id)}"></label>
        <label>隧道网段 <span class="help">Hub = ${esc(d.tunnel.hubIp)}，用户地址池 ${esc(d.tunnel.poolRange)}</span><input name="tunnel_net" value="${esc(s.tunnel_net)}"></label>
        <label>客户端 DNS <span class="help">可选，例如公司内网 DNS 192.168.1.1</span><input name="client_dns" value="${esc(s.client_dns)}"></label>
        <label>客户端连接名称<input name="vpn_name" value="${esc(s.vpn_name)}"></label>
        <span></span>
        ${chk('site_mesh', '站点互通', '各站点之间可以经云端互相访问（修改后需要重新下发各站点 H3C 配置）')}
        ${chk('users_full_tunnel', '远程用户全局代理', '远程用户的全部流量都经云端出网（云端做 NAT），默认只有访问公司内网的流量走 VPN')}
      </form>
      <div class="mt"><button class="btn primary" data-act="save-net">保存</button></div>
    </div>

    <div class="card"><h2>证书</h2>
      <div class="grid two">
        <div><dl class="kv">
          ${certRow('CA 根证书', pk.ca)}
          ${certRow('服务器证书', pk.server)}
          <dt>已吊销证书</dt><dd>${pk.crl} 个</dd>
        </dl>
        <div class="mt toolbar"><a class="btn sm" href="/api/pki/ca.crt">下载 CA 证书</a>${s.cert_mode === 'selfsigned' ? '<button class="btn sm" data-act="renew-server">重新签发服务器证书</button>' : ''}</div></div>
        <form class="form" id="f-cert" autocomplete="off">
          <label class="full">服务器证书来源<select name="cert_mode">
            <option value="selfsigned" ${s.cert_mode === 'selfsigned' ? 'selected' : ''}>面板自签 CA（客户端配置文件会自动带上 CA）</option>
            <option value="custom" ${s.cert_mode === 'custom' ? 'selected' : ''}>自定义证书（如 Let's Encrypt，需使用域名）</option></select></label>
          <label class="full">证书路径<input name="custom_cert_path" value="${esc(s.custom_cert_path)}" placeholder="/etc/letsencrypt/live/vpn.example.com/cert.pem"></label>
          <label class="full">私钥路径<input name="custom_key_path" value="${esc(s.custom_key_path)}" placeholder="/etc/letsencrypt/live/vpn.example.com/privkey.pem"></label>
          <label class="full">中间证书链路径（可选）<input name="custom_chain_path" value="${esc(s.custom_chain_path)}" placeholder="/etc/letsencrypt/live/vpn.example.com/chain.pem"></label>
          <div class="full"><button class="btn" type="button" data-act="save-cert">保存证书设置</button></div>
        </form>
      </div>
    </div>

    <div class="card"><div class="card-head"><h2>strongSwan 服务</h2>
      <div class="toolbar"><button class="btn sm" data-act="svc-reload">重新加载配置</button><button class="btn sm danger" data-act="svc-restart">重启 strongSwan</button></div></div>
      ${svc.network ? `<div class="alert warn">${esc(svc.network)}</div>` : ''}
      <dl class="kv">
        <dt>状态</dt><dd>${st.running ? `<span class="badge ok">运行中</span> ${esc(st.version)}` : `<span class="badge err">未运行</span> ${esc(st.error || '')}`}</dd>
        ${st.running ? `<dt>系统</dt><dd>${esc(st.system || '')}</dd><dt>启动时间</dt><dd>${esc(st.since || '')}</dd>` : ''}
        <dt>配置目录</dt><dd class="mono">${esc(svc.paths.swanctlDir)}</dd>
        <dt>VICI</dt><dd class="mono">${esc(svc.paths.vici)}</dd>
        <dt>数据目录</dt><dd class="mono">${esc(svc.paths.data)}</dd>
        <dt>用户可访问网段</dt><dd class="mono">${svc.userNets.map(esc).join(', ')}</dd>
      </dl>
      <details class="mt"><summary>查看生成的 swanctl 配置（已隐藏密钥）</summary><pre class="code mt">${esc(svc.config || '(尚未生成)')}</pre></details>
    </div>

    <div class="grid two">
      <div class="card"><h2>管理员</h2>
        <form class="form" id="f-admin" autocomplete="off">
          <label class="full">用户名<input name="username" value="${esc(d.admin)}"></label>
          <label class="full">当前密码<input name="current_password" type="password" autocomplete="current-password"></label>
          <label class="full">新密码 <span class="help">至少 8 位</span><input name="new_password" type="password" autocomplete="new-password"></label>
        </form>
        <div class="mt"><button class="btn" data-act="save-admin">修改</button></div>
      </div>
      <div class="card"><h2>数据保留</h2>
        <form class="form" id="f-retention">
          <label>流量数据（天）<input name="traffic_retention_days" type="number" min="1" value="${esc(s.traffic_retention_days)}"></label>
          <label>事件日志（天）<input name="events_retention_days" type="number" min="1" value="${esc(s.events_retention_days)}"></label>
        </form>
        <div class="mt"><button class="btn" data-act="save-retention">保存</button></div>
      </div>
    </div>`;

  const saveForm = async (sel, msg) => {
    const f = formData($(sel));
    for (const k of Object.keys(f)) if (typeof f[k] === 'boolean') f[k] = f[k] ? '1' : '0';
    afterSave(await PUT('/settings', f), msg);
    meta = { deviceTypes: {}, presets: {} };
    route();
  };
  pageActions = {
    'save-net': () => saveForm('#f-net', '已保存并重新加载'),
    'save-cert': () => saveForm('#f-cert', '证书设置已保存'),
    'save-retention': () => saveForm('#f-retention', '已保存'),
    'save-admin': async () => {
      await PUT('/admin', formData($('#f-admin')));
      toast('已修改，请重新登录', 'ok');
      showLogin();
    },
    'renew-server': async () => {
      if (!(await confirmBox('重新签发服务器证书？使用自签 CA 的客户端无需任何改动。'))) return;
      afterSave(await POST('/pki/renew-server'), '已重新签发');
      route();
    },
    'svc-reload': async () => {
      afterSave(await POST('/service/reload'), '配置已重新加载');
      route();
    },
    'svc-restart': async () => {
      if (!(await confirmBox('重启 strongSwan 会断开所有站点和用户，确定继续？', { danger: true, okText: '重启' }))) return;
      toast('正在重启……');
      afterSave(await POST('/service/restart'), 'strongSwan 已重启');
      route();
    },
  };
}

// ================= 全局事件 =================
let pageActions = {};
const globalActions = {
  logout: async () => {
    await POST('/logout').catch(() => {});
    showLogin();
  },
  'site-new': () => openSiteForm(null),
  'user-new': () => openUserForm(),
  copy: (el) => copyText(el.dataset.text),
  reveal: (el) => {
    const s = el.previousElementSibling;
    const shown = s.textContent !== '••••••••••••';
    s.textContent = shown ? '••••••••••••' : s.dataset.secret;
    el.textContent = shown ? '显示' : '隐藏';
  },
  'conn-kill': async (el) => {
    if (!(await confirmBox('确定断开这个连接？'))) return;
    await POST(`/connections/${el.dataset.id}/terminate`);
    toast('已断开', 'ok');
    setTimeout(route, 1200);
  },
};

document.addEventListener('click', async (e) => {
  const el = e.target.closest('[data-act]');
  if (!el) return;
  const fn = pageActions[el.dataset.act] || globalActions[el.dataset.act];
  if (!fn) return;
  e.preventDefault();
  el.disabled = true;
  try {
    await fn(el, e);
  } catch (err) {
    toast(err.message, 'error');
  } finally {
    el.disabled = false;
  }
});

// ================= 登录 =================
function showLogin() {
  clearInterval(refreshTimer);
  $('#modal-root').innerHTML = '';
  $('#app').hidden = true;
  $('#login').hidden = false;
  $('#login-error').textContent = '';
}

async function showApp(username) {
  $('#login').hidden = true;
  $('#app').hidden = false;
  $('#whoami').textContent = username || '';
  await route();
}

$('#login-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const f = formData(e.target);
  try {
    const r = await api('POST', '/login', f);
    e.target.reset();
    showApp(r.username);
  } catch (err) {
    $('#login-error').textContent = err.message;
  }
});

window.addEventListener('hashchange', () => {
  if (!$('#app').hidden) route();
});

(async () => {
  try {
    const s = await api('GET', '/session');
    if (s.loggedIn) showApp(s.username);
    else showLogin();
  } catch {
    showLogin();
  }
})();
