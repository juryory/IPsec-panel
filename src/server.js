'use strict';
const fs = require('node:fs');
const path = require('node:path');
const http = require('node:http');
const https = require('node:https');
const express = require('express');
const config = require('./config');
require('./db');
const auth = require('./auth');
const api = require('./api');
const strongswan = require('./strongswan');
const monitor = require('./monitor');
const { run } = require('./util');

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', config.trustProxy ? 'loopback, linklocal, uniquelocal' : false);

app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Content-Security-Policy', "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'");
  next();
});

app.use('/api', express.json({ limit: '1mb' }), api);
app.use(express.static(path.join(__dirname, '..', 'public'), { index: 'index.html', maxAge: 0 }));

// 统一错误处理
app.use((err, req, res, _next) => {
  const status = err.status || (err.type === 'entity.parse.failed' ? 400 : 500);
  if (status >= 500) console.error(err);
  res.status(status).json({ error: status >= 500 && !err.status ? `服务器错误：${err.message}` : err.message });
});

async function tlsOptions() {
  if (config.tls === 'custom') {
    return { cert: fs.readFileSync(config.tlsCert), key: fs.readFileSync(config.tlsKey) };
  }
  if (config.tls === 'auto') {
    const dir = path.join(config.dataDir, 'tls');
    const cert = path.join(dir, 'panel.crt');
    const key = path.join(dir, 'panel.key');
    if (!fs.existsSync(cert) || !fs.existsSync(key)) {
      fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
      await run(config.opensslBin, ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-sha256', '-days', '3650', '-keyout', key, '-out', cert, '-subj', '/CN=ipsec-panel']);
      fs.chmodSync(key, 0o600);
    }
    return { cert: fs.readFileSync(cert), key: fs.readFileSync(key) };
  }
  return null;
}

async function main() {
  const created = auth.ensureAdmin();
  if (created && created.password) {
    console.log('==================================================');
    console.log(' 已创建管理员账号');
    console.log(`   用户名: ${created.username}`);
    console.log(`   密码:   ${created.password}`);
    console.log(` （同时保存在 ${created.file}，修改密码后自动删除）`);
    console.log('==================================================');
  }

  const tls = await tlsOptions().catch((e) => {
    console.error('HTTPS 证书加载失败，改用 HTTP：', e.message);
    return null;
  });
  const server = tls ? https.createServer(tls, app) : http.createServer(app);
  server.on('error', (e) => {
    if (e.code === 'EADDRINUSE') {
      console.error(`端口 ${config.port} 已被占用，请用 PANEL_PORT 换一个端口`);
    } else if (e.code === 'EACCES') {
      console.error(`没有权限监听 ${config.host}:${config.port}。` + (process.platform === 'win32' ? '该端口可能在 Windows 保留端口段内（netsh interface ipv4 show excludedportrange protocol=tcp 查看），请用 PANEL_PORT 换一个端口' : '1024 以下端口需要 root 权限'));
    } else {
      console.error('HTTP 服务启动失败:', e.message);
    }
    process.exit(1);
  });
  server.listen(config.port, config.host, () => {
    console.log(`IPsec Panel 已启动: ${tls ? 'https' : 'http'}://${config.host}:${config.port}${config.mock ? '  [MOCK 模式]' : ''}`);
  });

  // 等 charon 就绪后把数据库里的配置加载进去（charon 重启、机器重启后都能自动恢复）
  (async () => {
    const ready = await strongswan.waitReady(60000);
    if (!ready) console.error('等待 strongSwan VICI 超时，稍后可在面板里点击“重新加载”');
    try {
      await strongswan.sync('面板启动');
    } catch (e) {
      console.error('初始加载配置失败:', e.message);
    }
    monitor.start();
  })();

  const shutdown = () => {
    monitor.stop();
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(0), 3000).unref();
  };
  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
