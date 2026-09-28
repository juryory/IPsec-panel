'use strict';
// 命令行工具：node src/cli.js <命令>
//   reset-password [新密码]   重置管理员密码（不填则随机生成）
//   status                    查看 strongSwan 与站点/用户状态
//   reload                    重新生成并加载 strongSwan 配置
const config = require('./config');
const { q } = require('./db');
const auth = require('./auth');
const { randomPassword } = require('./util');

async function main() {
  const [cmd, arg] = process.argv.slice(2).filter((a) => !a.startsWith('--'));
  switch (cmd) {
    case 'reset-password': {
      auth.ensureAdmin();
      const pw = arg || randomPassword();
      const name = auth.adminName() || config.adminUser;
      auth.setAdminPassword(name, pw);
      console.log(`管理员密码已重置\n  用户名: ${name}\n  密码:   ${pw}`);
      break;
    }
    case 'status': {
      const strongswan = require('./strongswan');
      const monitor = require('./monitor');
      const st = await strongswan.status();
      console.log(st.running ? `strongSwan 运行中: ${st.version}` : `strongSwan 未运行: ${st.error}`);
      const conns = st.running ? await monitor.connections().catch(() => []) : [];
      const online = new Set(conns.filter((c) => c.up).map((c) => c.entity));
      console.log('\n站点:');
      for (const s of q.all('SELECT name, enabled, subnets FROM sites')) {
        console.log(`  ${online.has(`site:${s.name}`) ? '●' : '○'} ${s.name.padEnd(20)} ${s.enabled ? '' : '[已禁用] '}${JSON.parse(s.subnets).join(', ')}`);
      }
      console.log('\n在线用户:');
      for (const c of conns.filter((x) => x.kind === 'user')) console.log(`  ● ${c.label.padEnd(20)} ${c.vips.join(', ')}  来自 ${c.remoteHost}`);
      break;
    }
    case 'reload': {
      const strongswan = require('./strongswan');
      const r = await strongswan.sync('命令行重新加载');
      console.log(r.output);
      break;
    }
    default:
      console.log('用法: node src/cli.js <reset-password [密码] | status | reload>');
      process.exitCode = 1;
  }
}

main().catch((e) => {
  console.error(e.message);
  process.exit(1);
});
