'use strict';
// 通过 SSH 把生成的命令下发到 H3C（Comware V5/V7）。
// H3C 没有公网 IP 时，只要隧道已建立，云端就可以经隧道访问它的 LAN 地址（源地址为 Hub IP）。
const { Client } = require('ssh2');

// Comware 提示符：<H3C>、[H3C]、[H3C-acl-ipv4-adv-3100]、[H3C-ikev2-keychain-ipsp-hub-peer-hub]
const PROMPT_RE = /(?:^|[\r\n])[<\[][^\r\n<>\[\]]{1,128}[>\]]\s*$/;
const CONFIRM_RE = /\[Y\/N\]\s*:?\s*$/i;
const ERROR_RE = /^\s*(%.*|Error:.*|.*Unrecognized command.*|.*Incomplete command.*|.*Wrong parameter.*|.*Too many parameters.*|.*Ambiguous command.*|.*does not exist.*|.*[Ff]ailed to .*)$/m;

const LEGACY_ALGOS = {
  kex: {
    append: ['diffie-hellman-group14-sha1', 'diffie-hellman-group-exchange-sha1', 'diffie-hellman-group1-sha1'],
  },
  serverHostKey: { append: ['ssh-rsa', 'ssh-dss'] },
  cipher: { append: ['aes128-cbc', 'aes256-cbc', '3des-cbc'] },
  hmac: { append: ['hmac-sha1', 'hmac-md5'] },
};

function push({ host, port, username, password, commands, onLine }) {
  return new Promise((resolve, reject) => {
    const conn = new Client();
    const transcript = [];
    const errors = [];
    let buffer = '';
    let waiter = null;
    let finished = false;
    let completed = false;

    const log = (s) => {
      transcript.push(s);
      if (onLine) onLine(s);
    };

    const finish = (err) => {
      if (finished) return;
      finished = true;
      clearTimeout(globalTimer);
      try {
        conn.end();
      } catch {}
      const result = { ok: !err && errors.length === 0, transcript: transcript.join(''), errors };
      if (err) {
        result.error = err.message;
        return reject(Object.assign(err, { result }));
      }
      resolve(result);
    };
    const globalTimer = setTimeout(() => finish(new Error('下发超时（超过 5 分钟）')), 5 * 60 * 1000);

    const waitPrompt = (stream, timeoutMs = 20000) =>
      new Promise((res, rej) => {
        const check = () => {
          if (CONFIRM_RE.test(buffer)) {
            stream.write('Y\n');
            buffer = '';
            return false;
          }
          if (PROMPT_RE.test(buffer)) {
            const out = buffer;
            buffer = '';
            waiter = null;
            clearTimeout(t);
            res(out);
            return true;
          }
          return false;
        };
        const t = setTimeout(() => {
          waiter = null;
          rej(new Error(`等待设备提示符超时，最后输出: ${buffer.slice(-200)}`));
        }, timeoutMs);
        waiter = check;
        check();
      });

    conn.on('ready', () => {
      conn.shell({ term: 'vt100', cols: 512, rows: 200 }, async (err, stream) => {
        if (err) return finish(err);
        stream.on('data', (d) => {
          const s = d.toString('utf8').replace(/\x1b\[[0-9;]*[A-Za-z]/g, '').replace(/ {2,}\x08+/g, '');
          buffer += s;
          log(s);
          if (waiter) waiter();
        });
        stream.on('close', () => finish(completed ? null : new Error('设备提前关闭了连接')));
        try {
          await waitPrompt(stream, 30000);
          stream.write('screen-length disable\n');
          await waitPrompt(stream);
          for (const { cmd, tolerate } of commands) {
            const line = cmd.trim();
            if (!line) continue;
            stream.write(line + '\n');
            const out = await waitPrompt(stream, line.startsWith('save') ? 120000 : 20000);
            const body = out.split(/\r?\n/).slice(1).join('\n');
            const m = body.match(ERROR_RE);
            if (m && !tolerate) {
              errors.push({ command: line, message: m[0].trim() });
            }
          }
          completed = true;
          stream.write('quit\n');
          setTimeout(() => finish(null), 500);
        } catch (e) {
          finish(e);
        }
      });
    });
    conn.on('error', (e) => finish(new Error(`SSH 连接失败: ${e.message}`)));
    conn.connect({
      host,
      port: port || 22,
      username,
      password,
      readyTimeout: 20000,
      tryKeyboard: true,
      algorithms: LEGACY_ALGOS,
    });
    conn.on('keyboard-interactive', (_n, _i, _l, prompts, cb) => cb(prompts.map(() => password)));
  });
}

module.exports = { push };
