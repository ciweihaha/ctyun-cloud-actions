// 复审第二轮：代理客户端断开必须销毁上游。
// 说明：直接 require server.js 会让测试进程无法自然退出（server.js 载入后
// 有常驻句柄），故真实场景放在子进程脚本里跑（test/helpers/ 下，不会被
// node --test 的 test/*.test.js  glob 误跑），本文件只断言子进程退出码与
// 输出；子进程内是真实 server + mock https.request，全 mock，不碰真实
// 账号与外网。
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

test('代理：响应流式传输中客户端断开，上游被销毁；正常结束不误伤', { timeout: 60000 }, async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ctyun-proxy-test-'));
  const child = spawn(process.execPath, [path.join(__dirname, 'helpers', 'proxy_disconnect_run.js')], {
    env: { ...process.env, CTYUN_DATA_DIR: tmpDir, CTYUN_DASHBOARD_ADMIN_PASSWORD: 'TestPass123' },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let out = '';
  let err = '';
  child.stdout.on('data', (c) => { out += c; });
  child.stderr.on('data', (c) => { err += c; });
  const code = await Promise.race([
    new Promise((r) => child.on('close', r)),
    new Promise((_, rej) => setTimeout(() => { child.kill('SIGKILL'); rej(new Error('子进程 45 秒未退出')); }, 45000)),
  ]);
  fs.rmSync(tmpDir, { recursive: true, force: true });
  assert.equal(code, 0, `子进程应以 0 退出，实际 ${code}，stderr：${err.slice(-2000)}`);
  assert.match(out, /DISCONNECT-PASS/, '断开场景应通过');
  assert.match(out, /NORMAL-PASS/, '正常结束对照组应通过');
});
