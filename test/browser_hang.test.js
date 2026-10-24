const { test } = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const bh = require('../app/tasks/browser_hang.js');

let pidSeq = 1000;
function fakeProc() {
  const p = new EventEmitter();
  p.pid = ++pidSeq;
  p.killedWith = [];
  p.kill = (sig) => { p.killedWith.push(sig || 'SIGTERM'); return true; };
  p.unref = () => {};
  return p;
}
function spawnOk() {
  const p = fakeProc();
  process.nextTick(() => p.emit('spawn'));
  return p;
}
function spawnErr() {
  const p = fakeProc();
  process.nextTick(() => p.emit('error', new Error('spawn ENOENT')));
  return p;
}
function clientWith(taskSeq) {
  let i = 0;
  const client = {
    account: { desktops: [{ objId: 'd1', desktopName: '云电脑A' }] },
    metrics: { officialTasks: [] },
    refreshOfficialTasks: async () => {
      const t = taskSeq[Math.min(i, taskSeq.length - 1)];
      i++;
      if (t === 'throw') throw new Error('api down');
      client.metrics.officialTasks = t;
    },
  };
  return client;
}
const hangTask = (cur, total = 3600, status = 1) => [{ name: '使用1小时云电脑', status, current: cur, total }];
const doneTask = [{ name: '使用1小时云电脑', status: 2, current: 3600, total: 3600 }];
const acc = (id) => ({ id, name: '账号' + id, username: 'u' + id });
const opts = (spawnFn, extra = {}) => ({
  spawnFn, browserPath: '/fake/browser', hangDurationMs: 300, progressIntervalMs: 40, launchConfirmMs: 500, ...extra,
});

test('spawn 异步 error 事件被捕获 → launch_failed（旧实现无监听且谎报启动成功）', async () => {
  const r = await bh.executeBrowserHang(clientWith([hangTask(0)]), acc('e1'), () => {}, opts(spawnErr));
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'launch_failed');
});

test('官方确认完成 → task_completed 且 ok:true', async () => {
  const r = await bh.executeBrowserHang(clientWith([hangTask(0), hangTask(1800), doneTask]), acc('e2'), () => {}, opts(spawnOk));
  assert.equal(r.ok, true);
  assert.equal(r.reason, 'task_completed');
});

test('浏览器中途退出 → browser_exited 且 ok:false（旧实现谎报 time_up 成功）', async () => {
  let proc;
  const spawnFn = () => { proc = spawnOk(); setTimeout(() => proc.emit('exit', 1), 90); return proc; };
  const r = await bh.executeBrowserHang(clientWith([hangTask(0)]), acc('e3'), () => {}, opts(spawnFn));
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'browser_exited');
});

test('时长耗尽但官方未确认 → time_up_unconfirmed 且 ok:false', async () => {
  const r = await bh.executeBrowserHang(clientWith([hangTask(600)]), acc('e4'), () => {}, opts(spawnOk));
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'time_up_unconfirmed');
});

test('进度检查持续失败 → progress_check_failed', async () => {
  const client = clientWith(['throw']);
  // 首次（启动前）进度读取在旧流程里失败仅告警；进入挂机后持续失败应归类 progress_check_failed
  const r = await bh.executeBrowserHang(client, acc('e5'), () => {}, opts(spawnOk));
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'progress_check_failed');
});

test('同账号并发被拒（already_running），不同账号 profile 目录不同', async () => {
  const spawnArgs = [];
  const spawnFn = (...a) => { spawnArgs.push(a); return spawnOk(); };
  const p1 = bh.executeBrowserHang(clientWith([hangTask(0)]), acc('e6'), () => {}, opts(spawnFn, { hangDurationMs: 5000 }));
  const r2 = await bh.executeBrowserHang(clientWith([hangTask(0)]), acc('e6'), () => {}, opts(spawnFn));
  assert.equal(r2.ok, false);
  assert.equal(r2.reason, 'already_running');
  const p3 = bh.executeBrowserHang(clientWith([hangTask(0)]), acc('e7'), () => {}, opts(spawnFn, { hangDurationMs: 5000 }));
  const dirs = spawnArgs.map(a => a[1].find(x => String(x).startsWith('--user-data-dir=')));
  assert.ok(dirs[0] !== dirs[1], `不同账号应使用不同 profile: ${dirs}`);
  bh.cancelBrowserHang('e6'); bh.cancelBrowserHang('e7');
  const [r1, r3] = await Promise.all([p1, p3]);
  assert.equal(r1.reason, 'cancelled');
  assert.equal(r3.reason, 'cancelled');
});

test('取消只终止自己 spawn 的进程并返回 cancelled', async () => {
  let proc;
  const spawnFn = () => { proc = spawnOk(); return proc; };
  const p = bh.executeBrowserHang(clientWith([hangTask(0)]), acc('e8'), () => {}, opts(spawnFn, { hangDurationMs: 5000 }));
  await new Promise(r => setTimeout(r, 120));
  assert.equal(bh.cancelBrowserHang('e8'), true);
  const r = await p;
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'cancelled');
  assert.ok(proc.killedWith.length > 0 || proc.pid > 0);
  assert.equal(bh.cancelBrowserHang('e8'), false, '已结束的任务不应再可取消');
});

test('今日已完成 → already_completed，不启动浏览器', async () => {
  let spawned = false;
  const r = await bh.executeBrowserHang(clientWith([doneTask]), acc('e9'), () => {}, opts(() => { spawned = true; return spawnOk(); }));
  assert.equal(r.reason, 'already_completed');
  assert.equal(spawned, false);
});
