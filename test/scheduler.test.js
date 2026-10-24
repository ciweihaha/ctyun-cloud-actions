const { test } = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

// 打桩 native_tasks / browser_hang：scheduler.js 在 require 时解构引用，必须先占 require.cache
const calls = { sign: 0, aiChat: 0, nativeHang: 0, browserHang: 0 };
function stubModule(rel, exportsObj) {
  const resolved = require.resolve(path.join(__dirname, '..', 'app', 'tasks', rel));
  require.cache[resolved] = { id: resolved, filename: resolved, loaded: true, exports: exportsObj };
}
stubModule('native_tasks.js', {
  executeNativeSign: async () => { calls.sign++; return { isCompleted: false }; },
  executeNativeAiChat: async () => { calls.aiChat++; },
  executeNativeHang: async () => { calls.nativeHang++; return { isCompleted: false }; },
});
stubModule('browser_hang.js', {
  executeBrowserHang: async () => { calls.browserHang++; return { ok: true, hangMinutes: 61, reason: 'time_up' }; },
  HANG_DURATION_MS: 61 * 60 * 1000,
  findBrowserPath: () => null,
});
const schedPath = require.resolve('../app/tasks/scheduler.js');
delete require.cache[schedPath];
const { TaskScheduler, TASK_STATUS } = require('../app/tasks/scheduler.js');

function makeScheduler({ accounts, settings, clients }) {
  const logs = [];
  const notifications = [];
  const s = new TaskScheduler({
    getAccounts: () => accounts,
    getSettings: () => settings,
    getClient: (acc) => clients[acc.id],
    appendLog: (src, msg, lvl) => logs.push({ src, msg, lvl }),
    sendNotification: (acc, title, content) => notifications.push({ title, content }),
    saveConfig: () => {},
  });
  return { s, logs, notifications };
}
function bjNowPlusHours(h) {
  const bj = new Date(new Date().toLocaleString('en-US', { timeZone: 'Asia/Shanghai' }));
  bj.setHours(bj.getHours() + h);
  return `${String(bj.getHours()).padStart(2, '0')}:${String(bj.getMinutes()).padStart(2, '0')}`;
}
function futureTarget() { return bjNowPlusHours(3); }
function pastTarget() { return bjNowPlusHours(-3); }

function baseSettings(overrides = {}) {
  return { cron: { executeTime: futureTarget(), enableSubCron: false, ...(overrides.cron || {}) }, ...overrides.rest };
}
function doneTasks() {
  return [
    { name: '登录AI云电脑打卡', status: 2, current: 1, total: 1 },
    { name: 'AI对话互动', status: 2, current: 1, total: 1 },
    { name: '使用1小时云电脑', status: 2, current: 3600, total: 3600 },
  ];
}
function makeClient({ tasks = [], refreshError = null } = {}) {
  return {
    metrics: { officialTasks: tasks },
    refreshOfficialTasks: async () => { if (refreshError) throw new Error(refreshError); },
    getRewards: async () => [],
    resolveTask: undefined,
  };
}
function ctyunAcc(overrides = {}) {
  return {
    id: 'a1', name: '账号A', enabled: true, platform: 'ctyun',
    features: { sign: true, aiChat: true, cloudHang: true, browserHang: true, autoRedeem: false, keepAlive: true },
    stats: {}, redeemConfig: {}, ...overrides,
  };
}
// taskGate 兜底映射读取 acc.features[taskType]（sign 例外映射 autoSign 字段不存在时回落 features.sign?）
// 注意：兜底逻辑 key = taskType==='sign' ? 'autoSign' : taskType，故测试账号用 autoSign 表示签到开关。
function accWithFeatures(f) {
  const a = ctyunAcc();
  a.features = { keepAlive: true, ...f };
  return a;
}

test('evaluateAccountCompletion: 官方全达成时五项口径（含 browserHang/redeem）', () => {
  const acc = accWithFeatures({ autoSign: true, aiChat: true, cloudHang: true, browserHang: true, autoRedeem: true });
  acc.redeemConfig = { prodId: 123, lastRedeemDate: new Date().toLocaleDateString('sv-SE', { timeZone: 'Asia/Shanghai' }) };
  const client = makeClient({ tasks: doneTasks() });
  const { s } = makeScheduler({ accounts: [acc], settings: baseSettings(), clients: { a1: client } });
  const states = s.evaluateAccountCompletion(acc, client, {});
  assert.equal(states.sign.status, TASK_STATUS.COMPLETED);
  assert.equal(states.aiChat.status, TASK_STATUS.COMPLETED);
  assert.equal(states.cloudHang.status, TASK_STATUS.COMPLETED);
  assert.equal(states.browserHang.status, TASK_STATUS.COMPLETED, 'browserHang 必须被判定（旧实现遗漏）');
  assert.equal(states.redeem.status, TASK_STATUS.COMPLETED);
  assert.equal(TaskScheduler.allStatesCompleted(states), true);
});

test('evaluateAccountCompletion: browserHang 未达成时 allDone 为假（旧实现误判）', () => {
  const tasks = doneTasks();
  tasks[2] = { name: '使用1小时云电脑', status: 1, current: 600, total: 3600 };
  const acc = accWithFeatures({ autoSign: true, aiChat: true, cloudHang: false, browserHang: true, autoRedeem: false });
  const client = makeClient({ tasks });
  const { s } = makeScheduler({ accounts: [acc], settings: baseSettings(), clients: { a1: client } });
  const states = s.evaluateAccountCompletion(acc, client, {});
  assert.equal(states.browserHang.status, TASK_STATUS.PENDING);
  assert.equal(TaskScheduler.allStatesCompleted(states), false);
});

test('evaluateAccountCompletion: 刷新失败一律 UNKNOWN，绝不判完成', () => {
  const acc = accWithFeatures({ autoSign: true, aiChat: true, cloudHang: true, browserHang: true });
  const client = makeClient({ tasks: doneTasks(), refreshError: 'timeout' });
  const { s } = makeScheduler({ accounts: [acc], settings: baseSettings(), clients: { a1: client } });
  const states = s.evaluateAccountCompletion(acc, client, { refreshFailed: true });
  assert.equal(states.sign.status, TASK_STATUS.UNKNOWN);
  assert.equal(TaskScheduler.allStatesCompleted(states), false);
});

test('evaluateAccountCompletion: redeem 今日策略未命中记 SKIPPED、命中未执行记 PENDING', () => {
  const today = new Date().toLocaleDateString('sv-SE', { timeZone: 'Asia/Shanghai' });
  const day = parseInt(today.split('-')[2], 10);
  const acc = accWithFeatures({ autoRedeem: true });
  acc.redeemConfig = { prodId: 1, scheduleType: 'monthly_days', monthlyDays: [day === 1 ? 2 : 1], lastRedeemDate: '' };
  const client = makeClient({ tasks: [] });
  const { s } = makeScheduler({ accounts: [acc], settings: baseSettings(), clients: { a1: client } });
  assert.equal(s.evaluateAccountCompletion(acc, client, {}).redeem.status, TASK_STATUS.SKIPPED);
  acc.redeemConfig = { prodId: 1, scheduleType: 'daily', lastRedeemDate: '' };
  assert.equal(s.evaluateAccountCompletion(acc, client, {}).redeem.status, TASK_STATUS.PENDING);
});

test('checkStartupCatchup: 刷新失败不得设置 lastCompletedDate（旧实现用旧缓存误判）', async () => {
  const acc = accWithFeatures({ autoSign: true, aiChat: true, cloudHang: true, browserHang: true });
  const client = makeClient({ tasks: doneTasks(), refreshError: 'network down' });
  const { s, logs } = makeScheduler({ accounts: [acc], settings: baseSettings(), clients: { a1: client } });
  // executeTime 设为未来，避免进入 runAllAccounts
  await s.checkStartupCatchup();
  assert.equal(s.lastCompletedDate, '', '刷新失败时不得标记今日完成');
  assert.ok(logs.some(l => /状态未知/.test(l.msg)), '应有状态未知告警日志');
});

test('checkStartupCatchup: 全部达成（含 browserHang）时标记完成', async () => {
  const acc = accWithFeatures({ autoSign: true, aiChat: true, cloudHang: true, browserHang: true, autoRedeem: false });
  const client = makeClient({ tasks: doneTasks() });
  const { s } = makeScheduler({ accounts: [acc], settings: baseSettings(), clients: { a1: client } });
  await s.checkStartupCatchup();
  const today = new Date().toLocaleDateString('sv-SE', { timeZone: 'Asia/Shanghai' });
  assert.equal(s.lastCompletedDate, today);
});

test('checkStartupCatchup: 官方任务未全部达成时不标记完成', async () => {
  const tasks = doneTasks(); tasks[0] = { name: '登录AI云电脑打卡', status: 1, current: 0, total: 1 };
  const acc = accWithFeatures({ autoSign: true, aiChat: true, cloudHang: true, browserHang: true });
  const client = makeClient({ tasks });
  const { s } = makeScheduler({ accounts: [acc], settings: baseSettings(), clients: { a1: client } });
  await s.checkStartupCatchup();
  assert.equal(s.lastCompletedDate, '');
});

test('heartbeatTick: browserHang Cron 同分钟只触发一次（分钟去重）', async () => {
  calls.browserHang = 0;
  const bj = new Date(new Date().toLocaleString('en-US', { timeZone: 'Asia/Shanghai' }));
  const expr = `${bj.getMinutes()} ${bj.getHours()} * * *`;
  const acc = accWithFeatures({ browserHang: true });
  const client = makeClient({});
  const settings = baseSettings({ cron: { enableSubCron: true, browserHangCron: expr, signCron: '', aiChatCron: '', cloudHangCron: '', redeemCron: '' } });
  const { s } = makeScheduler({ accounts: [acc], settings, clients: { a1: client } });
  await s.heartbeatTick();
  await s.heartbeatTick();
  assert.equal(calls.browserHang, 1, `同分钟应只启动一次，实际 ${calls.browserHang}`);
});

test('heartbeatTick: browserHang 未配 Cron 时兜底走 executeBrowserHang 而非原生挂机', async () => {
  calls.browserHang = 0; calls.nativeHang = 0;
  const acc = accWithFeatures({ browserHang: true, cloudHang: true });
  const client = makeClient({});
  const settings = baseSettings({ cron: { enableSubCron: true, browserHangCron: '', signCron: '0 0 1 1 *', aiChatCron: '0 0 1 1 *', cloudHangCron: '0 0 1 1 *', redeemCron: '0 0 1 1 *', executeTime: bjNowPlusHours(0) } });
  const { s } = makeScheduler({ accounts: [acc], settings, clients: { a1: client } });
  await s.heartbeatTick();
  assert.equal(calls.browserHang, 1, '兜底应执行浏览器真挂机');
  assert.equal(calls.nativeHang, 0, '兜底不应误走原生挂机');
});

test('heartbeatTick: 非法分项 Cron 只告警一次且不触发任务', async () => {
  const bj = new Date(new Date().toLocaleString('en-US', { timeZone: 'Asia/Shanghai' }));
  const acc = accWithFeatures({ autoSign: true });
  const client = makeClient({});
  const settings = baseSettings({ cron: { enableSubCron: true, signCron: '*/0 * * * *' } });
  const { s, logs } = makeScheduler({ accounts: [acc], settings, clients: { a1: client } });
  await s.heartbeatTick();
  // 换一分钟键再来一次，告警仍只应出现一次（_cronWarned 去重）
  s.lastTriggerMinute = '';
  await s.heartbeatTick();
  const warns = logs.filter(l => /表达式非法/.test(l.msg));
  assert.equal(warns.length, 1);
  assert.equal(calls.sign, 0);
});

test('stop(): 清除开机补跑定时器句柄', () => {
  const acc = accWithFeatures({});
  const client = makeClient({});
  const { s } = makeScheduler({ accounts: [acc], settings: baseSettings(), clients: { a1: client } });
  s.start();
  assert.ok(s.startupTimer, 'start 后应持有补跑定时器句柄');
  s.stop();
  assert.equal(s.startupTimer, null);
  assert.equal(s.timer, null);
});

test('runAllAccounts: 账号链路异常时不得标记今日完成（回归：异常账号不得从判定中消失）', async () => {
  const acc = accWithFeatures({});
  const client = {
    isWebUserActive: false,
    wsAlive: true,
    metrics: { officialTasks: [] },
    refreshOfficialTasks: async () => { throw new Error('official api down'); },
  };
  const { s, notifications } = makeScheduler({ accounts: [acc], settings: baseSettings(), clients: { a1: client } });
  await s.runAllAccounts('test');
  assert.equal(s.lastCompletedDate, '');
  assert.ok(notifications.every(n => !/圆满达成/.test(n.title)), '不得发送圆满达成通知');
});

test('runAllAccounts: 网页避让跳过的账号按官方状态纳入判定', async () => {
  const acc = accWithFeatures({ autoSign: true, aiChat: true, cloudHang: true, browserHang: true, autoRedeem: false });
  const client = {
    isWebUserActive: true,
    wsAlive: true,
    metrics: { officialTasks: doneTasks() },
    refreshOfficialTasks: async () => {},
  };
  const { s } = makeScheduler({ accounts: [acc], settings: baseSettings(), clients: { a1: client } });
  await s.runAllAccounts('test');
  const today = new Date().toLocaleDateString('sv-SE', { timeZone: 'Asia/Shanghai' });
  assert.equal(s.lastCompletedDate, today, '官方已全达成的避让账号应判完成');
});
