const { test } = require('node:test');
const assert = require('node:assert/strict');
const { executeRedeem, isRedeemDueToday, isRedeemRunAllowed } = require('../app/tasks/redeem_task.js');

const noSleep = async () => {};
function fetchReturning(sequence) {
  let i = 0;
  const calls = [];
  const fn = async (url, init) => {
    calls.push({ url, body: init && init.body ? JSON.parse(init.body) : null });
    const item = sequence[Math.min(i, sequence.length - 1)];
    i++;
    if (item === 'throw') throw new Error('socket hang up');
    if (item === 'badjson') return { json: async () => { throw new Error('invalid json'); } };
    return { json: async () => item };
  };
  fn.count = () => i;
  fn.calls = calls;
  return fn;
}

function makeClient({ points = 10000, desktopId = 0 } = {}) {
  return {
    metrics: { userPoints: points, desktopId },
    getSignedHeaders: (extra) => ({ ...(extra || {}), Authorization: 'test' }),
  };
}
function makeAcc({ autoRedeem = true, stats = {} } = {}) {
  return { id: 't1', name: 'test', user: '13800000000', features: { autoRedeem }, stats };
}
const baseConf = {
  enabled: true,
  targetType: 'redeem',
  desktopId: '12345',
  desktopName: 'test-pc',
  prodId: 17023101,
  prodName: '8C16G升配包1天 (500积分)',
  prodType: 'pointstplupgrade',
  costPoints: 500,
  maxRedeemTimes: 1,
  scheduleType: 'monthly_days',
  monthlyDays: [-1],
  intervalDays: 1,
  pointType: 1,
  lastRedeemDate: '',
};
const logs = [];
const onLog = (tag, msg, level = 'info') => logs.push({ tag, msg, level });

// ---------- 日期判定 ----------

test('isRedeemDueToday：monthlyDays 命中指定日', () => {
  assert.equal(isRedeemDueToday({ ...baseConf, monthlyDays: [15] }, '2026-11-15'), true);
  assert.equal(isRedeemDueToday({ ...baseConf, monthlyDays: [15] }, '2026-11-16'), false);
});

test('isRedeemDueToday：-1 代表月末最后一天', () => {
  assert.equal(isRedeemDueToday({ ...baseConf, monthlyDays: [-1] }, '2026-11-30'), true);
  assert.equal(isRedeemDueToday({ ...baseConf, monthlyDays: [-1] }, '2026-11-29'), false);
  assert.equal(isRedeemDueToday({ ...baseConf, monthlyDays: [-1] }, '2026-02-28'), true);
});

test('isRedeemDueToday：当天已兑过返回 false', () => {
  assert.equal(isRedeemDueToday({ ...baseConf, lastRedeemDate: '2026-11-30' }, '2026-11-30'), false);
});

test('isRedeemDueToday：daily 与 interval_days', () => {
  assert.equal(isRedeemDueToday({ ...baseConf, scheduleType: 'daily' }, '2026-11-15'), true);
  assert.equal(isRedeemDueToday({ ...baseConf, scheduleType: 'interval_days', intervalDays: 30, lastRedeemDate: '' }, '2026-11-15'), true);
  assert.equal(isRedeemDueToday({ ...baseConf, scheduleType: 'interval_days', intervalDays: 30, lastRedeemDate: '2026-11-01' }, '2026-11-15'), false);
  assert.equal(isRedeemDueToday({ ...baseConf, scheduleType: 'interval_days', intervalDays: 30, lastRedeemDate: '2026-10-01' }, '2026-11-15'), true);
});

test('isRedeemDueToday：无 prodId 返回 false', () => {
  assert.equal(isRedeemDueToday({}, '2026-11-30'), false);
});

// ---------- 两班限流 ----------

test('isRedeemRunAllowed：定时跑只允许早班（UTC 0 点）', () => {
  assert.equal(isRedeemRunAllowed('schedule', 0), true);
  assert.equal(isRedeemRunAllowed('schedule', 12), false);
  assert.equal(isRedeemRunAllowed('schedule', 8), false);
});

test('isRedeemRunAllowed：手动触发与本地运行不受限', () => {
  assert.equal(isRedeemRunAllowed('workflow_dispatch', 12), true);
  assert.equal(isRedeemRunAllowed(undefined, 12), true);
  assert.equal(isRedeemRunAllowed('', 12), true);
});

// ---------- executeRedeem ----------

test('未配置 prodId：跳过且不发任何下单请求', async () => {
  const f = fetchReturning([{ code: 0 }]);
  const r = await executeRedeem(makeClient(), makeAcc(), {}, onLog, { fetchFn: f, todayStr: '2026-11-30' });
  assert.equal(r.status, 'skipped');
  assert.equal(f.count(), 0);
});

test('enabled=false：跳过', async () => {
  const f = fetchReturning([{ code: 0 }]);
  const r = await executeRedeem(makeClient(), makeAcc(), { ...baseConf, enabled: false }, onLog, { fetchFn: f, todayStr: '2026-11-30' });
  assert.equal(r.status, 'skipped');
  assert.equal(f.count(), 0);
});

test('账号关闭 autoRedeem：跳过', async () => {
  const f = fetchReturning([{ code: 0 }]);
  const r = await executeRedeem(makeClient(), makeAcc({ autoRedeem: false }), baseConf, onLog, { fetchFn: f, todayStr: '2026-11-30' });
  assert.equal(r.status, 'skipped');
  assert.equal(f.count(), 0);
});

test('当天已兑过：completed 且不下单', async () => {
  const f = fetchReturning([{ code: 0 }]);
  const r = await executeRedeem(makeClient(), makeAcc(), { ...baseConf, lastRedeemDate: '2026-11-30' }, onLog, { fetchFn: f, todayStr: '2026-11-30' });
  assert.equal(r.status, 'completed');
  assert.equal(f.count(), 0);
});

test('未到兑换日：跳过且不下单', async () => {
  const f = fetchReturning([{ code: 0 }]);
  const r = await executeRedeem(makeClient(), makeAcc(), baseConf, onLog, { fetchFn: f, todayStr: '2026-11-29' });
  assert.equal(r.status, 'skipped');
  assert.equal(f.count(), 0);
});

test('需绑定云电脑但无有效 desktopId：跳过且不下单', async () => {
  const f = fetchReturning([{ code: 0 }]);
  const conf = { ...baseConf, desktopId: '' };
  const r = await executeRedeem(makeClient({ desktopId: 0 }), makeAcc(), conf, onLog, { fetchFn: f, todayStr: '2026-11-30' });
  assert.equal(r.status, 'skipped');
  assert.equal(f.count(), 0);
});

test('desktopId 可从 client.metrics 回退取得', async () => {
  const f = fetchReturning([{ code: 0 }]);
  const conf = { ...baseConf, desktopId: '' };
  const r = await executeRedeem(makeClient({ desktopId: 999 }), makeAcc(), conf, onLog, { fetchFn: f, todayStr: '2026-11-30' });
  assert.equal(r.status, 'success');
  assert.equal(f.calls[0].body.sku[0].attrs[0].attrVal, 999);
});

test('积分不足：跳过且不下单', async () => {
  const f = fetchReturning([{ code: 0 }]);
  const r = await executeRedeem(makeClient({ points: 100 }), makeAcc(), baseConf, onLog, { fetchFn: f, todayStr: '2026-11-30' });
  assert.equal(r.status, 'skipped');
  assert.match(r.message, /积分不足/);
  assert.equal(f.count(), 0);
});

test('积分未知（0）时不预检，交给服务端判定', async () => {
  const f = fetchReturning([{ code: 2001, msg: '积分不足' }]);
  const r = await executeRedeem(makeClient({ points: 0 }), makeAcc(), baseConf, onLog, { fetchFn: f, todayStr: '2026-11-30' });
  assert.equal(r.status, 'failed');
  assert.equal(f.count(), 1);
});

test('命中兑换日且积分充足：下单成功，报文与 dashboard 同口径', async () => {
  const f = fetchReturning([{ code: 0 }]);
  const r = await executeRedeem(makeClient(), makeAcc(), { ...baseConf, maxRedeemTimes: 2 }, onLog, { fetchFn: f, todayStr: '2026-11-30' });
  assert.equal(r.status, 'success');
  assert.equal(r.costPoints, 1000);
  assert.equal(r.times, 2);
  assert.equal(f.count(), 1);
  const body = f.calls[0].body;
  assert.equal(body.busiChannel, '010');
  assert.equal(body.orderType, 1);
  assert.equal(body.points, 1000);
  assert.equal(body.sku[0].prodId, 17023101);
  assert.equal(body.sku[0].prodType, 'pointstplupgrade');
  assert.deepEqual(body.sku[0].attrs, [{ attrKey: 'bindDesktopId', attrVal: 12345 }]);
  assert.match(f.calls[0].url, /placeOrder/);
});

test('非绑定类商品用 mobilephone 属性', async () => {
  const f = fetchReturning([{ code: 0 }]);
  const conf = { ...baseConf, prodId: 17029999, prodType: 'other', prodName: '其他商品', costPoints: 100 };
  const r = await executeRedeem(makeClient(), makeAcc(), conf, onLog, { fetchFn: f, todayStr: '2026-11-30' });
  assert.equal(r.status, 'success');
  assert.deepEqual(f.calls[0].body.sku[0].attrs, [{ attrKey: 'mobilephone' }]);
});

test('网络异常：unknown 且只调用 1 次（绝不重试防重复扣积分）', async () => {
  const f = fetchReturning(['throw', { code: 0 }]);
  const r = await executeRedeem(makeClient(), makeAcc(), baseConf, onLog, { fetchFn: f, todayStr: '2026-11-30' });
  assert.equal(r.status, 'unknown');
  assert.equal(f.count(), 1);
});

test('风控类错误：risk_blocked 且只调用 1 次', async () => {
  const f = fetchReturning([{ code: 3001, msg: '触发风控' }]);
  const r = await executeRedeem(makeClient(), makeAcc(), baseConf, onLog, { fetchFn: f, todayStr: '2026-11-30' });
  assert.equal(r.status, 'risk_blocked');
  assert.equal(f.count(), 1);
});

test('字符串成功码 "0" 同义成功', async () => {
  const f = fetchReturning([{ code: '0' }]);
  const r = await executeRedeem(makeClient(), makeAcc(), baseConf, onLog, { fetchFn: f, todayStr: '2026-11-30' });
  assert.equal(r.status, 'success');
  assert.equal(f.count(), 1);
});
