const { test } = require('node:test');
const assert = require('node:assert/strict');
const { attemptRedeemOrder } = require('../app/tasks/redeem_order.js');

const noSleep = async () => {};
function fetchReturning(sequence) {
  let i = 0;
  const fn = async () => {
    const item = sequence[Math.min(i, sequence.length - 1)];
    i++;
    if (item === 'throw') throw new Error('socket hang up');
    if (item === 'badjson') return { json: async () => { throw new Error('invalid json'); } };
    return { json: async () => item };
  };
  fn.count = () => i;
  return fn;
}
const base = { url: 'https://example.invalid/order', payload: { points: 100 }, headers: {}, sleepFn: noSleep };

test('首次成功：1 次调用即 success', async () => {
  const f = fetchReturning([{ code: 0 }]);
  const r = await attemptRedeemOrder({ ...base, fetchFn: f });
  assert.equal(r.status, 'success');
  assert.equal(f.count(), 1);
});

test('明确业务失败可重试，第 3 次成功', async () => {
  const f = fetchReturning([{ code: 1001, msg: '系统繁忙' }, { code: 1001, msg: '系统繁忙' }, { code: 0 }]);
  const r = await attemptRedeemOrder({ ...base, fetchFn: f });
  assert.equal(r.status, 'success');
  assert.equal(f.count(), 3);
});

test('致命业务错误（积分不足）立即终止，不重试', async () => {
  const f = fetchReturning([{ code: 2001, msg: '积分不足' }, { code: 0 }]);
  const r = await attemptRedeemOrder({ ...base, fetchFn: f });
  assert.equal(r.status, 'failed');
  assert.equal(f.count(), 1);
});

test('风控类错误标记 risk_blocked', async () => {
  const f = fetchReturning([{ code: 3001, msg: '触发风控' }]);
  const r = await attemptRedeemOrder({ ...base, fetchFn: f });
  assert.equal(r.status, 'risk_blocked');
});

test('核心回归：网络异常（可能已受理）绝不重试，返回 unknown 且只调用 1 次', async () => {
  const f = fetchReturning(['throw', { code: 0 }]);
  const r = await attemptRedeemOrder({ ...base, fetchFn: f });
  assert.equal(r.status, 'unknown');
  assert.equal(f.count(), 1, '网络异常后绝不能发第二次下单请求');
});

test('响应体解析失败同样视为结果不明确', async () => {
  const f = fetchReturning(['badjson', { code: 0 }]);
  const r = await attemptRedeemOrder({ ...base, fetchFn: f });
  assert.equal(r.status, 'unknown');
  assert.equal(f.count(), 1);
});

test('业务错误重试耗尽返回 failed 且共 3 次', async () => {
  const f = fetchReturning([{ code: 1001, msg: '系统繁忙' }]);
  const r = await attemptRedeemOrder({ ...base, fetchFn: f });
  assert.equal(r.status, 'failed');
  assert.equal(f.count(), 3);
});
