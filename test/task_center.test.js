const { test } = require('node:test');
const assert = require('node:assert/strict');
const { normalizeBusinessCode, isTaskCenterExpired, isTaskListOk, isPointsOk } = require('../app/task_center.js');

test('normalizeBusinessCode：数字原样，数字字符串归一化，非数字原样返回', () => {
  assert.equal(normalizeBusinessCode(0), 0);
  assert.equal(normalizeBusinessCode(40010), 40010);
  assert.equal(normalizeBusinessCode('0'), 0);
  assert.equal(normalizeBusinessCode('40010'), 40010);
  assert.equal(normalizeBusinessCode(' 0 '), 0);
  assert.equal(normalizeBusinessCode('ERR'), 'ERR');
  assert.equal(normalizeBusinessCode(null), null);
  assert.equal(normalizeBusinessCode(undefined), undefined);
  assert.equal(normalizeBusinessCode(true), true);
});

test('isTaskCenterExpired：数字/字符串 40010 均判过期', () => {
  assert.equal(isTaskCenterExpired({ code: 40010 }), true);
  assert.equal(isTaskCenterExpired({ code: '40010' }), true);
  assert.equal(isTaskCenterExpired({ code: ' 40010 ' }), true);
});

test('isTaskCenterExpired：msg 含过期文案仍判过期（旧口径保留）', () => {
  assert.equal(isTaskCenterExpired({ code: 0, msg: '登录信息已过期' }), true);
  assert.equal(isTaskCenterExpired({ code: 500, msg: '会话已过期，请重新登录' }), true);
  assert.equal(isTaskCenterExpired({ code: 500, msg: '系统繁忙' }), false);
});

test('isTaskCenterExpired：正常码与空响应不判过期', () => {
  assert.equal(isTaskCenterExpired({ code: 0 }), false);
  assert.equal(isTaskCenterExpired({ code: '0' }), false);
  assert.equal(isTaskCenterExpired(null), false);
  assert.equal(isTaskCenterExpired({}), false);
});

// 深查第 10 轮：旧实现 `code === 0` 只认数字，{code:"0"} 会让整轮
// 官方刷新判失败，签到/AI/挂机全被搁置；现字符串码同义。
test('isTaskListOk：数字/字符串 0 + data 均可用（回归主用例）', () => {
  assert.equal(isTaskListOk({ code: 0, data: [{ taskDefName: '登录AI云电脑' }] }), true);
  assert.equal(isTaskListOk({ code: '0', data: [{ taskDefName: '登录AI云电脑' }] }), true);
});

test('isTaskListOk：缺 data / 非零码 / 空响应均不可用', () => {
  assert.equal(isTaskListOk({ code: 0 }), false);
  assert.equal(isTaskListOk({ code: 0, data: null }), false);
  assert.equal(isTaskListOk({ code: 1, data: [] }), false);
  assert.equal(isTaskListOk({ code: '1', data: [] }), false);
  assert.equal(isTaskListOk(null), false);
});

test('isPointsOk：数字/字符串 0 + 非空数组均可用（回归主用例）', () => {
  assert.equal(isPointsOk({ code: 0, data: [{ points: 100 }] }), true);
  assert.equal(isPointsOk({ code: '0', data: [{ points: 100 }] }), true);
});

test('isPointsOk：空数组 / 非数组 data / 非零码均不可用', () => {
  assert.equal(isPointsOk({ code: 0, data: [] }), false);
  assert.equal(isPointsOk({ code: 0, data: {} }), false);
  assert.equal(isPointsOk({ code: 0 }), false);
  assert.equal(isPointsOk({ code: '500', data: [{ points: 1 }] }), false);
  assert.equal(isPointsOk(null), false);
});
