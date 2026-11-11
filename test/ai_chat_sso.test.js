const { test } = require('node:test');
const assert = require('node:assert/strict');
const { isSsoAuthSuccess } = require('../app/tasks/native_tasks.js');

test('数字成功码 0 + sessionKey 即成功', () => {
  assert.equal(isSsoAuthSuccess({ resultCode: 0, data: { sessionKey: 'abc' } }), true);
});

// 深查第 9 轮：旧实现 `resultCode !== 0` 只认数字，{resultCode:"0"}
// 会被误判鉴权失败，AI 问答在第 3 步即夭折；现字符串码同义。
test('字符串成功码 "0" + sessionKey 同样成功（回归主用例）', () => {
  assert.equal(isSsoAuthSuccess({ resultCode: '0', data: { sessionKey: 'abc' } }), true);
});

test('字符串成功码带空白 " 0 " 同样成功', () => {
  assert.equal(isSsoAuthSuccess({ resultCode: ' 0 ', data: { sessionKey: 'abc' } }), true);
});

test('SSO 只认 0：200 不算成功（与旧口径一致）', () => {
  assert.equal(isSsoAuthSuccess({ resultCode: 200, data: { sessionKey: 'abc' } }), false);
  assert.equal(isSsoAuthSuccess({ resultCode: '200', data: { sessionKey: 'abc' } }), false);
});

test('非零码（数字/字符串）均失败', () => {
  assert.equal(isSsoAuthSuccess({ resultCode: 40010, data: { sessionKey: 'abc' } }), false);
  assert.equal(isSsoAuthSuccess({ resultCode: '40010', data: { sessionKey: 'abc' } }), false);
  assert.equal(isSsoAuthSuccess({ resultCode: 'ERR', data: { sessionKey: 'abc' } }), false);
});

test('成功码但无 sessionKey 仍失败', () => {
  assert.equal(isSsoAuthSuccess({ resultCode: 0, data: {} }), false);
  assert.equal(isSsoAuthSuccess({ resultCode: 0 }), false);
  assert.equal(isSsoAuthSuccess({ resultCode: '0', data: { sessionKey: '' } }), false);
});

test('缺失/非对象响应一律失败，不抛 TypeError', () => {
  assert.equal(isSsoAuthSuccess(null), false);
  assert.equal(isSsoAuthSuccess(undefined), false);
  assert.equal(isSsoAuthSuccess('ok'), false);
  assert.equal(isSsoAuthSuccess(42), false);
  assert.equal(isSsoAuthSuccess({}), false);
  assert.equal(isSsoAuthSuccess({ resultCode: 0, data: null }), false);
});
