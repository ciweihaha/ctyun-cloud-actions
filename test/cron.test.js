const { test } = require('node:test');
const assert = require('node:assert/strict');
// scheduler.js 在 require 时只定义类与函数（定时器在 start() 才挂），可安全加载。
// 其依赖 native_tasks/browser_hang 为纯模块加载，无顶层副作用。
const sched = require('../app/tasks/scheduler.js');
const { validateCronExpression, shouldRunCron } = sched;

test('validateCronExpression: 合法表达式通过', () => {
  for (const e of ['0 2 * * *', '*/15 * * * *', '0 3,20 * * *', '30 8 1 * *', '0 9 * * 1-5', '0 0 29 2 *', '15 */2 * * *']) {
    const r = validateCronExpression(e);
    assert.equal(r.ok, true, `${e} 应合法: ${r.error || ''}`);
  }
});

test('validateCronExpression: 非法输入给出明确错误', () => {
  const bad = [
    ['', /不能为空/],
    ['0 2 * *', /5 个字段/],
    ['0 2 * * * *', /5 个字段/],
    ['*/0 * * * *', /步长/],
    ['60 * * * *', /分钟.*越界/],
    ['* 24 * * *', /小时.*越界/],
    ['* * 0 * *', /日期.*越界/],
    ['* * * 13 *', /月份.*越界/],
    ['* * * * 8', /星期.*越界/],
    ['a b c d e', /不是合法数字|越界/],
    ['5-2 * * * *', /范围/],
    ['1,,2 * * * *', /空/],
  ];
  for (const [expr, re] of bad) {
    const r = validateCronExpression(expr);
    assert.equal(r.ok, false, `${JSON.stringify(expr)} 应非法`);
    assert.match(r.error, re, `${JSON.stringify(expr)} 错误信息应匹配 ${re}，实际: ${r.error}`);
  }
});

test('shouldRunCron: dom 与 dow 均限定时按标准 Cron OR 语义', () => {
  // 2026-01-05 是周一、非 1 号；2026-02-01 是周日、是 1 号；2026-02-03 周二非 1 号；2026-01-01 周四、是 1 号
  const mon = new Date(2026, 0, 5, 9, 0);
  const firstSunday = new Date(2026, 1, 1, 9, 0);
  const neither = new Date(2026, 1, 3, 9, 0);
  assert.equal(mon.getDay(), 1); assert.equal(firstSunday.getDate(), 1); assert.equal(firstSunday.getDay(), 0);
  assert.equal(shouldRunCron('0 9 1 * 1', mon), true, '周一应命中');
  assert.equal(shouldRunCron('0 9 1 * 1', firstSunday), true, '1 号应命中');
  assert.equal(shouldRunCron('0 9 1 * 1', neither), false, '两者都不是应不命中');
});

test('shouldRunCron: 仅限定其一时按 AND 常规语义', () => {
  const mon = new Date(2026, 0, 5, 9, 0);
  const tue = new Date(2026, 0, 6, 9, 0);
  assert.equal(shouldRunCron('0 9 * * 1', mon), true);
  assert.equal(shouldRunCron('0 9 * * 1', tue), false);
  assert.equal(shouldRunCron('0 9 5 * *', mon), true);
  assert.equal(shouldRunCron('0 9 6 * *', mon), false);
});

test('shouldRunCron: dow=7 等同周日', () => {
  const sunday = new Date(2026, 1, 1, 9, 0);
  assert.equal(sunday.getDay(), 0);
  assert.equal(shouldRunCron('0 9 * * 7', sunday), true);
  assert.equal(shouldRunCron('0 9 * * 0', sunday), true);
});

test('shouldRunCron: 步长与范围、非法表达式恒假', () => {
  const d = new Date(2026, 0, 5, 9, 30);
  assert.equal(shouldRunCron('*/15 * * * *', d), true);
  assert.equal(shouldRunCron('*/20 * * * *', d), false);
  assert.equal(shouldRunCron('30 9-18 * * *', d), true);
  assert.equal(shouldRunCron('30 19-23 * * *', d), false);
  assert.equal(shouldRunCron('*/0 * * * *', d), false);
  assert.equal(shouldRunCron('nonsense', d), false);
  assert.equal(shouldRunCron('', d), false);
});
