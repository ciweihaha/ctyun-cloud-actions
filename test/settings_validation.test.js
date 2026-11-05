const { test } = require('node:test');
const assert = require('node:assert/strict');
const { validateSettingsUpdate, isValidTargetTime } = require('../app/settings_validation');

// 深查第 3 轮：PUT /api/settings 保存入口前置校验。
// 只测纯函数 validateSettingsUpdate（server.js 的 HTTP 接线层因缺 ws 依赖
// 本机无法启动，见 VERIFICATION.md 未验项）；接线本身为 6 行直调 + 改用
// normalized 合并，node --check 与 diff 审阅覆盖。

test('空体与无关字段原样通过', () => {
  assert.deepEqual(validateSettingsUpdate({}), { ok: true, normalized: {} });
  const r = validateSettingsUpdate({ systemTitle: 'x', notify: { enabled: false } });
  assert.equal(r.ok, true);
  assert.equal(r.normalized.systemTitle, 'x');
  assert.deepEqual(r.normalized.notify, { enabled: false });
});

test('非对象体被拒', () => {
  for (const bad of [null, undefined, [], 'x', 42]) {
    const r = validateSettingsUpdate(bad);
    assert.equal(r.ok, false, JSON.stringify(bad));
    assert.match(r.error, /JSON 对象/);
  }
});

test('keepAliveSeconds：合法数字与数字字符串通过并归一化为 Number', () => {
  assert.deepEqual(validateSettingsUpdate({ keepAliveSeconds: 60 }), { ok: true, normalized: { keepAliveSeconds: 60 } });
  const r = validateSettingsUpdate({ keepAliveSeconds: ' 120 ' });
  assert.equal(r.ok, true);
  assert.strictEqual(r.normalized.keepAliveSeconds, 120);
  assert.equal(validateSettingsUpdate({ keepAliveSeconds: 15 }).ok, true);
  assert.equal(validateSettingsUpdate({ keepAliveSeconds: 3600 }).ok, true);
});

test('keepAliveSeconds：非法值被拒（非数值 / 负数 / 零 / 小数 / 布尔 / 超限）', () => {
  const bad = ['abc', '60s', -5, 0, 60.5, true, 1e9, 3601, 14, NaN, Infinity, {}, []];
  for (const v of bad) {
    const r = validateSettingsUpdate({ keepAliveSeconds: v });
    assert.equal(r.ok, false, `keepAliveSeconds=${JSON.stringify(v)} 应被拒`);
    assert.match(r.error, /keepAliveSeconds/);
  }
});

test('keepAliveSeconds：null / undefined / 空串按未提供处理', () => {
  for (const v of [null, undefined, '']) {
    const r = validateSettingsUpdate({ keepAliveSeconds: v });
    assert.equal(r.ok, true, `keepAliveSeconds=${JSON.stringify(v)} 应按未提供处理`);
  }
});

test('pulseIntervalSeconds：合法与非法', () => {
  assert.equal(validateSettingsUpdate({ pulseIntervalSeconds: 30 }).ok, true);
  const r = validateSettingsUpdate({ pulseIntervalSeconds: '45' });
  assert.equal(r.ok, true);
  assert.strictEqual(r.normalized.pulseIntervalSeconds, 45);
  assert.equal(validateSettingsUpdate({ pulseIntervalSeconds: 10 }).ok, true);
  assert.equal(validateSettingsUpdate({ pulseIntervalSeconds: 3300 }).ok, true);
  for (const v of ['abc', 5, 3301, 0, -1, 30.5]) {
    const res = validateSettingsUpdate({ pulseIntervalSeconds: v });
    assert.equal(res.ok, false, `pulseIntervalSeconds=${JSON.stringify(v)} 应被拒`);
    assert.match(res.error, /pulseIntervalSeconds/);
  }
});

test('executeTime：合法值通过（含第 2 轮既定口径 "1:5" 与秒段）', () => {
  for (const t of ['01:20', '1:5', '00:00', '23:59', '01:20:30', '1:5:9']) {
    const r = validateSettingsUpdate({ cron: { executeTime: t } });
    assert.equal(r.ok, true, `executeTime=${t} 应通过`);
  }
  // 无 executeTime 的 cron 对象不干预（部分更新）
  assert.equal(validateSettingsUpdate({ cron: { enableSubCron: true } }).ok, true);
  assert.equal(validateSettingsUpdate({ cron: { executeTime: '' } }).ok, true);
});

test('executeTime：非法值被拒（越界 / 非法字符 / 全角冒号 / 非字符串）', () => {
  const bad = ['25:99', '24:00', '01:60', 'abc', '1：20', '01:20:60', '1', '01:20:30:40', 120, null, undefined];
  // null/undefined 按未提供处理，不在被拒之列
  for (const v of bad.filter((x) => x !== null && x !== undefined)) {
    const r = validateSettingsUpdate({ cron: { executeTime: v } });
    assert.equal(r.ok, false, `executeTime=${JSON.stringify(v)} 应被拒`);
    assert.match(r.error, /executeTime/);
  }
  assert.equal(validateSettingsUpdate({ cron: { executeTime: null } }).ok, true);
});

test('isValidTargetTime 与 scheduler.js 口径一致的抽查', () => {
  assert.equal(isValidTargetTime('01:20'), true);
  assert.equal(isValidTargetTime('1:5'), true);
  assert.equal(isValidTargetTime('25:99'), false);
  assert.equal(isValidTargetTime('1：20'), false);
  assert.equal(isValidTargetTime(120), false);
});

test('多字段同时非法时返回第一项错误；合法多字段一次性归一化', () => {
  const r = validateSettingsUpdate({ keepAliveSeconds: 'abc', pulseIntervalSeconds: 5 });
  assert.equal(r.ok, false);
  const ok = validateSettingsUpdate({ keepAliveSeconds: '60', pulseIntervalSeconds: '30', cron: { executeTime: '01:20' } });
  assert.equal(ok.ok, true);
  assert.deepEqual(ok.normalized, { keepAliveSeconds: 60, pulseIntervalSeconds: 30, cron: { executeTime: '01:20' } });
});

test('入参不被修改', () => {
  const body = { keepAliveSeconds: '60', pulseIntervalSeconds: '30' };
  validateSettingsUpdate(body);
  assert.strictEqual(body.keepAliveSeconds, '60');
  assert.strictEqual(body.pulseIntervalSeconds, '30');
});
