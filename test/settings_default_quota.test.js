const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const {
  validateSettingsUpdate,
  sanitizeSettingsForRestore,
  DEFAULT_QUOTA_MIN,
  DEFAULT_QUOTA_MAX,
} = require('../app/settings_validation');
const { AuthManager } = require('../app/auth_manager.js');

// 深查第 6 轮：defaultQuota（普通用户默认配额）此前零校验。
// PUT "abc" / -5 / 1000 均可落盘；注册时 `defaultQuota || 2` 只救 falsy 值，
// "abc" 原样成为新用户 maxQuota，配额门 `owned >= "abc"` 恒假（无限加账号），
// -5 则 `0 >= -5` 恒真（新用户一台都加不了）。单用户改配额 updateUserQuota
// 已有 `parseInt(...) || 2` 守卫，唯独全局默认值无校验，属口径遗漏。
// 只测纯函数与 AuthManager.register（server.js 的 HTTP 接线层因缺 ws 依赖
// 本机无法启动，见 VERIFICATION.md 未验项）；接线本身为既有直调 + 改用
// normalized 合并，node --check 与 diff 审阅覆盖。

function makeAuth(defaultQuota) {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ctyun-dq-test-'));
  const configManager = {
    config: { users: [], accounts: [], settings: { allowRegistration: true, defaultQuota } },
    dataDir,
    saveConfig() {},
    sessionStore: null,
  };
  return new AuthManager(configManager);
}

test('defaultQuota：合法值通过并归一化为 Number（含边界 1 与 999）', () => {
  assert.equal(DEFAULT_QUOTA_MIN, 1);
  assert.equal(DEFAULT_QUOTA_MAX, 999);
  assert.deepEqual(validateSettingsUpdate({ defaultQuota: 2 }), { ok: true, normalized: { defaultQuota: 2 } });
  assert.equal(validateSettingsUpdate({ defaultQuota: 1 }).ok, true);
  assert.equal(validateSettingsUpdate({ defaultQuota: 999 }).ok, true);
  const r = validateSettingsUpdate({ defaultQuota: '5' });
  assert.equal(r.ok, true);
  assert.strictEqual(r.normalized.defaultQuota, 5);
});

test('defaultQuota：非法值被拒（非数值 / 负数 / 零 / 小数 / 布尔 / 超限）', () => {
  const bad = ['abc', '2台', -5, 0, 2.5, true, 1000, 1e9, NaN, Infinity, {}, []];
  for (const v of bad) {
    const r = validateSettingsUpdate({ defaultQuota: v });
    assert.equal(r.ok, false, `defaultQuota=${JSON.stringify(v)} 应被拒`);
    assert.match(r.error, /defaultQuota/);
  }
});

test('defaultQuota：null / undefined / 空串按未提供处理', () => {
  for (const v of [null, undefined, '']) {
    const r = validateSettingsUpdate({ defaultQuota: v });
    assert.equal(r.ok, true, `defaultQuota=${JSON.stringify(v)} 应按未提供处理`);
  }
});

test('defaultQuota：还原清洗丢弃毒值、保留现值，合法值归一化', () => {
  const bad = sanitizeSettingsForRestore({ defaultQuota: 'abc' }, { defaultQuota: 2 });
  assert.deepEqual(bad.dropped, ['defaultQuota']);
  assert.ok(!('defaultQuota' in bad.sanitized), '毒值应被删掉，由调用方深合并保留现值');
  const neg = sanitizeSettingsForRestore({ defaultQuota: -5 }, { defaultQuota: 2 });
  assert.deepEqual(neg.dropped, ['defaultQuota']);
  const ok = sanitizeSettingsForRestore({ defaultQuota: '5' }, { defaultQuota: 2 });
  assert.deepEqual(ok.dropped, []);
  assert.strictEqual(ok.sanitized.defaultQuota, 5);
});

test('register：毒 defaultQuota 被钳制回合法配额，合法值不变', () => {
  // "abc"（修前：新用户 maxQuota="abc"，配额门恒假、可无限加账号）
  assert.strictEqual(makeAuth('abc').register('u-abc', 'long-enough-1').user.maxQuota, 2);
  // -5（修前：新用户 maxQuota=-5，`0 >= -5` 恒真、一台都加不了）
  // 钳制到下限 1：仍是合法配额，新用户至少能加 1 台
  assert.strictEqual(makeAuth(-5).register('u-neg', 'long-enough-1').user.maxQuota, 1);
  // 0（修前经 `|| 2` 回落为 2；钳制后为下限 1，同样合法）
  assert.strictEqual(makeAuth(0).register('u-zero', 'long-enough-1').user.maxQuota, 1);
  // 超限 1000 钳制到 999（与管理员自身 maxQuota 上限一致）
  assert.strictEqual(makeAuth(1000).register('u-big', 'long-enough-1').user.maxQuota, 999);
  // 合法值与数字字符串不变；缺省回落默认 2
  assert.strictEqual(makeAuth(5).register('u-5', 'long-enough-1').user.maxQuota, 5);
  assert.strictEqual(makeAuth('3').register('u-3', 'long-enough-1').user.maxQuota, 3);
  assert.strictEqual(makeAuth(undefined).register('u-def', 'long-enough-1').user.maxQuota, 2);
});

test('register：钳制后的配额门恢复正常（2 台上限：第 3 台应被挡）', () => {
  const am = makeAuth('abc');
  const reg = am.register('u-gate', 'long-enough-1');
  assert.strictEqual(reg.user.maxQuota, 2);
  // 逐字照抄 server.js 四处配额门的表达式：owned >= userMax
  const userMax = reg.user.maxQuota;
  assert.equal(0 >= userMax, false);
  assert.equal(1 >= userMax, false);
  assert.equal(2 >= userMax, true);
});
