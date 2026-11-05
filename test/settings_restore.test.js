const { test } = require('node:test');
const assert = require('node:assert/strict');
const {
  validateSettingsUpdate,
  sanitizeSettingsForRestore,
} = require('../app/settings_validation');

// 深查第 4 轮：POST /api/config/import 备份还原路径的“丢弃式”清洗。
// 只测纯函数 sanitizeSettingsForRestore 与本轮补的校验口径
// （server.js 的 HTTP 接线层因本机缺 ws 依赖无法启动，见 VERIFICATION.md
// 未验项；接线本身为 1 行解构 + 1 行合并 + 日志/响应回告，node --check
// 与 diff 审阅覆盖）。

const CURRENT = {
  keepAliveSeconds: 60,
  pulseIntervalSeconds: 30,
  cron: { executeTime: '01:20', signCron: '0 2 * * *' },
};

// 与 server.js 消费点同款的表达式：还原后合并值须让它们算出有限数。
function consumerValues(settings) {
  const pulseConnectSec = Math.min(60, Math.max(15, settings.keepAliveSeconds || 20));
  const newKeepSeconds = settings.keepAliveSeconds || 60; // PUT :6209 热更新同款
  const resetDelayMs = newKeepSeconds * 1000; // resetCycleTimeout 同款
  return { pulseConnectSec, newKeepSeconds, resetDelayMs };
}

test('全毒备份：4 个非法字段全丢弃，现有好值原样保留，消费表达式有限', () => {
  const imported = {
    keepAliveSeconds: 'abc',
    pulseIntervalSeconds: 'abc',
    pulseIntervalMinutes: 'abc',
    cron: { executeTime: '25:99' },
  };
  const { sanitized, dropped } = sanitizeSettingsForRestore(imported, CURRENT);
  assert.deepEqual(dropped, [
    'keepAliveSeconds',
    'pulseIntervalSeconds',
    'pulseIntervalMinutes',
    'cron.executeTime',
  ]);
  // cron 深合并：现有触发时间与 signCron 保留
  assert.deepEqual(sanitized, { cron: { executeTime: '01:20', signCron: '0 2 * * *' } });
  const merged = { ...CURRENT, ...sanitized };
  assert.deepEqual(merged, CURRENT);
  const v = consumerValues(merged);
  assert.equal(v.pulseConnectSec, 60);
  assert.equal(v.newKeepSeconds, 60);
  assert.equal(v.resetDelayMs, 60000);
  assert.ok(Number.isFinite(v.pulseConnectSec) && Number.isFinite(v.resetDelayMs));
});

test('合法备份：数字字符串归一化为 Number，cron 合法值替换，零丢弃', () => {
  const { sanitized, dropped } = sanitizeSettingsForRestore(
    {
      keepAliveSeconds: '120',
      pulseIntervalSeconds: '45',
      pulseIntervalMinutes: '30',
      cron: { executeTime: '02:30' },
    },
    CURRENT
  );
  assert.deepEqual(dropped, []);
  assert.deepEqual(sanitized, {
    keepAliveSeconds: 120,
    pulseIntervalSeconds: 45,
    pulseIntervalMinutes: 30,
    cron: { executeTime: '02:30', signCron: '0 2 * * *' },
  });
});

test('cron 为非对象时整块丢弃，现有 cron 对象保留', () => {
  for (const badCron of ['abc', 123, [], true]) {
    const { sanitized, dropped } = sanitizeSettingsForRestore({ cron: badCron }, CURRENT);
    assert.deepEqual(sanitized, {}, `cron=${JSON.stringify(badCron)} 应整块丢弃`);
    assert.deepEqual(dropped, ['cron']);
    assert.deepEqual({ ...CURRENT, ...sanitized }, CURRENT);
  }
});

test('cron.executeTime 非法时只丢该键，其余子项照常合并、现有触发时间保留', () => {
  const { sanitized, dropped } = sanitizeSettingsForRestore(
    { cron: { executeTime: 'abc', enableSubCron: true } },
    CURRENT
  );
  assert.deepEqual(dropped, ['cron.executeTime']);
  assert.deepEqual(sanitized.cron, {
    executeTime: '01:20',
    signCron: '0 2 * * *',
    enableSubCron: true,
  });
});

test('cron.executeTime 合法时替换；无 executeTime 的 cron 对象不干预', () => {
  const r1 = sanitizeSettingsForRestore({ cron: { executeTime: '1:5' } }, CURRENT);
  assert.deepEqual(r1.dropped, []);
  assert.equal(r1.sanitized.cron.executeTime, '1:5');
  assert.equal(r1.sanitized.cron.signCron, '0 2 * * *');
  const r2 = sanitizeSettingsForRestore({ cron: { enableSubCron: true } }, CURRENT);
  assert.deepEqual(r2.dropped, []);
  assert.equal(r2.sanitized.cron.executeTime, '01:20');
});

test('null / 空串的已知字段按未提供处理：不覆盖现值，也不计入丢弃', () => {
  const { sanitized, dropped } = sanitizeSettingsForRestore(
    { keepAliveSeconds: null, pulseIntervalSeconds: '', cron: { executeTime: '' } },
    CURRENT
  );
  assert.deepEqual(dropped, []);
  assert.deepEqual({ ...CURRENT, ...sanitized }, CURRENT);
});

test('无关字段原样透传；非对象 settings 整体丢弃', () => {
  const r = sanitizeSettingsForRestore({ systemTitle: 'x', notify: { enabled: false } }, CURRENT);
  assert.deepEqual(r, {
    sanitized: { systemTitle: 'x', notify: { enabled: false } },
    dropped: [],
  });
  for (const bad of [null, undefined, 'x', 42, []]) {
    assert.deepEqual(sanitizeSettingsForRestore(bad, CURRENT), {
      sanitized: {},
      dropped: ['settings'],
    });
  }
});

test('数值边界：上下限通过、越界丢弃', () => {
  const cases = [
    ['keepAliveSeconds', 15, true],
    ['keepAliveSeconds', 3600, true],
    ['keepAliveSeconds', 14, false],
    ['keepAliveSeconds', 3601, false],
    ['keepAliveSeconds', -5, false],
    ['keepAliveSeconds', 1e9, false],
    ['keepAliveSeconds', 60.5, false],
    ['pulseIntervalSeconds', 10, true],
    ['pulseIntervalSeconds', 3300, true],
    ['pulseIntervalSeconds', 9, false],
    ['pulseIntervalSeconds', 3301, false],
    ['pulseIntervalMinutes', 1, true],
    ['pulseIntervalMinutes', 55, true],
    ['pulseIntervalMinutes', 45, true],
    ['pulseIntervalMinutes', 0, false],
    ['pulseIntervalMinutes', 56, false],
    ['pulseIntervalMinutes', 30.5, false],
  ];
  for (const [key, value, shouldKeep] of cases) {
    const { sanitized, dropped } = sanitizeSettingsForRestore({ [key]: value }, CURRENT);
    assert.equal(key in sanitized, shouldKeep, `${key}=${value} 应${shouldKeep ? '保留' : '丢弃'}`);
    assert.equal(dropped.includes(key), !shouldKeep, `${key}=${value} dropped 应为 ${!shouldKeep}`);
  }
});

test('入参与现值不被修改', () => {
  const imported = { keepAliveSeconds: '60', cron: { executeTime: 'abc' } };
  const current = { keepAliveSeconds: 60, cron: { executeTime: '01:20' } };
  sanitizeSettingsForRestore(imported, current);
  assert.strictEqual(imported.keepAliveSeconds, '60');
  assert.strictEqual(imported.cron.executeTime, 'abc');
  assert.strictEqual(current.cron.executeTime, '01:20');
});

// 本轮补的 validateSettingsUpdate 口径：cron 非对象、pulseIntervalMinutes。
test('PUT 校验：cron 为非对象时拒绝，null 按未提供处理', () => {
  for (const bad of ['abc', 123, [], true]) {
    const r = validateSettingsUpdate({ cron: bad });
    assert.equal(r.ok, false, `cron=${JSON.stringify(bad)} 应被拒`);
    assert.match(r.error, /cron/);
  }
  assert.equal(validateSettingsUpdate({ cron: null }).ok, true);
  assert.equal(validateSettingsUpdate({ cron: undefined }).ok, true);
  assert.equal(validateSettingsUpdate({ cron: { executeTime: '01:20' } }).ok, true);
});

test('PUT 校验：pulseIntervalMinutes 合法通过并归一化，非法拒绝', () => {
  assert.equal(validateSettingsUpdate({ pulseIntervalMinutes: 45 }).ok, true);
  assert.equal(validateSettingsUpdate({ pulseIntervalMinutes: 1 }).ok, true);
  assert.equal(validateSettingsUpdate({ pulseIntervalMinutes: 55 }).ok, true);
  const r = validateSettingsUpdate({ pulseIntervalMinutes: '45' });
  assert.equal(r.ok, true);
  assert.strictEqual(r.normalized.pulseIntervalMinutes, 45);
  for (const v of ['abc', 0, 56, 99999, 30.5, true]) {
    const res = validateSettingsUpdate({ pulseIntervalMinutes: v });
    assert.equal(res.ok, false, `pulseIntervalMinutes=${JSON.stringify(v)} 应被拒`);
    assert.match(res.error, /pulseIntervalMinutes/);
  }
  assert.equal(validateSettingsUpdate({ pulseIntervalMinutes: null }).ok, true);
});
