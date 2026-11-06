/**
 * 深查第 5 轮：cron 子项类型校验与调度器读值容错。
 *
 * 问题背景：PUT /api/settings 与备份还原入口只校验 cron.executeTime，
 * 分项 Cron 表达式（signCron 等 5 个）为非字符串真值（数字 / 布尔 / 对象 /
 * 数组）时原样落盘；调度器 hasActiveSubCronRules / getSubCronMap /
 * heartbeatTick 巡检与触发分支均以 `?.trim()` 读值——`?.` 只 guard
 * null / undefined，对 123 / true / {} 照样抛
 * `TypeError: cron.signCron?.trim is not a function`。首抛点在
 * hasActiveSubCronRules（heartbeatTick:525），随后巡检循环与触发分支
 * 同形态；getSubCronMap 还被 checkStartupCatchup 与 scheduleNextRun
 * 的精确定时器回调调用，三条触发路径全灭，且精确定时器抛错后不再重挂
 * （server.js 的全局 unhandledRejection 兜底只记日志、进程继续运行，
 * 故影响是调度停摆 + 每 30 秒一条错误日志，不是进程崩溃）。
 * 修复分两层：入口（PUT 400 拒绝、还原丢弃）+ 调度器读值侧
 * cronExprText（非字符串按“未填写”处理，手工改配置文件也不抛错）。
 * 只校验类型，不校验表达式内容：非法字符串仍由调度器侧
 * validateCronExpression 在运行时告警并跳过（既有口径，本轮不收紧）。
 */
'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const {
  validateSettingsUpdate,
  sanitizeSettingsForRestore,
  SUB_CRON_FIELDS,
} = require('../app/settings_validation');

// 打桩 native_tasks / browser_hang：scheduler.js 在 require 时解构引用，必须先占 require.cache
//（与 test/scheduler.test.js 同款）。
function stubModule(rel, exportsObj) {
  const resolved = require.resolve(path.join(__dirname, '..', 'app', 'tasks', rel));
  require.cache[resolved] = { id: resolved, filename: resolved, loaded: true, exports: exportsObj };
}
stubModule('native_tasks.js', {
  executeNativeSign: async () => ({ isCompleted: false }),
  executeNativeAiChat: async () => {},
  executeNativeHang: async () => ({ isCompleted: false }),
});
stubModule('browser_hang.js', {
  executeBrowserHang: async () => ({ ok: true, hangMinutes: 61, reason: 'time_up' }),
  HANG_DURATION_MS: 61 * 60 * 1000,
  findBrowserPath: () => null,
});
const { TaskScheduler } = require('../app/tasks/scheduler.js');

function makeScheduler(settings) {
  const logs = [];
  const s = new TaskScheduler({
    getAccounts: () => [],
    getSettings: () => settings,
    getClient: () => null,
    appendLog: (src, msg, lvl) => logs.push({ src, msg, lvl }),
    sendNotification: () => {},
    saveConfig: () => {},
  });
  return { s, logs };
}

const POISON_VALUES = [123, true, ['0 2 * * *'], {}];

test('PUT：5 个分项 Cron 表达式为非字符串时一律 400', () => {
  for (const field of SUB_CRON_FIELDS) {
    for (const bad of POISON_VALUES) {
      const r = validateSettingsUpdate({ cron: { executeTime: '01:20', [field]: bad } });
      assert.equal(r.ok, false, `${field}=${JSON.stringify(bad)} 应拒绝`);
      assert.match(r.error, new RegExp(field), '错误信息须指明字段');
    }
  }
});

test('PUT：enableSubCron 非布尔值时 400（字符串 "false" 为真值，会误启用）', () => {
  for (const bad of ['false', 'true', 1, 0]) {
    const r = validateSettingsUpdate({ cron: { executeTime: '01:20', enableSubCron: bad } });
    assert.equal(r.ok, false, `enableSubCron=${JSON.stringify(bad)} 应拒绝`);
    assert.match(r.error, /enableSubCron/);
  }
});

test('PUT：合法字符串、空值与布尔开关照常通过，入参不被修改', () => {
  const body = {
    cron: {
      executeTime: '01:20',
      enableSubCron: true,
      signCron: '0 2 * * *',
      aiChatCron: '',
      cloudHangCron: null,
      browserHangCron: '0 3 * * *',
      redeemCron: '0 7 * * *',
    },
  };
  const snapshot = JSON.stringify(body);
  const r = validateSettingsUpdate(body);
  assert.equal(r.ok, true);
  assert.equal(JSON.stringify(body), snapshot, '入参不得被修改');
  assert.equal(r.normalized.cron.signCron, '0 2 * * *');
});

test('PUT：非法字符串表达式仍放行（内容校验仍在调度器运行时，不收紧）', () => {
  const r = validateSettingsUpdate({ cron: { executeTime: '01:20', signCron: 'not a cron' } });
  assert.equal(r.ok, true);
});

test('还原：非字符串分项表达式与非布尔开关只丢弃、现值保留', () => {
  const current = { cron: { executeTime: '01:20', signCron: '0 2 * * *', enableSubCron: false } };
  const { sanitized, dropped } = sanitizeSettingsForRestore(
    { cron: { executeTime: '01:20', enableSubCron: 'yes', signCron: 123, aiChatCron: true } },
    current
  );
  assert.deepEqual([...dropped].sort(), ['cron.aiChatCron', 'cron.enableSubCron', 'cron.signCron'].sort());
  // 丢弃后深合并保留现值：signCron 与 enableSubCron 仍为现值，aiChatCron 现值本就缺失
  assert.equal(sanitized.cron.signCron, '0 2 * * *');
  assert.equal(sanitized.cron.enableSubCron, false);
  assert.equal(sanitized.cron.executeTime, '01:20');
  assert.equal('aiChatCron' in sanitized.cron, false);
});

test('还原：合法字符串分项表达式照常透传，空值删除后现值保留', () => {
  const current = { cron: { executeTime: '01:20', signCron: '0 2 * * *' } };
  const { sanitized, dropped } = sanitizeSettingsForRestore(
    { cron: { executeTime: '01:20', signCron: '', aiChatCron: '0 3,20 * * *' } },
    current
  );
  assert.deepEqual(dropped, []);
  assert.equal(sanitized.cron.signCron, '0 2 * * *', '空串删除后现值保留');
  assert.equal(sanitized.cron.aiChatCron, '0 3,20 * * *');
});

test('调度器：毒配置下 heartbeatTick / getSubCronMap / checkStartupCatchup 均不抛错', async () => {
  const poisoned = {
    cron: {
      executeTime: '01:20',
      enableSubCron: true,
      signCron: 123,
      aiChatCron: true,
      cloudHangCron: ['0 4,6 * * *'],
      browserHangCron: {},
      redeemCron: 7,
    },
  };
  const { s } = makeScheduler(poisoned);
  assert.equal(s.hasActiveSubCronRules(), false, '非字符串表达式按“未填写”处理');
  assert.deepEqual(s.getSubCronMap(), { sign: false, aiChat: false, cloudHang: false, browserHang: false, redeem: false });
  await s.heartbeatTick();
  await s.checkStartupCatchup();
});

test('调度器：混合配置（一个合法字符串 + 一个毒值）不抛错，合法项仍被识别', async () => {
  const mixed = {
    cron: { executeTime: '01:20', enableSubCron: true, signCron: '0 2 * * *', aiChatCron: 123 },
  };
  const { s } = makeScheduler(mixed);
  assert.equal(s.hasActiveSubCronRules(), true);
  assert.deepEqual(s.getSubCronMap(), { sign: true, aiChat: false, cloudHang: false, browserHang: false, redeem: false });
  await s.heartbeatTick();
});

test('调度器：毒配置下 scheduleNextRun 挂载不抛错（精确定时器仍能重挂）', () => {
  const poisoned = { cron: { executeTime: '01:20', enableSubCron: true, signCron: 123 } };
  const { s } = makeScheduler(poisoned);
  assert.doesNotThrow(() => s.scheduleNextRun());
  s.stop();
});
