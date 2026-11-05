/**
 * PUT /api/settings 保存入口前置校验（深查第 3 轮，2026-11-05）。
 *
 * 问题背景：
 * 保存入口此前只校验 webhook，数值/时间型设置原样落盘并即时热更新。
 * 其中 keepAliveSeconds 是真凭据的故障点：`|| 60` 兜底只救 falsy 值，
 * 非数值 truthy 值（如 "abc"）原样通过，随即在 server.js:6197 进入
 * resetCycleTimeout → `setTimeout(fn, "abc" * 1000)` 即 setTimeout(fn, NaN)，
 * Node 按约 1ms 触发 endSession('Timeout Reset')，正在运行的会话被立刻掐断；
 * 新会话同样遭殃（pulseConnectSec 由 "abc" 算出 NaN → connectSec NaN →
 * 约 1ms 即 endSession('Pulse Finished')）；cycleCountdown 被置为 "abc" 后
 * `"abc" > 0` 恒假，倒计时显示冻结。负数（-5）与超大值（1e9，32 位溢出钳制
 * 到 1ms）同理。本地探针 11/11 复现（见 VERIFICATION.md）。
 * cron.executeTime 的保存时校验是第 2 轮报告记下的后续加固项：调度器侧
 * （scheduler.js getTargetTimes）已有回退防御，但保存入口静默接受非法值
 * 并落盘，用户得不到任何反馈，只能在运行日志里看到回退告警。
 *
 * 校验口径：
 * - 只校验 body 里出现的字段（PUT 为部分更新，未出现的字段不干预）。
 * - 数值字段接受 JSON 数字或纯数字字符串（前端输入值常为字符串），
 *   校验通过后归一化为 Number 再落盘；null / undefined / '' 按“未提供”
 *   处理（与各消费点 `|| 默认值` 的容忍口径一致）。
 * - keepAliveSeconds：整数，15–3600 秒。下限 15 与 server.js 脉冲下限
 *   `Math.max(15, ...)` 一致，上限 3600 与挂机上限 `Math.min(3600, ...)` 一致。
 * - pulseIntervalSeconds：整数，10–3300 秒。与 server.js:3132 钳制
 *   `Math.min(3300, Math.max(10, ...))` 一致（其消费点另有 parseInt||兜底，
 *   此处只拦脏数据落盘）。
 * - cron.executeTime：字符串，须符合 scheduler.js isValidTargetTime 口径
 *   （H:MM / HH:MM，时 0–23、分 0–59，允许可选秒段；第 2 轮既定口径接受
 *   '1:5'，此处不收紧为 HH:MM）。本模块自含该判定以保持零依赖、可独立测试；
 *   口径若变，两处须同步改并各自有测试锁定。
 * 其余字段（notify、webhook、开关量等）本函数不碰，由既有 webhook 校验
 * 与各消费点负责。cron 为非对象时不校验 executeTime（运行侧 `|| {}` 容忍，
 * 残余见 VERIFICATION.md）。
 * 深查第 4 轮补记：上述两处残余已在本轮补上——cron 为非对象时直接拒绝
 * （否则字符串 cron 会整块覆盖掉原 cron 对象）；pulseIntervalMinutes
 * 旧字段纳入校验（整数 1–55 分钟，见常量注释）。另新增
 * sanitizeSettingsForRestore，供备份还原路径复用同一口径做“丢弃式”清洗。
 *
 * @param {object} body - PUT /api/settings 的 JSON 体
 * @returns {{ok:true, normalized:object}|{ok:false, error:string}}
 *   ok 时 normalized 为 body 的浅拷贝（仅数值字段被归一化为 Number，
 *   入参本身不被修改）；非法时 error 为可直接返回给前端的中文说明。
 */
'use strict';

const KEEP_ALIVE_MIN = 15;
const KEEP_ALIVE_MAX = 3600;
const PULSE_MIN = 10;
const PULSE_MAX = 3300;
// 深查第 4 轮：pulseIntervalMinutes 旧字段（仅 server.js:6605 还原日志行引用，
// 无任何消费点读它）。合法旧备份里的值是分钟数，45 分钟即默认显示值；
// 折算成秒须落在 pulseIntervalSeconds 的 10–3300 秒窗口内，故取 1–55 分钟。
const PULSE_MINUTES_MIN = 1;
const PULSE_MINUTES_MAX = 55;

/**
 * 与 app/tasks/scheduler.js isValidTargetTime 同口径（深查第 2 轮既定口径）：
 * H:MM / HH:MM，时 0–23、分 0–59；允许可选的秒段（01:20:30），秒 0–59。
 */
function isValidTargetTime(t) {
  if (typeof t !== 'string') return false;
  const parts = t.split(':');
  if (parts.length < 2 || parts.length > 3) return false;
  if (!/^\d+$/.test(parts[0]) || !/^\d+$/.test(parts[1])) return false;
  if (parts.length === 3 && !/^\d+$/.test(parts[2])) return false;
  const h = Number(parts[0]);
  const m = Number(parts[1]);
  if (h < 0 || h > 23 || m < 0 || m > 59) return false;
  if (parts.length === 3) {
    const s = Number(parts[2]);
    if (s < 0 || s > 59) return false;
  }
  return true;
}

/**
 * 数值字段归一化：数字或纯数字字符串 → 整数；其余一律非法。
 * null / undefined / '' 由调用方先行判为“未提供”，不到此处。
 */
function asIntegerInRange(value, min, max) {
  let num;
  if (typeof value === 'number') {
    num = value;
  } else if (typeof value === 'string') {
    const s = value.trim();
    if (!/^-?\d+$/.test(s)) return { ok: false };
    num = Number(s);
  } else {
    return { ok: false };
  }
  if (!Number.isInteger(num) || num < min || num > max) return { ok: false };
  return { ok: true, value: num };
}

function isAbsent(v) {
  return v === null || v === undefined || v === '';
}

function validateSettingsUpdate(body) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return { ok: false, error: '设置内容须为 JSON 对象' };
  }
  const normalized = { ...body };

  if (!isAbsent(body.keepAliveSeconds)) {
    const r = asIntegerInRange(body.keepAliveSeconds, KEEP_ALIVE_MIN, KEEP_ALIVE_MAX);
    if (!r.ok) {
      return { ok: false, error: `保活周期 keepAliveSeconds 须为 ${KEEP_ALIVE_MIN}–${KEEP_ALIVE_MAX} 的整数秒` };
    }
    normalized.keepAliveSeconds = r.value;
  }

  if (!isAbsent(body.pulseIntervalSeconds)) {
    const r = asIntegerInRange(body.pulseIntervalSeconds, PULSE_MIN, PULSE_MAX);
    if (!r.ok) {
      return { ok: false, error: `脉冲间隔 pulseIntervalSeconds 须为 ${PULSE_MIN}–${PULSE_MAX} 的整数秒` };
    }
    normalized.pulseIntervalSeconds = r.value;
  }

  if (!isAbsent(body.pulseIntervalMinutes)) {
    const r = asIntegerInRange(body.pulseIntervalMinutes, PULSE_MINUTES_MIN, PULSE_MINUTES_MAX);
    if (!r.ok) {
      return { ok: false, error: `脉冲间隔 pulseIntervalMinutes 须为 ${PULSE_MINUTES_MIN}–${PULSE_MINUTES_MAX} 的整数分钟（旧字段）` };
    }
    normalized.pulseIntervalMinutes = r.value;
  }

  // 深查第 4 轮：cron 本身为非对象时直接拒绝。此前只在 cron 为对象时校验
  // executeTime，字符串/数字 cron 会原样通过并整块覆盖掉原 cron 对象。
  if (!isAbsent(body.cron)) {
    if (!body.cron || typeof body.cron !== 'object' || Array.isArray(body.cron)) {
      return { ok: false, error: '定时配置 cron 须为对象' };
    }
    if (!isAbsent(body.cron.executeTime)) {
      if (!isValidTargetTime(body.cron.executeTime)) {
        return { ok: false, error: '每日任务触发时间 executeTime 须为 HH:MM（时 0–23、分 0–59）' };
      }
    }
  }

  return { ok: true, normalized };
}

/**
 * 备份还原路径专用清洗（深查第 4 轮，2026-11-06）。
 *
 * 问题背景：POST /api/config/import（server.js:6603）在第 3 轮只给 PUT
 * /api/settings 加了前置校验，还原路径仍原样合并 body.settings、不校验。
 * 含非法值的旧备份（如 keepAliveSeconds "abc"）还原后即落盘；重启后新会话
 * 的 pulseConnectSec 由 "abc" 算出 NaN，约 1ms 即 endSession('Pulse Finished')；
 * 即使不重启，之后任意一次无关 PUT 也会把脏值再喂给 resetCycleTimeout
 * （server.js:6209 只读现值、不重验），约 1ms 掐断全部正在运行的会话。
 * 另 cron.executeTime 非法值落盘后调度器侧虽有回退（第 2 轮），仍是脏数据。
 *
 * 还原语义与 PUT 不同：账号是还原主体，非法设置字段只丢弃、不整单拒绝
 * （否则一个脏设置会堵死整份账号还原，用户只能手工改备份文件）；
 * 合法字段归一化为 Number 后合并；其余未知字段原样透传（与旧合并一致）。
 * - 非法/空值的已知字段从合并结果中删掉，现有好值保留（不用 null/'' 覆盖）。
 * - cron 为非对象时整块丢弃；cron 为对象时只丢非法的 executeTime，其余
 *   子项（signCron 等）照常合并；cron 做深合并（现有 cron 子项保留），
 *   否则只删 executeTime 再浅合并会把现有的触发时间一并丢掉。
 * - 入参本身不被修改；current 仅用于 cron 深合并，不被修改。
 *
 * @param {object} imported - 备份文件里的 settings 对象
 * @param {object} [current] - 当前 appConfig.settings（用于 cron 深合并）
 * @returns {{sanitized: object, dropped: string[]}}
 *   sanitized 为可直接浅合并进 appConfig.settings 的对象；
 *   dropped 为被丢弃的字段名（如 'keepAliveSeconds'、'cron.executeTime'）。
 */
function sanitizeSettingsForRestore(imported, current) {
  const dropped = [];
  if (!imported || typeof imported !== 'object' || Array.isArray(imported)) {
    return { sanitized: {}, dropped: ['settings'] };
  }
  const sanitized = { ...imported };

  // 逐个校验数值字段：合法则归一化为 Number；非法或空值则删掉（保留现值）。
  const checkIntegerField = (key, min, max) => {
    if (!(key in sanitized)) return;
    const v = sanitized[key];
    if (isAbsent(v)) {
      delete sanitized[key];
      return;
    }
    const r = asIntegerInRange(v, min, max);
    if (r.ok) sanitized[key] = r.value;
    else {
      delete sanitized[key];
      dropped.push(key);
    }
  };
  checkIntegerField('keepAliveSeconds', KEEP_ALIVE_MIN, KEEP_ALIVE_MAX);
  checkIntegerField('pulseIntervalSeconds', PULSE_MIN, PULSE_MAX);
  checkIntegerField('pulseIntervalMinutes', PULSE_MINUTES_MIN, PULSE_MINUTES_MAX);

  if ('cron' in sanitized) {
    const c = sanitized.cron;
    if (isAbsent(c)) {
      delete sanitized.cron;
    } else if (!c || typeof c !== 'object' || Array.isArray(c)) {
      delete sanitized.cron;
      dropped.push('cron');
    } else {
      const cronCopy = { ...c };
      if ('executeTime' in cronCopy) {
        const et = cronCopy.executeTime;
        if (isAbsent(et)) delete cronCopy.executeTime;
        else if (!isValidTargetTime(et)) {
          delete cronCopy.executeTime;
          dropped.push('cron.executeTime');
        }
      }
      const curCron =
        current && typeof current === 'object' && current.cron &&
        typeof current.cron === 'object' && !Array.isArray(current.cron)
          ? current.cron
          : {};
      sanitized.cron = { ...curCron, ...cronCopy };
    }
  }

  return { sanitized, dropped };
}

module.exports = {
  validateSettingsUpdate,
  sanitizeSettingsForRestore,
  isValidTargetTime,
  KEEP_ALIVE_MIN,
  KEEP_ALIVE_MAX,
  PULSE_MIN,
  PULSE_MAX,
  PULSE_MINUTES_MIN,
  PULSE_MINUTES_MAX,
};
