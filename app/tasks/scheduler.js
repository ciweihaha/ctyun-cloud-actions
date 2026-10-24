const { executeNativeAiChat, executeNativeSign, executeNativeHang } = require('./native_tasks');
const browserHangModule = require('./browser_hang');
const { executeBrowserHang } = browserHangModule;
const { attemptRedeemOrder } = require('./redeem_order');

function getBeijingDate() {
  const d = new Date();
  return new Date(d.toLocaleString('en-US', { timeZone: 'Asia/Shanghai' }));
}

function getBeijingDateStr() {
  const d = new Date();
  return d.toLocaleDateString('sv-SE', { timeZone: 'Asia/Shanghai' });
}

function getBeijingTimeString() {
  const d = new Date();
  return d.toLocaleString('sv-SE', { timeZone: 'Asia/Shanghai' });
}

const CRON_FIELD_RANGES = [
  { name: '分钟', min: 0, max: 59 },
  { name: '小时', min: 0, max: 23 },
  { name: '日期', min: 1, max: 31 },
  { name: '月份', min: 1, max: 12 },
  { name: '星期', min: 0, max: 7 }, // 0 与 7 均为周日（标准 Cron）
];

/**
 * 校验单个 Cron 字段，返回错误字符串或 null。
 * 支持：*、数字、a-b、* /step、a-b/step、逗号列表（step 不可为 0，数值必须在字段范围内）。
 */
function validateCronField(field, range) {
  if (field === undefined || field === '') return `${range.name}字段不能为空`;
  for (const part of field.split(',')) {
    if (part === '') return `${range.name}字段存在空项`;
    let base = part;
    if (part.includes('/')) {
      const segs = part.split('/');
      if (segs.length !== 2) return `${range.name}字段 "${part}" 格式非法`;
      base = segs[0];
      if (!/^\d+$/.test(segs[1])) return `${range.name}字段 "${part}" 的步长不是合法数字`;
      const step = parseInt(segs[1], 10);
      if (step < 1) return `${range.name}字段 "${part}" 的步长必须 ≥ 1（零步长无意义）`;
      if (base !== '*' && !base.includes('-')) return `${range.name}字段 "${part}" 的步长只能用于 * 或范围`;
    }
    if (base === '*') continue;
    if (base.includes('-')) {
      const segs = base.split('-');
      if (segs.length !== 2 || !/^\d+$/.test(segs[0]) || !/^\d+$/.test(segs[1])) {
        return `${range.name}字段 "${part}" 的范围格式非法`;
      }
      const [a, b] = segs.map(Number);
      if (a > b) return `${range.name}字段 "${part}" 的范围起始大于结束`;
      if (a < range.min || b > range.max) return `${range.name}字段 "${part}" 越界（允许 ${range.min}-${range.max}）`;
    } else {
      if (!/^\d+$/.test(base)) return `${range.name}字段 "${part}" 不是合法数字`;
      const v = parseInt(base, 10);
      if (v < range.min || v > range.max) return `${range.name}字段 "${part}" 越界（允许 ${range.min}-${range.max}）`;
    }
  }
  return null;
}

/**
 * 校验五字段 Cron 表达式。非法时返回 { ok:false, error }，供配置保存与调度入口提前暴露错误，
 * 避免旧实现「非法字段静默永假、任务永远不触发且无任何提示」。
 */
function validateCronExpression(expr) {
  if (!expr || typeof expr !== 'string' || !expr.trim()) return { ok: false, error: 'Cron 表达式不能为空' };
  const parts = expr.trim().split(/\s+/);
  if (parts.length !== 5) return { ok: false, error: `Cron 表达式必须为 5 个字段（分 时 日 月 周），当前 ${parts.length} 个` };
  for (let i = 0; i < 5; i++) {
    const err = validateCronField(parts[i], CRON_FIELD_RANGES[i]);
    if (err) return { ok: false, error: err };
  }
  return { ok: true };
}

function matchCronField(field, val) {
  if (field === '*') return true;
  const parts = field.split(',');
  for (const part of parts) {
    if (part.includes('/')) {
      const [range, step] = part.split('/');
      const stepNum = parseInt(step, 10);
      if (!Number.isFinite(stepNum) || stepNum < 1) continue; // 零步长/非法步长不匹配（校验层会另行报错）
      if (range === '*') {
        if (val % stepNum === 0) return true;
      } else {
        const [start, end] = range.split('-').map(Number);
        if (val >= start && val <= end && (val - start) % stepNum === 0) return true;
      }
    } else if (part.includes('-')) {
      const [start, end] = part.split('-').map(Number);
      if (val >= start && val <= end) return true;
    } else {
      if (parseInt(part, 10) === val) return true;
    }
  }
  return false;
}

/**
 * Cron 匹配（标准语义）：分/时/月恒为 AND；日期(dom) 与星期(dow) **都**被限定时按标准 Cron 的 OR 语义
 * （例如 `0 9 1 * 1` = 每月 1 号或每周一 09:00），仅限定其一时按该项匹配。
 * 仓库文档/UI 未声明自定义语义，故从旧「全 AND」修正为标准语义，并以 test/cron.test.js 固定。
 * 星期字段 7 与 0 同为周日。
 */
function shouldRunCron(cronExpr, date = new Date()) {
  if (!cronExpr) return false;
  if (!validateCronExpression(cronExpr).ok) return false;
  const parts = cronExpr.trim().split(/\s+/);
  const [minStr, hourStr, domStr, monthStr, dowStr] = parts;
  const min = date.getMinutes();
  const hour = date.getHours();
  const dom = date.getDate();
  const month = date.getMonth() + 1;
  const dow = date.getDay();

  if (!matchCronField(minStr, min)) return false;
  if (!matchCronField(hourStr, hour)) return false;
  if (!matchCronField(monthStr, month)) return false;
  const domOk = matchCronField(domStr, dom);
  const dowOk = matchCronField(dowStr, dow) || (dow === 0 && matchCronField(dowStr, 7));
  const domRestricted = domStr !== '*';
  const dowRestricted = dowStr !== '*';
  if (domRestricted && dowRestricted) return domOk || dowOk;
  return domOk && dowOk;
}

/**
 * 统一任务状态枚举（任务书要求）：所有完成判定（开机补跑 / 主流程最终判定 / 通知口径）
 * 只允许使用这组状态，禁止再各处用布尔值拼凑「完成」。
 */
const TASK_STATUS = Object.freeze({
  PENDING: 'pending',     // 已开启、未达成
  RUNNING: 'running',     // 执行中
  COMPLETED: 'completed', // 有权威证据确认达成（官方任务状态 / 兑换日期标记）
  SKIPPED: 'skipped',     // 未开启 / 被分项 Cron 管辖 / 今日策略未命中 / 平台不适用
  FAILED: 'failed',       // 本轮执行明确失败
  UNKNOWN: 'unknown',     // 状态证据不可得（如官方任务刷新失败）——绝不得按完成处理
});

/**
 * 自动兑换今日是否命中策略（从 runAllAccounts 的内联策略判定抽出，供完成判定复用同一口径）。
 * lastRedeemDate === todayStr 时视为今日已执行（返回 false，不再需要执行）。
 */
function isRedeemDueToday(rConf, todayStr) {
  if (!rConf || !rConf.prodId) return false;
  if (rConf.lastRedeemDate === todayStr) return false;
  const cstDay = parseInt(todayStr.split('-')[2], 10);
  const ym = todayStr.split('-');
  const lastDayOfMonth = new Date(Number(ym[0]), Number(ym[1]), 0).getDate();
  if (rConf.scheduleType === 'daily') return true;
  if (rConf.scheduleType === 'interval_days') {
    if (!rConf.lastRedeemDate) return true;
    const diffDays = Math.floor((new Date(todayStr).getTime() - new Date(rConf.lastRedeemDate).getTime()) / (1000 * 3600 * 24));
    return diffDays >= (parseInt(rConf.intervalDays) || 30);
  }
  const days = Array.isArray(rConf.monthlyDays) ? rConf.monthlyDays : [-1];
  return days.includes(cstDay) || (days.includes(-1) && cstDay === lastDayOfMonth);
}

class TaskScheduler {

  constructor({ getAccounts, getSettings, getClient, appendLog, sendNotification, saveConfig }) {
    this.getAccounts = getAccounts;
    this.getSettings = getSettings;
    this.getClient = getClient;
    this.appendLog = appendLog;
    this.sendNotification = sendNotification;
    this.saveConfig = saveConfig;
    this.timer = null;
    this.lastTriggerMinute = '';
    this.lastCompletedDate = '';
    this.isRunning = false;
  }

  /**
   * 开关语义统一入口 (暗线 A 的结构性修复 · 与 server.js resolveTaskEnabled 同源)
   * ----------------------------------------------------------
   * 历史缺陷：调度器各处就地读取 acc.features.autoSign / aiChat / cloudHang / keepAlive，
   * 与"任务类型常量 sign"之间存在名称漂移风险（打卡的账号级字段叫 autoSign，任务类型叫 sign），
   * 一旦某处写错字段名，开关就会静默失效 —— 这正是"关掉打卡但任务照跑"类投诉的根源。
   * 现在统一走 client.resolveTask()；client 不支持时按同一套映射就地兜底。
   */
  taskGate(acc, taskType, client) {
    const c = client || this.getClient(acc);
    if (c && typeof c.resolveTask === 'function') {
      return c.resolveTask(taskType).enabled;
    }
    // 兜底：与 server.js 的 TASK_FEATURE_KEY 保持一致（sign -> autoSign）
    const key = taskType === 'sign' ? 'autoSign' : taskType;
    if (acc.enabled === false) return false;
    return (acc.features || {})[key] !== false;
  }

  start() {
    this.appendLog('Scheduler', '⏰ 自动化调度引擎已启动 (准时时间点主导 + 30秒无缝巡检)...', 'success');
    // 立即计算并挂载下一次精准时间点延时器
    this.scheduleNextRun();
    // 同时启动轻量级 30 秒轮询看门狗：防止设置热更新失效、跨日兜底，并支持高级分项Cron自定义触发
    if (this.timer) clearInterval(this.timer);
    this.timer = setInterval(() => this.heartbeatTick(), 30000);
    // 立即执行一次开机/重启检测（句柄必须保存：旧实现无句柄，stop() 清不掉它，
    // 服务停止后 2 秒仍可能触发补跑 —— 新发现 S8）
    if (this.startupTimer) clearTimeout(this.startupTimer);
    this.startupTimer = setTimeout(() => { this.startupTimer = null; this.checkStartupCatchup(); }, 2000);
  }

  stop() {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
    if (this.nextRunTimer) {
      clearTimeout(this.nextRunTimer);
      this.nextRunTimer = null;
    }
    if (this.startupTimer) {
      clearTimeout(this.startupTimer);
      this.startupTimer = null;
    }
    // 停止时取消在跑的浏览器真挂机（只终止其自有子进程），避免孤儿浏览器残留
    try { browserHangModule.cancelAllBrowserHangs?.(); } catch (e) {}
  }

  /** 分项任务失败的统一脱敏日志（旧实现多处 .catch(()=>{}) 静默吞错，排障无据）。只记错误 message，不记任何凭据/报文。 */
  logTaskError(taskLabel, accName, err) {
    const msg = (err && err.message) ? err.message : String(err || '未知错误');
    this.appendLog('Scheduler', `[${accName}] 分项任务 [${taskLabel}] 执行失败: ${msg}`, 'error');
  }

  /**
   * 统一完成判定（单一事实来源）：返回该账号五类任务的 TASK_STATUS。
   * - 官方任务类（sign/aiChat/cloudHang/browserHang）以官方任务中心为唯一证据；
   *   browserHang 的目标与 cloudHang 同为官方「使用1小时」任务，以同一证据判定，但独立计列，
   *   堵住旧实现「补跑/最终判定/通知三处清单不一致、browserHang 与 autoRedeem 被系统性遗漏」。
   * - refreshFailed=true（官方任务刷新失败）时官方类一律 UNKNOWN —— 绝不用旧缓存判完成（新发现 S7）。
   * - redeem 以 redeemConfig 的日期与今日策略判定（仓内无订单状态查询接口）。
   * opts.exclude 为分项管辖表：被管辖的分项记 SKIPPED（由其 Cron 负责，不纳入本次判定）。
   */
  evaluateAccountCompletion(acc, client, opts = {}) {
    const S = TASK_STATUS;
    const exclude = opts.exclude || {};
    const todayStr = opts.todayStr || getBeijingDateStr();
    const states = {};
    const official = (taskKey, taskName) => {
      if (!this.taskGate(acc, taskKey, client)) return { status: S.SKIPPED };
      if (exclude[taskKey]) return { status: S.SKIPPED };
      if (opts.refreshFailed) return { status: S.UNKNOWN };
      const tasks = client?.metrics?.officialTasks;
      if (!Array.isArray(tasks)) return { status: S.UNKNOWN };
      const t = tasks.find(x => x.name && x.name.includes(taskName));
      if (!t) return { status: S.UNKNOWN };
      return { status: (t.status === 2 || (t.total > 0 && t.current >= t.total)) ? S.COMPLETED : S.PENDING };
    };
    if (acc.platform === 'ydpc' || acc.platform === 'ecloud') {
      for (const k of ['sign', 'aiChat', 'cloudHang', 'browserHang', 'redeem']) states[k] = { status: S.SKIPPED };
      return states;
    }
    states.sign = official('sign', '登录AI云电脑');
    states.aiChat = official('aiChat', 'AI对话');
    states.cloudHang = official('cloudHang', '使用1小时');
    states.browserHang = official('browserHang', '使用1小时');
    // 自动兑换
    if (!acc.features?.autoRedeem) states.redeem = { status: S.SKIPPED };
    else if (exclude.redeem) states.redeem = { status: S.SKIPPED };
    else {
      const rConf = acc.redeemConfig || {};
      if (!rConf.prodId) states.redeem = { status: S.SKIPPED };
      else if (rConf.lastRedeemDate === todayStr) states.redeem = { status: S.COMPLETED };
      else if (isRedeemDueToday(rConf, todayStr)) states.redeem = { status: S.PENDING };
      else states.redeem = { status: S.SKIPPED };
    }
    return states;
  }

  /** 全部任务是否真正完成：每项必须为 COMPLETED 或 SKIPPED，出现 PENDING/UNKNOWN/FAILED 即未完成。 */
  static allStatesCompleted(states) {
    return Object.values(states).every(s => s.status === TASK_STATUS.COMPLETED || s.status === TASK_STATUS.SKIPPED);
  }

  getTargetTimes() {
    const settings = this.getSettings() || {};
    const cron = settings.cron || {};
    const rawTimes = cron.executeTime || cron.taskTime || '01:20';
    const list = rawTimes.split(/[,，\s]+/).map(t => t.trim()).filter(Boolean);
    return list.length > 0 ? list : ['01:20'];
  }

  /**
   * 开机或配置热更新时自检：分项级补跑兜底。
   * - 已被分项 Cron 管辖的任务类型：绝不开机抢跑，等待其 Cron 下一个匹配分钟自然触发；
   * - 未被分项管辖的任务类型：若今日未达成且已过主时间点，则仅补跑该分项。
   */
  async checkStartupCatchup() {
    const todayStr = getBeijingDateStr();
    const accounts = this.getAccounts() || [];
    const subCronMap = this.getSubCronMap();

    // 判断是否存在"未被分项 Cron 管辖"的待补跑任务 (全部被管辖时补跑引擎直接休眠)
    let anyUngovernedTask = false;
    for (const acc of accounts) {
      if (!acc.enabled || acc.platform === 'ydpc' || acc.platform === 'ecloud') continue;
      const f = acc.features || {};
      if ((this.taskGate(acc, 'sign') && !subCronMap.sign) ||
          (this.taskGate(acc, 'aiChat') && !subCronMap.aiChat) ||
          (this.taskGate(acc, 'cloudHang') && !subCronMap.cloudHang) ||
          (this.taskGate(acc, 'browserHang') && !subCronMap.browserHang) ||
          (f.autoRedeem && !subCronMap.redeem)) {
        anyUngovernedTask = true;
        break;
      }
    }

    if (!anyUngovernedTask) {
      this.appendLog('Scheduler', `🛰️ 所有任务分项均由独立 Cron 精准管辖，开机补跑引擎转入休眠，各分项将由其 Cron 在匹配时间点独立触发。`, 'info');
      return;
    }

    let allDone = accounts.length > 0;
    for (const acc of accounts) {
      if (!acc.enabled) continue;
      if (acc.platform === 'ydpc') continue; // 移动云保活为常态巡检，无需达成度判定
      if (acc.platform === 'ecloud') continue; // 移动公众保活为常态巡检，无官方任务达成度可言
      const client = this.getClient(acc);
      // 官方任务状态刷新失败 ⇒ 该账号状态未知（UNKNOWN），绝不沿用旧缓存判完成（新发现 S7）；
      // 旧实现 catch 后直接读旧 officialTasks，缓存里的昨日「已完成」会让补跑误判全达成而漏跑。
      let refreshFailed = false;
      try {
        await client.refreshOfficialTasks();
      } catch (e) {
        refreshFailed = true;
        this.appendLog('Scheduler', `[${acc.name}] 官方任务状态刷新失败，本轮按状态未知处理（不判定完成）: ${(e && e.message) || e}`, 'warning');
      }
      // 统一完成判定（含 browserHang 与 autoRedeem —— 旧实现只查 sign/aiChat/cloudHang，
      // 与 anyUngovernedTask 的任务清单不一致，导致这两类未完成时仍被判全部完成，新发现 S6）
      const states = this.evaluateAccountCompletion(acc, client, { exclude: subCronMap, refreshFailed, todayStr });
      if (!TaskScheduler.allStatesCompleted(states)) {
        allDone = false;
        break;
      }
    }

    if (allDone) {
      this.lastCompletedDate = todayStr;
      this.appendLog('Scheduler', `✅ 检测确认：所有账号已开启的自动化任务均已圆满达成，系统转入低功耗休眠，等待设定时间准时触发。`, 'success');
      return;
    }

    // 检查当前北京时间是否已达到或超过预设的目标时间
    const targetTimes = this.getTargetTimes();
    const bj = getBeijingDate();
    const currentVal = bj.getHours() * 60 + bj.getMinutes();

    let shouldCatchup = false;
    for (const t of targetTimes) {
      const parts = t.split(':').map(Number);
      const tVal = parts[0] * 60 + (parts[1] || 0);
      if (currentVal >= tVal) {
        shouldCatchup = true;
        break;
      }
    }

    if (shouldCatchup && this.lastCompletedDate !== todayStr) {
      const excludedTasks = this.getExcludedTasksInfo(subCronMap);
      this.appendLog('Scheduler', `🚀 准时补跑机制触发：当前时间 (${String(bj.getHours()).padStart(2, '0')}:${String(bj.getMinutes()).padStart(2, '0')}) 已达或超过预设时间点 (${targetTimes.join(', ')})，执行分项级自动补跑...`, 'info');
      if (excludedTasks.list.length > 0) {
        this.appendLog('Scheduler', `🛰️ 以下分项由独立 Cron 管辖，本次补跑跳过: ${excludedTasks.text} (将由其 Cron 在下一个匹配时间点触发)`, 'info');
      }
      await this.runAllAccounts('catchup_or_scheduled', subCronMap);
    }
  }

  /**
   * 计算下次触发时间并挂载精确的延时器
   * 到点后按分项管辖表执行：被分项 Cron 管辖的任务类型跳过，仅兜底执行未管辖分项
   */
  scheduleNextRun() {
    if (this.nextRunTimer) {
      clearTimeout(this.nextRunTimer);
      this.nextRunTimer = null;
    }

    const targetTimes = this.getTargetTimes();
    const bj = getBeijingDate();
    const currentMs = bj.getTime();

    let nextTargetDate = null;
    for (const timeStr of targetTimes) {
      const [h, m] = timeStr.split(':').map(Number);
      const candidate = new Date(bj.getTime());
      candidate.setHours(h, m, 0, 0);
      if (candidate.getTime() > currentMs) {
        if (!nextTargetDate || candidate.getTime() < nextTargetDate.getTime()) {
          nextTargetDate = candidate;
        }
      }
    }

    if (!nextTargetDate) {
      const [h, m] = targetTimes[0].split(':').map(Number);
      const tomorrow = new Date(bj.getTime() + 24 * 3600 * 1000);
      tomorrow.setHours(h, m, 0, 0);
      nextTargetDate = tomorrow;
    }

    const delayMs = Math.max(1000, nextTargetDate.getTime() - currentMs);
    const targetH = String(nextTargetDate.getHours()).padStart(2, '0');
    const targetM = String(nextTargetDate.getMinutes()).padStart(2, '0');
    const hoursAway = (delayMs / 3600000).toFixed(1);

    this.appendLog('Scheduler', `⏰ 下一次自动化任务将在北京时间 ${targetH}:${targetM} 准时执行 (约 ${hoursAway} 小时后)。`, 'info');

    this.nextRunTimer = setTimeout(async () => {
      // 快照此刻的分项管辖表：分项 Cron 配置的任务类型由其自身 Cron 触发，主时间点只兜底未管辖分项
      const subCronMap = this.getSubCronMap();
      const excludedTasks = this.getExcludedTasksInfo(subCronMap);
      if (excludedTasks.list.length > 0) {
        this.appendLog('Scheduler', `⏰ 到达主调度时间点，以下分项由独立 Cron 精准管辖，本次主调度跳过: ${excludedTasks.text}`, 'info');
      }
      await this.runAllAccounts('point_in_time', subCronMap);
      this.scheduleNextRun();
    }, delayMs);
  }

  /**
   * 判断辅助规则是否启用且包含有效规则
   */
  hasActiveSubCronRules() {
    const settings = this.getSettings() || {};
    const cron = settings.cron || {};
    if (!cron.enableSubCron) return false;
    return !!(cron.signCron?.trim() || cron.aiChatCron?.trim() || cron.cloudHangCron?.trim() || cron.browserHangCron?.trim() || cron.redeemCron?.trim());
  }

  /**
   * 分项管辖表：分项 Cron 一旦填写，该分项完全由自己的 Cron 精准管辖，
   * 主时间点与开机补跑一律跳过，绝不重复执行。
   * @returns {{sign: boolean, aiChat: boolean, cloudHang: boolean, browserHang: boolean, redeem: boolean}}
   */
  getSubCronMap() {
    const settings = this.getSettings() || {};
    const cron = settings.cron || {};
    if (!cron.enableSubCron) {
      return { sign: false, aiChat: false, cloudHang: false, browserHang: false, redeem: false };
    }
    return {
      sign: !!cron.signCron?.trim(),
      aiChat: !!cron.aiChatCron?.trim(),
      cloudHang: !!cron.cloudHangCron?.trim(),
      browserHang: !!cron.browserHangCron?.trim(),
      redeem: !!cron.redeemCron?.trim()
    };
  }

  /**
   * 根据分项管辖表生成主调度需排除的任务类型列表与中文描述
   */
  getExcludedTasksInfo(excludeSet) {
    const names = { sign: '每日签到', aiChat: 'AI 对话', cloudHang: '云电脑挂机', browserHang: '浏览器真挂机', redeem: '自动兑换' };
    const excluded = Object.keys(names).filter(k => excludeSet[k]);
    return { list: excluded, text: excluded.map(k => names[k]).join('、') || '无' };
  }

  /**
   * 30 秒巡检看门狗：负责准点分钟匹配、高级 Cron 触发以及热更新重调度
   */
  async heartbeatTick() {
    const bj = getBeijingDate();
    const currentMinKey = bj.toISOString().substring(0, 16); // YYYY-MM-DDTHH:mm
    if (this.lastTriggerMinute === currentMinKey) return;

    const currentHm = `${String(bj.getHours()).padStart(2, '0')}:${String(bj.getMinutes()).padStart(2, '0')}`;
    const targetTimes = this.getTargetTimes();
    const todayStr = getBeijingDateStr();

    const settings = this.getSettings() || {};
    const cron = settings.cron || {};
    const subCronActive = this.hasActiveSubCronRules();

    // 分项 Cron 表达式合法性巡检：非法表达式只告警一次（shouldRunCron 对非法值恒假，
    // 旧实现静默永不触发、无任何提示 —— 任务书要求非法字段显式报错）
    if (cron.enableSubCron) {
      if (!this._cronWarned) this._cronWarned = new Set();
      for (const [label, expr] of [['签到打卡', cron.signCron], ['AI 对话', cron.aiChatCron], ['云电脑挂机', cron.cloudHangCron], ['浏览器真挂机', cron.browserHangCron], ['自动兑换', cron.redeemCron]]) {
        if (expr && expr.trim()) {
          const v = validateCronExpression(expr.trim());
          if (!v.ok && !this._cronWarned.has(expr)) {
            this._cronWarned.add(expr);
            this.appendLog('Scheduler', `⚠️ 分项 Cron [${label}] 表达式非法，已忽略该分项: ${v.error}（表达式: ${expr}）`, 'error');
          }
        }
      }
    }

    // 1. 如果未启用辅助规则，或者虽然启用了辅助规则但没有填写任何具体规则：
    // 则以【每日任务准时触发时间点 (主调度中心)】为主触发机制
    if (!subCronActive) {
      if (targetTimes.includes(currentHm)) {
        this.lastTriggerMinute = currentMinKey;
        if (this.lastCompletedDate !== todayStr) {
          this.appendLog('Scheduler', `⏰ 到达主调度中心每日任务准时触发时间点 [${currentHm}]，正在启动全自动流程...`, 'info');
          await this.runAllAccounts('scheduled_point');
          this.scheduleNextRun();
          return;
        }
      }
      return;
    }

    // 2. 如果启用了辅助规则且填写了具体 Cron 表达式：
    // 则严格以用户填写的各项辅助规则为准独立执行，未填写的分项则兜底遵循主调度中心时间
    const accounts = (this.getAccounts() || []).filter(a => a.enabled);

    // 2.1 每日签到打卡分项规则
    if (cron.signCron?.trim()) {
      if (shouldRunCron(cron.signCron.trim(), bj)) {
        this.lastTriggerMinute = currentMinKey;
        this.appendLog('Scheduler', `⏰ 触发分项辅助规则 [签到打卡] (Cron: ${cron.signCron})...`, 'info');
        for (const acc of accounts) {
          if (this.taskGate(acc, 'sign')) {
            const client = this.getClient(acc);
            executeNativeSign(client, acc, (src, msg, lvl) => this.appendLog(src, `[${acc.name}] ${msg}`, lvl))
              .then(signRes => {
                if (signRes && signRes.isCompleted) {
                  acc.stats.lastSignTime = getBeijingTimeString();
                  this.saveConfig();
                }
              })
              .catch(err => this.logTaskError('签到打卡', acc.name, err));
          }
        }
      }
    } else if (targetTimes.includes(currentHm) && this.lastCompletedDate !== todayStr) {
      // 辅助规则未配置该项，按主时间点兜底（兜底分支同样必须登记分钟标记，
      // 否则同分钟下一次 30 秒巡检会重复启动 —— 新发现 S3）
      this.lastTriggerMinute = currentMinKey;
      for (const acc of accounts) {
        if (this.taskGate(acc, 'sign')) {
          const client = this.getClient(acc);
          executeNativeSign(client, acc, (src, msg, lvl) => this.appendLog(src, `[${acc.name}] ${msg}`, lvl))
            .then(signRes => {
              if (signRes && signRes.isCompleted) {
                acc.stats.lastSignTime = getBeijingTimeString();
                this.saveConfig();
              }
            })
            .catch(err => this.logTaskError('签到打卡', acc.name, err));
        }
      }
    }

    // 2.2 AI 智能对话分项规则
    if (cron.aiChatCron?.trim()) {
      if (shouldRunCron(cron.aiChatCron.trim(), bj)) {
        this.lastTriggerMinute = currentMinKey;
        this.appendLog('Scheduler', `⏰ 触发分项辅助规则 [AI 对话] (Cron: ${cron.aiChatCron})...`, 'info');
        for (const acc of accounts) {
          if (this.taskGate(acc, 'aiChat')) {
            const client = this.getClient(acc);
            executeNativeAiChat(client, acc, (src, msg, lvl) => this.appendLog(src, `[${acc.name}] ${msg}`, lvl)).catch(err => this.logTaskError('AI 对话', acc.name, err));
          }
        }
      }
    } else if (targetTimes.includes(currentHm) && this.lastCompletedDate !== todayStr) {
      // 辅助规则未配置该项，按主时间点兜底（登记分钟标记防同分钟重复触发 —— 新发现 S3）
      this.lastTriggerMinute = currentMinKey;
      for (const acc of accounts) {
        if (this.taskGate(acc, 'aiChat')) {
          const client = this.getClient(acc);
          executeNativeAiChat(client, acc, (src, msg, lvl) => this.appendLog(src, `[${acc.name}] ${msg}`, lvl)).catch(err => this.logTaskError('AI 对话', acc.name, err));
        }
      }
    }

    // 2.3 云电脑挂机守护分项规则
    if (cron.cloudHangCron?.trim()) {
      if (shouldRunCron(cron.cloudHangCron.trim(), bj)) {
        this.lastTriggerMinute = currentMinKey;
        this.appendLog('Scheduler', `⏰ 触发分项辅助规则 [云电脑挂机] (Cron: ${cron.cloudHangCron})...`, 'info');
        for (const acc of accounts) {
          if (this.taskGate(acc, 'cloudHang')) {
            const client = this.getClient(acc);
            executeNativeHang(client, acc, (src, msg, lvl) => this.appendLog(src, `[${acc.name}] ${msg}`, lvl)).catch(err => this.logTaskError('云电脑挂机', acc.name, err));
          }
        }
      }
    }

    // 2.3b 浏览器真挂机分项规则（每天 3:00，挂 61 分钟）
    if (cron.browserHangCron?.trim()) {
      if (shouldRunCron(cron.browserHangCron.trim(), bj)) {
        // 命中分支必须登记分钟标记（旧实现唯独此分支漏记，同一分钟内 30 秒巡检
        // 会二次启动 61 分钟浏览器挂机，与其他账号共享 profile 时还会互踩 —— 新发现 S4）
        this.lastTriggerMinute = currentMinKey;
        this.appendLog('Scheduler', `⏰ 触发分项辅助规则 [浏览器真挂机] (Cron: ${cron.browserHangCron})...`, 'info');
        for (const acc of accounts) {
          if (this.taskGate(acc, 'browserHang') && acc.platform !== 'ydpc' && acc.platform !== 'ecloud') {
            const client = this.getClient(acc);
            executeBrowserHang(client, acc, (src, msg, lvl) => this.appendLog(src, `[${acc.name}] ${msg}`, lvl)).catch(err => this.logTaskError('浏览器真挂机', acc.name, err));
          }
        }
      }
    } else if (targetTimes.includes(currentHm) && this.lastCompletedDate !== todayStr) {
      // 辅助规则未配置该项，按主时间点兜底。
      // 【缺陷修复 S5】旧实现此分支门控用 cloudHang 且调用 executeNativeHang（原生挂机），
      // 与本节标题/注释声明的「浏览器真挂机兜底」不一致：只开启 browserHang 的账号在主时间点
      // 永远等不到浏览器挂机。现按注释意图修正为 browserHang 门控 + executeBrowserHang；
      // 原生挂机的主时间点兜底由 scheduleNextRun → runAllAccounts('point_in_time') 承担，不在此处。
      this.lastTriggerMinute = currentMinKey;
      for (const acc of accounts) {
        if (this.taskGate(acc, 'browserHang') && acc.platform !== 'ydpc' && acc.platform !== 'ecloud') {
          const client = this.getClient(acc);
          executeBrowserHang(client, acc, (src, msg, lvl) => this.appendLog(src, `[${acc.name}] ${msg}`, lvl)).catch(err => this.logTaskError('浏览器真挂机', acc.name, err));
        }
      }
    }

    // 2.4 自动兑换与抽奖分项规则
    if (cron.redeemCron?.trim()) {
      if (shouldRunCron(cron.redeemCron.trim(), bj)) {
        this.lastTriggerMinute = currentMinKey;
        this.appendLog('Scheduler', `⏰ 触发分项辅助规则 [自动兑换/抽奖] (Cron: ${cron.redeemCron})...`, 'info');
        for (const acc of accounts) {
          if (acc.features?.autoRedeem) {
            const client = this.getClient(acc);
            client.getRewards().catch(err => this.logTaskError('自动兑换商品刷新', acc.name, err));
          }
        }
      }
    } else if (targetTimes.includes(currentHm) && this.lastCompletedDate !== todayStr) {
      // 辅助规则未配置该项，按主时间点兜底 (兑换仍受自身策略日限制约，由完整流程内判定)
      this.lastTriggerMinute = currentMinKey;
      for (const acc of accounts) {
        if (acc.features?.autoRedeem && acc.platform !== 'ydpc' && acc.platform !== 'ecloud') {
          const client = this.getClient(acc);
          client.getRewards().catch(err => this.logTaskError('自动兑换商品刷新', acc.name, err));
        }
      }
    }
  }

  /**
   * 执行所有账号的自动化任务流
   * @param {string} reason 触发来源标识 (point_in_time / catchup_or_scheduled / manual)
   * @param {object|null} excludeSet 分项管辖排除表 {sign, aiChat, cloudHang, redeem}，为 true 的分项本次跳过
   *                                 (手动触发时传 null，强制全量执行)
   */
  async runAllAccounts(reason = 'scheduled', excludeSet = null) {
    if (this.isRunning) return;
    this.isRunning = true;

    // isRunning 必须用 try/finally 复位 (新发现 #32)：
    // 原实现把 this.isRunning = false 放在函数末尾，若末尾的通知/日志/落盘任一处抛错，
    // isRunning 会永久停留在 true —— 调度器从此静默死锁，此后所有账号的所有任务都不再执行，
    // 而日志里没有任何异常提示。用户只能看到"任务没跑"。
    // 以下 try 块内的缩进保持原样，以便审阅时 diff 最小化。
    try {

    const todayStr = getBeijingDateStr();
    const accounts = (this.getAccounts() || []).filter(a => a.enabled);

    this.appendLog('Scheduler', `🔔 开始按序执行 ${accounts.length} 个云电脑的原生任务流程 (触发来源: ${reason})...`, 'info');

    const summaryResults = [];
    const processedAccounts = [];

    // 辅助防风控随机延时：步骤间 2~5 秒离散等待
    const sleepStepJitter = async (accName, stepName) => {
      const ms = Math.floor(Math.random() * 3000) + 2000; // 2000ms ~ 5000ms
      this.appendLog('Scheduler', `[${accName}] 🛡️ [防风控] 任务步骤 (${stepName}) 间随机防抖，等待 ${(ms / 1000).toFixed(1)} 秒...`, 'info');
      await new Promise(r => setTimeout(r, ms));
    };

    for (let i = 0; i < accounts.length; i++) {
      const acc = accounts[i];
      const client = this.getClient(acc);
      const accSummary = { name: acc.name, sign: false, aiChat: false, hang: false };

      // 移动云电脑 (YDPc) 独立调度分支：仅执行 SOHO 心跳与 CAG TCP 握手保活
      // 【2026-09-22 用户要求】原"关机自动拉起"已移除（自动开机守护改由客户端侧按双开关独立判定），
      // 本分支不再下发任何电源指令。
      if (acc.platform === 'ydpc') {
        try {
          this.appendLog('Scheduler', `[${acc.name}] 正在执行移动爱家例行保活巡检...`, 'info', acc.name, 'ydpc');
          if (client.refreshVms) await client.refreshVms();
          const vms = acc.vms || client.metrics?.vms || [];
          for (const vm of vms) {
            if (vm.keepaliveEnabled !== false) {
              // 【2026-09-23 合并】SOHO 心跳与 CAG 握手共用一个"控制面保活"开关
              if (acc.features?.controlPlaneKeepalive !== false && client.sendHeartbeat) {
                await client.sendHeartbeat(vm.userServiceId).catch(() => {});
              }
              if (acc.features?.controlPlaneKeepalive !== false && client.pingCag) {
                await client.pingCag(vm.userServiceId, 3).catch(() => {});
              }
            }
          }
        } catch (err) {
          this.appendLog('Scheduler', `[${acc.name}] 移动爱家保活巡检异常: ${err.message}`, 'error', acc.name, 'ydpc');
        }

        // 账号间防风控随机退避
        if (i < accounts.length - 1) {
          const accountJitterMs = Math.floor(Math.random() * 8000) + 3000;
          await new Promise(r => setTimeout(r, accountJitterMs));
        }
        continue;
      }

      // 移动公众（ecloud）独立调度分支
      // ----------------------------------------------------------
      // 保活由 EcloudClient 自己的看护循环按「账号级开关 + 单机独立周期」执行，
      // 这里**只做幂等收敛**（确保看护在跑 / 关了要停），绝不重复下发一次保活 ——
      // 否则就会与看护循环形成第二套下发真相（这正是历史缺陷的形态）。
      if (acc.platform === 'ecloud') {
        try {
          // 开关判定一律走 taskGate（统一入口）—— 绝不就地读 acc.features.keepAlive
          const on = this.taskGate(acc, 'keepAlive', client);
          if (on && !client.workerRunning) {
            this.appendLog('Scheduler', `[${acc.name}] 移动公众保活看护未在运行，正在拉起...`, 'info', acc.name, 'ecloud');
            client.startKeepAliveWorker();
          } else if (!on && client.workerRunning) {
            this.appendLog('Scheduler', `[${acc.name}] 移动公众账号级保活已关闭，停止看护循环`, 'info', acc.name, 'ecloud');
            client.stopKeepAliveWorker();
          }
        } catch (err) {
          this.appendLog('Scheduler', `[${acc.name}] 移动公众保活看护检查异常: ${err.message}`, 'error', acc.name, 'ecloud');
        }

        // 账号间防风控随机退避
        if (i < accounts.length - 1) {
          const jitterMs = Math.floor(Math.random() * 8000) + 3000;
          await new Promise(r => setTimeout(r, jitterMs));
        }
        continue;
      }

      // 天翼云电脑 (CTYun) 原生调度分支
      // 若用户当前正在通过网页浏览器操控该云电脑，为避免互踢，自动跳过该账号的本次自动化，保持避让！
      if (client?.isWebUserActive) {
        this.appendLog('Scheduler', `[${acc.name}] 用户当前正在浏览器中远程操控云电脑，为避免会话冲突，本次自动化调度主动避让跳过，等用户关闭页面后再继续。`, 'info');
        continue;
      }

      try {
        // 1. 底层 WSS 长连接保活守护 (避免被踢) —— 仅在保活开关开启时拉起，尊重用户主动关机保护
        if (!client.wsAlive && this.taskGate(acc, 'keepAlive')) {
          client.startKeepAliveWorker();
        }

        // 2. 原生登录打卡 (分项 Cron 管辖时主调度跳过)
        if (this.taskGate(acc, 'sign')) {
          if (excludeSet?.sign) {
            this.appendLog('Scheduler', `[${acc.name}] 分项 [每日签到] 由独立 Cron 管辖，本次主调度跳过。`, 'info');
          } else {
            try {
              const signRes = await executeNativeSign(client, acc, (src, msg, lvl) => this.appendLog(src, `[${acc.name}] ${msg}`, lvl));
              // 严格以官方任务中心实时判定为准：只有官方确认达成才记录今日打卡标记与时间，绝不虚报
              if (signRes && signRes.isCompleted) {
                acc.stats.lastSignTime = getBeijingTimeString();
                accSummary.sign = true;
              }
            } catch (e) {
              this.appendLog('Sign', `[${acc.name}] 打卡未达标: ${e.message}`, 'error');
            }
            await sleepStepJitter(acc.name, '打卡 -> AI 对话');
          }
        }

        // 3. 原生毫秒级 AI 智能对话 (彻底剔除 Chromium) (分项 Cron 管辖时主调度跳过)
        if (this.taskGate(acc, 'aiChat')) {
          if (excludeSet?.aiChat) {
            this.appendLog('Scheduler', `[${acc.name}] 分项 [AI 对话] 由独立 Cron 管辖，本次主调度跳过。`, 'info');
          } else {
            try {
              await executeNativeAiChat(client, acc, (src, msg, lvl) => this.appendLog(src, `[${acc.name}] ${msg}`, lvl));
              acc.stats.lastAiChatTime = getBeijingTimeString();
              accSummary.aiChat = true;
            } catch (e) {
              this.appendLog('AIChat', `[${acc.name}] AI 对话未达标: ${e.message}`, 'error');
            }
            await sleepStepJitter(acc.name, 'AI 对话 -> 挂机检测');
          }
        }

        // 4. 原生云电脑挂机守护检测 (分项 Cron 管辖时主调度跳过)
        if (this.taskGate(acc, 'cloudHang')) {
          if (excludeSet?.cloudHang) {
            this.appendLog('Scheduler', `[${acc.name}] 分项 [云电脑挂机] 由独立 Cron 管辖，本次主调度跳过。`, 'info');
          } else {
            try {
              const hangRes = await executeNativeHang(client, acc, (src, msg, lvl) => this.appendLog(src, `[${acc.name}] ${msg}`, lvl));
              accSummary.hang = (hangRes && hangRes.isCompleted === true);
            } catch (e) {
              this.appendLog('Hang', `[${acc.name}] 挂机状态检测异常: ${e.message}`, 'error');
            }
            if (acc.features?.autoRedeem) {
              await sleepStepJitter(acc.name, '挂机检测 -> 自动兑换');
            }
          }
        }

        // 5. 自动兑换：策略命中 → 绑定机器下单 → 单笔最多3次重试(间隔3秒) (分项 Cron 管辖时主调度跳过)
        if (acc.features?.autoRedeem) {
          if (excludeSet?.redeem) {
            this.appendLog('Scheduler', `[${acc.name}] 分项 [自动兑换] 由独立 Cron 管辖，本次主调度跳过。`, 'info');
          } else {
          try {
            const rConf = acc.redeemConfig || {};
            const todayStr = getBeijingDateStr();

            if (rConf.lastRedeemDate !== todayStr && rConf.prodId) {
              // 策略判定 (每月指定日含月末-1 / 每日 / 间隔天数)
              const cstDay = parseInt(todayStr.split('-')[2], 10);
              const ym = todayStr.split('-');
              const lastDayOfMonth = new Date(Number(ym[0]), Number(ym[1]), 0).getDate();
              let shouldRedeem = false;
              let reason = '';

              if (rConf.scheduleType === 'daily') {
                shouldRedeem = true;
                reason = '命中每日兑换策略';
              } else if (rConf.scheduleType === 'interval_days') {
                if (!rConf.lastRedeemDate) {
                  shouldRedeem = true;
                  reason = '首次执行间隔兑换';
                } else {
                  const diffDays = Math.floor((new Date(todayStr).getTime() - new Date(rConf.lastRedeemDate).getTime()) / (1000 * 3600 * 24));
                  if (diffDays >= (parseInt(rConf.intervalDays) || 30)) {
                    shouldRedeem = true;
                    reason = `已间隔 ${diffDays} 天，达到设定的 ${rConf.intervalDays} 天`;
                  }
                }
              } else {
                // monthly_days (默认)：monthlyDays 数组，-1 代表月末最后一天
                const days = Array.isArray(rConf.monthlyDays) ? rConf.monthlyDays : [-1];
                if (days.includes(cstDay) || (days.includes(-1) && cstDay === lastDayOfMonth)) {
                  shouldRedeem = true;
                  reason = (days.includes(-1) && cstDay === lastDayOfMonth) ? `命中月末最后一天 (${cstDay}号) 兑换策略` : `命中每月 ${cstDay} 号兑换策略`;
                }
              }

              if (shouldRedeem) {
                const prodType = rConf.prodType || 'pointstplupgrade';
                const pId = Number(rConf.prodId);
                // 判断商品是否需要绑定云电脑
                const needsDesktop = [17023101, 17023111, 17024101, 17026101, 17026111].includes(pId) ||
                  ['pointstplupgrade', 'pointsdiskupgrade'].includes(String(prodType).toLowerCase().trim());

                const targetDesktopId = parseInt(rConf.desktopId) || parseInt(client.metrics.desktopId) || parseInt(acc.stats?.desktopId) || 0;
                if (needsDesktop && !targetDesktopId) {
                  this.appendLog('Redeem', `[${acc.name}] 自动兑换跳过: 该商品必须绑定云电脑，但名下未找到有效设备`, 'warning');
                } else {
                  const buyTimes = Math.max(1, parseInt(rConf.maxRedeemTimes) || 1);
                  const totalCost = Number(rConf.costPoints) * buyTimes;
                  this.appendLog('Redeem', `[${acc.name}] ${reason}，准备自动下单兑换【${rConf.prodName || rConf.prodId}】x${buyTimes}，总计 ${totalCost} 积分...`, 'info');

                  let success = false;
                  let lastMsg = '';
                  let isRisk = false;
                  let isUnknown = false;

                  // 报文属性构建
                  const orderAttrs = [];
                  if (needsDesktop) {
                    orderAttrs.push({ attrKey: 'bindDesktopId', attrVal: Number(targetDesktopId) });
                  } else {
                    orderAttrs.push({ attrKey: 'mobilephone' });
                  }

                  // 原子总积分下单：单笔请求直传总积分 points = costPoints * times
                  // 天翼云 PaaS 将在云端一次性合并处理，直接生成 xN 扩容工单，彻底规避连续发单导致的扩容中锁定冲突！
                  const payload = {
                    busiChannel: '010',
                    orderType: 1,
                    pointType: Number(rConf.pointType) || 1,
                    points: totalCost,
                    sku: [{
                      execSort: 1,
                      prodId: Number(rConf.prodId),
                      prodType,
                      attrs: orderAttrs
                    }]
                  };

                  // 下单与重试策略收敛至 redeem_order.attemptRedeemOrder（缺陷修复 S11）：
                  // 明确业务错误才有限重试；网络异常等结果不明确的情况绝不盲目重试，
                  // 防止「服务端已受理但响应丢失」被重试成重复扣积分。
                  const orderResult = await attemptRedeemOrder({
                    fetchFn: (u, init) => fetch(u, init),
                    url: 'https://desk.ctyun.cn/selforder/api/selforder/paas/placeOrder',
                    headers: client.getSignedHeaders({ 'Content-Type': 'application/json;charset=UTF-8' }),
                    payload,
                    maxBusinessRetries: 3,
                    onAttempt: (attempt, info) => {
                      if (info.phase === 'retry') {
                        this.appendLog('Redeem', `[${acc.name}] 正在进行第 ${attempt}/3 次自动重试（上次为明确业务失败）...`, 'info');
                      } else if (info.phase === 'business_error') {
                        this.appendLog('Redeem', `[${acc.name}] 第 ${attempt} 次自动兑换未成功: ${info.msg}`, 'warning');
                      }
                    },
                  });
                  success = orderResult.status === 'success';
                  isRisk = orderResult.status === 'risk_blocked';
                  isUnknown = orderResult.status === 'unknown';
                  lastMsg = orderResult.msg;
                  if (success) {
                    this.appendLog('Redeem', `[${acc.name}] ✅ 成功一次性完成【${rConf.prodName || rConf.prodId}】x${buyTimes} 自动兑换，共消耗 ${totalCost} 积分！`, 'success');
                    rConf.lastRedeemDate = todayStr;
                    acc.redeemConfig = rConf;
                    this.saveConfig();
                    this.sendNotification(
                      acc,
                      `🎉 天翼云自动兑换成功 - ${acc.name}`,
                      `策略: ${reason}\n账号【${acc.name}】成功兑换【${rConf.prodName || rConf.prodId}】x${buyTimes}，共消耗 ${totalCost} 积分。`
                    );
                  } else if (isRisk) {
                    this.appendLog('Redeem', `[${acc.name}] 自动兑换触发风控已自动中止: ${lastMsg}`, 'error');
                  } else if (isUnknown) {
                    // 结果不明确：可能已受理。不写 lastRedeemDate（避免误记），也不再重试，
                    // 明确通知人工核对天翼云订单/积分变动后再决定。
                    this.appendLog('Redeem', `[${acc.name}] ⚠️ 自动兑换结果不明确（已停止重试以防重复下单）: ${lastMsg}。请人工核对订单与积分变动。`, 'error');
                    this.sendNotification(
                      acc,
                      `⚠️ 天翼云自动兑换结果不明确 - ${acc.name}`,
                      `账号【${acc.name}】兑换【${rConf.prodName || rConf.prodId}】时网络异常，服务端可能已受理。系统已停止自动重试以防重复扣积分，请人工核对订单记录与积分变动。`
                    );
                  } else {
                    this.appendLog('Redeem', `[${acc.name}] 自动兑换失败: ${lastMsg}`, 'error');
                  }
                }
              }
            } else if (rConf.lastRedeemDate === todayStr && rConf.prodId) {
              this.appendLog('Redeem', `[${acc.name}] 今日自动兑换已完成，跳过重复执行。`, 'info');
            }
          } catch (e) {
            this.appendLog('Redeem', `[${acc.name}] 自动兑换执行异常: ${e.message}`, 'error');
          }
          }
        }

        await client.refreshOfficialTasks();
        summaryResults.push(accSummary);
        processedAccounts.push(acc);

      } catch (err) {
        this.appendLog('Scheduler', `[${acc.name}] 任务执行链路异常: ${err.message}`, 'error');
      }

      // 账号间防风控离散随机退避 (仅在还有下一个账号时等待 5~15 秒)
      if (i < accounts.length - 1) {
        const accountJitterMs = Math.floor(Math.random() * 10000) + 5000; // 5000ms ~ 15000ms
        this.appendLog('Scheduler', `🛡️ [防风控] 账号间执行退避：随机等待 ${(accountJitterMs / 1000).toFixed(1)} 秒后执行下一个账号...`, 'info');
        await new Promise(r => setTimeout(r, accountJitterMs));
      }
    }

    // 严格判定（统一完成判定 evaluateAccountCompletion，与开机补跑同一事实来源 —— 新发现 S10）：
    // 只有当所有已处理账号的全部已开启任务（含浏览器真挂机与自动兑换）都真正达成时，才标记今日圆满完成。
    // 旧实现此处只查 sign/aiChat/cloudHang 三项，且通知明细按三项硬编码，与实际任务范围不一致。
    const completionByAccount = processedAccounts.map(acc => ({
      acc,
      states: this.evaluateAccountCompletion(acc, this.getClient(acc), { todayStr }),
    }));
    const allAccountsFullyDone = completionByAccount.length > 0 &&
      completionByAccount.every(({ states }) => TaskScheduler.allStatesCompleted(states));

    const TASK_LABEL = { sign: '打卡', aiChat: 'AI对话', cloudHang: '挂机1小时', browserHang: '浏览器真挂机', redeem: '自动兑换' };
    const STATUS_TEXT = {
      [TASK_STATUS.COMPLETED]: '官方已确认达成',
      [TASK_STATUS.PENDING]: '尚未达成',
      [TASK_STATUS.UNKNOWN]: '状态未知（官方状态不可得）',
      [TASK_STATUS.FAILED]: '本轮执行失败',
      [TASK_STATUS.RUNNING]: '执行中',
    };
    const buildDetail = () => completionByAccount.map(({ acc, states }) => {
      const parts = [];
      for (const [key, label] of Object.entries(TASK_LABEL)) {
        const st = states[key];
        if (!st || st.status === TASK_STATUS.SKIPPED) continue;
        // 兑换的 completed 是本地策略证据而非官方确认，措辞区分
        const txt = key === 'redeem' && st.status === TASK_STATUS.COMPLETED ? '已完成' : (STATUS_TEXT[st.status] || st.status);
        parts.push(`${label}[${txt}]`);
      }
      return `• ${acc.name}: ${parts.join(', ')}`;
    }).join('\n');

    if (allAccountsFullyDone) {
      this.lastCompletedDate = todayStr;
      this.appendLog('Scheduler', `🎉 今日云电脑全部自动化任务已圆满达成！做完即标记今日达成，当天绝不再空转。`, 'success');
      // 明细由统一完成判定按真实状态生成（全部为 completed 才进入此分支），不再硬编码。
      this.sendNotification(
        this.getSettings(),
        `🎉 天翼云电脑今日任务圆满达成 (${todayStr})`,
        `今日自动化任务已全部达成：\n${buildDetail()}\n所有任务均为原生协议极速直连，零 Chromium 内存占用！`
      );
    } else {
      const anySignPending = completionByAccount.some(({ states }) => states.sign && states.sign.status === TASK_STATUS.PENDING);
      const anySignUnknown = completionByAccount.some(({ states }) => states.sign && states.sign.status === TASK_STATUS.UNKNOWN);
      const signStatusNote = anySignUnknown ? '打卡状态未知 (官方状态刷新异常)' : (anySignPending ? '打卡已认领、等待官方确认 (系统会自动复检)' : '打卡已完成');
      this.appendLog('Scheduler', `⚡ 定时任务已执行 (${signStatusNote})。注意：打卡与挂机的最终成败一律以官方任务中心为准。`, 'info');
      // 措辞一律不得暗示"已成功"：认领下发 ≠ 达成，挂机启动 ≠ 达成；明细与判定同源生成。
      this.sendNotification(
        this.getSettings(),
        `⚡ 天翼云电脑定时任务已触发 (${todayStr})`,
        `定时任务已触发执行，长连接正在后台持续挂机中：\n${buildDetail()}`
      );
    }

    } finally {
      this.isRunning = false;
    }
  }
}

module.exports = { TaskScheduler, validateCronExpression, shouldRunCron, TASK_STATUS };
