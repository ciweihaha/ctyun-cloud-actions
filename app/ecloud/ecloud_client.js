'use strict';
/**
 * 移动公众云电脑 · 账号客户端（保活调度 + 状态视图）
 * ==================================================
 *
 * ⚠️ 与另两平台的关系（用户 2026-09-24 明令）：「三个的保活代码机制不要重叠，各自各的，
 * 日志也是」。因此本文件：
 *   - **不 require** `ydpc_client.js` / `soho_client.js` / `cag_boot.js` / `zte_cag_raw.js`
 *     / `mqtt_client.js`，也**不复用**天翼云 `CtYunClient` 的任何方法；
 *   - 保活内核是**独立的 Python 侧车**（`app/ecloud_engine/sidecar.py`，走 ecloud 自己的
 *     HmacSHA1 + RSA-1024 协议族），不是 SOHO/CAG，也不是天翼云原生 WS；
 *   - 日志一律以 `source='ECLOUD'` + `platform='ecloud'` 落流，与 `SOHO/CAG`（移动爱家）
 *     和 `KeepAlive/Sign/...`（天翼云）分开，互不干扰。
 *
 * 保活分层（诚实口径：HTTP 层探针成功 ≠ 云电脑不会被关机）：
 *   L1 账号态保活   keepalive.l1  → USER_GET_INFO / USER_GET_DEVICE_INFO / PROBE_QKK_BATCHPUSH
 *                                   三态：ok=true 健康 / ok=false 全失败且 token 失效 / ok=null 全失败但非 token 错误
 *   L2 桌面登记保活 keepalive.l2  → desktopUptime
 *   （原 L3 SPICE 心跳占位层已于 2026-09-26 按用户要求整层删除）
 *
 * 诚实性红线（不可放宽）：
 *   1. 三态必须原样保留 —— 把 ok=null 压成 false 会导致每轮密码重登 → 短信轰炸；
 *   2. 单端点 401 绝不触发重登（判定在侧车 keepalive_probe 内完成）；
 *   3. L1/L2 成功**不等于**云电脑不被关机（HTTP 层没有会话心跳能力），
 *      因此 `metrics.keepaliveClaim` 恒为 'none'，UI 不得显示笼统的"保活中/已保活"。
 */

const { EcloudEngine, EngineState } = require('./ecloud_engine');

/** 日志来源标识（后端 inferLogPlatform 据此归入 ecloud 平台流） */
const LOG_SOURCE = 'ECLOUD';
/** 侧车保活 tick：20s 一片，真正的"到点"判定靠各目标自己的时间戳 */
const TICK_INTERVAL_MS = 20000;
/** 桌面列表静默刷新间隔 */
const DESKTOP_REFRESH_MS = 10 * 60 * 1000;
/** L1/L2 缺省周期（秒）——可由账号/单机字段覆盖 */
const DEFAULT_L1_INTERVAL_SEC = 300;
/**
 * 侧车连续拉起失败后的退避窗（2026-09-26）：9009（Python 缺失/商店占位符）这类
 * 确定性故障重试毫无意义，只会每 20s 把同一段错误刷进日志 —— 熔断 10 分钟。
 */
const ECLOUD_ENGINE_RETRY_BACKOFF_MS = 10 * 60 * 1000;

/**
 * 凭证主动续期周期（2026-09-27 真机实证）：平台 accessToken 有效期约 30 分钟——
 * 111 次 401 事件里 92 次间隔精确落在 30.5 分钟（均值 32.7 分钟），且该规律自 09-24
 * 起就存在（远早于任何功能改动）。被动续期（等 401 再重登）每天约产生 48 次
 * 「token 失效」告警 + 48 次密码重登，既吓人又无谓。
 * 现改为提前 ~5 分钟静默续期：密码登录频率与原先完全相同（仍约 30 分钟一次），
 * 但 401 从此不再出现。任何异常都回落为原有的"401 触发重登"路径。
 */
const ECLOUD_TOKEN_REFRESH_MS = Math.max(
  60000,
  parseInt(process.env.ECLOUD_TOKEN_REFRESH_MS, 10) || 25 * 60 * 1000
);

/**
 * 自动开机守护的同机冷却窗（2026-09-28 用户要求）：
 * 平台存在"约 48 小时强制关机"策略（真机实证，HTTP 保活无法阻止）——拦不住就自动恢复。
 * 冷却 10 分钟：既保证关机后尽快拉起，又避免接口被无效重试刷屏（沿用移动爱家同款节拍）。
 */
const ECLOUD_AUTOBOOT_COOLDOWN_MS = 10 * 60 * 1000;

/** 需要交互式短信验证才能继续的登录分支 */
const INTERACTIVE_BRANCHES = new Set([
  'need_device_trust', 'need_two_factor', 'need_enhanced_sms', 'need_4a',
]);

// ---------------------------------------------------------------------------
// 【2026-09-26 用户报障】平台口径必须可回放：把"平台到底报了什么"写进日志
// ---------------------------------------------------------------------------
// 事故：公众样本账号的「我的电脑」在 09-26 02:01 **真关机**（用户从云电脑自身系统取到的
// 开机/关机时间），可我们的卡片从那一刻起一直显示「运行中」，L1/L2 也一路"正常"。
// 复盘时才发现：平台返回的原始 `resourceStatus`（当时是 `available`）**从未进过日志**
// —— 它只落在 data/app_config.json 的最后一帧，历史无法回放，只能靠"在线时长"数字反推。
//
// 因此补两件事（纯加法，不改任何判定口径）：
//   ① 平台电源状态**发生变化时**落一条日志（同时给出原始 resourceStatus 与归一后的 powerState）；
//   ② 平台「在线时长」**回退时**落一条 warning —— 回退 = 平台侧会话记录被重建，
//      02:01 那次真关机正对应这个信号（57小时37分 → 8秒），当时它是静默发生的。
//
// ⚠️ 「在线时长」的准确语义（本次实测纠偏，勿再当运行时长用）：
//   它**不是虚机运行时长**。用户在 12:14 开机后，12:16 仍报「10小时14分33秒」
//   （从 02:01:36 起算的墙钟，开机并没有让它归零）。所以它只是"当前会话记录的年龄"：
//   **只有它变小（回退）才是有意义的事件**；单调增长仅说明"没发生过会话重建"，
//   **不能**用来证明机器正在运行。
/** 把平台返回的 "X小时X分X秒" 解析成秒；无法解析一律返回 -1（未知，绝不猜 0） */
function parseUptimeSeconds(text) {
  const s = String(text == null ? '' : text);
  const m = s.match(/(?:(\d+)\s*小时)?(?:(\d+)\s*分)?(?:(\d+)\s*秒)?/);
  if (!m || (!m[1] && !m[2] && !m[3])) return -1;
  return Number(m[1] || 0) * 3600 + Number(m[2] || 0) * 60 + Number(m[3] || 0);
}
/** 在线时长回退告警的最小幅度（秒）：小于此值视为解析差异/抖动，不报 */
const UPTIME_REGRESSION_MIN_SEC = 60;

// ---------------------------------------------------------------------------
// 【2026-09-26 用户拍板】L3（SPICE 显示面心跳）从未实现 —— 整层删除（UI 到底层）：
//   开关、探针、metrics.l3、侧车 keepalive.l3 op、Python l3_provider.py 一并移除。
//   保活分层只保留 L1（账号态）/ L2（桌面登记）；二者是 HTTP 层探针，
//   "成功 ≠ 云电脑不会被关机"的诚实口径不变。
// ---------------------------------------------------------------------------

class EcloudClient {
  /**
   * @param {object} account
   * @param {object} deps
   * @param {Function} deps.appendLog       (source, message, level, accountName, platform)
   * @param {Function} deps.sendNotification(target, title, content)
   * @param {Function} deps.saveConfig      () => void
   * @param {Function} deps.resolveTaskEnabled (account, desktop, taskType) —— 复用 server.js
   *        的权威开关判定，避免第二套真相（本文件不自行解释 features 字段）
   */
  constructor(account, deps = {}) {
    this.account = account;
    this.appendLog = deps.appendLog || (() => {});
    this.sendNotification = deps.sendNotification || (() => {});
    this.saveConfig = deps.saveConfig || (() => {});
    this.resolveTaskEnabled = deps.resolveTaskEnabled || (() => ({ enabled: false, reason: '缺少开关判定入口' }));

    this.sessionId = account.id;

    // 侧车：一个账号一个进程 —— 天然做到账号间与平台间的日志/会话隔离
    this.engine = new EcloudEngine({
      onLog: (entry) => this._log(entry.msg, entry.level || 'info'),
      onStderr: (line) => {
        // 侧车 stderr 是引擎内部诊断（logger 输出），只在 debug 级别留存，
        // 避免与上报日志重复刷屏
        if (/ERROR|Traceback/.test(line)) this._lastEngineStderr = line;
      },
    });
    this.engine.on('exit', (info) => {
      // 🔴 退出绝不静默
      this.metrics.engine.offline = true;
      this.metrics.engine.lastExit = info;
      this.metrics.status = 'offline';
      this.metrics.lastHeartbeatResult = `协议引擎已离线 (code=${info && info.code})，保活已停止`;
      this._sessionReady = false;
      // 卡片上的"侧车状态"小徽章已按用户要求移除 ⇒ 引擎离线必须落到日志，绝不静默
      this._log(`⚠️ 协议侧车进程已退出（code=${info && info.code}），保活已停止，将按需重新拉起`, 'error');
    });

    this.metrics = {
      status: 'offline',
      lastHeartbeatResult: '移动公众保活引擎待命中',
      successCount: 0,
      errorCount: 0,
      desktops: account.desktops || [],
      // 单机"当前动作"表：instanceId → { text, level, at }（仅内存，与 ydpc 各自的表各管各的）
      desktopActions: {},
      engine: { state: EngineState.STOPPED, offline: false, lastExit: null, pid: null },
      l1: { lastAt: 0, lastOk: null, lastError: '', okCount: 0, failCount: 0, unknownCount: 0, relogins: 0 },
      l2: { lastAt: 0, lastOk: null, lastError: '', okCount: 0 },
      // 诚实性：HTTP 层保活 ≠ 云电脑不被关机，因此永不为 'proven'
      keepaliveClaim: 'none',
      needsInteractiveLogin: false,
      sessionSource: '',
    };

    this.workerRunning = false;
    this.loopTimer = null;
    this._sessionReady = false;
    this._lastDesktopRefreshAt = 0;
    this._lastEngineStderr = '';
    this._suspendedNotified = false;
    // 凭证续期时间戳（0 = 尚未建立/恢复会话；建立后由 ensureSession / 各级重登写入）
    this._lastTokenRefreshAt = 0;
  }

  // ---------------------------------------------------------------- 基础设施
  _log(msg, level = 'info') {
    const accName = this.account.name || this.account.user || '移动公众账号';
    this.appendLog(LOG_SOURCE, `[${accName}] ${msg}`, level, accName, 'ecloud');
  }

  /** 每台桌面的"当前动作"（多机各自一行，避免账号级文案盖住真相） */
  _recordDesktopAction(instanceId, text, level = 'info') {
    if (!instanceId) return;
    this.metrics.desktopActions[instanceId] = { text, level, at: Date.now() };
  }

  /** 开关判定：一律转发给 server.js 的权威入口，本文件不自行解释 features */
  resolveTask(taskType, desktop = null) {
    try {
      return this.resolveTaskEnabled(this.account, desktop, taskType);
    } catch (e) {
      return { enabled: false, reason: `开关判定异常: ${e.message}` };
    }
  }

  async startEngine() {
    if (this.engine.isReady()) { this._engineFailStreak = 0; return this.engine.health(); }
    let health;
    try {
      health = await this.engine.start();
    } catch (e) {
      // 【2026-09-26】启动连续失败 ⇒ 退避熔断：不再每个巡检周期都重试刷屏。
      // 9009（Python 缺失/商店占位符）这类确定性故障重试没有意义，10 分钟后再自动尝试。
      this._engineFailStreak = (this._engineFailStreak || 0) + 1;
      if (this._engineFailStreak >= 2) {
        this._engineRetryNotBefore = Date.now() + ECLOUD_ENGINE_RETRY_BACKOFF_MS;
        this._log(
          `侧车连续 ${this._engineFailStreak} 次拉起失败，${Math.round(ECLOUD_ENGINE_RETRY_BACKOFF_MS / 60000)} 分钟内不再重试。根治指引：${e.message}`,
          'error'
        );
      }
      throw e;
    }
    this._engineFailStreak = 0;
    this._engineRetryNotBefore = 0;
    this.metrics.engine.state = this.engine.state;
    this.metrics.engine.offline = false;
    this.metrics.engine.pid = health && health.pid;
    if (health && health.credentials !== 'loaded') {
      throw new Error(`协议凭据未就绪：${health.credentialError || '未知原因'}（请配置 ECLOUD_CRED_FILE 或环境变量）`);
    }
    if (health && health.importError) {
      throw new Error(`侧车内核导入失败：${health.importError}`);
    }
    return health;
  }

  /** 设备指纹必须跨运行稳定（变化会触发服务端"未授信设备"） */
  ensureDeviceUid() {
    if (!this.account.ecloudDeviceUid) {
      this.account.ecloudDeviceUid = require('crypto').randomUUID();
      this.saveConfig();
      this._log('已生成并持久化设备指纹 deviceUid（用于规避"未授信设备"）', 'info');
    }
    return this.account.ecloudDeviceUid;
  }

  // ---------------------------------------------------------------- 登录
  _loginParams() {
    return {
      username: this.account.user,
      password: this.account.password,
      deviceUid: this.ensureDeviceUid(),
    };
  }

  /**
   * 确保可用会话：优先用本地保存的 token 恢复（免重复登录），
   * 不行再走一次密码登录。交互式短信分支无法在后台完成，必须如实上报。
   */
  async ensureSession() {
    if (this._sessionReady) return true;
    await this.startEngine();

    // 1) 尝试恢复（不含密码，避免 Node 每次重启都打一次登录接口）
    try {
      const r = await this.engine.request('session.restore',
        { username: this.account.user, deviceUid: this.ensureDeviceUid() }, this.sessionId);
      if (r && r.restored) {
        this._sessionReady = true;
        this._lastTokenRefreshAt = Date.now(); // 恢复即视为新鲜（真实年龄未知，401 路径兜底）
        this.metrics.sessionSource = 'restored';
        this.metrics.needsInteractiveLogin = false;
        this._log('会话已从本地 token 恢复（免重复登录）', 'info');
        return true;
      }
    } catch (e) {
      this._log(`会话恢复跳过（${e.message}），将走密码登录`, 'info');
    }

    // 2) 密码登录
    const r = await this.engine.loginBegin(this.sessionId, this._loginParams());
    const status = r && r.status;
    if (status === 'success') {
      this._sessionReady = true;
      this._lastTokenRefreshAt = Date.now(); // 新 token 签发
      this.metrics.sessionSource = 'login';
      this.metrics.needsInteractiveLogin = false;
      this._log('✅ 登录成功，会话已建立（token 已本地保存）', 'success');
      return true;
    }
    if (status === 'locked') {
      this.metrics.needsInteractiveLogin = true;
      this._log(`⛔ 登录被限流拦截：${r.error || ''}`, 'warning');
      throw new Error(`登录被限流：${r.error || ''}`);
    }
    if (INTERACTIVE_BRANCHES.has(status)) {
      // 后台无法代替用户完成短信验证 —— 必须如实告诉用户去面板登录
      this.metrics.needsInteractiveLogin = true;
      this.metrics.lastHeartbeatResult = '需要短信验证码，请在「移动公众」面板完成登录';
      this._log(`⚠️ 服务端要求短信验证（分支: ${status}），后台无法自动完成，请在界面上完成登录`, 'warning');
      this._notifyOnce('⚠️ 移动公众需要短信验证', `账号 [${this.account.name || this.account.user}] 登录需要短信验证码，请打开面板完成一次登录，之后可长期自动保活。`);
      throw new Error(`需要交互式短信验证: ${status}`);
    }
    this.metrics.needsInteractiveLogin = false;
    this._log(`❌ 登录失败: ${(r && r.error) || status || '未知错误'}`, 'error');
    throw new Error(`登录失败: ${(r && r.error) || status || '未知错误'}`);
  }

  /** 交互式登录（供 API/UI 调用）：返回结构化结果，不做任何"猜成功" */
  async loginInteractive(branch, code, opts = {}) {
    await this.startEngine();
    if (!branch) {
      const r = await this.engine.loginBegin(this.sessionId, this._loginParams());
      if (r && r.status === 'success') {
        this._sessionReady = true;
        this.metrics.sessionSource = 'login';
        this.metrics.needsInteractiveLogin = false;
        this._log('✅ 面板登录成功', 'success');
      }
      return r;
    }
    const r = await this.engine.loginSms(this.sessionId, {
      branch, code: code || '',
      mobile: opts.mobile || '',
      isTemporary: !!opts.isTemporary,
    });
    if (r && r.status === 'success') {
      this._sessionReady = true;
      this.metrics.sessionSource = 'login';
      this.metrics.needsInteractiveLogin = false;
      this._log('✅ 短信验证通过，登录成功', 'success');
    }
    return r;
  }

  /**
   * 下发短信验证码（need_* 分支后**必须**调用一次）。
   *
   * ⚠️ 为什么单独一个方法：实测确认服务端**不会**因为密码登录要求二次验证
   * 就替我们发码 —— 官方客户端是在拿到 mobile 后自己再打一次发码接口。漏掉这一步
   * 的表现是「界面让你输验证码，但手机永远收不到」，属静默不可用。
   * 失败一律抛出，绝不 return 一个"看起来成功"的对象。
   */
  async loginSendSms(branch, mobile, opts = {}) {
    await this.startEngine();
    const useMobile = mobile || opts.mobile || this.account?.mobile || '';
    const r = await this.engine.loginSendSms(this.sessionId, {
      branch: branch || '',
      mobile: useMobile,
    });
    if (!r || !r.sent) {
      throw new Error((r && r.error) || '短信验证码下发失败（侧车未确认发送）');
    }
    this._log(`📲 验证码已下发至 ${this._maskMobile(r.mobile || useMobile)}`, 'success');
    return r;
  }

  /** 手机号脱敏（前 3 后 4），日志与界面提示一律走这里，避免完整号码外泄。 */
  _maskMobile(m) {
    const s = String(m || '');
    return s.length >= 7 ? `${s.slice(0, 3)}****${s.slice(-4)}` : '***';
  }

  _notifyOnce(title, content) {
    if (this._suspendedNotified) return;
    this._suspendedNotified = true;
    try { this.sendNotification(this.account, title, content); } catch (e) { /* 通知失败不影响主流程 */ }
  }

  // ---------------------------------------------------------------- 桌面列表
  async refreshDesktops() {
    const accName = this.account.name || this.account.user;
    try {
      await this.ensureSession();
      const r = await this.engine.desktopList(this.sessionId);
      const list = (r && r.desktops) || [];

      // 差异合并：严格保留本机运行时状态。约定 `_` 前缀 = 本系统自用状态
      // （与 ydpc 同一纪律，但表与逻辑各自独立、互不共享）。
      const oldMap = new Map((this.account.desktops || []).map(d => [String(d.instanceId), d]));
      for (const d of list) {
        const old = oldMap.get(String(d.instanceId));
        if (old) {
          for (const k of Object.keys(old)) {
            if (k.startsWith('_') && old[k] !== undefined) d[k] = old[k];
          }
          if (old.keepaliveEnabled !== undefined) d.keepaliveEnabled = old.keepaliveEnabled;
          if (old.keepaliveInterval !== undefined) d.keepaliveInterval = old.keepaliveInterval;
          if (old.lastKeepAliveAt !== undefined) d.lastKeepAliveAt = old.lastKeepAliveAt;
          if (old.uptime !== undefined) d.uptime = old.uptime;
        } else if (d.keepaliveEnabled === undefined) {
          d.keepaliveEnabled = true;
        }

        // 【2026-09-26】平台电源状态发生变化必须留证（首次也记一次）。
        // 事件级日志：只在取值变化时写 —— 既不刷屏，又能完整还原状态变迁史，
        // 正是本次排查所缺的那块证据（原先只有 app_config.json 的最后一帧）。
        const rawNow = String(d.resourceStatus == null ? '' : d.resourceStatus);
        const rawPrev = old ? String(old.resourceStatus == null ? '' : old.resourceStatus) : null;
        if (rawPrev === null || rawPrev !== rawNow) {
          const from = rawPrev === null ? '（首次记录）' : (rawPrev || '（空）');
          this._log(
            `[${d.machineName || d.instanceId}] 平台电源状态${rawPrev === null ? '首次' : '变更'}：` +
            `${from} → ${rawNow || '（空）'}（界面口径 powerState=${String(d.powerState || 'unknown')}）`,
            rawPrev === null ? 'info' : 'warning'
          );
        }
      }
      this.account.desktops = list;
      this.metrics.desktops = list;
      this._lastDesktopRefreshAt = Date.now();
      this.saveConfig();
      this._log(`已同步桌面列表（${list.length} 台）`, 'info');
      return list;
    } catch (e) {
      this._log(`刷新桌面列表失败: ${e.message}`, 'error');
      this.metrics.errorCount += 1;
      return this.account.desktops || [];
    }
  }

  // ---------------------------------------------------------------- 保活
  /**
   * L1 保活一次。三态原样保留，并只在 ok===false 时才请求侧车重登。
   * @returns {Promise<{ok: boolean|null, error: string, relogged: boolean}>}
   */
  async keepaliveL1() {
    const r = await this.engine.keepaliveL1(this.sessionId);
    const ok = r ? r.ok : null;
    this.metrics.l1.lastAt = Date.now();
    this.metrics.l1.lastOk = ok;
    this.metrics.l1.lastError = (r && r.error) || '';

    if (ok === true) {
      this.metrics.l1.okCount += 1;
      this.metrics.successCount += 1;
      // 诚实口径：只描述"本次探针成功"，不说"保活成功"
      this.metrics.lastHeartbeatResult = 'L1 账号态探针成功（不代表云电脑不会被关机）';
      // 【2026-09-24 用户报障】成功路径**也必须落日志**。
      // 此前只有失败/重登才 _log，于是实时控制台里移动公众只剩登录记录，
      // 用户会误判"保活根本没跑"（卡片有 L1/L2，日志却一片空白）。
      this._log('L1 账号态探针通过（HTTP 层探针 ≠ 云电脑不会被关机）', 'success');
      return { ok, error: '', relogged: false };
    }

    if (ok === false) {
      this.metrics.l1.failCount += 1;
      this.metrics.errorCount += 1;
      this._log(`L1 保活判定 token 失效（服务端: ${(r && r.error) || '无详情'}），尝试重登刷新 token`, 'warning');
      let relogged = false;
      try {
        const rr = await this.engine.request('session.relogin', this._loginParams(), this.sessionId);
        relogged = !!(rr && rr.relogged);
        if (relogged) {
          this._lastTokenRefreshAt = Date.now(); // 重登 = 新 token
          this.metrics.l1.relogins += 1;
          this._log('重登成功，token 已刷新，下轮继续', 'success');
        } else if (rr && rr.skipped === 'cooldown') {
          this._log(`重登处于冷却期（${rr.nextInSec}s 后允许），本轮跳过 —— 防止短信轰炸`, 'warning');
        } else if (rr && rr.needInteractive) {
          this.metrics.needsInteractiveLogin = true;
          this._log(`重登需要短信验证（${rr.status}），请在面板完成登录后再恢复自动保活`, 'error');
        } else {
          this._log(`重登未成功: ${(rr && rr.error) || '未知'}`, 'error');
        }
      } catch (e) {
        this._log(`重登请求失败: ${e.message}`, 'error');
      }
      this.metrics.lastHeartbeatResult = relogged ? 'token 已重登刷新' : 'L1 判定 token 失效（重登未完成）';
      return { ok, error: (r && r.error) || '', relogged };
    }

    // ok === null：全端点失败但都不是 token 错误（服务端瞬时/5xx）
    // 🔴 绝不可在此重登 —— 高频密码重登会触发风控，正是"短信轰炸"的成因
    this.metrics.l1.unknownCount += 1;
    this.metrics.lastHeartbeatResult = 'L1 本轮请求全失败但非 token 错误（不重登，下轮重试）';
    this._log(`L1 本轮失败但非 token 失效（${(r && r.error) || '无详情'}）→ 按设计**不重登**，下轮重试`, 'warning');
    return { ok, error: (r && r.error) || '', relogged: false };
  }

  /** L2 桌面登记保活一次 */
  async keepaliveL2(desktop) {
    const r = await this.engine.keepaliveL2(this.sessionId, {
      instanceId: desktop.instanceId,
      machineId: desktop.machineId || '',
      machineName: desktop.machineName || '',
    });
    const ok = !!(r && r.ok);
    this.metrics.l2.lastAt = Date.now();
    this.metrics.l2.lastOk = ok;
    this.metrics.l2.lastError = (r && r.error) || '';
    if (ok) {
      this.metrics.l2.okCount += 1;
      desktop.uptime = (r && r.uptime) || desktop.uptime;

      // 【2026-09-26】在线时长**回退** = 平台侧会话记录被重建 ⇒ 机器极可能刚被关机/重启。
      // 这是"平台口径仍报在线"目前唯一能被我们察觉的证伪点（02:01 那次真关机正是它：
      // 57小时37分 → 8秒 静默发生，没有任何日志）。回退不影响保活能否成功，
      // 它只是把"平台说在线 ≠ 机器在跑"变成一条可追溯的证据。
      const upNow = parseUptimeSeconds(desktop.uptime);
      const upPrev = Number(desktop._uptimeSeconds);
      if (upNow >= 0) {
        if (Number.isFinite(upPrev) && upPrev >= 0 && upNow < upPrev - UPTIME_REGRESSION_MIN_SEC) {
          this._log(
            `⚠️ [${desktop.machineName || desktop.instanceId}] 平台在线时长回退：` +
            `${desktop._uptimeText || upPrev + '秒'} → ${desktop.uptime} —— ` +
            `平台侧会话记录被重建，机器在此前后很可能发生过关机/重启（这是"平台仍报在线"的反证）`,
            'warning'
          );
        }
        desktop._uptimeSeconds = upNow;
        desktop._uptimeText = desktop.uptime;
      }

      this._recordDesktopAction(desktop.instanceId, 'L2 桌面登记探针成功', 'ok');
      // 【2026-09-28】探针证据打点：成功 ⇒ 清除 NO_UPTIME 标记（describeDesktopKeepAlive 用它合成开关机判定）
      desktop._l2At = Date.now();
      desktop._l2NoUptime = false;
      // 成功同样落日志（同上：不得让日志流只剩失败与登录）
      this._log(
        `[${desktop.machineName || desktop.instanceId}] L2 桌面登记成功` +
        `${desktop.uptime ? ` · 在线时长 ${desktop.uptime}` : ''}`,
        'success'
      );
    } else {
      this._recordDesktopAction(desktop.instanceId, `L2 桌面登记失败: ${(r && r.error) || '未知'}`, 'error');
      // 【2026-09-28】探针证据打点：NO_UPTIME = "没读到在线时长" —— 实测为真关机的
      // 有效证据之一（09-28 关机全程如此）；但也可能在平台会话记录异常时出现，
      // 故只作为"合成判定"的补充证据（见 describeDesktopKeepAlive 的注释）。
      desktop._l2At = Date.now();
      desktop._l2NoUptime = !!(r && /NO_UPTIME/.test(String(r.error || '')));
      if (r && r.tokenExpired) {
        // 与 L1 同一纪律：只在明确 token 失效时才动重登，且侧车有冷却期兜底
        this._log(`[${desktop.machineName || desktop.instanceId}] L2 报告 token 失效，请求重登`, 'warning');
        try {
          const rr = await this.engine.request('session.relogin', this._loginParams(), this.sessionId);
          if (rr && rr.relogged) { this.metrics.l1.relogins += 1; this._lastTokenRefreshAt = Date.now(); }
        } catch (e) { this._log(`L2 重登请求失败: ${e.message}`, 'error'); }
      }
    }
    return { ok, error: (r && r.error) || '' };
  }

  /**
   * 桌面电源操作（用户显式触发）：开机 / 关机 / 重启。
   * 【2026-09-28】开机能力正式接入 —— 走平台官方 operate 通道（asar 客户端同款语义）：
   *   available=开机（后端不认识 startup/powerOn） | shutdown=关机 | restart=重启。
   * 真机验证：服务端对 operate=available 返回业务级回执（"已开机不允许开机"），调用链通。
   * 措辞纪律：成功只报"平台已受理"——受理 ≠ 已开机，最终状态以随后刷新的平台状态为准。
   */
  async powerDesktop(instanceId, operate = 'available') {
    const opCn = { available: '开机', shutdown: '关机', restart: '重启' }[operate] || operate;
    await this.ensureSession();
    const d = (this.account.desktops || []).find(x => String(x.instanceId) === String(instanceId));
    if (!d) throw new Error('未找到该云电脑（请先「同步桌面」拉取列表）');
    if (!d.machineId) throw new Error('该云电脑缺少 machineId，无法下发电源指令（请先「同步桌面」）');

    const r = await this.engine.desktopPower(this.sessionId, {
      instanceId: d.instanceId,
      machineId: d.machineId,
      machineName: d.machineName || '',
      resourcePoolUid: d.resourcePoolUid || '',
      operate,
    });
    const msg = (r && r.message) || `已下发${opCn}指令，平台已受理`;
    this._log(`[${d.machineName || d.instanceId}] ✅ 已下发【${opCn}】指令，平台已受理（operate=${operate}）`, 'success');
    this._recordDesktopAction(d.instanceId, `✅ 已下发${opCn}指令（待平台生效）`, 'ok');
    // 状态落地需要数秒到数十秒：推迟刷新，让状态徽章与日志同步
    setTimeout(() => this.refreshDesktops().catch(() => {}), operate === 'available' ? 15000 : 8000);
    return { success: true, message: msg, operate };
  }

  /** 供 API 手动触发一次完整保活（与自动 tick 走同一条代码路径） */
  async runKeepAliveOnce() {
    const out = { l1: null, l2: [] };
    const g1 = this.resolveTask('ecloudL1AccountKeep');
    if (g1.enabled) out.l1 = await this.keepaliveL1();
    else this._log(`L1 未执行：${g1.reason}`, 'info');

    for (const d of (this.account.desktops || [])) {
      const g2 = this.resolveTask('ecloudL2DesktopReg', d);
      if (!g2.enabled) continue;
      if (d.keepaliveEnabled === false) continue;
      out.l2.push({ instanceId: d.instanceId, ...(await this.keepaliveL2(d)) });
    }
    // 手动「立即保活」也把分层结论写进日志（与自动巡检同一口径、同一函数）
    this._logLayerSummary();
    return out;
  }

  /**
   * 把 L1/L2 分层结论落到**日志流**。
   * 【2026-09-24 用户要求】卡片上的「分层保活监视」改为只保留逐台云电脑状态，
   * 分层总览（L1 探针 / L2 登记）改由日志体现 —— 否则日志里只有登录记录，
   * 看不出保活到底跑没跑。
   * 只在**真正发生过巡检**后调用（20s 一次的 tick 不能刷屏）。口径与红线一致：
   * 只陈述探针/登记结果，绝不说"已保活"。
   */
  _logLayerSummary() {
    const l1 = this.metrics.l1;
    const l1Text = l1.lastOk === true
      ? `🟢 通过（累计 ${l1.okCount} 次）`
      : (l1.lastOk === false
        ? `🔴 token 失效（累计失败 ${l1.failCount} 次 · 已重登 ${l1.relogins} 次）`
        : `🟣 未判定（累计未判定 ${l1.unknownCount} 次 · 按纪律不重登）`);
    this._log(
      `📊 分层巡检结果 · L1 账号态: ${l1Text} · L2 桌面登记: 累计 ${this.metrics.l2.okCount} 台成功` +
      `${this.metrics.l2.lastError ? `（最近失败: ${this.metrics.l2.lastError}）` : ''} · ` +
      `说明: L1/L2 是 HTTP 层探针，成功不代表云电脑不会被关机`,
      'info'
    );
  }

  // ---------------------------------------------------------------- 保活循环
  startKeepAliveWorker() {
    if (this.workerRunning) return;
    this.workerRunning = true;
    const accName = this.account.name || this.account.user;
    this._log(`移动公众独立保活看门狗已启动（tick ${TICK_INTERVAL_MS / 1000}s，L1 基准周期 ${Math.round(this._l1IntervalSec() / 60)} 分钟）`, 'info');

    const runCycle = async () => {
      if (!this.workerRunning) return;
      try {
        if (this.account.features && this.account.features.keepAlive === false) {
          this.metrics.status = 'offline';
          this.metrics.lastHeartbeatResult = '账号级保活总开关已关闭（待命中）';
          for (const d of (this.account.desktops || [])) {
            this._recordDesktopAction(d.instanceId, '全局保活已关闭 · 本机未参与巡检', 'off');
          }
          this._scheduleNext(runCycle);
          return;
        }

        // 引擎离线（崩溃/被 kill）→ 如实置为离线，并尝试按需重启
        if (this.engine.isOffline()) {
          this.metrics.status = 'offline';
          this._sessionReady = false;
          // 退避熔断期内：安静等待，不再每 20s 重复"拉起→失败"的刷屏循环
          if (this._engineRetryNotBefore && Date.now() < this._engineRetryNotBefore) {
            this.metrics.lastHeartbeatResult = `侧车暂不可用（退避中，${Math.ceil((this._engineRetryNotBefore - Date.now()) / 60000)} 分钟后自动重试）`;
            this._scheduleNext(runCycle);
            return;
          }
          this.metrics.lastHeartbeatResult = '协议引擎已离线，正在尝试重新拉起…';
          this._log('检测到协议引擎离线，尝试重新拉起侧车', 'warning');
          await this.startEngine();
        }

        // 凭证主动续期（2026-09-27：平台 accessToken 约 30 分钟有效，真机统计 92/111 次 401
        // 间隔精确 30.5 分钟）。提前 ~5 分钟静默刷新，密码登录频率与原先完全相同，
        // 但不让"过期后的第一个调用"再吃 401。失败不阻断，回落为原有的 401 触发重登。
        if (this._lastTokenRefreshAt && Date.now() - this._lastTokenRefreshAt >= ECLOUD_TOKEN_REFRESH_MS) {
          try {
            const rr = await this.engine.request('session.relogin',
              { ...this._loginParams(), quiet: true }, this.sessionId);
            if (rr && rr.relogged) {
              this._lastTokenRefreshAt = Date.now();
              this._log('🔁 凭证已按周期静默续期（平台 accessToken 约 30 分钟有效，提前续期避免 401）', 'info');
            } else if (rr && rr.skipped === 'cooldown') {
              // 冷却期内不强行重登（防短信轰炸）；不推进时间戳，下一 tick 再试
            } else if (rr && rr.needInteractive) {
              this.metrics.needsInteractiveLogin = true;
              this._log(`凭证续期需要短信验证（${rr.status}），请在面板完成登录后再恢复自动保活`, 'error');
            }
          } catch (e) {
            this._log(`凭证周期续期失败（将回落为 401 触发重登）: ${e.message}`, 'warning');
          }
        }

        // 桌面列表静默刷新（10 分钟一次）
        if (!this._lastDesktopRefreshAt || Date.now() - this._lastDesktopRefreshAt > DESKTOP_REFRESH_MS) {
          await this.refreshDesktops().catch(() => {});
        }

        // ── 🛡️ 自动开机守护（2026-09-28 用户要求）────────────────────────────────
        // 背景：平台存在"约 48 小时强制关机"策略（真机实证：两次 02:01 强制关机、计数器精确
        // 48h 归零），HTTP 层保活无法阻止。既然拦不住，就保证**被关机后自动拉起**：
        //   双开关（账号级 + 单机，**均默认开启** ← 2026-09-28 用户拍板；不需要可显式关）
        //   + 同机 10 分钟冷却（防接口刷屏）+ 合成判定门禁（只对"确定关机"下发，绝不盲开）。
        if (this.account.features?.autoBoot !== false) {
          for (const d of (this.account.desktops || [])) {
            if (d.autoBootEnabled === false) continue; // 单机默认开启，显式关闭才跳过
            const st = this._effectivePowerState(d);
            if (st.state !== 'off') continue;
            if (Date.now() - (d._lastAutoBootAt || 0) < ECLOUD_AUTOBOOT_COOLDOWN_MS) continue;
            if (!this.engine.isReady()) continue; // 引擎不在线时不空跑（下轮再试）
            d._lastAutoBootAt = Date.now();
            this._log(`[${d.machineName || d.instanceId}] 🛡️ 自动开机守护：检测到关机（依据：${st.evidence}），正在下发开机指令...`, 'info');
            try {
              await this.powerDesktop(d.instanceId, 'available');
            } catch (e) {
              this._log(`[${d.machineName || d.instanceId}] 🛡️ 自动开机失败: ${e.message}`, 'warning');
            }
          }
        }

        const now = Date.now();
        // 本轮是否真的执行过巡检动作 —— 只有执行过才写"分层巡检结果"日志，
        // 否则 20s 一次的 tick 会把日志刷爆（用户要的是可读的保活轨迹）
        let acted = false;

        // L1：账号态保活（到点才做）
        const g1 = this.resolveTask('ecloudL1AccountKeep');
        if (!g1.enabled) {
          this._recordDesktopAction('__account__', `L1 未执行：${g1.reason}`, 'off');
        } else {
          const l1IntervalMs = this._l1IntervalSec() * 1000;
          if (now - (this.metrics.l1.lastAt || 0) >= l1IntervalMs) {
            const before = this.metrics.l1.lastAt;
            this.metrics.l1.lastAt = now; // 先打点，避免异常路径陷入高频重试
            try {
              await this.keepaliveL1();
              acted = true;
            } finally {
              if (!this.metrics.l1.lastAt) this.metrics.l1.lastAt = before;
            }
          }
        }

        // L2：桌面登记保活（逐台、各自周期）
        for (const d of (this.account.desktops || [])) {
          const g2 = this.resolveTask('ecloudL2DesktopReg', d);
          if (!g2.enabled) {
            this._recordDesktopAction(d.instanceId, `L2 未执行：${g2.reason}`, 'off');
            continue;
          }
          if (d.keepaliveEnabled === false) {
            this._recordDesktopAction(d.instanceId, '单机保活已关闭 · 不参与巡检', 'off');
            continue;
          }
          const intervalMs = Math.max(60, parseInt(d.keepaliveInterval, 10) || this._l1IntervalSec()) * 1000;
          if (now - (d.lastKeepAliveAt || 0) < intervalMs) continue;
          d.lastKeepAliveAt = now;
          try {
            await this.keepaliveL2(d);
            acted = true;
          } catch (e) {
            this._recordDesktopAction(d.instanceId, `L2 异常: ${e.message}`, 'error');
          }
        }

        // 【2026-09-26 用户拍板】原 L3（SPICE 心跳）占位层已整层删除 —— 分层巡检只保留 L1/L2。

        // 分层结论落日志（仅本轮确实巡检过）
        if (acted) this._logLayerSummary();

        const status = this.metrics.needsInteractiveLogin
          ? 'needs_login'
          : (this.metrics.l1.lastOk === true ? 'online' : (this.metrics.l1.lastAt ? 'degraded' : 'offline'));
        this.metrics.status = status;
        if (status === 'online') {
          this.metrics.lastHeartbeatResult = this.buildSummaryText();
        }
        this.saveConfig();
      } catch (e) {
        this.metrics.status = 'offline';
        this.metrics.errorCount += 1;
        this._log(`保活巡检异常: ${e.message}`, 'error');
        if (this.engine.isOffline()) this._sessionReady = false;
      }
      this._scheduleNext(runCycle);
    };

    this.loopTimer = setTimeout(runCycle, 1500);
  }

  _scheduleNext(runCycle) {
    if (!this.workerRunning) return;
    this.loopTimer = setTimeout(runCycle, TICK_INTERVAL_MS);
  }

  _l1IntervalSec() {
    return Math.max(60, parseInt(this.account.keepaliveInterval, 10) || DEFAULT_L1_INTERVAL_SEC);
  }

  stopKeepAliveWorker() {
    this.workerRunning = false;
    if (this.loopTimer) { clearTimeout(this.loopTimer); this.loopTimer = null; }
  }

  /** 账号级摘要（多机时逐台列示，避免一台的文案盖住全场） */
  buildSummaryText() {
    const desktops = this.account.desktops || [];
    if (desktops.length === 0) return '移动公众账号在线，暂无云电脑';
    const parts = desktops.map(d => {
      const act = this.metrics.desktopActions[d.instanceId];
      return `${d.machineName || d.instanceId}: ${act ? act.text : '待巡检'}`;
    });
    return parts.join(' · ');
  }

  /** 单机视图：供前端卡片渲染（倒计时/最近动作现算，不落盘） */
  /**
   * 开关机合成的**唯一判定入口**（界面视图与自动开机守护共用 —— 杜绝两套判定漂移）。
   * 三条独立信号优先级：在线时长探测（NO_UPTIME 且新鲜）> 平台操作表（可开机）> 平台状态。
   * 依据理由见 describeDesktopKeepAlive 的历史注释（平台状态会滞后、时长探测 09-26/09-28 行为还不一致）。
   * @returns {{state:'on'|'off'|'unknown', evidence:string}}
   */
  _effectivePowerState(desktop) {
    const d = desktop || {};
    const platformPower = String(d.powerState || 'unknown');
    const noUptimeRecent = d._l2NoUptime === true
      && (Date.now() - (d._l2At || 0) < 15 * 60 * 1000);
    if (platformPower !== 'off' && noUptimeRecent) {
      return { state: 'off', evidence: '在线时长探测（平台状态滞后，以探针为准）' };
    }
    if (platformPower === 'unknown' && d.powerOnEnable === true) {
      return { state: 'off', evidence: '平台操作表（可开机）' };
    }
    return { state: platformPower, evidence: '平台状态' };
  }

  describeDesktopKeepAlive(desktop) {
    const intervalSec = Math.max(60, parseInt(desktop.keepaliveInterval, 10) || this._l1IntervalSec());
    const last = desktop.lastKeepAliveAt || 0;
    const elapsedSec = last ? Math.floor((Date.now() - last) / 1000) : 0;
    const act = this.metrics.desktopActions[desktop.instanceId] || null;
    const g2 = this.resolveTask('ecloudL2DesktopReg', desktop);
    // ── 【2026-09-28】开关机判定加固：三条独立信号合成（唯一入口在 _effectivePowerState）──
    //   ① 平台状态 resourceStatus/powerState —— 实测会滞后（09-26 关机后仍报 available 数小时）；
    //   ② 平台操作表 powerOn.operateEnable —— 平台操作层现算（true=平台认为现在可开机）；
    //   ③ 在线时长探测（L2）—— 09-28 实测：真关机时 NO_UPTIME；但 09-26 实测：关机后
    //      仍能读到计时（平台侧会话记录在跑）⇒ 只能作"off 的补充证据"，不能当唯一真源。
    const eff = this._effectivePowerState(desktop);
    const powerState = eff.state;
    const powerEvidence = eff.evidence;
    const platformPower = String(desktop.powerState || 'unknown');
    return {
      intervalSec,
      elapsedSec,
      remainSec: last ? Math.max(0, intervalSec - elapsedSec) : 0,
      lastAction: act,
      enabled: desktop.keepaliveEnabled !== false && g2.enabled,
      disabledReason: desktop.keepaliveEnabled === false ? '单机保活开关已关闭' : (g2.enabled ? '' : g2.reason),
      uptime: desktop.uptime || '',
      // 开关机判定（界面唯一该看的合成口径）
      powerState,                                   // on / off / unknown
      powerEvidence,                                // 依据来源（如实标注）
      platformPowerState: platformPower,            // 平台原始口径（排查用）
      canBoot: desktop.powerOnEnable === true || powerState === 'off',
      powerOnHint: desktop.powerOnHint || '',
      // 诚实性标注：本视图不构成"保活成功"的证明
      claim: 'none',
    };
  }

  /** 进程退出路径：优雅停侧车 */
  async stop(force = false) {
    this.stopKeepAliveWorker();
    try { await this.engine.stop(force); } catch (e) { /* 退出路径不抛 */ }
  }
}

module.exports = { EcloudClient, LOG_SOURCE, INTERACTIVE_BRANCHES };
