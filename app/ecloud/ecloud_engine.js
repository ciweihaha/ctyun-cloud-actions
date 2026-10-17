'use strict';
/**
 * 移动公众云电脑 · 协议侧车桥接层
 * ================================
 *
 * 职责：把 `app/ecloud_engine/sidecar.py` 作为子进程托管起来，提供
 * 「发一条请求 → 拿一条响应」的 Promise 接口。
 *
 * 设计约束（2026-09-24 用户拍板，见 docs/移动公众融合方案.html）：
 *   1. **三平台保活机制互不重叠**：本模块只服务 `ecloud`（移动公众）。天翼云与
 *      移动爱家的保活逻辑各自独立，三者不共享保活代码。本模块产生的日志一律
 *      带 `platform: 'ecloud'`，与其它两平台的日志流分开。
 *   2. **调度归 Node**：本模块**不自建定时器**。何时调 `keepalive.l1/l2` 由
 *      `scheduler.js` + `taskGate()` 决定；这里只负责把一次调用可靠地送达侧车。
 *   3. **退出绝不静默**（对应方案书风险 R6）：侧车一旦退出/崩溃，必须把平台标记为
 *      「引擎离线」并让所有在途请求立刻失败 —— 绝不假装还在保活。
 *
 * 进程协议见 sidecar.py 头部注释（stdin/stdout JSON-Lines）。
 */

const { spawn } = require('child_process');
const path = require('path');
const readline = require('readline');

const ENGINE_DIR = path.join(__dirname, '..', 'ecloud_engine');
const SIDECAR = path.join(ENGINE_DIR, 'sidecar.py');

/** 解析 Python 解释器路径：环境变量优先，其次平台默认。 */
function resolvePython() {
  if (process.env.ECLOUD_PYTHON) return process.env.ECLOUD_PYTHON;
  return process.platform === 'win32' ? 'python' : 'python3';
}

// ---------------------------------------------------------------------------
// 【2026-09-26 真机实证·9009 循环】Windows 上 python.exe 可能是微软商店"占位符"：
// 它在 PATH 上"存在"，但一执行就打印 "Python was not found" 并以退出码 9009 退出
// ⇒ 侧车永远起不来、上层每轮巡检都重试 → 同一段错误把日志刷爆。
// 因此解释器必须**真跑一次**验证；候选都失败时给出可操作的人话结论并缓存，
// 同一进程内 10 分钟内不重复探测（装好 Python 后最多 10 分钟自动恢复）。
// ---------------------------------------------------------------------------
const PYTHON_PROBE_TIMEOUT_MS = 8000;
const PYTHON_PROBE_NEGATIVE_TTL_MS = 10 * 60 * 1000;
let _pythonProbeCache = null; // { triedAt, target: {path, args} | null }

function probePythonInterpreter(pythonPath, extraArgs = []) {
  return new Promise((resolve) => {
    const child = spawn(pythonPath, [...extraArgs, '-c', 'import sys;print(sys.version.split()[0])'], {
      cwd: ENGINE_DIR,
      stdio: ['ignore', 'pipe', 'pipe'],
      env: process.env,
    });
    let out = '';
    let err = '';
    child.stdout.on('data', (c) => { out += c; });
    child.stderr.on('data', (c) => { err += c; });
    const t = setTimeout(() => { try { child.kill(); } catch (_) { /* 已退出 */ } resolve({ ok: false, detail: '探测超时' }); }, PYTHON_PROBE_TIMEOUT_MS);
    child.on('error', (e) => { clearTimeout(t); resolve({ ok: false, detail: `${e.code || ''} ${e.message}`.trim() }); });
    child.on('exit', (code) => {
      clearTimeout(t);
      if (code === 0 && out.trim()) resolve({ ok: true, detail: out.trim() });
      else resolve({ ok: false, detail: (err || '').trim().split('\n')[0] || `exit=${code}` });
    });
  });
}

/**
 * 从候选里找第一个"真能跑"的 Python（进程级缓存；负结果 10 分钟后允许重探）。
 * @returns {Promise<{path:string,args:string[]} | null>} null = 全部候选不可用
 */
async function resolveWorkingPython() {
  if (_pythonProbeCache) {
    const fresh = Date.now() - _pythonProbeCache.triedAt < PYTHON_PROBE_NEGATIVE_TTL_MS;
    if (_pythonProbeCache.target) return _pythonProbeCache.target;
    if (fresh) return null; // 刚探过且全部失败：10 分钟内不重复打扰
  }

  const candidates = [];
  if (process.env.ECLOUD_PYTHON) candidates.push({ path: process.env.ECLOUD_PYTHON, args: [] });
  else if (process.platform === 'win32') {
    candidates.push({ path: 'python', args: [] }, { path: 'python3', args: [] }, { path: 'py', args: ['-3'] });
  } else {
    candidates.push({ path: 'python3', args: [] }, { path: 'python', args: [] });
  }

  let target = null;
  for (const c of candidates) {
    const probe = await probePythonInterpreter(c.path, c.args);
    if (probe.ok) { target = c; break; }
  }
  _pythonProbeCache = { triedAt: Date.now(), target };
  return target;
}

/** 9009 = Windows "命令未找到"（Python 未安装或只是商店占位符）的人话提示。 */
function exitCodeHint(code) {
  if (process.platform === 'win32' && code === 9009) {
    return ' —— 9009 = Windows 命令未找到（Python 未安装，或 python 只是微软商店占位符）';
  }
  return '';
}

/** 侧车运行状态 */
const EngineState = Object.freeze({
  STOPPED: 'stopped',
  STARTING: 'starting',
  READY: 'ready',
  EXITED: 'exited',
});

class EcloudEngine extends (require('events').EventEmitter) {
  /**
   * @param {object} [opts]
   * @param {string} [opts.pythonPath]   Python 解释器；默认 resolvePython()
   * @param {(entry:object)=>void} [opts.onLog] 侧车日志回调（已带 platform:'ecloud'）
   * @param {number} [opts.requestTimeoutMs] 单请求超时，默认 45s
   * @param {(msg:string)=>void} [opts.onStderr] 侧车 stderr 回调（引擎内部诊断）
   */
  constructor(opts = {}) {
    super();
    this.pythonPath = opts.pythonPath || resolvePython();
    this.onLog = opts.onLog || (() => {});
    this.onStderr = opts.onStderr || (() => {});
    this.requestTimeoutMs = opts.requestTimeoutMs || 45000;
    this.maxRestarts = opts.maxRestarts == null ? 3 : opts.maxRestarts;
    // 额外环境变量（覆盖 process.env）：生产用不到，测试用它验证"凭据文件不存在"
    // 这类部署配置分支（ECLOUD_CRED_FILE 指向不同路径），不必真去改宿主机环境。
    this.extraEnv = opts.env && typeof opts.env === 'object' ? opts.env : {};

    this._proc = null;
    this._state = EngineState.STOPPED;
    this._pending = new Map(); // id -> {resolve, reject, timer}
    this._seq = 0;
    this._restarts = 0;
    this._stderrTail = [];
    this._lastExit = null;
  }

  get state() { return this._state; }
  isReady() { return this._state === EngineState.READY; }

  /** 侧车是否为「引擎离线」状态（供 UI 如实显示，绝不伪装成保活中）。 */
  isOffline() {
    return this._state === EngineState.EXITED || this._state === EngineState.STOPPED;
  }

  /** 最近一次退出的信息（含退出码 / 信号 / stderr 尾部），用于诊断。 */
  lastExitInfo() {
    return this._lastExit ? { ...this._lastExit, stderrTail: this._stderrTail.slice(-20) } : null;
  }

  /**
   * 拉起侧车。幂等：已 READY 时直接返回。
   * 【2026-09-26】spawn 前必须先验证解释器真的能跑（Windows 商店占位符 python 退出码 9009）；
   * 没有可用解释器时抛出带根治指引的明确错误，绝不进入"起了就死"的重试循环。
   * ⚠️ 并发纪律：必须**先置 STARTING 再做任何 await**（含解释器探测）——
   *   否则两个并发调用（构造期 refreshDesktops + initAllKeepAlive 的 refreshDesktops）
   *   都会穿过状态守卫，各自 spawn 一个侧车（真机实测：双 pid 同秒拉起）。
   * @returns {Promise<object>} health 结果
   */
  async start() {
    if (this._state === EngineState.READY) return this.health();
    if (this._state === EngineState.STARTING) {
      await this._awaitReadyEvent();
      return this.health();
    }

    this._state = EngineState.STARTING;
    try {
      // 解释器解析：构造函数里传入的 pythonPath（显式指定 / 测试注入）作为第一候选，
      // 其余平台候选兜底；全部不可用 ⇒ 明确失败（带根治指引），不 spawn。
      if (!this._spawnTarget) {
        const probe = await probePythonInterpreter(this.pythonPath, []);
        if (probe.ok) {
          this._spawnTarget = { path: this.pythonPath, args: [] };
        } else {
          const working = await resolveWorkingPython();
          if (!working) {
            const err = new Error(
              `本机没有可用的 Python（首选 "${this.pythonPath}" 探测失败: ${probe.detail}）。` +
              '移动公众保活无法运行 —— 根治：安装 Python 3 并执行 pip install requests pycryptodome，' +
              '或设置环境变量 ECLOUD_PYTHON 指向真实解释器。'
            );
            err.code = 'ECLOUD_PYTHON_MISSING';
            throw err;
          }
          this._spawnTarget = working;
        }
      }

      const child = spawn(this._spawnTarget.path, [...this._spawnTarget.args, SIDECAR], {
        cwd: ENGINE_DIR,
        stdio: ['pipe', 'pipe', 'pipe'],
        env: { ...process.env, ...this.extraEnv },
      });
      this._proc = child;

      readline.createInterface({ input: child.stdout }).on('line', (line) => this._onLine(line));
      readline.createInterface({ input: child.stderr }).on('line', (line) => {
        this._stderrTail.push(line);
        if (this._stderrTail.length > 200) this._stderrTail.shift();
        this.onStderr(line);
      });

      child.on('error', (err) => {
        this._state = EngineState.EXITED;
        this._lastExit = { code: null, signal: null, error: `${err.code || ''} ${err.message}`.trim(), at: Date.now() };
        this._failAllPending(`侧车启动失败: ${err.message}`);
        this.emit('exit', this.lastExitInfo());
      });

      child.on('exit', (code, signal) => {
        this._state = EngineState.EXITED;
        this._lastExit = { code, signal, error: '', at: Date.now() };
        this._proc = null;
        // 🔴 退出绝不静默：立即让所有在途请求失败，平台据此标记「引擎离线」
        this._failAllPending(`侧车已退出 (code=${code}, signal=${signal})`);
        this.onLog({ level: 'error', platform: 'ecloud', msg: `协议引擎已离线 (code=${code}, signal=${signal})${exitCodeHint(code)}` });
        this.emit('exit', this.lastExitInfo());
      });

      // 主动探活：发一条 health，其应答即"就绪"信号（_onLine 会把状态切到 READY）
      let health;
      try {
        health = await this.request('health');
      } catch (e) {
        this.onLog({ level: 'error', platform: 'ecloud', msg: `协议引擎启动失败: ${e.message}` });
        throw e;
      }

      if (health && health.importError) {
        this.onLog({ level: 'error', platform: 'ecloud', msg: `侧车内核导入失败: ${health.importError}` });
      }
      if (health && health.credentials !== 'loaded') {
        this.onLog({ level: 'error', platform: 'ecloud', msg: `协议凭据未就绪: ${health.credentialError || '未知原因'}` });
      }
      return health;
    } catch (e) {
      // 探测失败 / 建连失败：退出 STARTING 态，让上层退避后还能重试（而不是永久卡死）
      if (this._state === EngineState.STARTING) this._state = EngineState.EXITED;
      try { if (this._proc) { this._proc.kill(); } } catch (_) { /* 已退出 */ }
      this._proc = null;
      throw e;
    }
  }

  /** 等待"就绪"事件（并发启动时用）：就绪或退出，二者先到先算。 */
  _awaitReadyEvent(timeoutMs = 20000) {
    if (this._state === EngineState.READY) return Promise.resolve();
    return new Promise((resolve, reject) => {
      const t = setTimeout(() => reject(new Error('侧车启动超时')), timeoutMs);
      const ok = () => { clearTimeout(t); resolve(); };
      const bad = () => { clearTimeout(t); reject(new Error('侧车在就绪前退出')); };
      this.once('ready', ok);
      this.once('exit', bad);
    });
  }

  _onLine(line) {
    const s = line.trim();
    if (!s) return;
    let msg;
    try { msg = JSON.parse(s); }
    catch (e) { this.onStderr(`[非JSON输出] ${s}`); return; }

    // 主动上报的事件（日志/进度）
    if (msg.event) {
      if (msg.event === 'log') {
        this.onLog({ level: msg.level || 'info', platform: 'ecloud', msg: msg.msg, ts: msg.ts });
      } else if (msg.event === 'ready') {
        this._state = EngineState.READY;
        this.emit('ready');
      } else {
        this.emit('event', msg);
      }
      return;
    }

    // 请求响应
    const id = msg.id;
    if (id == null) return;
    const p = this._pending.get(id);
    if (!p) return;
    this._pending.delete(id);
    clearTimeout(p.timer);
    if (msg.ok) {
      // 侧车在启动完成前就已能应答 ⇒ 视为就绪
      if (this._state === EngineState.STARTING) { this._state = EngineState.READY; this.emit('ready'); }
      p.resolve(msg.data);
    } else {
      const err = new Error(msg.error || '侧车返回失败');
      err.detail = msg.detail || '';
      err.fromEngine = true;
      p.reject(err);
    }
  }

  _failAllPending(reason) {
    for (const [, p] of this._pending) {
      clearTimeout(p.timer);
      p.reject(new Error(reason));
    }
    this._pending.clear();
  }

  /**
   * 发一条请求。
   * @param {string} op
   * @param {object} [params]
   * @param {string} [sessionId]
   */
  request(op, params = {}, sessionId = '') {
    if (!this._proc || this._state === EngineState.EXITED || this._state === EngineState.STOPPED) {
      return Promise.reject(new Error('协议引擎离线，无法执行 ' + op));
    }
    const id = 'r' + (++this._seq);
    const payload = { id, op, sessionId, params };
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this._pending.delete(id);
        reject(new Error(`侧车请求超时 (${op}, ${this.requestTimeoutMs}ms)`));
      }, this.requestTimeoutMs);
      this._pending.set(id, { resolve, reject, timer });
      try {
        this._proc.stdin.write(JSON.stringify(payload) + '\n');
      } catch (e) {
        clearTimeout(timer);
        this._pending.delete(id);
        reject(e);
      }
    });
  }

  /** 便捷封装 */
  health() { return this.request('health'); }
  loginBegin(sessionId, p) { return this.request('login.begin', p, sessionId); }
  loginSendSms(sessionId, p) { return this.request('login.sendSms', p, sessionId); }
  loginSms(sessionId, p) { return this.request('login.sms', p, sessionId); }
  desktopList(sessionId) { return this.request('desktop.list', {}, sessionId); }
  /** 桌面电源操作（available=开机 / shutdown=关机 / restart=restart）。用户显式触发。 */
  desktopPower(sessionId, p) { return this.request('desktop.power', p, sessionId); }
  keepaliveL1(sessionId) { return this.request('keepalive.l1', {}, sessionId); }
  keepaliveL2(sessionId, p) { return this.request('keepalive.l2', p, sessionId); }
  logout(sessionId) { return this.request('logout', {}, sessionId); }

  /** 优雅退出：先请求 shutdown，超时后强杀。 */
  async stop(force = false) {
    const proc = this._proc;
    if (!proc) { this._state = EngineState.STOPPED; return; }
    try {
      if (!force && this.isReady()) {
        await Promise.race([
          this.request('shutdown'),
          new Promise((r) => setTimeout(r, 2000)),
        ]);
      }
    } catch (e) { /* 退出路径不抛 */ }
    try { proc.stdin.end(); } catch (e) { /* ignore */ }
    if (!proc.killed) {
      const killer = setTimeout(() => { try { proc.kill('SIGKILL'); } catch (e) {} }, 2500);
      proc.once('exit', () => clearTimeout(killer));
      try { proc.kill(); } catch (e) { /* ignore */ }
    }
    this._state = EngineState.STOPPED;
  }
}

module.exports = { EcloudEngine, EngineState, resolvePython, ENGINE_DIR, SIDECAR };
