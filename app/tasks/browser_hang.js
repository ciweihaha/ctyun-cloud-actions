/**
 * 浏览器真挂机模块 (Browser Real Hang)
 *
 * 原理：用真实浏览器打开天翼云电脑网页版，保持会话约 61 分钟，
 * 让官方按"会话在线时长"累积"使用1小时"任务进度。
 *
 * 结果状态分类（缺陷修复 G3：旧实现除前置失败外一律 ok:true，浏览器中途
 * 退出/进度不可读也谎报成功）：
 * - task_completed       官方确认"使用1小时"达成（ok:true）
 * - already_completed    启动前官方已确认达成，未启动浏览器（ok:true）
 * - time_up_unconfirmed  时长耗尽但官方未确认达成（ok:false）
 * - browser_exited       浏览器进程在时长耗尽前退出（ok:false）
 * - launch_failed        spawn 失败或异步 error 事件（ok:false）
 * - progress_check_failed 全程未能成功读取一次官方进度（ok:false）
 * - already_running      同账号已有挂机在运行（ok:false）
 * - cancelled            被 stop/信号取消（ok:false）
 * - no_desktop / no_browser  前置条件缺失（ok:false）
 *
 * 并发与清理：
 * - 每账号独立 profile 目录（tmpdir/ctyun-browser-hang-<账号标识>），
 *   旧实现所有账号共用一个目录会互相顶号/锁冲突。
 * - 同账号互斥登记表，重复启动直接拒绝。
 * - 只终止本模块 spawn 的进程（按 pid/进程组），绝不误杀他人进程；
 *   cancelBrowserHang / cancelAllBrowserHangs 供调度器 stop() 与信号处理调用。
 * - 就绪验证：spawn 的 'spawn' 事件确认启动成功，随后首轮官方进度可读
 *   作为会话管线就绪证据；无 DOM 级探针可用，故不冒充页面级就绪。
 */

const { spawn, execSync, ChildProcess } = require('child_process');
const path = require('path');
const fs = require('fs');
const os = require('os');

// 挂机时长：61 分钟（毫秒）
const HANG_DURATION_MS = 61 * 60 * 1000;
// 进度检查间隔：30 秒
const PROGRESS_CHECK_INTERVAL_MS = 30 * 1000;
// spawn 启动确认超时：超过仍无 spawn/error 事件且无 pid 视为失败
const LAUNCH_CONFIRM_MS = 5000;

// 同账号互斥登记表：key -> { proc, cancelled, wake }
const activeHangs = new Map();
let signalCleanupInstalled = false;

function accountKey(acc) {
  return String((acc && (acc.id || acc.username || acc.user || acc.name)) || 'unknown');
}

function sanitizeKey(key) {
  return key.replace(/[^a-zA-Z0-9_-]/g, '_');
}

function profileDirFor(key) {
  return path.join(os.tmpdir(), `ctyun-browser-hang-${sanitizeKey(key)}`);
}

/**
 * 查找可用的浏览器可执行文件路径（Windows 固定路径 + PATH；补充 Linux 候选，
 * 旧实现只有 Windows 路径与 where 命令，在非 Windows 部署必然 no_browser）
 */
function findBrowserPath() {
  const candidates = process.platform === 'win32'
    ? [
        'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
        'C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe',
        'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
        'C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe',
      ]
    : [
        '/usr/bin/google-chrome',
        '/usr/bin/google-chrome-stable',
        '/usr/bin/chromium',
        '/usr/bin/chromium-browser',
        '/usr/bin/microsoft-edge',
        '/snap/bin/chromium',
      ];

  for (const p of candidates) {
    try {
      if (fs.existsSync(p)) return p;
    } catch (e) {}
  }

  const lookupCmd = process.platform === 'win32' ? 'where' : 'which';
  for (const name of ['chrome', 'google-chrome', 'chromium', 'chromium-browser', 'msedge', 'microsoft-edge']) {
    try {
      const found = execSync(`${lookupCmd} ${name}`, { encoding: 'utf8', timeout: 5000 }).trim().split('\n')[0];
      if (found && fs.existsSync(found.trim())) return found.trim();
    } catch (e) {}
  }

  return null;
}

/**
 * 获取天翼云电脑网页版 URL
 */
function getWebPortalUrl(client, desktop) {
  const desktopId = desktop.objId || desktop.desktopId || '';
  return `https://desk.ctyun.cn/web/?desktopId=${encodeURIComponent(desktopId)}`;
}

/** 只终止本模块 spawn 的进程：真实 ChildProcess 优先杀进程组，失败回退单进程 */
function killOwnProcessTree(proc) {
  if (!proc || !proc.pid) return;
  if (proc instanceof ChildProcess) {
    if (process.platform === 'win32') {
      try { execSync(`taskkill /PID ${proc.pid} /T /F`, { timeout: 10000 }); return; } catch (e) {}
    } else {
      // detached spawn 使子进程成为进程组组长，负 pid 杀整组（含浏览器子进程）
      try { process.kill(-proc.pid, 'SIGTERM'); return; } catch (e) {}
    }
  }
  try { proc.kill('SIGTERM'); } catch (e) {}
}

/** 取消指定账号的挂机；返回是否确有在跑的任务 */
function cancelBrowserHang(key) {
  const entry = activeHangs.get(String(key));
  if (!entry) return false;
  entry.cancelled = true;
  if (entry.wake) entry.wake();
  return true;
}

function cancelAllBrowserHangs() {
  for (const key of activeHangs.keys()) cancelBrowserHang(key);
}

function getActiveBrowserHangs() {
  return [...activeHangs.keys()];
}

/** 进程信号时清理自有浏览器进程（不决定进程退出，退出由服务主信号处理负责） */
function installSignalCleanup() {
  if (signalCleanupInstalled) return;
  signalCleanupInstalled = true;
  for (const sig of ['SIGINT', 'SIGTERM']) {
    try {
      process.on(sig, () => { cancelAllBrowserHangs(); });
    } catch (e) {}
  }
}

/** 等待 spawn 结果：'spawn' 成功 / 'error' 失败 / 超时 */
function waitForLaunch(proc, confirmMs) {
  return new Promise((resolve) => {
    let settled = false;
    const done = (ok, err) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({ ok, err });
    };
    const timer = setTimeout(() => done(!!proc.pid, proc.pid ? null : new Error('launch confirm timeout')), confirmMs);
    proc.once('spawn', () => done(true));
    proc.once('error', (err) => done(false, err));
  });
}

function interruptibleSleep(ms, entry) {
  return new Promise((resolve) => {
    const timer = setTimeout(() => { entry.wake = null; resolve(); }, ms);
    entry.wake = () => { clearTimeout(timer); entry.wake = null; resolve(); };
  });
}

/**
 * 执行浏览器真挂机
 * @param {object} client - CtYunClient 实例（已登录）
 * @param {object} acc - 账号信息
 * @param {function} onLog - 日志回调 (src, msg, lvl)
 * @param {object} [opts] - 测试/调优注入：spawnFn、browserPath、hangDurationMs、
 *                          progressIntervalMs、launchConfirmMs
 * @returns {Promise<object>} { ok, hangMinutes, reason }
 */
async function executeBrowserHang(client, acc, onLog, opts = {}) {
  const log = onLog || (() => {});
  const accName = acc.name || acc.username || '未知账号';
  const key = accountKey(acc);
  const spawnFn = opts.spawnFn || spawn;
  const hangDurationMs = opts.hangDurationMs || HANG_DURATION_MS;
  const progressIntervalMs = opts.progressIntervalMs || PROGRESS_CHECK_INTERVAL_MS;
  const launchConfirmMs = opts.launchConfirmMs || LAUNCH_CONFIRM_MS;

  if (activeHangs.has(key)) {
    log('BrowserHang', `[${accName}] 已有浏览器挂机在运行，跳过重复启动`, 'warning');
    return { ok: false, hangMinutes: 0, reason: 'already_running' };
  }
  // 互斥登记必须同步完成（在首个 await 之前），否则同账号并发调用会竞态穿透
  const entry = { proc: null, cancelled: false, wake: null };
  activeHangs.set(key, entry);
  installSignalCleanup();

  let browserProc = null;
  const procState = { exited: false, exitCode: null, error: null };

  try {
  log('BrowserHang', `[${accName}] 🌐 浏览器真挂机启动`, 'info');

  // 1. 检查今天是否已完成
  try {
    await client.refreshOfficialTasks();
    const hangTask = client.metrics.officialTasks?.find(t => t.name.includes('使用1小时'));
    if (hangTask && (hangTask.status === 2 || (hangTask.total > 0 && hangTask.current >= hangTask.total))) {
      log('BrowserHang', `[${accName}] 今日"使用1小时"任务已完成，跳过浏览器挂机`, 'info');
      return { ok: true, hangMinutes: 0, reason: 'already_completed' };
    }
    const curMin = hangTask ? Math.floor((hangTask.current || 0) / 60) : 0;
    log('BrowserHang', `[${accName}] 当前进度: ${curMin}/60 分钟`, 'info');
  } catch (e) {
    log('BrowserHang', `[${accName}] 读取任务进度失败: ${e.message}，继续执行挂机`, 'warning');
  }

  // 2. 获取目标桌面
  const desktops = client.account?.desktops || [];
  if (desktops.length === 0) {
    log('BrowserHang', `[${accName}] 未找到云电脑桌面，无法挂机`, 'error');
    return { ok: false, hangMinutes: 0, reason: 'no_desktop' };
  }
  const desktop = desktops[0];
  const desktopName = desktop.desktopName || desktop.name || '云电脑';

  // 3. 查找浏览器
  const browserPath = opts.browserPath || findBrowserPath();
  if (!browserPath) {
    log('BrowserHang', `[${accName}] 未找到 Chrome/Edge 浏览器，无法执行浏览器挂机`, 'error');
    return { ok: false, hangMinutes: 0, reason: 'no_browser' };
  }
  log('BrowserHang', `[${accName}] 使用浏览器: ${browserPath}`, 'info');

  // 4. 独立 profile 目录（按账号隔离）
  const userDataDir = profileDirFor(key);
  try {
    fs.mkdirSync(userDataDir, { recursive: true });
  } catch (e) {}

  const portalUrl = getWebPortalUrl(client, desktop);
  log('BrowserHang', `[${accName}][${desktopName}] 正在启动浏览器打开云电脑门户...`, 'info');

    try {
      browserProc = spawnFn(browserPath, [
        `--user-data-dir=${userDataDir}`,
        '--no-first-run',
        '--no-default-browser-check',
        '--disable-extensions',
        '--window-size=1280,800',
        portalUrl,
      ], {
        detached: true,
        stdio: 'ignore',
        windowsHide: false,
      });
    } catch (e) {
      log('BrowserHang', `[${accName}] 浏览器启动失败: ${e.message}`, 'error');
      return { ok: false, hangMinutes: 0, reason: 'launch_failed' };
    }
    entry.proc = browserProc;
    if (typeof browserProc.unref === 'function') browserProc.unref();

    // exit/close/error 全程监听（旧实现无任何监听，进程早退无感知）
    browserProc.on('exit', (code) => { procState.exited = true; procState.exitCode = code; if (entry.wake) entry.wake(); });
    browserProc.on('close', (code) => { procState.exited = true; if (procState.exitCode === null) procState.exitCode = code; });
    browserProc.on('error', (err) => { procState.error = err; });

    // 启动确认：等 'spawn' 事件，error 或超时无 pid 一律 launch_failed，
    // 不再像旧实现那样 spawn 调用不抛错就谎报"已启动"
    const launch = await waitForLaunch(browserProc, launchConfirmMs);
    if (!launch.ok) {
      log('BrowserHang', `[${accName}] 浏览器启动失败: ${launch.err ? launch.err.message : '未知错误'}`, 'error');
      return { ok: false, hangMinutes: 0, reason: 'launch_failed' };
    }
    if (entry.cancelled) {
      return { ok: false, hangMinutes: 0, reason: 'cancelled' };
    }
    log('BrowserHang', `[${accName}] 浏览器已启动 (PID: ${browserProc.pid})，开始挂机计时`, 'success');

    // 5. 挂机循环
    const startTime = Date.now();
    let completed = false;
    let anyProgressRead = false;

    while (Date.now() - startTime < hangDurationMs) {
      await interruptibleSleep(Math.min(progressIntervalMs, Math.max(0, hangDurationMs - (Date.now() - startTime))), entry);
      if (entry.cancelled) break;
      if (procState.exited) {
        log('BrowserHang', `[${accName}] 浏览器进程已退出 (code=${procState.exitCode})，挂机中断`, 'warning');
        break;
      }
      if (Date.now() - startTime >= hangDurationMs) break;

      const hangMinutes = Math.floor((Date.now() - startTime) / 60000);
      const remainMin = Math.ceil((hangDurationMs - (Date.now() - startTime)) / 60000);
      try {
        await client.refreshOfficialTasks();
        anyProgressRead = true;
        const hangTask = client.metrics.officialTasks?.find(t => t.name.includes('使用1小时'));
        if (hangTask) {
          const curSec = hangTask.current || 0;
          const curMin = Math.floor(curSec / 60);
          log('BrowserHang', `[${accName}] 挂机中: 已挂 ${hangMinutes} 分钟，官方进度 ${curMin}/60 分钟，剩余约 ${remainMin} 分钟`, 'info');
          if (hangTask.status === 2 || (hangTask.total > 0 && curSec >= hangTask.total)) {
            log('BrowserHang', `[${accName}] 🎉 官方确认"使用1小时"任务已完成！(+100积分)`, 'success');
            completed = true;
            break;
          }
        }
      } catch (e) {
        log('BrowserHang', `[${accName}] 进度检查失败: ${e.message}，继续挂机`, 'warning');
      }
    }

    const hangMinutes = Math.floor((Date.now() - startTime) / 60000);
    if (completed) {
      log('BrowserHang', `[${accName}] ✅ 浏览器真挂机完成：挂机 ${hangMinutes} 分钟，任务达成`, 'success');
      return { ok: true, hangMinutes, reason: 'task_completed' };
    }
    if (entry.cancelled) {
      log('BrowserHang', `[${accName}] 浏览器真挂机被取消：已挂 ${hangMinutes} 分钟`, 'warning');
      return { ok: false, hangMinutes, reason: 'cancelled' };
    }
    if (procState.exited) {
      return { ok: false, hangMinutes, reason: 'browser_exited' };
    }
    if (!anyProgressRead) {
      log('BrowserHang', `[${accName}] ❌ 挂机全程未能读取官方进度，结果不可确认`, 'error');
      return { ok: false, hangMinutes, reason: 'progress_check_failed' };
    }
    log('BrowserHang', `[${accName}] ⏰ 浏览器真挂机结束：挂机 ${hangMinutes} 分钟，官方未确认达成`, 'warning');
    return { ok: false, hangMinutes, reason: 'time_up_unconfirmed' };
  } finally {
    // 6. 清理：只关自己 spawn 的进程，注销登记
    if (browserProc && !procState.exited) {
      killOwnProcessTree(browserProc);
    }
    if (activeHangs.get(key) === entry) activeHangs.delete(key);
  }
}

module.exports = {
  executeBrowserHang,
  cancelBrowserHang,
  cancelAllBrowserHangs,
  getActiveBrowserHangs,
  HANG_DURATION_MS,
  findBrowserPath,
};
