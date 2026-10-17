/**
 * 浏览器真挂机模块 (Browser Real Hang)
 * 
 * 原理：用真实浏览器打开天翼云电脑网页版，保持会话 61 分钟，
 * 让官方按"会话在线时长"累积"使用1小时"任务进度。
 * 
 * 与 WebSocket 协议挂机的区别：
 * - WebSocket 挂机：纯协议，心跳包维持，轻量但可能被识别为非真实客户端
 * - 浏览器挂机：真实浏览器会话，与用户手动操作无异，更难被区分
 * 
 * 触发：每天凌晨 3:00 (browserHangCron: '0 3 * * *')，挂 61 分钟
 */

const { spawn, execSync } = require('child_process');
const path = require('path');
const fs = require('fs');
const os = require('os');

// 挂机时长：61 分钟（毫秒）
const HANG_DURATION_MS = 61 * 60 * 1000;
// 进度检查间隔：30 秒
const PROGRESS_CHECK_INTERVAL_MS = 30 * 1000;
// 任务完成的目标秒数
const TARGET_SECONDS = 3600;

/**
 * 查找可用的浏览器可执行文件路径 (Windows)
 * @returns {string|null} 浏览器路径，未找到返回 null
 */
function findBrowserPath() {
  const candidates = [
    // Chrome
    'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
    'C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe',
    // Edge
    'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
    'C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe',
  ];
  
  for (const p of candidates) {
    try {
      if (fs.existsSync(p)) return p;
    } catch (e) {}
  }
  
  // 尝试从注册表或 PATH 查找
  try {
    const chromePath = execSync('where chrome', { encoding: 'utf8', timeout: 5000 }).trim().split('\n')[0];
    if (chromePath && fs.existsSync(chromePath.trim())) return chromePath.trim();
  } catch (e) {}
  
  try {
    const edgePath = execSync('where msedge', { encoding: 'utf8', timeout: 5000 }).trim().split('\n')[0];
    if (edgePath && fs.existsSync(edgePath.trim())) return edgePath.trim();
  } catch (e) {}
  
  return null;
}

/**
 * 获取天翼云电脑网页版 URL
 * @param {object} client - CtYunClient 实例
 * @param {object} desktop - 桌面信息
 * @returns {string} 网页版 URL
 */
function getWebPortalUrl(client, desktop) {
  // 天翼云电脑网页版入口
  // 实际使用时，浏览器打开后用户需要手动选择桌面（或通过 URL 参数指定）
  const desktopId = desktop.objId || desktop.desktopId || '';
  // desk.ctyun.cn 是天翼云电脑的 Web 门户
  return `https://desk.ctyun.cn/web/?desktopId=${encodeURIComponent(desktopId)}`;
}

/**
 * 执行浏览器真挂机
 * @param {object} client - CtYunClient 实例（已登录）
 * @param {object} acc - 账号信息
 * @param {function} onLog - 日志回调 (src, msg, lvl)
 * @returns {Promise<object>} { ok, hangMinutes, reason }
 */
async function executeBrowserHang(client, acc, onLog) {
  const log = onLog || (() => {});
  const accName = acc.name || acc.username || '未知账号';
  
  log('BrowserHang', `[${accName}] 🌐 浏览器真挂机启动：每天 3:00，挂 61 分钟`, 'info');
  
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
  const browserPath = findBrowserPath();
  if (!browserPath) {
    log('BrowserHang', `[${accName}] 未找到 Chrome/Edge 浏览器，无法执行浏览器挂机`, 'error');
    return { ok: false, hangMinutes: 0, reason: 'no_browser' };
  }
  log('BrowserHang', `[${accName}] 使用浏览器: ${browserPath}`, 'info');
  
  // 4. 启动浏览器（独立用户数据目录，不干扰用户主浏览器）
  const userDataDir = path.join(os.tmpdir(), 'ctyun-browser-hang');
  try {
    if (!fs.existsSync(userDataDir)) fs.mkdirSync(userDataDir, { recursive: true });
  } catch (e) {}
  
  const portalUrl = getWebPortalUrl(client, desktop);
  log('BrowserHang', `[${accName}][${desktopName}] 正在启动浏览器打开云电脑门户...`, 'info');
  
  let browserProc = null;
  try {
    browserProc = spawn(browserPath, [
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
    browserProc.unref();
    log('BrowserHang', `[${accName}] 浏览器已启动 (PID: ${browserProc.pid})，开始 61 分钟挂机`, 'success');
  } catch (e) {
    log('BrowserHang', `[${accName}] 浏览器启动失败: ${e.message}`, 'error');
    return { ok: false, hangMinutes: 0, reason: 'browser_launch_failed' };
  }
  
  // 5. 挂机循环：每 30 秒检查一次进度
  const startTime = Date.now();
  let hangMinutes = 0;
  let completed = false;
  
  while (Date.now() - startTime < HANG_DURATION_MS) {
    await new Promise(r => setTimeout(r, PROGRESS_CHECK_INTERVAL_MS));
    
    hangMinutes = Math.floor((Date.now() - startTime) / 60000);
    const remainMin = Math.ceil((HANG_DURATION_MS - (Date.now() - startTime)) / 60000);
    
    // 检查官方任务进度
    try {
      await client.refreshOfficialTasks();
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
    
    // 检查浏览器进程是否还活着
    try {
      if (browserProc.pid) process.kill(browserProc.pid, 0); // 0 信号只检查存在性
    } catch (e) {
      log('BrowserHang', `[${accName}] 浏览器进程已退出，挂机中断`, 'warning');
      break;
    }
  }
  
  // 6. 关闭浏览器
  try {
    if (browserProc && browserProc.pid) {
      if (process.platform === 'win32') {
        execSync(`taskkill /PID ${browserProc.pid} /T /F`, { timeout: 10000 });
      } else {
        process.kill(browserProc.pid, 'SIGTERM');
      }
      log('BrowserHang', `[${accName}] 浏览器已关闭`, 'info');
    }
  } catch (e) {
    // 进程可能已经退出了，忽略
  }
  
  hangMinutes = Math.floor((Date.now() - startTime) / 60000);
  
  if (completed) {
    log('BrowserHang', `[${accName}] ✅ 浏览器真挂机完成：挂机 ${hangMinutes} 分钟，任务达成`, 'success');
  } else {
    log('BrowserHang', `[${accName}] ⏰ 浏览器真挂机结束：挂机 ${hangMinutes} 分钟（61 分钟到期）`, 'info');
  }
  
  return { ok: true, hangMinutes, reason: completed ? 'task_completed' : 'time_up' };
}

module.exports = { executeBrowserHang, HANG_DURATION_MS, findBrowserPath };
