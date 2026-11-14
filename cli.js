// 天翼云电脑 GitHub Actions 版 — cli.js v2（登录修复版）
// 环境变量: CTYUN_USER, CTYUN_PASS, 可选 CTYUN_SESSION（导出的 savedLoginInfo JSON）
//
// v2 修复了什么（2026-10-17 代码审查发现）：
// 旧 cli.js 直接调 client.login()，但 CtYunClient.login() 只有两条路——
//   (1) 内存里已有 savedLoginInfo（扫码 bootstrap 的会话）；
//   (2) 无感 renewToken() 续期。
// 全新 Actions 环境两条路都走不通，login() 必然返回
// "会话已过期，请在控制台输入验证码重新登录！" → 整个 workflow 直接 exit 1，
// 四个任务一个都跑不起来。v2 增加账号密码直登兜底：
// 先拿 genChallengeData 换 challenge，再调官方 api/auth/client/login。
// 用户已确认其账号登录不需要图形验证码，因此 captchaCode 传空尝试；
// 若官方返回要求验证码，脚本会明说原因并给出会话导出方案，而不是含糊报错。
//
// 注意：本文件只做了 node --check 语法检查与代码走读，真实登录未实测（无凭证）。

const { CtYunClient } = require('./server.js');
const { executeNativeSign, executeNativeAiChat, executeNativeHang } = require('./app/tasks/native_tasks.js');
const { executeRedeem, isRedeemRunAllowed } = require('./app/tasks/redeem_task.js');
// 深查第 12 轮：challenge 响应码用 task_center 的归一化判定（数字/字符串同义）。
// 旧实现 `chal.json.code !== 0` 只认数字，challenge 回 `{code:"0"}` 时整班
// 每日任务在登录第一步即 exit 1，签到/AI/挂机一个都跑不起来。
const { normalizeBusinessCode } = require('./app/task_center');

const LOGIN_URL = 'https://desk.ctyun.cn:8810/api/auth/client/login';
const CHALLENGE_URL = 'https://desk.ctyun.cn:8810/api/auth/client/genChallengeData';

const onLog = (tag, msg, level = 'info') => {
  console.log(`[${new Date().toISOString()}][${tag}][${level}] ${msg}`);
};

function genDeviceCode() {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let s = '';
  for (let i = 0; i < 32; i++) s += chars.charAt(Math.floor(Math.random() * chars.length));
  return 'web_' + s;
}

function mask(s, keep = 4) {
  s = String(s || '');
  return s.length <= keep ? '****' : s.slice(0, keep) + '****';
}

async function fetchJson(url, options = {}, timeoutMs = 30000) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(url, { ...options, signal: ctrl.signal });
    const text = await res.text();
    try { return { http: res.status, json: JSON.parse(text) }; }
    catch { return { http: res.status, json: null, raw: text.slice(0, 300) }; }
  } finally { clearTimeout(t); }
}

// 会话优先：CTYUN_SESSION（导出的 savedLoginInfo）→ login() 静默续期，全程无头可跑
async function loginWithSession(client) {
  const raw = process.env.CTYUN_SESSION;
  if (!raw) return { tried: false };
  let sess;
  try { sess = JSON.parse(raw); } catch (e) {
    return { tried: true, success: false, error: 'CTYUN_SESSION 不是合法 JSON' };
  }
  client.loginInfo = sess;
  const r = await client.login();
  return { tried: true, success: !!r.success, error: r.error };
}

// 账号密码直登：challenge → login（captchaCode 为空；用户确认其账号免验证码）
async function loginWithPassword(client, acc, onLog) {
  const deviceCode = acc.deviceCode;
  const headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/137.0.0.0',
    'ctg-devicetype': '60',
    'ctg-version': '103020001',
    'ctg-devicecode': deviceCode,
    'referer': 'https://pc.ctyun.cn/',
    'Content-Type': 'application/x-www-form-urlencoded',
  };

  onLog('Login', '正在获取登录 challenge...', 'info');
  const chal = await fetchJson(CHALLENGE_URL, {
    method: 'POST',
    headers: { ...headers, 'Content-Type': 'application/json' },
    body: '{}',
  });
  if (!chal.json || normalizeBusinessCode(chal.json.code) !== 0 || !chal.json.data) {
    return { success: false, error: `获取 challenge 失败: HTTP ${chal.http} ${chal.json ? (chal.json.msg || '') : (chal.raw || '')}` };
  }
  const { challengeCode, challengeId } = chal.json.data;

  onLog('Login', `正在用账号密码登录 (${mask(acc.user)})...`, 'info');
  // 直接复用 dashboard 的真实实现（server.js loginWithCaptcha），captchaCode 传空——
  // 用户已确认其账号登录不需要图形验证码；若官方要求，返回的 code/msg 会明说。
  const lr = await client.loginWithCaptcha('', String(challengeId || ''), String(challengeCode || ''));
  if (lr && lr.success) return { success: true };
  const msg = (lr && (lr.error || lr.msg)) || '未知错误';
  const code = (lr && lr.code) || '';
  return { success: false, error: `账号密码登录被拒 (code=${code}): ${msg}` };
}

async function main() {
  const user = process.env.CTYUN_USER;
  const pass = process.env.CTYUN_PASS;
  if (!user || !pass) {
    console.error('缺少 CTYUN_USER / CTYUN_PASS（去仓库 Settings → Secrets → Actions 添加）');
    process.exit(1);
  }

  const acc = {
    id: 'gh-action', name: 'GitHub Actions', user, password: pass,
    platform: 'ctyun', enabled: true,
    deviceCode: genDeviceCode(),
    features: { keepAlive: true, autoSign: true, aiChat: true, cloudHang: true, autoRedeem: true },
    stats: {},
  };

  const client = new CtYunClient(acc);
  const results = {};

  // —— 登录：会话优先，密码兜底 ——
  let loggedIn = false;
  const sess = await loginWithSession(client).catch(e => ({ tried: true, success: false, error: e.message }));
  if (sess.tried) {
    onLog('Login', sess.success ? 'CTYUN_SESSION 会话续期成功' : `会话登录失败: ${sess.error}，转账号密码直登`, sess.success ? 'success' : 'warning');
    loggedIn = !!sess.success;
  }
  if (!loggedIn) {
    const pw = await loginWithPassword(client, acc, onLog).catch(e => ({ success: false, error: e.message }));
    if (pw.success) {
      onLog('Login', '账号密码直登成功', 'success');
      loggedIn = true;
    } else {
      onLog('Login', `登录失败: ${pw.error}`, 'error');
      onLog('Login', '可能原因：官方要求图形验证码（Actions 无头跑不过）。替代方案：在天翼云电脑的 dashboard 上确认会话有效后，把 data/ 目录里的 savedLoginInfo 导出为 CTYUN_SESSION Secret，再跑一次。', 'error');
      process.exit(1);
    }
  }

  // —— 1. 签到（真实原生实现） ——
  try {
    const r = await executeNativeSign(client, acc, onLog);
    results.sign = r.isCompleted ? '已完成' : (r.pendingVerify ? '待官方确认' : (r.message || '跳过'));
  } catch (e) { results.sign = `异常: ${e.message}`; onLog('Main', `签到异常: ${e.message}`, 'error'); }

  // —— 2. AI 问答（真实原生实现） ——
  try {
    const r = await executeNativeAiChat(client, acc, onLog);
    results.aiChat = r.success ? 'OK' : (r.message || '跳过');
  } catch (e) { results.aiChat = `异常: ${e.message}`; onLog('Main', `AI问答异常: ${e.message}`, 'error'); }

  // —— 3. 1 小时挂机（真实原生实现；WebSocket 长连，GitHub runner 连 desk.ctyun.cn 若不通会自动重连/跳过） ——
  try {
    const r = await executeNativeHang(client, acc, onLog);
    results.hang = r.isCompleted ? '今日已满1小时' : (r.message || '已调度');
  } catch (e) { results.hang = `异常: ${e.message}`; onLog('Main', `挂机异常: ${e.message}`, 'error'); }

  // —— 4. 自动兑换（配置驱动；无 CTYUN_REDEEM Secret 时跳过） ——
  // 配置来源：GitHub Secrets 的 CTYUN_REDEEM（redeemConfig JSON，见 README）。
  // 无 Secret / JSON 非法 / 未到兑换日 / 积分不足时均跳过，不下单、不报错退出，
  // 其他三项任务的结果不受影响。编排与下单复用 app/tasks/redeem_task.js 与
  // redeem_order.attemptRedeemOrder（S11 安全重试口径），此处不写下单逻辑。
  try {
    const rawRedeem = process.env.CTYUN_REDEEM;
    if (!rawRedeem || !rawRedeem.trim()) {
      results.redeem = '跳过（未配置 CTYUN_REDEEM Secret）';
      onLog('Redeem', '自动兑换跳过：未配置 CTYUN_REDEEM Secret（redeemConfig JSON），其他任务不受影响', 'warning');
    } else {
      let redeemConfig = null;
      try { redeemConfig = JSON.parse(rawRedeem); } catch (e) { redeemConfig = null; }
      if (!redeemConfig || typeof redeemConfig !== 'object' || Array.isArray(redeemConfig)) {
        results.redeem = '跳过（CTYUN_REDEEM 不是合法 JSON 对象）';
        onLog('Redeem', '自动兑换跳过：CTYUN_REDEEM 不是合法 JSON 对象', 'error');
      } else if (!isRedeemRunAllowed(process.env.GITHUB_EVENT_NAME, new Date().getUTCHours())) {
        // 防同一天重复兑换：daily.yml 每天跑两班（08:00 / 20:00 CST），而 Actions
        // 无持久化配置，lastRedeemDate 写不回去；只允许早班（UTC 0 点）执行兑换。
        results.redeem = '跳过（晚班不执行兑换，防同一天重复下单）';
        onLog('Redeem', '自动兑换跳过：本次为晚班（20:00）定时跑，兑换只在早班（08:00）执行，防同一天重复下单', 'info');
      } else {
        const r = await executeRedeem(client, acc, redeemConfig, onLog);
        if (r.status === 'success') results.redeem = r.message;
        else if (r.status === 'completed') results.redeem = '今日已兑换';
        else if (r.status === 'skipped') results.redeem = `跳过（${r.message}）`;
        else if (r.status === 'unknown') results.redeem = `结果不明确：${r.message}`;
        else if (r.status === 'risk_blocked') results.redeem = `已中止：${r.message}`;
        else results.redeem = `失败：${r.message}`;
      }
    }
  } catch (e) { results.redeem = `异常: ${e.message}`; onLog('Redeem', `自动兑换异常: ${e.message}`, 'error'); }

  onLog('Main', `汇总: ${JSON.stringify(results)}`, 'success');
  process.exit(0);
}

main().catch(e => { console.error('Fatal:', e.message); process.exit(1); });
