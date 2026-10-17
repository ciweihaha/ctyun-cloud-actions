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

const crypto = require('crypto');
const { CtYunClient } = require('./server.js');
const { executeNativeSign, executeNativeAiChat, executeNativeHang } = require('./app/tasks/native_tasks.js');

const LOGIN_URL = 'https://desk.ctyun.cn:8810/api/auth/client/login';
const CHALLENGE_URL = 'https://desk.ctyun.cn:8810/api/auth/client/genChallengeData';

const onLog = (tag, msg, level = 'info') => {
  console.log(`[${new Date().toISOString()}][${tag}][${level}] ${msg}`);
};

function sha256(t) {
  return crypto.createHash('sha256').update(t).digest('hex').toLowerCase();
}

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
  if (!chal.json || chal.json.code !== 0 || !chal.json.data) {
    return { success: false, error: `获取 challenge 失败: HTTP ${chal.http} ${chal.json ? (chal.json.msg || '') : (chal.raw || '')}` };
  }
  const { challengeCode, challengeId } = chal.json.data;

  const body = new URLSearchParams({
    userAccount: acc.user,
    password: acc.password,
    sha256Password: sha256(sha256(acc.password) + challengeCode),
    challengeId: String(challengeId || ''),
    captchaCode: '',
    deviceCode,
    deviceName: 'Chrome浏览器',
    deviceType: '60',
    deviceModel: 'Windows NT 10.0; Win64; x64',
    appVersion: '3.2.0',
    sysVersion: 'Windows NT 10.0; Win64; x64',
    clientVersion: '103020001',
  });

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

  // —— 4. 自动兑换：暂不执行 ——
  // 原因：dashboard 的兑换是配置驱动的（acc.redeemConfig：商品 prodId、绑定机器、每月哪天兑），
  // Actions 环境没有这份配置，硬编码商品 ID 下单有误兑风险。待用户在 dashboard 配好兑换策略后，
  // 把 redeemConfig 以 JSON 形式加为 CTYUN_REDEEM Secret，再补上这一步。
  results.redeem = '跳过（需 dashboard 兑换配置，见文件头说明）';
  onLog('Main', '自动兑换：本次跳过（需要 dashboard 的 redeemConfig，硬编码下单有误兑风险）', 'warning');

  onLog('Main', `汇总: ${JSON.stringify(results)}`, 'success');
  process.exit(0);
}

main().catch(e => { console.error('Fatal:', e.message); process.exit(1); });
