// 天翼云电脑 GitHub Actions 版 - 完整任务
// 环境变量: CTYUN_USER, CTYUN_PASS

const crypto = require('crypto');
function md5(t) { return crypto.createHash('md5').update(t).digest('hex').toLowerCase(); }

const log = (tag, msg, level='info') => {
  console.log(`[${new Date().toISOString()}][${tag}][${level}] ${msg}`);
};

// 直接密码登录
async function directLogin(user, password) {
  const deviceCode = 'gh-action-' + md5(user).substring(0, 12);
  const body = new URLSearchParams({
    userAccount: user, password: password, deviceCode,
    deviceName: 'GitHub Actions', deviceType: '60',
    deviceModel: 'Linux x64', appVersion: '3.2.0',
    sysVersion: 'Linux x64', clientVersion: '103020001',
  });
  const res = await fetch('https://desk.ctyun.cn:8810/api/auth/client/login', {
    method: 'POST',
    headers: {
      'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) Chrome/137.0.0.0',
      'Content-Type': 'application/x-www-form-urlencoded',
      'referer': 'https://pc.ctyun.cn/',
      'ctg-devicetype': '60', 'ctg-version': '103020001', 'ctg-devicecode': deviceCode,
    },
    body: body.toString(),
  });
  const data = await res.json();
  if (data.code === 0 && data.data) {
    log('Login', '登录成功', 'success');
    return { loginInfo: data.data, deviceCode };
  }
  throw new Error(`登录失败: ${data.msg || data.code}`);
}

async function main() {
  const user = process.env.CTYUN_USER;
  const pass = process.env.CTYUN_PASS;
  if (!user || !pass) { console.error('缺少 CTYUN_USER / CTYUN_PASS'); process.exit(1); }

  try {
    // 1. 登录
    const { loginInfo, deviceCode } = await directLogin(user, pass);
    
    // 2. 构造 client（复用 dashboard 的 CtYunClient）
    const { CtYunClient } = require('./server.js');
    const acc = {
      id: 'gh-action', name: 'GitHub Actions', user, password: pass,
      platform: 'ctyun', enabled: true, deviceCode,
      savedLoginInfo: loginInfo,
      features: { keepAlive: true, autoSign: true, aiChat: true, cloudHang: true, autoRedeem: true },
      stats: {},
    };
    const client = new CtYunClient(acc);
    client.loginInfo = loginInfo;  // 预填登录态
    
    const { executeNativeSign, executeNativeAiChat, executeNativeHang } = require('./app/tasks/native_tasks.js');
    const onLog = (tag, msg, level) => log(tag, msg, level);

    // 3. 签到
    log('Main', '=== 签到 ===', 'info');
    try {
      const r = await executeNativeSign(client, acc, onLog);
      log('Main', `签到: ${r.success ? '成功' : '跳过/失败'}`, r.success ? 'success' : 'warning');
    } catch (e) { log('Main', `签到异常: ${e.message}`, 'error'); }

    // 4. AI问答
    log('Main', '=== AI问答 ===', 'info');
    try {
      const r = await executeNativeAiChat(client, acc, onLog);
      log('Main', `AI问答: ${r.success ? '成功' : '跳过/失败'}`, r.success ? 'success' : 'warning');
    } catch (e) { log('Main', `AI问答异常: ${e.message}`, 'error'); }

    // 5. 1小时挂机
    log('Main', '=== 1小时挂机 ===', 'info');
    try {
      const r = await executeNativeHang(client, acc, onLog);
      log('Main', `挂机: ${r.success ? '成功' : '跳过/失败'}`, r.success ? 'success' : 'warning');
    } catch (e) { log('Main', `挂机异常: ${e.message}`, 'error'); }

    log('Main', '全部完成', 'success');
  } catch (e) {
    log('Main', `失败: ${e.message}`, 'error');
    process.exit(1);
  }
}

main();
