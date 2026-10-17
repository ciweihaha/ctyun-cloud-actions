// 天翼云电脑 GitHub Actions 版 - 直接密码登录（无验证码）
const crypto = require('crypto');
const WebSocket = require('ws');

function md5(t) { return crypto.createHash('md5').update(t).digest('hex').toLowerCase(); }
function sha256(t) { return crypto.createHash('sha256').update(t).digest('hex').toLowerCase(); }

const log = (tag, msg, level='info') => {
  console.log(`[${new Date().toISOString()}][${tag}][${level}] ${msg}`);
};

// 直接密码登录（不带验证码）
async function directLogin(user, password) {
  const deviceCode = 'gh-action-' + md5(user).substring(0, 12);
  const body = new URLSearchParams({
    userAccount: user,
    password: password,
    deviceCode: deviceCode,
    deviceName: 'GitHub Actions',
    deviceType: '60',
    deviceModel: 'Linux x64',
    appVersion: '3.2.0',
    sysVersion: 'Linux x64',
    clientVersion: '103020001',
  });
  
  const res = await fetch('https://desk.ctyun.cn:8810/api/auth/client/login', {
    method: 'POST',
    headers: {
      'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) Chrome/137.0.0.0',
      'Content-Type': 'application/x-www-form-urlencoded',
      'referer': 'https://pc.ctyun.cn/',
      'ctg-devicetype': '60',
      'ctg-version': '103020001',
      'ctg-devicecode': deviceCode,
    },
    body: body.toString(),
  });
  
  const data = await res.json();
  log('Login', `登录接口返回 code=${data.code}`, 'info');
  
  if (data.code === 0 && data.data) {
    log('Login', '登录成功', 'success');
    return data.data;
  }
  throw new Error(`登录失败: ${data.msg || 'code=' + data.code}`);
}

async function main() {
  const user = process.env.CTYUN_USER;
  const pass = process.env.CTYUN_PASS;
  if (!user || !pass) {
    console.error('缺少 CTYUN_USER / CTYUN_PASS');
    process.exit(1);
  }

  try {
    const loginInfo = await directLogin(user, pass);
    log('Main', `Token 获取成功，用户ID: ${loginInfo.userId || 'unknown'}`, 'success');
    
    // TODO: 签到、AI问答、挂机逻辑（需补充完整API）
    log('Main', '登录验证通过，完整任务逻辑待补充', 'warning');
    
  } catch (e) {
    log('Main', `失败: ${e.message}`, 'error');
    process.exit(1);
  }
}

main();
