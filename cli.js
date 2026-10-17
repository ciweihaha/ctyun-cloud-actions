// 天翼云电脑 GitHub Actions 版
// 环境变量: CTYUN_USER, CTYUN_PASS

const { CtYunClient } = require('./server.js');
const { executeNativeSign, executeNativeAiChat, executeNativeHang } = require('./app/tasks/native_tasks.js');

const onLog = (tag, msg, level='info') => {
  console.log(`[${new Date().toISOString()}][${tag}][${level}] ${msg}`);
};

async function main() {
  const user = process.env.CTYUN_USER;
  const pass = process.env.CTYUN_PASS;
  if (!user || !pass) {
    console.error('缺少 CTYUN_USER / CTYUN_PASS');
    process.exit(1);
  }

  const acc = {
    id: 'gh-action', name: 'GitHub Actions', user, password: pass,
    platform: 'ctyun', enabled: true,
    features: { keepAlive: true, autoSign: true, aiChat: true, cloudHang: true, autoRedeem: true },
    stats: {},
  };

  const client = new CtYunClient(acc);
  
  onLog('Main', '正在登录...', 'info');
  const loginRes = await client.login();
  if (!loginRes.success) {
    onLog('Main', `登录失败: ${loginRes.error}`, 'error');
    process.exit(1);
  }
  onLog('Main', '登录成功', 'success');

  // 1. 签到
  try {
    const r = await executeNativeSign(client, acc, onLog);
    onLog('Main', `签到: ${r.success ? 'OK' : '跳过'}`, 'info');
  } catch (e) { onLog('Main', `签到异常: ${e.message}`, 'error'); }

  // 2. AI问答
  try {
    const r = await executeNativeAiChat(client, acc, onLog);
    onLog('Main', `AI问答: ${r.success ? 'OK' : '跳过'}`, 'info');
  } catch (e) { onLog('Main', `AI问答异常: ${e.message}`, 'error'); }

  // 3. 1小时挂机
  try {
    const r = await executeNativeHang(client, acc, onLog);
    onLog('Main', `挂机: ${r.success ? 'OK' : '跳过'}`, 'info');
  } catch (e) { onLog('Main', `挂机异常: ${e.message}`, 'error'); }

  onLog('Main', '全部完成', 'success');
  process.exit(0);
}

main().catch(e => { console.error('Fatal:', e.message); process.exit(1); });
