/**
* 自动兑换（GitHub Actions 复用版）——供 cli.js 调用。
*
* 口径与 dashboard 的 scheduler.js 内联自动兑换块一致（日期判定 / 绑定机器 /
* 积分预检 / 报文组装），下单与重试收敛至 redeem_order.attemptRedeemOrder
* （缺陷修复 S11：明确业务错误才有限重试；网络异常等结果不明确的情况绝不
* 盲目重试，防止「服务端已受理但响应丢失」被重试成重复扣积分）。本文件不重写
* 下单逻辑，只做编排；也不实例化 TaskScheduler（它绑定 dashboard 的
* getAccounts/getSettings/saveConfig/通知 wiring，Actions 环境不需要）。
*
* Actions 环境与 dashboard 的关键差异：
* - 持久化靠仓库根目录的 redeem-state.json：兑换成功后 cli.js 把当天日期
* 写进该文件，daily.yml 再把它 commit 推回 main 分支；下次跑先读文件里的
* lastRedeemDate 覆盖 Secret 里的同字段。GitHub Actions 无法更新 Secret，
* 所以日期不走 Secret 回写。isRedeemRunAllowed 的早班限流仍保留做兜底
* （万一回写推不上去，晚班也不会在同一天再兑一次）。
* - 积分取 client.metrics.userPoints（executeNativeSign 开头已调
* refreshOfficialTasks 刷新）；取不到（0）时不做预检，交给服务端判定，
* 与 dashboard 手动下单接口（server.js /api/accounts/:id/order）同口径。
*/

const { attemptRedeemOrder} = require('./redeem_order');
const fs = require('fs');
const path = require('path');

const PLACE_ORDER_URL = 'https://desk.ctyun.cn/selforder/api/selforder/paas/placeOrder';

// 与 scheduler.js / server.js rewardNeedsDesktop 同口径的需绑定云电脑商品。
const DESKTOP_BOUND_PROD_IDS = [17023101, 17023111, 17024101, 17026101, 17026111];
const DESKTOP_BOUND_PROD_TYPES = ['pointstplupgrade', 'pointsdiskupgrade'];

function getBeijingDateStr() {
const d = new Date();
return d.toLocaleDateString('sv-SE', { timeZone: 'Asia/Shanghai'});
}

// 兑换日期状态文件：仓库根目录 redeem-state.json，内容 {"lastRedeemDate": "YYYY-MM-DD"}。
// 它是 lastRedeemDate 的唯一事实来源：cli.js 每次跑先读它覆盖 Secret 里的同字段，
// 兑换成功后把当天日期写回，daily.yml 再把文件变化 commit 推回 main 分支。
const REDEEM_STATE_FILENAME = 'redeem-state.json';

// 默认状态文件路径：本文件在 app/tasks/，上两级即仓库根目录。
function defaultRedeemStatePath() {
return path.join(__dirname, '..', '..', REDEEM_STATE_FILENAME);
}

/**
* 读兑换状态文件。文件不存在 / JSON 非法 / 不是对象时返回 null（调用方沿用 Secret 的值）。
* 绝不抛错。
*/
function readRedeemState(statePath) {
const p = statePath || defaultRedeemStatePath();
try {
const data = JSON.parse(fs.readFileSync(p, 'utf8'));
if (data && typeof data === 'object' && !Array.isArray(data)) return data;
return null;
} catch {
return null;
}
}

/**
* 把状态文件里的 lastRedeemDate 合并进 redeemConfig（返回新对象，不改原配置）。
* 文件里的日期优先；文件不存在/不合法、或文件里没记日期（空串）时沿用 Secret 的值。
* 空串视为“没记过”：只在首次部署、文件还是初始值时才出现，此时 Secret 里若有人
* 工填过的日期应继续生效，避免同一天重复兑换。
*/
function applyRedeemState(redeemConfig, statePath) {
const merged = { ...(redeemConfig || {}) };
const state = readRedeemState(statePath);
if (state && typeof state.lastRedeemDate === 'string' && state.lastRedeemDate) {
merged.lastRedeemDate = state.lastRedeemDate;
}
return merged;
}

/**
* 把日期写回状态文件。写失败只记一条警告并返回 false，绝不抛错、不影响兑换结果判定。
*/
function writeRedeemState(dateStr, statePath, onLog) {
const p = statePath || defaultRedeemStatePath();
try {
fs.writeFileSync(p, JSON.stringify({ lastRedeemDate: dateStr }) + '\n', 'utf8');
return true;
} catch (e) {
if (typeof onLog === 'function') onLog('Redeem', `回写 ${REDEEM_STATE_FILENAME} 失败（不影响本次兑换结果）: ${e.message}`, 'warning');
return false;
}
}

/**
* 日期判定，与 scheduler.js isRedeemDueToday 同口径。
* scheduleType: 'daily'（每天）/ 'interval_days'（间隔天数）/ 'monthly_days'（默认，
* monthlyDays 数组，-1 代表月末最后一天）。lastRedeemDate 当天已兑过返回 false。
*/
function isRedeemDueToday(rConf, todayStr) {
if (!rConf ||!rConf.prodId) return false;
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
const days = Array.isArray(rConf.monthlyDays)? rConf.monthlyDays: [-1];
return days.includes(cstDay) || (days.includes(-1) && cstDay === lastDayOfMonth);
}

function rewardNeedsDesktop(prodId, prodType) {
if (DESKTOP_BOUND_PROD_IDS.includes(Number(prodId))) return true;
return DESKTOP_BOUND_PROD_TYPES.includes(String(prodType || '').toLowerCase().trim());
}

/**
* Actions 两班限流：定时跑只允许早班执行兑换，防同一天重复下单。
* @param {string|undefined} eventName - process.env.GITHUB_EVENT_NAME
* （'schedule' 为定时，'workflow_dispatch' 为手动触发，未设置视为本地运行）
* @param {number} utcHour - new Date().getUTCHours()（08:00 CST = UTC 0 点）
*/
function isRedeemRunAllowed(eventName, utcHour) {
if (eventName === 'schedule') return utcHour === 0;
return true;
}

/**
* 执行一次自动兑换。
* @param {object} client - CtYunClient（已登录；metrics.userPoints 由签到步骤刷新）
* @param {object} acc - 账号对象（features.autoRedeem / stats）
* @param {object} redeemConfig - CTYUN_REDEEM 解析后的 redeemConfig JSON
* @param {function} onLog - (tag, msg, level) => void
* @param {object} [opts] - 测试注入：{ fetchFn, todayStr}
* @returns {Promise<{status:'success'|'failed'|'unknown'|'risk_blocked'|'skipped'|'completed', message:string, costPoints?:number, times?:number, prodName?:string}>}
*/
async function executeRedeem(client, acc, redeemConfig, onLog = console.log, opts = {}) {
const accName = (acc && (acc.name || acc.user)) || '账号';
const rConf = redeemConfig || {};
const todayStr = opts.todayStr || getBeijingDateStr();

if (acc && acc.features && acc.features.autoRedeem === false) {
return { status: 'skipped', message: '账号已关闭 autoRedeem'};
}
if (!rConf.prodId ||!(Number(rConf.costPoints) > 0)) {
return { status: 'skipped', message: '兑换配置不完整（缺少 prodId 或 costPoints）'};
}
if (rConf.enabled === false) {
return { status: 'skipped', message: '兑换配置 enabled=false'};
}
if (rConf.lastRedeemDate === todayStr) {
onLog('Redeem', `[${accName}] 今日自动兑换已完成，跳过重复执行。`, 'info');
return { status: 'completed', message: '今日已兑换'};
}
if (!isRedeemDueToday(rConf, todayStr)) {
return { status: 'skipped', message: `今日未到兑换日（策略 ${rConf.scheduleType || 'monthly_days'}）`};
}

const prodType = rConf.prodType || 'pointstplupgrade';
const prodName = rConf.prodName || String(rConf.prodId);
const needsDesktop = rewardNeedsDesktop(rConf.prodId, prodType);
const targetDesktopId =
parseInt(rConf.desktopId) ||
parseInt(client && client.metrics && client.metrics.desktopId) ||
parseInt(acc && acc.stats && acc.stats.desktopId) ||
0;
if (needsDesktop &&!targetDesktopId) {
onLog('Redeem', `[${accName}] 自动兑换跳过: 该商品必须绑定云电脑，但未提供 desktopId（也未从账号/会话中找到有效设备）`, 'warning');
return { status: 'skipped', message: '需绑定云电脑但无有效 desktopId'};
}

const buyTimes = Math.max(1, parseInt(rConf.maxRedeemTimes) || 1);
const totalCost = Number(rConf.costPoints) * buyTimes;

// 积分预检：与 dashboard 手动下单接口同口径——只有积分已知（>0）且不足时才跳过；
// 取不到积分时不预检，交给服务端判定（积分不足是致命业务错误，不会重试）。
const cachedPts = (client && client.metrics && client.metrics.userPoints) || (acc && acc.stats && acc.stats.points) || 0;
if (cachedPts > 0 && cachedPts < totalCost) {
onLog('Redeem', `[${accName}] 自动兑换跳过: 积分不足，当前拥有 ${cachedPts} 积分，本次兑换需要 ${totalCost} 积分`, 'warning');
return { status: 'skipped', message: `积分不足：拥有 ${cachedPts}，需要 ${totalCost}`};
}

const orderAttrs = needsDesktop
? [{ attrKey: 'bindDesktopId', attrVal: Number(targetDesktopId)}]
: [{ attrKey: 'mobilephone'}];
const payload = {
busiChannel: '010',
orderType: 1,
pointType: Number(rConf.pointType) || 1,
points: totalCost,
sku: [{
execSort: 1,
prodId: Number(rConf.prodId),
prodType,
attrs: orderAttrs,
}],
};

onLog('Redeem', `[${accName}] 命中兑换日，准备自动下单兑换x${buyTimes}，总计 ${totalCost} 积分...`, 'info');
const orderResult = await attemptRedeemOrder({
fetchFn: opts.fetchFn || ((u, init) => fetch(u, init)),
url: PLACE_ORDER_URL,
headers: client.getSignedHeaders({ 'Content-Type': 'application/json;charset=UTF-8'}),
payload,
maxBusinessRetries: 3,
onAttempt: (attempt, info) => {
if (info.phase === 'retry') {
onLog('Redeem', `[${accName}] 正在进行第 ${attempt}/3 次自动重试（上次为明确业务失败）...`, 'info');
} else if (info.phase === 'business_error') {
onLog('Redeem', `[${accName}] 第 ${attempt} 次自动兑换未成功: ${info.msg}`, 'warning');
}
},
});

if (orderResult.status === 'success') {
onLog('Redeem', `[${accName}] ✅ 成功完成x${buyTimes} 自动兑换，共消耗 ${totalCost} 积分！`, 'success');
// lastRedeemDate 的回写由 cli.js 做（writeRedeemState 写 redeem-state.json，
// daily.yml 再推回仓库）；这里只返回成功状态，不碰文件。
return { status: 'success', message: `成功兑换x${buyTimes}，共消耗 ${totalCost} 积分`, costPoints: totalCost, times: buyTimes, prodName};
}
if (orderResult.status === 'risk_blocked') {
onLog('Redeem', `[${accName}] 自动兑换触发风控已自动中止: ${orderResult.msg}`, 'error');
return { status: 'risk_blocked', message: `触发风控已中止: ${orderResult.msg}`};
}
if (orderResult.status === 'unknown') {
onLog('Redeem', `[${accName}] ⚠️ 自动兑换结果不明确（已停止重试以防重复下单）: ${orderResult.msg}。请人工核对订单与积分变动。`, 'error');
return { status: 'unknown', message: `结果不明确（可能已受理），请人工核对订单与积分变动: ${orderResult.msg}`};
}
onLog('Redeem', `[${accName}] 自动兑换失败: ${orderResult.msg}`, 'error');
return { status: 'failed', message: orderResult.msg};
}

module.exports = { executeRedeem, isRedeemDueToday, isRedeemRunAllowed, rewardNeedsDesktop, getBeijingDateStr, readRedeemState, applyRedeemState, writeRedeemState };
