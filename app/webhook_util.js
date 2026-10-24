/**
* Webhook 目标校验与安全发送（缺陷修复 G7）。
* 旧实现缺口：
* - 只校验主机名字面（IP/保留名），不解析 DNS：公网域名解析到内网/元数据
* 地址即可绕过（DNS rebinding 型 SSRF）。
* - fetch 默认跟随重定向且不逐跳校验：公网 URL 302 跳内网即直达。
* - 无超时：慢响应可长期挂住通知链路。
* - isValidWebhookTarget 不拒 URL 内嵌用户信息（user:pass@host）。
* - 飞书分支用原始 notify.webhookUrl 发送（带 @secret 后缀）而非拆分后的
* feishuUrl，与钉钉分支对照坐实为 bug（修复在 server.js sendNotification）。
* 残余风险（如实记录）：校验-连接之间存在 TOCTOU 窗口，彻底封堵需连接时
* IP 钉扎（自定义 agent 在 connect 阶段校验对端 IP），本轮未实施。
*/
const net = require('net');
const dns = require('dns');
const { URL} = require('url');

function isPrivateIpOrHost(hostname) {
const h = (hostname || '').toLowerCase().trim();
if (!h) return true;
if (h === 'localhost' || h === '127.0.0.1' || h === '::1' || h === '0.0.0.0') return true;
if (h.endsWith('.local') || h.endsWith('.internal') || h.endsWith('.lan')) return true;

if (net.isIPv4(h)) {
const parts = h.split('.').map(Number);
if (parts[0] === 127) return true; // 127.0.0.0/8 loopback
if (parts[0] === 10) return true; // 10.0.0.0/8 private
if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true; // 172.16.0.0/12 private
if (parts[0] === 192 && parts[1] === 168) return true; // 192.168.0.0/16 private
if (parts[0] === 169 && parts[1] === 254) return true; // 169.254.0.0/16 link-local / cloud metadata
if (parts[0] === 0) return true; // 0.0.0.0/8 current network
}

if (net.isIPv6(h)) {
if (h === '::1' || h === '::') return true;
if (h.startsWith('fe80:')) return true; // link-local
if (h.startsWith('fc00:') || h.startsWith('fd00:')) return true; // ULA
}

return false;
}

function isValidWebhookTarget(channel, rawTarget) {
if (!rawTarget || typeof rawTarget!== 'string') return false;
const target = rawTarget.trim();
if (!target) return false;

const ch = channel || 'webhook';
// Token 型推送渠道 (向平台官方公共 API 发送请求)
if (ch === 'serverchan' || ch === 'pushplus') {
return /^[\w\-]{6,128}$/.test(target);
}
if (ch === 'telegram') {
// 格式 botToken@chatId
return /^[\w\-:]+@[\w\-]+$/.test(target);
}

// 钉钉支持输入纯 access_token (32~128位字符)
if (ch === 'dingtalk' && /^[a-zA-Z0-9_\-]{32,128}$/.test(target)) {
return true;
}

// URL 型推送渠道 (webhook, qywx, dingtalk, feishu, bark)
try {
// 剥离可能附带的 @SEC... 密钥后缀以供 URL 校验
const checkUrl = target.split('@SEC')[0].trim();
const u = new URL(checkUrl);
if (u.protocol!== 'http:' && u.protocol!== 'https:') return false;
// 拒内嵌用户信息：user:pass@host 形式既可伪装主机也可把凭据带进日志
if (u.username || u.password) return false;
if (isPrivateIpOrHost(u.hostname)) return false;
return true;
} catch (e) {
return false;
}
}

const defaultLookup = (hostname) =>
dns.promises.lookup(hostname, { all: true, verbatim: true});

/**
* 解析主机名并逐个校验全部地址：任一地址为私有/保留即拒绝。
* IP 字面量直接校验。lookupFn 可注入（单测）。
*/
async function assertHostPublic(hostname, lookupFn = defaultLookup) {
const h = (hostname || '').toLowerCase().trim();
if (isPrivateIpOrHost(h)) {
throw new Error(`Webhook 目标主机不允许: ${hostname}`);
}
if (net.isIP(h)) return; // 公网 IP 字面量已由 isPrivateIpOrHost 排除私有段
let addresses;
try {
addresses = await lookupFn(h);
} catch (e) {
throw new Error(`Webhook 目标域名解析失败: ${hostname}`);
}
if (!addresses || addresses.length === 0) {
throw new Error(`Webhook 目标域名无解析结果: ${hostname}`);
}
for (const a of addresses) {
const ip = typeof a === 'string'? a: a.address;
if (isPrivateIpOrHost(ip)) {
throw new Error(`Webhook 目标解析到私有地址: ${hostname} -> ${ip}`);
}
}
}

/**
* 带 SSRF 复检的安全 fetch：每一跳（含重定向）都重新解析并校验目标，
* redirect:'manual' 逐跳处理（≤ maxRedirects），单请求超时 timeoutMs。
* fetchFn/lookupFn 可注入（单测用本地模拟服务）。
*/
async function safeFetchJson(urlString, {
method = 'POST',
headers = {},
body,
fetchFn = fetch,
lookupFn = defaultLookup,
timeoutMs = 10000,
maxRedirects = 3,
} = {}) {
let current = urlString;
for (let hop = 0; hop <= maxRedirects; hop++) {
let u;
try {
u = new URL(current);
} catch (e) {
throw new Error(`Webhook URL 非法: ${current}`);
}
if (u.protocol!== 'http:' && u.protocol!== 'https:') {
throw new Error(`Webhook 协议不允许: ${u.protocol}`);
}
if (u.username || u.password) {
throw new Error('Webhook URL 不得内嵌用户信息');
}
await assertHostPublic(u.hostname, lookupFn);

const controller = new AbortController();
const timer = setTimeout(() => controller.abort(), timeoutMs);
let res;
try {
res = await fetchFn(u.toString(), {
method,
headers,
body,
redirect: 'manual',
signal: controller.signal,
});
} finally {
clearTimeout(timer);
}

const isRedirect = res.status >= 300 && res.status < 400;
const location = isRedirect && res.headers && typeof res.headers.get === 'function'
? res.headers.get('location')
: null;
if (isRedirect && location) {
if (hop === maxRedirects) throw new Error('Webhook 重定向次数过多');
current = new URL(location, u).toString();
continue;
}
return res;
}
throw new Error('Webhook 重定向次数过多');
}

module.exports = {
isPrivateIpOrHost,
isValidWebhookTarget,
assertHostPublic,
safeFetchJson,
};
