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
*
* 本轮追加修复（fix/webhook-body-timeout-20261024）：
* - 旧 safeFetchJson 在 fetch() 返回响应头后即 clearTimeout，调用方随后
* res.json() 读取响应体脱离超时保护，body 永不结束时可无限挂起。现改为
* 单个总超时覆盖 DNS/建连/响应头/重定向/响应体读取/JSON 解析全程，
* 函数内读完 body（上限 1MB）才返回同形对象，调用方不再二次读网络响应。
* - 安全拦截日志与 URL 非法报错曾拼接完整 webhookUrl（路径令牌、query、
* @secret 均可入日志），统一改为 redactUrlForLog 脱敏后输出。
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
* 日志/报错脱敏：Webhook 目标常把机器人令牌放在路径段（飞书 hook/<token>、
* Bark /<device_key>）、query（钉钉 access_token、企业微信 key）里，或带
* @SEC/@secret 后缀、URL 内嵌 userinfo。脱敏结果只保留协议＋主机名，
* 路径、query、userinfo、后缀一律抹除；非 URL 形态（纯 token、
* telegram 的 botToken@chatId）整体抹除。日志里只应出现此函数的输出。
*/
function redactUrlForLog(raw) {
if (!raw || typeof raw!== 'string') return '(未配置)';
const s = raw.trim();
if (!s) return '(未配置)';
try {
const u = new URL(s);
if (u.protocol === 'http:' || u.protocol === 'https:') {
return `${u.protocol}//${u.host}/***`;
}
} catch (e) { /* 非 URL 形态：整体抹除 */ }
return '***';
}

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
* 响应体上限：Webhook 渠道的响应都是小 JSON（errcode/errmsg 级别，通常
* <1KB），1MB 留了三个数量级余量，同时封堵“响应体无限大/永不结束”对
* 内存与通知链路的占用。
*/
const WEBHOOK_MAX_BODY_BYTES = 1024 * 1024;

/**
* 让 promise 与 AbortSignal 竞速：即使注入的 fetchFn/读取实现忽略 signal，
* 总超时一到也立刻以超时错误拒绝（真正的资源释放靠 signal 传播给底层）。
*/
function raceWithAbort(promise, signal, timeoutError) {
if (signal.aborted) return Promise.reject(timeoutError());
return Promise.race([
promise,
new Promise((_, reject) => {
signal.addEventListener('abort', () => reject(timeoutError()), { once: true });
}),
]);
}

/**
* 流式读取响应体并累计字节数：超过 maxBodyBytes 立即 cancel 并报错；
* 每次 read 都与总超时竞速，body 永不结束时不会无限等待。
*/
async function readStreamText(stream, signal, maxBodyBytes, timeoutError) {
const reader = stream.getReader();
const chunks = [];
let total = 0;
try {
for (;;) {
const { done, value } = await raceWithAbort(reader.read(), signal, timeoutError);
if (done) break;
if (value && value.byteLength) {
total += value.byteLength;
if (total > maxBodyBytes) {
try { await reader.cancel(); } catch (e) {}
const err = new Error(`Webhook 响应体超过上限（${maxBodyBytes} 字节）`);
err.code = 'WEBHOOK_BODY_TOO_LARGE';
throw err;
}
chunks.push(Buffer.from(value));
}
}
} catch (e) {
try { reader.cancel().catch(() => {}); } catch (err) {}
throw e;
} finally {
try { reader.releaseLock(); } catch (e) {}
}
return Buffer.concat(chunks).toString('utf8');
}

/**
* 在总超时保护内读完响应体并尝试 JSON 解析，返回 { data, text, error }：
* - 超时（含 body 挂起）与超限是硬失败，直接抛出；
* - 普通读取/解析错误不抛，存入 error 并由返回值的 json() 重演拒绝，
* 保持调用方既有的 `res.json().catch(() => ({}))` 兜底语义不变。
*/
async function readAndParseBody(res, signal, maxBodyBytes, timeoutError) {
let text;
if (res.body && typeof res.body.getReader === 'function') {
text = await readStreamText(res.body, signal, maxBodyBytes, timeoutError);
} else if (typeof res.text === 'function') {
try {
text = await raceWithAbort(res.text(), signal, timeoutError);
} catch (e) {
if (signal.aborted) throw timeoutError();
return { data: undefined, text: undefined, error: e };
}
if (typeof text === 'string' && Buffer.byteLength(text, 'utf8') > maxBodyBytes) {
const err = new Error(`Webhook 响应体超过上限（${maxBodyBytes} 字节）`);
err.code = 'WEBHOOK_BODY_TOO_LARGE';
throw err;
}
} else if (typeof res.json === 'function') {
try {
const data = await raceWithAbort(res.json(), signal, timeoutError);
return { data, text: undefined, error: null };
} catch (e) {
if (signal.aborted) throw timeoutError();
return { data: undefined, text: undefined, error: e };
}
} else {
text = '';
}
try {
return { data: JSON.parse(text), text, error: null };
} catch (e) {
return { data: undefined, text, error: e };
}
}

/**
* 带 SSRF 复检的安全 fetch：每一跳（含重定向）都重新解析并校验目标，
* redirect:'manual' 逐跳处理（≤ maxRedirects）。
* 【总超时语义】单个 timeoutMs 预算覆盖全程：DNS 校验、建连、响应头、
* 全部重定向跳以及最终响应体的读取与 JSON 解析——AbortController 在
* body 读完/解析完后才解除。旧实现在 fetch() 返回响应头后即 clearTimeout，
* 调用方随后 res.json() 脱离保护，body 永不结束时可无限挂起，本轮已修正：
* 函数内部读完 body 后才返回，返回值是与 Response 同形的对象
* （status/ok/headers/json()/text()），json() 直接给出已解析结果，
* 调用方不得、也不需要再对真实网络响应做二次读取。
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
maxBodyBytes = WEBHOOK_MAX_BODY_BYTES,
} = {}) {
const controller = new AbortController();
const timeoutError = () => new Error(`Webhook 请求总超时（${timeoutMs}ms，含响应体读取）`);
const timer = setTimeout(() => controller.abort(), timeoutMs);
try {
let current = urlString;
for (let hop = 0; hop <= maxRedirects; hop++) {
let u;
try {
u = new URL(current);
} catch (e) {
throw new Error(`Webhook URL 非法: ${redactUrlForLog(current)}`);
}
if (u.protocol!== 'http:' && u.protocol!== 'https:') {
throw new Error(`Webhook 协议不允许: ${u.protocol}`);
}
if (u.username || u.password) {
throw new Error('Webhook URL 不得内嵌用户信息');
}
await raceWithAbort(assertHostPublic(u.hostname, lookupFn), controller.signal, timeoutError);

const res = await raceWithAbort(fetchFn(u.toString(), {
method,
headers,
body,
redirect: 'manual',
signal: controller.signal,
}), controller.signal, timeoutError);

const isRedirect = res.status >= 300 && res.status < 400;
const location = isRedirect && res.headers && typeof res.headers.get === 'function'
? res.headers.get('location')
: null;
if (isRedirect && location) {
if (hop === maxRedirects) throw new Error('Webhook 重定向次数过多');
// 重定向响应的 body 不再使用，主动 cancel 以便连接尽早释放
try { if (res.body && typeof res.body.cancel === 'function') await res.body.cancel(); } catch (e) {}
current = new URL(location, u).toString();
continue;
}

const parsed = await readAndParseBody(res, controller.signal, maxBodyBytes, timeoutError);
return {
status: res.status,
ok: typeof res.ok === 'boolean' ? res.ok : (res.status >= 200 && res.status < 300),
headers: res.headers,
json: async () => {
if (parsed.error) throw parsed.error;
return parsed.data;
},
text: async () => {
if (parsed.text !== undefined) return parsed.text;
if (parsed.error) throw parsed.error;
return JSON.stringify(parsed.data);
},
};
}
throw new Error('Webhook 重定向次数过多');
} finally {
clearTimeout(timer);
}
}

module.exports = {
isPrivateIpOrHost,
isValidWebhookTarget,
assertHostPublic,
safeFetchJson,
redactUrlForLog,
};
