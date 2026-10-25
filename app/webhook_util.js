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
* 本轮修复（fix/round3-ctyun-webhook-dns-pinning-20261024）：
* 校验-连接 TOCTOU 已封堵：safeFetchJson 每一跳先经
* resolvePublicAddresses 拿到预校验通过的公网地址集，再把该地址集以
* pinnedIps 交给连接层；默认连接层 fetchWithPinnedIps 用 Node 内置
* http/https + 自定义 lookup（createPinnedLookup）建连，连接时不再做
* 任何系统 DNS 解析，实际连接的 IP 只能是 pinnedIps 中的地址。
* 之所以不用第三方 undici 包做自定义 dispatcher：本仓运行依赖只有
* ws，Node 24 的内置 fetch 所用的 undici 并不作为可 require 的公开
* 模块提供（实测 require('undici') / require('node:undici') 均不存在），
* 为此新引一个与运行时内置实现重复的 undici 依赖只会扩大供应链面；
* 内置 http/https 的 lookup 钉扎达到同一保证（连接 IP ∈ 预校验集），
* 且 TLS 栈仍是 Node 原生实现，见 fetchWithPinnedIps 的注释。
* 残余风险（如实记录）：若校验时刻的 DNS 本身已被投毒、返回攻击者
* 控制的公网 IP 且该 IP 持有与主机名匹配的有效证书，钉扎无法识别
* ——那已超出 TOCTOU 范畴，属于 DNS/证书信任问题，不在本轮口径内。
*
* 本轮追加修复（fix/webhook-body-timeout-20261024）：
* - 旧 safeFetchJson 在 fetch() 返回响应头后即 clearTimeout，调用方随后
* res.json() 读取响应体脱离超时保护，body 永不结束时可无限挂起。现改为
* 单个总超时覆盖 DNS/建连/响应头/重定向/响应体读取/JSON 解析全程，
* 函数内读完 body（上限 1MB）才返回同形对象，调用方不再二次读网络响应。
* - 安全拦截日志与 URL 非法报错曾拼接完整 webhookUrl（路径令牌、query、
* @secret 均可入日志），统一改为 redactUrlForLog 脱敏后输出。
*/
const net = require('net'); /* CTY-01 重定向策略：只管重定向跳，不管首跳选择；首跳 origin 由 safeFetchJson 记录（scheme+host+有效端口）；跨源默认拒绝，allowlist 放行并剥离敏感头（只保留 Content-Type）；allowlist 本身是信任边界，须定期复核。 */ const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]); function effectivePort(u) { return u.port ? Number(u.port) : (u.protocol === 'https:' ? 443 : 80); } function canonicalOrigin(u) { return `${u.protocol}//${u.hostname}:${effectivePort(u)}`; }
const dns = require('dns'); function normalizeRedirectAllowlist(list) { const items = Array.isArray(list) ? list : (typeof list === 'string' ? list.split(',') : []); const out = new Set(); for (const raw of items) { const s = String(raw || '').trim().toLowerCase(); if (!s) continue; if (s.includes('://')) { try { out.add(canonicalOrigin(new URL(s))); } catch (e) {} } else out.add(s.replace(/^\[|\]$/g, '')); } return out; } function redirectAllowlistFromEnv() { return normalizeRedirectAllowlist(process.env.CTYUN_WEBHOOK_REDIRECT_ALLOWLIST); }
const http = require('http'); function isAllowlistedRedirect(nextUrl, allowlist) { for (const entry of allowlist || []) { if (entry.includes('://')) { if (canonicalOrigin(nextUrl) === entry) return true; } else if (nextUrl.hostname.toLowerCase() === entry) return true; } return false; } function stripHeadersForCrossOrigin(headers) { const out = {}; for (const [k, v] of Object.entries(headers || {})) { if (String(k).toLowerCase() === 'content-type') out[k] = v; } return out; }
const https = require('https'); function applyRedirectPolicy({ fromUrl, toUrl, status, method, body, headers, firstOrigin, allowlist }) { if (!REDIRECT_STATUSES.has(status)) throw new Error(`Webhook 重定向状态不允许跟随: ${status}`); const from = new URL(fromUrl); const to = new URL(toUrl); if (from.protocol === 'https:' && to.protocol === 'http:') throw new Error('Webhook 重定向 https→http 被拒绝'); const crossOrigin = canonicalOrigin(to) !== firstOrigin; let nextHeaders = { ...(headers || {}) }; let allowlisted = false; if (crossOrigin) { if (!isAllowlistedRedirect(to, allowlist)) throw new Error(`Webhook 跨源重定向被拒绝: ${redactUrlForLog(to.toString())}`); allowlisted = true; nextHeaders = stripHeadersForCrossOrigin(headers); } let nextMethod = method; let nextBody = body; if (status === 303 || (String(method || '').toUpperCase() === 'POST' && (status === 301 || status === 302))) { nextMethod = 'GET'; nextBody = undefined; } return { method: nextMethod, body: nextBody, headers: nextHeaders, crossOrigin, allowlisted }; }
const { Readable } = require('stream'); /* CTY-02+CTY-03: IANA 特殊用途地址登记（RFC 6890、RFC 6598、RFC 3849 等）逐段 CIDR 位运算判定，替代前缀字符串匹配；建议每季度对照 IANA 登记复核一次。 */ function ipv4ToInt(s) { const p = s.split('.').map(Number); if (p.length !== 4 || p.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return null; return ((p[0] * 256 + p[1]) * 256 + p[2]) * 256 + p[3]; } function ipv4InCidr(ip, base, prefix) { const a = ipv4ToInt(ip); const b = ipv4ToInt(base); if (a === null || b === null) return false; const mask = prefix === 0 ? 0 : ((0xffffffff << (32 - prefix)) >>> 0); return (a & mask) === (b & mask); }
const { URL} = require('url'); function ipv6Groups(s) { let t = s.split('%')[0].toLowerCase(); if (t.startsWith('::ffff:') && t.includes('.')) { const n = ipv4ToInt(t.slice(7)); if (n === null) return null; return [0, 0, 0, 0, 0, 0xffff, (n >>> 16) & 0xffff, n & 0xffff]; } if (t.includes('.')) { const i = t.lastIndexOf(':'); if (i < 0) return null; const n = ipv4ToInt(t.slice(i + 1)); if (n === null) return null; t = t.slice(0, i) + ':' + (((n >>> 16) & 0xffff).toString(16)) + ':' + ((n & 0xffff).toString(16)); } const parts = t.split('::'); if (parts.length > 2) return null; const head = parts[0] ? parts[0].split(':').filter(Boolean) : []; const tail = parts.length === 2 && parts[1] ? parts[1].split(':').filter(Boolean) : []; if (parts.length === 1 && head.length !== 8) return null; if (parts.length === 2 && head.length + tail.length > 7) return null; const mid = Array(8 - head.length - tail.length).fill('0'); const all = [...head, ...mid, ...tail].map((x) => parseInt(x, 16)); if (all.length !== 8 || all.some((n) => Number.isNaN(n) || n < 0 || n > 0xffff)) return null; return all; } function ipv6InCidr(groups, baseGroups, prefix) { for (let i = 0; i < 8; i++) { const bits = Math.max(0, Math.min(16, prefix - i * 16)); if (bits === 0) break; const mask = bits === 16 ? 0xffff : ((0xffff << (16 - bits)) & 0xffff); if ((groups[i] & mask) !== (baseGroups[i] & mask)) return false; } return true; }

function isPrivateOrReservedIp(hostname) { const raw = (hostname || '').toLowerCase().trim(); if (!raw) return true; const h = raw.split('%')[0]; if (h === 'localhost') return true; if (net.isIPv4(h)) { const v4 = ['0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16', '172.16.0.0/12', '192.0.0.0/24', '192.0.2.0/24', '192.168.0.0/16', '198.18.0.0/15', '198.51.100.0/24', '203.0.113.0/24', '224.0.0.0/4', '240.0.0.0/4']; return v4.some((c) => { const parts = c.split('/'); return ipv4InCidr(h, parts[0], Number(parts[1])); }); } if (h.includes(':')) { const g = ipv6Groups(h); if (!g) return false; if (g.slice(0, 5).every((x) => x === 0) && g[5] === 0xffff) { const v4int = g[6] * 65536 + g[7]; const v4str = [((v4int >>> 24) & 255), ((v4int >>> 16) & 255), ((v4int >>> 8) & 255), (v4int & 255)].join('.'); return isPrivateOrReservedIp(v4str); } const v6 = [['::', 128], ['::1', 128], ['64:ff9b::', 96], ['100::', 64], ['2001:db8::', 32], ['fc00::', 7], ['fe80::', 10], ['fec0::', 10]]; return v6.some((c) => { const bg = ipv6Groups(c[0]); return bg && ipv6InCidr(g, bg, c[1]); }); } return h.endsWith('.local') || h.endsWith('.internal') || h.endsWith('.lan'); } function isPrivateIpOrHost(hostname) { if (isPrivateOrReservedIp(hostname)) return true;
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
* 解析主机名并逐个校验全部地址，返回预校验通过的公网地址集（去重保序）：
* 任一地址为私有/保留即拒绝。IP 字面量直接校验并返回自身。
* lookupFn 可注入（单测）。返回的地址集就是后续连接层唯一允许连接
* 的钉扎集：调用方不得在连接时重新解析，必须原样传给连接层。
* 报错文案与旧 assertHostPublic 保持一致（既有测试按文案匹配）。
*/
async function resolvePublicAddresses(hostname, lookupFn = defaultLookup) {
const h = (hostname || '').toLowerCase().trim();
if (isPrivateIpOrHost(h)) {
throw new Error(`Webhook 目标主机不允许: ${hostname}`);
}
if (net.isIP(h)) return [h]; // 公网 IP 字面量已由 isPrivateIpOrHost 排除私有段
let addresses;
try {
addresses = await lookupFn(h);
} catch (e) {
throw new Error(`Webhook 目标域名解析失败: ${hostname}`);
}
if (!addresses || addresses.length === 0) {
throw new Error(`Webhook 目标域名无解析结果: ${hostname}`);
}
const out = [];
for (const a of addresses) {
const ip = typeof a === 'string'? a: a.address;
if (isPrivateIpOrHost(ip)) {
throw new Error(`Webhook 目标解析到私有地址: ${hostname} -> ${ip}`);
}
if (ip && !out.includes(ip)) out.push(ip);
}
return out;
}

/**
* 解析主机名并逐个校验全部地址：任一地址为私有/保留即拒绝。
* 兼容旧接口：只做校验不返回值，需要钉扎集请用 resolvePublicAddresses。
*/
async function assertHostPublic(hostname, lookupFn = defaultLookup) {
await resolvePublicAddresses(hostname, lookupFn);
}

/**
* 由钉扎地址集构造 dns.lookup 兼容函数：连接时只返回钉扎地址，
* 绝不调用系统 DNS，也绝不接受调用方传入的任何解析结果。
* 签名兼容 net.connect 的 lookup 选项：(hostname, options, callback)，
* options 可为 family 数字或 { all, family }；all:true 时返回全部钉扎
* 地址，否则返回首个钉扎地址。family 仅作参考：返回地址的 family 以
* 地址本身为准，避免因 family 不匹配而被迫换到非钉扎地址。
*/
function createPinnedLookup(pinnedIps) {
const ips = (pinnedIps || []).filter(Boolean);
return (hostname, options, callback) => {
if (typeof options === 'function') {
callback = options;
options = {};
}
const all = !!(options && typeof options === 'object' && options.all);
const done = () => {
if (all) {
callback(null, ips.map((address) => ({ address, family: net.isIP(address) })));
} else if (ips.length > 0) {
callback(null, ips[0], net.isIP(ips[0]));
} else {
const err = new Error(`Webhook 钉扎地址集为空: ${hostname}`);
err.code = 'ENOTFOUND';
callback(err);
}
};
// lookup 回调按 Node 约定异步触发，避免同步回调打乱 net 内部状态机。
if (typeof process !== 'undefined' && typeof process.nextTick === 'function') process.nextTick(done);
else setTimeout(done, 0);
};
}

const PINNED_RETRYABLE_CODES = new Set(['ECONNREFUSED', 'ENETUNREACH', 'EHOSTUNREACH']);
function isTlsError(err) {
if (!err) return false;
if (typeof err.code === 'string' && (err.code.startsWith('CERT') || err.code.startsWith('ERR_TLS'))) return true;
return /certificate|TLS|SSL/i.test(err.message || '');
}

/**
* 以钉扎地址集建连的 fetch 等价实现（Node 内置 http/https，无新依赖）：
* - 连接 IP 唯一来源是 pinnedIps：通过 lookup 选项把主机名的解析结果
*   固定为钉扎集，建连全程不再查询系统 DNS，校验后重绑定无效。
* - TLS 绝不绕过：https 请求显式 servername=原始主机名（IP 字面量时
*   不设 servername，由 Node 按 IP SAN 校验），rejectUnauthorized 恒为
*   true，不改写 checkServerIdentity；ca 仅在调用方显式传入时转发
*   （生产调用方不传，即系统 CA；测试用自签证书时才传）。
* - agent:false：每个请求不用连接池复用，避免池中旧连接（可能对应
*   另一跳/另一地址集）被复用到本跳。
* - 多地址回落只限“建连前即被拒”的错误（ECONNREFUSED/ENETUNREACH/
*   EHOSTUNREACH：对端根本未接受连接，不存在已处理请求被重复发送
*   的风险）；TLS/证书错误一律硬失败不回落，避免用回落掩盖证书错配；
*   其余错误（包括已建连后中断）同样不回落，避免 POST 重复投递。
* - 公网性纵深防御：pinnedIps 中任一私网/保留地址且未显式
*   allowPrivatePinnedIps 时直接拒绝。生产入口 safeFetchJson 只传
*   预校验通过的公网集，本分支对其无影响；allowPrivate 仅供本地
*   回环测试（假主机名 + 127.0.0.1 本地服务器）显式 opt-in，生产
*   代码路径绝不设置它。
* 返回值与 Response 同形子集（status/ok/headers.get/body/text()/json()），
* body 为 Web ReadableStream（可由 safeFetchJson 的流式读体分支消费，
* 单次消费，与 Response 语义一致）；signal 中止时销毁请求与响应。
*/
async function fetchWithPinnedIps(urlString, {
method = 'GET',
headers = {},
body,
signal,
pinnedIps,
allowPrivatePinnedIps = false,
ca,
} = {}) {
let u;
try {
u = new URL(urlString);
} catch (e) {
throw new Error(`Webhook URL 非法: ${redactUrlForLog(urlString)}`);
}
if (u.protocol !== 'http:' && u.protocol !== 'https:') {
throw new Error(`Webhook 协议不允许: ${u.protocol}`);
}
if (u.username || u.password) {
throw new Error('Webhook URL 不得内嵌用户信息');
}
if (!pinnedIps || pinnedIps.length === 0) {
throw new Error('Webhook 钉扎地址集为空，拒绝建连');
}
if (!allowPrivatePinnedIps) {
for (const ip of pinnedIps) {
if (isPrivateIpOrHost(ip)) throw new Error(`Webhook 钉扎地址为私有/保留地址，拒绝建连: ${ip}`);
}
}
const isHttps = u.protocol === 'https:';
const port = u.port ? Number(u.port) : (isHttps ? 443 : 80);
const isIpLiteral = !!net.isIP(u.hostname);
let lastError = null;
for (let i = 0; i < pinnedIps.length; i++) {
const ip = pinnedIps[i];
try {
return await new Promise((resolve, reject) => {
if (signal && signal.aborted) {
const err = new Error('The operation was aborted');
err.name = 'AbortError';
reject(err);
return;
}
const requestOptions = {
host: u.hostname,
port,
path: `${u.pathname}${u.search}`,
method,
headers: { ...headers },
lookup: createPinnedLookup([ip]),
agent: false,
signal,
};
if (isHttps) {
requestOptions.rejectUnauthorized = true;
if (!isIpLiteral) requestOptions.servername = u.hostname;
if (ca !== undefined) requestOptions.ca = ca;
}
const requestFn = isHttps ? https.request : http.request;
let req;
let resRef = null;
try {
req = requestFn(requestOptions, (res) => {
resRef = res;
const webBody = Readable.toWeb(res);
let consumed = false;
const readAll = async () => {
if (consumed) throw new Error('Webhook 响应体已被消费');
consumed = true;
const reader = webBody.getReader();
const chunks = [];
for (;;) {
const { done, value } = await reader.read();
if (done) break;
if (value) chunks.push(Buffer.from(value));
}
return Buffer.concat(chunks).toString('utf8');
};
resolve({
status: res.statusCode,
ok: res.statusCode >= 200 && res.statusCode < 300,
headers: {
get: (name) => {
const v = res.headers[String(name).toLowerCase()];
if (Array.isArray(v)) return v[0] !== undefined ? v[0] : null;
return v !== undefined ? v : null;
},
raw: res.headers,
},
body: webBody,
text: readAll,
json: async () => JSON.parse(await readAll()),
});
});
} catch (e) {
reject(e);
return;
}
const onAbort = () => {
try { req.destroy(new Error('The operation was aborted')); } catch (e) {}
try { if (resRef) resRef.destroy(); } catch (e) {}
};
if (signal) signal.addEventListener('abort', onAbort, { once: true });
req.on('error', (err) => {
if (signal) signal.removeEventListener('abort', onAbort);
reject(err);
});
req.on('close', () => {
if (signal) signal.removeEventListener('abort', onAbort);
});
if (body !== undefined && body !== null) req.write(body);
req.end();
});
} catch (e) {
lastError = e;
if (signal && signal.aborted) throw e;
if (isTlsError(e)) throw e;
if (i < pinnedIps.length - 1 && e && PINNED_RETRYABLE_CODES.has(e.code)) continue;
throw e;
}
}
throw lastError || new Error('Webhook 钉扎建连失败');
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
const onAbort = () => reject(timeoutError()); signal.addEventListener('abort', onAbort, { once: true }); promise.then(() => signal.removeEventListener('abort', onAbort), () => signal.removeEventListener('abort', onAbort));
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
// 【复审第二轮】该分支此前只有超时保护、无字节上限：非标准响应对象
// （无 body.getReader 又无 text()）返回的超大 JSON 会整段进内存。
// 流式分支按累计字节拦截，此处只能事后序列化校验：序列化长度是线
// 上字节的近似（不计空白差异），超限即硬失败，与另两分支口径一致；
// 校验放在 try/catch 之外，避免超限错被降级为软 error 返回。
let data;
try {
data = await raceWithAbort(res.json(), signal, timeoutError);
} catch (e) {
if (signal.aborted) throw timeoutError();
return { data: undefined, text: undefined, error: e };
}
const serialized = JSON.stringify(data);
if (serialized !== undefined && Buffer.byteLength(serialized, 'utf8') > maxBodyBytes) {
const err = new Error(`Webhook 响应体超过上限（${maxBodyBytes} 字节）`);
err.code = 'WEBHOOK_BODY_TOO_LARGE';
throw err;
}
return { data, text: undefined, error: null };
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
* 【DNS 钉扎语义】每一跳只解析一次（resolvePublicAddresses），解析
* 结果 pinnedIps 原样交给连接层；默认连接层即 fetchWithPinnedIps，
* 连接时不再解析，校验后重绑定无效。fetchFn/lookupFn 可注入（单测
* 用本地模拟服务）：注入 fetchFn 时同样收到 pinnedIps，测试可断言
* 连接器拿到的是校验时地址集而非重绑定后地址；生产调用方不传
* fetchFn，走默认钉扎连接层。
*/
async function safeFetchJson(urlString, {
method = 'POST',
headers = {},
body,
fetchFn,
lookupFn = defaultLookup,
timeoutMs = 10000,
maxRedirects = 3,
maxBodyBytes = WEBHOOK_MAX_BODY_BYTES, redirectAllowlist, onRedirectAudit,
} = {}) {
const controller = new AbortController();
const timeoutError = () => new Error(`Webhook 请求总超时（${timeoutMs}ms，含响应体读取）`);
const timer = setTimeout(() => controller.abort(), timeoutMs); const allowlist = new Set([...normalizeRedirectAllowlist(redirectAllowlist), ...redirectAllowlistFromEnv()]);
try {
let current = urlString; let firstOrigin = canonicalOrigin(new URL(urlString));
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
const pinnedIps = await raceWithAbort(resolvePublicAddresses(u.hostname, lookupFn), controller.signal, timeoutError);
const transport = fetchFn || fetchWithPinnedIps;

const res = await raceWithAbort(transport(u.toString(), {
method,
headers,
body,
redirect: 'manual',
signal: controller.signal,
pinnedIps,
}), controller.signal, timeoutError);

const isRedirect = REDIRECT_STATUSES.has(res.status);
const location = isRedirect && res.headers && typeof res.headers.get === 'function'
? res.headers.get('location')
: null;
if (isRedirect && location) {
if (hop === maxRedirects) throw new Error('Webhook 重定向次数过多');
// 重定向响应的 body 不再使用，主动 cancel 以便连接尽早释放
try { if (res.body && typeof res.body.cancel === 'function') await res.body.cancel(); } catch (e) {}
const nextUrl = new URL(location, u).toString(); const policy = applyRedirectPolicy({ fromUrl: current, toUrl: nextUrl, status: res.status, method, body, headers, firstOrigin, allowlist }); if (policy.crossOrigin && policy.allowlisted) { if (typeof onRedirectAudit === 'function') { onRedirectAudit({ from: current, to: nextUrl, status: res.status }); } else { console.warn('Webhook 跨源重定向放行:', redactUrlForLog(current), '->', redactUrlForLog(nextUrl), res.status); } } method = policy.method; body = policy.body; headers = policy.headers; current = nextUrl;
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
resolvePublicAddresses,
createPinnedLookup,
fetchWithPinnedIps,
safeFetchJson, applyRedirectPolicy,
redactUrlForLog,
};
