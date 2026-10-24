/**
 * HTTP 基础工具（缺陷修复 G5）：请求体解析、CORS、异常熔断。
 * 从 server.js 抽出以便单测；server.js 只做装配。
 */
const { URL } = require('url');

function httpError(statusCode, message) {
  const err = new Error(message);
  err.statusCode = statusCode;
  return err;
}

const DEFAULT_JSON_MAX_BYTES = 1024 * 1024; // 1MB

/**
 * 解析 JSON 请求体（旧实现缺陷：字符串无上限累积、解析失败吞错返回 {}、
 * 客户端断开时 Promise 永不 settle 可挂死请求）。
 * - Buffer 累积并计数，超过 maxBytes 立即以 413 拒绝（chunked 同样受限）
 * - Content-Length 预检超限直接 413
 * - JSON 非法以 400 拒绝，不再用 {} 冒充成功
 * - 'aborted'/'error' 一律 reject，保证 settle
 */
function parseJsonBody(req, { maxBytes = DEFAULT_JSON_MAX_BYTES } = {}) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const fail = (err) => { if (!settled) { settled = true; reject(err); } };
    const done = (val) => { if (!settled) { settled = true; resolve(val); } };

    const declared = Number(req.headers && req.headers['content-length']);
    if (Number.isFinite(declared) && declared > maxBytes) {
      fail(httpError(413, '请求体过大'));
      return;
    }

    const chunks = [];
    let total = 0;
    req.on('data', (chunk) => {
      if (settled) return;
      total += chunk.length;
      if (total > maxBytes) {
        fail(httpError(413, '请求体过大'));
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      const text = Buffer.concat(chunks).toString('utf8');
      if (!text.trim()) { done({}); return; }
      try {
        done(JSON.parse(text));
      } catch (e) {
        fail(httpError(400, '请求体不是合法 JSON'));
      }
    });
    req.on('aborted', () => fail(httpError(400, '请求已中断')));
    req.on('error', (err) => fail(err && err.statusCode ? err : httpError(400, '请求读取失败')));
  });
}

function parseAllowedOrigins(envValue) {
  return String(envValue || '').split(',').map(s => s.trim()).filter(Boolean);
}

/**
 * CORS 响应头（旧实现全站 Access-Control-Allow-Origin: * 且 Allow-Headers: *，
 * 任意站点可跨域读取带凭据的 API 响应）。
 * 规则：仅当 Origin 与请求 Host 同源、或命中 CTYUN_CORS_ORIGINS 名单时回显该 Origin；
 * 无 Origin（非浏览器请求）不下发 CORS 头；不命中时只回 Vary: Origin。
 */
function corsHeadersFor(req, { allowedOrigins = [] } = {}) {
  const origin = req && req.headers && req.headers.origin;
  if (!origin) return {};
  let allowed = false;
  try {
    const o = new URL(origin);
    if (req.headers.host && o.host === req.headers.host) allowed = true;
  } catch (e) { /* 非法 Origin 不放行 */ }
  if (!allowed && allowedOrigins.includes(origin)) allowed = true;
  if (!allowed) return { 'Vary': 'Origin' };
  return {
    'Access-Control-Allow-Origin': origin,
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Vary': 'Origin',
  };
}

/**
 * 未捕获异常熔断（旧实现无限吞异常常驻，进程可能带病运行）。
 * 窗口内累计达到 threshold 次即判定不健康，回调 onFatal（由 server 落盘+停调度+退出，
 * 交给守护进程/Docker 重启策略拉起一个干净进程）。时钟可注入以便单测。
 */
function createExceptionGuard({ threshold = 5, windowMs = 10 * 60 * 1000, nowFn = () => Date.now(), onFatal = () => {} } = {}) {
  let times = [];
  let fatalFired = false;
  return {
    record(err) {
      const now = nowFn();
      times = times.filter(t => now - t < windowMs);
      times.push(now);
      if (times.length >= threshold && !fatalFired) {
        fatalFired = true;
        try { onFatal(err, times.length); } catch (e) {}
        return true;
      }
      return false;
    },
    count() { return times.length; },
  };
}

module.exports = {
  parseJsonBody,
  corsHeadersFor,
  parseAllowedOrigins,
  createExceptionGuard,
  httpError,
  DEFAULT_JSON_MAX_BYTES,
};
