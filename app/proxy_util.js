/**
 * 天翼云反向代理工具（缺陷修复 G6）。
 * 旧实现缺陷：路由完全无鉴权；目标仅 endsWith('.ctyun.cn') 一条校验
 * （协议/端口/用户信息/IP 字面量全不查）；请求头除 host/origin/referer 外
 * 全量转发（含仪表盘 Authorization/Cookie，等于把会话令牌送给上游）；
 * rejectUnauthorized:false 关闭 TLS 验证；请求体无上限；无上游超时；
 * 客户端断开不终止上游请求。
 * 本地只读探针（2026-10-24）：pc.ctyun.cn:443、desk.ctyun.cn:8810/8816
 * 证书链 Verify return code 均为 0，恢复 TLS 验证不破坏官方端点连通性。
 */
const { URL } = require('url');

const PROXY_ALLOWED_PORTS = new Set([443, 8810, 8816]);
const PROXY_BODY_MAX_BYTES = 10 * 1024 * 1024;
const PROXY_UPSTREAM_TIMEOUT_MS = 30000;

// 绝不转发到上游的请求头：连接级头由 http 模块自理；authorization/cookie 是
// 仪表盘自身凭据，与天翼云上游无关，转发即泄漏。
const PROXY_HEADER_BLOCKLIST = new Set([
  'host', 'origin', 'referer', 'content-length',
  'authorization', 'cookie',
  'connection', 'proxy-authorization', 'proxy-connection',
  'te', 'trailer', 'transfer-encoding', 'upgrade', 'keep-alive',
]);

function isIpLiteral(hostname) {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname) || hostname.includes(':') || hostname.startsWith('[');
}

/**
 * 校验代理目标。返回 { ok:true, url } 或 { ok:false, statusCode, error }。
 * 规则：必须是可解析 URL；仅 https；主机名恰为 ctyun.cn 或以 .ctyun.cn 结尾
 * （防 evilctyun.cn / ctyun.cn.evil.com 后缀伪造）；拒 URL 内嵌用户信息；
 * 拒 IP 字面量主机；端口仅允许 443/8810/8816（缺省 443）。
 */
function validateProxyTarget(targetUrl) {
  let url;
  try {
    url = new URL(targetUrl);
  } catch (e) {
    return { ok: false, statusCode: 400, error: 'Malformed proxy target' };
  }
  if (url.protocol !== 'https:') {
    return { ok: false, statusCode: 403, error: 'Proxy target must be https' };
  }
  if (url.username || url.password) {
    return { ok: false, statusCode: 403, error: 'Proxy target must not embed credentials' };
  }
  const hostname = url.hostname.toLowerCase();
  if (isIpLiteral(hostname)) {
    return { ok: false, statusCode: 403, error: 'Proxy target must be a hostname' };
  }
  if (!(hostname === 'ctyun.cn' || hostname.endsWith('.ctyun.cn'))) {
    return { ok: false, statusCode: 403, error: 'Invalid proxy target' };
  }
  const port = url.port ? Number(url.port) : 443;
  if (!PROXY_ALLOWED_PORTS.has(port)) {
    return { ok: false, statusCode: 403, error: 'Proxy target port not allowed' };
  }
  return { ok: true, url };
}

/** 构建转发上游的请求头：黑名单剔除 + 官方 Origin/Referer 防盗链头。 */
function buildProxyHeaders(reqHeaders, targetUrl) {
  const out = {};
  for (const [k, v] of Object.entries(reqHeaders || {})) {
    if (PROXY_HEADER_BLOCKLIST.has(k.toLowerCase())) continue;
    out[k] = v;
  }
  out['host'] = targetUrl.host;
  out['origin'] = 'https://pc.ctyun.cn';
  out['referer'] = 'https://pc.ctyun.cn/';
  return out;
}

module.exports = {
  validateProxyTarget,
  buildProxyHeaders,
  PROXY_ALLOWED_PORTS,
  PROXY_BODY_MAX_BYTES,
  PROXY_UPSTREAM_TIMEOUT_MS,
};
