const { test } = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const { validateProxyTarget, buildProxyHeaders } = require('../app/proxy_util.js');
const { readRawBody } = require('../app/http_util.js');

test('validateProxyTarget: 合法官方目标放行', () => {
  for (const u of [
    'https://pc.ctyun.cn/api/x',
    'https://desk.ctyun.cn:8810/api/auth',
    'https://desk.ctyun.cn:8816/ws',
    'https://a-deskmgr.ctyun.cn/v1',
    'https://ctyun.cn/',
  ]) {
    assert.equal(validateProxyTarget(u).ok, true, u);
  }
});

test('validateProxyTarget: 后缀伪造/协议/端口/用户信息/IP 全拒绝', () => {
  const bad = [
    'https://evilctyun.cn/',            // 无点前缀伪造
    'https://pc.ctyun.cn.evil.com/',    // 官方名作子域
    'https://evil.com/?x=.ctyun.cn',
    'http://pc.ctyun.cn/api',           // 明文协议
    'https://pc.ctyun.cn:22/api',       // 非白名单端口
    'https://pc.ctyun.cn:8443/api',
    'https://user:pass@pc.ctyun.cn/',   // 内嵌凭据
    'https://127.0.0.1:8810/',           // IP 字面量
    'https://[::1]:8810/',
    'ftp://pc.ctyun.cn/',
    'not a url',
    '',
  ];
  for (const u of bad) {
    assert.equal(validateProxyTarget(u).ok, false, u);
  }
});

test('buildProxyHeaders: 仪表盘凭据头绝不转发，官方防盗链头注入', () => {
  const out = buildProxyHeaders({
    authorization: 'Bearer DASHBOARD_TOKEN',
    cookie: 'token=abc',
    'content-type': 'application/json',
    'x-custom': '1',
    host: '127.0.0.1:8571',
    'content-length': '42',
  }, new URL('https://desk.ctyun.cn:8810/api'));
  assert.equal(out.authorization, undefined);
  assert.equal(out.cookie, undefined);
  assert.equal(out['content-length'], undefined);
  assert.equal(out['content-type'], 'application/json');
  assert.equal(out['x-custom'], '1');
  assert.equal(out.host, 'desk.ctyun.cn:8810');
  assert.equal(out.origin, 'https://pc.ctyun.cn');
});

test('readRawBody: 正常/超限 413/断开 reject', async () => {
  const mk = (chunks, evt = 'end', headers = {}) => {
    const req = new EventEmitter();
    req.headers = headers;
    process.nextTick(() => { for (const c of chunks) req.emit('data', Buffer.from(c)); req.emit(evt); });
    return req;
  };
  assert.equal((await readRawBody(mk(['ab', 'cd']))).toString(), 'abcd');
  await assert.rejects(readRawBody(mk(['x'.repeat(50)]), { maxBytes: 10 }), (e) => e.statusCode === 413);
  await assert.rejects(readRawBody(mk(['ab'], 'aborted')), (e) => e.statusCode === 400);
});
