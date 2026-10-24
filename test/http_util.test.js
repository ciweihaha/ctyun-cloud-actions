const { test } = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const { parseJsonBody, corsHeadersFor, parseAllowedOrigins, createExceptionGuard } = require('../app/http_util.js');

function fakeReq({ headers = {}, chunks = [], endWith = 'end' } = {}) {
  const req = new EventEmitter();
  req.headers = headers;
  process.nextTick(() => {
    for (const c of chunks) req.emit('data', Buffer.from(c));
    req.emit(endWith);
  });
  return req;
}

test('parseJsonBody: 正常解析与空体', async () => {
  assert.deepEqual(await parseJsonBody(fakeReq({ chunks: ['{"a":', '1}'] })), { a: 1 });
  assert.deepEqual(await parseJsonBody(fakeReq({ chunks: [] })), {});
});

test('parseJsonBody: 非法 JSON 以 400 拒绝（旧实现吞错返回 {}）', async () => {
  await assert.rejects(parseJsonBody(fakeReq({ chunks: ['{bad'] })), (e) => e.statusCode === 400);
});

test('parseJsonBody: chunked 累积超限 413', async () => {
  const req = fakeReq({ chunks: ['x'.repeat(600), 'y'.repeat(600)] });
  await assert.rejects(parseJsonBody(req, { maxBytes: 1024 }), (e) => e.statusCode === 413);
});

test('parseJsonBody: Content-Length 预检超限直接 413', async () => {
  const req = fakeReq({ headers: { 'content-length': '99999999' }, chunks: ['{}'] });
  await assert.rejects(parseJsonBody(req, { maxBytes: 1024 }), (e) => e.statusCode === 413);
});

test('parseJsonBody: 客户端断开必须 reject 不得挂死（旧实现永不 settle）', async () => {
  const req = fakeReq({ chunks: ['{"a"'], endWith: 'aborted' });
  await assert.rejects(parseJsonBody(req), (e) => e.statusCode === 400);
});

test('corsHeadersFor: 同源回显、名单回显、跨站不回显、无 Origin 不下发', () => {
  const sameOrigin = corsHeadersFor({ headers: { origin: 'http://127.0.0.1:8571', host: '127.0.0.1:8571' } });
  assert.equal(sameOrigin['Access-Control-Allow-Origin'], 'http://127.0.0.1:8571');
  const listed = corsHeadersFor(
    { headers: { origin: 'https://panel.example.com', host: '127.0.0.1:8571' } },
    { allowedOrigins: parseAllowedOrigins('https://panel.example.com, https://a.b') }
  );
  assert.equal(listed['Access-Control-Allow-Origin'], 'https://panel.example.com');
  const evil = corsHeadersFor({ headers: { origin: 'https://evil.example.com', host: '127.0.0.1:8571' } });
  assert.equal(evil['Access-Control-Allow-Origin'], undefined);
  const none = corsHeadersFor({ headers: { host: '127.0.0.1:8571' } });
  assert.deepEqual(none, {});
});

test('createExceptionGuard: 窗口内达阈值只触发一次 onFatal，窗口外不累计', () => {
  let now = 0;
  let fatal = 0;
  const g = createExceptionGuard({ threshold: 3, windowMs: 1000, nowFn: () => now, onFatal: () => fatal++ });
  g.record(new Error('a')); g.record(new Error('b'));
  assert.equal(fatal, 0);
  g.record(new Error('c'));
  assert.equal(fatal, 1);
  g.record(new Error('d'));
  assert.equal(fatal, 1, '不得重复触发退出');
  let fatal2 = 0;
  const g2 = createExceptionGuard({ threshold: 2, windowMs: 1000, nowFn: () => now, onFatal: () => fatal2++ });
  g2.record(new Error('x'));
  now += 2000;
  g2.record(new Error('y'));
  assert.equal(fatal2, 0, '窗口外旧记录应过期');
});
