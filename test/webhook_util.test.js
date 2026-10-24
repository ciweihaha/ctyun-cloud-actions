const { test } = require('node:test');
const assert = require('node:assert/strict');
const { isValidWebhookTarget, assertHostPublic, safeFetchJson } = require('../app/webhook_util.js');

const pub = async () => [{ address: '93.184.216.34', family: 4 }];
const priv = async () => [{ address: '169.254.169.254', family: 4 }];
const mixed = async () => [{ address: '93.184.216.34', family: 4 }, { address: '10.0.0.8', family: 4 }];
function res(status, { location, json = {} } = {}) {
  return {
    status,
    ok: status >= 200 && status < 300,
    headers: { get: (n) => (n.toLowerCase() === 'location' ? location || null : null) },
    json: async () => json,
  };
}

test('isValidWebhookTarget: 内嵌用户信息被拒（旧实现放行）', () => {
  assert.equal(isValidWebhookTarget('webhook', 'https://user:pass@hooks.example.com/x'), false);
  assert.equal(isValidWebhookTarget('webhook', 'https://hooks.example.com/x'), true);
  assert.equal(isValidWebhookTarget('webhook', 'http://192.168.1.1/x'), false);
  assert.equal(isValidWebhookTarget('webhook', 'https://169.254.169.254/latest/meta-data'), false);
});

test('assertHostPublic: 解析到私有/元数据地址即拒绝（DNS rebinding）', async () => {
  await assert.rejects(assertHostPublic('hooks.example.com', priv), /私有地址/);
  await assert.rejects(assertHostPublic('hooks.example.com', mixed), /私有地址/);
  await assertHostPublic('hooks.example.com', pub);
  await assert.rejects(assertHostPublic('localhost', pub), /不允许/);
  await assert.rejects(assertHostPublic('hooks.example.com', async () => { throw new Error('ENOTFOUND'); }), /解析失败/);
});

test('safeFetchJson: 目标解析到内网时根本不发起请求', async () => {
  let called = 0;
  await assert.rejects(
    safeFetchJson('https://hooks.example.com/x', { fetchFn: async () => { called++; return res(200); }, lookupFn: priv }),
    /私有地址/
  );
  assert.equal(called, 0);
});

test('safeFetchJson: 公网直达 200 透传', async () => {
  const r = await safeFetchJson('https://hooks.example.com/x', { fetchFn: async () => res(200, { json: { errcode: 0 } }), lookupFn: pub });
  assert.equal(r.status, 200);
  assert.equal((await r.json()).errcode, 0);
});

test('safeFetchJson: 重定向逐跳复检，跳内网在第二跳被拦', async () => {
  let calls = 0;
  const fetchFn = async (url) => {
    calls++;
    if (url.includes('hooks.example.com')) return res(302, { location: 'http://169.254.169.254/latest' });
    return res(200);
  };
  await assert.rejects(safeFetchJson('https://hooks.example.com/x', { fetchFn, lookupFn: pub }), /不允许|私有/);
  assert.equal(calls, 1, '第二跳不应真正发出');
});

test('safeFetchJson: 公网重定向链可完成，超限报错', async () => {
  const fetchFn = async (url) => {
    if (url.endsWith('/a')) return res(302, { location: '/b' });
    return res(200);
  };
  const r = await safeFetchJson('https://hooks.example.com/a', { fetchFn, lookupFn: pub });
  assert.equal(r.status, 200);
  const loop = async () => res(302, { location: '/a' });
  await assert.rejects(safeFetchJson('https://hooks.example.com/a', { fetchFn: loop, lookupFn: pub }), /重定向次数过多/);
});

test('safeFetchJson: 慢响应超时中断', async () => {
  const fetchFn = (url, init) => new Promise((_, reject) => {
    init.signal.addEventListener('abort', () => reject(new Error('The operation was aborted')));
  });
  await assert.rejects(
    safeFetchJson('https://hooks.example.com/x', { fetchFn, lookupFn: pub, timeoutMs: 30 }),
    /aborted/
  );
});
