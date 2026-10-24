const { test } = require('node:test');
const assert = require('node:assert/strict');
const { isValidWebhookTarget, assertHostPublic, safeFetchJson, redactUrlForLog } = require('../app/webhook_util.js');

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

// ===== 本轮回归：总超时必须覆盖响应体读取（旧实现 fetch 返回响应头即清定时器，
// 调用方随后 res.json() 脱离保护，body 永不结束时无限挂起） =====
function makeStreamResponse({ status = 200, chunks = [], chunkDelayMs = 0, hang = false } = {}) {
  const enc = new TextEncoder();
  const stream = new ReadableStream({
    async start(controller) {
      for (const c of chunks) {
        if (chunkDelayMs) await new Promise((r) => setTimeout(r, chunkDelayMs));
        controller.enqueue(enc.encode(c));
      }
      if (!hang) controller.close();
    },
  });
  return new Response(stream, { status, headers: { 'Content-Type': 'application/json' } });
}

test('safeFetchJson: 响应头已返回但 body 永不结束，总超时内失败', async () => {
  const fetchFn = async () => makeStreamResponse({ chunks: ['{"errcode":'], hang: true });
  const started = Date.now();
  await assert.rejects(
    safeFetchJson('https://hooks.example.com/x', { fetchFn, lookupFn: pub, timeoutMs: 120 }),
    /总超时/
  );
  assert.ok(Date.now() - started < 3000, '应在总超时附近失败，而不是无限等待 body');
});

test('safeFetchJson: body 慢速滴流累计超过总时长，总超时内失败', async () => {
  const fetchFn = async () => makeStreamResponse({ chunks: ['{"a":', '1', '}'], chunkDelayMs: 80 });
  await assert.rejects(
    safeFetchJson('https://hooks.example.com/x', { fetchFn, lookupFn: pub, timeoutMs: 150 }),
    /总超时/
  );
});

test('safeFetchJson: 正常小 body 在总超时内读完并可解析', async () => {
  const fetchFn = async () => makeStreamResponse({ chunks: ['{"errcode":', '0,"errmsg":"ok"}'] });
  const r = await safeFetchJson('https://hooks.example.com/x', { fetchFn, lookupFn: pub, timeoutMs: 2000 });
  assert.equal(r.status, 200);
  assert.equal(r.ok, true);
  assert.equal((await r.json()).errcode, 0);
});

test('safeFetchJson: 响应体超过上限时明确报错', async () => {
  const big = 'x'.repeat(4096);
  const fetchFn = async () => makeStreamResponse({ chunks: [big, big] });
  await assert.rejects(
    safeFetchJson('https://hooks.example.com/x', { fetchFn, lookupFn: pub, timeoutMs: 5000, maxBodyBytes: 1024 }),
    /超过上限/
  );
});

test('safeFetchJson: 非 JSON 响应体时 json() 拒绝（保持调用方 .catch 兜底语义）', async () => {
  const fetchFn = async () => makeStreamResponse({ chunks: ['not-json'] });
  const r = await safeFetchJson('https://hooks.example.com/x', { fetchFn, lookupFn: pub, timeoutMs: 2000 });
  await assert.rejects(r.json());
  const data = await r.json().catch(() => ({}));
  assert.deepEqual(data, {});
});

// ===== 日志脱敏：Webhook URL 的路径令牌 / query / userinfo / @secret 不得进日志 =====
test('redactUrlForLog: 各渠道 URL 中的令牌不出现在脱敏结果中', () => {
  const feishu = redactUrlForLog('https://open.feishu.cn/open-apis/bot/v2/hook/SECRET_TOKEN_123@SEC_SIGN_456');
  assert.ok(feishu.includes('open.feishu.cn'));
  assert.ok(!feishu.includes('SECRET_TOKEN_123'), '飞书路径令牌泄漏');
  assert.ok(!feishu.includes('SEC_SIGN_456'), '飞书 @secret 泄漏');

  const ding = redactUrlForLog('https://oapi.dingtalk.com/robot/send?access_token=ACCESS_TOKEN_789&sign=SIGNATURE_abc');
  assert.ok(ding.includes('oapi.dingtalk.com'));
  assert.ok(!ding.includes('ACCESS_TOKEN_789'), '钉钉 access_token 泄漏');
  assert.ok(!ding.includes('SIGNATURE_abc'), '钉钉 sign 泄漏');

  const qywx = redactUrlForLog('https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=QYWX_KEY_000');
  assert.ok(qywx.includes('qyapi.weixin.qq.com'));
  assert.ok(!qywx.includes('QYWX_KEY_000'), '企业微信 key 泄漏');

  const withUser = redactUrlForLog('https://user:passw0rd@hooks.example.com/x?token=tok123');
  assert.ok(!withUser.includes('passw0rd'), '内嵌密码泄漏');
  assert.ok(!withUser.includes('tok123'), 'query 令牌泄漏');

  const tg = redactUrlForLog('123456:AAE_bot_token_value@998877');
  assert.ok(!tg.includes('AAE_bot_token_value'), 'telegram bot token 泄漏');

  const plain = redactUrlForLog('sct_token_plain_value');
  assert.ok(!plain.includes('sct_token_plain_value'), '纯 token 泄漏');

  assert.equal(redactUrlForLog(''), '(未配置)');
  assert.equal(redactUrlForLog(undefined), '(未配置)');
});

// ===== 复审第二轮：readAndParseBody 第三分支（无 body.getReader 又无 text()
// 的非标准响应对象）此前只有超时、无字节上限 =====
test('safeFetchJson: 第三分支超大 JSON 被体积 guard 拦下（默认 1MB）', async () => {
  const big = { pad: 'x'.repeat(1024 * 1024 + 100) };
  const fetchFn = async () => ({ status: 200, ok: true, headers: { get: () => null }, json: async () => big });
  await assert.rejects(
    safeFetchJson('https://hooks.example.com/x', { fetchFn, lookupFn: pub, timeoutMs: 5000 }),
    /超过上限/
  );
});

test('safeFetchJson: 第三分支自定义小上限同样生效', async () => {
  const fetchFn = async () => ({ status: 200, ok: true, headers: { get: () => null }, json: async () => ({ pad: 'x'.repeat(2048) }) });
  await assert.rejects(
    safeFetchJson('https://hooks.example.com/x', { fetchFn, lookupFn: pub, timeoutMs: 5000, maxBodyBytes: 1024 }),
    /超过上限/
  );
});
