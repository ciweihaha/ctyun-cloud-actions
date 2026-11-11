'use strict';
// ydpc 保活路径行为回归测试（深查第 24 轮新建）。
//
// 背景：app/ydpc/product_route.js 与 ydpc_client.js 多处引用 tests/regression.test.js
// （组 7/13/21/22/23）作红线拦截，但该文件并不在仓内——这些行为此前零测试覆盖，
// 第 21 轮的 originCn（核验采样结束后抛 ReferenceError、报告永不返回）正是漏网实例。
// 本文件为第 20/21/22 轮修的三处缺陷补行为回归测试；不触网、不碰真实凭据，全部用桩。
const { test } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { YdpcClient } = require('../app/ydpc/ydpc_client.js');
const { SohoClient } = require('../app/ydpc/soho_client.js');

function runningVm() {
  return {
    userServiceId: '1001', vmName: '云电脑1', vmStatus: '运行中', vmStatusCode: 1,
    keepaliveEnabled: true, durationMode: 'permanent', remainHours: 999, remainText: '♾️ 永久使用'
  };
}

function makeYdpcClient(initialVms, listVms, getFirmAuth) {
  const acc = {
    id: 'probe', name: 'probe', user: '13800000000', password: 'x',
    deviceCode: 'web_probe', platform: 'ydpc', features: { keepAlive: true }, stats: {},
    vms: initialVms
  };
  const client = new YdpcClient(acc, { appendLog: () => {}, sendNotification: () => {}, saveConfig: () => {} });
  client.sohoClient.sohoToken = 'tok';
  client.sohoClient.listCloudPcs = listVms;
  client.sohoClient.getFirmAuth = getFirmAuth;
  return client;
}

// --- 第 21 轮：verifyKeepAliveEffect 补上未定义的 originCn --------------------

test('verifyKeepAliveEffect：手动核验返回报告（originCn 已定义）', async () => {
  const client = makeYdpcClient([runningVm()], async () => [runningVm()], async () => ({}));
  const report = await client.verifyKeepAliveEffect(1, 1);
  assert.equal(report.ok, true);
  assert.ok(Array.isArray(report.snapshots) && report.snapshots.length >= 1);
});

test('verifyKeepAliveEffect：看门狗核验 {origin:auto} 返回报告', async () => {
  const client = makeYdpcClient([runningVm()], async () => [runningVm()], async () => ({}));
  const report = await client.verifyKeepAliveEffect(1, 1, { origin: 'auto' });
  assert.equal(report.ok, true);
});

test('verifyKeepAliveEffect：机器已关机时返回 ok=false 且 stoppedEarly', async () => {
  const off = { ...runningVm(), vmStatus: '已关机', vmStatusCode: 23 };
  const client = makeYdpcClient([off], async () => [off], async () => ({}));
  const report = await client.verifyKeepAliveEffect(1, 1);
  assert.equal(report.ok, false);
  assert.equal(report.stoppedEarly, true);
});

// --- 第 20 轮：soho 登录流程内部调用禁用自动重登，防无限递归 -----------------

test('soho 登录：登录类接口回 4001 时干净失败，不无限递归重登', async () => {
  // 真实 RSA 密钥对供 bootstrap/publicKey 桩返回（rsaEncryptBody 要真加密）
  const { publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const pemBody = publicKey.export({ type: 'spki', format: 'pem' })
    .replace('-----BEGIN PUBLIC KEY-----', '').replace('-----END PUBLIC KEY-----', '').replace(/\n/g, '').trim();

  const realFetch = global.fetch;
  let fetchCount = 0;
  global.fetch = async (url) => {
    fetchCount++;
    // 200 次仍在继续即判定为无限递归（旧实现无上界；新实现 2 次即收敛）
    assert.ok(fetchCount <= 200, `登录请求超 200 次仍在继续（疑似无限递归），fetch=${fetchCount}`);
    const u = String(url);
    const resp = (obj) => ({ ok: true, status: 200, text: async () => JSON.stringify(obj), json: async () => obj, headers: { get: () => null } });
    if (u.includes('/login/encryptKey/v1')) return resp({ code: 2000, data: pemBody });
    return resp({ code: 4001, msg: '未登录' });
  };
  try {
    const client = new SohoClient({});
    await assert.rejects(client.login('13800000000', 'testpass'), /获取登录公钥失败|移动爱家登录失败/);
    assert.ok(fetchCount <= 5, `登录失败应 2 次请求收敛，实际 fetch=${fetchCount}`);
  } finally {
    global.fetch = realFetch;
  }
});

test('soho 登录：外部自动重登仍可用（首次 4001 → 重登 → 重试成功）', async () => {
  const { publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const pemBody = publicKey.export({ type: 'spki', format: 'pem' })
    .replace('-----BEGIN PUBLIC KEY-----', '').replace('-----END PUBLIC KEY-----', '').replace(/\n/g, '').trim();

  const realFetch = global.fetch;
  let listCalls = 0;
  global.fetch = async (url) => {
    const u = String(url);
    const resp = (obj) => ({ ok: true, status: 200, text: async () => JSON.stringify(obj), json: async () => obj, headers: { get: () => null } });
    if (u.includes('/login/encryptKey/v1')) return resp({ code: 2000, data: pemBody });
    if (u.includes('/login/publicKey/v1')) return resp({ code: 2000, data: pemBody });
    if (u.includes('/login/namePwdLogin/v1') || u.includes('/login/home/namePwdLogin/v1')) {
      return resp({ code: 2000, data: { userId: 'u1', sohoToken: 'tok1' } });
    }
    if (u.includes('/cc/cloudPc/list/v6')) {
      listCalls++;
      if (listCalls === 1) return resp({ code: 4001, msg: '未登录' });
      return resp({ code: 2000, data: { list: [] } });
    }
    throw new Error('unexpected fetch: ' + u);
  };
  try {
    const client = new SohoClient({});
    client.savedUsername = '13800000000';
    client.savedPassword = 'testpass';
    const list = await client.listCloudPcs();
    assert.deepEqual(list, []);
    assert.equal(client.sohoToken, 'tok1');
  } finally {
    global.fetch = realFetch;
  }
});

// --- 第 22 轮：refreshVms 底座探测缓存 --------------------------------------

test('refreshVms：探测失败且底座未明时标记 stale、不固化未知，下轮重探', async () => {
  let authCalls = 0;
  const client = makeYdpcClient(
    [],
    async () => [runningVm()],
    async () => { authCalls++; throw new Error('getFirmAuth 网络异常'); }
  );
  await client.refreshVms();
  assert.equal(client.account.vms[0].vendorProbeStale, true);
  assert.equal(client.account.vms[0].vendor, undefined);
  await client.refreshVms();
  assert.equal(authCalls, 2);
  assert.equal(client.account.vms[0].vendorProbeStale, true);
});

test('refreshVms：探测成功后跳过探测，路由由 spuCode 重建', async () => {
  let authCalls = 0;
  const withSpu = { ...runningVm(), spuCode: 'zte-cloud-pc' };
  const client = makeYdpcClient(
    [],
    async () => [{ ...withSpu }],
    async () => { authCalls++; return { cagIp: '1.2.3.4', cagPort: 443 }; }
  );
  await client.refreshVms();
  assert.equal(client.account.vms[0].vendor, 'ZTE');
  assert.equal(client.account.vms[0].vendorProbeStale, false);
  assert.equal(authCalls, 1);
  await client.refreshVms();
  assert.equal(authCalls, 1, '判定成功后第二轮不得再调 getFirmAuth');
  assert.equal(client.account.vms[0].vendor, 'ZTE');
  assert.equal(client.account.vms[0]._route.kind, 'ZTE');
});

test('refreshVms：失败一次后恢复 → 重探成功，随后跳过', async () => {
  let authCalls = 0;
  const client = makeYdpcClient(
    [],
    async () => [runningVm()],
    async () => {
      authCalls++;
      if (authCalls === 1) throw new Error('getFirmAuth 网络异常');
      return { cagIp: '1.2.3.4', cagPort: 443 };
    }
  );
  await client.refreshVms();
  assert.equal(client.account.vms[0].vendorProbeStale, true);
  await client.refreshVms();
  assert.equal(client.account.vms[0].vendorProbeStale, false);
  assert.equal(client.account.vms[0].vendor, 'ZTE');
  const callsAfterSuccess = authCalls;
  await client.refreshVms();
  assert.equal(authCalls, callsAfterSuccess, '成功后第三轮不得再调 getFirmAuth');
});
