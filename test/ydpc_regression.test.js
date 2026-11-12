'use strict';
// ydpc 保活路径行为回归测试（深查第 24 轮新建；第 26 轮补齐组 7 / 13 / 23）。
//
// 背景：app/ydpc/product_route.js 与 ydpc_client.js 曾引用 tests/regression.test.js
// （组 7/13/21/22/23）作红线拦截，但该路径并不在仓内——这些行为此前零测试覆盖，
// 第 21 轮的 originCn（核验采样结束后抛 ReferenceError、报告永不返回）正是漏网实例。
// 第 26 轮定为修引用：回归测试的正本就是本文件——npm test 只跑 test/*.test.js，
// 另建 tests/regression.test.js 不会被执行，还会造成两处回归测试分叉漂移；
// 组 7 / 13 / 23 在本轮补齐后，上述引用里的组号全部有测试对应。
// 本文件为第 20/21/22 轮修的三处缺陷补行为回归测试；不触网、不碰真实凭据，全部用桩。
const { test } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
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

// --- 第 26 轮：组 7 —— product_route.js 红线静态扫描 --------------------------
// product_route.js 自称“纯函数层 · 零网络 · 零凭据 · 零副作用”，注释里举例用
// 的违禁串（sc-user-… / SC_RSA_PK_… / 114.114.114.114 等）本身就长在注释里，
// 所以必须先去注释再扫描，否则测试会被自己的说明文字误伤。
// 注意：token 字样不在禁列——G2 分级用 /token/i 等模式串给错误信息分类，
// 那是字符串判定，不是读凭据。

function stripComments(src) {
  return src
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/(^|[^:'"\\])\/\/.*$/gm, '$1');
}

test('组 7：product_route.js 代码层不得出现协议常量/密钥/凭据读写/网络/TLS 开关', () => {
  const src = fs.readFileSync(path.join(__dirname, '..', 'app', 'ydpc', 'product_route.js'), 'utf8');
  const code = stripComments(src);
  // 去注释没把代码本身剥掉的自检
  assert.match(code, /function resolveVmRoute/);
  assert.match(code, /function isIpv4Literal/);
  const forbidden = [
    [/sc-user-/, '第三方客户端 ID 前缀 sc-user-'],
    [/SC_RSA_PK/, 'RSA 公钥常量 SC_RSA_PK'],
    [/cdpsdk-server/, '第三方客户端 ID cdpsdk-server'],
    [/-----BEGIN/, 'PEM 密钥块'],
    [/process\.env/, '读环境变量（凭据入口）'],
    [/\bpassword\b/i, 'password 字样'],
    [/\bpasswd\b/i, 'passwd 字样'],
    [/readFile|writeFile/, '文件读写'],
    [/\bfetch\s*\(/, 'fetch 网络请求'],
    [/axios/, 'axios 网络请求'],
    [/https?\.request\s*\(/, 'http(s).request 网络请求'],
    [/net\.connect\s*\(/, 'net.connect 网络请求'],
    [/tls\.connect\s*\(/, 'tls.connect 网络请求'],
    [/rejectUnauthorized/, 'TLS 校验开关'],
  ];
  for (const [re, label] of forbidden) {
    assert.doesNotMatch(code, re, `product_route.js 代码层不得出现：${label}`);
  }
});

// --- 第 26 轮：组 13 —— startKeepAliveWorker 行为测试 -------------------------
// 约束 ①：启动流程必须被行为测试真实执行一次（实例化 + 调用），仅靠“符号存在”
// 的静态断言抓不到运行期 ReferenceError；约束 ②：附加的核验看门狗坏掉绝不允
// 许拖垮主保活循环。测试内同步立即 stop，避免 2 秒后 runCycle 真跑起来。

test('组 13：startKeepAliveWorker 看门狗抛错也不拖垮主循环（实例化 + 真实调用）', () => {
  const logs = [];
  const acc = {
    id: 'probe13', name: 'probe13', user: '13800000000', password: 'x',
    deviceCode: 'web_probe', platform: 'ydpc', features: { keepAlive: true }, stats: {},
    vms: [runningVm()],
  };
  const client = new YdpcClient(acc, {
    appendLog: (...args) => { logs.push(args.join(' ')); },
    sendNotification: () => {},
    saveConfig: () => {},
  });
  client.startEffectWatchdog = () => { throw new Error('watchdog boom'); };
  try {
    assert.doesNotThrow(() => client.startKeepAliveWorker());
    assert.equal(client.workerRunning, true, '看门狗抛错后主循环仍应标记为已启动');
    assert.notEqual(client.loopTimer, null, '看门狗抛错后首次 runCycle 仍应被排程');
    const firstTimer = client.loopTimer;
    client.startKeepAliveWorker();
    assert.equal(client.loopTimer, firstTimer, '重复启动应被 workerRunning 守卫直接拦下');
    assert.ok(logs.some((l) => l.includes('看门狗启动失败')), '应记录看门狗启动失败的告警日志');
  } finally {
    client.stopKeepAliveWorker();
  }
  assert.equal(client.workerRunning, false);
  assert.equal(client.loopTimer, null);
});

// --- 第 26 轮：组 23 —— IP 字面量反向锁 + keepaliveProven 恒 false -------------
// product_route.js 刻意用手写字符判定实现 isIpv4Literal（不用正则），正是为了
// 让本测试的 IP 字面量模式串在去注释后的代码里永远匹配不到；一旦有人把判定
// 改成正则字面量、或往代码里写死官方 IP，本测试立即变红。

test('组 23：product_route.js 去注释后不得出现 IP 字面量模式串', () => {
  const src = fs.readFileSync(path.join(__dirname, '..', 'app', 'ydpc', 'product_route.js'), 'utf8');
  const code = stripComments(src);
  assert.match(code, /function isIpv4Literal/);
  assert.doesNotMatch(code, /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/, '代码层不得出现 IP 字面量（含正则字面量形态）');
});

test('组 23：ydpc_client.js 的 keepaliveProven 恒为 false 字面量（变异 M56）', () => {
  const src = fs.readFileSync(path.join(__dirname, '..', 'app', 'ydpc', 'ydpc_client.js'), 'utf8');
  const assignments = [...src.matchAll(/keepaliveProven\s*:\s*([^\s,}]+)/g)];
  assert.ok(assignments.length >= 1, '应至少有一处 keepaliveProven 赋值');
  for (const m of assignments) {
    assert.equal(m[1], 'false', 'keepaliveProven 只能是 false 字面量，严禁改成运行时推导');
  }
});

// --- 第 27 轮：组 13（续）—— 启动失败且日志也写失败时仍完成回滚 ----------------
// A/B 对照的 A：本测试先于修复落盘，在未修复代码上应失败——
// appendLog 首调即抛（模拟磁盘落盘失败）时，startKeepAliveWorker 内层
// appendLog 在 workerRunning=true 之后抛错，走外层 catch 回滚；回滚里的
// appendLog 同样抛错，未修复时该异常会原样抛回调用方。

test('组 13：startKeepAliveWorker 启动失败且日志也写失败时仍完成回滚、不抛回调用方', () => {
  const acc = {
    id: 'probe13b', name: 'probe13b', user: '13800000000', password: 'x',
    deviceCode: 'web_probe', platform: 'ydpc', features: { keepAlive: true }, stats: {},
    vms: [runningVm()],
  };
  const client = new YdpcClient(acc, {
    appendLog: () => { throw new Error('disk full'); },
    sendNotification: () => {},
    saveConfig: () => {},
  });
  assert.doesNotThrow(() => client.startKeepAliveWorker());
  assert.equal(client.workerRunning, false, '回滚后 workerRunning 必须复位为 false');
  assert.equal(client.loopTimer, null, '回滚后不得残留已排程的循环定时器');
  // 回滚后守卫不再锁死，下轮可再次尝试启动（而不是永久静默停摆）
  assert.doesNotThrow(() => client.startKeepAliveWorker());
  assert.equal(client.workerRunning, false);
  assert.equal(client.loopTimer, null);
});
