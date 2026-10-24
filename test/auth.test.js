const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { AuthManager, validatePasswordPolicy } = require('../app/auth_manager.js');
const { LoginRateLimiter } = require('../app/login_rate_limit.js');

function makeAuth() {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ctyun-auth-test-'));
  const configManager = {
    config: { users: [], accounts: [], settings: { allowRegistration: true, defaultQuota: 2 } },
    dataDir,
    saveConfig() {},
    sessionStore: null,
  };
  return new AuthManager(configManager);
}

test('validatePasswordPolicy: 统一最小长度 8', () => {
  assert.ok(validatePasswordPolicy('1234567'));
  assert.equal(validatePasswordPolicy('12345678'), null);
  assert.ok(validatePasswordPolicy(''));
  assert.ok(validatePasswordPolicy(12345678));
  assert.ok(validatePasswordPolicy('x'.repeat(129)));
});

test('register: 弱密码被拒（旧实现无任何策略）', () => {
  const am = makeAuth();
  const r = am.register('alice', 'short');
  assert.equal(r.success, false);
  const ok = am.register('alice', 'long-enough-1');
  assert.equal(ok.success, true);
});

test('改密吊销其他会话：keepToken 保留当前会话，其余全部失效（旧实现零吊销）', () => {
  const am = makeAuth();
  const reg = am.register('bob', 'first-password');
  const uid = reg.user.id;
  const t1 = am.login('bob', 'first-password').token;
  const t2 = am.login('bob', 'first-password', true).token;
  assert.ok(am.verifySession(t1) && am.verifySession(t2));
  am.updateUserPassword(uid, 'second-password', { keepToken: t1 });
  assert.ok(am.verifySession(t1), '当前会话应保留');
  assert.equal(am.verifySession(t2), null, '其他会话必须吊销');
  assert.equal(am.login('bob', 'first-password').success, false);
  assert.equal(am.login('bob', 'second-password').success, true);
});

test('管理员重置（无 keepToken）吊销该用户全部会话', () => {
  const am = makeAuth();
  const reg = am.register('carol', 'first-password');
  const t1 = am.login('carol', 'first-password').token;
  am.updateUserPassword(reg.user.id, 'reset-password');
  assert.equal(am.verifySession(t1), null);
});

test('changeOwnPassword: 必须验证当前密码（旧路由完全不验）', () => {
  const am = makeAuth();
  const reg = am.register('dave', 'first-password');
  const uid = reg.user.id;
  const bad = am.changeOwnPassword(uid, 'wrong-current', 'second-password');
  assert.equal(bad.success, false);
  const weak = am.changeOwnPassword(uid, 'first-password', 'short');
  assert.equal(weak.success, false);
  const keep = am.login('dave', 'first-password').token;
  const other = am.login('dave', 'first-password').token;
  const ok = am.changeOwnPassword(uid, 'first-password', 'second-password', keep);
  assert.equal(ok.success, true);
  assert.ok(am.verifySession(keep));
  assert.equal(am.verifySession(other), null);
});

test('LoginRateLimiter: 10 次失败后拦截、窗口过期恢复、成功清零', () => {
  let now = 1_000_000;
  const rl = new LoginRateLimiter({ nowFn: () => now });
  for (let i = 0; i < 9; i++) rl.recordFailure('1.2.3.4', 'eve');
  assert.equal(rl.isBlocked('1.2.3.4', 'eve'), false);
  rl.recordFailure('1.2.3.4', 'eve');
  assert.equal(rl.isBlocked('1.2.3.4', 'eve'), true);
  assert.equal(rl.isBlocked('1.2.3.4', 'frank'), false, '按 IP+用户名隔离');
  assert.equal(rl.isBlocked('5.6.7.8', 'eve'), false);
  now += 10 * 60 * 1000 + 1;
  assert.equal(rl.isBlocked('1.2.3.4', 'eve'), false, '窗口过期应恢复');
  rl.recordFailure('1.2.3.4', 'eve');
  rl.recordSuccess('1.2.3.4', 'eve');
  assert.equal(rl.isBlocked('1.2.3.4', 'eve'), false);
});
