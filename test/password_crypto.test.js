const { test } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { createPasswordCrypto } = require('../app/password_crypto.js');

const key = crypto.randomBytes(32);

test('加解密往返与格式', () => {
  const { encryptPassword, decryptPassword } = createPasswordCrypto(key);
  const enc = encryptPassword('p@ssw0rd-密码');
  assert.ok(enc.startsWith('ENC:'));
  assert.equal(decryptPassword(enc), 'p@ssw0rd-密码');
  assert.equal(encryptPassword(''), '');
  assert.equal(encryptPassword(enc), enc, '已加密不得重复加密');
  assert.equal(decryptPassword('legacy-plain'), 'legacy-plain', '历史明文兼容');
});

test('加密失败必须抛错，绝不回退明文（核心回归）', () => {
  const bad = createPasswordCrypto(Buffer.alloc(10)); // 非法密钥长度
  assert.throws(() => bad.encryptPassword('secret'));
});

test('解密失败返回空并触发 onError，绝不返回密文本身（核心回归）', () => {
  const errors = [];
  const a = createPasswordCrypto(key);
  const enc = a.encryptPassword('topsecret');
  const b = createPasswordCrypto(crypto.randomBytes(32), { onError: (m) => errors.push(m) });
  assert.equal(b.decryptPassword(enc), '');
  assert.equal(errors.length, 1);
  assert.equal(b.decryptPassword('ENC:bad:format:xx:yy'), '');
});

test('密钥丢失场景：saveConfig 式断言可拦截明文落盘', () => {
  // 模拟 saveConfig：加密产物必须全部以 ENC: 开头，否则中止写入
  const bad = createPasswordCrypto(Buffer.alloc(10));
  assert.throws(() => {
    const out = ['pw1'].map(p => bad.encryptPassword(p));
    for (const v of out) if (!v.startsWith('ENC:')) throw new Error('plaintext');
  });
});
