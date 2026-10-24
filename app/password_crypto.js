/**
 * 账号密码 AES-256-GCM 加解密（缺陷修复 G8，从 server.js 抽出以便单测）。
 * 旧实现缺陷：
 * - encryptPassword 加密异常时 catch 后返回明文，调用方无感知地把明文落盘。
 * - decryptPassword 解密失败时返回密文本身，下游拿着乱码当密码去登录，
 *   故障被伪装成"密码错误"，密钥丢失/损坏完全无声。
 * 新口径：加密失败抛错（由 saveConfig 的断言与 try/catch 拦截，绝不落盘明文）；
 * 解密失败记 error 日志并返回 ''（调用方据空值走"密码不可用"路径）。
 */
const crypto = require('crypto');

function createPasswordCrypto(masterKey, { onError = () => {} } = {}) {
  function encryptPassword(plainText) {
    if (!plainText || typeof plainText !== 'string') return '';
    if (plainText.startsWith('ENC:')) return plainText; // 避免重复加密
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', masterKey, iv);
    let enc = cipher.update(plainText, 'utf8', 'hex');
    enc += cipher.final('hex');
    const authTag = cipher.getAuthTag().toString('hex');
    return 'ENC:' + iv.toString('hex') + ':' + authTag + ':' + enc;
  }

  function decryptPassword(cipherText) {
    if (!cipherText || typeof cipherText !== 'string') return '';
    if (!cipherText.startsWith('ENC:')) return cipherText; // 兼容历史明文
    try {
      const parts = cipherText.split(':');
      if (parts.length !== 4) throw new Error('密文格式异常');
      const iv = Buffer.from(parts[1], 'hex');
      const authTag = Buffer.from(parts[2], 'hex');
      const encrypted = parts[3];
      const decipher = crypto.createDecipheriv('aes-256-gcm', masterKey, iv);
      decipher.setAuthTag(authTag);
      let dec = decipher.update(encrypted, 'hex', 'utf8');
      dec += decipher.final('utf8');
      return dec;
    } catch (e) {
      // 密钥丢失/不匹配/密文损坏：绝不把密文当密码返回，记日志并返回空
      onError(`密码解密失败（可能主密钥丢失或密文损坏）: ${e.message}`);
      return '';
    }
  }

  return { encryptPassword, decryptPassword };
}

module.exports = { createPasswordCrypto };
