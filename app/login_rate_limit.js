/**
 * 登录失败限速器（内存版，缺陷修复 G4：旧实现登录接口无任何限速，可无限撞库）。
 *
 * 口径：同一 (IP, 用户名) 在滑动窗口内失败达到上限即拦截；成功登录清零；
 * IP 取连接远端地址（req.socket.remoteAddress），不采信可伪造的 X-Forwarded-For
 * （反代部署时应在反代层终止并改由部署方注入可信头，属部署决策）。
 * 时钟可注入以便单测。
 */
class LoginRateLimiter {
  constructor({ maxFailures = 10, windowMs = 10 * 60 * 1000, nowFn = () => Date.now() } = {}) {
    this.maxFailures = maxFailures;
    this.windowMs = windowMs;
    this.nowFn = nowFn;
    this.failures = new Map(); // key -> number[] (timestamps)
  }

  _key(ip, username) {
    return `${ip || ''}|${String(username || '').toLowerCase()}`;
  }

  _prune(key) {
    const arr = this.failures.get(key);
    if (!arr) return [];
    const cutoff = this.nowFn() - this.windowMs;
    const kept = arr.filter(t => t > cutoff);
    if (kept.length === 0) this.failures.delete(key);
    else this.failures.set(key, kept);
    return kept;
  }

  isBlocked(ip, username) {
    return this._prune(this._key(ip, username)).length >= this.maxFailures;
  }

  recordFailure(ip, username) {
    const key = this._key(ip, username);
    const kept = this._prune(key);
    kept.push(this.nowFn());
    this.failures.set(key, kept);
    // 内存上限保护：键过多时顺带清扫已过期键
    if (this.failures.size > 10000) {
      for (const k of [...this.failures.keys()]) this._prune(k);
    }
  }

  recordSuccess(ip, username) {
    this.failures.delete(this._key(ip, username));
  }
}

module.exports = { LoginRateLimiter };
