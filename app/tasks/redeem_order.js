/**
 * 自动兑换下单（重试策略独立成模块，供隔离测试注入 fetch/sleep）。
 *
 * 策略（缺陷修复 S11）：
 * - 拿到**明确业务响应**（响应体 JSON 可解析）：code===0 为成功；致命业务错误
 *   （积分不足 / 风控 / 频繁 / 上限等，服务端明确拒绝）立即终止并标记 risk_blocked / failed；
 *   其他业务错误有限重试 —— 服务端已明确答复未受理，重试不会重复下单。
 * - **结果不明确**（fetch 抛错、响应体解析失败、网络中断）：服务端可能已经受理订单，
 *   客户端无从判断 —— 绝不盲目重试，立即停止并返回 unknown，交人工核对。
 *   （本仓库没有订单状态查询接口，无法在重试前自动核对订单状态；
 *    旧实现对网络异常与业务失败一视同仁重试 3 次，存在「已受理但响应丢失 → 重复扣积分」风险。）
 */

const FATAL_MARKERS = ['积分不足', '点数不足', '余额不足', '风控', '频繁', '异常操作', '超过最大', '上限'];
const RISK_MARKERS = ['风控', '频繁', '异常操作'];

function isFatalBusinessError(msg) {
  return FATAL_MARKERS.some(m => String(msg || '').includes(m));
}

function isRiskBusinessError(msg) {
  return RISK_MARKERS.some(m => String(msg || '').includes(m));
}

/**
 * @param {object} opts
 * @param {function} opts.fetchFn - (url, init) => Promise<{ json(): Promise<any> }>
 * @param {string} opts.url
 * @param {object} opts.payload
 * @param {object} opts.headers
 * @param {number} [opts.maxBusinessRetries=3] - 仅对明确业务错误的总尝试次数
 * @param {function} [opts.sleepFn] - (ms) => Promise
 * @param {function} [opts.onAttempt] - (attempt, info) => void 日志回调
 * @returns {Promise<{status:'success'|'failed'|'unknown'|'risk_blocked', msg:string, attempts:number}>}
 */
async function attemptRedeemOrder(opts) {
  const fetchFn = opts.fetchFn;
  const sleepFn = opts.sleepFn || ((ms) => new Promise(r => setTimeout(r, ms)));
  const maxAttempts = Math.max(1, opts.maxBusinessRetries || 3);
  const onAttempt = opts.onAttempt || (() => {});
  let lastMsg = '';

  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    if (attempt > 1) {
      onAttempt(attempt, { phase: 'retry' });
      await sleepFn(3000);
    }
    let data;
    try {
      const res = await fetchFn(opts.url, {
        method: 'POST',
        headers: opts.headers,
        body: JSON.stringify(opts.payload),
      });
      data = await res.json();
    } catch (e) {
      // 结果不明确：可能已受理。绝不重试。
      return { status: 'unknown', msg: `网络异常，结果不明确（可能已受理）: ${(e && e.message) || e}`, attempts: attempt };
    }
    if (data && data.code === 0) {
      return { status: 'success', msg: 'OK', attempts: attempt };
    }
    lastMsg = (data && data.msg) || `错误码 ${data && data.code}`;
    if (isFatalBusinessError(lastMsg)) {
      return {
        status: isRiskBusinessError(lastMsg) ? 'risk_blocked' : 'failed',
        msg: lastMsg,
        attempts: attempt,
      };
    }
    onAttempt(attempt, { phase: 'business_error', msg: lastMsg });
  }
  return { status: 'failed', msg: lastMsg, attempts: maxAttempts };
}

module.exports = { attemptRedeemOrder, isFatalBusinessError, isRiskBusinessError };
