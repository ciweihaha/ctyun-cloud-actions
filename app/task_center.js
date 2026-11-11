'use strict';

/**
 * 官方任务中心（getTaskList / getUserPoints）响应码判定（深查第 10 轮）。
 *
 * 背景：server.js refreshOfficialTasks 是全部完成判定的唯一事实来源
 * （scheduler evaluateAccountCompletion、executeNativeSign、
 * executeNativeHang、browserHang 均以它为准；刷新失败时一律按 UNKNOWN
 * 处理，绝不用旧缓存判完成）。旧实现 `taskRes.code === 0` /
 * `=== 40010` 只认数字码；同系接口已证实存在字符串码型
 * （native_tasks getTicket 分支兼容 40010/'40010'）。若任务中心回
 * `{code:"0"}`，旧实现会整轮判刷新失败：签到不认领、AI 不跑、挂机
 * 不启动，三个 +100 全被搁置，只因码型不同。
 * 新口径：数字与等值数字字符串同义；缺失/非数字码仍判失败，与旧实现一致。
 *
 * 本模块为纯函数：server.js 直接 require 会拉起整服务（含建密钥、
 * 读配置、挂调度器），无法单测；判定逻辑抽出以便单测，server.js 只做装配。
 */

function normalizeBusinessCode(code) {
  if (typeof code === 'number') return code;
  if (typeof code === 'string' && code.trim() !== '') {
    const n = Number(code.trim());
    if (Number.isFinite(n)) return n;
  }
  return code;
}

/** 凭据过期：归一化码 40010，或 msg 含过期文案（后两项与旧实现原样一致）。 */
function isTaskCenterExpired(taskRes) {
  if (!taskRes || typeof taskRes !== 'object') return false;
  if (normalizeBusinessCode(taskRes.code) === 40010) return true;
  const msg = String(taskRes.msg || '');
  return msg.includes('登录信息已过期') || msg.includes('会话已过期');
}

/** 任务列表可用：归一化码为 0 且 data 存在。 */
function isTaskListOk(taskRes) {
  return !!taskRes && typeof taskRes === 'object' &&
    normalizeBusinessCode(taskRes.code) === 0 && !!taskRes.data;
}

/** 积分接口可用：归一化码为 0 且 data 为非空数组。 */
function isPointsOk(pointRes) {
  return !!pointRes && typeof pointRes === 'object' &&
    normalizeBusinessCode(pointRes.code) === 0 &&
    Array.isArray(pointRes.data) && pointRes.data.length > 0;
}

module.exports = { normalizeBusinessCode, isTaskCenterExpired, isTaskListOk, isPointsOk };
