'use strict';

/**
 * ============================================================================
 * 移动云底座路由判定 + 失败分级（纯函数层 · 零网络 · 零凭据 · 零副作用）
 * ============================================================================
 *
 * 设计口径：**只读官方接口返回的字段，不携带任何协议常量 / 凭据 / 指纹**。
 *
 *   G1 底座闸门 —— SCG / ZTE / ERROR 三分类互斥一次判定，无回落分支；
 *      底座自动判定，不提供手选。
 *      目的：在**拨号之前**确定这台机器走哪套底座；判不出来就明确拒绝，
 *      而不是"默认当成 ZTE 去盲拨"。今天 `vm.vendor` 只用于界面展示，
 *      **从未被任何执行路径当过闸门** —— 于是一台 SCG 机器每轮都在被
 *      ZTE 握手盲拨。G1 修的就是这个。
 *
 *   G2 软 / 硬失败分级（软失败 / 硬失败 / 未执行 三分类）。目的：把
 *      "会话过期（可重登重试）" / "已知非致命（维护、升级、时长耗尽、已关机、限流）" /
 *      "真异常" 分开，既不把一次维护窗口当成链路熔断，也不把过期会话静默吞掉。
 *
 * ---------------------------------------------------------------------------
 * 🔒 红线（由 tests/regression.test.js 组 7 / 21 / 22 机械拦截）
 * ---------------------------------------------------------------------------
 *   本文件严禁出现：
 *     ✗ 任何第三方协议常量、RSA 公钥、客户端 ID（如 sc-user-… / SC_RSA_PK_… /
 *       cdpsdk-server-*）—— 一律不得写入本仓库；
 *     ✗ 任何凭据读写、网络请求、TLS 校验开关（rejectUnauthorized 等）；
 *     ✗ 任何硬编码的官方 IP —— DNS 才是唯一正确入口（见 AI 对话第七根因：
 *       DNS 含 114.114.114.114 会让专网域名解析出错误结果）。
 *   本文件只做**字符串判定**，输入是调用方已经拿到的对象，输出是纯数据。
 *
 * ---------------------------------------------------------------------------
 * 为什么 spuCode 优先于 firm-auth（这不是"叠加信号"，是**防误判**）
 * ---------------------------------------------------------------------------
 *   firm-auth 的 `scAuthCode && !cagIp` 规则会把一台 ZTE 机器误判成 SCG：
 *   cagIp 只在机器被拉起后才由网关下发，**空闲/刚关机的 ZTE 机器 cagIp 为空**，
 *   若此时 scAuthCode 非空就会被误判成 SCG。而 `spuCode` 是账号级静态属性，
 *   不随机器开关机漂移 —— 先看它，就能挡住这类瞬时误判。
 *   两者都判不出来（或互相矛盾且都无权威值）时才落到 UNKNOWN，**拒绝猜测**。
 */

// ---------------------------------------------------------------------------
// 官方口径：SPU 编码 → 底座（这是唯一的"权威"信号）
// ---------------------------------------------------------------------------
// ZTE 前缀在实测样本上为 `zte-cloud-pc`。
// 【2026-09-26 现场样本】`sc-cloud-pc` 已由真机证实：爱家样本账号两台家庭云电脑
// （畅享版 / 高级版）的 `spuCode` 均为 `sc-cloud-pc`，且其 firm-auth 材料里
// **只有 scgIp/scgTcpPort/scAuthCode、没有 cagIp/connectStr** —— 即典型的 SCG 底座。
// 早期这里写过"它只是保守占位，遇到就明确拒绝"，那句话已随 SCG 通道落地而失效，见 git 历史。
const SPU_ZTE = /^zte[-_]/i;
const SPU_SCG = /^sc[-_]cloud[-_]pc/i;

/**
 * 判定一台云电脑的底座路由。纯函数：不读全局、不写外部、不抛异常。
 *
 * @param {object} vm        云电脑对象（只用 spuCode / vmName / skuName 做诊断文案）
 * @param {object|null} firmAuth  账号级 firm-auth 凭据字段（可为 null，表示未取到）
 * @returns {{kind:'ZTE'|'SCG'|'UNKNOWN', supported:boolean, source:'spuCode'|'firmAuth'|'none', reason:string}}
 *   - kind      : 判定结果
 *   - supported : 本系统**是否实现了该底座的保活通道**。
 *                 ZTE（raw ZTEC / TLS+CAGMux）与 SCG（trunk+SPICE，app/ydpc/scg_keepalive.js）
 *                 **均已实现** ⇒ 两者都为 true；只有 UNKNOWN 为 false。
 *   - source    : 该判定来自哪一级信号（便于日志溯源，不参与业务分支）
 *   - reason    : 面向人的中文原因串（直接进日志 / 界面提示）
 */
function resolveVmRoute(vm, firmAuth) {
  const v = vm || {};
  const spu = String(v.spuCode || '').trim();
  const a = firmAuth || null;
  const spuText = spu ? `spuCode=${spu}` : 'spuCode 为空';

  // ── 第一级：官方 SPU 编码（权威信号，不随开关机漂移） ─────────────────
  if (spu && SPU_ZTE.test(spu)) {
    return { kind: 'ZTE', supported: true, source: 'spuCode', reason: spuText };
  }
  if (spu && SPU_SCG.test(spu)) {
    return {
      kind: 'SCG',
      supported: true,
      source: 'spuCode',
      reason: `${spuText}（SCG 通道：不引入 CEM/第三方客户端身份，直接用 firm-auth 下发的 scgIp/scAuthCode）`
    };
  }

  // ── 第二级：账号 firm-auth 字段（沿用既有在用规则，保持行为等价） ─────
  if (a) {
    const hasScg = !!a.scAuthCode && !a.cagIp;
    const hasZte = !!(a.cagIp || a.vmUserName || a.vmcIp);
    const suffix = spu ? `（${spuText} 未登记，回退 firm-auth）` : '';
    if (hasScg) {
      return {
        kind: 'SCG',
        supported: true,
        source: 'firmAuth',
        reason: `scAuthCode 非空且 cagIp 为空${suffix}（SCG 通道：走 firm-auth 的 scgIp/scAuthCode）`
      };
    }
    if (hasZte) {
      return {
        kind: 'ZTE',
        supported: true,
        source: 'firmAuth',
        reason: `firm-auth 字段齐备${suffix}`
      };
    }
  }

  // ── 两级信号都不足：拒绝猜测（这是 G1 的核心价值） ────────────────────
  return {
    kind: 'UNKNOWN',
    supported: false,
    source: spu ? 'spuCode' : (a ? 'firmAuth' : 'none'),
    reason: `${spuText}、firm-auth 字段均不足 —— 拒绝猜测底座`
  };
}

/**
 * 把路由判定转成本系统既有的 vendor / vendorName 展示口径（单一真源，避免多处手写中文）。
 */
function routeVendorLabel(route) {
  if (route && route.kind === 'ZTE') return { vendor: 'ZTE', vendorName: '中兴 ZTE' };
  if (route && route.kind === 'SCG') return { vendor: 'SCG', vendorName: '深信服 SCG' };
  return { vendor: 'UNKNOWN', vendorName: '底座未知' };
}

/**
 * 闸门判定：拨号前调用。
 *
 * ⚠️ 刻意设计成 **fail-open**：`route` 为空（从未判定过）时放行。
 * 理由：判定由 refreshVms 负责且结果随 `_` 前缀跨刷新保留，正常路径上闸门运行时
 * `route` 必定已存在；若因探测通道本身失败而暂时没有判定，贸然阻断会把一次
 * 瞬时网络故障固化成"永久拒绝保活"。**只有拿到明确的"不支持"结论才阻断。**
 *
 * ✅ 为什么这道闸门**不可能误伤今天能正常工作的机器**（这是它敢阻断的前提）：
 *   · ZTE 侧：CAG 握手（`pingCag` → `performCagAuthHold`）与动态取公钥都**必须有 `cagIp`**，
 *     而 `cagIp` 非空 ⇒ firm-auth 第二级直接判 ZTE ⇒ 放行。
 *   · SCG 侧：firm-auth 的 `scAuthCode && !cagIp` ⇒ 判 SCG，且 SCG 通道已实现 ⇒ 放行。
 *   换言之：**凡是我们的通道今天真能拨通的机器，今天就走在"放行"分支上**，
 *   闸门对它们零影响。会被拦下的只剩"连 spuCode 与 firm-auth 都判不出底座"的
 *   UNKNOWN —— 那类机器本来也必拨必失败。
 *
 * @param {object|null|undefined} route
 * @returns {{ allow:boolean, reason:string }}
 */
function routeGate(route) {
  if (!route) return { allow: true, reason: '' };
  if (route.supported === true) return { allow: true, reason: '' };
  return { allow: false, reason: `底座不支持：${route.kind}（${route.reason}）` };
}

// ---------------------------------------------------------------------------
// G2 · 失败分级
// ---------------------------------------------------------------------------
// 三类的语义（判据取自**本仓库自己产生**的错误串）：
//   tokenRetry : 会话 / token 失效 → 重新登录一次后重试即可，不当成链路故障
//   soft       : 已知非致命 → 只告警、不熔断（维护、升级、时长耗尽、已关机、限流）
//   hard       : 兜底 —— 含 TLS / DNS / 网络层故障与一切未知错误
// **顺序即优先级**：tokenRetry → hard → soft。hard 必须排在 soft 之前，
// 否则 `CERT_HAS_EXPIRED`（证书到期，真问题）会被 `/到期/` 误判为"套餐到期"这类软失败。
const TOKEN_RETRY_PATTERNS = [
  /1000100/,                        // CSAP 用户会话已失效（官方归类为可重试）
  /\b4001\b/, /\b4003\b/,           // SOHO：token 过期 / 用户未登录
  /未登录/, /未授权/, /鉴权失败/, /登录失效/, /已失效/, /会话/,
  /重新登录/, /unauthorized/i, /\b401\b/,
  /token/i, /accessToken/i
];

const HARD_PATTERNS = [
  // TLS / 证书（注意：必须在 soft 之前命中，否则 CERT_HAS_EXPIRED 会被 /到期/ 误吞）
  /CERT_/i, /UNABLE_TO_VERIFY/i, /self[-_ ]?signed/i, /证书/,
  // DNS
  /ENOTFOUND/i, /EAI_AGAIN/i, /\bDNS\b/i, /getaddrinfo/i,
  // 网络层
  /ECONNREFUSED/i, /ECONNRESET/i, /EPIPE/i, /ETIMEDOUT/i,
  /EHOSTUNREACH/i, /ENETUNREACH/i, /socket hang up/i,
  // 超时
  /超时/, /timeout/i
];

const SOFT_PATTERNS = [
  /用完/, /已用尽/, /计费周期/, /欠费/, /时长/,   // 套餐时长耗尽 / 受限
  /到期/,                                        // 套餐到期
  /维护/, /升级/,                                // 平台维护窗口
  /已关机/, /未开机/, /关机/,                    // 机器本就不在运行
  /启动中/, /正在启动/, /启动时间过长/,          // 启动尚未完成
  /\bbusy\b/i, /too many/i, /限流/, /频繁/, /稍后重试/, /请稍候/, /\b104\b/
];

/**
 * 把一条错误文本分级。纯函数；空 / 非字符串输入一律返回 'hard'（fail-safe：
 * 不确定就当硬失败，宁可多报一次也绝不把真故障静默降级）。
 *
 * @param {string} text
 * @returns {'tokenRetry'|'soft'|'hard'}
 */
function classifyZteError(text) {
  const s = String(text == null ? '' : text).trim();
  if (!s) return 'hard';
  for (const p of TOKEN_RETRY_PATTERNS) { if (p.test(s)) return 'tokenRetry'; }
  for (const p of HARD_PATTERNS) { if (p.test(s)) return 'hard'; }
  for (const p of SOFT_PATTERNS) { if (p.test(s)) return 'soft'; }
  return 'hard';
}

/**
 * 失败分级 → 是否应当熔断（停止本轮后续拨号）。
 * 三类的分流口径：tokenRetry 与 soft 都**不熔断**（前者重登重试、后者只告警），
 * 只有 hard 需要把本轮标记为异常。
 */
function shouldTripBreaker(kind) {
  return kind === 'hard';
}

// ---------------------------------------------------------------------------
// G5 · 地址族路由（connectStr 内层主机 → 该走哪条数据面通道）
// ---------------------------------------------------------------------------
// 为什么必须**在拨号之前**判定，而不是让拨号函数自己去撞：
//   既有 `zte_cag_raw.js` 只实现了 IPv6 raw 路径，它的 `ipv6ToBytes()` 遇到 IPv4
//   字面量会抛 `非法 IPv6 段` —— 而那一抛发生在 `sock.on('data')` 回调内，
//   **不在 Promise 链上**：既成为未捕获异常，又让返回的 Promise 一直挂到 15s 超时。
//   于是这台机器的失败既不是 tokenRetry 也不是 soft/hard，而是**绕过了 G2 分级**。
//   把判定提到拨号之前，这类机器才会得到一句可分级、可留证的明确结论。
//
// 判据：**只看 connectStr 内层主机有没有冒号**。
//   · 含 `:`      ⇒ IPv6 字面量 ⇒ raw ZTEC（50B 短头 + 220B blob，不升 TLS）
//   · 点分四段十进制 ⇒ IPv4 字面量 ⇒ TLS + CAGMux + raw SPICE
//   · 其余（空串 / 主机名 / 畸形）⇒ 明确拒绝，不猜
// 官方 connectStr 对同一次取材料会**同时**给 `-h`（IPv4）与 `--hv6`（IPv6），
// 因此地址族是「每台每次取材料」的属性，**不是账号属性** —— 不得按账号一刀切。

/**
 * 点分四段十进制 IPv4 字面量判定。
 * 刻意手写字符判定而不用正则 —— 本文件被组 23 用
 * `/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/` 反向锁死"不得出现 IP 字面量"，
 * 手写形态连"看起来像 IP 的模式串"都不会出现，从机制上不可能误伤。
 */
function isIpv4Literal(s) {
  const parts = String(s).split('.');
  if (parts.length !== 4) return false;
  for (const p of parts) {
    if (p.length < 1 || p.length > 3) return false;
    for (let i = 0; i < p.length; i++) {
      const c = p.charCodeAt(i);
      if (c < 48 || c > 57) return false; // 仅 ASCII 数字
    }
    if (Number(p) > 255) return false;
  }
  return true;
}

/**
 * 判定内层主机应走哪条数据面通道。纯函数：不读全局、不写外部、不抛异常。
 *
 * @param {string} innerHost  connectStr 解出的内层主机（`--hv6` / `-h`）
 * @returns {{path:'raw'|'tls'|'reject', family:'ipv6'|'ipv4'|'unknown', reason:string}}
 *   - path   : 'raw'    → 走现有 dialCagTcpRaw + keepaliveRawZtecLoop
 *              'tls'    → 走 dialCagTcpTls + CAGMux + raw SPICE
 *              'reject' → 明确拒绝（不得"先按 raw 试一下"）
 *   - reason : 面向人的中文原因串（直接进日志 / 界面提示）
 */
function resolveInnerRoute(innerHost) {
  const host = String(innerHost == null ? '' : innerHost).trim();
  if (!host) {
    return { path: 'reject', family: 'unknown', reason: 'connectStr 未解出内层主机' };
  }
  // 剥 IPv6 zone（fe80::1%eth0 形态，WAN 上不出现但协议允许）
  const bare = host.includes('%') ? host.slice(0, host.indexOf('%')) : host;
  if (bare.includes(':')) {
    return { path: 'raw', family: 'ipv6', reason: '内层主机为 IPv6 字面量 ⇒ raw ZTEC 通道' };
  }
  if (isIpv4Literal(bare)) {
    return {
      path: 'tls',
      family: 'ipv4',
      reason: '内层主机为 IPv4 字面量 ⇒ TLS + CAGMux + raw SPICE 通道'
    };
  }
  // 主机名 / 畸形 ⚠️ 不得"按 IPv4 试一下"：blob 的 IPv4 编码会当场抛错，
  // 而那条错误无法与"地址确实不对"区分开，会把排查引向错误方向。
  return {
    path: 'reject',
    family: 'unknown',
    reason: `内层主机既非 IPv4 也非 IPv6 字面量（${host}），拒绝猜测通道`
  };
}

// ---------------------------------------------------------------------------
// 重启恢复 · 由已持久化的 vendor 重建路由判定
// ---------------------------------------------------------------------------
// 【2026-09-26 修复 fail-open 空洞】底座判定的**输入**（`vendor` / `vendorName` /
// `spuCode` / `vendorProbeStale`）都会落盘，而判定的**结果** `vm._route` 带 `_` 前缀
// （本机运行时状态）**不落盘**。于是进程重启后出现一个致命组合：
//     vendor 还在 → needProbe=false → refreshVms 里那段判定整体被跳过
//     → vm._route 永远是 undefined → routeGate(null) 命中 fail-open 放行
//     → 一台 SCG 机器照样被 ZTE 握手盲拨（每 30s 抛「cagIp 缺失，无法开机」）。
// 实测证据：爱家样本账号两台 `spuCode=sc-cloud-pc`（家庭云电脑畅享版/高级版）。
//
// 为什么按 vendor 重建**不是猜**：`vendor` 是**上一次权威判定**的产物
// （要么来自 spuCode，要么来自真探测过的 firm-auth），只是它被持久化了而
// `_route` 没有。重建等于把"已持久化的结论"翻译回判定对象，信息量不增不减。
//
// @param {string} vendor 已持久化的 vendor（'ZTE' / 'SCG' / 'UNKNOWN' / 其它）
// @returns {{kind:'ZTE'|'SCG'|'UNKNOWN', supported:boolean, source:'persisted', reason:string}}
function routeFromPersistedVendor(vendor) {
  const v = String(vendor == null ? '' : vendor).trim();
  if (v === 'ZTE') {
    return {
      kind: 'ZTE',
      supported: true,
      source: 'persisted',
      reason: '由已持久化的 vendor=ZTE 重建判定'
    };
  }
  if (v === 'SCG') {
    return {
      kind: 'SCG',
      supported: true,
      source: 'persisted',
      reason: '由已持久化的 vendor=SCG 重建判定'
    };
  }
  // 认不出的 vendor（含空）⇒ 明确判 UNKNOWN 并**拒绝**：宁可如实说"底座未知"，
  // 也不能默认放行去盲拨 —— 那正是本函数要堵的那个洞。
  return {
    kind: 'UNKNOWN',
    supported: false,
    source: 'persisted',
    reason: `已持久化的 vendor=${v || '(空)'} 无法映射到底座 —— 拒绝猜测`
  };
}

module.exports = {
  SPU_ZTE,
  resolveInnerRoute,
  isIpv4Literal,
  SPU_SCG,
  resolveVmRoute,
  routeFromPersistedVendor,
  routeVendorLabel,
  routeGate,
  classifyZteError,
  shouldTripBreaker,
  TOKEN_RETRY_PATTERNS,
  HARD_PATTERNS,
  SOFT_PATTERNS
};
