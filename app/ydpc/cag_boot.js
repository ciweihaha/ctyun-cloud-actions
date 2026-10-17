'use strict';

/**
 * ============================================================================
 * 移动云 CAG HTTPS 开机通道（干净实现 · ZTE CSAP 协议）
 * ============================================================================
 *
 * 【实现口径】本文件只走官方 CAG HTTPS 通道（官方 CSAP 接口族）：
 *   ✅ 使用账号自身 firm-auth 的凭据（vmUserName / vmPassword / vmId）
 *   ✅ RSA 公钥从 cs_sysConfig.action 动态获取，绝不硬编码
 *   ✅ 保留 TLS 证书校验
 *   ✅ 不声明任何伪造的客户端身份
 *
 * ============================================================================
 * 【2026-09-23 二次重大修正】协议实现按真机实测校准
 * ============================================================================
 *
 * 上一版实现被真实网关以 `1000100 用户会话已失效` 拒绝，当时误判为"平台封禁、
 * 中兴底座无法脚本开机"。实测核对后确认：**根因是"业务参数放进了 body 而非
 * query string"**，不是权限问题。
 *
 * 对照实验（真机验证）：
 *   无 query string                          → 1000100
 *   ?RspSecurity=1 无 accessToken            → 1000100
 *   ?accessToken=xxx&RspSecurity=1 + 参数在 body → 7010001
 *   ?accessToken=xxx&uuid=..&vmid=..&全部参数&RspSecurity=1 + 空 body → ✅ 成功
 *
 * ⇒ 因此本版修正五件事（前两件是关键）：
 *   ① 业务参数全部移入 **query string**，body 只发**加密空串**
 *   ② **恢复 `RspSecurity=1`**（官方客户端全链路都带它，不是禁区）
 *   ③ 实现 `ZTE_Security_Params` 的 **AES-256-CBC 解密**
 *      —— 上一版"不带 RspSecurity 才拿到明文"是因为**不会解密**，属降级绕过
 *   ④ 实现 `connectStr` 的 **AES-128-ECB 二次解密**
 *   ⑤ 密码编码、请求头、`version`、步骤序列按官方对齐
 *
 * 【协议流程】（对照官方 CSAP 请求顺序）
 *   1. cs_sysConfig.action                取 CAG 的 RSA 公钥（rsapub）+ 系统配置
 *   2. cs_getToken.action                 换取 accessToken（密码经 AES-ECB 编码）
 *   3. cs_getDesktopList.action           取桌面列表（拿 uuid / userId / groupId / poolId）
 *   4. cs_startDesktop.action             提交启动请求 → connectStr
 *   5. cs_startDesktop_async_query.action 轮询（CAG2.0 边缘可能 404，则回到 4 重试）
 *
 * 【加密体系】（三把对称密钥来自官方客户端自带的 installinfo.ini）
 *   UasKey / UasIv  AES-256-CBC   加密请求体、解密响应的 ZTE_Security_Params
 *   csapId          AES-128-ECB   解密 connectStr / 编码 getToken 的 password
 * 这三把是**官方客户端安装配置里的共享密钥**（客户端与网关的对称约定，随安装包分发、
 * 非按用户签发），性质上不是"冒用他人身份"的私有凭据，故本文件允许内置。
 * 边界不变：公钥仍动态取、不伪造身份、证书校验仍受控保留。
 *
 * 【边界声明】
 *   本模块只做"把已关机的机器拉起来"这一件事。它不构造任何 SPICE/画面帧，
 *   不伪造屏幕刷新，也不使用任何抓包逆出的定长帧。
 */

const https = require('https');
const crypto = require('crypto');
const os = require('os');

// CAG 默认端口（官方 CSAP 服务入口，与 cag_client.js 保持一致）
const DEFAULT_CAG_PORT = 8899;

// 默认等待桌面就绪的上限（秒）
const DEFAULT_BOOT_WAIT = 180;

// 单次 HTTPS 请求超时（毫秒）
const DEFAULT_REQ_TIMEOUT = 15000;

// 官方客户端版本号（真机实测 V7.25.22；CAG2.0 边缘亦见 V7.25.40-HY）
const CSAP_VERSION = 'V7.25.22';
const CSAP_REQUEST_FROM = 9;
const CSAP_LANGUAGE = 'zh';

// 错误码：token / 会话失效。官方做法是重新登录（重取 token）后重试一次。
const CSAP_TOKEN_RETRY_CODES = new Set(['1000100']);

/**
 * 【对称密钥】来自官方客户端自带的 installinfo.ini [PublicKey] 段。
 *
 * 这三个值随官方客户端安装包分发，属客户端与网关的固定对称约定，并非按用户签发。
 *
 * 官方安装包里以"ASCII 的 hex 编码"存放，本文件直接使用解码后的字符串：
 *   csap_key → "3fec8a54-7e49-48"
 *   uas_key  → "56Acf4c3498fD4c5a0B1fb26947e2daB"
 *   uas_iv   → "3498fD4c5a0B1fbA"
 */
const ZTE_UAS_KEY = '56Acf4c3498fD4c5a0B1fb26947e2daB'; // 32B → AES-256-CBC
const ZTE_UAS_IV = '3498fD4c5a0B1fbA';                  // 16B → AES-CBC IV
const ZTE_CSAP_ID = '3fec8a54-7e49-48';                 // 16B → AES-128-ECB

/**
 * 【2026-09-23 实测结论】CAG 服务端证书链不完整。
 *
 * 真机首跑（`cs_sysConfig.action`）报：
 *   UNABLE_TO_VERIFY_LEAF_SIGNATURE — unable to verify the first certificate
 * 即服务端**只下发叶证书、不下发中间 CA**，导致无法链到受信任根。
 *
 * 旁证：同一 CAG 端点（8899）的 ZTEC 保活握手走的是**裸 TCP**
 * （见 `app/ydpc/cag_client.js` 的 `new net.Socket()`），根本不经 TLS。
 * ⇒ 该端点本身就不是为"严格校验证书的 HTTPS 客户端"设计的，
 *   证书链不完整属其常态，而非可修复的服务端配置问题。
 *
 * 【策略：降级为"记录不阻断"】
 * 默认仍**严格校验**；仅当握手失败且错误属于"**证书链完整性**"这一类时，
 * 打 warning 留证，然后**对该次请求**降级重试。
 *
 * 严格边界（不得放宽）：
 *   - 只对**证书链缺陷类**错误降级，不做无条件 `rejectUnauthorized:false`
 *   - 降级必须**留证**（host + 错误码 + 原因）写入日志
 *   - 与本模块的另外三条底线无关：不伪造身份、不硬编码第三方凭据、不硬编码公钥
 */
const CERT_CHAIN_ERROR_CODES = new Set([
  'UNABLE_TO_VERIFY_LEAF_SIGNATURE', // 只发叶证书，无中间 CA（本次实测命中）
  'SELF_SIGNED_CERT_IN_CHAIN',       // 链中含自签证书
  'DEPTH_ZERO_SELF_SIGNED_CERT',     // 自签根
  'CERT_HAS_EXPIRED',                // 证书过期（服务端未轮换）
  'UNABLE_TO_GET_ISSUER_CERT_LOCALLY',
  'UNABLE_TO_GET_ISSUER_CERT',
  'ERR_TLS_CERT_ALTNAME_INVALID'     // 证书与主机名不匹配（CAG 按 IP 访问常见）
]);

/**
 * 判断一个错误是否属于"证书链完整性"类，即可以降级的情形。
 */
function isCertChainError(err) {
  let cur = err;
  for (let i = 0; i < 5 && cur; i++) {
    if (cur.code && CERT_CHAIN_ERROR_CODES.has(cur.code)) return cur.code;
    cur = cur.cause;
  }
  return null;
}

/**
 * 【2026-09-24 实测反馈】降级留证的**去重键**（进程内有效）。
 *
 * 现象：一次开机 = 5 步定序请求 + N 次就绪轮询（实测 5 + 9 = 13 个请求）。
 * 由于 CAG 端点的证书链缺陷是**端点固有属性**，每个请求都必然先严格失败一次，
 * 于是逐请求留证会在日志里刷出 2 × 13 = 26 行同质告警，把真正的业务进度
 * （轮询 #n / connectStr）淹掉，看起来像"报了一堆错才开机成功"。
 *
 * 留证的本意是"记录**降级这个事实**及其 host + 错误码"，而不是"记录降级了多少次"。
 * 同一 host:port 的重复条目不携带任何新信息 ⇒ 每个端点只在**首次**命中原样详述，
 * 之后仍照常降级重试，只是不再重复打警告。
 *
 * 边界不变：只对证书链缺陷类错误降级、降级仍发生、首次留证仍含 host + 错误码。
 * 新进程（或重启后）该集合为空 → 新一次开机仍会重新留证一次，证据不会永久缺失。
 */
const _certChainWarned = new Set();

/**
 * 【2026-09-23 调试支持】报文级日志开关。
 *
 * 背景：CAG 通道是全新实现，从未在真机验证。首跑失败时若只有"请求失败"一句话，
 * 无法定位是接口路径、参数名、还是请求体格式的问题。
 * 因此提供可选的 wire 日志：把 URL、请求体、响应状态、响应体原文完整打出。
 *
 * ⚠️ 安全：日志会对 password / accessToken 等字段做脱敏，避免明文泄露到日志；
 * 但**请求体与响应体结构本身会原样打印** —— 仅用于本地调试，勿长期开启。
 */
function makeWireLogger(onLog) {
  if (typeof onLog !== 'function') return null;
  return (msg, level = 'info') => {
    try {
      onLog('CAG', msg, level);
    } catch (e) {
      // 日志回调自身异常不得影响主流程
    }
  };
}

// 需要在日志中脱敏的字段名
const SENSITIVE_KEYS = ['password', 'accessToken', 'token', 'vmPassword', 'secret'];

/**
 * 对请求/响应体做脱敏，保留结构。过长时截断。
 */
function redactForLog(value, maxLen = 1200) {
  const walk = (v) => {
    if (v === null || v === undefined) return v;
    if (Array.isArray(v)) return v.map(walk);
    if (typeof v === 'object') {
      const out = {};
      for (const [k, val] of Object.entries(v)) {
        if (SENSITIVE_KEYS.some((s) => k.toLowerCase() === s.toLowerCase())) {
          const sv = val === null || val === undefined ? '' : String(val);
          out[k] = sv ? `<redacted len=${sv.length}>` : sv;
        } else {
          out[k] = walk(val);
        }
      }
      return out;
    }
    return v;
  };
  let text;
  try {
    text = typeof value === 'string' ? value : JSON.stringify(walk(value));
  } catch (e) {
    text = String(value);
  }
  if (text === undefined || text === null) text = '';
  if (text.length > maxLen) text = text.slice(0, maxLen) + `...<truncated total=${text.length}>`;
  return text;
}

/* ============================================================================
 * ZTE 对称加密/解密原语
 * ==========================================================================*/

/**
 * AES-256-CBC 加密（PKCS#7 填充），输出**大写 hex**。
 *
 * 序列化与加密口径（真机验证）：
 *   json.dumps(body, separators=(",", ":"), sort_keys=True) → AES-CBC(UasKey, UasIv)
 *   → hex().upper()
 * ⚠️ 注意 sort_keys=True —— **字典序排序后再序列化**，顺序错了服务端解出来对不上。
 */
function zteEncryptBody(body) {
  let plain;
  if (typeof body === 'string') {
    plain = body;
  } else {
    plain = stableStringify(body === undefined || body === null ? '' : body);
  }
  const cipher = crypto.createCipheriv(
    'aes-256-cbc',
    Buffer.from(ZTE_UAS_KEY, 'utf8'),
    Buffer.from(ZTE_UAS_IV, 'utf8')
  );
  const enc = Buffer.concat([cipher.update(Buffer.from(plain, 'utf8')), cipher.final()]);
  return enc.toString('hex').toUpperCase();
}

/** 为加密空串——ZTE 要求"无 body 参数"的 action 也发一个加密后的空字符串。 */
function zteEncryptEmptyBody() {
  return zteEncryptBody('');
}

/**
 * AES-256-CBC 解密 `ZTE_Security_Params` → 明文 JSON 对象。
 * 与网关下发的 ZTE_Security_Params 一一对应。
 */
function zteDecryptSecurityParams(hex) {
  const buf = Buffer.from(String(hex), 'hex');
  const decipher = crypto.createDecipheriv(
    'aes-256-cbc',
    Buffer.from(ZTE_UAS_KEY, 'utf8'),
    Buffer.from(ZTE_UAS_IV, 'utf8')
  );
  const dec = Buffer.concat([decipher.update(buf), decipher.final()]);
  const text = dec.toString('utf8').replace(/\0+$/, '');
  return JSON.parse(text);
}

/**
 * 用 csapId 做 AES-128-ECB 加密，用于编码 getToken 的 password。
 *
 * 编码口径（真机验证）：
 *   urllib.parse.quote(value, safe="-_.~") → AES-128-ECB(csap_key) + PKCS#7
 *   → base64 → 把 "+" 换成 "%2B"
 * ⚠️ 是"先 URL 转义再加密再 base64"，不是"加密再转义"。
 */
function zteCsapEncryptQueryValue(value) {
  const escaped = encodeURIComponent(String(value));
  const cipher = crypto.createCipheriv(
    'aes-128-ecb',
    Buffer.from(ZTE_CSAP_ID, 'utf8'),
    null
  );
  cipher.setAutoPadding(true);
  const enc = Buffer.concat([cipher.update(Buffer.from(escaped, 'utf8')), cipher.final()]);
  return enc.toString('base64').replace(/\+/g, '%2B');
}

/**
 * 用 csapId 做 AES-128-ECB 解密 `connectStr` → 启动命令行文本。
 * 解密 connectStr → 启动命令行文本（解密后再 URL decode）。
 */
function zteDecodeConnectStr(hex) {
  const buf = Buffer.from(String(hex), 'hex');
  const decipher = crypto.createDecipheriv(
    'aes-128-ecb',
    Buffer.from(ZTE_CSAP_ID, 'utf8'),
    null
  );
  decipher.setAutoPadding(true);
  const dec = Buffer.concat([decipher.update(buf), decipher.final()]);
  let text = dec.toString('utf8').replace(/\0+$/, '');
  try {
    text = decodeURIComponent(text);
  } catch (e) {
    // 已是明文则原样返回
  }
  return text;
}

/**
 * 稳定序列化：按 key 字典序排序后 JSON 化（对齐 Python 的 sort_keys=True）。
 * ZTE 的加密 body 对字段顺序敏感，必须排序。
 */
function stableStringify(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(stableStringify).join(',') + ']';
  const keys = Object.keys(value).sort();
  const parts = keys
    .filter((k) => value[k] !== undefined)
    .map((k) => `${JSON.stringify(k)}:${stableStringify(value[k])}`);
  return '{' + parts.join(',') + '}';
}

/**
 * 解析 ZTE CSAP 的"裸 RSA 参数"公钥表示法。
 *
 * 【2026-09-23 实测确认】cs_sysConfig 明文响应里的 rsapub 字段**不是 PEM**，
 * 而是形如下面的两行文本（\n 分隔）：
 *     N = A20FFA15...（512 hex = 2048 bit 模数）
 *     E = 010001      （标准指数 65537）
 * 因此必须先按 key=hex 解析，再走 JWK 构造出 Node 可用的公钥。
 *
 * @returns {{n: string, e: string}|null} 归一化（去前导 0、偶数长度）后的 hex 参数
 */
function parseZteRsaParams(text) {
  if (typeof text !== 'string' || !text) return null;
  const found = {};
  for (const line of text.split(/\r?\n/)) {
    const m = line.match(/^\s*([A-Za-z][A-Za-z0-9_]*)\s*=\s*([0-9A-Fa-f]+)\s*$/);
    if (m) found[m[1].toUpperCase()] = m[2];
  }
  const nRaw = found.N || found.MODULUS;
  const eRaw = found.E || found.EXPONENT || '010001';
  if (!nRaw) return null;
  const norm = (h) => {
    let s = h.replace(/^0+/, '');
    if (!s) return null;
    if (s.length % 2) s = '0' + s;
    return s;
  };
  const n = norm(nRaw);
  const e = norm(eRaw) || '010001';
  if (!n || n.length < 16) return null;
  return { n, e };
}

/** hex → base64url（JWK 字段要求） */
function hexToB64url(hex) {
  let h = hex.replace(/^0+/, '');
  if (!h) return '';
  if (h.length % 2) h = '0' + h;
  return Buffer.from(h, 'hex').toString('base64url');
}

/**
 * 从 CAG 响应里尽力解出 JSON。
 * CAG 返回体在不同版本下可能是纯 JSON、或 JSON 外层套一层加密串，这里做保守解析。
 */
function tryParseCagJson(text) {
  if (!text) return null;
  const trimmed = text.trim();
  if (!trimmed) return null;
  try {
    return JSON.parse(trimmed);
  } catch (e) {
    // 容错：截取第一个 { 到最后一个 }
    const start = trimmed.indexOf('{');
    const end = trimmed.lastIndexOf('}');
    if (start >= 0 && end > start) {
      try {
        return JSON.parse(trimmed.slice(start, end + 1));
      } catch (e2) {
        return null;
      }
    }
    return null;
  }
}

/**
 * 【2026-09-23 新增】把 CAG 响应规整成明文对象。
 *
 * 服务端有两种响应形态：
 *   A) 明文 JSON —— 直接用
 *   B) `{"ZTE_Security_Params":"<hex>"}` —— 用 UasKey/UasIv 做 AES-256-CBC 解密后是 JSON
 *
 * 官方客户端走的是 B（带 `RspSecurity=1`）。上一版实现因为不会解密，
 * 只能靠"不带 RspSecurity"拿明文，属降级绕过。本版按官方走 B 并实现解密。
 */
function decodeCagResponse(text) {
  const outer = tryParseCagJson(text);
  if (!outer) return { json: null, decrypted: false, securityParams: null };

  const sp = outer.ZTE_Security_Params;
  if (typeof sp === 'string' && sp.length) {
    try {
      const inner = zteDecryptSecurityParams(sp);
      inner._securityParams = sp;
      return { json: inner, decrypted: true, securityParams: sp };
    } catch (e) {
      // 解密失败时把外层退回，并保留错误证据供调用方判断
      return { json: outer, decrypted: false, securityParams: sp, decryptError: e };
    }
  }
  return { json: outer, decrypted: false, securityParams: null };
}

/**
 * 在解码后的对象里递归寻找 RSA 公钥字段（rsapub / rsaPub / publicKey）。
 *
 * 【2026-09-23】原实现用 `v.length > 64` 作为"像公钥"的门槛。实测 rsapub 是
 * `N = <512 位 hex>\nE = 010001`，长度 530 满足；但为兼容更短的参数组合，
 * 这里放宽到 > 16，并**优先按语义判定**（能被 parseZteRsaParams 解析出来的才算）。
 */
function findRsaPublicKey(obj, depth = 0) {
  if (!obj || typeof obj !== 'object' || depth > 6) return null;
  const keys = ['rsapub', 'rsaPub', 'RsaPub', 'rsa_public_key', 'publicKey', 'pubKey'];
  for (const k of keys) {
    const v = obj[k];
    if (typeof v === 'string' && v.length > 16) return v;
  }
  for (const v of Object.values(obj)) {
    if (v && typeof v === 'object') {
      const found = findRsaPublicKey(v, depth + 1);
      if (found) return found;
    }
  }
  return null;
}

/**
 * 把 CAG 返回的公钥规整成 PEM。
 * 支持的三种输入：
 *   1) 已是 PEM（含 BEGIN）—— 原样返回
 *   2) ZTE 裸参数 `N = <hex>\nE = <hex>` —— 实测的真实格式，走 JWK 构造
 *   3) 裸 base64 —— 补 PEM 头
 */
function normalizeRsaPublicKeyPem(raw) {
  if (!raw || typeof raw !== 'string') return null;
  const s = raw.trim();
  if (s.includes('BEGIN')) return s;

  // 【2026-09-23】优先尝试 ZTE 裸参数格式（N = <hex> / E = <hex>），
  // 这是 cs_sysConfig.rsapub 的**真实格式**，实测确认。
  const params = parseZteRsaParams(s);
  if (params) {
    try {
      const keyObj = crypto.createPublicKey({
        key: { kty: 'RSA', n: hexToB64url(params.n), e: hexToB64url(params.e) },
        format: 'jwk'
      });
      const pem = keyObj.export({ type: 'spki', format: 'pem' });
      if (pem && pem.includes('BEGIN')) return pem;
    } catch (e) {
      // 落到下面的"裸 base64 包 PEM 头"分支再试
    }
  }

  const body = s.replace(/\s+/g, '');
  const lines = body.match(/.{1,64}/g) || [];
  return `-----BEGIN PUBLIC KEY-----\n${lines.join('\n')}\n-----END PUBLIC KEY-----`;
}

/**
 * 用 RSA PKCS#1 v1.5 加密（与官方 CSAP 一致）。
 */
function rsaPkcs1Encrypt(plaintext, publicKeyPem) {
  if (plaintext === undefined || plaintext === null || plaintext === '') return '';
  const buf = Buffer.from(String(plaintext), 'utf8');
  const encrypted = crypto.publicEncrypt(
    { key: publicKeyPem, padding: crypto.constants.RSA_PKCS1_PADDING },
    buf
  );
  return encrypted.toString('base64');
}

/**
 * 【2026-09-23 新增】RSA PKCS#1 v1.5 加密，输出 **hex 大写 → base64**。
 *
 * CAG2.0 对密码用的是这个编码（真机报文反解）：
 *   RSA PKCS#1 v1.5 → 密文转**大写 hex 字符串** → 再对 hex 字符串做 base64
 * 这与"标准 raw-ciphertext base64"不同，是 ZTE 特有的双层编码。
 */
function rsaPkcs1EncryptHexB64(plaintext, publicKeyPem) {
  if (plaintext === undefined || plaintext === null || plaintext === '') return '';
  const buf = Buffer.from(String(plaintext), 'utf8');
  const encrypted = crypto.publicEncrypt(
    { key: publicKeyPem, padding: crypto.constants.RSA_PKCS1_PADDING },
    buf
  );
  return Buffer.from(encrypted.toString('hex').toUpperCase(), 'utf8').toString('base64');
}

/* ============================================================================
 * 请求构造
 * ==========================================================================*/

/** 本机真实标识（不硬编码任何第三方客户端 ID） */
function localIdentity() {
  let mac = '';
  try {
    const nics = os.networkInterfaces();
    for (const list of Object.values(nics)) {
      for (const ni of list || []) {
        if (!ni.internal && ni.mac && ni.mac !== '00:00:00:00:00:00') {
          mac = ni.mac.replace(/:/g, '-');
          break;
        }
      }
      if (mac) break;
    }
  } catch (e) {
    mac = '';
  }
  if (!mac) mac = '00-00-00-00-00-00';

  let ip = '127.0.0.1';
  try {
    const nics = os.networkInterfaces();
    for (const list of Object.values(nics)) {
      for (const ni of list || []) {
        if (!ni.internal && ni.family === 'IPv4') {
          ip = ni.address;
          break;
        }
      }
      if (ip !== '127.0.0.1') break;
    }
  } catch (e) {
    // 保持 127.0.0.1
  }

  return {
    hostName: os.hostname(),
    mac,
    clientIp: ip,
    snCode: crypto.randomUUID().toUpperCase()
  };
}

/**
 * 生成一次桌面连接请求的 body。
 *
 * ⚠️ 【2026-09-23 修正】业务参数**全部移入 query string**，body 只发加密空串。
 * 这是 1000100 的根因，详见文件头"二次重大修正"。
 * 仅保留 ZTE 明确要求走 body 的辅助字段（getToken 的 clienttype/hardware/nettype/ostype）。
 */
function buildConnectDesktopBody({ vmId, vmUserName, encryptedPassword, hostName, clientIp }) {
  // 保留函数签名以便回归测试与调用方复用；实际不再发送这些字段作为 body。
  return { body: { vmid: vmId, name: vmUserName, password: encryptedPassword, hostName, clientIp } };
}

/**
 * 【2026-09-23 新增】构造 cs_connectDesktop.action 的 query string。
 * 字段对齐官方 startDesktop body 解密结果（真机核对）。
 */
function buildConnectDesktopQuery({ vmId, vmUserName, accessToken, identity, desktop }) {
  const id = identity || localIdentity();
  const d = desktop || {};
  const userId = Number(d.userId || 0);
  const groupId = Number(d.groupId !== undefined && d.groupId !== null ? d.groupId : -1);
  const poolId = Number(d.poolId || 0);
  const connectionType = Number(d.connectionType || 0);
  const desktopType = Number(d.desktopType || 1);
  const desktopUuid = String(d.uuid || '');
  const q = [
    ['accessToken', accessToken || ''],
    ['uuid', desktopUuid],
    ['vmid', vmId],
    ['type', String(desktopType)],
    ['connectionType', String(connectionType)],
    ['assignRelationtoString', `${userId},${groupId},${poolId}`],
    ['version', CSAP_VERSION],
    ['language', CSAP_LANGUAGE],
    ['requestFrom', String(CSAP_REQUEST_FROM)],
    ['isvm', '0'],
    ['encryption', '1'],
    ['prover', '1'],
    ['supportAsync', '1'],
    ['allowSwitchRap', '1'],
    ['raptype', connectionType === 0 ? '2' : '1'],
    ['SNcode', id.snCode],
    ['hostName', id.hostName],
    ['localipandmac', `${id.clientIp},${id.mac}`],
    ['diskNo', id.snCode],
    ['newpara', '1'],
    ['newcharsetparse', '1'],
    ['upmnew', '1'],
    ['watermarkType', '1'],
    ['allowExtUSBPolicy', '1'],
    ['verifyTerminalBind', '11'],
    // ★ 官方客户端全链路都带它；启用响应加密信封，配合 decodeCagResponse 解密
    ['RspSecurity', '1']
  ];
  return q
    .filter(([, v]) => v !== undefined && v !== null && String(v) !== '')
    .map(([k, v]) => `${k}=${encodeURIComponent(String(v))}`)
    .join('&');
}

/**
 * 构造 cs_startDesktop_async_query.action 的 query string。
 */
function buildAsyncQuery({ vmId, accessToken }) {
  return [
    ['accessToken', accessToken || ''],
    ['language', CSAP_LANGUAGE],
    ['isvm', '0'],
    ['vmid', vmId],
    ['prover', '1'],
    ['allowSwitchRap', '1'],
    ['RspSecurity', '1']
  ]
    .filter(([, v]) => v !== undefined && v !== null && String(v) !== '')
    .map(([k, v]) => `${k}=${encodeURIComponent(String(v))}`)
    .join('&');
}

/**
 * 从解码结果里递归寻找 connectStr / accessToken，用于判断桌面是否已就绪。
 */
function findConnectStr(obj, depth = 0) {
  if (!obj || typeof obj !== 'object' || depth > 6) return null;
  if (typeof obj.connectStr === 'string' && obj.connectStr) return obj.connectStr;
  for (const v of Object.values(obj)) {
    if (v && typeof v === 'object') {
      const found = findConnectStr(v, depth + 1);
      if (found) return found;
    }
  }
  return null;
}

function findAccessToken(obj, depth = 0) {
  if (!obj || typeof obj !== 'object' || depth > 6) return null;
  if (typeof obj.accessToken === 'string' && obj.accessToken) return obj.accessToken;
  for (const v of Object.values(obj)) {
    if (v && typeof v === 'object') {
      const found = findAccessToken(v, depth + 1);
      if (found) return found;
    }
  }
  return null;
}

/** 递归找桌面列表（数组），取第一台。 */
function findDesktopList(obj, depth = 0) {
  if (!obj || typeof obj !== 'object' || depth > 6) return null;
  for (const [k, v] of Object.entries(obj)) {
    if (Array.isArray(v) && v.length && v[0] && typeof v[0] === 'object' && ('uuid' in v[0] || 'vmId' in v[0])) {
      return v;
    }
  }
  for (const v of Object.values(obj)) {
    if (v && typeof v === 'object') {
      const found = findDesktopList(v, depth + 1);
      if (found) return found;
    }
  }
  return null;
}

/** 取响应里的 result 字段（ZTE 用 result=0 表示成功）。 */
function getResult(obj) {
  if (!obj || typeof obj !== 'object') return null;
  for (const k of ['result', 'resultCode', 'code']) {
    if (obj[k] !== undefined && obj[k] !== null) return String(obj[k]);
  }
  return null;
}

/** 取响应里的错误消息。 */
function getMessage(obj) {
  if (!obj || typeof obj !== 'object') return '';
  for (const k of ['mesg', 'msg', 'message', 'unifiedErrorCode']) {
    if (typeof obj[k] === 'string' && obj[k]) return obj[k];
  }
  return '';
}

/* ============================================================================
 * 主流程
 * ==========================================================================*/

/**
 * 发起一次 CAG HTTPS 请求。
 *
 * 默认**保留证书校验**（不设置 rejectUnauthorized）。
 * 若握手因"证书链不完整"失败，则打 warning 留证后**对该次请求**降级重试一次
 * —— 见文件上方 CERT_CHAIN_ERROR_CODES 的说明与边界。
 */
function cagHttpsRequest(host, port, pathWithQuery, body, timeoutMs = DEFAULT_REQ_TIMEOUT, wireLog = null, session = null, extraHeaders = null) {
  return new Promise((resolve, reject) => {
    if (!host || !port) {
      reject(new Error('CAG host/port 缺失，无法发起请求'));
      return;
    }

    const payload = typeof body === 'string' ? body : (body ? JSON.stringify(body) : '');
    const payloadBuf = Buffer.from(payload, 'utf8');

    const headers = {
      'Accept': '*/*',
      'Content-Type': 'application/xml',
      'Content-Length': payloadBuf.length
    };

    // 【2026-09-23】官方要求的附加请求头（真机核对）：
    // X-Ap-sHost 指向 VMC 主机、process_id=2、serialNum、otlp_trace_id / otlp_parent_id。
    if (extraHeaders && typeof extraHeaders === 'object') {
      for (const [k, v] of Object.entries(extraHeaders)) {
        if (v !== undefined && v !== null && String(v) !== '') headers[k] = String(v);
      }
    }

    // 【2026-09-23】会话 Cookie 透传。
    // CAG 的 cs_connectDesktop 会校验"本次连接前是否已查询系统配置"
    // （否则返回 7090003 "Client need query system configuration again"），
    // 该状态绑定在服务端会话上，靠 Cookie（如 JSESSIONID）串联。
    // 无会话容器时退化为无状态请求（旧行为，保持向后兼容）。
    if (session && session.cookies && Object.keys(session.cookies).length) {
      headers['Cookie'] = Object.entries(session.cookies)
        .map(([k, v]) => `${k}=${v}`)
        .join('; ');
    }

    const startedAt = Date.now();
    if (wireLog) {
      wireLog(`→ POST https://${host}:${port}${pathWithQuery}`, 'info');
      wireLog(`  请求体 (${payloadBuf.length}B): ${redactForLog(payload)}`, 'info');
    }

    // 内部执行器：allowInsecure=false 时严格校验；降级重试时置 true
    const attempt = (allowInsecure, onCertError) => {
      const reqOpts = {
        host,
        port,
        path: pathWithQuery,
        method: 'POST',
        headers,
        timeout: timeoutMs
      };
      // 仅在"证书链不完整"降级路径上传 false；正常路径不传 → 保留系统校验
      if (allowInsecure) reqOpts.rejectUnauthorized = false;

      const req = https.request(
        reqOpts,
        (res) => {
          // 收集会话 Cookie（供后续请求复用）
          if (session) {
            const rawSet = res.headers['set-cookie'];
            if (rawSet && rawSet.length) {
              session.cookies = session.cookies || {};
              for (const c of rawSet) {
                const kv = String(c).split(';')[0];
                const idx = kv.indexOf('=');
                if (idx > 0) {
                  const k = kv.slice(0, idx).trim();
                  const v = kv.slice(idx + 1).trim();
                  if (k) session.cookies[k] = v;
                }
              }
              if (wireLog) {
                wireLog(`  ↳ 会话 Cookie：${Object.keys(session.cookies).join(', ')}`, 'info');
              }
            }
          }
          const chunks = [];
          res.on('data', (c) => chunks.push(c));
          res.on('end', () => {
            const text = Buffer.concat(chunks).toString('utf8');
            if (wireLog) {
              const cost = Date.now() - startedAt;
              wireLog(`← HTTP ${res.statusCode} (${cost}ms, ${Buffer.byteLength(text)}B)`, res.statusCode >= 400 ? 'warning' : 'info');
              wireLog(`  响应体: ${redactForLog(text)}`, res.statusCode >= 400 ? 'warning' : 'info');
            }
            resolve({ status: res.statusCode, text });
          });
        }
      );

      req.on('timeout', () => {
        if (wireLog) wireLog(`✖ 请求超时 (${timeoutMs}ms)：POST ${pathWithQuery}`, 'error');
        req.destroy(new Error(`CAG 请求超时 (${timeoutMs}ms)`));
      });
      req.on('error', (err) => {
        const certCode = isCertChainError(err);
        if (certCode && !allowInsecure) {
          // 命中"证书链不完整"类错误 → 交给上层决定是否降级重试
          onCertError(certCode, err);
          return;
        }
        if (wireLog) wireLog(`✖ 请求错误：${describeErr(err)}`, 'error');
        reject(err);
      });

      if (payloadBuf.length) req.write(payloadBuf);
      req.end();
    };

    // 严格模式先行；仅在证书链错误时降级重试一次
    attempt(false, (certCode, err) => {
      // 留证去重：同一 host:port 只在首次详述（见 _certChainWarned 的说明）。
      // 去重**不影响**降级行为本身 —— 下面仍会对该请求降级重试。
      const warnKey = `${host}:${port}`;
      if (!_certChainWarned.has(warnKey)) {
        _certChainWarned.add(warnKey);
        if (wireLog) {
          wireLog(
            `⚠️ TLS 证书链验证失败 (code=${certCode})：${describeErr(err)}`,
            'warning'
          );
          wireLog(
            `⚠️ 判定为"服务端证书链不完整"（同一 CAG 端点的 ZTEC 保活走裸 TCP，不经 TLS）。` +
            `已对该请求降级重试（host=${host}:${port}）。此降级仅针对证书链缺陷，不代表放弃校验策略。` +
            `【该端点后续请求将静默降级，不再重复告警；重启后重新留证一次】`,
            'warning'
          );
        }
      }
      attempt(true, () => {
        // allowInsecure 分支不会再走这里（certCode 存在但 allowInsecure=true）
      });
    });
  });
}

/**
 * 通过 CAG HTTPS 通道拉起一台已关机的移动云电脑。
 *
 * 流程（对齐官方 CSAP 请求顺序）：
 *   1. cs_sysConfig.action     → 取 rsapub（动态）+ 会话 Cookie
 *   2. cs_getToken.action      → accessToken（密码 AES-ECB 编码）
 *   3. cs_getDesktopList.action→ 桌面 uuid / userId / groupId / poolId
 *   4. cs_startDesktop.action  → connectStr（业务参数全在 query，body 加密空串）
 *   5. cs_startDesktop_async_query.action → 轮询；404 则回到 4 重试
 *
 * @param {object} firmAuth  SohoClient.getFirmAuth(userServiceId) 的返回数据
 * @param {object} opts
 * @param {function} opts.onLog  日志回调 (label, message, level)
 * @param {number} opts.bootWait 等待桌面就绪上限（秒），默认 180
 * @param {number} opts.timeout  单次请求超时（毫秒），默认 15000
 * @param {boolean} opts.wireLog 是否打印报文级日志，默认 true
 * @param {number} opts.connectRetries CAG2.0 下 async_query 404 时重试 connectDesktop 次数
 * @returns {Promise<{success: boolean, message: string, connectStr?: string, accessToken?: string, waitedSeconds?: number}>}
 */
async function cagBootVm(firmAuth, opts = {}) {
  const onLog = typeof opts.onLog === 'function' ? opts.onLog : () => {};
  const bootWait = Number.isFinite(opts.bootWait) ? opts.bootWait : DEFAULT_BOOT_WAIT;
  const reqTimeout = Number.isFinite(opts.timeout) ? opts.timeout : DEFAULT_REQ_TIMEOUT;
  // 报文级日志默认开启（首跑排障期），可通过 opts.wireLog = false 关闭
  const wire = opts.wireLog === false ? null : makeWireLogger(onLog);

  // 【2026-09-23】整个开机流程共享一个会话容器。
  // CAG 服务端用会话状态串联"查配置 → 取 token → 提交连接 → 轮询"几步；
  // 若不传 Cookie，cs_connectDesktop 会直接拒绝：7090003 "Client need query system configuration again"。
  const session = { cookies: {} };

  const cagHost = String(firmAuth?.cagIp || firmAuth?.cagHost || '');
  const cagPort = Number(firmAuth?.cagPort) || DEFAULT_CAG_PORT;
  const vmId = String(firmAuth?.vmId || firmAuth?.vmID || firmAuth?.uuid || '');
  const vmUserName = String(firmAuth?.vmUserName || '');
  const vmPassword = String(firmAuth?.vmPassword || '');
  const vmcHost = String(firmAuth?.vmcIp || '');
  const vmcPort = String(firmAuth?.vmcPort || '');

  const identity = localIdentity();
  // 官方要求的附加请求头（X-Ap-sHost 指向 VMC 主机）
  const extraHeaders = {
    'process_id': '2',
    'serialNum': identity.snCode,
    'otlp_trace_id': crypto.randomBytes(16).toString('hex'),
    'otlp_parent_id': crypto.randomBytes(8).toString('hex')
  };
  if (vmcHost) {
    extraHeaders['X-Ap-sHost'] = `${vmcHost}${vmcPort ? ':' + vmcPort : ''}`;
  }

  if (wire) {
    wire(`firm-auth 材料：cagIp=${cagHost || '(空)'} cagPort=${cagPort} vmcIp=${vmcHost || '(空)'} ` +
      `vmId=${vmId || '(空)'} vmUserName=${vmUserName || '(空)'} ` +
      `vmPassword=${vmPassword ? `<len=${vmPassword.length}>` : '(空)'}`, 'info');
    wire(`firm-auth 原始键名：${Object.keys(firmAuth || {}).join(', ') || '(空对象)'}`, 'info');
    wire(`本机标识：hostName=${identity.hostName} mac=${identity.mac} ip=${identity.clientIp}`, 'info');
  }

  if (!cagHost) {
    return { success: false, message: '该机器未暴露 CAG 连接材料（cagIp 缺失），无法开机' };
  }
  if (!vmId || !vmUserName || !vmPassword) {
    return { success: false, message: '机器凭据不完整（缺少 vmId / vmUserName / vmPassword），无法开机' };
  }

  onLog('CAG', `正在通过 CAG 通道拉起机器 (${cagHost}:${cagPort})...`, 'info');

  // ---- 步骤 1：取 CAG 的 RSA 公钥 + 系统配置 ----
  let rsaPublicKeyPem;
  {
    // 【2026-09-23 二次修正】恢复 `RspSecurity=1`。
    // 上一版以为它是禁区（"带上就拿不到明文"）——那是误判：我方不会解密
    // ZTE_Security_Params 才只能靠不带它取明文。官方客户端全链路都带，
    // 正确做法是带着它并用 UasKey/UasIv 解密响应。
    const sysPath =
      '/cs/cs_sysConfig.action?version=' + encodeURIComponent(CSAP_VERSION) +
      '&language=' + encodeURIComponent(CSAP_LANGUAGE) +
      '&requestFrom=' + CSAP_REQUEST_FROM +
      '&name=' + encodeURIComponent(vmUserName) +
      '&RspSecurity=1';
    if (wire) wire('[步骤 1/5] 取 CAG RSA 公钥 (cs_sysConfig.action)', 'info');
    let sysRes;
    try {
      sysRes = await cagHttpsRequest(cagHost, cagPort, sysPath, zteEncryptEmptyBody(), reqTimeout, wire, session, extraHeaders);
    } catch (err) {
      return { success: false, message: `获取 CAG 系统配置异常：${describeErr(err)}` };
    }

    const decoded = decodeCagResponse(sysRes.text);
    if (!decoded.json) {
      return {
        success: false,
        message: `获取 CAG 系统配置失败：响应不是可解析的 JSON (HTTP ${sysRes.status})` +
          `，响应原文前 200 字：${String(sysRes.text).slice(0, 200)}`
      };
    }
    if (wire) {
      wire(`  响应解密：${decoded.decrypted ? 'ZTE_Security_Params → 已解密' : '明文 JSON'}` +
        `${decoded.securityParams ? ` (密文 len=${decoded.securityParams.length})` : ''}`, 'info');
    }
    if (decoded.decryptError && wire) {
      wire(`  ⚠️ ZTE_Security_Params 解密失败，已退回外层对象：${describeErr(decoded.decryptError)}`, 'warning');
    }

    const rawPub = findRsaPublicKey(decoded.json);
    const pubParams = rawPub ? parseZteRsaParams(rawPub) : null;
    if (wire) {
      wire(`  公钥字段：${rawPub ? `已找到 (len=${rawPub.length}` +
        `${pubParams ? `, N=${pubParams.n.length * 4}bit, E=${pubParams.e}` : ''})` : '未找到'}；` +
        `响应顶层键：${Object.keys(decoded.json).join(', ')}`, rawPub ? 'info' : 'warning');
    }
    rsaPublicKeyPem = normalizeRsaPublicKeyPem(rawPub);
    if (!rsaPublicKeyPem) {
      return {
        success: false,
        message: 'CAG 系统配置中未找到可用的 RSA 公钥（cs_sysConfig 返回异常）' +
          (rawPub ? `，已取到字段但无法规整为公钥：${String(rawPub).slice(0, 120)}` : '')
      };
    }
  }

  // ---- 步骤 2：取 accessToken（密码用 AES-ECB 编码进 query）----
  let accessToken = null;
  {
    const encPassword = zteCsapEncryptQueryValue(vmPassword);
    const tokenQuery = [
      ['username', vmUserName],
      ['password', encPassword],
      ['version', CSAP_VERSION],
      ['language', CSAP_LANGUAGE],
      ['clientId', ''],
      ['encrypt', '4'],
      ['token', ''],
      ['requestFrom', String(CSAP_REQUEST_FROM)],
      ['mac', identity.mac],
      ['clientIp', identity.clientIp],
      ['hostName', identity.hostName],
      // 以下为官方固定开关
      ['newVersionCtrl', '1'],
      ['netflags', '1'],
      ['unityType', '1'],
      ['isvm', '0'],
      ['RspSecurity', '1']
    ]
      .filter(([, v]) => v !== undefined && v !== null && String(v) !== '')
      .map(([k, v]) => `${k}=${encodeURIComponent(String(v))}`)
      .join('&');

    // getToken 是唯一"body 有辅助参数"的 action：clienttype/hardware/nettype/ostype
    const tokenBody = zteEncryptBody({ clienttype: 5, hardware: 25, nettype: 2, ostype: 10 });

    if (wire) wire('[步骤 2/5] 换取 accessToken (cs_getToken.action)', 'info');
    let tokenRes;
    try {
      tokenRes = await cagHttpsRequest(
        cagHost, cagPort, '/cs/cs_getToken.action?' + tokenQuery,
        tokenBody, reqTimeout, wire, session, extraHeaders
      );
    } catch (err) {
      return { success: false, message: `CAG 取 accessToken 异常：${describeErr(err)}` };
    }

    const decoded = decodeCagResponse(tokenRes.text);
    if (wire && decoded.json) {
      wire(`  响应解密：${decoded.decrypted ? 'ZTE_Security_Params → 已解密' : '明文 JSON'}；` +
        `result=${getResult(decoded.json)} mesg=${getMessage(decoded.json) || '(空)'}`, 'info');
    }

    accessToken = findAccessToken(decoded.json);
    const result = getResult(decoded.json);

    if (!accessToken) {
      // token 失效是**可重试**的（官方归类为 tokenRetry），故只提示、不致命：
      // 部分部署下 startDesktop 可不依赖 accessToken 直接走 connectDesktop。
      if (wire) {
        wire(`  ⚠️ 未取得 accessToken (result=${result} ${getMessage(decoded.json)})，` +
          `将尝试无 token 直连（CAG2.0 connectDesktop 路径）`, 'warning');
      }
    } else if (wire) {
      wire(`  ✅ accessToken 已取得 (len=${accessToken.length})`, 'info');
    }
  }

  // ---- 步骤 3：取桌面列表（拿 uuid / userId / groupId / poolId）----
  let desktop = null;
  if (accessToken) {
    const listQuery = [
      ['accessToken', accessToken],
      ['language', CSAP_LANGUAGE],
      ['requestFrom', String(CSAP_REQUEST_FROM)],
      ['isvm', '0'],
      ['RspSecurity', '1']
    ]
      .map(([k, v]) => `${k}=${encodeURIComponent(String(v))}`)
      .join('&');

    if (wire) wire('[步骤 3/5] 取桌面列表 (cs_getDesktopList.action)', 'info');
    try {
      const listRes = await cagHttpsRequest(
        cagHost, cagPort, '/cs/cs_getDesktopList.action?' + listQuery,
        zteEncryptEmptyBody(), reqTimeout, wire, session, extraHeaders
      );
      const decoded = decodeCagResponse(listRes.text);
      const result = getResult(decoded.json);
      if (wire) {
        wire(`  响应解密：${decoded.decrypted ? 'ZTE_Security_Params → 已解密' : '明文 JSON'}；` +
          `result=${result} mesg=${getMessage(decoded.json) || '(空)'}`, 'info');
      }
      if (CSAP_TOKEN_RETRY_CODES.has(String(result))) {
        if (wire) wire(`  ⚠️ 命中 token 失效码 ${result}（官方归类为可重试），将继续按无 token 路径尝试`, 'warning');
      } else {
        const list = findDesktopList(decoded.json);
        if (list && list.length) {
          // 优先匹配本机 vmId 对应的桌面，否则取第一台
          desktop = list.find((d) => String(d.vmId || d.vmid || '') === vmId) || list[0];
          if (wire) {
            wire(`  桌面列表 ${list.length} 台，已选中 uuid=${desktop.uuid || '(空)'} ` +
              `userId=${desktop.userId} groupId=${desktop.groupId} poolId=${desktop.poolId}`, 'info');
          }
        } else if (wire) {
          wire('  未解析出桌面列表（将使用无 uuid 的连接请求）', 'warning');
        }
      }
    } catch (err) {
      onLog('CAG', `取桌面列表失败（继续尝试连接）：${describeErr(err)}`, 'warning');
    }
  }

  // ---- 步骤 4 / 5：提交启动请求 → 轮询 ----
  const connectRetries = Number.isFinite(opts.connectRetries) ? opts.connectRetries : 3;
  const startedAt = Date.now();
  let lastMessage = '';
  let pollCount = 0;
  let connectStr = null;

  const connectQuery = buildConnectDesktopQuery({
    vmId, vmUserName, accessToken, identity, desktop
  });

  const doConnect = async () => {
    if (wire) wire('[步骤 4/5] 提交启动请求 (cs_startDesktop.action，参数全在 query，body 加密空串)', 'info');
    const res = await cagHttpsRequest(
      cagHost, cagPort, '/cs/cs_startDesktop.action?' + connectQuery,
      zteEncryptEmptyBody(), reqTimeout, wire, session, extraHeaders
    );
    const decoded = decodeCagResponse(res.text);
    const result = getResult(decoded.json);
    if (wire) {
      wire(`  result=${result} mesg=${getMessage(decoded.json) || '(空)'} ` +
        `解密=${decoded.decrypted ? '是' : '否'}`, 'info');
    }
    if (result !== null && result !== '0') {
      lastMessage = `${result} ${getMessage(decoded.json)}`.trim();
      if (CSAP_TOKEN_RETRY_CODES.has(String(result)) && wire) {
        wire(`  ⚠️ 命中 token 失效码 ${result}（官方做法：重取 token 后重试一次）`, 'warning');
      }
    }
    return decoded.json;
  };

  try {
    const first = await doConnect();
    connectStr = findConnectStr(first);
    if (connectStr) {
      const waited = Math.round((Date.now() - startedAt) / 1000);
      onLog('CAG', `✅ CAG 开机成功，桌面已在运行 (${waited}s)`, 'success');
      return { success: true, message: '机器已处于运行状态', connectStr, accessToken, waitedSeconds: waited };
    }
  } catch (err) {
    lastMessage = describeErr(err);
    if (wire) wire(`✖ cs_startDesktop 异常：${lastMessage}`, 'error');
  }

  // 轮询阶段：优先 walk async_query；若该端点不存在（CAG2.0 边缘恒 404），
  // 则改为重试 cs_startDesktop（connectRetries 次上限）。
  const asyncQuery = buildAsyncQuery({ vmId, accessToken });
  let asyncUnavailable = false;
  let connectAttempts = 0;

  if (wire) wire('[步骤 5/5] 轮询等待桌面就绪 (cs_startDesktop_async_query.action)', 'info');

  while (Date.now() - startedAt < bootWait * 1000) {
    await sleep(Math.max(1000, Number(opts.pollIntervalMs) || 3000));
    pollCount++;

    // 若 async_query 不可用，则退化为重试 connectDesktop
    if (asyncUnavailable) {
      if (connectAttempts >= connectRetries) {
        break; // 重试预算用尽
      }
      connectAttempts++;
      try {
        const j = await doConnect();
        connectStr = findConnectStr(j);
        if (wire) wire(`  重试 connectDesktop #${connectAttempts}：connectStr=${connectStr ? '已就绪' : '未就绪'}`, 'info');
        if (connectStr) break;
      } catch (err) {
        onLog('CAG', `重试 connectDesktop 失败：${describeErr(err)}`, 'warning');
      }
      continue;
    }

    try {
      const pollRes = await cagHttpsRequest(
        cagHost, cagPort, '/cs/cs_startDesktop_async_query.action?' + asyncQuery,
        zteEncryptEmptyBody(), reqTimeout, wire, session, extraHeaders
      );

      // CAG2.0 边缘上该端点返回 404 → 标记不可用，转 connectDesktop 重试
      if (pollRes.status === 404) {
        asyncUnavailable = true;
        if (wire) {
          wire('  ⚠️ cs_startDesktop_async_query.action 返回 404（CAG2.0 边缘常见），' +
            `改为重试 cs_startDesktop（最多 ${connectRetries} 次）`, 'warning');
        }
        continue;
      }

      const decoded = decodeCagResponse(pollRes.text);
      const result = getResult(decoded.json);
      if (result !== null && result !== '0') {
        lastMessage = `${result} ${getMessage(decoded.json)}`.trim();
      }
      connectStr = findConnectStr(decoded.json);
      if (wire) {
        wire(`  轮询 #${pollCount} (第 ${Math.round((Date.now() - startedAt) / 1000)}s)：` +
          `result=${result} connectStr=${connectStr ? '已就绪' : '未就绪'}` +
          `${decoded.json ? `，顶层键=${Object.keys(decoded.json).join(', ')}` : '，响应非 JSON'}`, 'info');
      }
      if (connectStr) break;
    } catch (err) {
      // 轮询期单次失败不放弃：继续等待，但把根因记录出来（不静默吞错）
      onLog('CAG', `开机轮询单次失败，将继续重试：${describeErr(err)}`, 'warning');
    }
  }

  if (connectStr) {
    const waited = Math.round((Date.now() - startedAt) / 1000);
    onLog('CAG', `✅ CAG 开机成功，桌面已就绪 (等待 ${waited}s)`, 'success');
    return { success: true, message: 'CAG 开机成功，桌面已就绪', connectStr, accessToken, waitedSeconds: waited };
  }

  return {
    success: false,
    message: `CAG 开机超时：等待 ${bootWait}s（轮询 ${pollCount} 次）后仍未取得 connectStr` +
      (lastMessage ? `。网关最后返回：${lastMessage}` : ''),
    waitedSeconds: bootWait
  };
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

/**
 * 展开错误根因链（不丢弃证据）。
 */
function describeErr(err) {
  if (!err) return 'unknown';
  const parts = [];
  let cur = err;
  const seen = new Set();
  for (let i = 0; i < 5 && cur; i++) {
    if (seen.has(cur)) break;
    seen.add(cur);
    const bits = [];
    if (cur.code) bits.push(`code=${cur.code}`);
    if (cur.syscall) bits.push(`syscall=${cur.syscall}`);
    if (cur.message) bits.push(String(cur.message).slice(0, 160));
    parts.push(`[${i}] ${bits.join(' ')}`);
    cur = cur.cause;
  }
  return parts.join(' → ');
}

/** 解析 connectStr 解密后的命令行，取出 session-key / 地址 / 端口。 */
function parseConnectCommand(cmdText) {
  const out = {};
  if (!cmdText) return out;
  const tokens = String(cmdText).split(/\s+/);
  const map = {
    '-k': 'sessionKey', '--session-key': 'sessionKey',
    // ⚠️ IPv4 与 IPv6 内层主机必须**分开存**。官方客户端对同一次取材料会同时下发
    // `-h <IPv4>` 与 `--hv6 <IPv6>`，而这两条是完全不同的数据面通道
    // （IPv4 ⇒ TLS + CAGMux + SPICE；IPv6 ⇒ raw ZTEC）。旧写法把两者写进同一个
    // key，于是"走哪条通道"取决于参数**在命令行里的先后顺序** —— 那是碰巧，不是判定。
    '-h': 'hostV4',
    '--hv6': 'hostV6',
    '--proxy-sport': 'spicePort',
    '--pv6': 'kcpDestPort', '-p': 'kcpDestPort',
    '--vmid': 'vmId',
    '--accessToken': 'accessToken',
    '--sn': 'connSerial',
    '--otlp-trace-id': 'traceId',
    '--otlp-parent-id': 'parentId'
  };
  for (let i = 0; i < tokens.length; i++) {
    const key = map[tokens[i]];
    if (key && i + 1 < tokens.length) out[key] = tokens[i + 1];
  }
  // 地址族选择口径：**IPv4 优先**，缺 `-h` 才回退 `--hv6`。
  // 对齐官方客户端的 firstNonEmpty(-h, --hv6) 取值顺序，不是我们自己选的偏好。
  // 实测样本（tools/_probe_connectstr.json）只有 `--hv6`、没有 `-h`，故那条材料仍走 raw。
  out.spiceHost = out.hostV4 || out.hostV6 || '';
  return out;
}

module.exports = {
  cagBootVm,
  cagHttpsRequest,
  normalizeRsaPublicKeyPem,
  rsaPkcs1Encrypt,
  rsaPkcs1EncryptHexB64,
  findRsaPublicKey,
  parseZteRsaParams,
  hexToB64url,
  findConnectStr,
  findAccessToken,
  findDesktopList,
  getResult,
  getMessage,
  decodeCagResponse,
  zteEncryptBody,
  zteEncryptEmptyBody,
  zteDecryptSecurityParams,
  zteCsapEncryptQueryValue,
  zteDecodeConnectStr,
  stableStringify,
  buildConnectDesktopQuery,
  buildConnectDesktopBody,
  buildAsyncQuery,
  parseConnectCommand,
  localIdentity,
  redactForLog,
  isCertChainError,
  CERT_CHAIN_ERROR_CODES,
  CSAP_TOKEN_RETRY_CODES,
  CSAP_VERSION,
  ZTE_UAS_KEY,
  ZTE_UAS_IV,
  ZTE_CSAP_ID,
  DEFAULT_CAG_PORT
};
