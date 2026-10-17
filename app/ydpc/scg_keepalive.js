'use strict';

/**
 * ============================================================================
 * 移动云 SCG（深信服）数据面保活 —— S1 取材料 / S2 传输 / S3 保活帧
 * ============================================================================
 *
 * 【为什么单独一套】SCG 与 ZTE 是**两条完全不同的数据面**：
 *   · ZTE：connectStr 内层主机 → raw ZTEC 帧 / TLS+CAGMux（app/ydpc/zte_cag_raw.js、
 *          zte_cag_tls.js）
 *   · SCG：firm-auth 直接下发 scgIp/scgTcpPort/scAuthCode → 裸 TCP 发 auth 包 →
 *          同 socket 升 TLS → Chuanyun trunk 帧 + SPICE 通道认证（**本文件**）
 * 两边**没有任何帧可以互借**，故不合并、不抽象成"统一通道"。
 *
 * 【协议来源】按官方客户端（Go chuanyun）同源行为与真机抓包逐字节复现。
 * 借的是**协议格式**（帧头/帧类型/TLV/通道号/REDQ/ExtInfo/SPICE 消息号）。
 *
 * ---------------------------------------------------------------------------
 * 🔒 红线自检（逐条核对，由回归机械拦截）
 * ---------------------------------------------------------------------------
 *   【2026-09-26 修订】真机四轮探针实证：firm-auth 的 scAuthCode 只是 5 分钟有效期的
 *   OAuth ext-grant 令牌（JWT），不经 CEM 控制面直接拨 scgIp:scgTcpPort，边缘对任何
 *   字节一律静默丢包（TCP 可连、零应答）——这正是「SCG auth 无应答」的机制性根因。
 *   经用户明确批准（2026-09-26），CEM 控制面按官方协议路径引入，原红线修订如下：
 *     ✓ CEM 客户端 ID 与 sdk2 RSA 公钥 —— 【已放宽】二者为官方 SDK 内嵌的协议常量
 *       （client_id 与公钥均非私密凭据），仅用于用户自己账号的会话建立。
 *       「伪造服务端身份直连开机」禁令**不变**；开机只走官方通道（ZTE：CAG；SCG：CEM）。
 *     ✗ 伪造服务端 UA（cdpsdk-server-…）—— 仍然禁止（保活用的是官方 macOS SDK 的
 *       cdpsdk-macos UA，属官方客户端协议头，与服务端身份串无关）。
 *     ✗ `rejectUnauthorized:false` 无条件关校验 —— 仍然禁止。数据面与 CEM 请求均为
 *       「严格先行 + 证书链缺陷白名单降级一次 + warning 留证」。
 *   ✅ 数据面本身不需要 CEM 客户端身份做任何额外动作：CEM 只负责「换会话材料」，
 *      auth 包用的仍是账号自己的 scAuthCode（CEM 下发的会话绑定版）。
 *
 * ---------------------------------------------------------------------------
 * 🧭 诚实性口径（与全项目一致，不许美化）
 * ---------------------------------------------------------------------------
 *   · `keepaliveProven` **恒为 false** —— 建立会话 ≠ 证明机器不会被关机。
 *   · 本文件只如实回报**观察到的事实**：通道是否认证、是否收到 display 标记、
 *     是否收到真实显示数据（SURFACE_CREATE / DRAW_COPY）。
 *   · 未收到真实显示数据时，一律只称"切片完成 / 重拨"，**绝不称"保活成功"**。
 */

const net = require('net');
const https = require('https');
const crypto = require('crypto');
const tls = require('tls');

// ---------------------------------------------------------------------------
// Chuanyun trunk 帧（协议格式）
// ---------------------------------------------------------------------------
const SCG_TRUNK_HELLO = 3;
const SCG_TRUNK_DATA = 4;
const SCG_TRUNK_SWITCH = 5;
const SCG_TRUNK_GBN = 6;
const SCG_FRAME_HEAD_SIZE = 24;
const SCG_DATA_TYPE = 1;
const SCG_CONTROL_TYPE = 2;

// SCG auth 包的协议级共享密钥（对称，非身份凭据；类比本项目已在用的 installinfo UasKey/UasIv）
const SCG_AUTH_AES_KEY = Buffer.from('fe'.repeat(16), 'hex'); // 16 × 0xFE
const SCG_AUTH_CTR_INIT = 0xfefefefefefefefen;                // BigInt：超出 Number 安全整数

// 通道号（字段2）
const SCG_CH_CTRL = 0;
const SCG_CH_MAIN = 1;
const SCG_CH_DISPLAY = 2;
const SCG_CH_INPUTS = 3;
const SCG_CH_CURSOR = 4;
const SCG_CH_PLAYBACK = 5;
const SCG_CH_RECORD = 6;

// SPICE 消息号
const SPICE_MSG = {
  SET_ACK: 0x0003,
  PING: 0x0004,
  PONG: 0x0005,
  ACK_SYNC: 0x0006,
  ACK: 0x0007,
  MARK: 0x0066,
  MAIN_INIT: 0x0067,
  CHANNELS_LIST: 0x0068,
  DISPLAY_INIT: 0x0065,
  DRAW_COPY: 0x0130,
  SURFACE_CREATE: 0x013a
};
const SPICE_MINI_HEADER_SIZE = 6;
const SPICE_DATA_HEADER_SIZE = 18;
const SPICE_TICKET_PUBKEY_BYTES = 162;
/** SPKI SubjectPublicKeyInfo 的通用 DER 前导（对方 B 实现同源）*/
const SPICE_PUBKEY_MARKER = Buffer.from('30819f300d', 'hex');

/** ExtInfo 模板：**字节级沿用协议格式**；`[-1]` 写通道类型，`[10:14]` 写 vmId(u32 BE) */
const SCG_EXT_INFO_TEMPLATE = Buffer.from('010013f300080000000000010820f1000101f2000104', 'hex');

// SPICE 通道**类型**（协议内 channelType 枚举，与上面的"通道号"不是一回事）
const SPICE_CH_MAIN_TYPE = 1;
const SPICE_CH_DISPLAY_TYPE = 2;
const SPICE_CH_INPUTS_TYPE = 3;
const SPICE_CH_CURSOR_TYPE = 4;

/** 双平面 hold 节拍（对齐对方 I-HOLD）：快平面 ~1s，慢平面 ~25s */
const SCG_HOLD_SELECT_SECONDS = 1.0;
const SCG_HOLD_KEEPALIVE_INTERVAL = 25.0;

// 证书链缺陷白名单 —— **只含证书链问题**，绝不混入通用网络/协议错误。
// 与 app/ydpc/zte_cag_tls.js 同一份口径（SCG 与 CAG 各自一份，避免互改牵连）。
const CERT_CHAIN_ERROR_CODES = [
  'UNABLE_TO_VERIFY_LEAF_SIGNATURE',
  'SELF_SIGNED_CERT_IN_CHAIN',
  'DEPTH_ZERO_SELF_SIGNED_CERT',
  'CERT_HAS_EXPIRED',
  'UNABLE_TO_GET_ISSUER_CERT_LOCALLY',
  'UNABLE_TO_GET_ISSUER_CERT',
  'ERR_TLS_CERT_ALTNAME_INVALID'
];

// ===========================================================================
// S1 · 取材料
// ===========================================================================

/**
 * 从官方 firm-auth 响应里取 SCG 连接材料（**账号自己的材料**，零新增凭据）。
 *
 * 【2026-09-27 修订】必填项收敛为 scAuthCode + vmId：
 *   firm-auth 的 scgIp/scgTcpPort 是**间歇性**的（会话失效/未分配时网关不下发，
 *   真机实测同一账号不同时刻时有时无），而 CEM 流程根本不需要它们 ——
 *   拨号地址由 CEM getConnectInfo 下发。旧实现把它们当必填 ⇒ 数据面循环每 60s
 *   误报一次「缺 scgIp / scgTcpPort」。现改为：有则带回（日志用），没有也不拦。
 *
 * @param {object} firmAuth
 * @returns {{host:string, port:number, scAuthCode:string, vmId:string, bizCode:string}}
 * @throws {Error} code='SCG_MATERIAL_MISSING' —— scAuthCode/vmId 缺失，**明确拒绝**
 */
function resolveScgMaterial(firmAuth) {
  const a = firmAuth || {};
  const host = String(a.scgIp || a.scgIpv6 || '').trim();
  const port = Number(a.scgTcpPort || a.scgPort || 0) || 0;
  const scAuthCode = String(a.scAuthCode || '');
  const vmId = String(a.vmId || a.vmID || a.uuid || '');

  const missing = [];
  if (!scAuthCode) missing.push('scAuthCode');
  if (!vmId) missing.push('vmId');

  if (missing.length) {
    const err = new Error(
      `SCG 连接材料不完整（缺 ${missing.join(' / ')}）—— 该机器可能并非 SCG 底座，或材料尚未下发`
    );
    err.code = 'SCG_MATERIAL_MISSING';
    err.missing = missing;
    throw err;
  }
  // scgIp/scgTcpPort：仅回带（可能为空 —— CEM getConnectInfo 会下发真正的拨号地址）
  return { host, port, scAuthCode, vmId, bizCode: String(a.bizCode || '10002') };
}

/**
 * 只报 presence（不吐任何值）—— 供日志留证，用于确认"官方是否真的下发 SCG 材料"。
 * 刻意**不返回** scAuthCode 本身，避免凭据进日志。
 */
function describeScgMaterialPresence(firmAuth) {
  const a = firmAuth || {};
  return {
    scgIp: !!(a.scgIp || a.scgIpv6),
    scgTcpPort: Number(a.scgTcpPort || a.scgPort || 0) > 0,
    scAuthCode: !!a.scAuthCode,
    vmId: !!(a.vmId || a.vmID || a.uuid),
    cagIp: !!a.cagIp,
    spuCode: String(a.spuCode || '')
  };
}

// ===========================================================================
// 协议编解码（协议格式，不含任何身份/凭据）
// ===========================================================================

/** Go 兼容的 AES-CTR 流：计数器块 = LE(init+i) || LE(init)，用 AES-ECB 逐块加密后异或 */
function scgAesCtrStream(plaintext) {
  const cipher = crypto.createCipheriv('aes-128-ecb', SCG_AUTH_AES_KEY, null);
  cipher.setAutoPadding(false);
  const blocks = Math.ceil(plaintext.length / 16) || 1;
  const stream = Buffer.alloc(blocks * 16);
  for (let i = 0; i < blocks; i++) {
    const counter = Buffer.alloc(16);
    counter.writeBigUInt64LE(SCG_AUTH_CTR_INIT + BigInt(i), 0);
    counter.writeBigUInt64LE(SCG_AUTH_CTR_INIT, 8);
    cipher.update(counter).copy(stream, i * 16);
  }
  cipher.final();
  const out = Buffer.alloc(plaintext.length);
  for (let i = 0; i < plaintext.length; i++) out[i] = plaintext[i] ^ stream[i];
  return out;
}

/**
 * 构建 SCG auth 包：`\x01` + len(低 8 位) + AES-CTR(TLV)。
 * TLV = `\x00\x02` + ts(u64 BE) + `\x03` + len(u16 BE) + `scAuthCode|vmId`
 */
function buildScgAuthPacket(scAuthCode, vmId) {
  const tlv = Buffer.from(`${scAuthCode}|${vmId}`, 'utf8');
  if (tlv.length > 0xffff) throw new Error('SCG auth TLV 过长');
  const head = Buffer.alloc(13);
  head.writeUInt16BE(0x0002, 0);
  head.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 1000)), 2);
  head.writeUInt8(0x03, 10);
  head.writeUInt16BE(tlv.length, 11);
  const encrypted = scgAesCtrStream(Buffer.concat([head, tlv]));
  return Buffer.concat([Buffer.from([0x01, encrypted.length & 0xff]), encrypted]);
}

/** Chuanyun 24B 帧头：version(1) pktType(1) payloadLen(u16 LE) reserved(u32) field1(u64 LE) field2(u64 LE) */
function frameHeadPack(pktType, payloadLen, field1, field2) {
  if (payloadLen > 0xffff) throw new Error('SCG 载荷超出 u16 帧长');
  const head = Buffer.alloc(SCG_FRAME_HEAD_SIZE);
  head.writeUInt8(1, 0);
  head.writeUInt8(pktType & 0xff, 1);
  head.writeUInt16LE(payloadLen & 0xffff, 2);
  head.writeUInt32LE(0, 4);
  head.writeBigUInt64LE(BigInt.asUintN(64, BigInt(field1 || 0)), 8);
  head.writeBigUInt64LE(BigInt.asUintN(64, BigInt(field2 || 0)), 16);
  return head;
}

/** trunk_switch：payload = targetCID(u64) senderCID(u64) param(u32) reason(u8) pad(3) extraID(u64) */
function trunkSwitchPack(targetCid, senderCid, param, switchReason, extraId, field1, field2) {
  const reason = Math.min(Number(switchReason) || 0, 6);
  const payload = Buffer.alloc(32);
  payload.writeBigUInt64LE(BigInt.asUintN(64, BigInt(targetCid || 0)), 0);
  payload.writeBigUInt64LE(BigInt.asUintN(64, BigInt(senderCid || 0)), 8);
  payload.writeUInt32LE((param || 0) >>> 0, 16);
  payload.writeUInt8(reason, 20);
  payload.writeBigUInt64LE(BigInt.asUintN(64, BigInt(extraId || 0)), 24);
  return Buffer.concat([frameHeadPack(SCG_TRUNK_SWITCH, payload.length, field1, field2), payload]);
}

/** ExtInfo + SPICE REDQ 令牌（SCG 通道认证）。`vmIdInt` 为 0 时保留模板内既有值。 */
function buildChannelAuth(sid, channelId, channelType, connectionId = 0, vmIdInt = 0) {
  const extInfo = Buffer.from(SCG_EXT_INFO_TEMPLATE);
  extInfo[extInfo.length - 1] = channelType & 0xff;
  if (Number(vmIdInt) > 0) extInfo.writeUInt32BE(Number(vmIdInt) >>> 0, 10);

  const redq = Buffer.alloc(channelType === 1 || channelType === 2 || channelType === 5 || channelType === 6 ? 42 : 38);
  let o = 0;
  redq.write('REDQ', o, 'ascii'); o += 4;
  redq.writeUInt32LE(2, o); o += 4;
  redq.writeUInt32LE(2, o); o += 4;
  if (channelType === 1 || channelType === 2 || channelType === 5 || channelType === 6) {
    redq.writeUInt32LE(26, o); o += 4;
    redq.writeUInt32LE(connectionId >>> 0, o); o += 4;
    redq.writeUInt8(channelType & 0xff, o); redq.writeUInt8(0, o + 1); o += 2;
    redq.writeUInt32LE(1, o); o += 4;
    redq.writeUInt32LE(1, o); o += 4;
    redq.writeUInt32LE(18, o); o += 4;
    redq.writeUInt32LE(0x09, o); o += 4;
    redq.writeUInt32LE(0x0f, o);
  } else {
    redq.writeUInt32LE(22, o); o += 4;
    redq.writeUInt32LE(connectionId >>> 0, o); o += 4;
    redq.writeUInt8(channelType & 0xff, o); redq.writeUInt8(0, o + 1); o += 2;
    redq.writeUInt32LE(1, o); o += 4;
    redq.writeUInt32LE(0, o); o += 4;
    redq.writeUInt32LE(14, o); o += 4;
    redq.writeUInt32LE(0x09, o);
  }
  const tokenRedq = Buffer.concat([crypto.randomBytes(16), redq]);
  return Buffer.concat([
    frameHeadPack(SCG_DATA_TYPE, extInfo.length, sid, channelId), extInfo,
    frameHeadPack(SCG_DATA_TYPE, tokenRedq.length, sid, channelId), tokenRedq
  ]);
}

/** 从 SPICE LinkReply 载荷里取出 RSA 公钥 DER（162B）。**运行时材料，不硬编码。** */
function findReplyPubkey(payload) {
  const off = payload.indexOf(SPICE_PUBKEY_MARKER);
  if (off >= 0 && payload.length >= off + SPICE_TICKET_PUBKEY_BYTES) {
    return payload.subarray(off, off + SPICE_TICKET_PUBKEY_BYTES);
  }
  return null;
}

/**
 * SPICE ticket = RSA-OAEP(SHA-1) 加密空口令。公钥是**服务端本次下发的**，
 * 与本项目"公钥必须动态获取"的规矩一致。
 */
function encodeSpiceTicket(pubDer, password = Buffer.alloc(0)) {
  let key;
  try {
    key = crypto.createPublicKey({ key: pubDer, format: 'der', type: 'spki' });
  } catch (e) {
    key = crypto.createPublicKey({ key: pubDer, format: 'der', type: 'pkcs1' });
  }
  return crypto.publicEncrypt(
    { key, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha1' },
    password
  );
}

function encodeMiniMessage(messageType, payload = Buffer.alloc(0)) {
  const head = Buffer.alloc(SPICE_MINI_HEADER_SIZE);
  head.writeUInt16LE(messageType & 0xffff, 0);
  head.writeUInt32LE(payload.length, 2);
  return Buffer.concat([head, payload]);
}

/** DISPLAY_INIT：pixmapCacheId(u8) size(i64) glzId(u8) glzWindow(u32) */
function encodeDisplayInit(pixmapCacheId = 1, pixmapCacheSize = 20 * 1024 * 1024, glzId = 1, glzWindow = 0x7ffc00) {
  const body = Buffer.alloc(14);
  body.writeUInt8(pixmapCacheId & 0xff, 0);
  body.writeBigInt64LE(BigInt(pixmapCacheSize), 1);
  body.writeUInt8(glzId & 0xff, 9);
  body.writeUInt32LE(glzWindow >>> 0, 10);
  return encodeMiniMessage(SPICE_MSG.DISPLAY_INIT, body);
}

/**
 * 剥离可选的 6B 令牌前缀（u16 魔数 + u32 声明长度）。
 *
 * ⚠️ 必须「先能解析、才允许剥」。理由：SPICE data 头的头 8 字节是 serial，当 serial 恰好
 * 落在 0x0100 附近时前两字节就是 `00 01`，只看魔数会把**合法的 data 帧**误切 6 字节，
 * 于是 MARK / SURFACE_CREATE 全部解不出来 ⇒ display 永远 unproven（静默失明）。
 * 因此这里改成：**只有剥掉之后剩余字节确实能解出一条已知消息时才剥**。
 */
function stripSpiceTokenPrefix(payload) {
  if (decodeDisplayMessage(payload)) return payload;
  if (payload.length > 6 && payload[0] === 0x00 && payload[1] === 0x01) {
    const rest = payload.subarray(6);
    if (decodeDisplayMessage(rest)) return rest;
  }
  return payload;
}

/**
 * 解出**一条** display 消息。
 *
 * 主解释：SPICE data 头（18B：serial u64 + type u16 + size u32 + subList u32）
 *   —— 与对方 `spice_protocol.encode_data_message` 的离线证明构造方式一致，
 *      真实 display 通道下行消息也是这个形状。
 * 次解释：SPICE mini 头（6B：type u16 + size u32），仅用于短格式。
 *
 * ⚠️ **两条路径都必须要求 type 属于已知集合**。否则一串零字节会被 mini 头"合法"地
 * 当成 type=0/size=0 吞掉 6 字节，把后面的真消息顶歪 —— 这是本文件第一版实测踩到的
 * 缺陷（MARK 永远收不到）。未知字节一律返回 null，由调用方停止解析，绝不猜。
 *
 * @returns {{mtype:number, body:Buffer, consumed:number}|null}
 */
function decodeDisplayMessage(data) {
  if (!data || !data.length) return null;
  if (data.length >= SPICE_DATA_HEADER_SIZE) {
    const mtype = data.readUInt16LE(8);
    const size = data.readUInt32LE(10);
    if (SPICE_KNOWN_TYPES.has(mtype) && SPICE_DATA_HEADER_SIZE + size <= data.length) {
      return {
        mtype,
        body: data.subarray(SPICE_DATA_HEADER_SIZE, SPICE_DATA_HEADER_SIZE + size),
        consumed: SPICE_DATA_HEADER_SIZE + size
      };
    }
  }
  if (data.length >= SPICE_MINI_HEADER_SIZE) {
    const mtype = data.readUInt16LE(0);
    const size = data.readUInt32LE(2);
    if (SPICE_KNOWN_TYPES.has(mtype) && SPICE_MINI_HEADER_SIZE + size <= data.length) {
      return {
        mtype,
        body: data.subarray(SPICE_MINI_HEADER_SIZE, SPICE_MINI_HEADER_SIZE + size),
        consumed: SPICE_MINI_HEADER_SIZE + size
      };
    }
  }
  return null;
}

/** 创建一个空的"协议进度"状态（诚实性判据的地基） */
function createProtocolProgress() {
  return {
    displayInitSent: false,
    setAckReceived: false,
    ackSyncSent: false,
    pingReceived: false,
    pongSent: false,
    surfaceCreateReceived: false,
    drawCopyReceived: false,
    markReceived: false
  };
}

/**
 * **唯一**的"显示面已被证明"判据（对齐对方 `is_protocol_keepalive_success`）：
 *   发了 DISPLAY_INIT 且收到 MARK，且收到过真实显示数据（SURFACE_CREATE 或 DRAW_COPY）。
 * ⚠️ 只建立连接 / 只完成通道认证**都不算**。
 */
function isDisplayProven(progress) {
  const p = progress || {};
  return !!(p.displayInitSent && p.markReceived &&
    (p.surfaceCreateReceived || p.drawCopyReceived));
}

/** 解析一段 display 载荷，更新进度并产出需要回的响应（遇到未知字节就停，绝不抛） */
function applyDisplaySpiceType(mtype, body, responses, progress) {
  if (mtype === SPICE_MSG.SET_ACK) {
    const gen = body.length >= 4 ? body.readUInt32LE(0) : 1;
    responses.push(encodeMiniMessage(SPICE_MSG.ACK_SYNC, (() => {
      const b = Buffer.alloc(4); b.writeUInt32LE(gen >>> 0, 0); return b;
    })()));
    progress.setAckReceived = true;
    progress.ackSyncSent = true;
  } else if (mtype === SPICE_MSG.PING) {
    responses.push(encodeMiniMessage(SPICE_MSG.PONG, body));
    progress.pingReceived = true;
    progress.pongSent = true;
  } else if (mtype === SPICE_MSG.SURFACE_CREATE) {
    progress.surfaceCreateReceived = true;
  } else if (mtype === SPICE_MSG.DRAW_COPY) {
    progress.drawCopyReceived = true;
  } else if (mtype === SPICE_MSG.MARK) {
    progress.markReceived = true;
  }
}

const SPICE_KNOWN_TYPES = new Set([
  SPICE_MSG.SET_ACK, SPICE_MSG.PING, SPICE_MSG.PONG, SPICE_MSG.ACK_SYNC, SPICE_MSG.ACK,
  SPICE_MSG.MARK, SPICE_MSG.DISPLAY_INIT, SPICE_MSG.DRAW_COPY, SPICE_MSG.SURFACE_CREATE
]);

/**
 * 处理 display 载荷：按 18B data 头 / 6B mini 头逐条解，**未知字节立刻停**（绝不抛）。
 * @returns {Buffer[]} 需要回写的响应列表
 */
function handleDisplayPayload(payload, progress) {
  let data = stripSpiceTokenPrefix(payload);
  const responses = [];
  while (data.length) {
    const one = decodeDisplayMessage(data);
    if (!one) break; // 未知字节就停，绝不猜
    applyDisplaySpiceType(one.mtype, one.body, responses, progress);
    data = data.subarray(one.consumed);
  }
  return responses;
}

// ===========================================================================
// S0 · CEM 控制面（OAuth ext grant → getConnectInfo → 就绪轮询）
// ===========================================================================
// 【2026-09-26 真机实证】CEM 是 SCG 数据面的前置必经步骤，不是可选优化：
//   · getConnectInfo 在服务端创建「连接会话」并返回会话绑定的 scgIp/scgTcpPort/新 scAuthCode
//     （真机观测：每次返回的 scgIp 都在边缘池内漂移，如 .14 → .54 → .15）；
//   · 对未开机机器，getConnectInfo 本身就等同触发开机（官方语义），随后轮询 readyStatus；
//   · 不走 CEM 直接用 firm-auth 材料拨号 = 边缘没有会话上下文 = 任何输入都静默丢包。
// 注意：/gzs/auth/oauth/rsa-public-key 运行时下发的公钥**不是** getConnectInfo 用的那把
//（真机实测：用它加密 vmId 必报「参数错误或解密失败」）——getConnectInfo 绑定官方 SDK
// 内嵌的 sdk2 公钥。公钥非机密，按官方 SDK 常量内置（2026-09-26 用户批准）。

const SCG_CEM_BASE = 'https://api.soho.komect.com:1443';
const SCG_CEM_CLIENT_ID = 'sc-user-5e38ece5';
const SCG_CEM_RSA_PUBLIC_KEY =
  'MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDRwADvpa+s20CapaSeDeWA' +
  'fRKbK5zD91jIUxNDe/2twuvKdQA+Ln3VWFtL8opVod0ebqQanpVb/uITI56G' +
  'coVdSzis2IgqIkVvN+iOPH+on/FK+6EXYeIZn3MYmVxsmS0IVifVl2EGLeOC' +
  'RMwjPmy9fHB+gByQtGnxAsknwBKUqQIDAQAB';
const SCG_CEM_SDK_UA = 'cdpsdk-macos-2.18.21(2.18.21.159)';
const SCG_CEM_RSA_PREFIX = '{rsa}';
const SCG_CEM_READY_POLL_MS = 5000;
const SCG_CEM_READY_MAX_POLLS = 12; // 60s 就绪预算（服务端 timeInterval 建议 5s）

// 数据面 TLS 的 SNI：SCG 边缘证书是 *.soho.komect.com 通配符，IP 直连不带 SNI 会因
// ALTNAME 不符降级；恒带此 SNI 后严格校验可一次通过（真机 2026-09-26 实测）。
// 真机同时验证过：SNI 有无不影响 SCG 网关的应用层路由（auth/trunk 行为一致）。
const SCG_TLS_SNI = 'scg.soho.komect.com';

/** CEM 请求（TLS 策略由 allowInsecure 显式控制，与数据面同口径） */
function cemHttpsRequest({ reqPath, method, headers, body, timeoutMs = 20000, allowInsecure = false }) {
  return new Promise((resolve, reject) => {
    const req = https.request(SCG_CEM_BASE + reqPath, {
      method,
      headers,
      timeout: timeoutMs,
      rejectUnauthorized: !allowInsecure
    }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString('utf8') }));
    });
    req.on('timeout', () => req.destroy(new Error(`CEM 请求超时 ${timeoutMs}ms: ${reqPath}`)));
    req.once('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

/** CEM 请求严格先行 + 证书链缺陷白名单降级一次 + 留证（与 scgConnect 同一份口径） */
async function cemRequestStrict(args, onLog) {
  try {
    return await cemHttpsRequest({ ...args, allowInsecure: false });
  } catch (e) {
    const code = String((e && (e.code || e.reason)) || '');
    if (!CERT_CHAIN_ERROR_CODES.includes(code)) throw e;
    const log = typeof onLog === 'function' ? onLog : () => {};
    log('SCG', `CEM TLS 严格校验失败（code=${code}）—— 命中证书链缺陷白名单，降级重试一次并留证`, 'warning');
    return await cemHttpsRequest({ ...args, allowInsecure: true });
  }
}

function cemHeaders(accessToken) {
  const h = {
    'Content-Type': 'application/json',
    'gzs-client-id': SCG_CEM_CLIENT_ID,
    'gzs-timestamp': String(Date.now()),
    'sc-terminal-sn': '',
    'sc-network-type': '2',
    'sc-unit-type': 'MacBookPro',
    'User-Agent': SCG_CEM_SDK_UA
  };
  if (accessToken) h.Authorization = `Bearer ${accessToken}`;
  return h;
}

/** vmId 加密：官方 SDK 内嵌公钥 RSA-PKCS1v15 → 标准 base64（真机实证：urlsafe 变体不被接受） */
function cemEncryptVmId(vmId) {
  const pemBody = String(SCG_CEM_RSA_PUBLIC_KEY).replace(/(.{64})/g, '$1\n').trim();
  const pem = ['-----BEGIN PUBLIC KEY-----', pemBody, '-----END PUBLIC KEY-----'].join('\n');
  const ct = crypto.publicEncrypt({ key: pem, padding: crypto.constants.RSA_PKCS1_PADDING }, Buffer.from(String(vmId), 'utf8'));
  return SCG_CEM_RSA_PREFIX + ct.toString('base64');
}

/** 步骤 1：OAuth ext grant —— firm-auth 的 scAuthCode 在这里换 access_token */
async function cemExchangeToken(scAuthCode, bizCode, onLog) {
  const form = new URLSearchParams({
    grant_type: 'ext',
    client_id: SCG_CEM_CLIENT_ID,
    bizCode: String(bizCode || '10002'),
    token: String(scAuthCode || ''),
    source: 'biz'
  }).toString();
  const res = await cemRequestStrict({
    reqPath: '/gzs/auth/oauth/token',
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: form
  }, onLog);
  let json;
  try { json = JSON.parse(res.body); } catch (e) {
    throw new Error(`CEM OAuth 响应异常 (HTTP ${res.status})`);
  }
  const data = json.data || json;
  if (String(json.code) !== '00000' || !data.access_token) {
    throw new Error(`CEM OAuth token 交换失败: ${json.message || json.msg || json.code || '(无错误码)'}`);
  }
  return String(data.access_token);
}

/** 步骤 2：getConnectInfo —— 创建服务端连接会话，取回会话绑定的数据面材料。
 *  ⚠️ 对冷启动机器，服务端会**握住连接等机器就绪才响应**（真机实测 >30s），
 *     因此 timeoutMs 必须放大到 90~120s，否则会把"正在开机"误判成失败。
 *  ⚠️【2026-09-27 真机实证】冷启动时 CEM 网关自身的等待上限更短，会先回 **HTTP 504**
 *     （用户实测：点开机 → 504 → 但机器确实被拉起）。504/5xx 与网络超时的语义是
 *     "**开机已在途、只是还没就绪**"，必须由调用方按可重试处理，绝不当作失败。 */
async function cemGetConnectInfo(accessToken, vmId, onLog, { timeoutMs = 20000 } = {}) {
  let res;
  try {
    res = await cemRequestStrict({
      reqPath: '/sc/open-portal/openapi/terminal/v1/getConnectInfo',
      method: 'POST',
      headers: cemHeaders(accessToken),
      body: JSON.stringify({ vmId: cemEncryptVmId(vmId) }),
      timeoutMs
    }, onLog);
  } catch (e) {
    // 网络层超时 / 连接重置：同样属于"在途"语义（真机 30s 超时那次机器照样被拉起）
    const err = new Error(`CEM getConnectInfo 请求未完成（${e.message}）—— 开机可能已在途`);
    err.retryable = true;
    err.cause = e;
    throw err;
  }
  if (res.status >= 500) {
    const err = new Error(`CEM getConnectInfo 网关超时/不可用 (HTTP ${res.status}) —— 开机可能已在途`);
    err.retryable = true;
    err.httpStatus = res.status;
    throw err;
  }
  let json;
  try { json = JSON.parse(res.body); } catch (e) {
    throw new Error(`CEM getConnectInfo 响应异常 (HTTP ${res.status})`);
  }
  if (String(json.code) !== '00000' || !json.data) {
    throw new Error(`CEM getConnectInfo 失败: ${json.message || json.msg || json.code}`);
  }
  return json.data;
}

/**
 * CEM 开机/就绪一体流程（真机 2026-09-26/27 验证：getConnectInfo 本身就是开机触发器，
 * 对未开机机器服务端会握住连接等拉起后才响应；冷启动时网关可能先回 504 —— 属"在途"）。
 *
 * @param {object} firmAuth   账号 firm-auth（需 scAuthCode / vmId / bizCode）
 * @param {object} [opts]
 * @param {number} [opts.maxWaitSeconds=180]  总预算（getConnectInfo 重试 + readyStatus 轮询）
 * @param {Function} [opts.onLog]
 * @returns {Promise<{ok:boolean, pending:boolean, reason:string, readyStatus:string|number,
 *                    host:string, port:number, scAuthCode:string, vmId:string, traceId:string}>}
 *   ok=false + pending=true 表示开机已在途（getConnectInfo 受 5xx/超时或未就绪），
 *   由调用方做独立状态核验后再下结论 —— 绝不把"正在开机"报成失败。
 */
async function cemBootVm(firmAuth, { maxWaitSeconds = 180, onLog } = {}) {
  const log = (m, lvl = 'info') => { if (typeof onLog === 'function') onLog('SCG', m, lvl); };
  const material = resolveScgMaterial(firmAuth); // 缺 scAuthCode/vmId ⇒ 明确拒绝
  const accessToken = await cemExchangeToken(material.scAuthCode, material.bizCode, onLog);
  const deadline = Date.now() + maxWaitSeconds * 1000;

  // ── getConnectInfo（触发开机）：504/5xx/超时 = "在途"，按预算重试直到拿到会话材料 ──
  let ci = null;
  let lastRetryable = null;
  for (let attempt = 1; ; attempt++) {
    try {
      // 冷启动等待：服务端最长可握 120s+，必须在请求层给足
      ci = await cemGetConnectInfo(accessToken, material.vmId, onLog, { timeoutMs: 120000 });
      break;
    } catch (e) {
      if (!e.retryable) throw e; // 真失败（OAuth 被拒 / 参数错误）原样抛
      lastRetryable = e;
      const remainMs = deadline - Date.now();
      if (remainMs <= SCG_CEM_READY_POLL_MS) {
        // 预算耗尽：开机已在途，交回上层做独立核验（绝不当失败）
        log(`CEM getConnectInfo 持续超时/5xx（最近：${e.message}），等待预算已用尽 —— 开机已在途，稍后核验`, 'warning');
        return {
          ok: false, pending: true, reason: e.message, readyStatus: null,
          host: '', port: 0, scAuthCode: material.scAuthCode, vmId: material.vmId, traceId: ''
        };
      }
      log(`CEM 网关在等待机器启动（${e.message}），${Math.round(SCG_CEM_READY_POLL_MS / 1000)}s 后重试（第 ${attempt} 次）`, 'warning');
      await new Promise((r) => setTimeout(r, SCG_CEM_READY_POLL_MS));
    }
  }

  let scAuthCode = String(ci.scAuthCode || '') || material.scAuthCode;
  const traceId = String(ci.traceId || '');
  let readyStatus = ci.readyStatus;

  if (traceId && String(readyStatus) !== '1') {
    const started = Date.now();
    for (let i = 0; ; i++) {
      if (Date.now() >= deadline) break;
      await new Promise((r) => setTimeout(r, SCG_CEM_READY_POLL_MS));
      let rd = {};
      try {
        const res = await cemRequestStrict({
          reqPath: '/sc/open-portal/openapi/terminal/v1/getVmReadyStatus',
          method: 'POST',
          headers: cemHeaders(accessToken),
          body: JSON.stringify({ vmId: cemEncryptVmId(material.vmId), traceId })
        }, onLog);
        rd = JSON.parse(res.body).data || {};
      } catch (e) {
        log(`CEM 就绪轮询第 ${i + 1} 次失败：${e.message}，继续等待`, 'warning');
        continue;
      }
      readyStatus = rd.readyStatus;
      if (rd.scAuthCode) scAuthCode = String(rd.scAuthCode);
      log(`CEM 开机就绪轮询 ${i + 1}: readyStatus=${readyStatus}（已等待 ${Math.round((Date.now() - started) / 1000)}s）`);
      if (String(readyStatus) === '1') break;
    }
  }

  const host = String(ci.scgIp || ci.scgIpv6 || '').trim();
  const port = Number(ci.scgTcpPort || ci.scgPort || 0) || 0;
  return {
    ok: String(readyStatus) === '1',
    pending: String(readyStatus) !== '1',
    reason: String(readyStatus) === '1' ? '' : `等待窗口内未就绪（readyStatus=${readyStatus}，机器仍在启动）`,
    readyStatus,
    host, port, scAuthCode, vmId: material.vmId, traceId
  };
}

/**
 * CEM 会话准备：material（firm-auth）→ 会话绑定的数据面材料（复用 cemBootVm 流程）。
 * @returns {{host:string, port:number, scAuthCode:string, vmId:string, traceId:string}}
 */
async function prepareScgSession(material, onLog) {
  const log = (m, lvl = 'info') => { if (typeof onLog === 'function') onLog('SCG', m, lvl); };
  const boot = await cemBootVm(material, { maxWaitSeconds: 60, onLog });
  if (!boot.ok) {
    const e = new Error(`CEM 就绪轮询超时（readyStatus=${boot.readyStatus}，机器未进入就绪状态），本轮挂起等待下一轮重试`);
    e.code = 'SCG_CEM_NOT_READY';
    throw e;
  }
  const host = String(boot.host || '').trim();
  const port = Number(boot.port || 0) || 0;
  if (!host || !(port > 0) || !boot.scAuthCode) {
    const e = new Error('CEM getConnectInfo 未返回有效的数据面材料（scgIp/scgTcpPort/scAuthCode）');
    e.code = 'SCG_CEM_MATERIAL_MISSING';
    throw e;
  }
  log(`CEM 会话材料就绪：scg=${host}:${port} vmId=${material.vmId.slice(0, 8)}… traceId=${boot.traceId ? '有' : '无'}`);
  return { host, port, scAuthCode: boot.scAuthCode, vmId: material.vmId, traceId: boot.traceId };
}

// ===========================================================================
// S2 · 传输（裸 TCP → auth 包 → 同 socket 升 TLS）
// ===========================================================================

/** 裸 socket 上收满 n 字节（一次性，用于 auth 应答） */
function recvUpTo(sock, n, timeoutMs) {
  return new Promise((resolve, reject) => {
    let buf = Buffer.alloc(0);
    const timer = setTimeout(() => { cleanup(); resolve(buf); }, timeoutMs);
    const onData = (c) => {
      buf = Buffer.concat([buf, c]);
      if (buf.length >= n) { cleanup(); resolve(buf.subarray(0, n)); }
    };
    const onErr = (e) => { cleanup(); reject(e); };
    const onClose = () => { cleanup(); resolve(buf); };
    function cleanup() {
      clearTimeout(timer);
      sock.removeListener('data', onData);
      sock.removeListener('error', onErr);
      sock.removeListener('close', onClose);
    }
    sock.on('data', onData);
    sock.on('error', onErr);
    sock.on('close', onClose);
  });
}

/**
 * 单次 SCG 建连（不含重试）。**TLS 策略由 allowInsecure 显式控制**：
 *   allowInsecure=false（默认）⇒ 严格校验
 *   allowInsecure=true          ⇒ 仅在上层已确认"证书链缺陷白名单"后才可传入
 * ⚠️ 本函数不自己放宽校验；放宽的责任与留证在 `scgConnect()`。
 */
async function scgConnectOnce({ host, port, scAuthCode, vmId, timeoutMs = 10000, allowInsecure = false, onLog }) {
  const log = (m, lvl = 'info') => { if (typeof onLog === 'function') onLog('SCG', m, lvl); };

  const raw = await new Promise((resolve, reject) => {
    const s = net.createConnection({ host, port });
    const t = setTimeout(() => { s.destroy(); reject(new Error(`SCG TCP 连接超时 ${host}:${port}`)); }, timeoutMs);
    s.once('connect', () => { clearTimeout(t); resolve(s); });
    s.once('error', (e) => { clearTimeout(t); reject(e); });
  });

  try {
    const authPkt = buildScgAuthPacket(scAuthCode, vmId);
    raw.write(authPkt);
    const resp = await recvUpTo(raw, 128, timeoutMs);
    // 【2026-09-26 现场】"一个字都没收到" ≠ "服务端回了 0x00"。
    // 这里曾经写成 `(resp.length ? resp[0] : 0)` ⇒ 零应答被渲染成 `byte[0]=0x0`，
    // 读起来像服务端明确回了零字节，实际是**超时未回包 / 已被对端断开**。
    // 同一分支的正确语义是 -1（即"没有这个字节"），
    // 把它写成 0 是**编造数据**，会把人往"协议字节对不上"的方向带偏。
    if (!resp.length) {
      const e = new Error(
        'SCG auth 无应答：超时内未收到任何字节（服务端未回包或连接已被断开）'
      );
      e.code = 'SCG_AUTH_NO_RESPONSE';
      throw e;
    }
    if (resp[0] !== 0x00) {
      if (resp[0] === 0x0b) {
        const e = new Error('SCG auth 降级（token 过期或重放）');
        e.code = 'SCG_AUTH_DOWNGRADE';
        throw e;
      }
      const e = new Error(`SCG auth 失败：byte[0]=0x${resp[0].toString(16).padStart(2, '0')}`);
      e.code = 'SCG_AUTH_FAILED';
      throw e;
    }
    if (resp.length < 9) throw new Error(`SCG auth 应答过短：${resp.length} 字节`);
    const sessionId = (resp[6] << 16) | (resp[7] << 8) | resp[8];
    log(`auth 通过，session_id=${sessionId}`);

    // 升级 TLS：认证是明文（协议如此），TLS 在其之上。
    // 【2026-09-26】证书为 *.soho.komect.com 通配符，IP 直连不带 SNI 必然 ALTNAME 不符
    //（真机实证：带 SNI 后严格校验完全通过）—— 故对边缘恒发 SNI，严格先行通常一次过。
    const tlsSock = await new Promise((resolve, reject) => {
      const t = setTimeout(() => reject(new Error('SCG TLS 升级超时')), timeoutMs);
      const s = tls.connect({
        socket: raw,
        rejectUnauthorized: !allowInsecure,
        servername: SCG_TLS_SNI
      }, () => {
        clearTimeout(t);
        resolve(s);
      });
      s.once('error', (e) => { clearTimeout(t); reject(e); });
    });
    if (allowInsecure) log('⚠️ TLS 已按受控降级建立（仅证书链缺陷，已留证）', 'warning');
    return { socket: tlsSock, sessionId };
  } catch (e) {
    try { raw.destroy(); } catch (_) { /* 已关闭 */ }
    throw e;
  }
}

/**
 * SCG 建连（**严格先行 + 证书链缺陷白名单降级一次**）。
 * 只有命中白名单才降级重连一次，且必然打 warning 留证（host + 错误码）。
 * 非证书链错误一律**不降级**，原样抛出（fail-closed）。
 */
async function scgConnect(opts) {
  try {
    return await scgConnectOnce({ ...opts, allowInsecure: false });
  } catch (e) {
    const code = String((e && (e.code || e.reason)) || '');
    if (!CERT_CHAIN_ERROR_CODES.includes(code)) throw e;
    const onLog = typeof opts.onLog === 'function' ? opts.onLog : () => {};
    onLog('SCG',
      `TLS 严格校验失败（host=${opts.host} code=${code}）—— 命中证书链缺陷白名单，降级重连一次并以 warning 留证`,
      'warning');
    return await scgConnectOnce({ ...opts, allowInsecure: true });
  }
}

// ===========================================================================
// S3 · 保活帧 / 握手 / hold
// ===========================================================================

/** 缓冲式 trunk 帧读取器：读满 24B 头再按 payloadLen 取载荷 */
function createFrameReader(sock) {
  let buf = Buffer.alloc(0);
  let errored = null;
  let closed = false;
  const waiters = [];
  const notify = () => { const ws = waiters.splice(0); for (const w of ws) w(); };
  sock.on('data', (c) => { buf = Buffer.concat([buf, c]); notify(); });
  sock.on('error', (e) => { errored = e; notify(); });
  sock.on('close', () => { closed = true; notify(); });

  return {
    detach() {
      sock.removeAllListeners('data');
      sock.removeAllListeners('error');
      sock.removeAllListeners('close');
      closed = true;
      notify();
    },
    /** @returns {Promise<{pktType:number,payload:Buffer,field1:number,field2:number}|null>} null = 超时 */
    async readFrame(timeoutMs = 2000) {
      const deadline = Date.now() + timeoutMs;
      for (;;) {
        if (buf.length >= SCG_FRAME_HEAD_SIZE) {
          const version = buf.readUInt8(0);
          const pktType = buf.readUInt8(1);
          const payloadLen = buf.readUInt16LE(2);
          const field1 = buf.readBigUInt64LE(8);
          const field2 = buf.readBigUInt64LE(16);
          if (version !== 1) throw new Error(`SCG 帧版本异常：${version}`);
          if (buf.length >= SCG_FRAME_HEAD_SIZE + payloadLen) {
            const payload = Buffer.from(buf.subarray(SCG_FRAME_HEAD_SIZE, SCG_FRAME_HEAD_SIZE + payloadLen));
            buf = buf.subarray(SCG_FRAME_HEAD_SIZE + payloadLen);
            return { pktType, payload, field1: Number(field1), field2: Number(field2) };
          }
        }
        if (errored) throw errored;
        if (closed) throw new Error('SCG 连接已关闭');
        const remain = deadline - Date.now();
        if (remain <= 0) return null;
        await new Promise((r) => {
          const t = setTimeout(r, Math.min(remain, 200));
          waiters.push(() => { clearTimeout(t); r(); });
        });
      }
    }
  };
}

/** 回 PING→PONG / SET_ACK→ACK_SYNC（对方 `_reply_keepalive_frame` 同形） */
function replyKeepaliveFrame(sock, sid, frame, stats) {
  if (frame.pktType !== SCG_DATA_TYPE || frame.payload.length < 6) return false;
  const msgType = frame.payload.readUInt16LE(0);
  if (msgType === SPICE_MSG.PING) {
    const body = frame.payload.subarray(6);
    const head = Buffer.alloc(6);
    head.writeUInt16LE(0x03, 0);
    head.writeUInt32LE(body.length, 2);
    const pong = Buffer.concat([head, body]);
    sock.write(Buffer.concat([frameHeadPack(SCG_DATA_TYPE, pong.length, sid, frame.field2), pong]));
    stats.responses += 1;
    return true;
  }
  if (msgType === SPICE_MSG.SET_ACK) {
    const gen = frame.payload.length >= 10 ? frame.payload.readUInt32LE(6) : 0;
    const ackSync = Buffer.alloc(6);
    ackSync.writeUInt16LE(0x01, 0);
    ackSync.writeUInt32LE(4, 2);
    const genBuf = Buffer.alloc(4); genBuf.writeUInt32LE(gen >>> 0, 0);
    const body = Buffer.concat([ackSync, genBuf]);
    sock.write(Buffer.concat([frameHeadPack(SCG_DATA_TYPE, body.length, sid, frame.field2), body]));
    stats.responses += 1;
    return true;
  }
  return false;
}

/** SPICE MOUSE_MODE_REQUEST（主通道慢平面） */
function sendMouseMode(sock, sid) {
  const payload = Buffer.alloc(10);
  payload.writeUInt16LE(0x69, 0);
  payload.writeUInt32LE(4, 2);
  payload.writeUInt32LE(2, 6);
  sock.write(Buffer.concat([frameHeadPack(SCG_DATA_TYPE, payload.length, sid, SCG_CH_MAIN), payload]));
}

/**
 * SCG SPICE 握手（对齐对方 `spice_handshake`）。
 * 顺序：MAIN 认证 → MAIN_INIT → client_info/attach → 通道表 → DISPLAY 认证 →
 *       DISPLAY_INIT → 等 MARK → INPUTS/CURSOR 认证。
 * @returns {{spiceSessionId:number, channels:string[], progress:object, stats:object}}
 */
async function scgHandshake(sock, { vmId = '', onLog } = {}) {
  const log = (m, lvl = 'info') => { if (typeof onLog === 'function') onLog('SCG', m, lvl); };
  const reader = createFrameReader(sock);
  const progress = createProtocolProgress();
  const stats = { frames: 0, responses: 0, trunkSwitchReplies: 0 };
  const connected = [];
  const vmIdInt = /^\d+$/.test(String(vmId)) ? Number(vmId) : 0;

  const first = await reader.readFrame(3000);
  if (!first) throw new Error('SCG 握手失败：未收到首帧');
  const sid = first.field1;
  let spiceSessionId = 0;
  log(`首帧 pkt=${first.pktType} sid=${sid} ch=${first.field2}`);

  // 真正的回包要带 sid，这里重建一个带 sid 的回复器（首帧的那次回复不涉及）
  const reply = (frame) => replyKeepaliveFrame(sock, sid, frame, stats);

  const authenticateChannel = async (channelId, channelType, waitSeconds, connectionId = 0) => {
    sock.write(buildChannelAuth(sid, channelId, channelType, connectionId, vmIdInt));
    const deadline = Date.now() + waitSeconds * 1000;
    while (Date.now() < deadline) {
      let frame;
      try { frame = await reader.readFrame(2000); } catch (e) { log(`通道 ${channelId} 收帧异常：${e.message}`, 'warning'); return false; }
      if (!frame) continue;
      stats.frames += 1;
      reply(frame);
      if (frame.pktType === SCG_CONTROL_TYPE) continue;
      if (frame.field2 !== channelId) {
        if (frame.field2 === SCG_CH_DISPLAY && frame.payload.length) {
          for (const r of handleDisplayPayload(frame.payload, progress)) {
            sock.write(Buffer.concat([frameHeadPack(SCG_DATA_TYPE, r.length, sid, SCG_CH_DISPLAY), r]));
          }
        }
        continue;
      }
      if (frame.payload.indexOf(Buffer.from('REDQ')) < 0) continue;
      const pub = findReplyPubkey(frame.payload);
      if (!pub) return false;
      const ticket = encodeSpiceTicket(pub, Buffer.alloc(0));
      const authType = Buffer.alloc(4);
      authType.writeUInt32LE(1, 0);
      sock.write(Buffer.concat([
        frameHeadPack(SCG_DATA_TYPE, authType.length, sid, channelId), authType,
        frameHeadPack(SCG_DATA_TYPE, ticket.length, sid, channelId), ticket
      ]));
      for (let i = 0; i < 10; i++) {
        if (Date.now() >= deadline) break;
        let af;
        try { af = await reader.readFrame(2000); } catch (e) { break; }
        if (!af) continue;
        stats.frames += 1;
        reply(af);
        if (af.pktType === SCG_CONTROL_TYPE) continue;
        if (af.field2 !== channelId) {
          if (af.field2 === SCG_CH_DISPLAY && af.payload.length) {
            for (const r of handleDisplayPayload(af.payload, progress)) {
              sock.write(Buffer.concat([frameHeadPack(SCG_DATA_TYPE, r.length, sid, SCG_CH_DISPLAY), r]));
            }
          }
          continue;
        }
        if (af.payload.length !== 4) continue;
        return af.payload.readUInt32LE(0) === 0;
      }
      return false;
    }
    return false;
  };

  const waitMainInit = async (waitSeconds = 30) => {
    const deadline = Date.now() + waitSeconds * 1000;
    while (Date.now() < deadline) {
      let frame;
      try { frame = await reader.readFrame(2000); } catch (e) { continue; }
      if (!frame) continue;
      stats.frames += 1;
      reply(frame);
      if (frame.pktType === SCG_CONTROL_TYPE || frame.field2 !== SCG_CH_MAIN || frame.payload.length < 10) continue;
      const msgType = frame.payload.readUInt16LE(0);
      const msgSize = frame.payload.readUInt32LE(2);
      if (msgType === SPICE_MSG.MAIN_INIT && msgSize >= 4) return frame.payload.readUInt32LE(6);
    }
    return 0;
  };

  const sendClientInfoAndAttach = () => {
    const clientInfo = Buffer.from('7200140000001000000064000000080000002008010000000000', 'hex');
    const attach = Buffer.from('680000000000', 'hex');
    sock.write(Buffer.concat([
      frameHeadPack(SCG_DATA_TYPE, clientInfo.length, sid, SCG_CH_MAIN), clientInfo,
      frameHeadPack(SCG_DATA_TYPE, attach.length, sid, SCG_CH_MAIN), attach
    ]));
    stats.responses += 2;
  };

  const waitChannelsList = async (waitSeconds = 20) => {
    const deadline = Date.now() + waitSeconds * 1000;
    while (Date.now() < deadline) {
      let frame;
      try { frame = await reader.readFrame(2000); } catch (e) { break; }
      if (!frame) continue;
      stats.frames += 1;
      reply(frame);
      if (frame.pktType === SCG_CONTROL_TYPE) continue;
      if (frame.field2 === SCG_CH_MAIN && frame.payload.length >= 6 &&
        frame.payload.readUInt16LE(0) === SPICE_MSG.CHANNELS_LIST) return;
    }
  };

  const waitDisplayMark = async (waitSeconds = 40) => {
    const deadline = Date.now() + waitSeconds * 1000;
    for (let i = 0; i < 20; i++) {
      if (Date.now() >= deadline) break;
      let frame;
      try { frame = await reader.readFrame(2000); } catch (e) { break; }
      if (!frame) continue;
      stats.frames += 1;
      reply(frame);
      if (frame.pktType === SCG_CONTROL_TYPE) continue;
      if (frame.field2 === SCG_CH_DISPLAY && frame.payload.length) {
        for (const r of handleDisplayPayload(frame.payload, progress)) {
          sock.write(Buffer.concat([frameHeadPack(SCG_DATA_TYPE, r.length, sid, SCG_CH_DISPLAY), r]));
        }
      }
      if (progress.markReceived) break;
      if (frame.field2 !== SCG_CH_DISPLAY || frame.payload.length < 6) continue;
      if (frame.payload.readUInt16LE(0) === SPICE_MSG.MARK) { progress.markReceived = true; break; }
    }
  };

  if (await authenticateChannel(SCG_CH_MAIN, SPICE_CH_MAIN_TYPE, 40.0)) {
    connected.push('main');
    const sid2 = await waitMainInit();
    if (sid2) {
      spiceSessionId = sid2;
      sendClientInfoAndAttach();
      await waitChannelsList();
      if (await authenticateChannel(SCG_CH_DISPLAY, SPICE_CH_DISPLAY_TYPE, 120.0, spiceSessionId)) {
        connected.push('display');
        const init = encodeDisplayInit();
        sock.write(Buffer.concat([frameHeadPack(SCG_DATA_TYPE, init.length, sid, SCG_CH_DISPLAY), init]));
        progress.displayInitSent = true;
        await waitDisplayMark();
        if (await authenticateChannel(SCG_CH_INPUTS, SPICE_CH_INPUTS_TYPE, 60.0, spiceSessionId)) connected.push('inputs');
        if (await authenticateChannel(SCG_CH_CURSOR, SPICE_CH_CURSOR_TYPE, 60.0, spiceSessionId)) connected.push('cursor');
      }
    }
  }

  return { sid, spiceSessionId, channels: connected, progress, stats, reader };
}

/**
 * 双平面 hold：快平面 ~1s 读帧/回包/trunk_switch 应答；慢平面 ~25s mouse_mode + 外部心跳。
 * 任何时刻都只如实统计，**不合成任何"假的活跃流量"**。
 */
async function holdScgSession(socket, {
  sid, holdSeconds, progress, stats, reader, onLog, onSlowPlane, shouldStop
}) {
  const log = (m, lvl = 'info') => { if (typeof onLog === 'function') onLog('SCG', m, lvl); };
  const started = Date.now();
  const deadline = started + holdSeconds * 1000;
  let lastSlow = null;
  let slowCount = 0;
  let lastProgressAt = started;

  for (;;) {
    if (typeof shouldStop === 'function' && shouldStop()) return { stopped: true, slowCount };
    const now = Date.now();
    if (now >= deadline) return { stopped: false, slowCount };
    if (now - lastProgressAt >= 10000) {
      lastProgressAt = now;
      log(`progress slow=${slowCount} frames=${stats.frames} responses=${stats.responses} ` +
        `left=${Math.round((deadline - now) / 1000)}s display=${isDisplayProven(progress) ? 'proven' : 'unproven'}`);
    }

    // 慢平面：~25s 一次
    if (lastSlow === null || now - lastSlow >= SCG_HOLD_KEEPALIVE_INTERVAL * 1000) {
      lastSlow = now;
      slowCount += 1;
      try { sendMouseMode(socket, sid); } catch (e) { log(`mouse_mode 发送失败：${e.message}`, 'warning'); }
      if (typeof onSlowPlane === 'function') {
        try { await onSlowPlane(); } catch (e) { log(`慢平面心跳异常：${e.message}`, 'warning'); }
      }
    }

    // 快平面：读一帧（1s 上限），顺手应答
    let frame;
    try {
      frame = await reader.readFrame(SCG_HOLD_SELECT_SECONDS * 1000);
    } catch (e) {
      return { stopped: false, slowCount, error: e.message };
    }
    if (!frame) continue;
    stats.frames += 1;
    if (frame.pktType === SCG_TRUNK_SWITCH && frame.payload.length >= 32) {
      const targetCid = frame.payload.readBigUInt64LE(0);
      const senderCid = frame.payload.readBigUInt64LE(8);
      const param = frame.payload.readUInt32LE(16);
      const reason = frame.payload.readUInt8(20);
      const extraId = frame.payload.readBigUInt64LE(24);
      socket.write(trunkSwitchPack(Number(targetCid), Number(senderCid), param, reason, Number(extraId), frame.field1, frame.field2));
      stats.trunkSwitchReplies += 1;
      continue;
    }
    if (frame.pktType === SCG_DATA_TYPE && frame.field2 === SCG_CH_DISPLAY && frame.payload.length) {
      for (const r of handleDisplayPayload(frame.payload, progress)) {
        socket.write(Buffer.concat([frameHeadPack(SCG_DATA_TYPE, r.length, sid, SCG_CH_DISPLAY), r]));
        stats.responses += 1;
      }
      continue;
    }
    replyKeepaliveFrame(socket, sid, frame, stats);
  }
}

/**
 * 跑一个完整的 SCG 切片（CEM 会话准备 → 建连 → 握手 → hold）。
 * 【2026-09-26 根因修复】数据面拨号必须使用 CEM 会话绑定的材料：
 *   firm-auth 的 scAuthCode 只是 OAuth ext-grant 令牌，直接拨号边缘一律静默丢包。
 * 顺序契约（回归机械拦截）：材料校验 → CEM 会话准备 → scgConnect → 握手 → hold。
 * @returns {Promise<object>} 如实计数；`keepaliveProven` **恒 false**
 */
async function runScgSession({
  firmAuth, holdSeconds = 900, timeoutMs = 10000, onLog, onSlowPlane, shouldStop
}) {
  const log = (m, lvl = 'info') => { if (typeof onLog === 'function') onLog('SCG', m, lvl); };
  const material = resolveScgMaterial(firmAuth); // 材料不全 ⇒ 直接抛，绝不带半套材料去拨（必须先于任何网络动作）
  log(`firm-auth 材料就绪：vmId=${material.vmId.slice(0, 8)}… scAuthCodeLen=${material.scAuthCode.length}（准备经 CEM 换会话材料）`);

  const session = await prepareScgSession(material, onLog);
  const conn = await scgConnect({
    host: session.host, port: session.port, scAuthCode: session.scAuthCode,
    vmId: material.vmId, timeoutMs, onLog
  });
  let handshake = null;
  let holdResult = null;
  try {
    handshake = await scgHandshake(conn.socket, { vmId: material.vmId, onLog });
    holdResult = await holdScgSession(conn.socket, {
      sid: handshake.sid,
      holdSeconds,
      progress: handshake.progress,
      stats: handshake.stats,
      reader: handshake.reader,
      onLog,
      onSlowPlane,
      shouldStop
    });
  } finally {
    try { handshake && handshake.reader && handshake.reader.detach(); } catch (_) { /* 已分离 */ }
    try { conn.socket.destroy(); } catch (_) { /* 已关闭 */ }
  }

  const displayProven = isDisplayProven(handshake.progress);
  return {
    sessionId: handshake.sid,
    authSessionId: conn.sessionId,
    spiceSessionId: handshake.spiceSessionId,
    channels: handshake.channels,
    progress: handshake.progress,
    stats: handshake.stats,
    slowCount: holdResult.slowCount,
    stopped: !!holdResult.stopped,
    error: holdResult.error || '',
    displayProven,
    // 诚实性：会话建立 / 显示面观察 都不等于"机器不会被关机"
    keepaliveProven: false
  };
}

module.exports = {
  // S0 · CEM 控制面
  prepareScgSession,
  cemBootVm,
  cemExchangeToken,
  cemGetConnectInfo,
  cemEncryptVmId,
  // S1
  resolveScgMaterial,
  describeScgMaterialPresence,
  // 协议编解码（供回归单测）
  scgAesCtrStream,
  buildScgAuthPacket,
  frameHeadPack,
  trunkSwitchPack,
  buildChannelAuth,
  findReplyPubkey,
  encodeSpiceTicket,
  encodeMiniMessage,
  encodeDisplayInit,
  stripSpiceTokenPrefix,
  decodeDisplayMessage,
  createProtocolProgress,
  isDisplayProven,
  applyDisplaySpiceType,
  handleDisplayPayload,
  // S2
  scgConnect,
  scgConnectOnce,
  // S3
  scgHandshake,
  holdScgSession,
  runScgSession,
  replyKeepaliveFrame,
  sendMouseMode,
  createFrameReader,
  // 常量
  SCG_FRAME_HEAD_SIZE,
  SCG_DATA_TYPE,
  SCG_CONTROL_TYPE,
  SCG_TRUNK_HELLO,
  SCG_TRUNK_DATA,
  SCG_TRUNK_SWITCH,
  SCG_TRUNK_GBN,
  SCG_CH_CTRL,
  SCG_CH_MAIN,
  SCG_CH_DISPLAY,
  SCG_CH_INPUTS,
  SCG_CH_CURSOR,
  SCG_CH_PLAYBACK,
  SCG_CH_RECORD,
  SPICE_MSG,
  SPICE_CH_MAIN_TYPE,
  SPICE_CH_DISPLAY_TYPE,
  SPICE_CH_INPUTS_TYPE,
  SPICE_CH_CURSOR_TYPE,
  CERT_CHAIN_ERROR_CODES,
  SCG_HOLD_SELECT_SECONDS,
  SCG_HOLD_KEEPALIVE_INTERVAL,
  SCG_CEM_BASE,
  SCG_CEM_CLIENT_ID,
  SCG_CEM_RSA_PUBLIC_KEY,
  SCG_CEM_SDK_UA,
  SCG_TLS_SNI
};
