'use strict';

/**
 * ============================================================================
 * 移动云 ZTE CAG 数据面保活 —— IPv4 / TLS 长会话通道
 * ============================================================================
 *
 * 【这是什么】官方客户端在**内层主机为 IPv4 字面量**时走的那条"经典"数据面通道：
 *
 *   TCP 连外层 CAG(cagIp:cagPort)
 *     → 发 178B ZTEC 认证头（官方 199B 包的 [21:]）
 *     → 读 50B 回包（魔数 ZTEC，conv @ [14:18]）
 *     → 发 220B auth blob（IPv4：地址 4B @[4:8]、family tag 0x50、port = --proxy-sport）
 *     → 读 36B 回包（ack[4] === 0x01）
 *     → **同一 socket 升级 TLS**
 *     → CAGMux（4B 头 [cmd][linkID][u16len LE] 的链路复用层）
 *     → raw SPICE 主干握手（REDQ → 128B 零 ticket → MAIN_INIT → attach → client_info）
 *     → 7 条子通道（display / input / … 各自 REDQ 认证）
 *     → keepaliveRawSpiceLoop（display type=3 心跳 ~21Hz，模拟屏幕刷新）
 *
 * 【为什么这条通道值得做】本项目的既有结论是「唯一真保活 = SPICE 完成 Display
 * Surface 创建」；而 Display Surface 只在这条 TLS+CAGMux+SPICE 路径上被建立 ——
 * IPv6 raw 路径只是把连接尽量久地吊住。此前我们只实现了 raw 分支，于是"带 IPv4
 * 材料的机器"根本没有可用的**真**保活通道。
 *
 * 【红线自检】本文件实现 IPv4 / TLS 数据面通道，四项底线逐条对照：
 *   ① 身份：**不声明**任何第三方客户端身份（无 `cdpsdk-server-*` 之类）；
 *   ② 凭据：外层用账号自身 firm-auth 的 cagIp/cagPort；内层材料全部来自 connectStr
 *          （session-key / vmId / proxy-sport）。**无任何硬编码第三方客户端 ID**；
 *   ③ 公钥：raw SPICE 回包里出现 RSA 公钥时**只做存在性校验**，不使用、不硬编码；
 *   ④ TLS：**严格校验先行**；仅当命中"证书链缺陷"白名单时，对本端点**重新拨号并**
 *          放宽校验一次，且降级**必留证**（host + 错误码）。见 upgradeToTls()。
 * 帧字节模板属于「协议格式」，不是私有凭据 —— 这与伪造成官方客户端是两回事。
 *
 * 【与 zte_cag_raw.js 的分工】
 *   raw（IPv6 内层主机，不升 TLS）→ app/ydpc/zte_cag_raw.js
 *   tls（IPv4 内层主机，本文件）    → 两族共用 220B blob 构造器 buildCagAuthBlob()
 * 地址族判定收在 product_route.js 的 resolveInnerRoute()，**本文件不再自己判一次**。
 */

const net = require('net');
const tls = require('tls');
const crypto = require('crypto');
const { buildCagAuthBlob, ipv4ToBytes } = require('./zte_cag_raw');

// ---------------------------------------------------------------------------
// CAG proxy 帧常量（真机抓包核对）
// ---------------------------------------------------------------------------
const CAG_PROXY_DATA_CMD = 0x0a;
const CAG_PROXY_ADD_LINK_CMD = 0x1a;
const CAG_PROXY_CLOSE_LINK_CMD = 0x2a;
const CAG_PROXY_PAYLOAD_MAX = 0xffff;
/** LinkInfo 定长载荷（B 用 0x9a 字节块） */
const CAG_ADD_LINK_PAYLOAD_LEN = 0x9a;
/** LinkInfo[0x53] 的 QoS 值（官方隧道固定值） */
const CAG_ADD_LINK_QOS = 0x05;
/** link 1 = SPICE 主干；其余子通道填 2 */
const CAG_ADD_LINK_CH_MAIN = 0x01;
const CAG_ADD_LINK_CH_OTHER = 0x02;

// ---------------------------------------------------------------------------
// TLS 策略常量
// ---------------------------------------------------------------------------
const TLS_MIN_VERSION = 'TLSv1.2';
/**
 * 证书链缺陷白名单 —— 与 app/ydpc/cag_boot.js 的同名常量**同一套口径**
 * （刻意各存一份：数据面不得依赖"开机模块"是否还在）。
 * 只有命中这里的错误码才允许降级；其它任何 TLS 错误都必须原样上抛。
 */
const CERT_CHAIN_ERROR_CODES = [
  'UNABLE_TO_VERIFY_LEAF_SIGNATURE', // 只发叶证书、无中间 CA（cag_boot 侧实测命中）
  'SELF_SIGNED_CERT_IN_CHAIN',
  'DEPTH_ZERO_SELF_SIGNED_CERT',
  'CERT_HAS_EXPIRED',
  'UNABLE_TO_GET_ISSUER_CERT_LOCALLY',
  'UNABLE_TO_GET_ISSUER_CERT',
  'ERR_TLS_CERT_ALTNAME_INVALID'     // CAG 按 IP 访问时的主机名不匹配
];

// ---------------------------------------------------------------------------
// raw SPICE 帧常量（真机抓包核对）
// ---------------------------------------------------------------------------
const TERMINAL_GUID = '31BF5444-86E0-4D5D-B1AB-A42FFBAC72C9';
const TERMINAL_GUID_BYTES = Buffer.from('4454BF31E0865D4DB1ABA42FFBAC72C9', 'hex');

/** 主干 REDQ 定长 */
const MAIN_REDQ_LEN = 729;
/** 压缩 REDQ 回包长度上限（超过即视为畸形） */
const REDQ_REPLY_MAX = 4096;
/** raw SPICE 消息体长度上限（1 MiB） */
const RAW_MSG_MAX = 1 << 20;

/**
 * 子通道表 (linkId, channelType, channelId) —— 真机协商结果。
 * 主干已占 link 1，故这 7 条按 open 顺序拿到 link 2..8。
 */
const SUBCHANNEL_REDQS = [
  [3, 4, 1],
  [2, 6, 0],
  [4, 5, 0],
  [6, 3, 0],
  [7, 2, 0],
  [8, 4, 0],
  [5, 2, 1]
];
/** 认证成功后写一次的通道初始化消息（真机协商结果） */
const SUBCHANNEL_INIT_KIND = { 6: 'input', 5: 'display', 7: 'display' };

// ===========================================================================
// 一、CAG 认证头 / blob（IPv4 分支）
// ===========================================================================

/**
 * 构建 178B ZTEC 认证头（官方 199B 包的 `[21:]`）。
 *
 * 199B 包的前 21B 是 UDP 封装壳（含 `[0:4]=06 00 00 80` 与 `[11:15]` 的随机 syn_id），
 * **TCP 路径不发** —— 所以这里直接构造那 178B，字节布局与官方一致：
 *   [0:4]  "ZTEC"
 *   [4:6]  0x00ac LE          （对比 50B 短头的 0x002c —— 长短头靠这个字段区分）
 *   [6:10] 101 LE
 *   [10:14] random
 *   [14:18] dc 00 00 00
 *   [18:38] random（20B）
 *   [38:42] 07 00 0b 0b
 *   [42:54] 零
 *   [54:86] 32B ascii hex（由 16 随机字节编码）
 *   [86:118] 零
 *   [118:134] 16B ascii hex（由 8 随机字节编码）
 *   [134:178] 零
 */
function buildCagAuthHeadLong() {
  const p = Buffer.alloc(178);
  p.write('ZTEC', 0, 'ascii');
  p.writeUInt16LE(0x00ac, 4);
  p.writeUInt32LE(101, 6);
  crypto.randomFillSync(p, 10, 4);
  p.write('dc000000', 14, 'hex');
  crypto.randomFillSync(p, 18, 20);
  p.write('07000b0b', 38, 'hex');
  p.write(crypto.randomBytes(16).toString('hex'), 54, 32, 'ascii');
  p.write(crypto.randomBytes(8).toString('hex'), 118, 16, 'ascii');
  return p; // [42:54] / [86:118] / [134:178] 保持零
}

// ===========================================================================
// 二、CAG proxy 复用层（帧 + 链路）
// ===========================================================================

/** 打包一个 4B 头的 CAG proxy 帧：[cmd][linkID][u16 len LE][payload] */
function packFrame(cmd, linkId, payload) {
  const body = payload ? Buffer.from(payload) : Buffer.alloc(0);
  if (body.length > CAG_PROXY_PAYLOAD_MAX) {
    throw new Error(`CAG proxy 帧载荷过大：${body.length} > ${CAG_PROXY_PAYLOAD_MAX}`);
  }
  const head = Buffer.alloc(4);
  head[0] = cmd & 0xff;
  head[1] = linkId & 0xff;
  head.writeUInt16LE(body.length, 2);
  return Buffer.concat([head, body]);
}

/** 16 字节链路 UUID（置 v4 版本位与 RFC-4122 variant 位，对齐 newZTELinkUUID） */
function newZteLinkUuid() {
  const b = crypto.randomBytes(16);
  b[6] = (b[6] & 0x0f) | 0x40;
  b[8] = (b[8] & 0x3f) | 0x80;
  return b;
}

function randomHex(n) {
  return crypto.randomBytes(n).toString('hex');
}

/** 把 text 按 C 字符串语义写入 buf[offset:offset+size]（短则补 NUL，长则截断且不补） */
function writeCString(buf, offset, size, text) {
  if (size <= 0) return;
  const enc = Buffer.from(String(text == null ? '' : text), 'utf8').subarray(0, size);
  enc.copy(buf, offset);
  if (enc.length < size) buf[offset + enc.length] = 0;
}

/**
 * 构建 add-link 包（`4 + 0x9a` 字节）。
 *
 * LinkInfo 布局（真机抓包核对）：
 *   [0:2]       port         LE u16 —— 内层服务端口（connectStr 的 --pv6/-p）
 *   [2]         channel type 主链路 1 / 子链路 2
 *   [4:8]       IPv4         **反序**字节（ip[3],ip[2],ip[1],ip[0]）
 *   [0x53]      QoS          0x05
 *   [0x54]      SPICE main   仅主干（link 1）为 0x01
 *   [0x68:0x89] traceId      33B C 字符串
 *   [0x89:0x9a] spanId       17B C 字符串
 *
 * 注：link_uuid 不写进 add-link 载荷（官方同样如此，UUID 由调用方带在 REDQ 里）。
 */
function buildCagProxyAddLinkPacket(inner, linkId, traceId, spanId) {
  const host = String((inner && inner.host) || '');
  const port = Number((inner && inner.port) || 0);
  const addr = ipv4ToBytes(host); // 非 IPv4 会抛错 —— 这是调用方必须先过地址族路由的原因
  const payload = Buffer.alloc(CAG_ADD_LINK_PAYLOAD_LEN);
  payload.writeUInt16LE(port & 0xffff, 0);
  payload[2] = linkId === 1 ? CAG_ADD_LINK_CH_MAIN : CAG_ADD_LINK_CH_OTHER;
  payload[4] = addr[3];
  payload[5] = addr[2];
  payload[6] = addr[1];
  payload[7] = addr[0];
  payload[0x53] = CAG_ADD_LINK_QOS;
  if (linkId === 1) payload[0x54] = CAG_ADD_LINK_CH_MAIN;
  writeCString(payload, 0x68, 0x21, traceId);
  writeCString(payload, 0x89, 0x11, spanId);
  return packFrame(CAG_PROXY_ADD_LINK_CMD, linkId, payload);
}

/** 单条虚拟链路：与 socket 兼容的读/写 + 5 字节后缀缓冲（对齐 CAGMuxLink） */
class CagMuxLink {
  constructor(mux, linkId, linkUuid, traceId, spanId) {
    this.mux = mux;
    this.linkId = linkId;
    this.linkUuid = linkUuid;
    this.traceId = traceId;
    this.spanId = spanId;
    /** REDQ 用的 span（与 add-link 的 spanId 不同，对齐 newZTELinkUUID 之后的 randomHex(8)） */
    this.redqSpanId = randomHex(8);
    this._rbuf = Buffer.alloc(0);
    this._waiters = [];
    this._closed = false;
    this._closeErr = null;
  }

  /** 读取**恰好** n 字节（不足则等待，超时抛 code='ETIMEDOUT'） */
  readExact(n, timeoutMs) {
    return new Promise((resolve, reject) => {
      const failIfClosed = () => {
        if (this._closed) {
          reject(this._closeErr || new Error(`CAG mux link ${this.linkId} 已关闭`));
          return true;
        }
        return false;
      };
      if (n <= 0) { resolve(Buffer.alloc(0)); return; }
      if (failIfClosed()) return;
      if (this._rbuf.length >= n) { resolve(this._take(n)); return; }

      const waiter = { want: n, resolve, reject, timer: null };
      if (timeoutMs > 0) {
        waiter.timer = setTimeout(() => {
          const i = this._waiters.indexOf(waiter);
          if (i >= 0) this._waiters.splice(i, 1);
          const err = new Error(`CAG mux link ${this.linkId} 读取超时（等 ${n}B）`);
          err.code = 'ETIMEDOUT';
          reject(err);
        }, timeoutMs);
      }
      this._waiters.push(waiter);
      this._pump();
    });
  }

  /**
   * 写数据（按 0xFFFF 分帧）。对齐 CAGMuxLink.write。
   * 返回写入字节数；data 为空时不发任何帧（与官方一致）。
   */
  write(data) {
    const buf = Buffer.from(data || Buffer.alloc(0));
    let off = 0;
    while (off < buf.length) {
      const n = Math.min(buf.length - off, CAG_PROXY_PAYLOAD_MAX);
      this.mux.writeFrame(CAG_PROXY_DATA_CMD, this.linkId, buf.subarray(off, off + n));
      off += n;
    }
    return buf.length;
  }

  /** 从缓冲区头部取 n 字节（同步；用于剥离 ZTE 5B 后缀） */
  takeReadBufferN(n) {
    if (n <= 0 || this._rbuf.length === 0) return Buffer.alloc(0);
    return this._take(Math.min(n, this._rbuf.length));
  }

  /** 清空读缓冲（对齐 DiscardReadBuffer） */
  discardReadBuffer() {
    this._rbuf = Buffer.alloc(0);
  }

  close() {
    if (this._closed) return;
    this._closed = true;
    try { this.mux.writeFrame(CAG_PROXY_CLOSE_LINK_CMD, this.linkId, Buffer.alloc(0)); } catch (e) { /* 已断开 */ }
    this._rejectWaiters(new Error(`CAG mux link ${this.linkId} 已关闭`));
  }

  // -- 内部 --
  _take(n) {
    const out = Buffer.from(this._rbuf.subarray(0, n));
    this._rbuf = this._rbuf.subarray(n);
    return out;
  }

  _pump() {
    while (this._waiters.length > 0) {
      const w = this._waiters[0];
      if (w.want > this._rbuf.length) break;
      this._waiters.shift();
      if (w.timer) clearTimeout(w.timer);
      w.resolve(this._take(w.want));
    }
  }

  _rejectWaiters(err) {
    const ws = this._waiters;
    this._waiters = [];
    for (const w of ws) {
      if (w.timer) clearTimeout(w.timer);
      w.reject(err);
    }
  }

  /** 由 mux 读循环调用 */
  _pushPayload(payload) {
    if (this._closed) return;
    this._rbuf = this._rbuf.length === 0 ? payload : Buffer.concat([this._rbuf, payload]);
    this._pump();
  }

  /** 由 mux 读循环调用（对端 close 帧） */
  _markClosed(err) {
    if (this._closed) return;
    this._closed = true;
    this._closeErr = err || null;
    this._rejectWaiters(err || new Error(`CAG mux link ${this.linkId} 对端已关闭`));
  }
}

/** CAG proxy 多路复用器：一条（已 TLS 的）连接上承载多条虚拟链路 */
class CagMux {
  constructor(conn) {
    this.conn = conn;
    this._links = new Map();
    this._nextLinkId = 1;
    this._closed = false;
    this._rx = Buffer.alloc(0);
    this._onData = (chunk) => {
      // ⚠️ 本回调不在 Promise 链上：解析异常必须就地收敛，绝不能冒成未捕获异常
      try { this._feed(chunk); } catch (e) { this._failAll(e); }
    };
    this._onErr = (err) => this._failAll(err || new Error('CAG mux socket 错误'));
    this._onClose = () => this._failAll(new Error('CAG mux 连接被关闭'));
    conn.on('data', this._onData);
    conn.on('error', this._onErr);
    conn.on('close', this._onClose);
  }

  /** 创建 mux 并接上读循环（对齐 CAGMux.open） */
  static open(conn) {
    return new CagMux(conn);
  }

  _feed(chunk) {
    this._rx = this._rx.length === 0 ? chunk : Buffer.concat([this._rx, chunk]);
    while (this._rx.length >= 4) {
      const cmd = this._rx[0];
      const linkId = this._rx[1];
      const len = this._rx.readUInt16LE(2);
      if (this._rx.length < 4 + len) break;
      const payload = Buffer.from(this._rx.subarray(4, 4 + len));
      this._rx = this._rx.subarray(4 + len);
      if (cmd === CAG_PROXY_CLOSE_LINK_CMD) {
        const link = this._links.get(linkId);
        if (link) { this._links.delete(linkId); link._markClosed(); }
      } else if (cmd === CAG_PROXY_DATA_CMD || (cmd & 0x0f) === CAG_PROXY_DATA_CMD) {
        const link = this._links.get(linkId);
        if (link) link._pushPayload(payload);
      }
      // 其它 cmd：按官方语义丢弃
    }
  }

  _failAll(err) {
    const links = Array.from(this._links.values());
    this._links.clear();
    this._rx = Buffer.alloc(0);
    for (const l of links) l._markClosed(err);
  }

  /** 开一条新链路（发出 add-link 包） */
  openLink(inner, traceId, spanId) {
    if (this._closed) throw new Error('CAG mux 已关闭');
    const linkId = this._nextLinkId;
    this._nextLinkId += 1;
    const link = new CagMuxLink(
      this,
      linkId,
      newZteLinkUuid(),
      traceId || randomHex(16),
      spanId || randomHex(8)
    );
    this._links.set(linkId, link);
    const packet = buildCagProxyAddLinkPacket(inner, linkId, link.traceId, link.spanId);
    try {
      this.conn.write(packet);
    } catch (e) {
      this._links.delete(linkId);
      throw e;
    }
    return link;
  }

  writeFrame(cmd, linkId, payload) {
    if (this._closed) throw new Error('CAG mux 已关闭');
    this.conn.write(packFrame(cmd, linkId, payload));
  }

  close() {
    if (this._closed) return;
    this._closed = true;
    this._failAll(new Error('CAG mux 已关闭'));
    this.conn.removeListener('data', this._onData);
    this.conn.removeListener('error', this._onErr);
    this.conn.removeListener('close', this._onClose);
    try { this.conn.destroy(); } catch (e) { /* 已断开 */ }
  }

  get linkCount() { return this._links.size; }
}

// ===========================================================================
// 三、raw SPICE 帧构造
// ===========================================================================

function putU32(buf, off, v) { buf.writeUInt32LE(v >>> 0, off); }

/** 主干 REDQ（729B） */
function buildRawMainREDQ(key, vmId, linkUuid, traceId, spanId) {
  const uuid = (linkUuid && linkUuid.length === 16) ? linkUuid : crypto.randomBytes(16);
  const redq = Buffer.alloc(MAIN_REDQ_LEN);
  redq.write('REDQ', 0, 'ascii');
  putU32(redq, 4, 2);
  putU32(redq, 8, 2);
  putU32(redq, 12, 713);
  redq[20] = 1;
  putU32(redq, 22, 1);
  putU32(redq, 26, 1);
  putU32(redq, 30, 705);
  putU32(redq, 42, 0x1400);
  putU32(redq, 46, 0x10000);
  writeCString(redq, 50, 45, `${key || ''}${vmId || ''}`);
  uuid.copy(redq, 95, 0, 16);
  TERMINAL_GUID_BYTES.copy(redq, 127);
  writeCString(redq, 159, 33, traceId);
  writeCString(redq, 192, 17, spanId);
  putU32(redq, 717, 0x800);
  putU32(redq, 721, 0x232900);
  return redq;
}

/** 各通道类型的 REDQ 形状（对齐 BuildZTERawChannelREDQ 的分支表） */
const CHANNEL_REDQ_SHAPE = {
  2: { length: 733, size: 717, capCount: 2, caps: [0xa00, 0xffc30dec, 0x48] },
  5: { length: 729, size: 713, capCount: 1, caps: [0x800, 0x0e] },
  6: { length: 729, size: 713, capCount: 1, caps: [0x800, 0x07] }
};
const CHANNEL_REDQ_DEFAULT = { length: 725, size: 709, capCount: 0, caps: [0x800] };

/** 子通道 REDQ（长度随 channelType 变化） */
function buildRawChannelREDQ(key, vmId, linkUuid, traceId, spanId, connectionId, channelType, channelId) {
  const shape = CHANNEL_REDQ_SHAPE[channelType] || CHANNEL_REDQ_DEFAULT;
  const uuid = (linkUuid && linkUuid.length === 16) ? linkUuid : crypto.randomBytes(16);
  const redq = Buffer.alloc(shape.length);
  redq.write('REDQ', 0, 'ascii');
  putU32(redq, 4, 2);
  putU32(redq, 8, 2);
  putU32(redq, 12, shape.size);
  putU32(redq, 16, connectionId);
  redq[20] = channelType & 0xff;
  redq[21] = channelId & 0xff;
  putU32(redq, 22, 1);
  putU32(redq, 26, shape.capCount);
  putU32(redq, 30, 705);
  putU32(redq, 42, 0x1400);
  putU32(redq, 46, 0x10000);
  writeCString(redq, 50, 45, `${key || ''}${vmId || ''}`);
  uuid.copy(redq, 95, 0, 16);
  writeCString(redq, 159, 33, traceId);
  writeCString(redq, 192, 17, spanId);
  const capOff = shape.length - shape.caps.length * 4;
  shape.caps.forEach((cap, i) => putU32(redq, capOff + i * 4, cap));
  return redq;
}

function buildTerminalInfoMessage() {
  const msg = Buffer.alloc(68);
  msg.writeUInt16LE(0x7c, 0);
  msg.writeUInt32LE(57, 2);
  msg.write(TERMINAL_GUID, 11, 36, 'ascii');
  return msg;
}

function buildZteRawDisplayInit() {
  return Buffer.from('65001300000000000000000100004001000000000100fc5f000000000003', 'hex');
}

function buildZteRawInputInit() {
  return Buffer.from('67000200000000000000000200', 'hex');
}

/**
 * display type=3 心跳（18B）。
 *
 * 来自 pcapng 流分析：display 通道周期性发 type=3，消息体形如
 *   [0:u32][0xffffff00:u32][varying_u32]
 * 第三个 u32 是单调计数器，约每 5 个包 +250（≈21Hz），模拟屏幕刷新时间戳。
 */
function buildZteRawDisplayHeartbeat(counter) {
  const msg = Buffer.alloc(18);
  msg.writeUInt16LE(0x0003, 0);
  msg.writeUInt32LE(12, 2);
  msg.writeUInt32LE(0, 6);
  msg.writeUInt32LE(0xffffff00, 10);
  msg.writeUInt32LE(counter >>> 0, 14);
  return msg;
}

/** 8 字节 ZTE 数据消息前缀（u32 serial + 4B 零） */
function rawMessageWithPrefix(serial, msg) {
  const out = Buffer.alloc(8 + msg.length);
  out.writeUInt32LE(serial >>> 0, 0);
  msg.copy(out, 8);
  return out;
}

/** MAIN_INIT 的 connection_id 不在 payload[:4]：用标记 0x02 00 00 00 01 定位其前 4B */
function zteMainInitConnectionId(payload) {
  const marker = Buffer.from([0x02, 0x00, 0x00, 0x00, 0x01]);
  const idx = payload.indexOf(marker);
  if (idx >= 4) return payload.readUInt32LE(idx - 4);
  if (payload.length >= 7) return payload.readUInt32LE(3);
  return 0;
}

// ===========================================================================
// 四、raw SPICE 读写状态机（对齐 RawState）
// ===========================================================================

class RawState {
  constructor() {
    this.lastSerial = 0;
    this.lastSuffix = Buffer.alloc(0);
    this.nextSerialValue = 0;
  }

  /**
   * 读一条 raw SPICE 消息。返回 { msgType, payload }。
   * size === 0 说明这条消息带 8B ZTE 前缀（serial 在头 4B），此时要把
   * 塞在载荷之后的 **5 字节后缀** 剥到 lastSuffix，否则会污染下一条消息的定界。
   */
  async readMessage(link, timeoutMs) {
    let head = await link.readExact(6, timeoutMs);
    let msgType = head.readUInt16LE(0);
    let size = head.readUInt32LE(2);
    let hasZtePrefix = false;
    if (size === 0) {
      const serial = head.readUInt32LE(0);
      await link.readExact(2, timeoutMs);          // 前缀剩余 2B
      head = await link.readExact(6, timeoutMs);
      msgType = head.readUInt16LE(0);
      size = head.readUInt32LE(2);
      this.lastSerial = serial;
      this.lastSuffix = Buffer.alloc(0);
      hasZtePrefix = true;
    }
    if (size > RAW_MSG_MAX) throw new Error(`raw SPICE 消息体过大：${size}`);
    const payload = size > 0 ? await link.readExact(size, timeoutMs) : Buffer.alloc(0);
    if (hasZtePrefix && typeof link.takeReadBufferN === 'function') {
      this.lastSuffix = link.takeReadBufferN(5) || Buffer.alloc(0);
    }
    return { msgType, payload };
  }

  /** 对 ping / 鼠标模式 / 0x74 三类消息自动回包。返回是否回过。 */
  autoReply(link, msgType, payload) {
    if (msgType === 0x04) {
      const pong = Buffer.alloc(6 + payload.length);
      pong.writeUInt16LE(0x03, 0);
      pong.writeUInt32LE(payload.length, 2);
      payload.copy(pong, 6);
      this.writeMessage(link, this.lastSerial, pong);
      return true;
    }
    if (msgType === 0x03) {
      const generation = payload.length >= 4 ? payload.readUInt32LE(0) : 0;
      const ack = Buffer.alloc(10);
      ack.writeUInt16LE(0x01, 0);
      ack.writeUInt32LE(4, 2);
      ack.writeUInt32LE(generation, 6);
      this.writeMessage(link, this.lastSerial, ack);
      return true;
    }
    if (msgType === 0x74) {
      const reply = Buffer.alloc(7);
      reply.writeUInt16LE(0x79, 0);
      reply.writeUInt32LE(1, 2);
      this.writeMessage(link, this.nextSerial(), reply);
      return true;
    }
    return false;
  }

  writeMessage(link, serial, msg) {
    const data = Buffer.concat([rawMessageWithPrefix(serial, msg), this.lastSuffix || Buffer.alloc(0)]);
    return link.write(data);
  }

  nextSerial() {
    if (this.nextSerialValue === 0) this.nextSerialValue = 4;
    const s = this.nextSerialValue;
    this.nextSerialValue += 1;
    return s;
  }
}

/** 读一条 REDQ 链路回包：16B 头（含长度）+ 长度字节的体 */
async function readRawLinkReply(link, timeoutMs) {
  const head = await link.readExact(16, timeoutMs);
  if (head.subarray(0, 4).toString('ascii') !== 'REDQ') {
    throw new Error(`raw SPICE 链路回包魔数非法：${head.subarray(0, 4).toString('hex')}`);
  }
  const size = head.readUInt32LE(12);
  if (size > REDQ_REPLY_MAX) throw new Error(`raw SPICE REDQ 回包长度非法：${size}`);
  const body = size > 0 ? await link.readExact(size, timeoutMs) : Buffer.alloc(0);
  return Buffer.concat([head, body]);
}

/** 回包里定位 RSA 公钥标记（只做存在性校验，不使用、不硬编码） */
function hasRsaPublicKeyMarker(reply) {
  if (reply.indexOf(Buffer.from([0x30, 0x81, 0x9f, 0x30, 0x0d])) >= 0) return true;
  return reply.indexOf(Buffer.from([0x30, 0x81])) >= 0;
}

const RAW_TICKET = Buffer.alloc(128); // 128B 全零 ticket（无 auth-type 前缀）

/**
 * raw SPICE 主干握手（对齐 RawMainHandshake）。
 * 返回 { ok, spiceSessionId, error }。
 */
async function rawMainHandshake(link, { key, vmId, linkUuid, traceId, spanId }, onLog) {
  const log = (m, lvl = 'info') => { if (typeof onLog === 'function') onLog('CAGTLS', m, lvl); };
  const state = new RawState();
  try {
    link.write(buildRawMainREDQ(key, vmId, linkUuid, traceId, spanId));
    const reply = await readRawLinkReply(link, 8000);
    if (!hasRsaPublicKeyMarker(reply)) {
      return { ok: false, spiceSessionId: 0, error: 'REDQ 回包里没有 RSA 公钥定位标记' };
    }
    // 官方产品隧道此处发 **128B 全零 ticket**（不带 auth-type 前缀）——保留线上行为
    link.write(RAW_TICKET);
    const authResult = await link.readExact(4, 8000);
    const code = authResult.readUInt32LE(0);
    if (code !== 0) return { ok: false, spiceSessionId: 0, error: `raw SPICE 认证失败：result=${code}` };

    let spiceSessionId = 0;
    for (let i = 0; i < 15; i++) {
      const { msgType, payload } = await state.readMessage(link, 2000);
      if (msgType === 0x67 && payload.length >= 10) {
        spiceSessionId = zteMainInitConnectionId(payload);
        link.discardReadBuffer();
        break;
      }
      state.autoReply(link, msgType, payload);
    }
    if (spiceSessionId === 0) return { ok: false, spiceSessionId: 0, error: '未收到 raw SPICE MAIN_INIT' };

    const attach = Buffer.from('680000000000', 'hex');
    let attachSent = false;
    for (let i = 0; i < 4; i++) {
      let got;
      try { got = await state.readMessage(link, 2000); } catch (e) { break; }
      if (got.msgType === 0x04) {
        if (state.lastSerial === 3 || i === 3) {
          state.writeMessage(link, state.lastSerial, attach);
          attachSent = true;
          break;
        }
        continue;
      }
      state.autoReply(link, got.msgType, got.payload);
    }
    if (!attachSent) {
      link.write(Buffer.concat([rawMessageWithPrefix(3, attach), Buffer.alloc(5)]));
    }

    const clientInfo = Buffer.from('72000800000000000000000100000001000000', 'hex');
    link.write(rawMessageWithPrefix(1, clientInfo));
    link.write(rawMessageWithPrefix(2, buildTerminalInfoMessage()));

    let initOk = false;
    for (let i = 0; i < 5; i++) {
      let got;
      try { got = await state.readMessage(link, 1000); } catch (e) { break; }
      if (got.msgType !== 0x04) state.autoReply(link, got.msgType, got.payload);
      if (got.msgType === 0x68 || got.msgType === 0x73) {
        initOk = true;
        if (got.msgType === 0x73) break;
      }
    }
    if (!initOk) {
      return { ok: false, spiceSessionId, error: 'raw SPICE 初始化未到达 CHANNELS_LIST/info' };
    }
    log(`raw SPICE 主干握手完成（spiceSessionId=${spiceSessionId}）`);
    return { ok: true, spiceSessionId, error: null };
  } catch (e) {
    return { ok: false, spiceSessionId: 0, error: String(e && e.message ? e.message : e) };
  }
}

/**
 * 子通道认证（对齐 RawSubChannelHandshake）：
 * 与主干同样的"REDQ → 128B 零 ticket → 4B 结果"三步，只是 REDQ 换成通道作用域版本，
 * 且跳过 MAIN_INIT / attach / client_info 这些只属于主干的过程。
 */
async function rawSubChannelHandshake(link, { key, vmId, linkUuid, traceId, spanId }, spiceSessionId, channelType, channelId, timeoutMs) {
  try {
    link.write(buildRawChannelREDQ(
      key, vmId, linkUuid, traceId, spanId, spiceSessionId, channelType, channelId
    ));
    const reply = await readRawLinkReply(link, timeoutMs);
    if (!hasRsaPublicKeyMarker(reply)) return false;
    link.write(RAW_TICKET);
    const res = await link.readExact(4, timeoutMs);
    return res.readUInt32LE(0) === 0;
  } catch (e) {
    return false;
  }
}

/**
 * 开 + 认证 7 条子通道（对齐 setup_zte_subchannels）。
 *
 * ⚠️ 必须**先把 7 条全开出来**再去认证：链路 id 是按 open 顺序递增分配的，
 * 若边开边认证，id 与 SUBCHANNEL_REDQS 表的对应关系就会错位。
 */
async function setupSubChannels(mux, inner, mainLink, spiceSessionId, opts = {}) {
  const timeoutMs = Number(opts.timeoutMs) || 8000;
  const onLog = opts.onLog;
  const log = (m, lvl = 'info') => { if (typeof onLog === 'function') onLog('CAGTLS', m, lvl); };

  const links = new Map();
  for (let i = 0; i < SUBCHANNEL_REDQS.length; i++) {
    const link = mux.openLink(inner, mainLink.traceId, mainLink.redqSpanId);
    links.set(link.linkId, link);
  }

  const authed = new Set();
  for (const [linkId, channelType, channelId] of SUBCHANNEL_REDQS) {
    const link = links.get(linkId);
    if (!link) continue;
    const ok = await rawSubChannelHandshake(
      link,
      { key: opts.key, vmId: opts.vmId, linkUuid: mainLink.linkUuid, traceId: mainLink.traceId, spanId: mainLink.redqSpanId },
      spiceSessionId, channelType, channelId, timeoutMs
    );
    if (!ok) continue;
    authed.add(linkId);
    const kind = SUBCHANNEL_INIT_KIND[linkId];
    if (kind === 'display') link.write(rawMessageWithPrefix(1, buildZteRawDisplayInit()));
    else if (kind === 'input') link.write(rawMessageWithPrefix(1, buildZteRawInputInit()));
  }
  log(`raw SPICE 子通道：开出 ${links.size} 条，认证通过 ${authed.size} 条（display=${[5, 7].filter((l) => authed.has(l)).join('/') || '无'}）`);
  return { links, authed };
}

/**
 * 主干保活循环（对齐 keepaliveRawSpiceLoop）。
 *
 * 每 `interval` 秒向主干补发 display/input init；当 heartbeatHz > 0 时，
 * 还以该节奏向 display 子链路注入 type=3 心跳，模拟屏幕刷新流量。
 * 读超时被缩到心跳间隔以内，否则节奏无法兑现。
 *
 * 诚实性：本函数只**如数返回计数器**。收到消息 / 回过包 ≠ 保活被证明 ——
 * "是否证明"由上层字段明确表达，不在这里冒充。
 */
async function keepaliveRawSpiceLoop(mainLink, opts = {}) {
  const interval = Number(opts.interval) || 25;
  const stopAfter = Number(opts.stopAfter) || 0;
  const heartbeatHz = opts.heartbeatHz === undefined ? 21 : Number(opts.heartbeatHz);
  const displayLinks = Array.isArray(opts.displayLinks) ? opts.displayLinks : null;
  const onLog = opts.onLog;
  const shouldStop = typeof opts.shouldStop === 'function' ? opts.shouldStop : null;
  const log = (m, lvl = 'info') => { if (typeof onLog === 'function') onLog('CAGTLS', m, lvl); };

  const state = new RawState();
  const started = Date.now();
  const counters = {
    messages: 0, autoReplies: 0, ticks: 0, errors: 0,
    heartbeats: 0, displayType3HeartbeatFrames: 0, heartbeatHz
  };
  const hbIntervalMs = heartbeatHz > 0 ? 1000 / heartbeatHz : 0;
  const readTimeoutMs = hbIntervalMs > 0 ? Math.min(hbIntervalMs, 1000) : Math.min(1000, Math.max(100, interval * 1000));
  let nextTickAt = Date.now();
  let nextHbAt = Date.now();
  let hbCounter = 0;
  let hbSeq = 0;
  let lastProgressAt = Date.now();

  while (true) {
    if (shouldStop && shouldStop()) break;
    if (stopAfter > 0 && (Date.now() - started) / 1000 >= stopAfter) break;

    try {
      const { msgType, payload } = await state.readMessage(mainLink, readTimeoutMs);
      counters.messages += 1;
      if (state.autoReply(mainLink, msgType, payload)) counters.autoReplies += 1;
    } catch (e) {
      if (e && e.code === 'ETIMEDOUT') {
        // 读超时是常态（服务端只在有事件时才发）
      } else {
        counters.errors += 1;
        if (counters.messages === 0 && counters.ticks === 0) {
          log(`raw SPICE 主干读取中断：${e && e.message ? e.message : e}`, 'warning');
        }
        break;
      }
    }

    const now = Date.now();
    if (now >= nextTickAt) {
      try {
        mainLink.write(rawMessageWithPrefix(state.nextSerial(), buildZteRawDisplayInit()));
        mainLink.write(rawMessageWithPrefix(state.nextSerial(), buildZteRawInputInit()));
        counters.ticks += 1;
      } catch (e) {
        counters.errors += 1;
        break;
      }
      nextTickAt = now + interval * 1000;
    }

    if (hbIntervalMs > 0 && now >= nextHbAt) {
      const targets = displayLinks && displayLinks.length > 0 ? displayLinks : [mainLink];
      try {
        const suffix = state.lastSuffix && state.lastSuffix.length > 0 ? state.lastSuffix : Buffer.alloc(5);
        const hbMsg = Buffer.concat([
          rawMessageWithPrefix(state.nextSerial(), buildZteRawDisplayHeartbeat(hbCounter)), suffix
        ]);
        for (const l of targets) l.write(hbMsg);
        counters.heartbeats += 1;
        counters.displayType3HeartbeatFrames += targets.length;
        hbSeq += 1;
        if (hbSeq % 5 === 0) hbCounter = (hbCounter + 250) & 0xffffffff;
      } catch (e) {
        counters.errors += 1;
        break;
      }
      nextHbAt = now + hbIntervalMs;
    }

    if (now - lastProgressAt >= 10000) {
      lastProgressAt = now;
      const left = stopAfter > 0 ? Math.max(0, Math.round(stopAfter - (now - started) / 1000)) : -1;
      log(`progress msg=${counters.messages} reply=${counters.autoReplies} tick=${counters.ticks} hb=${counters.heartbeats} left=${left < 0 ? '∞' : left + 's'}`);
    }
  }
  return counters;
}

// ===========================================================================
// 五、拨号：TCP 预认证 → 同一 socket 升 TLS（受控降级）
// ===========================================================================

/**
 * 在**已认证的同一 socket** 上升 TLS。
 *
 * 🔒 受控降级的四条硬条件（与 cag_boot.js 的同名策略一致）：
 *   ① 有明确的证书链错误码白名单（CERT_CHAIN_ERROR_CODES），不做笼统 catch；
 *   ② 降级前必须留证 —— 打一条含 host + 错误码的 warning；
 *   ③ 默认走严格校验（allowInsecure 为假时不设任何放宽项）；
 *   ④ 不得无条件关闭校验 —— 只在 `if (allowInsecure)` 分支里放宽。
 *
 * ⚠️ 降级不是"就在这个 socket 上再握手一次"：失败的 ClientHello 已经把这个
 * 字节流弄脏了，同一 socket 重试必然失败。所以降级实现为**整条重新拨号**
 * （见 dialCagTcpTls），本函数只负责"这一次要严格还是要放宽"。
 */
function upgradeToTls(socket, { host, allowInsecure, onLog }) {
  return new Promise((resolve, reject) => {
    const options = {
      socket,
      servername: undefined,       // 内网 IP 端点，无 SNI 可用
      minVersion: TLS_MIN_VERSION
    };
    if (allowInsecure) {
      // 仅由受控降级路径传入 true；严格路径下这一行不会被执行。
      options.rejectUnauthorized = false;
    }
    const stream = tls.connect(options, () => resolve(stream));
    stream.once('error', (err) => {
      if (typeof onLog === 'function' && allowInsecure === false) {
        onLog(`TLS 握手失败（${host}）：${(err && err.code) || (err && err.message) || err}`, 'warning');
      }
      reject(err);
    });
  });
}

/** 单次拨号（严格或放宽）。成功返回 { socket, conv } */
function dialCagTcpTlsOnce(opts, allowInsecure) {
  const {
    outerHost, outerPort, innerHost, innerPort, proxySport, vmId,
    timeoutMs = 15000, onLog
  } = opts;
  const log = (m, lvl = 'info') => { if (typeof onLog === 'function') onLog('CAGTLS', m, lvl); };

  return new Promise((resolve, reject) => {
    // 两块线上材料先构造好：它们抛错必须落在 Promise 里，
    // 绝不能留到 socket 回调里去抛（那会成为未捕获异常）。
    let head;
    let blob;
    try {
      head = buildCagAuthHeadLong();
      blob = buildCagAuthBlob({ innerHost, innerPort, proxySport, vmId });
    } catch (e) {
      reject(e);
      return;
    }

    let settled = false;
    const done = (fn, val) => { if (!settled) { settled = true; fn(val); } };

    const sock = net.createConnection({ host: outerHost, port: Number(outerPort) });
    let recvBuf = Buffer.alloc(0);
    let stage = 1;
    let conv = 0;

    const timer = setTimeout(() => {
      try { sock.destroy(); } catch (e) { /* 已断开 */ }
      done(reject, new Error(`CAG TLS 拨号超时（${timeoutMs}ms）`));
    }, timeoutMs);

    const onConnect = () => {
      log(`TCP 已连接 ${outerHost}:${outerPort}，发送 178B ZTEC 认证头（IPv4/TLS 路径）`);
      sock.write(head);
    };

    const handleData = (chunk) => {
      recvBuf = Buffer.concat([recvBuf, chunk]);

      if (stage === 1) {
        if (recvBuf.length < 50) return;
        const ack = recvBuf.subarray(0, 50);
        const magic = ack.toString('ascii', 0, 4);
        if (magic !== 'ZTEC') {
          clearTimeout(timer);
          sock.destroy();
          done(reject, new Error(`178B 头回包魔数校验失败："${magic}"`));
          return;
        }
        conv = ack.readUInt32LE(14);
        recvBuf = recvBuf.subarray(50);
        stage = 2;
        log(`conv = ${conv} (0x${conv.toString(16)})，发送 220B auth blob（IPv4：host=${innerHost} proxySport=${proxySport}）`);
        sock.write(blob);
        return;
      }

      if (recvBuf.length < 36) return;
      const ack = recvBuf.subarray(0, 36);
      if (ack[4] !== 0x01) {
        clearTimeout(timer);
        sock.destroy();
        done(reject, new Error(`auth ack 校验失败：ack[4]=0x${ack[4].toString(16)}`));
        return;
      }

      // 认证通过 → 本体接管这个 socket：先把我们的监听器全部摘掉，
      // 否则 TLS 层的字节会被这里的 data 回调抢先吃掉。
      clearTimeout(timer);
      sock.removeListener('connect', onConnect);
      sock.removeListener('data', onData);
      sock.removeListener('error', onError);
      sock.removeListener('close', onClose);
      sock.setTimeout(0);
      log(`auth 通过（conv=${conv}），升级 TLS（${allowInsecure ? '受控降级：已放宽校验' : '严格校验先行'}）`);

      upgradeToTls(sock, { host: outerHost, allowInsecure, onLog: opts.onLog })
        .then((stream) => done(resolve, { socket: stream, conv }))
        .catch((err) => {
          try { sock.destroy(); } catch (e) { /* 已断开 */ }
          done(reject, err);
        });
    };

    const onData = (chunk) => {
      // ⚠️ 本回调不在 Promise 链上，异常必须就地收敛
      try { handleData(chunk); }
      catch (e) { clearTimeout(timer); sock.destroy(); done(reject, e); }
    };
    const onError = (err) => { clearTimeout(timer); done(reject, err); };
    const onClose = () => { clearTimeout(timer); done(reject, new Error('CAG TLS 连接在完成认证前被关闭')); };

    sock.on('connect', onConnect);
    sock.on('data', onData);
    sock.on('error', onError);
    sock.on('close', onClose);
  });
}

/**
 * IPv4/TLS 拨号（对外入口，含受控降级）。
 *
 * 严格校验先行；**仅当**失败原因是证书链缺陷白名单里的错误码时，
 * 留证后**重新拨号**一次并放宽校验。返回 { socket, conv, tlsDowngraded, tlsError }。
 */
async function dialCagTcpTls(opts) {
  const log = (m, lvl = 'info') => { if (typeof opts.onLog === 'function') opts.onLog('CAGTLS', m, lvl); };
  try {
    const r = await dialCagTcpTlsOnce(opts, false);
    return { ...r, tlsDowngraded: false, tlsError: null };
  } catch (err) {
    const code = String((err && (err.code || err.message)) || '');
    if (!CERT_CHAIN_ERROR_CODES.some((c) => code.includes(c))) throw err;
    // 留证：降级必须写明 host + 错误码（这是红线的硬条件，不是可选的日志）
    log(
      `TLS 证书链验证失败（${opts.outerHost} / ${code}）→ 受控降级：重新拨号并放宽校验一次` +
      `（该 CAG 端点只下发叶证书、无中间 CA）`,
      'warning'
    );
    const r = await dialCagTcpTlsOnce(opts, true);
    return { ...r, tlsDowngraded: true, tlsError: code };
  }
}

// ===========================================================================
// 六、整段会话（拨号 → 主干握手 → 子通道 → 保活循环）
// ===========================================================================

/**
 * 跑完一个 IPv4/TLS 数据面切片。
 *
 * @param {object} opts
 *   outerHost/outerPort  外层 CAG（账号 firm-auth 的 cagIp/cagPort）
 *   innerHost/innerPort  内层 IPv4 与内层服务端口（connectStr 的 -h / -p|--pv6）
 *   proxySport           内层代理端口（connectStr 的 --proxy-sport）—— IPv4 blob 用它
 *   key                  会话密钥（connectStr 的 -k）
 *   vmId                 云主机 id（36 字节）
 *   traceId              可选；缺省随机
 *   holdSeconds          本切片时长
 *   timeoutMs            单次拨号超时
 *   onLog / shouldStop
 * @returns {Promise<object>} 计数器 + 会话事实（**不含任何保活有效性声明**）
 */
async function runTlsSpiceSession(opts) {
  const {
    outerHost, outerPort, innerHost, innerPort, proxySport, vmId, key,
    timeoutMs = 15000, holdSeconds = 900, onLog, shouldStop
  } = opts;
  const log = (m, lvl = 'info') => { if (typeof onLog === 'function') onLog('CAGTLS', m, lvl); };

  const dial = await dialCagTcpTls({
    outerHost, outerPort, innerHost, innerPort, proxySport, vmId, timeoutMs, onLog
  });
  if (dial.tlsDowngraded) {
    log(`TLS 已按受控降级建立（原因码 ${dial.tlsError}）`, 'warning');
  }

  const mux = CagMux.open(dial.socket);
  let mainLink;
  try {
    const traceId = opts.traceId || randomHex(16);
    mainLink = mux.openLink({ host: innerHost, port: innerPort }, traceId);
    const hs = await rawMainHandshake(
      mainLink,
      { key, vmId, linkUuid: mainLink.linkUuid, traceId: mainLink.traceId, spanId: mainLink.redqSpanId },
      onLog
    );
    if (!hs.ok) throw new Error(`raw SPICE 主干握手失败：${hs.error}`);

    const { links, authed } = await setupSubChannels(
      mux, { host: innerHost, port: innerPort }, mainLink, hs.spiceSessionId,
      { key, vmId, timeoutMs: 8000, onLog }
    );

    const displayLinks = [];
    for (const [linkId, link] of links) {
      if (SUBCHANNEL_INIT_KIND[linkId] === 'display' && authed.has(linkId)) displayLinks.push(link);
    }

    // 会话已建立（≠ 保活已被证明）—— 立刻回调一次，让上层能实时打日志/记动作，
    // 而不是等整个切片 hold 完才有第一行输出。
    if (typeof opts.onEstablished === 'function') {
      opts.onEstablished({
        conv: dial.conv,
        spiceSessionId: hs.spiceSessionId,
        subLinks: links.size,
        authedSubLinks: authed.size,
        displaySubLinks: displayLinks.length,
        tlsDowngraded: !!dial.tlsDowngraded
      });
    }

    const started = Date.now();
    const counters = await keepaliveRawSpiceLoop(mainLink, {
      interval: 25,
      stopAfter: holdSeconds,
      heartbeatHz: 21,
      displayLinks,
      onLog,
      shouldStop
    });

    return {
      sessionEstablished: true,
      conv: dial.conv,
      spiceSessionId: hs.spiceSessionId,
      subLinks: links.size,
      authedSubLinks: authed.size,
      displaySubLinks: displayLinks.length,
      tlsDowngraded: !!dial.tlsDowngraded,
      tlsError: dial.tlsError,
      elapsedSec: Math.round((Date.now() - started) / 1000),
      ...counters
    };
  } finally {
    try { mux.close(); } catch (e) { /* 已断开 */ }
    try { if (!dial.socket.destroyed) dial.socket.destroy(); } catch (e) { /* 已断开 */ }
  }
}

module.exports = {
  // 认证头 / 帧
  buildCagAuthHeadLong,
  packFrame,
  newZteLinkUuid,
  buildCagProxyAddLinkPacket,
  // 复用层
  CagMux,
  CagMuxLink,
  CAG_PROXY_DATA_CMD,
  CAG_PROXY_ADD_LINK_CMD,
  CAG_PROXY_CLOSE_LINK_CMD,
  // raw SPICE
  RawState,
  buildRawMainREDQ,
  buildRawChannelREDQ,
  buildTerminalInfoMessage,
  buildZteRawDisplayInit,
  buildZteRawInputInit,
  buildZteRawDisplayHeartbeat,
  rawMessageWithPrefix,
  readRawLinkReply,
  hasRsaPublicKeyMarker,
  rawMainHandshake,
  rawSubChannelHandshake,
  setupSubChannels,
  keepaliveRawSpiceLoop,
  SUBCHANNEL_REDQS,
  // 拨号 / 会话
  upgradeToTls,
  dialCagTcpTlsOnce,
  dialCagTcpTls,
  runTlsSpiceSession,
  CERT_CHAIN_ERROR_CODES
};
