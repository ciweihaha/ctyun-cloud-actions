'use strict';

/**
 * ============================================================================
 * 移动云 ZTE CAG 数据面 raw 拨号（IPv6 长会话路径，无 TLS）
 * ============================================================================
 *
 * 【背景】ZTE 数据面保活按 connectStr 内层主机分流：
 *   · IPv6 内层主机 → raw ZTEC 帧 + 自定义 ZTEC 加密（无 TLS，**本文件**）
 *   · IPv4 内层主机 → TLS + CAGMux + SPICE Display Surface（app/ydpc/zte_cag_tls.js）
 * 地址族是「每台每次取材料」的属性：本机探测到的第一台样本 connectStr 里
 * 只有 `--hv6`（无 `-h`），故走 raw；带 `-h <IPv4>` 的机器要走另一个文件。
 * 分流的判据与"不许猜"的口径在 product_route.js 的 resolveInnerRoute()。
 *
 * 【协议来源】官方客户端在 IPv6 长会话下的真实行为（真机抓包复现）：dial_cag_tcp_raw /
 * build_cag_auth_head_packet_short / build_cag_auth_blob 的帧格式（cag.go 同源）。
 * 帧字节模板是「协议格式」，非第三方私有凭据。
 *
 * 【红线自检】
 *   - 本路径是**裸 TCP + ZTEC 自定义加密**，不涉及 TLS 证书校验，
 *     因此不触碰组 7 的 `rejectUnauthorized:false` 禁令。
 *   - 不伪造身份、不硬编码任何第三方客户端 ID / RSA 公钥。
 *   - 220B auth blob 由 connectStr 动态字段（innerHost/port/vmId）+ 随机填充构建，
 *     无预捕获模板依赖。
 */

const net = require('net');
const crypto = require('crypto');
const { isIpv4Literal } = require('./product_route');

// 官方 raw ZTEC 保活帧常量（真机抓包核对）
const ZTEC_RAW_HB = Buffer.from([0x0a, 0x00, 0x00, 0x00]); // 空 CAG DATA 心跳
const CAG_ADD_LINK_CMD = 0x1A;
const CAG_ADD_LINK_PAYLOAD_LEN = 0x9A; // 154
const RAW_ZTEC_LINK_PORT = 3246;
const RAW_ZTEC_LINK_TYPE = 0x09;
const RAW_ZTEC_LINK_IDS = [7, 8];
const CAG_DATA_CMD = 0x0A;
const RAW_ZTEC_DATA_LID = 7;
const RAW_ZTEC_DATA_PLEN = 1688;
const RAW_ZTEC_DATA_RESEND_S = 60.0;

/**
 * 构建官方 raw-ZTEC ADD_LINK 帧（158B）。
 * 4B 头（cmd=0x1A, lid, plen=0x9A LE）+ 154B payload：
 *   payload[0:2]=port 3246 LE, [2]=channel_type 0x09,
 *   [4:8]=127.0.0.1 反向字节序（01 00 00 7f）, [0x54]=0x0c，其余零。
 */
function buildRawZtecAddLinkPacket(linkId) {
  const payload = Buffer.alloc(CAG_ADD_LINK_PAYLOAD_LEN);
  payload.writeUInt16LE(RAW_ZTEC_LINK_PORT & 0xFFFF, 0);
  payload[2] = RAW_ZTEC_LINK_TYPE & 0xFF;
  payload[4] = 1;
  payload[5] = 0;
  payload[6] = 0;
  payload[7] = 127;
  payload[0x54] = 0x0c;
  const head = Buffer.alloc(4);
  head[0] = CAG_ADD_LINK_CMD;
  head[1] = linkId & 0xFF;
  head.writeUInt16LE(CAG_ADD_LINK_PAYLOAD_LEN, 2);
  return Buffer.concat([head, payload]);
}

/**
 * 构建官方 raw-ZTEC DATA 帧（1692B，post-ADD_LINK）。
 * 4B 头（cmd=0x0A, lid=7, plen=1688 LE）+ 1688B body：
 *   body[8]=0x12, [528]=0x01, [537]=0x01，其余零。
 */
function buildRawZtecDataPacket(linkId = RAW_ZTEC_DATA_LID) {
  const body = Buffer.alloc(RAW_ZTEC_DATA_PLEN);
  body[8] = 0x12;
  body[528] = 0x01;
  body[537] = 0x01;
  const head = Buffer.alloc(4);
  head[0] = CAG_DATA_CMD;
  head[1] = linkId & 0xFF;
  head.writeUInt16LE(RAW_ZTEC_DATA_PLEN, 2);
  return Buffer.concat([head, body]);
}

/**
 * 预热：发送 ADD_LINK lid=7/8 + DATA lid=7（真机协商序号）。
 */
function primeRawZtecLinks(sock) {
  sock.write(buildRawZtecAddLinkPacket(RAW_ZTEC_LINK_IDS[0]));
  sock.write(buildRawZtecAddLinkPacket(RAW_ZTEC_LINK_IDS[1]));
  sock.write(buildRawZtecDataPacket(RAW_ZTEC_DATA_LID));
  return { links_sent: 2, data_sent: 1 };
}

/**
 * post-auth raw ZTEC 保活循环：ADD_LINK + DATA 预热后保持心跳。
 * ADD_LINK + DATA 预热 → 周期 HB（interval 秒）+ 每 dataResend 秒重发 DATA。
 * 成功判定：hb_recv > 0（收到 HB 尺寸回帧）。
 *
 * 历史证据（真机长跑观测）：纯 HB → BrokenPipe@~1839s + VM off；
 * ADD_LINK + HB → Timeout@~2129s + VM off；故必须 ADD_LINK + DATA + HB（+重发 DATA）。
 *
 * @returns {Promise<{hbSent, hbRecv, ok, linksSent, dataSent, primeRecv, error?}>}
 */
function keepaliveRawZtecLoop(sock, opts = {}) {
  const interval = Number(opts.interval) || 1.0;
  const stopAfter = Number(opts.stopAfter) || 20;
  const primeLinks = opts.primeLinks !== false;
  const dataResend = Number(opts.dataResend) || RAW_ZTEC_DATA_RESEND_S;
  const log = (m, lvl = 'info') => { if (typeof opts.onLog === 'function') opts.onLog('CAGRAW', m, lvl); };

  return new Promise((resolve) => {
    let hbSent = 0;
    let hbRecv = 0;
    let linksSent = 0;
    let dataSent = 0;
    let primeRecv = 0;
    let settled = false;
    const finish = (extra = {}) => {
      if (settled) return;
      settled = true;
      resolve({
        hbSent, hbRecv, ok: hbRecv > 0 ? 1 : 0,
        linksSent, dataSent, primeRecv, ...extra
      });
    };

    const started = Date.now();
    const deadline = started + stopAfter * 1000;
    let nextDataAt = 0;
    let lastProgressAt = started;

    // 累计接收字节，按 4B HB 帧估算 hb_recv
    const onData = (chunk) => {
      hbRecv += Math.max(1, Math.floor(chunk.length / 4));
    };
    const onError = (err) => finish({ error: err.message });
    const onClose = () => finish();
    sock.on('data', onData);
    sock.on('error', onError);
    sock.on('close', onClose);

    // 预热 ADD_LINK + DATA
    if (primeLinks) {
      try {
        const primed = primeRawZtecLinks(sock);
        linksSent = primed.links_sent;
        dataSent = primed.data_sent;
        if (dataResend > 0) nextDataAt = Date.now() + dataResend * 1000;
        log(`raw-ZTEC 预热 links=${linksSent} data=${dataSent}`);
      } catch (e) {
        log(`raw-ZTEC 预热告警: ${e.message}`, 'warning');
      }
    }

    const tick = () => {
      const now = Date.now();
      if (settled) return;
      if (now >= deadline) {
        sock.removeListener('data', onData);
        sock.removeListener('error', onError);
        sock.removeListener('close', onClose);
        finish();
        return;
      }

      // 周期性重发 DATA（保持隧道活跃，纯 HB 会 ~30min 关机）
      if (dataResend > 0 && now >= nextDataAt) {
        try {
          sock.write(buildRawZtecDataPacket(RAW_ZTEC_DATA_LID));
          dataSent += 1;
          nextDataAt = now + dataResend * 1000;
        } catch (e) {
          sock.removeListener('data', onData);
          finish({ error: e.message });
          return;
        }
      }

      // 发 HB 心跳
      try {
        sock.write(ZTEC_RAW_HB);
        hbSent += 1;
      } catch (e) {
        sock.removeListener('data', onData);
        finish({ error: e.message });
        return;
      }

      // 每 10s 打一次进度
      if (now - lastProgressAt >= 10000) {
        lastProgressAt = now;
        log(`progress hb_sent=${hbSent} hb_recv=${hbRecv} data=${dataSent} left=${Math.round((deadline - now) / 1000)}s`);
      }

      const nextDelay = Math.min(interval * 1000, deadline - now);
      setTimeout(tick, Math.max(10, nextDelay));
    };

    tick();
  });
}

/**
 * 构建官方 50 字节 ZTEC auth 短头（ye4B6y C2S L50）。
 *
 * 布局（50 字节 C2S 短头，真机抓包核对）：
 *   [0:4]   "ZTEC"
 *   [4:6]   0x002c LE
 *   [6:10]  101 LE
 *   [10:14] random
 *   [14:18] dc 00 00 00
 *   [18:34] zeros (16B)
 *   [34:38] 03 00 8c 0c
 *   [38:50] zeros (12B)
 */
function buildCagAuthHeadShort() {
  const pkt = Buffer.alloc(50);
  pkt.write('ZTEC', 0, 'ascii');
  pkt.writeUInt16LE(0x002c, 4);
  pkt.writeUInt32LE(101, 6);
  crypto.randomFillSync(pkt, 10, 4); // [10:14] random
  pkt.writeUInt32LE(0xdc, 14);       // [14:18] dc 00 00 00
  // [18:34] 保持零
  pkt[34] = 0x03;
  pkt[35] = 0x00;
  pkt[36] = 0x8c;
  pkt[37] = 0x0c;
  // [38:50] 保持零
  return pkt;
}

/**
 * IPv6 字面量 → 16 字节网络序（等价 socket.inet_pton(AF_INET6)）。
 * 支持 `::` 压缩与 `%zone` 区段（剥离 zone）。
 */
function ipv6ToBytes(addr) {
  const bare = String(addr).split('%')[0];
  const dbl = bare.indexOf('::');
  let headParts = [];
  let tailParts = [];
  if (dbl >= 0) {
    headParts = bare.slice(0, dbl) ? bare.slice(0, dbl).split(':') : [];
    tailParts = bare.slice(dbl + 2) ? bare.slice(dbl + 2).split(':') : [];
  } else {
    headParts = bare.split(':');
  }
  const missing = 8 - headParts.length - tailParts.length;
  if (missing < 0) throw new Error(`非法 IPv6 地址: ${addr}`);
  const parts = [...headParts, ...Array(missing).fill('0'), ...tailParts];
  if (parts.length !== 8) throw new Error(`IPv6 段数异常: ${addr}`);
  const buf = Buffer.alloc(16);
  for (let i = 0; i < 8; i++) {
    const seg = parts[i] || '0';
    if (!/^[0-9a-fA-F]{1,4}$/.test(seg)) throw new Error(`非法 IPv6 段: ${seg}`);
    buf.writeUInt16BE(parseInt(seg, 16), i * 2);
  }
  return buf;
}

/**
 * IPv4 点分四段字面量 → 4 字节网络序（等价 socket.inet_aton）。
 * 与 product_route.isIpv4Literal 共用同一判据，避免两处各写一份。
 */
function ipv4ToBytes(addr) {
  if (!isIpv4Literal(addr)) throw new Error(`非法 IPv4 字面量: ${addr}`);
  const parts = String(addr).split('.');
  const buf = Buffer.alloc(4);
  for (let i = 0; i < 4; i++) buf[i] = Number(parts[i]) & 0xff;
  return buf;
}

/**
 * 构建 220 字节 CAG auth blob（**地址族双分支**，真机抓包核对）。
 *
 * 布局：
 *   [0:4]   port u32 LE —— ⚠️ **两族取值不同**：
 *             IPv6 raw 路径 = innerPort（connectStr 的 --pv6/-p，如 5100）
 *             IPv4 TLS 路径 = proxySport（connectStr 的 --proxy-sport，如 60065）
 *           探针证据：IPv6 上填 proxySport → FAIL_AUTH；填 port → OK。
 *   [4:20]  主机地址 —— IPv4 占 [4:8]（[8:20] 留零）**或** 完整 16B IPv6
 *   [20:56] vmId ASCII（36B）
 *   [56:60] 零
 *   [60:188] random（128B）
 *   [188]   family tag —— 0x50（IPv4）/ 0x51（IPv6）
 *   [189:220] 零
 *
 * 地址族由 innerHost 自己决定（含 ':' ⇒ IPv6），**不额外传参** ——
 * 少一个可能与主机不一致的输入，就少一类"标签与地址打架"的故障。
 */
function buildCagAuthBlob({ innerHost, innerPort, proxySport, vmId }) {
  if (!innerHost || !vmId) throw new Error('auth blob 缺少 innerHost/vmId');
  if (vmId.length !== 36) throw new Error(`auth blob 需要 36 字节 vmId，实际 ${vmId.length}`);

  const msg = String(innerHost);
  const isV6 = msg.includes(':');
  const blob = Buffer.alloc(220);
  let portVal;
  if (isV6) {
    portVal = Number(innerPort);
    if (!(portVal > 0)) throw new Error('auth blob (IPv6) 需要 connectStr 的服务端口');
    ipv6ToBytes(msg).copy(blob, 4, 0, 16);
    blob[188] = 0x51;                     // IPv6 family tag
  } else {
    portVal = Number(proxySport);
    if (!(portVal > 0)) throw new Error('auth blob (IPv4) 需要 proxySport（--proxy-sport）');
    ipv4ToBytes(msg).copy(blob, 4, 0, 4); // 只占 [4:8]，[8:20] 保持零
    blob[188] = 0x50;                     // IPv4 family tag
  }
  blob.writeUInt32LE(portVal >>> 0, 0);
  blob.write(vmId, 20, 36, 'ascii');
  // [56:60] 保持零
  crypto.randomFillSync(blob, 60, 128);   // [60:188] random
  // [189:220] 保持零
  return blob;
}

/**
 * 内层主机必须先判地址族再进拨号 —— 返回 null 表示"是 IPv6，可走本文件的 raw 路径"，
 * 否则返回一句原因串。
 *
 * 为什么必须有这道前置校验：`ipv6ToBytes()` 遇到 IPv4 字面量会抛
 * `非法 IPv6 段`，而旧代码是在 `sock.on('data')` 回调里调用 blob 构造的 ——
 * 那个回调**不在 Promise 链上**，于是异常既成为未捕获异常（只有 server.js 的
 * uncaughtException 兜底才没让进程死），又让返回的 Promise 一直挂到 15s 超时，
 * 最终这台机器的失败**绕过了 G2 失败分级**。现在改为拨号前判明、明确拒绝。
 */
function describeNonIpv6InnerHost(innerHost) {
  const host = String(innerHost == null ? '' : innerHost).trim();
  if (!host) return 'connectStr 未解出内层主机';
  const bare = host.includes('%') ? host.slice(0, host.indexOf('%')) : host;
  if (bare.includes(':')) return null; // IPv6 ⇒ raw 路径可用
  if (isIpv4Literal(bare)) return `内层主机为 IPv4（${host}）⇒ 应走 TLS 通道，不得用 raw 拨号`;
  return `内层主机既非 IPv4 也非 IPv6 字面量（${host}）⇒ 拒绝猜测通道`;
}

/**
 * 执行 IPv6 raw ZTEC 拨号：
 *   TCP 连 outer CAG → 发 50B 短头 → 读 50B ack（ZTEC 魔数 + conv）
 *   → 发 220B auth blob → 读 36B ack（ack[4]==0x01）→ 保持 raw TCP。
 *
 * @returns {Promise<{success, conv, ackHex, socket}>} 成功后 socket 保持连接（供保活循环复用）
 */
function dialCagTcpRaw({ host, port, innerHost, innerPort, proxySport, vmId, timeoutMs = 15000, onLog }) {
  // 前置地址族校验：必须在 createConnection **之前**拒绝。理由见
  // describeNonIpv6InnerHost() 的注释 —— 只有这样，失败才落在 Promise 链上、可被 G2 分级，
  // 而不是在 data 回调里变成未捕获异常后让 Promise 挂到超时。
  const wrongFamily = describeNonIpv6InnerHost(innerHost);
  if (wrongFamily) {
    return Promise.reject(new Error(`CAG raw 拨号前置校验失败：${wrongFamily}`));
  }

  return new Promise((resolve, reject) => {
    const log = (m, lvl = 'info') => { if (typeof onLog === 'function') onLog('CAGRAW', m, lvl); };

    let settled = false;
    const done = (fn, val) => { if (!settled) { settled = true; fn(val); } };

    const sock = net.createConnection({ host, port });
    let recvBuf = Buffer.alloc(0);
    let stage = 1;
    let conv = 0;

    const timer = setTimeout(() => {
      sock.destroy();
      done(reject, new Error(`CAG raw 拨号超时 (${timeoutMs}ms)`));
    }, timeoutMs);

    sock.on('connect', () => {
      log(`TCP 已连接 ${host}:${port}，发送 50B ZTEC 短头`);
      sock.write(buildCagAuthHeadShort());
    });

    const handleData = (chunk) => {
      recvBuf = Buffer.concat([recvBuf, chunk]);

      if (stage === 1) {
        if (recvBuf.length < 50) return;
        const ack = recvBuf.subarray(0, 50);
        log(`50B ack: ${ack.toString('hex')}`);
        const magic = ack.toString('ascii', 0, 4);
        if (magic !== 'ZTEC') {
          clearTimeout(timer);
          sock.destroy();
          done(reject, new Error(`50B ack 魔数校验失败: "${magic}"`));
          return;
        }
        conv = ack.readUInt32LE(14);
        log(`conv = ${conv} (0x${conv.toString(16)})`);
        recvBuf = recvBuf.subarray(50);
        stage = 2;
        log(`发送 220B auth blob (innerPort=${innerPort} innerHost=${innerHost})`);
        // 本路径经前置校验保证 innerHost 为 IPv6 ⇒ blob 走 [4:20] 16B + tag 0x51 分支。
        // proxySport 一并传入只为让 blob 的入参契约完整（IPv4 分支用得着它）。
        sock.write(buildCagAuthBlob({ innerHost, innerPort, proxySport, vmId }));
        return;
      }

      // stage 2
      if (recvBuf.length < 36) return;
      const ack = recvBuf.subarray(0, 36);
      log(`36B auth ack: ${ack.toString('hex')}`);
      log(`auth ack[4] = 0x${ack[4].toString(16)}`);
      clearTimeout(timer);
      if (ack[4] === 0x01) {
        log('✅ CAG raw 拨号成功，auth 通过');
        // 清掉拨号阶段的监听器，把干净的 raw socket 交给保活循环复用
        sock.removeAllListeners('data');
        sock.removeAllListeners('error');
        sock.removeAllListeners('close');
        sock.removeAllListeners('timeout');
        sock.setTimeout(0);
        done(resolve, { success: true, conv, ackHex: ack.toString('hex'), socket: sock });
      } else {
        sock.destroy();
        done(reject, new Error(`auth ack 校验失败: ack[4]=0x${ack[4].toString(16)}`));
      }
    };

    // ⚠️ 本回调**不在 Promise 链上** —— 在它里面抛出的任何异常都会变成未捕获异常，
    // 并让上面那个 Promise 一直挂到超时（IPv4 内层主机撞上 ipv6ToBytes 时就是这样）。
    // 故必须就地收敛成 reject，让失败落进 G2 失败分级的视野，而不是无人接管。
    sock.on('data', (chunk) => {
      try { handleData(chunk); }
      catch (e) { clearTimeout(timer); sock.destroy(); done(reject, e); }
    });

    sock.on('error', (err) => { clearTimeout(timer); done(reject, err); });
    sock.on('timeout', () => { clearTimeout(timer); sock.destroy(); done(reject, new Error('CAG raw socket 超时')); });
    sock.on('close', () => { clearTimeout(timer); done(reject, new Error('CAG raw 连接被关闭')); });
  });
}

module.exports = {
  buildCagAuthHeadShort,
  ipv6ToBytes,
  ipv4ToBytes,
  buildCagAuthBlob,
  describeNonIpv6InnerHost,
  dialCagTcpRaw,
  buildRawZtecAddLinkPacket,
  buildRawZtecDataPacket,
  primeRawZtecLinks,
  keepaliveRawZtecLoop,
  ZTEC_RAW_HB
};
