// 子进程场景脚本：真实 server + mock https.request。
// 由 test/proxy_disconnect.test.js spawn，自身判定后以退出码汇报；
// 结束时显式 process.exit（server.js 载入后有常驻句柄，无法自然退出）。
const http = require('node:http');
const https = require('node:https');
const { Readable } = require('node:stream');
const { EventEmitter } = require('node:events');
const { server } = require('../../server.js');

const realHttpsRequest = https.request;
let fakeReq = null;
let fakeRes = null;

class FakeUpstreamReq extends EventEmitter {
  constructor() { super(); this.destroyedFlag = false; }
  write() { return true; }
  end() { this.ended = true; }
  destroy() { if (!this.destroyedFlag) { this.destroyedFlag = true; this.emit('close'); } }
}

// 慢速滴流上游：每 40ms 一个 chunk，永不主动结束（除非被 destroy）
class FakeUpstreamRes extends Readable {
  constructor() {
    super();
    this.headers = { 'content-type': 'text/plain' };
    this.statusCode = 200;
    this.destroyedFlag = false;
    this._n = 0;
    this._timer = null;
  }
  _read() {
    if (this._timer) return;
    this._timer = setInterval(() => {
      if (this.destroyedFlag) return;
      this.push(`chunk-${this._n++};`);
    }, 40);
  }
  destroy() {
    if (this.destroyedFlag) return;
    this.destroyedFlag = true;
    clearInterval(this._timer);
    super.destroy();
  }
}

function postJson(port, pathname, body) {
  return new Promise((resolveP, rejectP) => {
    const data = JSON.stringify(body);
    const req = http.request({ host: '127.0.0.1', port, path: pathname, method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) } },
      (res) => {
        let buf = '';
        res.on('data', (c) => { buf += c; });
        res.on('end', () => resolveP(JSON.parse(buf)));
      });
    req.on('error', rejectP);
    req.write(data);
    req.end();
  });
}

async function waitFor(cond, ms, what) {
  const start = Date.now();
  while (Date.now() - start < ms) {
    if (cond()) return;
    await new Promise((r) => setTimeout(r, 25));
  }
  throw new Error(`超时未达成：${what}`);
}

async function main() {
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const port = server.address().port;
  const login = await postJson(port, '/api/auth/login', { username: 'admin', password: 'TestPass123' });
  if (!login.success) throw new Error('管理员登录失败：' + JSON.stringify(login));
  const token = login.token;

  // --- 场景 1：响应流式传输中客户端断开 ---
  https.request = (url, options, cb) => {
    fakeReq = new FakeUpstreamReq();
    fakeRes = new FakeUpstreamRes();
    process.nextTick(() => cb(fakeRes));
    return fakeReq;
  };
  await new Promise((resolveP) => {
    const clientReq = http.request({ host: '127.0.0.1', port,
      path: '/api/ctyun-proxy?target=' + encodeURIComponent('https://pc.ctyun.cn/slow'),
      method: 'GET', headers: { Authorization: 'Bearer ' + token } },
      (clientRes) => {
        if (clientRes.statusCode !== 200) throw new Error('代理应返回 200，实际 ' + clientRes.statusCode);
        setTimeout(() => { clientReq.destroy(); resolveP(); }, 150);
      });
    clientReq.on('error', () => {});
    clientReq.end();
  });
  try {
    await waitFor(() => fakeReq && fakeReq.destroyedFlag, 3000, '上游请求被 destroy');
    await waitFor(() => fakeRes && fakeRes.destroyedFlag, 3000, '上游响应被 destroy');
    console.log('DISCONNECT-PASS');
  } catch (e) {
    if (fakeRes) fakeRes.destroy();
    console.log('DISCONNECT-FAIL: ' + e.message);
    throw e;
  }

  // --- 场景 2：正常结束不误伤（对照组） ---
  https.request = (url, options, cb) => {
    fakeReq = new FakeUpstreamReq();
    fakeRes = new Readable({
      read() { this.push('a'); this.push('b'); this.push(null); },
    });
    fakeRes.headers = { 'content-type': 'text/plain' };
    fakeRes.statusCode = 200;
    // Readable 默认 autoDestroy，正常结束也会自毁；只记录结束前的销毁。
    fakeRes.destroyedBeforeEnd = false;
    const origDestroy = fakeRes.destroy.bind(fakeRes);
    fakeRes.destroy = (...args) => { if (!fakeRes.readableEnded) fakeRes.destroyedBeforeEnd = true; return origDestroy(...args); };
    process.nextTick(() => cb(fakeRes));
    return fakeReq;
  };
  const body = await new Promise((resolveP, rejectP) => {
    const req = http.request({ host: '127.0.0.1', port,
      path: '/api/ctyun-proxy?target=' + encodeURIComponent('https://pc.ctyun.cn/ok'),
      method: 'GET', headers: { Authorization: 'Bearer ' + token } },
      (res) => {
        let buf = '';
        res.on('data', (c) => { buf += c; });
        res.on('end', () => resolveP(buf));
      });
    req.on('error', rejectP);
    req.end();
  });
  if (body !== 'ab') throw new Error('正常结束应完整收到 ab，实际 ' + JSON.stringify(body));
  if (fakeReq.destroyedFlag) throw new Error('正常结束不应销毁上游请求');
  if (fakeRes.destroyedBeforeEnd) throw new Error('正常结束不应在结束前销毁上游响应');
  console.log('NORMAL-PASS');
}

main().then(
  () => { https.request = realHttpsRequest; server.close(() => process.exit(0)); setTimeout(() => process.exit(0), 1000).unref(); },
  (e) => { console.error('SCENARIO-FAIL: ' + (e && e.stack || e)); server.close(() => process.exit(1)); setTimeout(() => process.exit(1), 1000).unref(); },
);
