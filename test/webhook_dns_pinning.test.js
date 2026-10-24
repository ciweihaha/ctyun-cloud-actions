const { test } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const https = require('node:https');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const {
  safeFetchJson,
  resolvePublicAddresses,
  createPinnedLookup,
  fetchWithPinnedIps,
} = require('../app/webhook_util.js');

const PUB = '93.184.216.34';
const PUB2 = '93.184.216.35';
const META = '169.254.169.254';
const PRIV = '10.0.0.8';

const pubLookup = async () => [{ address: PUB, family: 4 }];

function res200(json = { errcode: 0 }) {
  return {
    status: 200,
    ok: true,
    headers: { get: () => null },
    json: async () => json,
  };
}

test('resolvePublicAddresses: 返回预校验通过的公网地址集，私有/混合仍拒绝', async () => {
  assert.deepEqual(await resolvePublicAddresses('hooks.example.com', pubLookup), [PUB]);
  assert.deepEqual(
    await resolvePublicAddresses('hooks.example.com', async () => [
      { address: PUB, family: 4 },
      { address: PUB2, family: 4 },
      { address: PUB, family: 4 },
    ]),
    [PUB, PUB2],
    '重复地址应去重，保持顺序'
  );
  assert.deepEqual(await resolvePublicAddresses(PUB, pubLookup), [PUB], '公网 IP 字面量直接钉扎');
  await assert.rejects(
    resolvePublicAddresses('hooks.example.com', async () => [{ address: META, family: 4 }]),
    /私有地址/
  );
  await assert.rejects(
    resolvePublicAddresses('hooks.example.com', async () => [
      { address: PUB, family: 4 },
      { address: PRIV, family: 4 },
    ]),
    /私有地址/
  );
});

test('createPinnedLookup: 只返回钉扎地址，绝不回落到系统 DNS', async () => {
  const lookup = createPinnedLookup([PUB, PUB2]);
  const single = await new Promise((resolve, reject) => {
    lookup('hooks.example.com', {}, (err, address, family) => (err ? reject(err) : resolve({ address, family })));
  });
  assert.equal(single.address, PUB);
  const all = await new Promise((resolve, reject) => {
    lookup('hooks.example.com', { all: true }, (err, addresses) => (err ? reject(err) : resolve(addresses)));
  });
  assert.deepEqual(all.map((a) => a.address), [PUB, PUB2]);
});

test('safeFetchJson: 校验后连接前 DNS 重绑定时，连接器收到的仍是校验时钉扎的公网地址', async () => {
  // lookupFn 调用序列：第一次（校验时）返回公网；此后任何再次解析（模拟重绑定）
  // 都返回元数据地址。一个只做校验时解析、不在连接时重解析的实现，
  // 传给连接器的 pinnedIps 必须仍是第一次的公网地址。
  let calls = 0;
  const lookupFn = async () => {
    calls++;
    if (calls === 1) return [{ address: PUB, family: 4 }];
    return [{ address: META, family: 4 }];
  };
  const seen = [];
  const fetchFn = async (url, init) => {
    seen.push(init && init.pinnedIps);
    return res200();
  };
  const r = await safeFetchJson('https://hooks.example.com/x', { fetchFn, lookupFn });
  assert.equal(r.status, 200);
  assert.equal(seen.length, 1);
  assert.deepEqual(seen[0], [PUB], '连接器必须拿到校验时钉扎的地址，而不是重绑定后的元数据地址');
});

test('safeFetchJson: 重定向每一跳都重新钉扎，重绑定不影响第二跳的连接地址', async () => {
  // 校验序列：第一跳公网 A，第二跳校验公网 B；此后重解析一律返回私网。
  const sequence = [PUB, PUB2, PRIV, META];
  let idx = 0;
  const lookupFn = async () => [{ address: sequence[Math.min(idx++, sequence.length - 1)], family: 4 }];
  const seen = [];
  const fetchFn = async (url, init) => {
    seen.push({ url, pinnedIps: init && init.pinnedIps });
    if (url.includes('/a')) {
      return {
        status: 302,
        ok: false,
        headers: { get: (n) => (n.toLowerCase() === 'location' ? 'https://other.example.com/b' : null) },
        json: async () => ({}),
      };
    }
    return res200();
  };
  const r = await safeFetchJson('https://hooks.example.com/a', { fetchFn, lookupFn });
  assert.equal(r.status, 200);
  assert.equal(seen.length, 2);
  assert.deepEqual(seen[0].pinnedIps, [PUB]);
  assert.deepEqual(seen[1].pinnedIps, [PUB2]);
  for (const s of seen) {
    assert.ok(!s.pinnedIps.includes(PRIV) && !s.pinnedIps.includes(META), '任何一跳都不应把私网/元数据地址交给连接器');
  }
});

test('fetchWithPinnedIps: 用假主机名 + 钉扎本地地址，实际命中本地服务器（证明连接时不走系统 DNS）', async () => {
  const server = http.createServer((req, res) => {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ fromLocal: true, hostHeader: req.headers.host, path: req.url }));
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  try {
    const r = await fetchWithPinnedIps(`http://hooks.example.com:${port}/x`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ hi: 1 }),
      pinnedIps: ['127.0.0.1'],
      allowPrivatePinnedIps: true,
    });
    assert.equal(r.status, 200);
    // 通过 safeFetchJson 内部的读体路径同款方式验证：直接用返回的 body 流
    const text = await r.text();
    const data = JSON.parse(text);
    assert.equal(data.fromLocal, true, '响应必须来自本地服务器，而非 hooks.example.com 的真实解析结果');
    assert.ok(String(data.hostHeader).startsWith('hooks.example.com'), 'Host 头必须仍是原始主机名，而非钉扎 IP');
    assert.equal(data.path, '/x');
  } finally {
    server.close();
  }
});

test('fetchWithPinnedIps: 默认拒绝私网钉扎地址（纵深防御，本地测试须显式 opt-in）', async () => {
  await assert.rejects(
    fetchWithPinnedIps('http://hooks.example.com/x', { pinnedIps: ['127.0.0.1'] }),
    /私有|不允许/
  );
  await assert.rejects(
    fetchWithPinnedIps('http://hooks.example.com/x', { pinnedIps: [META] }),
    /私有|不允许/
  );
});

function makeCertFor(cn, sanDns) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ctyun-pinning-'));
  const key = path.join(dir, 'key.pem');
  const crt = path.join(dir, 'crt.pem');
  execFileSync('openssl', [
    'req', '-x509', '-newkey', 'rsa:2048', '-keyout', key, '-out', crt,
    '-days', '1', '-nodes', '-subj', `/CN=${cn}`,
    '-addext', `subjectAltName=${sanDns.map((d) => `DNS:${d}`).join(',')},IP:127.0.0.1`,
  ], { stdio: 'pipe' });
  return { dir, key, crt, certPem: fs.readFileSync(crt, 'utf8') };
}

test('fetchWithPinnedIps: HTTPS 保留 TLS 校验——证书与主机名匹配才放行，错配必须失败', async () => {
  const { dir, key, crt, certPem } = makeCertFor('hooks.example.com', ['hooks.example.com']);
  const server = https.createServer(
    { key: fs.readFileSync(key), cert: fs.readFileSync(crt) },
    (req, res) => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ tlsOk: true }));
    }
  );
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  try {
    const ok = await fetchWithPinnedIps(`https://hooks.example.com:${port}/x`, {
      pinnedIps: ['127.0.0.1'],
      allowPrivatePinnedIps: true,
      ca: certPem,
    });
    assert.equal(ok.status, 200);
    assert.equal(JSON.parse(await ok.text()).tlsOk, true);

    // 同一证书、不同主机名：若实现为钉扎绕过了 TLS（例如把 servername 改成 IP
    // 或关掉校验），这次请求就会错误地成功；正确实现必须因证书错配而失败。
    await assert.rejects(
      fetchWithPinnedIps(`https://other.example.com:${port}/x`, {
        pinnedIps: ['127.0.0.1'],
        allowPrivatePinnedIps: true,
        ca: certPem,
      }),
      /certificate|CERT|TLS|SSL/i
    );
  } finally {
    server.close();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
