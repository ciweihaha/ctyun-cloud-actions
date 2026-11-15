// 子进程场景脚本：真实 require server.js 后断言 XSS 防护辅助函数行为。
// 由 test/xss_helpers.test.js spawn，自身判定后以退出码汇报；
// 结束时显式 process.exit（server.js 载入后有常驻句柄，无法自然退出）。
const assert = require('node:assert/strict');
const { escapeHtml, safeJsonForScript, validateAccountName, sanitizeImportedAccountName } = require('../../server.js');

function main() {
  // H1 主向量：账号名拼进 <title> 前必须转义，`</title><script>` 不得原样出现
  const evilName = '</title><script>alert(1)</script>';
  const escaped = escapeHtml(evilName);
  assert.ok(!escaped.includes('<') && !escaped.includes('>'), '转义后不得残留尖括号：' + escaped);
  assert.equal(escaped, '&lt;/title&gt;&lt;script&gt;alert(1)&lt;/script&gt;');
  assert.equal(escapeHtml('a&b"c\'d'), 'a&amp;b&quot;c&#39;d');

  // H1 第二向量：注入 <script> 的 JSON 不得含 `</script>`，且 JSON.parse 可还原原文
  const payload = { userName: '</script><script>alert(1)</script>', note: 'a&b\u2028c\u2029d' };
  const safe = safeJsonForScript(payload);
  assert.ok(!safe.includes('</script'), '安全 JSON 不得含 script 闭合标签：' + safe);
  assert.ok(!safe.includes('<'), '安全 JSON 不得含原始 <');
  assert.deepEqual(JSON.parse(safe), payload, '转义后 JSON.parse 必须还原原文');

  // H1 纵深防御：账号名白名单
  assert.equal(validateAccountName('我的云电脑'), null);
  assert.ok(validateAccountName('a<b'));
  assert.ok(validateAccountName('a>b'));
  assert.ok(validateAccountName('x'.repeat(51)), '超长应拒绝');
  assert.equal(validateAccountName('x'.repeat(50)), null);

  // H1 导入路径：去掉 < > 并截断，不失败整个导入
  assert.equal(sanitizeImportedAccountName('a<b>c', 'fb'), 'abc');
  assert.equal(sanitizeImportedAccountName('', 'fb'), 'fb');
  assert.equal(sanitizeImportedAccountName('x'.repeat(60), 'fb').length, 50);

  console.log('XSS-HELPERS-PASS');
}

try {
  main();
  process.exit(0);
} catch (e) {
  console.error('XSS-HELPERS-FAIL: ' + (e && e.stack || e));
  process.exit(1);
}
