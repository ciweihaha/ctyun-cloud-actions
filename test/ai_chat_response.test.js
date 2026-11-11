const { test } = require('node:test');
const assert = require('node:assert/strict');
const { parseAiChatResponse } = require('../app/tasks/native_tasks.js');

const okBody = JSON.stringify({ choices: [{ message: { content: '你好' } }] });

test('纯 JSON 成功体原样解析', () => {
  const r = parseAiChatResponse(okBody);
  assert.equal(r.choices[0].message.content, '你好');
});

test('SSE 单帧 data:{...} 剥帧后解析', () => {
  const r = parseAiChatResponse(`data:${okBody}\n\n`);
  assert.equal(r.choices[0].message.content, '你好');
});

test('SSE 多帧 + data:[DONE] 收尾：取最后一段完整帧', () => {
  const first = JSON.stringify({ code: 0, progress: 1 });
  const r = parseAiChatResponse(`data:${first}\ndata:${okBody}\ndata:[DONE]\n\n`);
  assert.equal(r.choices[0].message.content, '你好');
});

test('数字成功码 0 / 200 通过', () => {
  assert.equal(parseAiChatResponse(JSON.stringify({ code: 0 })).code, 0);
  assert.equal(parseAiChatResponse(JSON.stringify({ code: 200 })).code, 200);
});

// 深查第 8 轮：旧实现 `code !== 0 && code !== 200` 只认数字，{code:"0"}
// 会被误判业务错误、成功对话记失败丢 100 积分；现字符串码同义。
test('字符串成功码 "0" / "200" 同样通过（回归主用例）', () => {
  assert.equal(parseAiChatResponse(JSON.stringify({ code: '0' })).code, '0');
  assert.equal(parseAiChatResponse(JSON.stringify({ code: '200' })).code, '200');
});

test('字符串成功码带空白 " 0 " 同样通过', () => {
  assert.equal(parseAiChatResponse(JSON.stringify({ code: ' 0 ' })).code, ' 0 ');
});

test('SSE 帧内字符串成功码同样通过', () => {
  const r = parseAiChatResponse(`data:${JSON.stringify({ code: '0', choices: [] })}\ndata:[DONE]`);
  assert.equal(r.code, '0');
});

test('数字非零码抛业务错误', () => {
  assert.throws(() => parseAiChatResponse(JSON.stringify({ code: 400, message: 'bad request' })), /AI 对话业务返回错误/);
});

test('字符串非零码同样抛业务错误', () => {
  assert.throws(() => parseAiChatResponse(JSON.stringify({ code: '400', message: 'bad request' })), /AI 对话业务返回错误/);
});

test('非数字码字符串同样抛业务错误，不被当成功', () => {
  assert.throws(() => parseAiChatResponse(JSON.stringify({ code: 'ERR', message: 'fail' })), /AI 对话业务返回错误/);
});

test('错误页（非 JSON）抛“返回非 JSON”', () => {
  assert.throws(() => parseAiChatResponse('<html><body>502 Bad Gateway</body></html>'), /返回非 JSON/);
});

test('SSE 截断体抛“返回非 JSON”', () => {
  assert.throws(() => parseAiChatResponse('data:{"choices":['), /返回非 JSON/);
});

test('只有 data:[DONE]、无业务帧时抛“返回非 JSON”', () => {
  assert.throws(() => parseAiChatResponse('data:[DONE]\n\n'), /返回非 JSON/);
});

test('空响应抛“返回非 JSON”', () => {
  assert.throws(() => parseAiChatResponse(''), /返回非 JSON/);
  assert.throws(() => parseAiChatResponse('   \n  '), /返回非 JSON/);
});

test('JSON null 不再抛无语义 TypeError，改为“返回非 JSON”', () => {
  assert.throws(() => parseAiChatResponse('null'), /返回非 JSON/);
});
