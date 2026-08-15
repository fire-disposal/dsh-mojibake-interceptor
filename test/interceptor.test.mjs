import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createInterceptor, buildReason } from '../lib/interceptor.js';

const findings = [{ severity: 'severe', kind: 'utf8-as-cp1252-cjk', detail: 'ä¸­æ–‡ → 中文' }];

function flag(interceptor, name = 'write', path = 'a.md', text = 'ä¸­æ–‡') {
  return interceptor.decide({ name, path, text, findings });
}

test('warn mode: first flagged write is denied with a review message', () => {
  const it = createInterceptor({ mode: 'warn' });
  const d = flag(it);
  assert.equal(d.kind, 'deny');
  assert.match(d.reason, /乱码拦截器/);
  assert.match(d.reason, /a\.md/);
  assert.match(d.reason, /复查/);
  assert.match(d.reason, /原样重试同一次写入/);
});

test('warn mode: identical retry passes (执意放行)', () => {
  const it = createInterceptor({ mode: 'warn' });
  assert.equal(flag(it).kind, 'deny');
  assert.equal(flag(it).kind, 'allow');
});

test('warn mode: changed content is evaluated afresh (still flagged → deny again)', () => {
  const it = createInterceptor({ mode: 'warn' });
  assert.equal(flag(it).kind, 'deny');
  assert.equal(flag(it, 'write', 'a.md', '涓枃').kind, 'deny');
});

test('warn mode: same content to a different path is a different write (warned again)', () => {
  const it = createInterceptor({ mode: 'warn' });
  assert.equal(flag(it, 'write', 'a.md').kind, 'deny');
  assert.equal(flag(it, 'write', 'b.md').kind, 'deny');
});

test('block mode: flagged writes are always denied', () => {
  const it = createInterceptor({ mode: 'block' });
  assert.equal(flag(it).kind, 'deny');
  assert.equal(flag(it).kind, 'deny');
  assert.equal(flag(it).kind, 'deny');
});

test('ask mode: flagged writes route to the approval seam every time', () => {
  const it = createInterceptor({ mode: 'ask' });
  const d1 = flag(it);
  const d2 = flag(it);
  assert.equal(d1.kind, 'ask');
  assert.equal(d2.kind, 'ask');
  assert.match(d1.reason, /乱码拦截器/);
});

test('buildReason preview is bounded', () => {
  const many = Array.from({ length: 20 }, () => findings[0]);
  const reason = buildReason('a.md', many, 40);
  assert.ok(reason.length < 3000);
  assert.match(reason, /另有 14 处特征/);
});
