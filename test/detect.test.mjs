import { test } from 'node:test';
import assert from 'node:assert/strict';
import { detectMojibake, analyzePwshEncoding } from '../lib/detect.js';

const kinds = async (text, opts) => {
  const r = await detectMojibake(text, { path: 'test.md', ...opts });
  return r.findings.map((f) => f.kind);
};

test('pure ASCII is never flagged', async () => {
  assert.deepEqual(await kinds('hello world, this is fine 123'), []);
  assert.deepEqual(await kinds('const x = 1;\nfunction foo() { return x; }\n'), []);
});

test('clean Chinese is not flagged', async () => {
  assert.deepEqual(await kinds('你好，世界。这是一段完全正常的中文文本。'), []);
  assert.deepEqual(await kinds('Hello, 世界! This is fine.'), []);
  assert.deepEqual(await kinds('中文😀 emoji mix'), []);
});

test('clean French/German is not flagged', async () => {
  assert.deepEqual(await kinds("café déjà vu, c'était très bien"), []);
  assert.deepEqual(await kinds('Größe'), []);
  assert.deepEqual(await kinds('naïve Æther'), []);
});

test('clean punctuation is not flagged', async () => {
  assert.deepEqual(await kinds('……——'), []);
  assert.deepEqual(await kinds('「引号」与（括号）'), []);
});

test('UTF-8 read as CP1252 (Chinese) is flagged severe', async () => {
  const r = await detectMojibake('ä¸­æ–‡', { path: 'a.md' });
  assert.ok(r.findings.some((f) => f.kind === 'utf8-as-cp1252-cjk' && f.severity === 'severe'), JSON.stringify(r.findings));
});

test('double-encoded 测试 (UTF-8 as CP1252) is flagged', async () => {
  const r = await detectMojibake('æµ‹è¯•', { path: 'a.md' });
  assert.ok(r.findings.some((f) => f.kind === 'utf8-as-cp1252-cjk'), JSON.stringify(r.findings));
});

test('accent mojibake dÃ©jÃ is flagged moderate', async () => {
  const r = await detectMojibake('dÃ©jÃ ', { path: 'a.md' });
  assert.ok(r.findings.some((f) => f.kind === 'utf8-as-cp1252'), JSON.stringify(r.findings));
});

test('symbol mojibake Â© is flagged', async () => {
  const r = await detectMojibake('Copyright Â© 2024', { path: 'a.md' });
  assert.ok(r.findings.some((f) => f.kind === 'utf8-as-cp1252'), JSON.stringify(r.findings));
});

test('fullwidth mojibake ï¼š (：) is flagged', async () => {
  const r = await detectMojibake('ï¼š', { path: 'a.md' });
  assert.ok(r.findings.some((f) => f.kind === 'utf8-as-cp1252-cjk'), JSON.stringify(r.findings));
});

test('GBK read as CP1252 (ÖÐÎÄ = 中文) is flagged severe', async () => {
  const r = await detectMojibake('ÖÐÎÄ', { path: 'a.md' });
  assert.ok(r.findings.some((f) => f.kind === 'gbk-as-cp1252' && f.severity === 'severe'), JSON.stringify(r.findings));
});

test('GBK read as CP1252 (ÖÐ¹ú = 中国) is flagged', async () => {
  const r = await detectMojibake('ÖÐ¹ú', { path: 'a.md' });
  assert.ok(r.findings.some((f) => f.kind === 'gbk-as-cp1252'), JSON.stringify(r.findings));
});

test('UTF-8 read as GBK (涓\uE15F枃 = 中文) is flagged severe', async () => {
  // Complete 3-char garbage: the full UTF-8 of 中文 (E4B8ADE69687) read as GBK.
  const r = await detectMojibake('涓\uE15F枃', { path: 'a.md' });
  assert.ok(r.findings.some((f) => f.kind === 'utf8-as-gbk' && f.severity === 'severe'), JSON.stringify(r.findings));
});

test('UTF-8 read as GBK (娴嬭瘯 = 测试) is flagged', async () => {
  const r = await detectMojibake('娴嬭瘯', { path: 'a.md' });
  assert.ok(r.findings.some((f) => f.kind === 'utf8-as-gbk'), JSON.stringify(r.findings));
});

test('replacement-char runs are flagged severe', async () => {
  const r = await detectMojibake('a�b�c�', { path: 'a.md' });
  assert.ok(r.findings.some((f) => f.kind === 'replacement-char' && f.severity === 'severe'), JSON.stringify(r.findings));
  assert.ok(r.score >= 2);
});

test('a single replacement char is flagged moderate', async () => {
  const r = await detectMojibake('a�b', { path: 'a.md' });
  assert.ok(r.findings.some((f) => f.kind === 'lone-replacement' && f.severity === 'moderate'), JSON.stringify(r.findings));
});

test('UTF-16 text (NUL-separated) is flagged severe', async () => {
  const r = await detectMojibake('h\u0000e\u0000l\u0000l\u0000o\u0000', { path: 'a.md' });
  assert.ok(r.findings.some((f) => f.kind === 'utf16-leak' && f.severity === 'severe'), JSON.stringify(r.findings));
});

test('锟斤拷 (GBK-misread replacement chars) is flagged', async () => {
  const r = await detectMojibake('锟斤拷', { path: 'a.md' });
  assert.ok(r.findings.some((f) => f.kind === 'gbk-misread-replacement'), JSON.stringify(r.findings));
});

test('literal unicode escapes are flagged in non-code files', async () => {
  const r = await detectMojibake('标题是 \\u4e2d\\u6587 乱码转义', { path: 'note.md' });
  assert.ok(r.findings.some((f) => f.kind === 'literal-unicode-escape'), JSON.stringify(r.findings));
});

test('literal escapes are exempt in code/JSON files', async () => {
  assert.deepEqual(await kinds("const s = '\\u4e2d\\u6587';", { path: 'a.ts' }), []);
  assert.deepEqual(await kinds('{"name":"\\u4e2d\\u6587"}', { path: 'a.json' }), []);
});

test('HTML numeric entities are flagged in markdown', async () => {
  const r = await detectMojibake('&#20013;&#25991; &#x4E2D;', { path: 'note.md' });
  assert.ok(r.findings.some((f) => f.kind === 'html-numeric-entity'), JSON.stringify(r.findings));
});

test('HTML entities are exempt in HTML files', async () => {
  assert.deepEqual(await kinds('&#20013;&#25991;', { path: 'page.html' }), []);
});

test('ANSI escape sequences are flagged', async () => {
  const r = await detectMojibake('\u001b[31mred\u001b[0m', { path: 'a.txt' });
  assert.ok(r.findings.some((f) => f.kind === 'ansi-escape'), JSON.stringify(r.findings));
});

test('excludeKinds suppresses the ansi-escape signal (result monitoring)', async () => {
  const r = await detectMojibake('\u001b[31mred\u001b[0m', { path: 'a.txt', excludeKinds: ['ansi-escape'] });
  assert.deepEqual(r.findings, []);
  // other signals still pass through
  const r2 = await detectMojibake('\u00e4\u00b8\u00ad\u00e6\u2013\u2021', { path: 'a.txt', excludeKinds: ['ansi-escape'] });
  assert.ok(r2.findings.length > 0);
});

test('stray BOM is flagged', async () => {
  const r = await detectMojibake('abc\uFEFFdef', { path: 'a.md' });
  assert.ok(r.findings.some((f) => f.kind === 'bom-anomaly'), JSON.stringify(r.findings));
});

test('control characters are flagged', async () => {
  const r = await detectMojibake('a\u0007b', { path: 'a.md' });
  assert.ok(r.findings.some((f) => f.kind === 'control-char'), JSON.stringify(r.findings));
});

test('tabs/newlines/CR are not control-char findings', async () => {
  assert.deepEqual(await kinds('line1\t\nline2\r\n'), []);
});

test('mojibake inside otherwise-clean text is still found', async () => {
  const r = await detectMojibake('正常中文\nä¸­æ–‡\n更多正常', { path: 'a.md' });
  assert.ok(r.findings.some((f) => f.kind === 'utf8-as-cp1252-cjk'), JSON.stringify(r.findings));
});

test('minSeverity=severe drops moderate findings', async () => {
  const r = await detectMojibake('dÃ©jÃ ', { path: 'a.md', minSeverity: 'severe' });
  assert.deepEqual(r.findings, []);
});

test('maxFindings caps the result', async () => {
  const text = ['ä¸­æ–‡', 'æµ‹è¯•', 'ï¼š', 'ÖÐÎÄ', '涓枃', '�', '�', '�'].join('\n');
  const r = await detectMojibake(text, { path: 'a.md', maxFindings: 3 });
  assert.ok(r.findings.length <= 3);
});

test('performance: 1MB ASCII content returns quickly', async () => {
  const big = 'x'.repeat(1024 * 1024);
  const t0 = performance.now();
  const r = await detectMojibake(big, { path: 'big.txt' });
  const ms = performance.now() - t0;
  assert.deepEqual(r.findings, []);
  assert.ok(ms < 500, `1MB ASCII scan took ${ms}ms`);
});

test('performance: 200KB clean Chinese returns quickly', async () => {
  const line = '这是一段完全正常的中文文本，用于性能测试。\n';
  const big = line.repeat(4000);
  const t0 = performance.now();
  const r = await detectMojibake(big, { path: 'big.md' });
  const ms = performance.now() - t0;
  assert.deepEqual(r.findings, []);
  assert.ok(ms < 1000, `200KB Chinese scan took ${ms}ms`);
});

// ── pwsh command encoding audit ──────────────────────────────────────────────

test('pwsh: Set-Content with non-ASCII and no encoding → ambiguous (moderate)', () => {
  const f = analyzePwshEncoding("Set-Content -Path x.txt -Value '你好'");
  assert.deepEqual(f.map((x) => x.kind), ['pwsh-ambiguous-encoding']);
  assert.equal(f[0].severity, 'moderate');
});

test('pwsh: Out-File -Encoding Default → unsafe (severe)', () => {
  const f = analyzePwshEncoding("Out-File -Path x.txt -Value '你好' -Encoding Default");
  assert.deepEqual(f.map((x) => x.kind), ['pwsh-unsafe-encoding']);
  assert.equal(f[0].severity, 'severe');
});

test('pwsh: GetEncoding(936) → unsafe (severe)', () => {
  const f = analyzePwshEncoding("[IO.File]::WriteAllText('x.txt', '你好', [Text.Encoding]::GetEncoding(936))");
  assert.deepEqual(f.map((x) => x.kind), ['pwsh-unsafe-encoding']);
});

test('pwsh: explicit -Encoding utf8 → safe (no findings)', () => {
  assert.deepEqual(analyzePwshEncoding("Set-Content -Path x.txt -Value '你好' -Encoding utf8"), []);
});

test('pwsh: .NET WriteAllText 2-arg (defaults to UTF-8) → safe', () => {
  assert.deepEqual(analyzePwshEncoding("[IO.File]::WriteAllText('x.txt', '你好')"), []);
});

test('pwsh: redirect with non-ASCII content and no encoding → ambiguous', () => {
  const f = analyzePwshEncoding("'你好' | Out-File -Path out.md");
  assert.deepEqual(f.map((x) => x.kind), ['pwsh-ambiguous-encoding']);
});

test('pwsh: chcp 65001 (UTF-8) is not unsafe', () => {
  const f = analyzePwshEncoding("chcp 65001 | Out-Null; Set-Content -Path x.txt -Value '你好'");
  assert.deepEqual(f.map((x) => x.kind), ['pwsh-ambiguous-encoding']);
});

test('pwsh: pure-ASCII command never audited', () => {
  assert.deepEqual(analyzePwshEncoding('Get-Content x.txt | Set-Content y.txt'), []);
});

test('pwsh: comparison `> $b` is not a redirect', () => {
  assert.deepEqual(analyzePwshEncoding('if ($a > $b) { Write-Host hi }'), []);
});

// ── command (inCommand) detection ────────────────────────────────────────────

test('inCommand: embedded mojibake is still found', async () => {
  const r = await detectMojibake("Set-Content -Path x -Value '\u00e4\u00b8\u00ad\u00e6\u2013\u2021'", { path: 'cmd.pwsh', inCommand: true });
  assert.ok(r.findings.some((f) => f.kind === 'utf8-as-cp1252-cjk'), JSON.stringify(r.findings));
});

test('inCommand: pwsh regex \\uXXXX escapes are NOT flagged', async () => {
  const r = await detectMojibake("'abc' -match '[\\u4e00-\\u9fff]'", { path: 'cmd.pwsh', inCommand: true });
  assert.deepEqual(r.findings, []);
});

test('inCommand: bash heredoc with garbled content is found', async () => {
  const r = await detectMojibake("cat > out.md <<'EOF'\n涓\uE15F枃\nEOF", { path: 'cmd.bash', inCommand: true });
  assert.ok(r.findings.some((f) => f.kind === 'utf8-as-gbk'), JSON.stringify(r.findings));
});
