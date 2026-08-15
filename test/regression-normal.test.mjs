// False-positive regression suite: NORMAL operations must never be flagged.
// Garbled samples are built from \u escapes so this source stays clean.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { detectMojibake, analyzePwshEncoding } from '../lib/detect.js';

const none = async (text, opts) => {
  const r = await detectMojibake(text, opts);
  assert.deepEqual(r.findings, [], `unexpected findings for ${JSON.stringify(text.slice(0, 60))}: ${JSON.stringify(r.findings)}`);
};

// ── normal document / code content ───────────────────────────────────────────

test('normal Chinese prose with fullwidth punctuation', async () => {
  await none('这是一段正常的中文文章：包含句号。逗号，问号？感叹号！书名号《》和引号“”。还有破折号——和省略号……以及百分号％和波浪号～。', { path: 'note.md' });
});

test('mixed Chinese-English text', async () => {
  await none('使用 DeepSeek Harness 的 write 工具写入文件，路径为 D:\\repo\\dev\\personal-shrine。', { path: 'note.md' });
});

test('English markdown', async () => {
  await none('# Title\n\nThis is a **normal** paragraph with `inline code` and a [link](https://example.com).\n\n- item one\n- item two\n', { path: 'doc.md' });
});

test('JS source with Chinese comments and unicode escapes', async () => {
  await none("// 计算两个数的和\nfunction add(a, b) { return a + b; } // 注释\nconst s = '\\u4e2d\\u6587'; // 中文转义字面量\n", { path: 'lib.ts' });
});

test('JSON with Chinese values', async () => {
  await none('{"title": "我的笔记", "tags": ["中文", "test"], "n": 42}', { path: 'data.json' });
});

test('Python docstring with Chinese', async () => {
  await none('def f():\n    """\n    这是一个函数。\n    Returns:\n        int: 结果\n    """\n    return 42\n', { path: 'mod.py' });
});

test('HTML with Chinese', async () => {
  await none('<!doctype html><html><body><h1>标题</h1><p>正常内容</p></body></html>', { path: 'page.html' });
});

test('Japanese / Korean / Thai normal text', async () => {
  await none('こんにちは、世界。', { path: 'note.md' });
  await none('안녕하세요 세계', { path: 'note.md' });
  await none('สวัสดีชาวโลก', { path: 'note.md' });
});

test('symbols, math, arrows, currency, Greek', async () => {
  await none('∑∏ ∈ ℝ → 箭头 ← 货币 €¥£ 希腊 αβγδ 度数 45° 温度 ±2°C', { path: 'note.md' });
});

test('accented European text (French/German/Spanish/Nordic)', async () => {
  await none("L'œuvre de l'ingénieur est déjà là : ça s'appelle la préparation. À très bientôt !", { path: 'fr.md' });
  await none('Größe, Straße, über, für, Ärger, Österreich', { path: 'de.md' });
  await none('Español: ¡Hola! ¿Qué tal? ñ á é í ó ú', { path: 'es.md' });
  await none('Æsir, Øresund, Ångström, måndag', { path: 'se.md' });
});

test('emoji and edge unicode', async () => {
  await none('🎉🎊🎈 party! 😀 emoji mixed 中文', { path: 'note.md' });
  await none('· • – — ・', { path: 'note.md' });
});

test('tabs/newlines/CR and empty/short inputs', async () => {
  await none('a\tb\nc\r\nd');
  await none('');
  await none('a');
  await none('中文');
});

// ── normal pwsh commands ─────────────────────────────────────────────────────

const psOk = (command) => {
  assert.deepEqual(analyzePwshEncoding(command), [], `unexpected pwsh finding for: ${command}`);
};

test('pwsh: explicit utf8 variants are safe', () => {
  psOk("Set-Content -Path f.txt -Value '你好' -Encoding utf8");
  psOk("Set-Content -Path f.txt -Value '你好' -Encoding UTF8");
  psOk("Set-Content -Path f.txt -Value '你好' -Enc utf8"); // parameter abbreviation
  psOk("Out-File -Path f.txt -InputObject '你好' -Encoding utf8NoBOM");
  psOk("Add-Content -Path f.txt -Value '你好' -Encoding utf8");
});

test('pwsh: fully-qualified .NET types are safe', () => {
  psOk("[System.IO.File]::WriteAllText('x.txt', '你好')"); // 2-arg overload defaults to UTF-8
  psOk("[System.IO.File]::WriteAllText('x.txt', '你好', [System.Text.Encoding]::UTF8)");
  psOk("[System.Text.Encoding]::UTF8.GetBytes('你好') | [System.IO.File]::WriteAllBytes('x.bin', $_)");
});

test('pwsh: Chinese comments never trigger the encoding audit', () => {
  psOk("Set-Content -Path f.txt -Value $data # 写入数据到文件");
  psOk("$rows = Get-ChildItem; $rows | Out-File -Path list.txt # 导出列表");
  psOk("<# 这是块注释：中文说明 #> Set-Content -Path f.txt -Value $data");
});

test('pwsh: Chinese filenames do not trigger the encoding audit', () => {
  psOk("Get-Content -Path '中文.txt' -Encoding utf8 | Set-Content -Path '副本.txt' -Encoding utf8");
  psOk("Set-Content -LiteralPath '我的文档/笔记.md' -Value $content -Encoding utf8");
  psOk("Get-Content -Path '中文.txt' | Out-Null"); // read-only
});

test('pwsh: positional Chinese filenames after a write cmdlet are a deliberate gray zone', () => {
  // `Set-Content 副本.txt` without -Encoding genuinely writes with the PS 5.1
  // default (ANSI/GBK), so a copy through positional filenames draws one review.
  const f = analyzePwshEncoding("Get-Content 中文.txt | Set-Content 副本.txt");
  assert.deepEqual(f.map((x) => x.kind), ['pwsh-ambiguous-encoding']);
});

test('pwsh: Set-Item / registry / env writes are not file-content writes', () => {
  psOk("Set-Item Env:FOO '你好'"); // environment variable, no file encoding concern
  psOk("Set-Item -Path 'HKCU:\\Software\\App' -Value '你好'"); // registry is UTF-16-safe
});

test('pwsh: file operations that are not text-content writes', () => {
  psOk('Copy-Item a.txt b.txt');
  psOk("Move-Item '报告.docx' archive/");
  psOk("Remove-Item '旧文件.txt' -Force");
  psOk("Rename-Item 'old.md' '新名字.md'");
  psOk('git clone https://github.com/example/repo.git');
  psOk('npm install && npm run build');
  psOk('Get-Content a.txt | Measure-Object -Line');
});

test('pwsh: variable-only content, comparisons, loops', () => {
  psOk('$x = 你好'); // no write primitive
  psOk('$data = Get-Content in.txt; Set-Content out.txt $data'); // no literal content, no encoding declaration needed
  psOk('if ($a -gt $b) { Write-Host "bigger" }');
  psOk('for ($i = 0; $i -lt 10; $i++) { $i | Out-Null }');
  psOk("Set-Content -Path f.txt -Value ($x + 1)"); // ASCII expression content
});

test('pwsh: content literals WITHOUT encoding still intercepted (intent)', () => {
  const f = analyzePwshEncoding("Set-Content -Path x.txt -Value '你好'");
  assert.deepEqual(f.map((x) => x.kind), ['pwsh-ambiguous-encoding']);
  const g = analyzePwshEncoding("'你好' | Out-File -Path out.md");
  assert.deepEqual(g.map((x) => x.kind), ['pwsh-ambiguous-encoding']);
  const h = analyzePwshEncoding("Set-Content -Path x.txt -Value '你好' -Encoding Default");
  assert.deepEqual(h.map((x) => x.kind), ['pwsh-unsafe-encoding']);
});

// ── normal bash commands (inCommand detection only, no encoding audit) ───────

test('bash: normal commands never flagged', async () => {
  await none("echo '你好' > /tmp/out.txt", { path: 'cmd.bash', inCommand: true });
  await none("cat <<'EOF' > out.md\n正常的中文内容\nEOF", { path: 'cmd.bash', inCommand: true });
  await none("grep -r '模式' src/ | head -20", { path: 'cmd.bash', inCommand: true });
  await none("git commit -m '提交说明'", { path: 'cmd.bash', inCommand: true });
  await none("iconv -f gbk -t utf8 in.txt > out.txt", { path: 'cmd.bash', inCommand: true });
});

// ── the guard still catches the real targets (sanity, escaped samples) ───────

test('regression: real garbled samples are still caught', async () => {
  const moji = '\u00e4\u00b8\u00ad\u00e6\u2013\u2021'; // utf8-as-cp1252
  const garb = '\u6d93\uE15F\u6783'; // utf8-as-gbk
  const r1 = await detectMojibake(moji, { path: 'a.md' });
  assert.ok(r1.findings.length > 0);
  const r2 = await detectMojibake(garb, { path: 'a.md' });
  assert.ok(r2.findings.length > 0);
  const r3 = await detectMojibake("Set-Content -Path x -Value '" + moji + "'", { path: 'cmd.pwsh', inCommand: true });
  assert.ok(r3.findings.length > 0);
});
