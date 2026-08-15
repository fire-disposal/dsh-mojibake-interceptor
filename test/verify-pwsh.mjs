// End-to-end pwsh/bash pre-execute simulation against the installed profile copy.
// Run: node test/verify-pwsh.mjs  (from the plugin dir; the profile's hoisted
// node_modules is linked below for module resolution).
import fs from 'node:fs';
import yaml from 'js-yaml';

const patch = yaml.load(fs.readFileSync('C:/Users/Firedisposal/.dsh/profiles/web/cordis.patch.yml', 'utf8'));
console.log('patch ok:', patch[0].insert[0].id, '| guard:', patch[0].insert[0].config.pwshEncodingGuard);

const mod = await import('dsh-mojibake-interceptor');
console.log('default tools:', JSON.stringify(mod.Config({}).tools));

const fakeCtx = { on(e, fn) { this.h = this.h || {}; this.h[e] = fn; } };
mod.apply(fakeCtx, mod.Config({ mode: 'warn', pwshEncodingGuard: 'warn' }));
const pre = fakeCtx.h['tools/pre-execute'];
const next = async () => ({ kind: 'allow' });
const run = async (name, command) => {
  const d = await pre({ name, arguments: { command }, agent: {} }, next);
  return { kind: d?.kind, head: d?.reason?.slice(0, 44) };
};

// Garbled samples, built from escapes so this source file stays clean:
// MOJI = UTF-8 bytes read as CP1252 (the classic Chinese-Windows garble);
// GARB = the same bytes read as GBK.
const MOJI = '\u00e4\u00b8\u00ad\u00e6\u2013\u2021';
const GARB = '\u6d93\uE15F\u6783';

const cases = [
  ['1 pwsh garbled inline', 'pwsh', `Set-Content -Path x.txt -Value '${MOJI}'`, 'deny'],
  ['2 pwsh identical retry', 'pwsh', `Set-Content -Path x.txt -Value '${MOJI}'`, 'allow'],
  ['3 pwsh unsafe enc Default', 'pwsh', `Out-File -Path x.txt -Value '你好' -Encoding Default`, 'deny'],
  ['4 pwsh ambiguous no enc', 'pwsh', `Set-Content -Path x.txt -Value '你好'`, 'deny'],
  ['5 pwsh utf8 safe', 'pwsh', `Set-Content -Path x.txt -Value '你好' -Encoding utf8`, 'allow'],
  ['6 pwsh ascii write', 'pwsh', 'Get-Content a.txt | Set-Content b.txt', 'allow'],
  ['7 bash heredoc garbled', 'bash', `cat > out.md <<'EOF'\n${GARB}\nEOF`, 'deny'],
  ['8 pwsh regex escape', 'pwsh', "'abc' -match '[\\u4e00-\\u9fff]'", 'allow'],
  ['9 GetEncoding(936)', 'pwsh', `[IO.File]::WriteAllText('x.txt', '你好', [Text.Encoding]::GetEncoding(936))`, 'deny'],
  ['10 chcp65001 utf8', 'pwsh', `chcp 65001 | Out-Null; Set-Content -Path x.txt -Value '你好'`, 'deny'],
];

let fails = 0;
for (const [label, tool, command, expect] of cases) {
  const r = await run(tool, command);
  const ok = r.kind === expect;
  if (!ok) fails++;
  console.log(`${ok ? 'PASS' : 'FAIL'} ${label}: got ${r.kind}, want ${expect}${ok ? '' : ` | head: ${r.head}`}`);
}

// Result monitoring: ANSI-coloured terminal output must NOT notify; real
// mojibake output must.
const post = fakeCtx.h['tools/post-execute'];
const runPost = async (name, text) => {
  const out = await post(
    { name, agent: {} },
    { isError: false, content: [{ type: 'text', text }] },
    async () => ({ kind: 'accept' }),
  );
  return Array.isArray(out.additionalContexts) && out.additionalContexts.length > 0;
};
const ansiOk = (await runPost('pwsh', '\u001b[31mred\u001b[0m')) === false;
console.log(`${ansiOk ? 'PASS' : 'FAIL'} post: ANSI colour output does not notify`);
const mojiOk = (await runPost('pwsh', '\u00e4\u00b8\u00ad\u00e6\u2013\u2021')) === true;
console.log(`${mojiOk ? 'PASS' : 'FAIL'} post: mojibake output notifies`);
if (!ansiOk) fails++;
if (!mojiOk) fails++;

// Read of an excluded path must stay silent (plugin docs contain samples).
const mod2 = await import('dsh-mojibake-interceptor');
const ctx2 = { on(e, fn) { this.h = this.h || {}; this.h[e] = fn; } };
mod2.apply(ctx2, mod2.Config({ mode: 'warn', excludePaths: ['*dsh-mojibake-interceptor*'] }));
const post2 = ctx2.h['tools/post-execute'];
const out2 = await post2(
  { name: 'read', agent: {}, arguments: { file_path: 'D:/x/dsh-mojibake-interceptor/README.md' } },
  { isError: false, content: [{ type: 'text', text: '\u00e4\u00b8\u00ad\u00e6\u2013\u2021' }] },
  async () => ({ kind: 'accept' }),
);
const exclOk = !(Array.isArray(out2.additionalContexts) && out2.additionalContexts.length > 0);
console.log(`${exclOk ? 'PASS' : 'FAIL'} post: excluded read path stays silent`);
if (!exclOk) fails++;

// Reading a CODE file with literal \uXXXX escapes must not notify either.
const out3 = await post2(
  { name: 'read', agent: {}, arguments: { file_path: 'D:/x/src/util.ts' } },
  { isError: false, content: [{ type: 'text', text: "const s = '\\u4e2d\\u6587'; // ok" }] },
  async () => ({ kind: 'accept' }),
);
const codeOk = !(Array.isArray(out3.additionalContexts) && out3.additionalContexts.length > 0);
console.log(`${codeOk ? 'PASS' : 'FAIL'} post: reading code with \\u escapes does not notify`);
if (!codeOk) fails++;

console.log(fails === 0 ? 'ALL PASS' : `${fails} FAILURES`);
process.exit(fails === 0 ? 0 : 1);
