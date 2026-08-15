/**
 * Feature-based mojibake detection engine for the DeepSeek Harness.
 *
 * There are NO keyword/signature tables. Every signal is derived from
 * character statistics or from encoding round-trips:
 *
 *   1. Character statistics — U+FFFD replacement chars, NUL/control chars,
 *      ANSI escape sequences, stray BOMs, UTF-16 leakage.
 *   2. Encoding round-trips — the core feature. A suspicious segment is
 *      re-encoded into a legacy charset (CP1252 / GBK / Big5) and re-decoded
 *      with a STRICT decoder. Text that was really UTF-8 bytes misread as
 *      another charset re-encodes to the original valid UTF-8 byte stream,
 *      which is a discriminating property: legitimate text of any single
 *      encoding almost never survives that round-trip, and when it does the
 *      decoded script matches the original script.
 *   3. Script-consistency features — the round-trip must produce a script
 *      different from the segment's own, or compact the text (accent pairs
 *      like "Ã©" collapse to "é"), otherwise the segment is left alone.
 *   4. Structural escapes — literal `\uXXXX` / `\xXX` escapes and HTML
 *      numeric entities standing in for real non-ASCII characters.
 *
 * Performance model: a single gate regex rejects pure-ASCII content in one
 * fast pass; every later stage is bounded by `maxFindings`, `maxRunChars`
 * and `maxRuns`, and legacy-charset work only runs when the cheap
 * character-class checks already passed.
 */

// ─────────────────────────────────────────────────────────────────────────────
// Character classes
// ─────────────────────────────────────────────────────────────────────────────

/** One-pass gate: any control, DEL, non-ASCII char, literal unicode escape or numeric entity. */
const RE_GATE =
  /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F\u0080-\uFFFF]|\\u[0-9a-fA-F]{4}|\\U[0-9a-fA-F]{8}|\\x[0-9a-fA-F]{2}|&#[0-9]{1,7};|&#[xX][0-9a-fA-F]{1,6};/;

/** Cheap feature characters: replacement char, NUL, controls (incl. ESC), DEL, BOM. */
const RE_FEATURE_CHARS = /[\uFFFD\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F\u001B\uFEFF]/g;

/** CJK / fullwidth / Hangul — the "non-Latin script" family Chinese mojibake produces. */
const RE_CJK = /[\u3400-\u4DBF\u4E00-\u9FFF\uF900-\uFAFF\uAC00-\uD7AF\uFF00-\uFFEF]/;
const RE_CJK_G = /[\u3400-\u4DBF\u4E00-\u9FFF\uF900-\uFAFF\uAC00-\uD7AF\uFF00-\uFFEF]/g;

/** Maximal runs of CP1252-encodable non-ASCII chars (the UTF-8-as-CP1252 alphabet). */
const RE_LATIN_SEGMENT =
  /[\u0080-\u00FF\u0152\u0153\u0160\u0161\u017D\u017E\u0178\u0192\u02C6\u02DC\u2013\u2014\u2018-\u201F\u2020-\u2022\u2026\u2030\u2039\u203A\u20AC\u2122]+/g;

/** Maximal runs of any non-ASCII text (candidate GBK/Big5-misread segments). */
const RE_NON_ASCII_SEGMENT = /[^\u0000-\u007F]+/g;

const RE_UTF16_LEAK = /(?:[\u0020-\u007E]\u0000){2,}/;
const RE_NON_ASCII = /[^\u0000-\u007F]/;
const RE_ESCAPE = /\\u([0-9a-fA-F]{4})|\\U([0-9a-fA-F]{8})|\\x([0-9a-fA-F]{2})/g;
const RE_ENTITY = /&#(\d{1,7});|&#[xX]([0-9a-fA-F]{1,6});/g;

// ─────────────────────────────────────────────────────────────────────────────
// CP1252 — hand-rolled, dependency-free encode table
// ─────────────────────────────────────────────────────────────────────────────

/** CP1252 0x80–0x9F special mappings (code point → byte). */
const CP1252_SPECIAL = new Map([
  [0x20ac, 0x80], [0x201a, 0x82], [0x0192, 0x83], [0x201e, 0x84], [0x2026, 0x85],
  [0x2020, 0x86], [0x2021, 0x87], [0x02c6, 0x88], [0x2030, 0x89], [0x0160, 0x8a],
  [0x2039, 0x8b], [0x0152, 0x8c], [0x017d, 0x8e], [0x2018, 0x91], [0x2019, 0x92],
  [0x201c, 0x93], [0x201d, 0x94], [0x2022, 0x95], [0x2013, 0x96], [0x2014, 0x97],
  [0x02dc, 0x98], [0x2122, 0x99], [0x0161, 0x9a], [0x203a, 0x9b], [0x0153, 0x9c],
  [0x017e, 0x9e], [0x0178, 0x9f],
]);

/**
 * Encode a CP1252-encodable segment to bytes. Returns `null` when a character
 * is not mappable (segments are built from the CP1252 alphabet, so this only
 * fires on a bug).
 */
function cp1252Encode(segment) {
  const bytes = new Uint8Array(segment.length);
  for (let i = 0; i < segment.length; i++) {
    const code = segment.charCodeAt(i);
    if (code >= 0xa0 && code <= 0xff) {
      bytes[i] = code;
    } else {
      const mapped = CP1252_SPECIAL.get(code);
      if (mapped === undefined) return null;
      bytes[i] = mapped;
    }
  }
  return bytes;
}

// ─────────────────────────────────────────────────────────────────────────────
// Strict decoding (fatal on invalid sequences, so a failed round-trip returns
// `null` instead of silently substituting replacement chars)
// ─────────────────────────────────────────────────────────────────────────────

function strictDecode(label, bytes) {
  try {
    return new TextDecoder(label, { fatal: true }).decode(bytes);
  } catch {
    return null;
  }
}

const strictUtf8 = (bytes) => strictDecode('utf-8', bytes);
const strictGbk = (bytes) => strictDecode('gbk', bytes);

// ─────────────────────────────────────────────────────────────────────────────
// GBK / Big5 encoders — iconv-lite, loaded lazily and cached; the direction
// degrades gracefully (returns no findings) when the package is unavailable.
// ─────────────────────────────────────────────────────────────────────────────

let iconvPromise = null;
let iconvUnavailableLogged = false;

function loadIconv() {
  if (!iconvPromise) {
    iconvPromise = import('iconv-lite')
      .then((m) => m.default ?? m)
      .catch((err) => {
        if (!iconvUnavailableLogged) {
          iconvUnavailableLogged = true;
          console.error('[mojibake-interceptor] iconv-lite unavailable; GBK/Big5 round-trip detection disabled:', err.message);
        }
        return null;
      });
  }
  return iconvPromise;
}

/**
 * Encode `text` with `encoding`, returning `null` when the encode was lossy.
 * iconv-lite substitutes `?` (0x3F) for unmappable characters; the segments
 * analyzed here are non-ASCII by construction, so any 0x3F byte proves loss.
 */
function encodeLossless(iconv, text, encoding) {
  const buf = iconv.encode(text, encoding);
  return buf.includes(0x3f) ? null : buf;
}

// ─────────────────────────────────────────────────────────────────────────────
// Small counters
// ─────────────────────────────────────────────────────────────────────────────

function countCjk(s) {
  const m = s.match(RE_CJK_G);
  return m ? m.length : 0;
}

function countUfffd(s) {
  let n = 0;
  for (let i = 0; i < s.length; i++) if (s.charCodeAt(i) === 0xfffd) n++;
  return n;
}

function clip(s, n) {
  return s.length <= n ? s : `${s.slice(0, n)}…`;
}

// ─────────────────────────────────────────────────────────────────────────────
// Per-feature analyzers
// ─────────────────────────────────────────────────────────────────────────────

function analyzeCounts(text, push) {
  const stats = { fffd: 0, nul: 0, esc: 0, control: 0, bom: 0, firstBomAt: -1, firstCtrlAt: -1 };
  let m;
  RE_FEATURE_CHARS.lastIndex = 0;
  while ((m = RE_FEATURE_CHARS.exec(text))) {
    const code = m[0].charCodeAt(0);
    if (code === 0xfffd) {
      stats.fffd++;
    } else if (code === 0x001b) {
      stats.esc++;
    } else if (code === 0xfeff) {
      stats.bom++;
      if (stats.firstBomAt < 0) stats.firstBomAt = m.index;
    } else {
      stats.control++;
      stats.nul += code === 0x0000 ? 1 : 0;
      if (stats.firstCtrlAt < 0) stats.firstCtrlAt = m.index;
    }
  }

  if (stats.fffd >= 2) {
    push('severe', 'replacement-char', `U+FFFD 替换符 ×${stats.fffd}（无效 UTF-8 字节）`);
  } else if (stats.fffd === 1) {
    push('moderate', 'lone-replacement', '含 1 处 U+FFFD 替换符');
  }

  if (stats.nul >= 2 && (stats.nul / text.length >= 0.15 || RE_UTF16_LEAK.test(text))) {
    push('severe', 'utf16-leak', `NUL 字节 ×${stats.nul}（UTF-16 字节被当作文本）`);
  }

  if (stats.control > 0) {
    const ch = text.charAt(stats.firstCtrlAt);
    push('severe', 'control-char', `含控制字符 U+${ch.charCodeAt(0).toString(16).toUpperCase().padStart(4, '0')}`);
  }

  if (stats.esc > 0) {
    push('moderate', 'ansi-escape', `ESC 转义序列 ×${stats.esc}（如 \\x1B[…m 颜色码）`);
  }

  if (stats.bom > 0 && (stats.firstBomAt > 0 || stats.bom > 1)) {
    push('moderate', 'bom-anomaly', `U+FEFF BOM 字符 ×${stats.bom}`);
  }
}

/**
 * Latin-segment round-trips. Two directions:
 *   seg → CP1252 bytes → strict UTF-8   (UTF-8 misread as CP1252/Latin-1)
 *   seg → CP1252 bytes → strict GBK     (GBK misread as CP1252/Latin-1, e.g. "ÖÐÎÄ")
 */
function analyzeLatinSegment(seg, push) {
  if (seg.length < 2) return;
  const bytes = cp1252Encode(seg);
  if (!bytes) return;

  const dec = strictUtf8(bytes);
  if (dec && dec !== seg) {
    const nonAscii = countNonAscii(dec);
    // Compactness: the round-trip must shrink the non-ASCII count
    // ("Ã©" → "é"), otherwise the segment was already native UTF-8 text
    // ("åå" → "åå" is skipped).
    if (nonAscii > 0 && nonAscii < seg.length) {
      if (RE_CJK.test(dec)) {
        push('severe', 'utf8-as-cp1252-cjk', `${clip(seg, 48)} → ${clip(dec, 48)}`);
      } else {
        push('moderate', 'utf8-as-cp1252', `${clip(seg, 48)} → ${clip(dec, 48)}`);
      }
    }
  }

  const g = strictGbk(bytes);
  // GBK-as-CP1252 is only credible when the decoded characters come from the
  // COMMON GBK Hanzi range (lead byte 0xB0–0xF7): real Chinese text encodes to
  // those leads, while incidental byte pairs from legit punctuation (e.g. the
  // CP1252 bytes of "……——") land in the rare extension ranges (0x81–0xA0…)
  // and must not fire.
  if (g && g !== seg && countCjk(g) >= 2) {
    let commonPairs = 0;
    for (let i = 0; i + 1 < bytes.length; i += 2) {
      const lead = bytes[i];
      const trail = bytes[i + 1];
      if (lead >= 0xb0 && lead <= 0xf7 && trail >= 0xa1 && trail <= 0xfe) commonPairs++;
    }
    if (commonPairs >= 2) {
      push('severe', 'gbk-as-cp1252', `${clip(seg, 48)} → ${clip(g, 48)}`);
    }
  }
}

function countNonAscii(s) {
  let n = 0;
  for (let i = 0; i < s.length; i++) if (s.charCodeAt(i) > 0x7f) n++;
  return n;
}

/**
 * CJK-segment round-trips (requires iconv-lite): the segment is re-encoded to
 * GBK/Big5 bytes and strictly re-decoded as UTF-8. Real mojibake (garbage like
 * "涓枃" that IS the GBK reading of valid UTF-8 bytes) round-trips to the
 * original clean text; real CJK prose almost never does (its GBK bytes are
 * not valid UTF-8).
 */
async function analyzeCjkSegment(seg, maxRunChars, push) {
  if (seg.length < 2) return;
  const iconv = await loadIconv();
  if (!iconv) return;
  const sample = seg.slice(0, maxRunChars);

  const gbk = encodeLossless(iconv, sample, 'gbk');
  if (gbk) {
    const dec = strictUtf8(gbk);
    if (dec && dec !== seg) {
      if (countCjk(dec) >= 2) {
        push('severe', 'utf8-as-gbk', `${clip(seg, 48)} → ${clip(dec, 48)}`);
      } else if (countUfffd(dec) >= 2) {
        // The classic "锟斤拷": GBK reading of UTF-8 replacement bytes.
        push('severe', 'gbk-misread-replacement', `${clip(seg, 48)} → ${clip(dec, 48)}`);
      }
    }
  }

  const big5 = encodeLossless(iconv, sample, 'big5');
  if (big5) {
    const dec = strictUtf8(big5);
    if (dec && dec !== seg && countCjk(dec) >= 2) {
      push('severe', 'utf8-as-big5', `${clip(seg, 48)} → ${clip(dec, 48)}`);
    }
  }
}

/** File extensions where literal `\uXXXX` escapes are legitimate source syntax. */
const ESCAPE_EXEMPT_EXTS = new Set([
  'js', 'mjs', 'cjs', 'jsx', 'ts', 'mts', 'cts', 'tsx', 'py', 'rb', 'php', 'go',
  'rs', 'java', 'kt', 'kts', 'c', 'h', 'cpp', 'hpp', 'cc', 'cs', 'swift', 'scala',
  'json', 'jsonc', 'sql', 'lua', 'pl', 'r', 'dart', 'ex', 'exs', 'erl', 'hs',
  'ml', 'vb', 'f', 'fs', 'sh', 'bash', 'ps1', 'psm1', 'bat', 'cmd',
]);

/** File extensions where HTML numeric entities are legitimately decoded by a parser. */
const HTML_EXTS = new Set(['html', 'htm', 'xhtml', 'xml', 'svg', 'vue', 'svelte', 'astro', 'mdx']);

function extOf(path) {
  const i = path.lastIndexOf('.');
  if (i < 0) return '';
  const base = path.slice(i + 1).toLowerCase();
  return base.split(/[/\\]/)[0];
}

function analyzeEscapes(text, path, push) {
  if (ESCAPE_EXEMPT_EXTS.has(extOf(path))) return;
  let total = 0;
  let cjk = 0;
  let first = '';
  RE_ESCAPE.lastIndex = 0;
  let m;
  while ((m = RE_ESCAPE.exec(text))) {
    const hex = m[1] ?? m[2] ?? m[3];
    const cp = parseInt(hex, 16);
    if (cp < 0x80) continue;
    total++;
    if (!first) first = m[0];
    if (RE_CJK.test(String.fromCodePoint(cp))) cjk++;
  }
  if (total >= 2 || (cjk >= 1 && total >= 1)) {
    push('moderate', 'literal-unicode-escape', `${first} 等 ${total} 处非 ASCII 字面转义（应为实际字符）`);
  }
}

function analyzeEntities(text, path, push) {
  if (HTML_EXTS.has(extOf(path))) return;
  let total = 0;
  let cjk = 0;
  RE_ENTITY.lastIndex = 0;
  let m;
  while ((m = RE_ENTITY.exec(text))) {
    const cp = m[1] !== undefined ? parseInt(m[1], 10) : parseInt(m[2], 16);
    if (cp < 0x80) continue;
    total++;
    if (RE_CJK.test(String.fromCodePoint(cp))) cjk++;
  }
  if (total >= 2 || cjk >= 1) {
    push('moderate', 'html-numeric-entity', `&#…; 数字实体 ${total} 处（非 HTML 文件）`);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// PowerShell (pwsh) command encoding audit — catches the Windows tragedy where
// the model writes/replaces file content THROUGH a pwsh command and the
// command's encoding silently corrupts everything (PS 5.1 `Out-File`/`>`
// default UTF-16LE, `Set-Content` default ANSI/GBK, `-Encoding Default`,
// `chcp`, `[Console]::OutputEncoding`, …).
// These are grammar patterns, not keyword lists.
// ─────────────────────────────────────────────────────────────────────────────

/** PowerShell cmdlets / .NET calls that write text to disk (System-prefixed forms included). */
const RE_PS_WRITE_PRIMITIVES =
  /Set-Content|Add-Content|Out-File|Export-Csv|Export-Clixml|\[(?:System\.)?IO\.File\]::WriteAll(?:Text|Lines)|\[(?:System\.)?IO\.StreamWriter\]|\[(?:System\.)?Text\.File\]::WriteAllText/gi;

/** Redirection to a file-like target (needs a `.`, `\` or `/` so `> $b` comparisons do not match). */
const RE_PS_REDIRECT = />>?\s*["']?[^"'|;\s]*[.\\/][^"'|;\s]*/g;

/**
 * Explicitly safe encodings — the command knows what it is doing. Covers the
 * `-Enc` parameter abbreviation and fully-qualified .NET type names.
 */
const RE_PS_SAFE_ENCODING =
  /-Enc(?:oding)?\s+(?:utf8|utf-8|utf8NoBOM|ascii)\b|\[(?:System\.)?Text\.Encoding\]::(?:UTF8|ASCII)\b|\[(?:System\.)?Text\.Encoding\]::GetEncoding\(\s*(?:65001|["'][^"']*(?:utf|ascii)[^"']*["'])\s*\)|\[(?:System\.)?IO\.File\]::WriteAll(?:Text|Lines)\(\s*[^,]+,\s*[^,)]*\)/gi;

/** Explicitly dangerous encodings — ANSI/GBK/OEM/UTF-16 and codepage pinning (chcp 65001 = UTF-8 is safe). */
const RE_PS_UNSAFE_ENCODING =
  /-Enc(?:oding)?\s+(?:Default|ANSI|OEM|Unicode|BigEndianUnicode)\b|\[(?:System\.)?Text\.Encoding\]::Default\b|\[(?:System\.)?Text\.Encoding\]::GetEncoding\(\s*(?:936|950|1252|20936|54936|["'][^"']*(?:gbk|gb2312|gb18030|big5|shift_jis|ansi|cp936|oem)[^"']*["'])\s*\)|\[Console\]::OutputEncoding\s*=|chcp\s+(?!65001)\d+|\$OutputEncoding\s*=/gi;

/** Line and block comments in a pwsh command (stripped before auditing so Chinese comments never trigger). */
const RE_PS_COMMENT = /<#[\s\S]*?#>|#[^\r\n]*/g;

/** Non-ASCII inside a quoted string literal (content context, not paths/identifiers). */
const RE_PS_QUOTED_NON_ASCII = /(["'])(?:(?!\1)[\s\S])*[^\u0000-\u007F][\s\S]*?\1/g;

/** Path/name parameter names that precede a filename literal. */
const RE_PS_PATH_PARAM = /(?<![\w-])(?:-Path|-LiteralPath|-Destination|-FilePath|-Name|-Source|-Target)\s*$/i;

/** Read/context cmdlets whose non-ASCII arguments are filenames, not content. */
const RE_PS_READ_CONTEXT =
  /(?:Get-Content|Get-Item|Get-ChildItem|ReadAllText|ReadAllLines|Import-Csv|ConvertFrom-Json|Set-Location|Push-Location|Get-Location)\s*$/i;

/** An UNQUOTED non-ASCII token in positional position right after a write cmdlet (`Set-Content 副本.txt`). */
const RE_PS_BARE_CONTENT_AFTER_WRITE = /(?:Set-Content|Add-Content|Out-File)\s+(?![-$\w])([^\s"'|;]+[^\u0000-\u007F])/i;

/**
 * Non-ASCII in a file-CONTENT position. In a command that writes, every quoted
 * non-ASCII literal counts as content EXCEPT literals sitting in a clear
 * filename position: after a path/name parameter (`-Path`/`-LiteralPath`/…)
 * or after a read/context cmdlet (`Get-Content`/`ReadAllText`/…). Unquoted
 * positional tokens right after a write cmdlet also count. Comments are
 * stripped before this runs. Positional filenames after a write cmdlet
 * (`Set-Content 副本.txt`) remain a deliberate gray zone: in PS 5.1 that call
 * genuinely writes with a default encoding, so one review is the intent.
 */
function hasContentNonAscii(command) {
  for (const m of command.matchAll(RE_PS_QUOTED_NON_ASCII)) {
    const before = command.slice(Math.max(0, m.index - 40), m.index);
    if (RE_PS_PATH_PARAM.test(before)) continue;
    if (RE_PS_READ_CONTEXT.test(before)) continue;
    return true;
  }
  return RE_PS_BARE_CONTENT_AFTER_WRITE.test(command);
}

/** Reset a global regex before `.test()` so a stale `lastIndex` cannot skip matches. */
function resetAndTest(re, text) {
  re.lastIndex = 0;
  return re.test(text);
}

/**
 * Audit one pwsh command for encoding-unsafe file writes. Comments are
 * stripped first; only quoted non-ASCII in a content position counts.
 * @param {string} command - the model's pwsh command text.
 * @returns {Array<{severity:'severe'|'moderate', kind:string, detail:string}>}
 */
export function analyzePwshEncoding(command) {
  if (typeof command !== 'string' || command.length === 0) return [];
  const findings = [];
  const stripped = command.replace(RE_PS_COMMENT, '');
  const writes =
    resetAndTest(RE_PS_WRITE_PRIMITIVES, stripped) ||
    resetAndTest(RE_PS_REDIRECT, stripped);
  if (!writes || !hasContentNonAscii(stripped)) return findings;
  if (resetAndTest(RE_PS_SAFE_ENCODING, stripped)) return findings; // 知情编码：不拦
  if (resetAndTest(RE_PS_UNSAFE_ENCODING, stripped)) {
    findings.push({ severity: 'severe', kind: 'pwsh-unsafe-encoding', detail: '写入命令使用了 ANSI/GBK/OEM/UTF-16 或固定代码页编码' });
  } else {
    findings.push({ severity: 'moderate', kind: 'pwsh-ambiguous-encoding', detail: '写入命令的字符串内容含非 ASCII 但未显式声明 -Encoding utf8（PS 5.1 默认 ANSI/UTF-16，可能批量乱码）' });
  }
  return findings;
}

// ─────────────────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────────────────

/** Preload the lazy iconv-lite import (fire at plugin apply time, not on the hot path). */
export function prewarmIconv() {
  return loadIconv();
}

/**
 * Detect mojibake in `text` using feature-based analysis.
 *
 * @param {string} text - the text to analyze.
 * @param {object} [opts]
 * @param {string} [opts.path=''] - target path; exempts code/JSON files from
 *   escape checks and HTML files from entity checks.
 * @param {'moderate'|'severe'} [opts.minSeverity='moderate'] - drop findings
 *   below this severity.
 * @param {number} [opts.maxFindings=8] - stop after this many findings.
 * @param {number} [opts.maxRunChars=2048] - per-segment round-trip cap.
 * @param {number} [opts.maxRuns=64] - per-direction segment cap.
 * @param {number} [opts.maxPreviewChars=80] - preview width in findings.
 * @param {boolean} [opts.inCommand=false] - text is a shell command: skip
 *   literal-escape / entity checks (code-flavoured syntax is legitimate there).
 * @param {string[]} [opts.excludeKinds=[]] - finding kinds to suppress
 *   (e.g. result monitoring drops 'ansi-escape', because coloured terminal
 *   output is normal there).
 * @returns {Promise<{findings: Array<{severity:'severe'|'moderate', kind:string, detail:string}>, score:number}>}
 */
export async function detectMojibake(text, opts = {}) {
  const {
    path = '',
    minSeverity = 'moderate',
    maxFindings = 8,
    maxRunChars = 2048,
    maxRuns = 64,
  } = opts;

  const findings = [];
  const excludeKinds = new Set(opts.excludeKinds ?? []);
  const push = (severity, kind, detail) => {
    if (excludeKinds.has(kind)) return;
    if (minSeverity === 'severe' && severity !== 'severe') return;
    if (findings.length >= maxFindings) return;
    findings.push({ severity, kind, detail: clip(detail, opts.maxPreviewChars ?? 80) });
  };
  const finish = () => ({
    findings,
    score: findings.reduce((s, f) => s + (f.severity === 'severe' ? 2 : 1), 0),
  });

  if (typeof text !== 'string' || text.length === 0) return finish();

  // Stage 0 — gate: pure ASCII, escape-free content can never be mojibake.
  RE_GATE.lastIndex = 0;
  if (!RE_GATE.test(text)) return finish();

  // Stage 1 — cheap global character statistics.
  analyzeCounts(text, push);
  if (findings.length >= maxFindings) return finish();

  // Stage 2 — Latin-segment round-trips (dependency-free).
  let runs = 0;
  RE_LATIN_SEGMENT.lastIndex = 0;
  let seg;
  while ((seg = RE_LATIN_SEGMENT.exec(text))) {
    if (++runs > maxRuns) break;
    analyzeLatinSegment(seg[0].slice(0, maxRunChars), push);
    if (findings.length >= maxFindings) return finish();
  }

  // Stage 3 — CJK-segment round-trips (GBK/Big5 via iconv-lite).
  if (findings.length < maxFindings && RE_CJK.test(text)) {
    let cjkRuns = 0;
    RE_NON_ASCII_SEGMENT.lastIndex = 0;
    let cseg;
    while ((cseg = RE_NON_ASCII_SEGMENT.exec(text))) {
      if (++cjkRuns > maxRuns) break;
      const value = cseg[0];
      if (!RE_CJK.test(value)) continue; // pure Latin handled in stage 2
      await analyzeCjkSegment(value, maxRunChars, push);
      if (findings.length >= maxFindings) return finish();
    }
  }

  // Stage 4 — structural escapes / entities (path-dependent). Command text
  // (pwsh/bash) legitimately contains `\uXXXX` inside regex literals, so the
  // code-flavoured checks are skipped under `inCommand`.
  if (findings.length < maxFindings && !opts.inCommand) {
    analyzeEscapes(text, path, push);
    analyzeEntities(text, path, push);
  }

  return finish();
}
