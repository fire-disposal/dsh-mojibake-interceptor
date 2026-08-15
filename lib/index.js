/**
 * Mojibake interceptor — a DeepSeek Harness (Cordis) plugin.
 *
 * Hooks:
 *  - `tools/pre-execute`: before a `write` / `edit` / `str_replace_editor`
 *    mutation lands, the payload text is scanned with feature-based mojibake
 *    detection. A flagged write is denied with a review message; the model
 *    may fix the encoding or insist by re-issuing the identical write, which
 *    then passes (or, in `ask` mode, a human approves through the harness
 *    approval seam).
 *  - `tools/post-execute`: terminal / read results (`pwsh`, `bash`,
 *    `bash_persistent`, `read`) are scanned and a notice is injected when the
 *    captured output is itself garbled — the most common pollution vector on
 *    Windows (console codepage / pipe encoding mismatches), so the model is
 *    warned before it copies the garbage into a file.
 *
 * See the package README for the detection feature set, performance model,
 * and profile wiring.
 */

import z from '@deepseek-ai/schemastery';
import { detectMojibake, prewarmIconv, analyzePwshEncoding } from './detect.js';
import { createInterceptor, buildReason, KIND_LABELS } from './interceptor.js';

export const name = 'mojibake-interceptor';

/** Plugin configuration schema (validated by the harness loader). */
export const Config = z.object({
  /** warn = deny once, identical retry passes; block = always deny; ask = human approval each time. */
  mode: z.union([z.const('warn'), z.const('block'), z.const('ask')]).default('warn'),
  /** Tools whose write payloads / commands are scanned. */
  tools: z.array(z.string()).default(['write', 'edit', 'str_replace_editor', 'pwsh', 'bash', 'bash_persistent']),
  /** Tools whose results are scanned for garbled output notices. */
  resultWatchTools: z.array(z.string()).default(['pwsh', 'bash', 'bash_persistent', 'read']),
  /**
   * pwsh encoding audit: 'warn' = deny unsafe writes before execution (the
   * default); 'off' = only scan embedded content, skip encoding-declaration
   * auditing.
   */
  pwshEncodingGuard: z.union([z.const('warn'), z.const('off')]).default('warn'),
  /** Drop findings below this severity. */
  minSeverity: z.union([z.const('moderate'), z.const('severe')]).default('moderate'),
  /** Path `*`-patterns excluded from scanning. */
  excludePaths: z.array(z.string()).default([]),
  /** Stop analyzing after this many findings. */
  maxFindings: z.number().default(8),
  /** Per-segment round-trip character cap (bounds legacy-charset work). */
  maxRunChars: z.number().default(2048),
  /** Per-direction segment cap. */
  maxRuns: z.number().default(64),
  /** Preview width in the review message. */
  maxPreviewChars: z.number().default(80),
});

function failLoud(name_, value, guard, label) {
  if (!guard(value)) throw new Error(`mojibake-interceptor: invalid ${label} ${value} — ${name_}`);
}

/** Compile one `*`-wildcard pattern to an anchored RegExp (other metacharacters literal). */
function wildcardToRegExp(pattern) {
  const escaped = pattern.replace(/[|\\{}()[\]^$+?.]/g, String.raw`\$&`);
  return new RegExp(`^${escaped.replaceAll('*', '.*')}$`);
}

function getPath(args) {
  if (!args || typeof args !== 'object') return '';
  const p = args.file_path ?? args.path;
  return typeof p === 'string' ? p : '';
}

/** Shell tools whose `command` argument carries embedded file content. */
const SHELL_TOOLS = new Set(['pwsh', 'bash', 'bash_persistent']);

/** Extract the text a mutation is ABOUT TO WRITE (not text it matches against). */
function extractWriteText(toolName, args) {
  if (!args || typeof args !== 'object') return [];
  if (SHELL_TOOLS.has(toolName)) {
    // The whole command is scanned: content embedded inline (`Set-Content
    // -Value '…'`, `echo '…' > f`) is the pollution vector, and the pwsh
    // encoding audit runs on the same text.
    return typeof args.command === 'string' ? [args.command] : [];
  }
  switch (toolName) {
    case 'write':
      return typeof args.content === 'string' ? [args.content] : [];
    case 'edit':
      // Only the inserted text: `old_string` is existing file content and a
      // mojibake fix legitimately matches against garbled old text.
      return typeof args.new_string === 'string' ? [args.new_string] : [];
    case 'str_replace_editor': {
      const out = [];
      const cmds = Array.isArray(args.commands) ? args.commands : [];
      for (const c of cmds) {
        if (!c || typeof c !== 'object') continue;
        if (c.command === 'str_replace' || c.command === 'insert') {
          if (typeof c.new_str === 'string') out.push(c.new_str);
        } else if (c.command === 'create') {
          if (typeof c.content === 'string') out.push(c.content);
        }
      }
      return out;
    }
    default:
      return [];
  }
}

/** Extract plain text from a normalized tool result for output scanning. */
function extractResultText(result) {
  const blocks = result?.content;
  if (!Array.isArray(blocks)) return '';
  let out = '';
  for (const b of blocks) {
    if (b && typeof b === 'object' && b.type === 'text' && typeof b.text === 'string') out += `${b.text}\n`;
  }
  return out;
}

function pluginNotice(text, summary) {
  return {
    id: crypto.randomUUID(),
    role: 'user',
    content: [{ type: 'text', text }],
    source: { kind: 'plugin', plugin: 'mojibake-interceptor', form: 'notice', summary },
  };
}

/**
 * Install the mojibake interceptor.
 * @param ctx - plugin context; listeners are scoped to it and disposed with it.
 * @param config - validated configuration.
 */
export function apply(ctx, config) {
  const mode = config.mode;
  if (!['warn', 'block', 'ask'].includes(mode)) throw new Error(`mojibake-interceptor: invalid mode ${mode}`);
  failLoud('maxFindings', config.maxFindings, (v) => Number.isInteger(v) && v >= 1, 'maxFindings (integer >= 1)');
  failLoud('maxRunChars', config.maxRunChars, (v) => Number.isInteger(v) && v >= 64, 'maxRunChars (integer >= 64)');
  failLoud('maxRuns', config.maxRuns, (v) => Number.isInteger(v) && v >= 1, 'maxRuns (integer >= 1)');
  failLoud('maxPreviewChars', config.maxPreviewChars, (v) => Number.isInteger(v) && v >= 16, 'maxPreviewChars (integer >= 16)');

  const excludePatterns = config.excludePaths.map(wildcardToRegExp);
  const interceptor = createInterceptor(config);
  const detectOpts = {
    minSeverity: config.minSeverity,
    maxFindings: config.maxFindings,
    maxRunChars: config.maxRunChars,
    maxRuns: config.maxRuns,
    maxPreviewChars: config.maxPreviewChars,
  };

  // Kick the lazy iconv-lite import early so the first flagged call does not
  // pay the module-load cost inline.
  void prewarmIconv();

  ctx.on('tools/pre-execute', async (exec, next) => {
    if (!config.tools.includes(exec.name)) return next();
    const args = exec.arguments;
    const isShell = SHELL_TOOLS.has(exec.name);
    const path = getPath(args);
    if (!isShell && excludePatterns.some((r) => r.test(path))) return next();
    const displayPath = isShell ? `${exec.name} 命令` : path;

    for (const payload of extractWriteText(exec.name, args)) {
      if (payload.length === 0) continue;
      const { findings } = await detectMojibake(payload, { ...detectOpts, path, inCommand: isShell });
      // pwsh-specific: audit the command for unsafe write encodings BEFORE it
      // executes — the ANSI/UTF-16/Default tragedy that garbles whole files.
      if (isShell && exec.name === 'pwsh' && config.pwshEncodingGuard === 'warn') {
        for (const f of analyzePwshEncoding(payload)) {
          if (config.minSeverity === 'severe' && f.severity !== 'severe') continue;
          if (findings.length >= config.maxFindings) break;
          findings.push(f);
        }
      }
      if (findings.length === 0) continue;

      const decision = interceptor.decide({ name: exec.name, path: displayPath, text: payload, findings });
      if (decision.kind === 'allow') return next(); // 执意重试 → 放行

      const downstream = await next();
      if (downstream.kind !== 'allow') return downstream; // another gate already decided
      return decision.kind === 'ask'
        ? { kind: 'ask', reason: decision.reason }
        : { kind: 'deny', reason: decision.reason };
    }
    return next();
  });

  if (config.resultWatchTools.length > 0) {
    ctx.on('tools/post-execute', async (exec, result, next) => {
      const downstream = await next();
      if (!exec.agent) return downstream;
      if (!config.resultWatchTools.includes(exec.name)) return downstream;
      if (result?.isError) return downstream;
      // Read results carry their target path; honor excludePaths there too so
      // scanning the plugin's own docs (which contain mojibake samples) stays
      // silent.
      if (exec.name === 'read') {
        const readPath = getPath(exec.arguments);
        if (excludePatterns.some((r) => r.test(readPath))) return downstream;
      }
      const text = extractResultText(result);
      if (!text) return downstream;

      // Use the real target path for read results so code/JSON files keep
      // their literal-escape / entity exemptions; shell outputs have none.
      const scanPath = exec.name === 'read' ? getPath(exec.arguments) : `result:${exec.name}`;
      const { findings } = await detectMojibake(text, {
        ...detectOpts,
        path: scanPath,
        maxFindings: Math.min(detectOpts.maxFindings, 4),
        // Coloured terminal output is normal: drop the ANSI-escape signal
        // from result monitoring (write interception keeps it).
        excludeKinds: ['ansi-escape'],
      });
      if (findings.length === 0) return downstream;

      const lines = findings
        .slice(0, 3)
        .map((f) => {
          const label = KIND_LABELS[f.kind] ?? f.kind;
          const detail = f.detail && f.detail !== label ? `：${f.detail.slice(0, 60)}` : '';
          return `• ${label}${detail}`;
        })
        .join('\n');
      const notice = pluginNotice(
        `[乱码拦截器] ${exec.name} 的输出疑似乱码/编码错误（${findings.length} 处特征命中，常见于 Windows 控制台/管道编码不一致：chcp/GBK/UTF-16/ANSI 颜色码）。请勿把该输出直接复制进文件；先核实编码（例如重定向到文件后再按 UTF-8 读取）。\n${lines}`,
        `${exec.name} output may be mojibake (${findings.length})`,
      );
      return {
        ...downstream,
        additionalContexts: [notice, ...(downstream.additionalContexts ?? [])],
      };
    });
  }
}

export { buildReason };
