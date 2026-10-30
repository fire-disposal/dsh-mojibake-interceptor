import { createHash } from 'node:crypto';

/**
 * Interceptor state machine for the mojibake guard.
 *
 * `warn` mode (default) implements the review-then-release flow:
 *   1. first sighting of a flagged write → deny with a review message;
 *   2. the model reviews and either fixes the text (different payload →
 *      freshly evaluated) or insists and re-issues the IDENTICAL write
 *      (same tool + path + payload) → allowed through.
 * `block` mode always denies flagged writes; `ask` mode routes every flagged
 * write through the harness approval seam (a human decides).
 */

export const KIND_LABELS = {
  'utf8-as-cp1252-cjk': 'UTF-8 被按 CP1252/拉丁1 误读（中文回环还原）',
  'utf8-as-cp1252': 'UTF-8 被按 CP1252/拉丁1 误读',
  'gbk-as-cp1252': 'GBK 被按 CP1252/拉丁1 误读',
  'utf8-as-gbk': 'UTF-8 被按 GBK 误读',
  'utf8-as-big5': 'UTF-8 被按 Big5 误读',
  'replacement-char': 'U+FFFD 替换符密集（无效 UTF-8 字节被替换）',
  'lone-replacement': '含替换符 U+FFFD',
  'utf16-leak': 'UTF-16 字节被当作文本（NUL 分隔）',
  'control-char': '含控制字符',
  'ansi-escape': 'ANSI 转义序列（彩色控制台输出残留）',
  'bom-anomaly': '文本中部含 BOM 字符',
  'literal-unicode-escape': '以 \\uXXXX 字面转义代替实际字符',
  'html-numeric-entity': '以 HTML 数字实体代替实际字符',
  'gbk-misread-replacement': 'GBK 误读的替换符序列',
  'pwsh-unsafe-encoding': 'pwsh 写入命令使用了危险编码（ANSI/GBK/OEM/UTF-16/固定代码页）',
  'pwsh-ambiguous-encoding': 'pwsh 写入命令含非 ASCII 内容但未声明 -Encoding utf8',
};

function clip(s, n) {
  return s.length <= n ? s : `${s.slice(0, n)}…`;
}

/** Build the model-facing review message carried by a deny/ask decision. */
export function buildReason(path, findings, maxPreviewChars = 80) {
  const top = findings.slice(0, 6);
  const lines = top.map((f) => {
    const label = KIND_LABELS[f.kind] ?? f.kind;
    const detail = f.detail ? `：${clip(f.detail, maxPreviewChars)}` : '';
    return `• [${f.severity === 'severe' ? '严重' : '中等'}] ${label}${detail}`;
  });
  const more = findings.length > top.length ? `\n… 另有 ${findings.length - top.length} 处特征` : '';
  return (
    `[乱码拦截器] 已拦截写入 "${path}"：内容疑似乱码/编码错误（${findings.length} 处特征命中）。` +
    `\n${lines.join('\n')}${more}\n` +
    `请复查文本编码后重试。若你已核实该内容确为有意保留的原文，请原样重试同一次写入，拦截器将放行。`
  );
}

/** Cap on remembered warned entries; evicts everything past it to bound memory. */
const WARNED_CAP = 4096;

/**
 * @param {object} config
 * @param {'warn'|'block'|'ask'} [config.mode='warn']
 * @param {number} [config.maxPreviewChars=80]
 */
export function createInterceptor(config) {
  const mode = config.mode ?? 'warn';
  const maxPreviewChars = config.maxPreviewChars ?? 80;
  const warned = new Map(); // `${tool}\u0000${path}\u0000${sha256(payload)}` → true

  return {
    /**
     * Decide what to do with one flagged write.
     * @param {{name: string, path: string, text: string, findings: Array}} input
     * @returns {{kind: 'allow'}|{kind: 'deny', reason: string}|{kind: 'ask', reason: string}}
     */
    decide({ name, path, text, findings }) {
      if (mode === 'block') {
        return { kind: 'deny', reason: buildReason(path, findings, maxPreviewChars) };
      }
      if (mode === 'ask') {
        return { kind: 'ask', reason: buildReason(path, findings, maxPreviewChars) };
      }
      const digest = createHash('sha256').update(text).digest('base64url');
      const key = `${name}\u0000${path}\u0000${digest}`;
      if (!warned.has(key)) {
        warned.set(key, true);
        if (warned.size > WARNED_CAP) warned.delete(warned.keys().next().value);
        return { kind: 'deny', reason: buildReason(path, findings, maxPreviewChars) };
      }
      return { kind: 'allow' }; // 执意重试同一次写入 → 放行
    },
  };
}
