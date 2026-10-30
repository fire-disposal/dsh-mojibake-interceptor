/**
 * Mojibake interceptor — DeepSeek Harness plugin.
 * @module dsh-mojibake-interceptor
 */

import type { Context } from '@deepseek-ai/cordis';
import '@deepseek-ai/dsh-tools';
import type { DetectOptions } from './detect.js';

export declare const name = 'mojibake-interceptor';

export interface Config {
  /** warn = deny once, identical retry passes; block = always deny; ask = human approval. Default 'warn'. */
  mode?: 'warn' | 'block' | 'ask';
  /** Tools whose write payloads are scanned. Defaults to write/edit/str_replace_editor/apply_patch and shell input tools. */
  tools?: string[];
  /** Tools whose results are scanned for garbled-output notices. Defaults to shell, terminal, job output, and read tools. */
  resultWatchTools?: string[];
  /** Audit unsafe PowerShell file-write encoding declarations. Default 'warn'. */
  pwshEncodingGuard?: 'warn' | 'off';
  minSeverity?: 'moderate' | 'severe';
  excludePaths?: string[];
  maxFindings?: number;
  maxRunChars?: number;
  maxRuns?: number;
  maxPreviewChars?: number;
}

export declare const Config: import('@deepseek-ai/schemastery').default<Config>;

export declare function apply(ctx: Context, config: Config & DetectOptions): void;

export { buildReason } from './interceptor.js';
export { detectMojibake, type MojibakeFinding, type MojibakeResult } from './detect.js';
