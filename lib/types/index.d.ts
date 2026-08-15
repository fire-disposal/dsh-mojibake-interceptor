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
  /** Tools whose write payloads are scanned. Default ['write','edit','str_replace_editor']. */
  tools?: string[];
  /** Tools whose results are scanned for garbled-output notices. Default ['pwsh','bash','bash_persistent','read']. */
  resultWatchTools?: string[];
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
