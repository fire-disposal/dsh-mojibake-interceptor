/**
 * Interceptor state machine types.
 * @module dsh-mojibake-interceptor/interceptor
 */

import type { MojibakeFinding } from './detect.js';

export type InterceptorMode = 'warn' | 'block' | 'ask';

export type InterceptorDecision =
  | { kind: 'allow' }
  | { kind: 'deny'; reason: string }
  | { kind: 'ask'; reason: string };

export interface InterceptorConfig {
  mode?: InterceptorMode;
  maxPreviewChars?: number;
}

export interface DecideInput {
  name: string;
  path: string;
  text: string;
  findings: MojibakeFinding[];
}

export interface MojibakeInterceptor {
  decide(input: DecideInput): InterceptorDecision;
}

export declare const KIND_LABELS: Readonly<Record<string, string>>;

export declare function buildReason(path: string, findings: MojibakeFinding[], maxPreviewChars?: number): string;

export declare function createInterceptor(config: InterceptorConfig): MojibakeInterceptor;
