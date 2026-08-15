/**
 * Mojibake detection engine types.
 * @module dsh-mojibake-interceptor/detect
 */

export interface MojibakeFinding {
  /** 'severe' findings are near-certain encoding corruption; 'moderate' warrant review. */
  severity: 'severe' | 'moderate';
  /** Stable machine kind, e.g. 'utf8-as-cp1252-cjk' | 'utf8-as-gbk' | 'utf16-leak'. */
  kind: string;
  /** Human-readable detail, preview-capped. */
  detail: string;
}

export interface MojibakeResult {
  findings: MojibakeFinding[];
  /** Weighted sum: severe = 2, moderate = 1. */
  score: number;
}

export interface DetectOptions {
  /** Target path; exempts code/JSON from escape checks and HTML from entity checks. */
  path?: string;
  /** Drop findings below this severity. Default 'moderate'. */
  minSeverity?: 'moderate' | 'severe';
  /** Stop after this many findings. Default 8. */
  maxFindings?: number;
  /** Per-segment round-trip character cap. Default 2048. */
  maxRunChars?: number;
  /** Per-direction segment cap. Default 64. */
  maxRuns?: number;
  /** Preview width in findings. Default 80. */
  maxPreviewChars?: number;
}

export declare function detectMojibake(text: string, opts?: DetectOptions): Promise<MojibakeResult>;

/** Preload the lazy iconv-lite import. */
export declare function prewarmIconv(): Promise<unknown>;
