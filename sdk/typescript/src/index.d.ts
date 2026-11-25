export declare const DEFAULT_API_URL: string;
export declare const DEFAULT_WEB_URL: string;

/** The overall verdict for a scan. */
export type Verdict = "malicious" | "suspicious" | "clean" | "unknown";

/** A scan's progress. `completed` and `failed` are final. */
export type ScanStatus = "pending" | "queued" | "analyzing" | "processing" | "completed" | "failed" | (string & {});

export interface VerdyxOptions {
  /** An API key (`vdx_…`). Defaults to the VERDYX_API_KEY environment variable. */
  apiKey?: string;
  /** Defaults to VERDYX_API_URL, then https://api.verdyx.dev. */
  apiUrl?: string;
  /** Where report links point. Defaults to VERDYX_WEB_URL, then https://verdyx.dev. */
  webUrl?: string;
  /** A fetch implementation, for tests or custom agents. */
  fetch?: typeof fetch;
  userAgent?: string;
  /** Retries for network errors, 429 and 502–504. Default 3. */
  maxRetries?: number;
}

export interface SubmitOptions {
  /** The name to upload a file under. Defaults to the path's base name. */
  filename?: string;
  description?: string;
  /** Save the scan to this team (organization id). */
  teamId?: string;
  priority?: boolean;
}

export interface WaitOptions {
  /** Give up after this many seconds. Default 300. */
  timeoutSeconds?: number;
  /** Fixed polling interval. By default it starts at 2 s and backs off to 10 s. */
  pollIntervalSeconds?: number;
  /** Called with each status seen while waiting. */
  onStatus?: (status: ScanStatus) => void;
}

export interface Submission {
  id: string;
  status: ScanStatus;
  sha256: string | null;
  filename: string | null;
  type: string | null;
}

export interface EngineResult {
  name: string;
  type: string | null;
  /** null when the engine gave no verdict. */
  verdict: Verdict | null;
  /** Percent: how sure the engine is of the verdict it gave. */
  confidence: number | null;
  /**
   * Percent: a model's calibrated chance that the file is malware (the
   * Windows Program Model). A model can say clean at 64% when its line for
   * suspicious is higher; its confidence in "clean" is then 36%.
   */
  malwareChance: number | null;
  /** "counted", "no_record", "advisory" or "unavailable". */
  vote: string | null;
  /** Why it didn't vote, when it didn't. */
  reason: string | null;
}

export interface ScanResult {
  id: string;
  status: ScanStatus;
  verdict: Verdict;
  /** The file name or URL that was scanned. */
  target: string | null;
  sha256: string | null;
  failureReason: string | null;
  explanation: string | null;
  votes: { malicious: number; suspicious: number; clean: number; total: number };
  engines: EngineResult[];
  reportUrl: string;
  /** The raw API objects, for fields not mapped above. */
  submission: Record<string, unknown>;
  consensus: Record<string, unknown> | null;
}

export declare class VerdyxError extends Error {
  /** The HTTP status, when the API answered. */
  status?: number;
  body?: unknown;
  /** Seconds, from a Retry-After header. */
  retryAfter?: number;
  constructor(message: string, info?: { status?: number; body?: unknown; retryAfter?: number });
}

export declare class ScanTimeoutError extends VerdyxError {
  submissionId: string;
  constructor(submissionId: string, seconds: number);
}

/** True when `verdict` is at least as bad as `threshold`. */
export declare function meetsThreshold(
  verdict: Verdict | string,
  threshold: "malicious" | "suspicious" | "never" | (string & {}),
): boolean;

export declare class Verdyx {
  readonly apiUrl: string;
  readonly webUrl: string;
  constructor(options?: VerdyxOptions);
  reportUrl(id: string): string;
  request<T = unknown>(method: string, path: string, opts?: { body?: BodyInit; json?: unknown; retry?: boolean }): Promise<T>;
  /** Upload a file: a path, or bytes with `options.filename`. */
  submitFile(file: string | Blob | Uint8Array | ArrayBuffer, options?: SubmitOptions): Promise<Submission>;
  submitUrl(url: string, options?: SubmitOptions): Promise<Submission>;
  getSubmission(id: string): Promise<Record<string, unknown>>;
  getConsensus(id: string): Promise<Record<string, unknown>>;
  getAnalyses(id: string): Promise<Record<string, unknown>[]>;
  listEngines(): Promise<Array<{ name: string; status?: string; description?: string | null } & Record<string, unknown>>>;
  /** Poll until the scan finishes. Throws ScanTimeoutError on timeout. */
  waitForResult(id: string, options?: WaitOptions): Promise<ScanResult>;
  /** The result of a scan as it stands now. */
  result(id: string, submission?: Record<string, unknown>): Promise<ScanResult>;
  /** Submit a file path or http(s) URL, then wait for the verdict. */
  scan(target: string, options?: SubmitOptions & WaitOptions): Promise<ScanResult>;
}
