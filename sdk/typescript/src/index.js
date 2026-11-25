// Verdyx API client for Node.js 18+. No dependencies.
// Types live in index.d.ts.

import { readFile } from "node:fs/promises";
import { basename } from "node:path";

export const DEFAULT_API_URL = "https://api.verdyx.dev";
export const DEFAULT_WEB_URL = "https://verdyx.dev";

/** Statuses after which a scan won't change any more. */
const FINISHED = new Set(["completed", "failed"]);

/** Verdict severity, for comparing against a threshold. */
const RANK = { clean: 0, unknown: 0, suspicious: 1, malicious: 2 };

export class VerdyxError extends Error {
  /**
   * @param {string} message
   * @param {{ status?: number, body?: unknown, retryAfter?: number }} [info]
   */
  constructor(message, info = {}) {
    super(message);
    this.name = "VerdyxError";
    this.status = info.status;
    this.body = info.body;
    this.retryAfter = info.retryAfter;
  }
}

export class ScanTimeoutError extends VerdyxError {
  /** @param {string} submissionId @param {number} seconds */
  constructor(submissionId, seconds) {
    super(`scan ${submissionId} did not finish within ${seconds}s`);
    this.name = "ScanTimeoutError";
    this.submissionId = submissionId;
  }
}

/**
 * True when `verdict` is at least as bad as `threshold`
 * ("malicious", "suspicious" or "never").
 * @param {string} verdict
 * @param {string} threshold
 */
export function meetsThreshold(verdict, threshold) {
  if (threshold === "never" || threshold === "none") return false;
  const t = RANK[threshold];
  if (t === undefined) throw new VerdyxError(`unknown threshold "${threshold}"`);
  return (RANK[verdict] ?? 0) >= t;
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export class Verdyx {
  /** @param {import("./index").VerdyxOptions} [options] */
  constructor(options = {}) {
    const env = typeof process !== "undefined" ? process.env : {};
    this.apiKey = options.apiKey ?? env.VERDYX_API_KEY ?? undefined;
    this.apiUrl = (options.apiUrl ?? env.VERDYX_API_URL ?? DEFAULT_API_URL).replace(/\/+$/, "");
    this.webUrl = (options.webUrl ?? env.VERDYX_WEB_URL ?? DEFAULT_WEB_URL).replace(/\/+$/, "");
    this.fetch = options.fetch ?? globalThis.fetch;
    this.userAgent = options.userAgent ?? "verdyx-js/0.1.0";
    this.maxRetries = options.maxRetries ?? 3;
    if (typeof this.fetch !== "function") {
      throw new VerdyxError("no fetch available; use Node.js 18+ or pass options.fetch");
    }
  }

  /** The website link for a scan. @param {string} id */
  reportUrl(id) {
    return `${this.webUrl}/analysis/${encodeURIComponent(id)}`;
  }

  /**
   * @param {string} method
   * @param {string} path
   * @param {{ body?: BodyInit, json?: unknown, retry?: boolean }} [opts]
   */
  async request(method, path, opts = {}) {
    const headers = { Accept: "application/json" };
    if (this.apiKey) headers["X-API-Key"] = this.apiKey;
    // Browsers refuse to set User-Agent; Node sends it.
    if (typeof window === "undefined") headers["User-Agent"] = this.userAgent;
    let body = opts.body;
    if (opts.json !== undefined) {
      headers["Content-Type"] = "application/json";
      body = JSON.stringify(opts.json);
    }
    const url = `${this.apiUrl}/api/v1${path}`;
    for (let attempt = 0; ; attempt++) {
      let res;
      try {
        res = await this.fetch(url, { method, headers, body });
      } catch (e) {
        if (attempt < this.maxRetries && opts.retry !== false) {
          await sleep(backoff(attempt));
          continue;
        }
        throw new VerdyxError(`could not reach ${this.apiUrl}: ${e?.message ?? e}`);
      }
      const text = await res.text();
      let data = text;
      try {
        data = text ? JSON.parse(text) : null;
      } catch {
        // Leave non-JSON bodies as text.
      }
      if (res.ok) return data;

      const retryAfter = Number(res.headers.get("retry-after")) || undefined;
      const retryable = res.status === 429 || res.status === 502 || res.status === 503 || res.status === 504;
      if (retryable && attempt < this.maxRetries && opts.retry !== false) {
        await sleep(retryAfter ? Math.min(retryAfter, 60) * 1000 : backoff(attempt));
        continue;
      }
      throw new VerdyxError(errorMessage(res.status, data), { status: res.status, body: data, retryAfter });
    }
  }

  /**
   * Upload a file for scanning. Accepts a path (Node), or bytes with a name.
   * @param {string | Blob | Uint8Array | ArrayBuffer} file
   * @param {import("./index").SubmitOptions} [options]
   */
  async submitFile(file, options = {}) {
    let blob;
    let name = options.filename;
    if (typeof file === "string") {
      let bytes;
      try {
        bytes = await readFile(file);
      } catch (e) {
        const why = e?.code === "ENOENT" ? "file not found" : e?.code === "EISDIR" ? "is a directory, not a file" : e?.message;
        throw new VerdyxError(`${file}: ${why}`);
      }
      blob = new Blob([bytes]);
      name ??= basename(file);
    } else if (file instanceof Blob) {
      blob = file;
      name ??= /** @type {any} */ (file).name;
    } else {
      blob = new Blob([file]);
    }
    if (blob.size === 0) throw new VerdyxError("the file is empty");
    const form = new FormData();
    form.append("file", blob, name ?? "upload.bin");
    addCommon(form, options);
    return normaliseSubmission(await this.request("POST", "/submissions/file", { body: form, retry: false }));
  }

  /**
   * Submit a URL for scanning.
   * @param {string} url
   * @param {import("./index").SubmitOptions} [options]
   */
  async submitUrl(url, options = {}) {
    if (!/^https?:\/\//i.test(url)) throw new VerdyxError(`not an http(s) URL: ${url}`);
    const form = new FormData();
    form.append("url", url);
    addCommon(form, options);
    return normaliseSubmission(await this.request("POST", "/submissions/file", { body: form, retry: false }));
  }

  /** @param {string} id */
  async getSubmission(id) {
    return this.request("GET", `/submissions/${encodeURIComponent(id)}`);
  }

  /** @param {string} id */
  async getConsensus(id) {
    return this.request("GET", `/submissions/${encodeURIComponent(id)}/consensus`);
  }

  /** @param {string} id */
  async getAnalyses(id) {
    const data = await this.request("GET", `/submissions/${encodeURIComponent(id)}/analyses`);
    return Array.isArray(data) ? data : (data?.analyses ?? data?.data ?? []);
  }

  /** The engines and whether each is online. */
  async listEngines() {
    const data = await this.request("GET", "/engines");
    return Array.isArray(data) ? data : (data?.engines ?? data?.data ?? []);
  }

  /**
   * Wait for a scan to finish, then return its verdict and engine results.
   * @param {string} id
   * @param {import("./index").WaitOptions} [options]
   */
  async waitForResult(id, options = {}) {
    const timeout = options.timeoutSeconds ?? 300;
    const deadline = Date.now() + timeout * 1000;
    let delay = options.pollIntervalSeconds ? options.pollIntervalSeconds * 1000 : 2000;
    for (;;) {
      const submission = await this.getSubmission(id);
      const status = submission?.analysisStatus ?? submission?.status ?? "pending";
      options.onStatus?.(status);
      if (FINISHED.has(status)) return this.result(id, submission);
      if (Date.now() + delay > deadline) throw new ScanTimeoutError(id, timeout);
      await sleep(delay);
      if (!options.pollIntervalSeconds) delay = Math.min(delay * 1.5, 10000);
    }
  }

  /**
   * Build the result for a finished scan.
   * @param {string} id
   * @param {any} [submission]
   * @returns {Promise<import("./index").ScanResult>}
   */
  async result(id, submission) {
    submission ??= await this.getSubmission(id);
    const status = submission?.analysisStatus ?? submission?.status ?? "pending";
    const [consensus, analyses] =
      status === "completed"
        ? await Promise.all([this.getConsensus(id), this.getAnalyses(id)])
        : [null, []];
    const verdict = status === "completed" ? normaliseVerdict(consensus?.finalVerdict) : "unknown";
    return {
      id,
      status,
      verdict,
      target: submission?.url ?? submission?.originalFilename ?? submission?.filename ?? null,
      sha256: submission?.fileHash ?? null,
      failureReason: submission?.failureReason ?? null,
      explanation: consensus?.explanation ?? null,
      votes: {
        malicious: consensus?.maliciousVotes ?? 0,
        suspicious: consensus?.suspiciousVotes ?? 0,
        clean: consensus?.cleanVotes ?? 0,
        total: consensus?.totalVotes ?? 0,
      },
      engines: analyses.map(engineResult),
      reportUrl: this.reportUrl(id),
      submission,
      consensus,
    };
  }

  /**
   * Submit a file path or URL and wait for the verdict.
   * @param {string} target
   * @param {import("./index").SubmitOptions & import("./index").WaitOptions} [options]
   */
  async scan(target, options = {}) {
    const sub = /^https?:\/\//i.test(target)
      ? await this.submitUrl(target, options)
      : await this.submitFile(target, options);
    return this.waitForResult(sub.id, options);
  }
}

function addCommon(form, options) {
  if (options.description) form.append("description", options.description);
  if (options.teamId) form.append("organizationId", options.teamId);
  if (options.priority) form.append("priority", "true");
}

function normaliseSubmission(raw) {
  if (!raw || typeof raw !== "object" || !raw.id) {
    throw new VerdyxError("unexpected response from the submit endpoint", { body: raw });
  }
  return {
    id: String(raw.id),
    status: raw.analysis_status ?? raw.analysisStatus ?? "pending",
    sha256: raw.file_hash ?? raw.fileHash ?? null,
    filename: raw.original_filename ?? raw.originalFilename ?? null,
    type: raw.submission_type ?? raw.submissionType ?? null,
  };
}

/** The API says "benign" in some places and "clean" in others. */
function normaliseVerdict(v) {
  const s = String(v ?? "unknown").toLowerCase();
  if (s === "benign") return "clean";
  return s in RANK ? s : "unknown";
}

function engineResult(a) {
  // The API sends "unknown" for an engine that ran but didn't vote.
  const verdict = a?.verdict ? normaliseVerdict(a.verdict) : "unknown";
  const probability = a?.metadata?.probability;
  return {
    name: a?.engine?.name ?? a?.engineName ?? "engine",
    type: a?.engine?.type ?? a?.engineType ?? null,
    verdict: verdict === "unknown" ? null : verdict,
    confidence: a?.confidence ?? null,
    malwareChance: typeof probability === "number" ? Math.round(probability * 100) : null,
    vote: a?.vote ?? null,
    reason: a?.reason ?? null,
  };
}

function errorMessage(status, data) {
  const detail =
    (data && typeof data === "object" && (data.message || data.error || data.detail)) ||
    (typeof data === "string" && data.length < 300 ? data : "");
  const hint =
    status === 401
      ? "the API key is missing, revoked or expired"
      : status === 403
        ? "the API key isn't allowed to do this"
        : status === 404
          ? "not found, or not visible to this API key"
          : status === 413
            ? "the file is larger than the 100 MB limit"
            : status === 429
              ? "rate limited"
              : "";
  return [`HTTP ${status}`, detail || hint].filter(Boolean).join(": ");
}

function backoff(attempt) {
  return Math.min(1000 * 2 ** attempt, 15000) + Math.floor(Math.random() * 250);
}
