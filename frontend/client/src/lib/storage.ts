// Cloud storage scanning for teams: types and helpers for the team's Storage
// tab. The server checks every setting; these decide what to show.

export type StorageProvider = "aws" | "r2" | "gcs" | "other";
export type StorageAnalysis = "quick" | "full" | "deep";

export interface StorageConnection {
  id: string;
  name: string;
  provider: StorageProvider;
  endpoint: string | null;
  region: string;
  bucket: string;
  prefix: string;
  accessKeyId: string;
  analysisType: StorageAnalysis;
  intervalMinutes: number;
  maxObjectMb: number;
  enabled: boolean;
  scanSince: string;
  scanRequested: boolean;
  running: boolean;
  lastRunAt: string | null;
  lastError: string | null;
  lastScanned: number;
  createdAt: string;
  stats: { files: number; flagged: number; waiting: number };
}

export interface StorageList {
  connections: StorageConnection[];
  limit: number;
  maxObjectMb: number;
}

export interface StorageObject {
  key: string;
  size: number;
  lastModified: string | null;
  status: "queued" | "too_large" | "failed";
  error: string | null;
  seenAt: string;
  submissionId: string | null;
  analysisStatus: string | null;
  verdict: string | null;
}

export interface ProviderInfo {
  value: StorageProvider;
  label: string;
  /** Whether the team types an endpoint. */
  needsEndpoint: boolean;
  endpointHint: string;
  /** Whether the team types a region. */
  needsRegion: boolean;
  regionHint: string;
  keyHint: string;
}

export const PROVIDERS: ProviderInfo[] = [
  {
    value: "aws",
    label: "Amazon S3",
    needsEndpoint: false,
    endpointHint: "",
    needsRegion: true,
    regionHint: "us-east-1",
    keyHint: "An IAM user's access key, allowed s3:ListBucket and s3:GetObject on this bucket.",
  },
  {
    value: "r2",
    label: "Cloudflare R2",
    needsEndpoint: true,
    endpointHint: "https://<account id>.r2.cloudflarestorage.com",
    needsRegion: false,
    regionHint: "auto",
    keyHint: "An R2 API token with Object Read only, for this bucket.",
  },
  {
    value: "gcs",
    label: "Google Cloud Storage",
    needsEndpoint: false,
    endpointHint: "https://storage.googleapis.com",
    needsRegion: false,
    regionHint: "auto",
    keyHint: "An HMAC key for a service account with Storage Object Viewer on this bucket.",
  },
  {
    value: "other",
    label: "Other S3-compatible",
    needsEndpoint: true,
    endpointHint: "https://s3.eu-central-003.backblazeb2.com",
    needsRegion: true,
    regionHint: "us-east-1",
    keyHint: "A read-only key for this bucket (MinIO, Backblaze B2, Wasabi, DigitalOcean Spaces…).",
  },
];

export const providerInfo = (p: StorageProvider): ProviderInfo =>
  PROVIDERS.find((x) => x.value === p) ?? PROVIDERS[PROVIDERS.length - 1];

export const INTERVALS: { value: number; label: string }[] = [
  { value: 15, label: "Every 15 minutes" },
  { value: 60, label: "Every hour" },
  { value: 180, label: "Every 3 hours" },
  { value: 360, label: "Every 6 hours" },
  { value: 1440, label: "Once a day" },
];

export const intervalLabel = (minutes: number): string =>
  INTERVALS.find((i) => i.value === minutes)?.label ?? `Every ${minutes} minutes`;

/** Where the connection reads from, as people would write it. */
export function locationOf(c: Pick<StorageConnection, "provider" | "bucket" | "prefix">): string {
  const scheme = c.provider === "gcs" ? "gs" : c.provider === "r2" ? "r2" : "s3";
  return `${scheme}://${c.bucket}/${c.prefix}`;
}

export type Tone = "danger" | "warning" | "ok" | "muted";

/** One line on how a connection is doing. */
export function connectionStatus(c: StorageConnection, now = Date.now()): { text: string; tone: Tone } {
  if (!c.enabled) return { text: "Off", tone: "muted" };
  if (c.lastError) return { text: `Last run failed: ${c.lastError}`, tone: "danger" };
  if (c.running) return { text: "Looking for new files…", tone: "muted" };
  if (c.scanRequested || !c.lastRunAt) return { text: "Looks for files within a minute", tone: "muted" };
  const mins = Math.max(0, Math.round((now - Date.parse(c.lastRunAt)) / 60000));
  const ago = mins < 1 ? "just now" : mins < 60 ? `${mins} min ago` : `${Math.round(mins / 60)} h ago`;
  const found = c.lastScanned === 0 ? "no new files" : `${c.lastScanned} new ${c.lastScanned === 1 ? "file" : "files"}`;
  return { text: `Checked ${ago}: ${found}`, tone: "ok" };
}

/** What happened to one file. */
export function objectStatus(o: StorageObject): { text: string; tone: Tone } {
  if (o.status === "too_large") return { text: "Not scanned: over the size limit", tone: "muted" };
  if (o.status === "failed") return { text: `Couldn't download: ${o.error ?? "unknown error"}`, tone: "warning" };
  if (o.analysisStatus === "failed") return { text: "Scan failed", tone: "warning" };
  if (o.analysisStatus !== "completed") return { text: "Scanning…", tone: "muted" };
  switch (o.verdict) {
    case "malicious":
      return { text: "Malicious", tone: "danger" };
    case "suspicious":
      return { text: "Suspicious", tone: "warning" };
    case "benign":
    case "clean":
      return { text: "Clean", tone: "ok" };
    default:
      return { text: "No verdict", tone: "muted" };
  }
}

export interface ConnectionForm {
  name: string;
  provider: StorageProvider;
  endpoint: string;
  region: string;
  bucket: string;
  prefix: string;
  accessKeyId: string;
  secretAccessKey: string;
  analysisType: StorageAnalysis;
  intervalMinutes: number;
  maxObjectMb: number;
  scanExisting: boolean;
}

export const emptyForm = (maxObjectMb = 32): ConnectionForm => ({
  name: "",
  provider: "aws",
  endpoint: "",
  region: "",
  bucket: "",
  prefix: "",
  accessKeyId: "",
  secretAccessKey: "",
  analysisType: "full",
  intervalMinutes: 60,
  maxObjectMb: Math.min(32, maxObjectMb),
  scanExisting: false,
});

/** What's missing before the form can be sent, or "" when it's complete. */
export function formProblem(f: ConnectionForm): string {
  const p = providerInfo(f.provider);
  if (!f.name.trim()) return "Give the connection a name.";
  if (p.needsEndpoint && !f.endpoint.trim()) return "Enter the endpoint.";
  if (p.needsEndpoint && /^http:\/\//i.test(f.endpoint.trim())) return "The endpoint must use https.";
  if (f.provider === "aws" && !f.region.trim()) return "Enter the bucket's region.";
  if (!f.bucket.trim()) return "Enter the bucket's name.";
  if (!f.accessKeyId.trim() || !f.secretAccessKey.trim()) return "Enter the access key ID and secret access key.";
  return "";
}

/** The request body for a new connection: only what the provider uses. */
export function createBody(f: ConnectionForm): Record<string, unknown> {
  const p = providerInfo(f.provider);
  return {
    name: f.name.trim(),
    provider: f.provider,
    endpoint: p.needsEndpoint ? f.endpoint.trim() : undefined,
    region: p.needsRegion && f.region.trim() ? f.region.trim() : undefined,
    bucket: f.bucket.trim(),
    prefix: f.prefix.trim(),
    accessKeyId: f.accessKeyId.trim(),
    secretAccessKey: f.secretAccessKey.trim(),
    analysisType: f.analysisType,
    intervalMinutes: f.intervalMinutes,
    maxObjectMb: f.maxObjectMb,
    scanExisting: f.scanExisting,
  };
}
