import type { ApiSubmission } from "@/lib/api-types";

/** What a scan found, as the profile shows it. */
export type ScanOutcome = "malicious" | "suspicious" | "clean" | "unknown" | "running" | "failed";

export function scanOutcome(s: ApiSubmission): ScanOutcome {
  const status = (s.analysisStatus || s.status || "pending").toLowerCase();
  if (status === "failed") return "failed";
  if (status !== "completed") return "running";
  switch ((s.verdict ?? "").toLowerCase()) {
    case "malicious":
      return "malicious";
    case "suspicious":
      return "suspicious";
    case "benign":
    case "clean":
      return "clean";
    case "unknown":
      return "unknown";
  }
  // Scans stored before the list carried the verdict.
  if (s.isMalicious === true) return "malicious";
  if (s.isMalicious === false) return "clean";
  return "unknown";
}

export const OUTCOME_LABEL: Record<ScanOutcome, string> = {
  malicious: "Malicious",
  suspicious: "Suspicious",
  clean: "No threats",
  unknown: "No verdict",
  running: "Scanning",
  failed: "Failed",
};

/** Worst first, for the activity grid and the "latest catch". */
const SEVERITY: Record<ScanOutcome, number> = {
  malicious: 4,
  suspicious: 3,
  clean: 2,
  unknown: 1,
  running: 1,
  failed: 0,
};

export function isThreat(o: ScanOutcome): boolean {
  return o === "malicious" || o === "suspicious";
}

export type ScanKind = "file" | "url" | "email";

export function scanKind(s: ApiSubmission): ScanKind {
  const t = (s.submissionType ?? "").toLowerCase();
  if (t === "url") return "url";
  if (t === "email") return "email";
  return "file";
}

export function scanName(s: ApiSubmission): string {
  const name = s.originalFilename || s.filename || s.fileName || s.url || s.id;
  // A URL reads better without its scheme in a list.
  return scanKind(s) === "url" ? name.replace(/^https?:\/\//i, "") : name;
}

export interface ScanCounts {
  total: number;
  malicious: number;
  suspicious: number;
  clean: number;
  thisWeek: number;
}

export function scanCounts(list: ApiSubmission[], now = new Date()): ScanCounts {
  const weekAgo = now.getTime() - 7 * 86_400_000;
  const c: ScanCounts = { total: list.length, malicious: 0, suspicious: 0, clean: 0, thisWeek: 0 };
  for (const s of list) {
    const o = scanOutcome(s);
    if (o === "malicious") c.malicious++;
    else if (o === "suspicious") c.suspicious++;
    else if (o === "clean") c.clean++;
    const t = new Date(s.createdAt ?? "").getTime();
    if (Number.isFinite(t) && t >= weekAgo) c.thisWeek++;
  }
  return c;
}

export interface ActivityDay {
  /** YYYY-MM-DD, local time. */
  date: string;
  scans: number;
  /** The worst outcome that day, or null with no scans. */
  worst: ScanOutcome | null;
}

function dayKey(d: Date): string {
  const m = String(d.getMonth() + 1).padStart(2, "0");
  const day = String(d.getDate()).padStart(2, "0");
  return `${d.getFullYear()}-${m}-${day}`;
}

/** One entry per day for the last `days` days, oldest first. */
export function activityDays(list: ApiSubmission[], days = 84, now = new Date()): ActivityDay[] {
  const byDay = new Map<string, ActivityDay>();
  const out: ActivityDay[] = [];
  for (let i = days - 1; i >= 0; i--) {
    const d = new Date(now.getFullYear(), now.getMonth(), now.getDate() - i);
    const entry = { date: dayKey(d), scans: 0, worst: null };
    byDay.set(entry.date, entry);
    out.push(entry);
  }
  for (const s of list) {
    const t = new Date(s.createdAt ?? "");
    if (Number.isNaN(t.getTime())) continue;
    const entry = byDay.get(dayKey(t));
    if (!entry) continue;
    entry.scans++;
    const o = scanOutcome(s);
    if (entry.worst === null || SEVERITY[o] > SEVERITY[entry.worst]) entry.worst = o;
  }
  return out;
}

/** Days in a row, ending today or yesterday, with at least one scan. */
export function currentStreak(days: ActivityDay[]): number {
  let i = days.length - 1;
  if (i >= 0 && days[i].scans === 0) i--; // today may not have a scan yet
  let streak = 0;
  for (; i >= 0 && days[i].scans > 0; i--) streak++;
  return streak;
}

/** The most recent scan that found a threat. */
export function latestCatch(list: ApiSubmission[]): ApiSubmission | undefined {
  return [...list]
    .filter((s) => isThreat(scanOutcome(s)))
    .sort((a, b) => new Date(b.createdAt ?? 0).getTime() - new Date(a.createdAt ?? 0).getTime())[0];
}

/** "arjunp2989@proton.me" → "ar•••@proton.me", safe to show on a shared screen. */
export function maskEmail(email: string): string {
  const at = email.indexOf("@");
  if (at < 1) return email;
  return `${email.slice(0, Math.min(2, at))}•••${email.slice(at)}`;
}

export function shortAddress(address: string): string {
  return address.length > 12 ? `${address.slice(0, 6)}…${address.slice(-4)}` : address;
}

export interface Standing {
  rank?: number;
  userId?: string;
  score?: number;
  accuracyRate?: string | number | null;
  totalEarned?: string | number | null;
}

/** The user's place on the leaderboard, or null when they aren't on it. */
export function findStanding(
  analysts: Standing[] | undefined,
  userId: string,
): { rank: number; of: number; standing: Standing } | null {
  const list = analysts ?? [];
  const i = list.findIndex((a) => a.userId === userId);
  if (i < 0) return null;
  return { rank: Number(list[i].rank ?? i + 1), of: list.length, standing: list[i] };
}

/** "12.5" or 12.5 → "12.5"; anything else → null. */
export function amount(v: string | number | null | undefined): number | null {
  if (v === null || v === undefined || v === "") return null;
  const n = typeof v === "number" ? v : Number(v);
  return Number.isFinite(n) ? n : null;
}
