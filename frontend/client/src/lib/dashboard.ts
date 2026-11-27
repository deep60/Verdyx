import type { ApiEngine, ApiStats } from "@/lib/api-types";

/** How often the dashboard's stats and results refresh on their own. */
export const DASHBOARD_REFRESH_MS = 30_000;

export type AnalysisType = "quick" | "full" | "deep" | "behavioral";

/**
 * What each analysis type runs. Mirrors `analysis_options_for` in the
 * analysis engine: `engineTypes` are the `engineType` values from
 * /api/engines that vote in that mode, `extras` are steps with no engine row.
 */
export const ANALYSIS_TYPES: {
  value: AnalysisType;
  label: string;
  time: string;
  description: string;
  engineTypes: string[];
  extras: string[];
}[] = [
  {
    value: "quick",
    label: "Quick",
    time: "Seconds",
    description: "Reputation lookups, ClamAV, YARA and signatures. Archives and email attachments aren't opened.",
    engineTypes: ["hash", "clamav", "yara", "signature"],
    extras: [],
  },
  {
    value: "full",
    label: "Full",
    time: "Under a minute",
    description: "Every engine, plus the files inside archives and emails. The right choice for most files.",
    engineTypes: ["hash", "clamav", "yara", "signature", "static", "heuristic", "ml"],
    extras: ["Archive contents"],
  },
  {
    value: "deep",
    label: "Deep",
    time: "A few minutes",
    description: "Full, plus archives inside archives and up to 50 files per archive.",
    engineTypes: ["hash", "clamav", "yara", "signature", "static", "heuristic", "ml"],
    extras: ["Nested archives"],
  },
  {
    value: "behavioral",
    label: "Behavioral",
    time: "Up to 30 minutes",
    description: "Deep, plus VirusTotal's sandboxes run the file and report what it does.",
    engineTypes: ["hash", "clamav", "yara", "signature", "static", "heuristic", "ml"],
    extras: ["Nested archives", "VirusTotal sandbox"],
  },
];

/** What a URL scan checks. URL scans ignore the analysis type. */
export const URL_CHECKS = ["Redirect chain", "TLS and headers", "DNS and mail", "URLhaus", "ThreatFox", "VirusTotal", "Safe Browsing"];

export type InputKind = "url" | "email" | "hash";

/** Guess what someone pasted into the scan box. */
export function detectInput(text: string): InputKind | null {
  const t = text.trim();
  if (!t) return null;
  if (/^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$/i.test(t)) return "hash";
  // Raw messages start with headers; a URL never spans lines.
  if (/^(received|return-path|from|delivered-to|message-id|mime-version|subject|to|date):/im.test(t) && t.includes("\n")) {
    return "email";
  }
  if (/\s/.test(t)) return null;
  if (/^https?:\/\/[^\s/]+\.[^\s]+/i.test(t)) return "url";
  if (/^[a-z0-9-]+(\.[a-z0-9-]+)*\.[a-z]{2,}(\/\S*)?$/i.test(t)) return "url";
  return null;
}

/** Add a scheme when someone pastes a bare domain. */
export function normalizeUrl(text: string): string {
  const t = text.trim();
  return /^https?:\/\//i.test(t) ? t : `https://${t}`;
}

export type EngineState = "online" | "advisory" | "off";

export function engineState(e: ApiEngine): EngineState {
  const s = (e.status ?? "").toLowerCase();
  if (s === "online") return "online";
  if (s === "advisory") return "advisory";
  return "off";
}

export interface EngineSummary {
  online: number;
  advisory: number;
  off: number;
  total: number;
}

export function engineSummary(engines: ApiEngine[]): EngineSummary {
  const sum = { online: 0, advisory: 0, off: 0, total: engines.length };
  for (const e of engines) sum[engineState(e)] += 1;
  return sum;
}

/** The engines that vote in this mode, as listed by /api/engines. */
export function enginesFor(type: AnalysisType, engines: ApiEngine[]): ApiEngine[] {
  const wanted = ANALYSIS_TYPES.find((t) => t.value === type)?.engineTypes ?? [];
  return engines.filter((e) => wanted.includes((e.engineType ?? e.type ?? "").toLowerCase()));
}

export interface VerdictMix {
  malicious: number;
  suspicious: number;
  clean: number;
  total: number;
}

/** Platform-wide verdict counts; null until at least one scan has finished. */
export function verdictMix(stats: ApiStats | undefined): VerdictMix | null {
  if (!stats) return null;
  const malicious = Number(stats.maliciousCount ?? 0);
  const suspicious = Number(stats.suspiciousCount ?? 0);
  const clean = Number(stats.benignCount ?? 0);
  const total = malicious + suspicious + clean;
  return total > 0 ? { malicious, suspicious, clean, total } : null;
}

export function greeting(now = new Date()): string {
  const h = now.getHours();
  if (h < 5) return "Working late";
  if (h < 12) return "Good morning";
  if (h < 18) return "Good afternoon";
  return "Good evening";
}

export function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

export const DASHBOARD_TABS = ["overview", "recon", "yara", "compare", "analytics"] as const;
export type DashboardTab = (typeof DASHBOARD_TABS)[number];

/** Old tab names still sent by bookmarks and the command palette. */
const TAB_ALIASES: Record<string, DashboardTab> = {
  scanner: "overview",
  "web-intel": "recon",
  diff: "compare",
  pipeline: "overview",
};

export function toDashboardTab(value: string | null | undefined): DashboardTab {
  const v = (value ?? "").replace(/^#/, "");
  if ((DASHBOARD_TABS as readonly string[]).includes(v)) return v as DashboardTab;
  return TAB_ALIASES[v] ?? "overview";
}
