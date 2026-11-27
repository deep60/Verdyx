/**
 * The detection benchmark behind /benchmark. The data is written by
 * `backend/analysis-engine/benchmark/publish.py` from a real run on the
 * production engine image; nothing here is hand-entered.
 */

export interface Tally {
  total: number;
  /** Malicious or Suspicious. */
  flagged: number;
  /** Malicious only. */
  malicious: number;
  /** Unknown, an error, or the engine had nothing to say (YARA with no match). */
  noVerdict: number;
}

export interface EngineResult {
  name: string;
  malware: Tally;
  clean: Tally;
}

export interface GroupResult {
  /** File type for malware (pe, script, office…), software release for clean files. */
  name: string;
  consensus: Tally;
  engines: Record<string, Tally>;
}

export interface BenchmarkData {
  ranAt: string;
  /** Git commit the engine image was built from. */
  revision: string | null;
  image: string | null;
  clamav: boolean;
  /** The Windows program model (EMBER2024). Missing from runs before it was measured. */
  peModel?: boolean;
  /** Hash-reputation feeds (VirusTotal, MalwareBazaar). Off for a fair test. */
  feeds: boolean;
  seconds: number;
  set: { malicious: number; clean: number; families: number; skipped: number };
  consensus: { malware: Tally; clean: Tally };
  engines: EngineResult[];
  notMeasured: string[];
  byFileType: GroupResult[];
  bySource: GroupResult[];
  missedFamilies: string[];
  falsePositives: { file: string; engines: string[] }[];
}

export const REPO = "https://github.com/deep60/Verdyx";
export const BENCHMARK_DIR = `${REPO}/tree/main/backend/analysis-engine/benchmark`;
export const MANIFEST_URL = `${REPO}/blob/main/backend/analysis-engine/benchmark/manifest.json`;

/** "41.1%", with one decimal, or "–" when there's nothing to divide by. */
export function pct(n: number, total: number): string {
  if (!total) return "–";
  const v = (n / total) * 100;
  if (v > 0 && v < 0.1) return "<0.1%";
  return `${v.toFixed(1)}%`;
}

/** "81 of 197" */
export function ofTotal(n: number, total: number): string {
  return `${n.toLocaleString("en-US")} of ${total.toLocaleString("en-US")}`;
}

/** Display names for file-type groups. */
const FILE_TYPES: Record<string, string> = {
  pe: "Windows programs and DLLs",
  script: "Scripts",
  office: "Office documents",
  elf: "Linux programs",
  apk: "Android apps",
  lnk: "Windows shortcuts",
  pdf: "PDF",
};

export function fileTypeLabel(group: string): string {
  return FILE_TYPES[group] ?? group;
}

/** Display names for clean-software sources. */
export function sourceLabel(source: string): string {
  if (source === "system-usr-bin") return "Debian /usr/bin";
  return source
    .replace(/-(dist|portable|embed)(-[a-z0-9]+)*$/i, "")
    .replace(/-(w64|64-bit)$/i, "")
    .replace(/-(?=\d)/, " ");
}

/** "Verdyx Static Analyzer" → "Static", "Office Document Analyzer" → "Office", for tight table headers. */
export function shortEngine(name: string): string {
  return name.replace(/^Verdyx /, "").replace(/ (Document |App )?Analyzer$/, "");
}

/** "MassLogger (4)" → { name: "MassLogger", samples: 4 } */
export function parseFamily(entry: string): { name: string; samples: number } {
  const m = entry.match(/^(.*) \((\d+)\)$/);
  return m ? { name: m[1], samples: Number(m[2]) } : { name: entry, samples: 1 };
}

/** "26 November 2026" */
export function runDate(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleDateString("en-GB", { day: "numeric", month: "long", year: "numeric", timeZone: "UTC" });
}
