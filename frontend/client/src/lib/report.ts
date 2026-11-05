/**
 * Turns the API's scan results into what a report shows. Everything here comes
 * from what an engine recorded; nothing is estimated or filled in.
 */
import type { ApiAnalysis, ApiConsensus } from "@/lib/api-types";

export type Tone = "danger" | "warning" | "ok" | "muted";

/** The headline verdict. "Clean" would overclaim: engines can only fail to find something. */
export function verdictLabel(verdict?: string | null): { label: string; tone: Tone } {
  switch ((verdict ?? "").toLowerCase()) {
    case "malicious":
      return { label: "Malicious", tone: "danger" };
    case "suspicious":
      return { label: "Suspicious", tone: "warning" };
    case "clean":
    case "benign":
      return { label: "No threats found", tone: "ok" };
    default:
      return { label: "No verdict", tone: "muted" };
  }
}

export type EngineRole = "flagged" | "clear" | "no_record" | "advisory" | "unavailable" | "no_verdict";

/** How an engine took part in this scan's verdict. */
export function engineRole(a: ApiAnalysis): { role: EngineRole; label: string; tone: Tone } {
  const verdict = (a.verdict ?? "").toLowerCase();
  switch (a.vote) {
    case "no_record":
      return { role: "no_record", label: "No record", tone: "muted" };
    case "advisory":
      return { role: "advisory", label: "Advisory", tone: "muted" };
    case "unavailable":
      return { role: "unavailable", label: "Unavailable", tone: "warning" };
  }
  if (verdict === "malicious") return { role: "flagged", label: "Malicious", tone: "danger" };
  if (verdict === "suspicious") return { role: "flagged", label: "Suspicious", tone: "warning" };
  if (verdict === "clean" || verdict === "benign") return { role: "clear", label: "Nothing found", tone: "ok" };
  return { role: "no_verdict", label: "No verdict", tone: "muted" };
}

/** "Flagged by 1 of 3 voting engines". */
export function flaggedSummary(c?: ApiConsensus | null): string {
  if (!c) return "";
  const voting = c.totalVotes ?? 0;
  const flagged = c.flaggedVotes ?? (c.maliciousVotes ?? 0) + (c.suspiciousVotes ?? 0);
  if (voting === 0) return "No engine gave a verdict";
  if (flagged === 0) return `None of ${voting} voting ${voting === 1 ? "engine" : "engines"} flagged it`;
  return `Flagged by ${flagged} of ${voting} voting ${voting === 1 ? "engine" : "engines"}`;
}

/** The engine's reason when a curated-list match decided the verdict, else null. */
export function decidedBy(c?: ApiConsensus | null): string | null {
  const m = c?.explanation?.match(/^Known malicious: listed by [^.]+\./);
  return m ? m[0] : null;
}

/** "Not voting: no record (URLhaus, ThreatFox); unavailable (ClamAV)". */
export function notVotingSummary(c?: ApiConsensus | null): string | null {
  const list = c?.unavailableEngines ?? [];
  if (list.length === 0) return null;
  const groups: Array<[string, string]> = [
    ["no_record", "no record"],
    ["advisory", "advisory"],
    ["unavailable", "unavailable"],
  ];
  const parts = groups
    .map(([kind, label]) => {
      const names = list.filter((u) => (u.kind ?? "unavailable") === kind).map((u) => u.engineName);
      return names.length ? `${label} (${names.join(", ")})` : null;
    })
    .filter(Boolean);
  return `Not voting: ${parts.join("; ")}.`;
}

export interface Fact {
  label: string;
  value: string;
  tone?: Tone;
}

type Meta = Record<string, unknown>;

const str = (v: unknown): string | undefined =>
  typeof v === "string" && v.trim() ? v : typeof v === "number" ? String(v) : undefined;
const arr = (v: unknown): Meta[] =>
  Array.isArray(v) ? v.filter((x): x is Meta => !!x && typeof x === "object") : [];

/** The evidence an engine recorded, in words, for the facts it actually reports. */
export function engineFacts(a: ApiAnalysis): Fact[] {
  const m: Meta = a.metadata && typeof a.metadata === "object" ? a.metadata : {};
  const facts: Fact[] = [];
  const role = engineRole(a).role;

  if (a.reason && role !== "flagged" && role !== "clear") {
    facts.push({ label: "Why no vote", value: a.reason });
  }

  for (const l of arr(m.listings)) {
    const what = [str(l.malware), str(l.threat)?.replace(/_/g, " ")].filter(Boolean).join(", ");
    const status = str(l.status);
    const conf = str(l.feed_confidence);
    facts.push({
      label: `Listed (${str(l.matched) ?? "match"})`,
      value: [str(l.indicator), what && `(${what})`, status && `status ${status}`, conf && `feed confidence ${conf}%`]
        .filter(Boolean)
        .join(" "),
      tone: "danger",
    });
  }

  const family = str(m.malware_family);
  if (family && arr(m.listings).length === 0) facts.push({ label: "Malware family", value: family, tone: "danger" });

  for (const f of arr(m.findings)) {
    const sev = str(f.severity);
    facts.push({
      label: str(f.title) ?? "Finding",
      value: str(f.detail) ?? "",
      tone: sev === "critical" ? "danger" : sev === "high" ? "warning" : "muted",
    });
  }

  const tls = m.tls && typeof m.tls === "object" ? (m.tls as Meta) : undefined;
  if (tls) {
    const valid = tls.valid === true;
    const issuer = str(tls.issuer);
    const days = typeof tls.expires_in_days === "number" ? tls.expires_in_days : undefined;
    facts.push({
      label: "TLS certificate",
      value: valid
        ? [issuer && `issued by ${issuer}`, days !== undefined && `expires in ${days} days`].filter(Boolean).join(", ") ||
          "valid"
        : "not valid",
      tone: valid ? undefined : "warning",
    });
  }
  if (typeof m.redirects === "number") {
    facts.push({
      label: "Redirects",
      value: m.redirects === 0 ? "none" : `${m.redirects}, ending at ${str(m.final_url) ?? "unknown"}`,
    });
  }
  const title = str(m.page_title);
  if (title) facts.push({ label: "Page title", value: title });
  if (m.password_form === true) facts.push({ label: "Password form", value: "present on the page", tone: "warning" });

  const matches = arr(m.matches);
  if (matches.length > 0) {
    const names = matches.map((x) => str(x.rule_name) ?? str(x.rule) ?? str(x.name) ?? str(x.signature_name)).filter(Boolean);
    facts.push({ label: "Matched", value: names.slice(0, 8).join(", ") || `${matches.length} rules`, tone: "danger" });
  } else if (typeof m.match_count === "number" && typeof m.signatures_checked === "number") {
    facts.push({ label: "Signatures", value: `${m.match_count} of ${m.signatures_checked} matched` });
  }
  if (typeof m.bytes_scanned === "number") {
    facts.push({ label: "Scanned", value: formatBytes(m.bytes_scanned) });
  }

  const advisory = str(m.advisory_verdict);
  if (advisory) facts.push({ label: "Prediction (not counted)", value: advisory });

  return facts;
}

export function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

export function formatDuration(ms?: number | null): string | null {
  if (ms === undefined || ms === null || Number.isNaN(ms)) return null;
  return ms < 1000 ? `${Math.round(ms)} ms` : `${(ms / 1000).toFixed(1)} s`;
}

/** Engines that voted first (flagged before clear), then the rest. */
export function sortEngines(list: ApiAnalysis[]): ApiAnalysis[] {
  const order: Record<EngineRole, number> = {
    flagged: 0,
    clear: 1,
    advisory: 2,
    no_record: 3,
    unavailable: 4,
    no_verdict: 5,
  };
  return [...list].sort(
    (a, b) =>
      order[engineRole(a).role] - order[engineRole(b).role] ||
      (a.engine?.name ?? "").localeCompare(b.engine?.name ?? ""),
  );
}

export interface ReportInput {
  submissionId: string;
  target: string;
  targetType: string;
  sha256?: string;
  submittedAt?: string;
  consensus?: ApiConsensus | null;
  analyses: ApiAnalysis[];
}

/** A Markdown report with the same facts as the page. */
export function markdownReport(r: ReportInput, generatedAt = new Date()): string {
  const v = verdictLabel(r.consensus?.finalVerdict);
  const lines: string[] = [
    "# Verdyx scan report",
    "",
    `- **Target:** ${r.target}`,
    `- **Type:** ${r.targetType}`,
  ];
  if (r.sha256 && r.targetType !== "url") lines.push(`- **SHA-256:** ${r.sha256}`);
  if (r.submittedAt) lines.push(`- **Submitted:** ${new Date(r.submittedAt).toISOString()}`);
  lines.push(`- **Scan ID:** ${r.submissionId}`, `- **Report generated:** ${generatedAt.toISOString()}`, "");
  lines.push("## Verdict", "", `**${v.label}.** ${flaggedSummary(r.consensus)}.`, "");
  const decided = decidedBy(r.consensus);
  if (decided) lines.push(decided, "");
  const notVoting = notVotingSummary(r.consensus);
  if (notVoting) lines.push(notVoting, "");
  lines.push("## Engines", "", "| Engine | Result | Confidence | Evidence |", "|---|---|---|---|");
  for (const a of sortEngines(r.analyses)) {
    const role = engineRole(a);
    const evidence = engineFacts(a)
      .map((f) => (f.value ? `${f.label}: ${f.value}` : f.label))
      .join("; ")
      .replace(/\|/g, "\\|");
    const confidence = typeof a.confidence === "number" ? `${a.confidence}%` : "—";
    lines.push(`| ${a.engine?.name ?? "Engine"} | ${role.label} | ${confidence} | ${evidence || "—"} |`);
  }
  lines.push(
    "",
    "---",
    "",
    "Results are what each engine recorded. An engine with no record or an advisory role does not vote. " +
      "A match in a curated known-malware list (MalwareBazaar, URLhaus, ThreatFox) decides the verdict.",
    "",
  );
  return lines.join("\n");
}
