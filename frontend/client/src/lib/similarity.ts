/**
 * Similarity search: files close to a scanned file by fuzzy hash.
 * Shapes match `GET /api/v1/submissions/{id}/similar`.
 */

export type Closeness = "identical" | "very_similar" | "similar" | "related" | "same_imports";

export interface SimilarMatch {
  closeness: Closeness;
  tlshDistance: number | null;
  ssdeepScore: number | null;
  sameImphash: boolean;
}

export interface SimilarFile {
  submissionId: string;
  sha256: string | null;
  filename: string | null;
  fileSize: number | null;
  createdAt: string;
  verdict: string | null;
  reportUrl: string;
  match: SimilarMatch;
}

export interface SimilarResponse {
  submissionId: string;
  /** ready, pending (still scanning), not_a_file (a URL), unavailable (no hashes). */
  status: "ready" | "pending" | "not_a_file" | "unavailable";
  hashes: { tlsh: string | null; ssdeep: string | null; imphash: string | null } | null;
  similar: SimilarFile[];
  compared: number;
}

export const CLOSENESS_LABEL: Record<Closeness, string> = {
  identical: "Identical",
  very_similar: "Very similar",
  similar: "Similar",
  related: "Related",
  same_imports: "Same imports",
};

/** What the match rests on, in plain words, e.g. "TLSH distance 12 · ssdeep 88% · same imphash". */
export function matchEvidence(m: SimilarMatch): string {
  if (m.closeness === "identical") return "Same SHA-256";
  const parts: string[] = [];
  if (m.tlshDistance !== null && m.tlshDistance <= 100) parts.push(`TLSH distance ${m.tlshDistance}`);
  if (m.ssdeepScore !== null && m.ssdeepScore >= 40) parts.push(`ssdeep ${m.ssdeepScore}%`);
  if (m.sameImphash) parts.push("same imphash");
  return parts.join(" · ");
}

/** The panel's one-line summary. */
export function similarSummary(r: SimilarResponse): string {
  switch (r.status) {
    case "pending":
      return "Similar files appear once the scan finishes.";
    case "not_a_file":
      return "Similarity search works on files, not web pages.";
    case "unavailable":
      return "This file has no fuzzy hashes: it's too small, too uniform, or was scanned before similarity search existed and has since been deleted.";
  }
  const n = r.similar.length;
  const of = `${r.compared.toLocaleString()} ${r.compared === 1 ? "file" : "files"} you can see`;
  if (n === 0) return `Nothing similar among ${of}.`;
  return `${n} similar ${n === 1 ? "file" : "files"} among ${of}.`;
}
