import { Link } from "wouter";
import { useQuery } from "@tanstack/react-query";
import { verdictLabel, type Tone } from "@/lib/report";
import { timeAgo } from "@/lib/live-hunts";
import { CLOSENESS_LABEL, matchEvidence, similarSummary, type SimilarResponse } from "@/lib/similarity";

const TONE_TEXT: Record<Tone, string> = {
  danger: "text-destructive",
  warning: "text-warning",
  ok: "text-success",
  muted: "text-muted-foreground",
};

/**
 * Files close to this one by fuzzy hash, among the uploads the viewer may
 * read. Catches repacked or recompiled variants that SHA-256 can't.
 */
export function SimilarFilesPanel({ submissionId, signedIn }: { submissionId: string; signedIn: boolean }) {
  const { data, isLoading, isError } = useQuery<SimilarResponse>({
    queryKey: [`/api/submissions/${submissionId}/similar`],
    enabled: signedIn,
    // Hashes are stored while the scan runs; check again until they are.
    refetchInterval: (q) => (q.state.data?.status === "pending" ? 5000 : false),
  });

  if (!signedIn) {
    return (
      <p className="border border-border p-6 text-sm text-muted-foreground" data-testid="similar-signed-out">
        <Link href="/login" className="text-primary hover:underline">
          Sign in
        </Link>{" "}
        to find files similar to this one among your uploads, your teams' and bounty scans.
      </p>
    );
  }
  if (isLoading) return <p className="p-6 text-sm text-muted-foreground">Comparing fuzzy hashes…</p>;
  if (isError || !data) {
    return <p className="border border-border p-6 text-sm text-destructive">Couldn't load similar files.</p>;
  }

  return (
    <div className="space-y-4 border border-border p-6" data-testid="similar-files">
      <p className="text-sm text-muted-foreground">{similarSummary(data)}</p>
      {data.similar.length > 0 && (
        <ul className="divide-y divide-border border-y border-border" data-testid="similar-results">
          {data.similar.map((f) => {
            const v = verdictLabel(f.verdict);
            return (
              <li key={f.submissionId} className="flex flex-wrap items-center justify-between gap-x-4 gap-y-1 py-3 text-sm">
                <div className="min-w-0 flex-1">
                  <Link href={`/analysis/${f.submissionId}`} className="block truncate font-mono text-foreground hover:underline">
                    {f.filename || f.sha256 || f.submissionId}
                  </Link>
                  <p className="text-xs text-muted-foreground">
                    {matchEvidence(f.match)} · {timeAgo(f.createdAt)}
                  </p>
                </div>
                <span className="font-mono text-[11px] uppercase tracking-[0.08em] text-foreground">
                  {CLOSENESS_LABEL[f.match.closeness]}
                </span>
                <span className={`w-36 text-right text-xs ${TONE_TEXT[v.tone]}`}>{v.label}</span>
              </li>
            );
          })}
        </ul>
      )}
      {data.hashes && (
        <dl className="grid gap-x-6 gap-y-2 text-xs sm:grid-cols-3">
          {(
            [
              ["TLSH", data.hashes.tlsh],
              ["ssdeep", data.hashes.ssdeep],
              ["imphash", data.hashes.imphash],
            ] as const
          ).map(([label, value]) => (
            <div key={label} className="min-w-0">
              <dt className="text-muted-foreground">{label}</dt>
              <dd className="break-all font-mono text-foreground">{value || "—"}</dd>
            </div>
          ))}
        </dl>
      )}
      <p className="text-xs text-muted-foreground">
        Only uploads you can open are searched: yours, your teams' and scans posted with a bounty.
      </p>
    </div>
  );
}
