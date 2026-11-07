import { useEffect, useMemo, useState } from "react";
import { useRoute } from "wouter";
import { useQuery, useMutation } from "@tanstack/react-query";
import { Navigation } from "@/components/navigation";
import { SEO } from "@/components/seo";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ExportReport } from "@/components/export-report";
import { CommitRevealPanel } from "@/components/commit-reveal-panel";
import { WebsiteIntelligencePanel } from "@/components/website-intelligence-panel";
import { EmailForensicsPanel } from "@/components/email-forensics-panel";
import { AttackMatrix } from "@/components/attack-matrix";
import { IocGraph } from "@/components/ioc-graph";
import { mapAttackTechniques } from "@/lib/attack-mapping";
import { useWebSocket } from "@/hooks/use-websocket";
import { apiRequest } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import { Copy, Loader2, Play } from "lucide-react";
import { StatCardSkeleton, SubmissionSkeleton } from "@/components/loading-skeleton";
import { ErrorState } from "@/components/error-state";
import type { ApiSubmission, ApiAnalysis, ApiConsensus } from "@/lib/api-types";
import {
  decidedBy,
  engineFacts,
  engineRole,
  notVotingSummary,
  flaggedSummary,
  formatBytes,
  formatDuration,
  sortEngines,
  verdictLabel,
  type Tone,
} from "@/lib/report";

const TONE_TEXT: Record<Tone, string> = {
  danger: "text-destructive",
  warning: "text-warning",
  ok: "text-success",
  muted: "text-muted-foreground",
};

const TONE_BADGE: Record<Tone, string> = {
  danger: "border-destructive/50 bg-destructive/10 text-destructive",
  warning: "border-warning/50 bg-warning/10 text-warning",
  ok: "border-success/50 bg-success/10 text-success",
  muted: "border-border text-muted-foreground",
};

const TONE_BAR: Record<Tone, string> = {
  danger: "bg-destructive",
  warning: "bg-warning",
  ok: "bg-success",
  muted: "bg-muted-foreground/40",
};

function RoleBadge({ label, tone }: { label: string; tone: Tone }) {
  return (
    <span
      className={`inline-flex shrink-0 items-center border px-2 py-0.5 font-mono text-[11px] uppercase tracking-[0.08em] ${TONE_BADGE[tone]}`}
    >
      {label}
    </span>
  );
}

function formatTime(iso?: string) {
  if (!iso) return null;
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? null : d.toLocaleString();
}

function EngineRow({ analysis }: { analysis: ApiAnalysis }) {
  const role = engineRole(analysis);
  const facts = engineFacts(analysis);
  const time = formatDuration(analysis.processingTimeMs);
  return (
    <li className="py-4" data-testid="engine-row">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
        <span className="font-medium text-foreground">{analysis.engine?.name ?? "Engine"}</span>
        {analysis.engine?.version && (
          <span className="font-mono text-xs text-muted-foreground">{analysis.engine.version}</span>
        )}
        <span className="ml-auto flex items-center gap-3">
          {typeof analysis.confidence === "number" && (
            <span className="font-mono text-xs text-muted-foreground">{analysis.confidence}% confidence</span>
          )}
          {time && <span className="font-mono text-xs text-muted-foreground">{time}</span>}
          <RoleBadge label={role.label} tone={role.tone} />
        </span>
      </div>
      {facts.length > 0 && (
        <dl className="mt-2 grid gap-x-4 gap-y-1 text-sm sm:grid-cols-[minmax(0,10rem)_minmax(0,1fr)]">
          {facts.map((f, i) => (
            <div key={i} className="contents">
              <dt className="text-muted-foreground">{f.label}</dt>
              <dd className={`break-words ${f.tone ? TONE_TEXT[f.tone] : "text-foreground/90"}`}>{f.value || "—"}</dd>
            </div>
          ))}
        </dl>
      )}
    </li>
  );
}

export default function AnalysisDetails() {
  const [, params] = useRoute("/analysis/:id");
  const submissionId = params?.id;
  const { toast } = useToast();
  const [, setHideAnalystTally] = useState(false);

  const {
    data: submission,
    isLoading: submissionLoading,
    isError: submissionError,
    refetch: refetchSubmission,
  } = useQuery<ApiSubmission>({
    queryKey: [`/api/submissions/${submissionId}`],
    enabled: !!submissionId,
    refetchInterval: (query) => {
      const st = query.state.data?.status || query.state.data?.analysisStatus;
      return st === "pending" || st === "analyzing" ? 3000 : false;
    },
  });

  const currentStatus = submission?.status || submission?.analysisStatus || "pending";
  const inProgress = currentStatus === "pending" || currentStatus === "analyzing";

  const {
    data: analyses = [],
    isLoading: analysesLoading,
    isError: analysesError,
    refetch: refetchAnalyses,
  } = useQuery<ApiAnalysis[]>({
    queryKey: [`/api/submissions/${submissionId}/analyses`],
    enabled: !!submissionId,
    refetchInterval: inProgress ? 3000 : false,
  });

  const { data: consensus, refetch: refetchConsensus } = useQuery<ApiConsensus>({
    queryKey: [`/api/submissions/${submissionId}/consensus`],
    enabled: !!submissionId && (currentStatus === "completed" || analyses.length > 0),
  });

  const startAnalysisMutation = useMutation({
    mutationFn: async () => {
      const res = await apiRequest("POST", `/api/submissions/${submissionId}/start-analysis`, {});
      return res.json();
    },
    onSuccess: () => {
      toast({ title: "Scan started", description: "The engines will report here as they finish." });
      refetchSubmission();
      refetchAnalyses();
    },
    onError: (err) => {
      toast({
        title: "Couldn't start the scan",
        description: err instanceof Error ? err.message : "Please try again",
        variant: "destructive",
      });
    },
  });

  const { lastMessage } = useWebSocket();
  useEffect(() => {
    if (!lastMessage || !submissionId) return;
    try {
      const data = JSON.parse(lastMessage.data);
      if (
        data.type === "analysis_updated" ||
        (data.type === "analysis_completed" && data.data?.submissionId === submissionId)
      ) {
        refetchSubmission();
        refetchAnalyses();
        refetchConsensus();
      }
    } catch {
      // Ignore non-JSON frames
    }
  }, [lastMessage, submissionId, refetchSubmission, refetchAnalyses, refetchConsensus]);

  const target =
    submission?.url ||
    submission?.originalFilename ||
    submission?.filename ||
    submission?.fileName ||
    submission?.id ||
    "";
  const isUrlTarget = Boolean(
    submission && (submission.submissionType === "url" || target.startsWith("http://") || target.startsWith("https://")),
  );
  const isEmailTarget = Boolean(
    submission &&
      (submission.submissionType === "email" ||
        target.toLowerCase().endsWith(".eml") ||
        analyses.some((a) => (a.engine?.name || "").toLowerCase().includes("email"))),
  );
  const targetType = isUrlTarget ? "url" : isEmailTarget ? "email" : "file";

  const { data: recentSubmissions = [] } = useQuery<ApiSubmission[]>({
    queryKey: ["/api/submissions"],
    enabled: Boolean(submission),
  });
  const { data: pageIntel } = useQuery<Record<string, unknown>>({
    queryKey: [`/api/submissions/${submissionId}/web-intel`],
    enabled: Boolean(submissionId) && isUrlTarget,
  });

  const attackTechniques = useMemo(() => mapAttackTechniques(analyses), [analyses]);
  const engines = useMemo(() => sortEngines(analyses), [analyses]);
  const finishedAt = useMemo(() => {
    const times = analyses.map((a) => a.completedAt).filter((t): t is string => Boolean(t));
    return times.sort().at(-1);
  }, [analyses]);

  if (submissionError || analysesError) {
    return (
      <div className="min-h-screen bg-background text-foreground">
        <SEO title="Scan not found" description="This scan couldn't be loaded." />
        <Navigation />
        <div className="mx-auto max-w-5xl px-4 py-12 sm:px-6 lg:px-8">
          <ErrorState
            title="Scan not found"
            message="It doesn't exist, or it belongs to another account. Sign in with the account that ran it."
            onRetry={() => {
              refetchSubmission();
              refetchAnalyses();
            }}
          />
        </div>
      </div>
    );
  }

  if (submissionLoading || !submission) {
    return (
      <div className="min-h-screen bg-background text-foreground">
        <SEO title="Loading scan" description="Loading scan results." />
        <Navigation />
        <div className="mx-auto max-w-5xl px-4 py-12 sm:px-6 lg:px-8">
          <div className="mb-8 grid gap-6 md:grid-cols-3">
            {[1, 2, 3].map((i) => (
              <StatCardSkeleton key={i} />
            ))}
          </div>
          {[1, 2, 3].map((i) => (
            <SubmissionSkeleton key={i} />
          ))}
        </div>
      </div>
    );
  }

  const verdict = verdictLabel(consensus?.finalVerdict);
  const submitted = formatTime(submission.createdAt);
  const finished = formatTime(finishedAt);

  const copyId = () => {
    navigator.clipboard?.writeText(submission.id).then(
      () => toast({ title: "Scan ID copied" }),
      () => undefined,
    );
  };

  return (
    <div className="min-h-screen bg-background text-foreground">
      <SEO title={`Scan: ${target}`} description="Verdyx scan results: verdict, per-engine evidence and checks." />
      <Navigation />

      <main id="main-content" tabIndex={-1} className="mx-auto max-w-5xl px-4 py-10 sm:px-6 sm:py-12 lg:px-8">
        {/* Header */}
        <header className="mb-8 flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
          <div className="min-w-0 flex-1">
            <div className="mb-2 font-mono text-[11px] uppercase tracking-[0.12em] text-muted-foreground">
              {targetType === "url" ? "URL scan" : targetType === "email" ? "Email scan" : "File scan"}
            </div>
            <h1 className="break-all font-mono text-xl font-medium text-foreground sm:text-2xl">{target}</h1>
            <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-sm text-muted-foreground">
              {submitted && <span>Submitted {submitted}</span>}
              <button
                type="button"
                onClick={copyId}
                className="inline-flex items-center gap-1.5 font-mono text-xs hover:text-foreground"
                title="Copy scan ID"
              >
                {submission.id}
                <Copy className="h-3 w-3" aria-hidden />
              </button>
            </div>
          </div>
          <div className="flex items-center gap-3">
            {currentStatus === "pending" && (
              <Button
                onClick={() => startAnalysisMutation.mutate()}
                disabled={startAnalysisMutation.isPending}
                data-testid="button-trigger-analysis"
              >
                <Play className="mr-2 h-4 w-4" />
                {startAnalysisMutation.isPending ? "Starting…" : "Run scan"}
              </Button>
            )}
            <ExportReport
              submissionId={submission.id}
              target={target}
              targetType={targetType}
              submittedAt={submission.createdAt}
              consensus={consensus}
              analyses={analyses}
              attackTechniques={attackTechniques}
              sha256={targetType === "url" ? undefined : submission.fileHash}
              targetUrl={isUrlTarget ? target : undefined}
            />
          </div>
        </header>

        {/* Verdict */}
        {inProgress ? (
          <section className="mb-8 flex items-center gap-3 border border-border bg-card/50 p-6" aria-live="polite">
            <Loader2 className="h-5 w-5 animate-spin text-muted-foreground" aria-hidden />
            <div>
              <div className="font-medium text-foreground">
                {currentStatus === "pending" ? "Queued" : "Scanning"}
              </div>
              <p className="text-sm text-muted-foreground">
                {analyses.length > 0
                  ? `${analyses.length} ${analyses.length === 1 ? "engine has" : "engines have"} reported so far.`
                  : "Engines report here as they finish. This usually takes under a minute."}
              </p>
            </div>
          </section>
        ) : currentStatus === "failed" ? (
          <section className="mb-8 border border-destructive/40 bg-destructive/10 p-6">
            <div className="font-medium text-destructive">The scan failed</div>
            <p className="mt-1 text-sm text-muted-foreground">
              {isUrlTarget
                ? "The page couldn't be fetched or analysed. Check the address is public and reachable, then scan it again."
                : "The file couldn't be analysed. Try uploading it again."}
            </p>
            {submission?.failureReason && (
              <p className="mt-2 text-sm text-muted-foreground">
                Reason: <span className="text-foreground">{submission.failureReason}</span>
              </p>
            )}
          </section>
        ) : (
          consensus && (
            <section className="mb-8 border border-border bg-card/50" aria-labelledby="verdict-heading">
              <div className="flex">
                <div className={`w-1 shrink-0 ${TONE_BAR[verdict.tone]}`} aria-hidden />
                <div className="grid flex-1 gap-6 p-6 sm:p-8 md:grid-cols-[minmax(0,3fr)_minmax(0,2fr)]">
                  <div>
                    <div className="font-mono text-[11px] uppercase tracking-[0.12em] text-muted-foreground">
                      Verdict
                    </div>
                    <h2
                      id="verdict-heading"
                      className={`mt-1 text-3xl font-medium tracking-[-0.03em] sm:text-4xl ${TONE_TEXT[verdict.tone]}`}
                      data-testid="text-verdict"
                    >
                      {verdict.label}
                    </h2>
                    <p className="mt-2 text-foreground/90">{flaggedSummary(consensus)}.</p>
                    {decidedBy(consensus) && (
                      <p className="mt-2 text-sm text-destructive">
                        {decidedBy(consensus)} A match in a curated malware list decides the verdict.
                      </p>
                    )}
                    {notVotingSummary(consensus) && (
                      <p className="mt-2 text-sm text-muted-foreground">{notVotingSummary(consensus)}</p>
                    )}
                  </div>
                  <dl className="divide-y divide-border self-start border-y border-border text-sm">
                    {[
                      ["Engines run", consensus.engineCount ?? analyses.length],
                      ["Voted", consensus.totalVotes ?? 0],
                      ["Malicious", consensus.maliciousVotes ?? 0],
                      ["Suspicious", consensus.suspiciousVotes ?? 0],
                      ["Found nothing", consensus.cleanVotes ?? 0],
                    ].map(([label, value]) => (
                      <div key={label} className="flex justify-between gap-4 py-2">
                        <dt className="text-muted-foreground">{label}</dt>
                        <dd className="font-mono text-foreground">{value}</dd>
                      </div>
                    ))}
                    {finished && (
                      <div className="flex justify-between gap-4 py-2">
                        <dt className="text-muted-foreground">Finished</dt>
                        <dd className="text-right font-mono text-xs text-foreground">{finished}</dd>
                      </div>
                    )}
                  </dl>
                </div>
              </div>
            </section>
          )
        )}

        {/* Engines */}
        <section className="mb-10" aria-labelledby="engines-heading">
          <div className="mb-2 flex flex-col gap-1 sm:flex-row sm:items-baseline sm:justify-between sm:gap-4">
            <h2 id="engines-heading" className="text-lg font-medium text-foreground">
              Engines
            </h2>
            <span className="text-xs text-muted-foreground">
              Only engines that vote decide the verdict. No record and advisory engines are shown for reference.
            </span>
          </div>
          {analysesLoading ? (
            [1, 2, 3].map((i) => <SubmissionSkeleton key={i} />)
          ) : engines.length === 0 ? (
            <div className="border border-border p-6 text-sm text-muted-foreground">
              {inProgress ? "Waiting for the first engine to report." : "No engine results were recorded for this scan."}
            </div>
          ) : (
            <ul className="divide-y divide-border border-y border-border">
              {engines.map((a) => (
                <EngineRow key={a.id} analysis={a} />
              ))}
            </ul>
          )}
        </section>

        {/* Further detail */}
        <Tabs
          defaultValue={isUrlTarget ? "web-intel" : isEmailTarget ? "email-forensics" : "details"}
          className="space-y-6"
        >
          <TabsList className="flex h-auto flex-wrap">
            {isUrlTarget && <TabsTrigger value="web-intel">Website checks</TabsTrigger>}
            {isEmailTarget && (
              <TabsTrigger value="email-forensics" data-testid="tab-email-forensics">
                Email forensics
              </TabsTrigger>
            )}
            {!isUrlTarget && <TabsTrigger value="attack">ATT&amp;CK ({attackTechniques.length})</TabsTrigger>}
            <TabsTrigger value="infrastructure">Infrastructure</TabsTrigger>
            <TabsTrigger value="details">Details</TabsTrigger>
          </TabsList>

          {isUrlTarget && (
            <TabsContent value="web-intel">
              <WebsiteIntelligencePanel submissionId={submission.id} initialUrl={target} />
            </TabsContent>
          )}
          {isEmailTarget && (
            <TabsContent value="email-forensics">
              <EmailForensicsPanel analyses={analyses} />
            </TabsContent>
          )}
          {!isUrlTarget && (
            <TabsContent value="attack">
              <AttackMatrix techniques={attackTechniques} />
            </TabsContent>
          )}
          <TabsContent value="infrastructure">
            <IocGraph submission={submission} analyses={analyses} webIntel={pageIntel} submissions={recentSubmissions} />
          </TabsContent>
          <TabsContent value="details">
            <dl className="grid gap-x-6 gap-y-4 border border-border p-6 text-sm sm:grid-cols-2">
              {(
                [
                  [isUrlTarget ? "URL" : "File name", target],
                  ["Type", targetType],
                  !isUrlTarget && ["SHA-256", submission.fileHash],
                  !isUrlTarget && submission.fileSize ? ["Size", formatBytes(submission.fileSize)] : null,
                  !isUrlTarget && ["MIME type", submission.mimeType],
                  ["Submitted", submitted],
                  ["Finished", finished],
                  ["Scan ID", submission.id],
                  submission.description ? ["Note", submission.description] : null,
                ].filter(Boolean) as Array<[string, string | null | undefined]>
              ).map(([label, value]) => (
                <div key={label}>
                  <dt className="text-muted-foreground">{label}</dt>
                  <dd className="mt-0.5 break-all font-mono text-foreground">{value || "—"}</dd>
                </div>
              ))}
            </dl>
          </TabsContent>
        </Tabs>

        {/* Analyst review exists only for scans posted with a bounty. */}
        {submission.bountyId && consensus && (
          <section className="mt-10 border border-border bg-card/50 p-6" aria-labelledby="review-heading">
            <h2 id="review-heading" className="mb-4 text-lg font-medium text-foreground">
              Analyst review
            </h2>
            <CommitRevealPanel
              bountyId={submission.bountyId}
              submissionId={submission.id}
              currentVerdict={consensus.finalVerdict}
              onCommitPhase={setHideAnalystTally}
            />
          </section>
        )}
      </main>
    </div>
  );
}
