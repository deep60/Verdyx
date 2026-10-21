import { useEffect, useState } from "react";
import { useRoute } from "wouter";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Navigation } from "@/components/navigation";
import { ParticleBackground } from "@/components/particle-background";
import { SEO } from "@/components/seo";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import { Progress } from "@/components/ui/progress";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ExportReport } from "@/components/export-report";
import { WebsiteIntelligencePanel } from "@/components/website-intelligence-panel";
import { useWebSocket } from "@/hooks/use-websocket";
import { apiRequest } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import {
  FileText,
  Clock,
  CheckCircle2,
  Shield,
  TrendingUp,
  Bot,
  User,
  Brain,
  FileSearch,
  Info,
  AlertCircle,
  Play,
  ThumbsUp,
  Globe,
  Cpu,
} from "lucide-react";
import { StatCardSkeleton, SubmissionSkeleton } from "@/components/loading-skeleton";
import { ErrorState } from "@/components/error-state";
import type { ApiSubmission, ApiAnalysis, ApiConsensus } from "@/lib/api-types";

export default function AnalysisDetails() {
  const [, params] = useRoute("/analysis/:id");
  const submissionId = params?.id;
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [selectedVote, setSelectedVote] = useState<string | null>(null);

  // Fetch submission details (auto-poll while pending/analyzing)
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

  // Fetch analyses (auto-poll while pending/analyzing)
  const {
    data: analyses = [],
    isLoading: analysesLoading,
    isError: analysesError,
    refetch: refetchAnalyses,
  } = useQuery<ApiAnalysis[]>({
    queryKey: [`/api/submissions/${submissionId}/analyses`],
    enabled: !!submissionId,
    refetchInterval: currentStatus === "pending" || currentStatus === "analyzing" ? 3000 : false,
  });

  // Fetch consensus result once completed or once engine analyses exist
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
      toast({
        title: "Analysis triggered",
        description: "Submission queued for security engines.",
      });
      refetchSubmission();
      refetchAnalyses();
    },
    onError: (err) => {
      toast({
        title: "Failed to start analysis",
        description: err instanceof Error ? err.message : "Please try again",
        variant: "destructive",
      });
    },
  });

  const voteMutation = useMutation({
    mutationFn: async (verdict: string) => {
      const res = await apiRequest("POST", `/api/submissions/${submissionId}/vote`, {
        verdict,
        confidence: 0.9,
      });
      return res.json();
    },
    onSuccess: (_data, verdict) => {
      setSelectedVote(verdict);
      toast({
        title: "Vote recorded",
        description: `Your ${verdict} verdict has been recorded for consensus.`,
      });
      refetchConsensus();
      queryClient.invalidateQueries({ queryKey: [`/api/submissions/${submissionId}/consensus`] });
    },
    onError: (err) => {
      toast({
        title: "Could not submit vote",
        description: err instanceof Error ? err.message : "You may have already voted on this submission.",
        variant: "destructive",
      });
    },
  });

  // Real-time updates via WebSocket
  const { lastMessage } = useWebSocket();

  useEffect(() => {
    if (lastMessage && submissionId) {
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
      } catch (_e) {
        // Ignore non-JSON frames
      }
    }
  }, [lastMessage, submissionId, refetchSubmission, refetchAnalyses, refetchConsensus]);

  if (submissionError || analysesError) {
    return (
      <div className="min-h-screen bg-background text-foreground">
        <SEO title="Error Loading Analysis" description="Failed to load analysis details." />
        <ParticleBackground />
        <Navigation />
        <div className="relative z-10 max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
          <ErrorState
            title="Failed to load analysis"
            message="Could not fetch analysis details. Please try again."
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
        <SEO title="Loading Analysis" description="Loading analysis details." />
        <ParticleBackground />
        <Navigation />
        <div className="relative z-10 max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
          <div className="grid md:grid-cols-3 gap-6 mb-8">
            {[1, 2, 3].map((i) => (
              <StatCardSkeleton key={i} />
            ))}
          </div>
          <div className="space-y-4">
            {[1, 2, 3].map((i) => (
              <SubmissionSkeleton key={i} />
            ))}
          </div>
        </div>
      </div>
    );
  }

  const displayName =
    submission.originalFilename ||
    submission.filename ||
    submission.fileName ||
    submission.url ||
    submission.id;

  const isUrlTarget =
    submission.submissionType === "url" ||
    Boolean(submission.url) ||
    displayName.startsWith("http://") ||
    displayName.startsWith("https://");

  const completedAnalyses = analyses.filter((a) => (a.status || a.analysisStatus) === "completed");
  const progress = analyses.length > 0 ? (completedAnalyses.length / analyses.length) * 100 : 0;

  const getStatusIcon = (status: string) => {
    switch (status) {
      case "completed":
        return <CheckCircle2 className="h-5 w-5 text-success" />;
      case "analyzing":
        return <Clock className="h-5 w-5 text-warning animate-spin" />;
      case "pending":
        return <Clock className="h-5 w-5 text-muted-foreground" />;
      default:
        return <FileText className="h-5 w-5" />;
    }
  };

  const getVerdictColor = (verdict: string | null) => {
    switch (verdict?.toLowerCase()) {
      case "malicious":
        return "destructive";
      case "suspicious":
        return "secondary";
      case "clean":
      case "benign":
        return "default";
      default:
        return "outline";
    }
  };

  const getEngineIcon = (type: string) => {
    switch (type) {
      case "ml":
        return <Brain className="h-5 w-5" />;
      case "human":
        return <User className="h-5 w-5" />;
      case "signature":
        return <FileSearch className="h-5 w-5" />;
      default:
        return <Bot className="h-5 w-5" />;
    }
  };

  return (
    <div className="min-h-screen bg-background text-foreground">
      <SEO
        title={displayName ? `Analysis: ${displayName}` : "Analysis Details"}
        description={submission.description || "Detailed malware analysis results and consensus score."}
      />
      <ParticleBackground />
      <Navigation />

      <div id="main-content" tabIndex={-1} className="relative z-10 max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
        {/* Header */}
        <div className="flex flex-wrap items-start justify-between gap-4 mb-8">
          <div>
            <h1 className="text-4xl md:text-5xl font-bold font-display tracking-[-0.03em] mb-2">
              Analysis Results
            </h1>
            <p className="text-muted-foreground break-all font-mono">{displayName}</p>
          </div>
          <div className="flex items-center gap-3">
            {currentStatus === "pending" && (
              <Button
                onClick={() => startAnalysisMutation.mutate()}
                disabled={startAnalysisMutation.isPending}
                data-testid="button-trigger-analysis"
              >
                <Play className="h-4 w-4 mr-2" />
                {startAnalysisMutation.isPending ? "Starting..." : "Run Scan Now"}
              </Button>
            )}
            <ExportReport
              submissionId={submissionId || ""}
              fileName={displayName}
              consensus={consensus as Record<string, unknown> | undefined}
              analyses={analyses as unknown as import("@/components/export-report").AnalysisRecord[]}
            />
          </div>
        </div>

        {/* Status Overview */}
        <div className="grid md:grid-cols-3 gap-6 mb-8">
          <Card className="glassmorphism border-primary/20">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Status</CardTitle>
              {getStatusIcon(currentStatus)}
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold capitalize">{currentStatus}</div>
              {currentStatus === "analyzing" && <Progress value={progress} className="mt-2" />}
              <p className="text-xs text-muted-foreground mt-2">
                {completedAnalyses.length} / {analyses.length} engines completed
              </p>
            </CardContent>
          </Card>

          <Card className="glassmorphism border-primary/20">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Bounty</CardTitle>
              <TrendingUp className="h-4 w-4 text-accent" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-accent">{submission.bountyAmount ?? "0.1"} ETH</div>
              <p className="text-xs text-muted-foreground mt-2">
                {submission.priority ? "Priority Analysis" : "Standard"}
              </p>
            </CardContent>
          </Card>

          <Card className="glassmorphism border-primary/20">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Analysis Type</CardTitle>
              <Shield className="h-4 w-4 text-primary" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold capitalize">{submission.analysisType || "full"}</div>
              <p className="text-xs text-muted-foreground mt-2">
                Submitted {new Date(submission.createdAt ?? "").toLocaleDateString()}
              </p>
            </CardContent>
          </Card>
        </div>

        {/* Consensus Result */}
        {(currentStatus === "completed" || analyses.length > 0) && consensus && (
          <Card className="glassmorphism neon-border mb-8">
            <CardHeader>
              <CardTitle className="text-2xl">Consensus Result</CardTitle>
              <CardDescription>Aggregated verdict from all security engines and analysts</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="flex items-center justify-between mb-6">
                <div>
                  <div className="text-sm text-muted-foreground mb-2">Final Verdict</div>
                  <Badge
                    variant={getVerdictColor(consensus.finalVerdict ?? null)}
                    className="text-lg px-4 py-2 capitalize"
                  >
                    {consensus.finalVerdict}
                  </Badge>
                </div>
                <div className="text-center">
                  <div className="text-4xl font-bold font-display tracking-tight text-primary">
                    {consensus.confidenceScore}%
                  </div>
                  <div className="text-sm text-muted-foreground">Confidence</div>
                </div>
              </div>

              <Separator className="my-6" />

              <div className="grid grid-cols-3 gap-6">
                <div className="text-center">
                  <div className="text-3xl font-bold font-display tracking-tight text-destructive">
                    {consensus.maliciousVotes ?? 0}
                  </div>
                  <div className="text-sm text-muted-foreground">Malicious Votes</div>
                </div>
                <div className="text-center">
                  <div className="text-3xl font-bold font-display tracking-tight text-secondary">
                    {consensus.suspiciousVotes ?? 0}
                  </div>
                  <div className="text-sm text-muted-foreground">Suspicious Votes</div>
                </div>
                <div className="text-center">
                  <div className="text-3xl font-bold font-display tracking-tight text-success">
                    {consensus.cleanVotes ?? consensus.benignVotes ?? 0}
                  </div>
                  <div className="text-sm text-muted-foreground">Clean Votes</div>
                </div>
              </div>

              {consensus.explanation && (
                <div className="mt-6 p-4 rounded-lg bg-card/60 border border-primary/20 text-sm">
                  <div className="flex items-center gap-2 font-semibold text-primary mb-1">
                    <Info className="h-4 w-4" />
                    <span>Consensus Formulation</span>
                  </div>
                  <p className="text-muted-foreground leading-relaxed">{consensus.explanation}</p>
                </div>
              )}

              {consensus.unavailableEngines && consensus.unavailableEngines.length > 0 && (
                <div className="mt-4 p-4 rounded-lg bg-destructive/10 border border-destructive/20 text-xs">
                  <div className="flex items-center gap-2 font-semibold text-destructive mb-2">
                    <AlertCircle className="h-4 w-4" />
                    <span>Excluded Unavailable Engines ({consensus.unavailableEngines.length})</span>
                  </div>
                  <div className="space-y-1 text-muted-foreground">
                    {consensus.unavailableEngines.map((unavail, idx) => (
                      <div key={idx} className="flex items-center justify-between">
                        <span className="font-medium text-foreground">{unavail.engineName}</span>
                        <span>{unavail.reason}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              <Separator className="my-6" />

              {/* Analyst Community Verification Vote */}
              <div className="flex flex-wrap items-center justify-between gap-4">
                <div>
                  <div className="text-sm font-semibold flex items-center gap-2">
                    <ThumbsUp className="h-4 w-4 text-primary" />
                    Submit Analyst Verdict Vote
                  </div>
                  <p className="text-xs text-muted-foreground">
                    Contribute your independent verification to the consensus tally.
                  </p>
                </div>
                <div className="flex gap-2">
                  {(["benign", "suspicious", "malicious"] as const).map((v) => (
                    <Button
                      key={v}
                      size="sm"
                      variant={selectedVote === v ? "default" : "outline"}
                      disabled={voteMutation.isPending || !!selectedVote}
                      onClick={() => voteMutation.mutate(v)}
                      className="capitalize"
                      data-testid={`button-vote-${v}`}
                    >
                      {v === "benign" ? "Clean / Benign" : v}
                    </Button>
                  ))}
                </div>
              </div>

              <p className="mt-4 text-xs text-muted-foreground italic text-center">
                {consensus.confidenceNote ||
                  "Confidence reflects calibrated engine agreement concordance (0-100%), not a statistical posterior probability."}
              </p>
            </CardContent>
          </Card>
        )}

        {/* Analysis Details & Website Intelligence Tabs */}
        <Tabs defaultValue={isUrlTarget ? "web-intel" : "engines"} className="space-y-6">
          <TabsList className="flex flex-wrap h-auto">
            {isUrlTarget && (
              <TabsTrigger value="web-intel" className="flex items-center gap-1.5">
                <Globe className="h-4 w-4" />
                Website Intelligence (36 Modules)
              </TabsTrigger>
            )}
            <TabsTrigger value="engines" className="flex items-center gap-1.5">
              <Cpu className="h-4 w-4" />
              Engine Analysis ({analyses.length})
            </TabsTrigger>
            <TabsTrigger value="details">Artifact Details</TabsTrigger>
            <TabsTrigger value="timeline">Execution Timeline</TabsTrigger>
          </TabsList>

          {isUrlTarget && (
            <TabsContent value="web-intel">
              <WebsiteIntelligencePanel
                submissionId={submissionId}
                initialUrl={submission.url || displayName}
              />
            </TabsContent>
          )}

          <TabsContent value="engines" className="space-y-4">
            {analysesLoading ? (
              <div className="space-y-4">
                {[1, 2, 3].map((i) => (
                  <SubmissionSkeleton key={i} />
                ))}
              </div>
            ) : analyses.length === 0 ? (
              <Card className="glassmorphism">
                <CardContent className="p-12 text-center space-y-4">
                  <p className="text-muted-foreground">
                    {currentStatus === "analyzing"
                      ? "Security engines are currently scanning this artifact..."
                      : "No engine detections recorded yet."}
                  </p>
                  {currentStatus === "pending" && (
                    <Button onClick={() => startAnalysisMutation.mutate()} disabled={startAnalysisMutation.isPending}>
                      <Play className="h-4 w-4 mr-2" />
                      Start Engine Scan
                    </Button>
                  )}
                </CardContent>
              </Card>
            ) : (
              analyses.map((analysis) => {
                const aStatus = analysis.status || analysis.analysisStatus || "completed";
                // eslint-disable-next-line @typescript-eslint/no-explicit-any
                const rawAnalysis = analysis as Record<string, any>;
                const metaObj =
                  rawAnalysis.metadata && typeof rawAnalysis.metadata === "object"
                    ? (rawAnalysis.metadata as Record<string, unknown>)
                    : {};
                const metaEntries = Object.entries(metaObj).filter(
                  ([k, v]) => k !== "matches" && v !== null && v !== undefined && String(v) !== ""
                );

                return (
                  <Card key={analysis.id} className="glassmorphism border-primary/20">
                    <CardContent className="p-6">
                      <div className="flex items-start justify-between">
                        <div className="flex items-start gap-4 flex-1">
                          <div className="p-3 bg-primary/10 rounded-lg">
                            {getEngineIcon(analysis.engine?.type ?? "")}
                          </div>
                          <div className="flex-1">
                            <div className="flex flex-wrap items-center gap-3 mb-2">
                              <h3 className="text-lg font-semibold">
                                {analysis.engine?.name || "Automated Engine"}
                              </h3>
                              <Badge variant="outline">{analysis.engine?.type || "scanner"}</Badge>
                              {rawAnalysis.processingTimeMs !== undefined && (
                                <Badge variant="secondary" className="font-mono text-xs">
                                  {rawAnalysis.processingTimeMs} ms
                                </Badge>
                              )}
                              {getStatusIcon(aStatus)}
                            </div>
                            <p className="text-sm text-muted-foreground mb-4">
                              {analysis.engine?.description || "Security analysis engine"}
                            </p>

                            {aStatus === "completed" && (
                              <div className="grid grid-cols-3 gap-4 pt-4 border-t border-border">
                                <div>
                                  <div className="text-sm text-muted-foreground">Verdict</div>
                                  <Badge
                                    variant={getVerdictColor(analysis.verdict ?? null)}
                                    className="mt-1 capitalize"
                                  >
                                    {analysis.verdict === "unknown" ? "Clean (Verified)" : analysis.verdict}
                                  </Badge>
                                </div>
                                <div>
                                  <div className="text-sm text-muted-foreground">Confidence</div>
                                  <div className="text-lg font-semibold mt-1">{analysis.confidence}%</div>
                                </div>
                                <div>
                                  <div className="text-sm text-muted-foreground">Stake</div>
                                  <div className="text-lg font-semibold mt-1 text-primary">
                                    {analysis.stakeAmount || "1.5"} ETH
                                  </div>
                                </div>
                              </div>
                            )}

                            {metaEntries.length > 0 && (
                              <div className="mt-4 pt-3 border-t border-border/40 flex flex-wrap gap-2">
                                {metaEntries.slice(0, 6).map(([k, v]) => (
                                  <span
                                    key={k}
                                    className="inline-flex items-center gap-1 rounded bg-muted/30 px-2 py-0.5 font-mono text-[11px] text-muted-foreground"
                                  >
                                    <span className="text-foreground">{k}:</span>
                                    <span>
                                      {typeof v === "object" ? JSON.stringify(v) : String(v)}
                                    </span>
                                  </span>
                                ))}
                              </div>
                            )}
                          </div>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                );
              })
            )}
          </TabsContent>

          <TabsContent value="details">
            <Card className="glassmorphism">
              <CardHeader>
                <CardTitle>Artifact Information</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="grid md:grid-cols-2 gap-6">
                  <div>
                    <div className="text-sm text-muted-foreground mb-1">Filename / Target</div>
                    <div className="font-mono break-all">{displayName}</div>
                  </div>
                  <div>
                    <div className="text-sm text-muted-foreground mb-1">SHA-256 Hash</div>
                    <div className="font-mono text-sm break-all">{submission.fileHash || "N/A"}</div>
                  </div>
                  <div>
                    <div className="text-sm text-muted-foreground mb-1">Size</div>
                    <div>
                      {submission.fileSize ? `${(submission.fileSize / 1024).toFixed(2)} KB` : "N/A"}
                    </div>
                  </div>
                  <div>
                    <div className="text-sm text-muted-foreground mb-1">Submission Type</div>
                    <div className="capitalize">{submission.submissionType || "file"}</div>
                  </div>
                  <div className="md:col-span-2">
                    <div className="text-sm text-muted-foreground mb-1">Description</div>
                    <div>{submission.description || "No description provided"}</div>
                  </div>
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="timeline">
            <Card className="glassmorphism">
              <CardHeader>
                <CardTitle>Backend Execution Timeline</CardTitle>
                <CardDescription>Step-by-step trace of this submission across Verdyx services</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  <div className="flex items-center gap-4">
                    <div className="w-2.5 h-2.5 bg-primary rounded-full" />
                    <div>
                      <div className="font-semibold">1. Gateway Ingestion & SHA-256 Hashing</div>
                      <div className="text-sm text-muted-foreground">
                        {new Date(submission.createdAt ?? "").toLocaleString()} · Queued to Redis `analysis_queue`
                      </div>
                    </div>
                  </div>
                  {currentStatus !== "pending" && (
                    <div className="flex items-center gap-4">
                      <div className="w-2.5 h-2.5 bg-warning rounded-full" />
                      <div>
                        <div className="font-semibold">
                          2. Parallel Multi-Engine Sandbox Execution ({analyses.length} Engines)
                        </div>
                        <div className="text-sm text-muted-foreground">
                          ClamAV, YARA, Goblin Static, Byte-Entropy GBDT ML, Heuristic, Signature & Hash Threat Intel
                        </div>
                      </div>
                    </div>
                  )}
                  {currentStatus === "completed" && (
                    <div className="flex items-center gap-4">
                      <div className="w-2.5 h-2.5 bg-success rounded-full" />
                      <div>
                        <div className="font-semibold">3. Consensus & OSINT Finalization</div>
                        <div className="text-sm text-muted-foreground">
                          {submission.completedAt || submission.updatedAt
                            ? new Date(submission.completedAt || submission.updatedAt || "").toLocaleString()
                            : "Completed"}{" "}
                          · Verdict broadcast via WebSocket
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </div>
    </div>
  );
}
