import { useEffect } from "react";
import { useRoute } from "wouter";
import { useQuery } from "@tanstack/react-query";
import { Navigation } from "@/components/navigation";
import { ParticleBackground } from "@/components/particle-background";
import { SEO } from "@/components/seo";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import { Progress } from "@/components/ui/progress";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ExportReport } from "@/components/export-report";
import { useWebSocket } from "@/hooks/use-websocket";
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
} from "lucide-react";
import { StatCardSkeleton, SubmissionSkeleton } from "@/components/loading-skeleton";
import { ErrorState } from "@/components/error-state";
import type { ApiSubmission, ApiAnalysis, ApiConsensus } from "@/lib/api-types";

export default function AnalysisDetails() {
  const [, params] = useRoute("/analysis/:id");
  const submissionId = params?.id;

  // Fetch submission details
  const {
    data: submission,
    isLoading: submissionLoading,
    isError: submissionError,
    refetch: refetchSubmission,
  } = useQuery<ApiSubmission>({
    queryKey: [`/api/submissions/${submissionId}`],
    enabled: !!submissionId,
  });

  // Fetch analyses
  const {
    data: analyses = [],
    isLoading: analysesLoading,
    isError: analysesError,
    refetch: refetchAnalyses,
  } = useQuery<ApiAnalysis[]>({
    queryKey: [`/api/submissions/${submissionId}/analyses`],
    enabled: !!submissionId,
  });

  // Fetch consensus result
  const { data: consensus } = useQuery<ApiConsensus>({
    queryKey: [`/api/submissions/${submissionId}/consensus`],
    enabled: !!submissionId && submission?.status === "completed",
  });

  // Real-time updates
  const { lastMessage } = useWebSocket();

  useEffect(() => {
    if (lastMessage && submissionId) {
      const data = JSON.parse(lastMessage.data);
      if (
        data.type === "analysis_updated" ||
        (data.type === "analysis_completed" && data.data.submissionId === submissionId)
      ) {
        refetchSubmission();
        refetchAnalyses();
      }
    }
  }, [lastMessage, submissionId, refetchSubmission, refetchAnalyses]);

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

  const completedAnalyses = analyses.filter((a) => a.status === "completed");
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
    switch (verdict) {
      case "malicious":
        return "destructive";
      case "suspicious":
        return "secondary";
      case "clean":
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
      <SEO title={submission.filename ? `Analysis: ${submission.filename}` : "Analysis Details"} description={submission.description || "Detailed malware analysis results and consensus score."} />
      <ParticleBackground />
      <Navigation />

      <div id="main-content" tabIndex={-1} className="relative z-10 max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
        {/* Header */}
        <div className="flex items-start justify-between mb-8">
          <div>
            <h1 className="text-4xl md:text-5xl font-bold font-display tracking-[-0.03em] mb-2">Analysis Results</h1>
            <p className="text-muted-foreground">{submission.filename}</p>
          </div>
          <ExportReport
            submissionId={submissionId || ""}
            fileName={submission.filename ?? ""}
            consensus={consensus as Record<string, unknown> | undefined}
            analyses={analyses as unknown as import("@/components/export-report").AnalysisRecord[]}
          />
        </div>

        {/* Status Overview */}
        <div className="grid md:grid-cols-3 gap-6 mb-8">
          <Card className="glassmorphism border-primary/20">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Status</CardTitle>
              {getStatusIcon(submission.status ?? "")}
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold capitalize">{submission.status}</div>
              {submission.status === "analyzing" && (
                <Progress value={progress} className="mt-2" />
              )}
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
              <div className="text-2xl font-bold text-accent">{submission.bountyAmount} ETH</div>
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
              <div className="text-2xl font-bold capitalize">{submission.analysisType}</div>
              <p className="text-xs text-muted-foreground mt-2">
                Submitted {new Date(submission.createdAt ?? "").toLocaleDateString()}
              </p>
            </CardContent>
          </Card>
        </div>

        {/* Consensus Result (if completed) */}
        {submission.status === "completed" && consensus && (
          <Card className="glassmorphism neon-border mb-8">
            <CardHeader>
              <CardTitle className="text-2xl">Consensus Result</CardTitle>
              <CardDescription>Aggregated verdict from all security engines</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="flex items-center justify-between mb-6">
                <div>
                  <div className="text-sm text-muted-foreground mb-2">Final Verdict</div>
                  <Badge
                    variant={getVerdictColor(consensus.finalVerdict ?? null)}
                    className="text-lg px-4 py-2"
                  >
                    {consensus.finalVerdict}
                  </Badge>
                </div>
                <div className="text-center">
                  <div className="text-4xl font-bold font-display tracking-tight text-primary">{consensus.confidenceScore}%</div>
                  <div className="text-sm text-muted-foreground">Confidence</div>
                </div>
              </div>

              <Separator className="my-6" />

              <div className="grid grid-cols-3 gap-6">
                <div className="text-center">
                  <div className="text-3xl font-bold font-display tracking-tight text-destructive">{consensus.maliciousVotes}</div>
                  <div className="text-sm text-muted-foreground">Malicious Votes</div>
                </div>
                <div className="text-center">
                  <div className="text-3xl font-bold font-display tracking-tight text-secondary">{consensus.suspiciousVotes}</div>
                  <div className="text-sm text-muted-foreground">Suspicious Votes</div>
                </div>
                <div className="text-center">
                  <div className="text-3xl font-bold font-display tracking-tight text-success">{consensus.cleanVotes}</div>
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

              <p className="mt-4 text-xs text-muted-foreground italic text-center">
                {consensus.confidenceNote || "Confidence reflects calibrated engine agreement concordance (0-100%), not a statistical posterior probability."}
              </p>
            </CardContent>
          </Card>
        )}

        {/* Analysis Details */}
        <Tabs defaultValue="engines" className="space-y-6">
          <TabsList>
            <TabsTrigger value="engines">Engine Analysis ({analyses.length})</TabsTrigger>
            <TabsTrigger value="details">File Details</TabsTrigger>
            <TabsTrigger value="timeline">Timeline</TabsTrigger>
          </TabsList>

          <TabsContent value="engines" className="space-y-4">
            {analysesLoading ? (
              <div className="space-y-4">
                {[1, 2, 3].map((i) => (
                  <SubmissionSkeleton key={i} />
                ))}
              </div>
            ) : analyses.length === 0 ? (
              <Card className="glassmorphism">
                <CardContent className="p-12 text-center">
                  <p className="text-muted-foreground">No analyses started yet</p>
                </CardContent>
              </Card>
            ) : (
              analyses.map((analysis) => (
                <Card key={analysis.id} className="glassmorphism border-primary/20">
                  <CardContent className="p-6">
                    <div className="flex items-start justify-between">
                      <div className="flex items-start gap-4 flex-1">
                        <div className="p-3 bg-primary/10 rounded-lg">
                          {getEngineIcon(analysis.engine?.type ?? "")}
                        </div>
                        <div className="flex-1">
                          <div className="flex items-center gap-3 mb-2">
                            <h3 className="text-lg font-semibold">{analysis.engine?.name || "Unknown Engine"}</h3>
                            <Badge variant="outline">{analysis.engine?.type}</Badge>
                            {getStatusIcon(analysis.status ?? "")}
                          </div>
                          <p className="text-sm text-muted-foreground mb-4">
                            {analysis.engine?.description || "Security analysis engine"}
                          </p>

                          {analysis.status === "completed" && (
                            <div className="grid grid-cols-3 gap-4 pt-4 border-t border-border">
                              <div>
                                <div className="text-sm text-muted-foreground">Verdict</div>
                                <Badge variant={getVerdictColor(analysis.verdict ?? null)} className="mt-1">
                                  {analysis.verdict}
                                </Badge>
                              </div>
                              <div>
                                <div className="text-sm text-muted-foreground">Confidence</div>
                                <div className="text-lg font-semibold mt-1">{analysis.confidence}%</div>
                              </div>
                              <div>
                                <div className="text-sm text-muted-foreground">Stake</div>
                                <div className="text-lg font-semibold mt-1">{analysis.stakeAmount} ETH</div>
                              </div>
                            </div>
                          )}

                          {analysis.status === "analyzing" && (
                            <div className="flex items-center gap-2 text-sm text-muted-foreground">
                              <Clock className="h-4 w-4 animate-spin" />
                              Analysis in progress...
                            </div>
                          )}
                        </div>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              ))
            )}
          </TabsContent>

          <TabsContent value="details">
            <Card className="glassmorphism">
              <CardHeader>
                <CardTitle>File Information</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="grid md:grid-cols-2 gap-6">
                  <div>
                    <div className="text-sm text-muted-foreground mb-1">Filename</div>
                    <div className="font-mono">{submission.filename}</div>
                  </div>
                  <div>
                    <div className="text-sm text-muted-foreground mb-1">File Hash (SHA-256)</div>
                    <div className="font-mono text-sm">{submission.fileHash}</div>
                  </div>
                  <div>
                    <div className="text-sm text-muted-foreground mb-1">File Size</div>
                    <div>{submission.fileSize ? `${(submission.fileSize / 1024).toFixed(2)} KB` : "N/A"}</div>
                  </div>
                  <div>
                    <div className="text-sm text-muted-foreground mb-1">Submission Type</div>
                    <div className="capitalize">{submission.submissionType}</div>
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
                <CardTitle>Analysis Timeline</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  <div className="flex items-center gap-4">
                    <div className="w-2 h-2 bg-primary rounded-full" />
                    <div>
                      <div className="font-semibold">Submission Created</div>
                      <div className="text-sm text-muted-foreground">
                        {new Date(submission.createdAt ?? "").toLocaleString()}
                      </div>
                    </div>
                  </div>
                  {submission.status !== "pending" && (
                    <div className="flex items-center gap-4">
                      <div className="w-2 h-2 bg-warning rounded-full" />
                      <div>
                        <div className="font-semibold">Analysis Started</div>
                        <div className="text-sm text-muted-foreground">Engines assigned</div>
                      </div>
                    </div>
                  )}
                  {submission.status === "completed" && (
                    <div className="flex items-center gap-4">
                      <div className="w-2 h-2 bg-success rounded-full" />
                      <div>
                        <div className="font-semibold">Analysis Completed</div>
                        <div className="text-sm text-muted-foreground">
                          {submission.completedAt ? new Date(submission.completedAt).toLocaleString() : "Recently"}
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
