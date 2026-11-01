import { useQuery } from "@tanstack/react-query";
import { Link } from "wouter";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Activity, CheckCircle, AlertTriangle, RotateCw, FileText, Link as LinkIcon, ShieldCheck, Inbox } from "lucide-react";
import { useWebSocket } from "@/hooks/use-websocket";
import { Skeleton } from "@/components/ui/skeleton";
import { ErrorState } from "@/components/error-state";
import { StatCard } from "@/components/stat-card";
import type { ApiSubmission, ApiStats } from "@/lib/api-types";

const statusMeta: Record<string, { label: string; icon: typeof Activity; className: string; dot: string }> = {
  analyzing: { label: "Analyzing", icon: RotateCw, className: "text-primary", dot: "bg-primary" },
  completed: { label: "Completed", icon: CheckCircle, className: "text-accent", dot: "bg-accent" },
  pending: { label: "Pending", icon: Activity, className: "text-warning", dot: "bg-warning" },
  failed: { label: "Failed", icon: AlertTriangle, className: "text-destructive", dot: "bg-destructive" },
};

function getMeta(status: string) {
  return statusMeta[status] ?? statusMeta.pending;
}

/** How often the dashboard's stats and results refresh on their own. */
export const DASHBOARD_REFRESH_MS = 30_000;

/** KPI row — four uniform cards for a balanced, symmetrical header. */
export function DashboardStats() {
  const { data: stats, isLoading, isError } = useQuery<ApiStats>({
    queryKey: ["/api/analysis/stats"],
    refetchInterval: DASHBOARD_REFRESH_MS,
  });

  const cards = [
    {
      label: "Total Submissions",
      value: Number(stats?.totalSubmissions ?? 0).toLocaleString(),
      icon: Inbox,
      accent: "primary" as const,
      hint: "All-time files analyzed",
    },
    {
      label: "Active Analyses",
      value: Number(stats?.activeAnalyses ?? stats?.analyzingCount ?? 0),
      icon: Activity,
      accent: "accent" as const,
      hint: "Currently in progress",
    },
    {
      label: "Completed Today",
      value: Number(stats?.completedToday ?? stats?.completedAnalyses ?? 0),
      icon: ShieldCheck,
      accent: "primary" as const,
      hint: "Reports finalized today",
    },
    {
      label: "Threats Detected",
      value: Math.floor(Number(stats?.threatsDetected ?? 0)),
      icon: AlertTriangle,
      accent: "destructive" as const,
      hint: "Malicious files found",
    },
  ];

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">
      {cards.map((c) => (
        <StatCard
          key={c.label}
          label={c.label}
          value={isError ? "—" : c.value}
          live={!isError}
          icon={c.icon}
          accent={c.accent}
          hint={isError ? "Unable to load" : c.hint}
          loading={isLoading}
        />
      ))}
    </div>
  );
}

/** Recent analysis results list with loading/error/empty states. */
export function RecentAnalyses() {
  const {
    data: rawSubmissions,
    isError,
    refetch,
    isLoading,
  } = useQuery<ApiSubmission[]>({
    queryKey: ["/api/submissions"],
    refetchInterval: DASHBOARD_REFRESH_MS,
  });
  const submissions: ApiSubmission[] = Array.isArray(rawSubmissions) ? rawSubmissions : [];

  useWebSocket((message) => {
    if (
      message.type === "analysis_updated" ||
      message.type === "analysis_completed" ||
      message.type === "new_submission"
    ) {
      refetch();
    }
  });

  return (
    <Card className="glassmorphism h-full">
      <CardHeader className="flex flex-row items-center justify-between">
        <CardTitle className="text-lg font-semibold">Recent Analysis Results</CardTitle>
        {!isError && (
          <Badge variant="outline" className="font-mono text-xs">
            {submissions.length} total
          </Badge>
        )}
      </CardHeader>
      <CardContent>
        <div className="space-y-3">
          {isError ? (
            <ErrorState
              title="Failed to load submissions"
              message="Could not fetch recent analysis results. Please try again."
              onRetry={refetch}
            />
          ) : isLoading ? (
            Array.from({ length: 4 }).map((_, i) => (
              <div key={i} className="flex items-center gap-4 rounded-lg border border-border/50 p-4">
                <Skeleton className="h-11 w-11 rounded-lg" />
                <div className="flex-1 space-y-2">
                  <Skeleton className="h-4 w-40" />
                  <Skeleton className="h-3 w-28" />
                </div>
                <Skeleton className="h-6 w-16" />
              </div>
            ))
          ) : submissions.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-12 text-center">
              <div className="mb-3 flex h-12 w-12 items-center justify-center rounded-full bg-muted">
                <Inbox className="h-6 w-6 text-muted-foreground" />
              </div>
              <p className="font-medium">No submissions yet</p>
              <p className="text-sm text-muted-foreground">Submit a file to see results here.</p>
            </div>
          ) : (
            submissions.slice(0, 6).map((submission) => {
              const currentStatus = submission.status || submission.analysisStatus || "pending";
              const meta = getMeta(currentStatus);
              const StatusIcon = meta.icon;
              const displayName =
                submission.originalFilename ||
                submission.filename ||
                submission.fileName ||
                submission.url ||
                "Untitled";
              return (
                <Link key={submission.id} href={`/analysis/${submission.id}`}>
                  <div
                    className="cursor-pointer flex items-center gap-4 rounded-lg border border-border/50 bg-card/40 p-4 transition-colors hover:border-primary/40"
                    data-testid={`analysis-result-${submission.id}`}
                  >
                    <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded-lg bg-primary/10 text-primary">
                      {submission.submissionType === "url" ? (
                        <LinkIcon className="h-5 w-5" />
                      ) : (
                        <FileText className="h-5 w-5" />
                      )}
                    </div>

                    <div className="min-w-0 flex-1">
                      <div className="truncate font-medium" data-testid={`filename-${submission.id}`}>
                        {displayName}
                      </div>
                      <div className="truncate font-mono text-xs text-muted-foreground">
                        SHA256: {(submission.fileHash ?? "—").substring(0, 16)}
                        {submission.fileHash ? "…" : ""}
                      </div>
                    </div>

                    <div className="hidden items-center gap-1.5 sm:flex">
                      <StatusIcon
                        className={`h-4 w-4 ${meta.className} ${currentStatus === "analyzing" ? "animate-spin" : ""}`}
                      />
                      <span className={`text-sm font-medium ${meta.className}`}>{meta.label}</span>
                    </div>

                    <Badge variant="outline" className="shrink-0 border-primary/30 bg-primary/10 font-mono text-primary">
                      {submission.bountyAmount ?? 0} ETH
                    </Badge>
                  </div>
                </Link>
              );
            })
          )}
        </div>
      </CardContent>
    </Card>
  );
}
