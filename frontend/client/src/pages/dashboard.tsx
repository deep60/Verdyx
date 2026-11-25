import { useEffect, useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useLocation } from "wouter";
import { ArrowLeftRight, BarChart3, Binary, Globe, LayoutGrid } from "lucide-react";
import { SWITCH_DASHBOARD_TAB_EVENT } from "@/components/command-palette";
import { Navigation } from "@/components/navigation";
import { Footer } from "@/components/footer";
import { SEO } from "@/components/seo";
import { Card } from "@/components/ui/card";
import { FileSubmissionForm } from "@/components/file-submission-form";
import { PlatformAnalytics } from "@/components/platform-analytics";
import { WebsiteIntelligencePanel } from "@/components/website-intelligence-panel";
import { YaraStudio } from "@/components/yara-studio";
import { ScanDiffPanel } from "@/components/scan-diff";
import { LatestCatch, SubmissionList } from "@/components/analyst-profile";
import { EngineHealth, KpiStrip, SystemStatus, VerdictMixCard } from "@/components/dashboard-panels";
import { ErrorState } from "@/components/error-state";
import { useAuth } from "@/contexts/auth-context";
import { useWebSocket } from "@/hooks/use-websocket";
import { cn } from "@/lib/utils";
import type { ApiEngine, ApiStats, ApiSubmission } from "@/lib/api-types";
import { latestCatch, scanCounts } from "@/lib/profile";
import { DASHBOARD_REFRESH_MS, type DashboardTab, greeting, toDashboardTab } from "@/lib/dashboard";

const TABS: { value: DashboardTab; label: string; icon: typeof Globe }[] = [
  { value: "overview", label: "Overview", icon: LayoutGrid },
  { value: "recon", label: "Website recon", icon: Globe },
  { value: "yara", label: "YARA studio", icon: Binary },
  { value: "compare", label: "Compare scans", icon: ArrowLeftRight },
  { value: "analytics", label: "Analytics", icon: BarChart3 },
];

/** Cards rise in one after another; reduced-motion users get them at once (global CSS). */
function Rise({ i, children }: { i: number; children: React.ReactNode }) {
  return (
    <div className="animate-fade-up" style={{ animationDelay: `${80 + i * 70}ms` }}>
      {children}
    </div>
  );
}

function initialTab(): DashboardTab {
  if (typeof window === "undefined") return "overview";
  // The command palette leaves the tab here before it navigates.
  const saved = sessionStorage.getItem("verdyx_dashboard_tab");
  if (saved) {
    sessionStorage.removeItem("verdyx_dashboard_tab");
    return toDashboardTab(saved);
  }
  return toDashboardTab(window.location.hash);
}

export default function Dashboard() {
  const { user } = useAuth();
  const [, setLocation] = useLocation();
  const [tab, setTabState] = useState<DashboardTab>(initialTab);

  const setTab = (next: DashboardTab) => {
    setTabState(next);
    const hash = next === "overview" ? "" : `#${next}`;
    window.history.replaceState(null, "", `${window.location.pathname}${window.location.search}${hash}`);
    window.scrollTo({ top: 0, behavior: "smooth" });
  };

  useEffect(() => {
    const onSwitch = (e: Event) => {
      const detail = (e as CustomEvent<string>).detail;
      if (detail) setTabState(toDashboardTab(detail));
    };
    const onHash = () => setTabState(toDashboardTab(window.location.hash));
    window.addEventListener(SWITCH_DASHBOARD_TAB_EVENT, onSwitch);
    window.addEventListener("hashchange", onHash);
    return () => {
      window.removeEventListener(SWITCH_DASHBOARD_TAB_EVENT, onSwitch);
      window.removeEventListener("hashchange", onHash);
    };
  }, []);

  const submissionsQuery = useQuery<ApiSubmission[]>({
    queryKey: ["/api/submissions"],
    refetchInterval: DASHBOARD_REFRESH_MS,
  });
  const statsQuery = useQuery<ApiStats>({
    queryKey: ["/api/analysis/stats"],
    refetchInterval: DASHBOARD_REFRESH_MS,
  });
  const enginesQuery = useQuery<ApiEngine[]>({
    queryKey: ["/api/engines"],
    staleTime: 60_000,
    refetchInterval: 60_000,
  });

  const { isConnected } = useWebSocket((message) => {
    if (
      message.type === "analysis_updated" ||
      message.type === "analysis_completed" ||
      message.type === "new_submission"
    ) {
      submissionsQuery.refetch();
      statsQuery.refetch();
    }
  });

  const submissions = useMemo(
    () => (Array.isArray(submissionsQuery.data) ? submissionsQuery.data : []),
    [submissionsQuery.data],
  );
  const counts = useMemo(() => scanCounts(submissions), [submissions]);
  const catchScan = useMemo(() => latestCatch(submissions), [submissions]);
  const engines = Array.isArray(enginesQuery.data) ? enginesQuery.data : [];
  const name = user?.username?.split(/[\s@]/)[0] ?? "";

  return (
    <div className="flex min-h-screen flex-col bg-background text-foreground">
      <SEO
        title="Console — Verdyx"
        description="Scan a file, link or email with every Verdyx engine, and keep track of what you've caught."
      />
      <Navigation />

      <main id="main-content" tabIndex={-1} className="relative z-10 flex-1 pb-16 pt-8 sm:pt-10">
        <div className="mx-auto max-w-7xl space-y-6 px-4 sm:px-6 lg:px-8">
          {/* Header */}
          <header className="flex animate-fade-up flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
            <div className="min-w-0">
              <p className="font-mono text-[11px] uppercase tracking-[0.2em] text-muted-foreground">Console</p>
              <h1 className="mt-2 truncate font-display text-3xl font-medium leading-[1.05] tracking-[-0.04em] sm:text-[2.75rem]">
                {greeting()}
                {name && <span className="text-muted-foreground">, {name}</span>}
              </h1>
            </div>
            <SystemStatus engines={engines} enginesLoading={enginesQuery.isLoading} live={isConnected} />
          </header>

          {/* Tabs */}
          <nav
            className="-mx-4 flex gap-1 overflow-x-auto border-b border-border px-4 sm:mx-0 sm:px-0 [&::-webkit-scrollbar]:hidden"
            role="tablist"
            aria-label="Console sections"
          >
            {TABS.map(({ value, label, icon: Icon }) => (
              <button
                key={value}
                type="button"
                role="tab"
                aria-selected={tab === value}
                onClick={() => setTab(value)}
                data-testid={`dashboard-tab-${value}`}
                className={cn(
                  "relative inline-flex shrink-0 items-center gap-2 px-3 py-2.5 text-sm transition-colors duration-200",
                  "after:absolute after:inset-x-2 after:-bottom-px after:h-0.5 after:origin-center after:rounded-full after:bg-foreground after:transition-transform after:duration-300 after:ease-expo-out",
                  tab === value
                    ? "text-foreground after:scale-x-100"
                    : "text-muted-foreground after:scale-x-0 hover:text-foreground",
                )}
              >
                <Icon className="h-4 w-4" aria-hidden />
                {label}
              </button>
            ))}
          </nav>

          {tab === "overview" && (
            <div className="grid items-start gap-6 lg:grid-cols-12" data-testid="dashboard-overview">
              {/* Each column stacks on its own, so a tall card never leaves a hole beside it. */}
              <div className="space-y-6 lg:col-span-7">
                <Rise i={0}>
                  <Card className="p-5 sm:p-6">
                    <div className="mb-5">
                      <h2 className="text-lg font-medium tracking-tight">New scan</h2>
                      <p className="mt-1 text-sm text-muted-foreground">
                        Every engine reads it, and you get one verdict with each engine's evidence.
                      </p>
                    </div>
                    <FileSubmissionForm />
                  </Card>
                </Rise>
                <Rise i={2}>
                  {submissionsQuery.isError ? (
                    <Card className="p-5">
                      <ErrorState
                        title="Couldn't load your scans"
                        message="Your session may have ended. Sign in again, or retry."
                        onRetry={() => submissionsQuery.refetch()}
                      />
                    </Card>
                  ) : (
                    <SubmissionList
                      submissions={submissions}
                      limit={8}
                      title="Recent scans"
                      onShowAll={() => setLocation("/profile#submissions")}
                    />
                  )}
                </Rise>
              </div>
              <div className="space-y-6 lg:col-span-5">
                <Rise i={1}>
                  <KpiStrip counts={counts} loading={submissionsQuery.isLoading} stats={statsQuery.data} />
                </Rise>
                <Rise i={2}>
                  <LatestCatch scan={catchScan} />
                </Rise>
                <Rise i={3}>
                  <EngineHealth engines={engines} loading={enginesQuery.isLoading} error={enginesQuery.isError} />
                </Rise>
                <Rise i={4}>
                  <VerdictMixCard
                    stats={statsQuery.data}
                    loading={statsQuery.isLoading}
                    onOpenAnalytics={() => setTab("analytics")}
                  />
                </Rise>
              </div>
            </div>
          )}

          {tab === "recon" && (
            <div className="animate-fade-up">
              <WebsiteIntelligencePanel />
            </div>
          )}
          {tab === "yara" && (
            <div className="animate-fade-up">
              <YaraStudio />
            </div>
          )}
          {tab === "compare" && (
            <div className="animate-fade-up">
              <ScanDiffPanel />
            </div>
          )}
          {tab === "analytics" && (
            <div className="animate-fade-up">
              <PlatformAnalytics />
            </div>
          )}
        </div>
      </main>

      <Footer tag="console" />
    </div>
  );
}
