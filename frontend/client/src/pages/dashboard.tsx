import { SWITCH_DASHBOARD_TAB_EVENT } from "@/components/command-palette";
import { useState, useEffect } from "react";
import { useQuery } from "@tanstack/react-query";
import { Navigation } from "@/components/navigation";
import { DASHBOARD_REFRESH_MS, DashboardStats, RecentAnalyses } from "@/components/analysis-dashboard";
import { FileSubmissionForm } from "@/components/file-submission-form";
import { PlatformAnalytics } from "@/components/platform-analytics";
import { WebsiteIntelligencePanel } from "@/components/website-intelligence-panel";
import { YaraStudio } from "@/components/yara-studio";
import { ScanDiffPanel } from "@/components/scan-diff";
import { Footer } from "@/components/footer";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Badge } from "@/components/ui/badge";
import {
  Activity,
  BarChart3,
  Upload,
  Globe,
  Cpu,
  Database,
  ShieldCheck,
  Radio,
  Layers,
  Terminal,
  Zap,
  CheckCircle2,
  AlertCircle,
  Binary,
  ArrowLeftRight,
} from "lucide-react";
import { useWebSocket } from "@/hooks/use-websocket";
import { SEO } from "@/components/seo";
import { verdyxFetch } from "@/lib/csrf";

function ApiHealthBadge() {
  const { data, isError, isPending } = useQuery({
    queryKey: ["/api/v1/health"],
    queryFn: async () => {
      const res = await verdyxFetch("/api/v1/health");
      if (!res.ok) throw new Error(`Health check failed: ${res.status}`);
      return (await res.json()) as { status: "healthy" | "degraded" | "unhealthy" };
    },
    refetchInterval: 30_000,
    retry: false,
  });

  if (isPending) {
    return (
      <Badge variant="outline" className="font-mono text-xs">
        Checking API...
      </Badge>
    );
  }
  if (isError || data.status === "unhealthy") {
    return (
      <Badge variant="outline" className="font-mono text-xs border-destructive/40 text-destructive">
        <AlertCircle className="h-3.5 w-3.5 mr-1.5" />
        API unavailable
      </Badge>
    );
  }
  return (
    <Badge variant="outline" className="font-mono text-xs border-accent/40 text-accent">
      <CheckCircle2 className="h-3.5 w-3.5 mr-1.5" />
      {data.status === "healthy" ? "API, database and Redis healthy" : "API online, blockchain RPC unavailable"}
    </Badge>
  );
}

export default function Dashboard() {
  const [activeTab, setActiveTab] = useState(() => {
    if (typeof window !== "undefined") {
      const saved = sessionStorage.getItem("verdyx_dashboard_tab");
      if (saved) {
        sessionStorage.removeItem("verdyx_dashboard_tab");
        return saved;
      }
    }
    return "scanner";
  });

  useEffect(() => {
    const onSwitchTab = (e: Event) => {
      const custom = e as CustomEvent<string>;
      if (custom.detail) setActiveTab(custom.detail);
    };
    window.addEventListener(SWITCH_DASHBOARD_TAB_EVENT, onSwitchTab);
    return () => window.removeEventListener(SWITCH_DASHBOARD_TAB_EVENT, onSwitchTab);
  }, []);
  const { isConnected } = useWebSocket();
  const { isError: statsUnavailable } = useQuery({
    queryKey: ["/api/analysis/stats"],
    refetchInterval: DASHBOARD_REFRESH_MS,
  });
  const [activeLogIdx, setActiveLogIdx] = useState(0);

  const liveAgentLogs = [
    {
      ts: "00:00.012",
      node: "gateway-edge-01",
      action: "INGEST_ARTIFACT",
      detail: "Upload validated and submission saved",
      color: "text-muted-foreground",
    },
    {
      ts: "00:00.048",
      node: "redis-queue-zset",
      action: "ENQUEUE_PRIORITY",
      detail: "Job queued for the analysis engine",
      color: "text-primary",
    },
    {
      ts: "00:00.195",
      node: "engine-clamav-yara",
      action: "SIGNATURE_SWEEP",
      detail: "YARA rules and ClamAV signatures checked",
      color: "text-accent",
    },
    {
      ts: "00:00.340",
      node: "engine-ml-onnx",
      action: "ML_SCORE",
      detail: "Byte features scored by the ONNX model",
      color: "text-warning",
    },
    {
      ts: "00:00.620",
      node: "osint-web-intel",
      action: "RECON_36_MODULES",
      detail: "DoH DNS, Shodan InternetDB ports/CVEs, RDAP WHOIS, CT logs & HSTS",
      color: "text-muted-foreground",
    },
    {
      ts: "00:00.890",
      node: "consensus-quorum",
      action: "VERDICT_FINALIZE",
      detail: "Engine votes combined · Broadcast over /ws pubsub",
      color: "text-success",
    },
  ];

  useEffect(() => {
    const timer = setInterval(() => {
      setActiveLogIdx((prev) => (prev + 1) % liveAgentLogs.length);
    }, 2400);
    return () => clearInterval(timer);
  }, [liveAgentLogs.length]);

  const pipelineStages = [
    {
      step: "01",
      title: "API Gateway & Validation",
      service: "verdyx-api-gateway · Rust/Axum",
      detail:
        "Validates uploaded files or URLs and saves the submission details.",
      icon: Upload,
      accent: "border-border",
    },
    {
      step: "02",
      title: "Redis Priority ZSET Scheduler",
      service: "verdyx-redis · In-Flight Guard",
      detail:
        "Schedules jobs into a priority-weighted sorted set with automatic crash recovery and Pub/Sub event fan-out.",
      icon: Layers,
      accent: "border-border",
    },
    {
      step: "03",
      title: "8-Engine Parallel Analysis",
      service: "verdyx-analysis-engine · tokio::join!",
      detail:
        "Runs ClamAV, YARA, Goblin PE/ELF static parsing, ONNX ML, heuristics, signatures, and hash and threat-intel lookups concurrently.",
      icon: Cpu,
      accent: "border-border",
    },
    {
      step: "04",
      title: "36-Module Website OSINT Recon",
      service: "web_intel · DoH + Shodan + RDAP + CT",
      detail:
        "Queries Cloudflare DoH, Shodan InternetDB open ports & CVEs, RDAP WHOIS, Certificate Transparency subdomains, and HTTP security.",
      icon: Globe,
      accent: "border-border",
    },
    {
      step: "05",
      title: "Weighted Consensus",
      service: "verdyx-consensus-service",
      detail:
        "Combines automated engine detections and analyst votes, weighted by reputation and confidence.",
      icon: ShieldCheck,
      accent: "border-border",
    },
    {
      step: "06",
      title: "PostgreSQL & Live WebSocket Stream",
      service: "postgres + /ws pubsub relay",
      detail:
        "Persists per-engine telemetry to verdyx_gateway and pushes real-time completion frames to connected browsers.",
      icon: Database,
      accent: "border-border",
    },
  ];

  return (
    <div className="min-h-screen flex flex-col bg-background text-foreground">
      <SEO
        title="Analysis Dashboard — Verdyx Command Center"
        description="Submit files or URLs for 8-engine malware analysis, inspect 36+ website OSINT modules, and see how the backend pipeline works."
      />
      <Navigation />

      <main id="main-content" tabIndex={-1} className="relative z-10 flex-1 py-8 sm:py-10">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 space-y-8">
          {/* Dashboard Header */}
          <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-4 animate-fade-up">
            <div>
              <h1 className="text-3xl font-medium tracking-[-0.035em] sm:text-4xl">
                Analysis
              </h1>
              <p className="mt-2 max-w-xl text-sm leading-relaxed text-muted-foreground sm:text-base">
                Submit a file or a URL. Engine votes, the site report, and the quorum stay on the case.
              </p>
            </div>

            <div className="inline-flex items-center gap-2.5 self-start border border-border bg-card px-3 py-1.5 font-mono text-xs sm:self-auto">
              <span
                className={`h-2 w-2 ${statsUnavailable ? "bg-destructive" : isConnected ? "bg-success" : "bg-warning"}`}
              />
              <span>
                {statsUnavailable
                  ? "Live Data Unavailable"
                  : isConnected
                    ? "Live Stream Connected"
                    : "Refreshing Every 30s"}
              </span>
            </div>
          </div>

          {/* KPI Row */}
          <DashboardStats />

          {/* Clean, Structured Workspace Tabs */}
          <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-8">
            <TabsList className="grid w-full grid-cols-2 md:grid-cols-3 xl:grid-cols-6 h-auto p-1.5 gap-1.5 bg-card/70 border border-border/70 rounded-xl">
              <TabsTrigger value="scanner" className="flex items-center gap-2 py-2.5 text-xs sm:text-sm font-semibold">
                <Activity className="h-4 w-4" />
                Live Scanner &amp; Feed
              </TabsTrigger>
              <TabsTrigger value="web-intel" className="flex items-center gap-2 py-2.5 text-xs sm:text-sm font-semibold">
                <Globe className="h-4 w-4" />
                Website OSINT (36+)
              </TabsTrigger>
              <TabsTrigger value="yara" className="flex items-center gap-2 py-2.5 text-xs sm:text-sm font-semibold">
                <Binary className="h-4 w-4" />
                YARA Studio
              </TabsTrigger>
              <TabsTrigger value="compare" className="flex items-center gap-2 py-2.5 text-xs sm:text-sm font-semibold">
                <ArrowLeftRight className="h-4 w-4" />
                Scan Diff
              </TabsTrigger>
              <TabsTrigger value="pipeline" className="flex items-center gap-2 py-2.5 text-xs sm:text-sm font-semibold">
                <Cpu className="h-4 w-4" />
                Backend Pipeline
              </TabsTrigger>
              <TabsTrigger value="analytics" className="flex items-center gap-2 py-2.5 text-xs sm:text-sm font-semibold">
                <BarChart3 className="h-4 w-4" />
                Platform Analytics
              </TabsTrigger>
            </TabsList>

            {/* Tab 1: Live Scanner + Worker Telemetry + Recent Results */}
            <TabsContent value="scanner" className="space-y-6 animate-fade-in">
              <div className="grid lg:grid-cols-12 gap-6 items-start">
                <div className="lg:col-span-5">
                  <Card className="bento-card">
                    <CardHeader className="pb-4">
                      <div className="flex items-center justify-between">
                        <Badge variant="outline" className="font-mono text-[10px] border-primary/40 text-primary">
                          ARTIFACT &amp; URL INGESTION
                        </Badge>
                        <span className="text-xs font-mono text-accent flex items-center gap-1">
                          <Zap className="h-3 w-3" /> Instant Queue
                        </span>
                      </div>
                      <CardTitle className="flex items-center gap-2 text-xl font-display mt-2">
                        <Upload className="h-5 w-5 text-primary" />
                        Quick Submit
                      </CardTitle>
                      <CardDescription>
                        Upload a file, paste a phishing email, or scan a URL. Email checks SPF, DKIM, DMARC, and attachments.
                      </CardDescription>
                    </CardHeader>
                    <CardContent>
                      <FileSubmissionForm />
                    </CardContent>
                  </Card>
                </div>

                <div className="lg:col-span-7 space-y-6">
                  <RecentAnalyses />

                  {/* Illustrative walkthrough of the pipeline. Not connected to live data. */}
                  <Card>
                    <CardHeader className="pb-3 flex flex-row items-center justify-between">
                      <div>
                        <div className="flex items-center gap-2">
                          <Terminal className="h-4 w-4 text-accent" />
                          <CardTitle className="text-base font-display">
                            How a Scan Moves Through Verdyx
                          </CardTitle>
                        </div>
                        <CardDescription className="text-xs font-mono mt-0.5">
                          Example pipeline, not live data
                        </CardDescription>
                      </div>
                      <div className="flex items-center gap-1.5">
                        <span className="h-2 w-2 bg-mark" />
                      </div>
                    </CardHeader>
                    <CardContent>
                      <div className="rounded-sm border border-border bg-background p-3.5 font-mono text-xs space-y-2">
                        {liveAgentLogs.map((log, i) => {
                          const isActive = i === activeLogIdx;
                          return (
                            <div
                              key={log.action}
                              className={`flex flex-wrap items-center justify-between gap-2 px-2.5 py-1.5 rounded-lg transition-all duration-300 ${
                                isActive
                                  ? "bg-primary/15 border border-primary/40"
                                  : "opacity-65"
                              }`}
                            >
                              <div className="flex items-center gap-2 min-w-0">
                                <span className="text-muted-foreground text-[11px]">{log.ts}</span>
                                <Badge variant="outline" className="font-mono text-[10px] py-0 px-1.5">
                                  {log.node}
                                </Badge>
                                <span className={`font-semibold ${log.color}`}>{log.action}</span>
                              </div>
                              <span className="text-muted-foreground truncate text-[11px]">
                                {log.detail}
                              </span>
                            </div>
                          );
                        })}
                      </div>
                    </CardContent>
                  </Card>
                </div>
              </div>
            </TabsContent>

            {/* Tab 2: 36+ Module Website OSINT Recon (No default URL pre-filled) */}
            <TabsContent value="web-intel" className="space-y-6 animate-fade-in">
              <WebsiteIntelligencePanel />
            </TabsContent>

            <TabsContent value="yara" className="space-y-6 animate-fade-in">
              <YaraStudio />
            </TabsContent>

            <TabsContent value="compare" className="space-y-6 animate-fade-in">
              <ScanDiffPanel />
            </TabsContent>

            {/* Tab 3: 6-Stage Distributed Backend Pipeline */}
            <TabsContent value="pipeline" className="space-y-6 animate-fade-in">
              <div className="flex flex-wrap items-end justify-between gap-4">
                <div>
                  <span className="text-xs font-mono uppercase tracking-widest text-accent">
                    HOW VERDYX WORKS IN THE BACKEND
                  </span>
                  <h2 className="text-2xl sm:text-3xl font-extrabold font-display tracking-tight mt-1">
                    The path a file takes
                  </h2>
                </div>
                <ApiHealthBadge />
              </div>

              <div className="grid gap-5 md:grid-cols-2 lg:grid-cols-3">
                {pipelineStages.map((st) => {
                  const Icon = st.icon;
                  return (
                    <div
                      key={st.step}
                      className="rounded-sm border border-border bg-card p-6 space-y-3"
                    >
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2.5">
                          <div className="p-2.5 rounded-xl bg-background/80 border border-border text-primary">
                            <Icon className="h-5 w-5" />
                          </div>
                          <span className="font-mono text-xs font-bold tracking-wider text-primary">
                            STAGE {st.step}
                          </span>
                        </div>
                      </div>
                      <h3 className="text-lg font-bold font-display">{st.title}</h3>
                      <div className="font-mono text-xs text-accent flex items-center gap-1">
                        <Radio className="h-3 w-3" />
                        {st.service}
                      </div>
                      <p className="text-xs text-muted-foreground leading-relaxed">{st.detail}</p>
                    </div>
                  );
                })}
              </div>
            </TabsContent>

            {/* Tab 4: Platform Analytics */}
            <TabsContent value="analytics" className="space-y-6 animate-fade-in">
              <PlatformAnalytics />
            </TabsContent>
          </Tabs>
        </div>
      </main>

      <Footer tag="v2.1-dashboard" />
    </div>
  );
}
