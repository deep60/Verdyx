import { useState } from "react";
import { Navigation } from "@/components/navigation";
import { ParticleBackground } from "@/components/particle-background";
import { DashboardStats, RecentAnalyses } from "@/components/analysis-dashboard";
import { FileSubmissionForm } from "@/components/file-submission-form";
import { PlatformAnalytics } from "@/components/platform-analytics";
import { WebsiteIntelligencePanel } from "@/components/website-intelligence-panel";
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
  ArrowRight,
} from "lucide-react";
import { useWebSocket } from "@/hooks/use-websocket";
import { SEO } from "@/components/seo";

export default function Dashboard() {
  const [activeTab, setActiveTab] = useState("overview");
  const { isConnected } = useWebSocket();

  const pipelineStages = [
    {
      step: "01",
      title: "API Gateway & SHA-256 Ingestion",
      service: "verdyx-api-gateway (Rust / Axum)",
      detail: "Validates multipart payload or target URL, computes cryptographic SHA-256/MD5/BLAKE2b hashes, and persists artifact metadata.",
      icon: Upload,
    },
    {
      step: "02",
      title: "Redis Priority Job Queue",
      service: "verdyx-redis (ZSET Queue)",
      detail: "Enqueues submission into priority-weighted Redis sorted set with automatic in-flight recovery and pub/sub event bus.",
      icon: Layers,
    },
    {
      step: "03",
      title: "Parallel 8-Engine Sandbox Execution",
      service: "verdyx-analysis-engine",
      detail: "Concurrently executes ClamAV daemon, YARA rules, Static PE/ELF Goblin parser, Byte-Entropy GBDT ML, Heuristic, Signature, and Hash Intel.",
      icon: Cpu,
    },
    {
      step: "04",
      title: "Deep Website OSINT & TLS/DNS Recon",
      service: "web_intel (DoH / Shodan / RDAP / CT)",
      detail: "Probes DNS-over-HTTPS, TLS cipher suites, Shodan InternetDB ports/CVEs, Certificate Transparency subdomains, and HTTP security headers.",
      icon: Globe,
    },
    {
      step: "05",
      title: "Stake-Weighted Bayesian Consensus",
      service: "verdyx-consensus-service",
      detail: "Aggregates multi-engine detections and community analyst votes weighted by accuracy reputation and staked ETH.",
      icon: ShieldCheck,
    },
    {
      step: "06",
      title: "PostgreSQL Persistence & Live WebSocket",
      service: "postgres + /ws pubsub relay",
      detail: "Writes per-engine telemetry to verdyx_gateway and broadcasts real-time completion frames over WebSocket.",
      icon: Database,
    },
  ];

  return (
    <div className="min-h-screen bg-background text-foreground">
      <SEO
        title="Live Threat Dashboard"
        description="Monitor live malware analyses, multi-engine consensus telemetry, and 36-module website OSINT reconnaissance."
      />
      <ParticleBackground />
      <Navigation />

      <main id="main-content" tabIndex={-1} className="relative z-10 py-10">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 space-y-8">
          {/* Page Header */}
          <div className="flex flex-col sm:flex-row sm:items-end sm:justify-between gap-4">
            <div>
              <h1 className="text-3xl md:text-4xl font-bold font-display tracking-[-0.03em]">
                Analysis Dashboard
              </h1>
              <p className="text-muted-foreground mt-1">
                Monitor real-time threat detection, backend engine execution pipeline, and deep website OSINT reconnaissance
              </p>
            </div>
            <div className="inline-flex items-center gap-2 self-start sm:self-auto rounded-full border border-border bg-card/60 px-3 py-1.5 text-xs font-medium">
              <span
                className={`h-2 w-2 rounded-full ${
                  isConnected ? "bg-accent animate-pulse" : "bg-muted-foreground"
                }`}
              />
              <span className="text-muted-foreground">
                {isConnected ? "Live Stream Connected" : "Polling Active"}
              </span>
            </div>
          </div>

          <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-8">
            <TabsList className="grid w-full max-w-2xl grid-cols-3">
              <TabsTrigger value="overview" className="flex items-center gap-2">
                <Activity className="h-4 w-4" />
                Live Analysis & Pipeline
              </TabsTrigger>
              <TabsTrigger value="web-intel" className="flex items-center gap-2">
                <Globe className="h-4 w-4" />
                Website OSINT Recon (36+)
              </TabsTrigger>
              <TabsTrigger value="analytics" className="flex items-center gap-2">
                <BarChart3 className="h-4 w-4" />
                Platform Analytics
              </TabsTrigger>
            </TabsList>

            <TabsContent value="overview" className="space-y-8">
              {/* Row 1: 4 uniform KPI cards */}
              <DashboardStats />

              {/* Row 2: Recent analyses (8 cols) + Quick Submit (4 cols) */}
              <div className="grid lg:grid-cols-12 gap-8 items-start">
                <div className="lg:col-span-7">
                  <RecentAnalyses />
                </div>
                <div className="lg:col-span-5">
                  <Card className="glassmorphism neon-border">
                    <CardHeader>
                      <CardTitle className="flex items-center gap-2 text-lg">
                        <Upload className="h-5 w-5 text-primary" />
                        Quick Submit
                      </CardTitle>
                      <CardDescription>
                        Send a binary file or website URL for multi-engine consensus & OSINT analysis.
                      </CardDescription>
                    </CardHeader>
                    <CardContent>
                      <FileSubmissionForm />
                    </CardContent>
                  </Card>
                </div>
              </div>

              {/* Row 3: How the Backend Pipeline Works in Real Time */}
              <Card className="glassmorphism border-primary/25">
                <CardHeader>
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div>
                      <CardTitle className="flex items-center gap-2 text-xl">
                        <Radio className="h-5 w-5 text-primary animate-pulse" />
                        Live Distributed Backend Execution Architecture
                      </CardTitle>
                      <CardDescription>
                        End-to-end microservice pipeline executing behind every file and URL scan
                      </CardDescription>
                    </div>
                    <Badge variant="outline" className="font-mono text-xs border-primary/40 text-primary">
                      9 Rust Microservices · 8 Security Engines · 36 OSINT Recon Probes
                    </Badge>
                  </div>
                </CardHeader>
                <CardContent>
                  <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
                    {pipelineStages.map((st, idx) => {
                      const Icon = st.icon;
                      return (
                        <div
                          key={st.step}
                          className="relative rounded-xl border border-border/60 bg-card/50 p-4 space-y-2 hover:border-primary/40 transition-colors"
                        >
                          <div className="flex items-center justify-between">
                            <div className="flex items-center gap-2">
                              <div className="p-2 rounded-lg bg-primary/10 text-primary">
                                <Icon className="h-4 w-4" />
                              </div>
                              <span className="font-mono text-xs text-primary font-bold">
                                STAGE {st.step}
                              </span>
                            </div>
                            {idx < pipelineStages.length - 1 && (
                              <ArrowRight className="h-3.5 w-3.5 text-muted-foreground hidden lg:block" />
                            )}
                          </div>
                          <div className="font-semibold text-sm">{st.title}</div>
                          <div className="font-mono text-[11px] text-accent">{st.service}</div>
                          <p className="text-xs text-muted-foreground leading-relaxed">
                            {st.detail}
                          </p>
                        </div>
                      );
                    })}
                  </div>
                </CardContent>
              </Card>
            </TabsContent>

            <TabsContent value="web-intel" className="space-y-8">
              <WebsiteIntelligencePanel />
            </TabsContent>

            <TabsContent value="analytics" className="space-y-8">
              <PlatformAnalytics />
            </TabsContent>
          </Tabs>
        </div>
      </main>
    </div>
  );
}
