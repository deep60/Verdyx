import { useState } from "react";
import { Navigation } from "@/components/navigation";
import { Footer } from "@/components/footer";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Key, Copy, Check, Play, Terminal, Globe, Webhook } from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import { SEO } from "@/components/seo";
import { apiRequest } from "@/lib/queryClient";
import { useAuth } from "@/contexts/auth-context";
import { useLocation } from "wouter";

const ENDPOINT_GROUPS = [
  {
    category: "Submissions & 8-Engine Scanning",
    items: [
      {
        method: "POST",
        path: "/api/v1/submissions/file",
        description: "Submit binary file, phishing email (.eml / MIME), or URL for 8-engine analysis",
        methodColor: "bg-accent text-accent-foreground",
      },
      {
        method: "POST",
        path: "/api/v1/submissions/:id/start-analysis",
        description: "Enqueue or re-trigger parallel execution across all 8 analyzer engines",
        methodColor: "bg-accent text-accent-foreground",
      },
      {
        method: "GET",
        path: "/api/v1/submissions/:id/analyses",
        description: "Retrieve per-engine detections, PE/ELF metadata, entropy, and MIME email forensics",
        methodColor: "bg-primary text-primary-foreground",
      },
      {
        method: "GET",
        path: "/api/v1/submissions/:id/consensus",
        description: "Get stake-weighted Bayesian consensus score and engine agreement breakdown",
        methodColor: "bg-primary text-primary-foreground",
      },
    ],
  },
  {
    category: "36-Module Website OSINT Reconnaissance",
    items: [
      {
        method: "GET",
        path: "/api/v1/analysis/web-intel?url=example.com",
        description: "Run live 36+ module OSINT recon (DoH DNS, TLS, Shodan ports/CVEs, RDAP WHOIS, HSTS, DOM)",
        methodColor: "bg-primary text-primary-foreground",
      },
      {
        method: "GET",
        path: "/api/v1/submissions/:id/web-intel",
        description: "Fetch cached or live 36-module Website Intelligence for a URL submission",
        methodColor: "bg-primary text-primary-foreground",
      },
    ],
  },
  {
    category: "Commit-Reveal Voting, Disputes & 30-Day Grading",
    items: [
      {
        method: "GET",
        path: "/api/v1/voting/bounty/:bountyId/phase",
        description: "Check active commit/reveal voting window and sealed commitment count",
        methodColor: "bg-primary text-primary-foreground",
      },
      {
        method: "POST",
        path: "/api/v1/voting/bounty/:bountyId/commit",
        description: "Seal a SHA-256 salted verdict commitment without leaking vote direction",
        methodColor: "bg-accent text-accent-foreground",
      },
      {
        method: "POST",
        path: "/api/v1/voting/bounty/:bountyId/reveal",
        description: "Reveal plaintext verdict, confidence, and salt after the commit window closes",
        methodColor: "bg-accent text-accent-foreground",
      },
      {
        method: "POST",
        path: "/api/v1/disputes/create",
        description: "Open a formal challenge against a finalized consensus verdict",
        methodColor: "bg-accent text-accent-foreground",
      },
      {
        method: "GET",
        path: "/api/v1/grades/:bountyId",
        description: "Retrieve 30-day delayed ground-truth re-scan grade and crowd overturn status",
        methodColor: "bg-primary text-primary-foreground",
      },
    ],
  },
  {
    category: "Reputation, Wallet & Outbound Webhooks",
    items: [
      {
        method: "GET",
        path: "/api/v1/reputation/standings",
        description: "Leaderboard rankings by historical accuracy, win streak, and staked ETH",
        methodColor: "bg-primary text-primary-foreground",
      },
      {
        method: "GET",
        path: "/api/v1/wallet/balance",
        description: "Fetch available ETH, active staked escrow, pending rewards, and total earned",
        methodColor: "bg-primary text-primary-foreground",
      },
      {
        method: "POST",
        path: "/api/v1/webhooks",
        description: "Register an HMAC-signed webhook endpoint with SSRF protection",
        methodColor: "bg-accent text-accent-foreground",
      },
    ],
  },
];

const PLAYGROUND_PRESETS = [
  { label: "Gateway Health", path: "/api/health" },
  { label: "Platform Stats", path: "/api/analysis/stats" },
  { label: "Security Engines (8)", path: "/api/engines" },
  { label: "Reputation Standings", path: "/api/reputation/standings" },
  { label: "Recent Submissions", path: "/api/submissions" },
  { label: "Website OSINT (example.com)", path: "/api/analysis/web-intel?url=https://example.com" },
];

export default function ApiDocs() {
  const { toast } = useToast();
  const { isAuthenticated } = useAuth();
  const [, setLocation] = useLocation();
  const [generatedKey, setGeneratedKey] = useState<string | null>(null);
  const [generating, setGenerating] = useState(false);

  // Interactive Playground state
  const [playPath, setPlayPath] = useState("/api/health");
  const [playStatus, setPlayStatus] = useState<number | null>(null);
  const [playLatency, setPlayLatency] = useState<number | null>(null);
  const [playOutput, setPlayOutput] = useState<string>(
    '// Click "Send Live Request" to inspect the real JSON response from your Verdyx gateway.'
  );
  const [playRunning, setPlayRunning] = useState(false);

  const copyToClipboard = async (text: string, label = "Code snippet copied successfully") => {
    try {
      await navigator.clipboard.writeText(text);
      toast({
        title: "Copied to clipboard",
        description: label,
      });
    } catch (_error) {
      toast({
        title: "Failed to copy",
        description: "Please copy manually",
        variant: "destructive",
      });
    }
  };

  const handleGenerateApiKey = async () => {
    if (!isAuthenticated) {
      toast({
        title: "Authentication required",
        description: "Please sign in to generate an API key.",
      });
      setLocation("/login");
      return;
    }

    setGenerating(true);
    try {
      const res = await apiRequest("POST", "/api/auth/api-key", {
        name: "Developer CLI Key",
      });
      const data = await res.json();
      if (data.api_key) {
        setGeneratedKey(data.api_key);
        toast({
          title: "API Key generated",
          description: "Copy and store your key securely — it is only shown once.",
        });
      }
    } catch (err) {
      toast({
        title: "Could not generate API key",
        description: err instanceof Error ? err.message : "Please try again",
        variant: "destructive",
      });
    } finally {
      setGenerating(false);
    }
  };

  const runPlayground = async (e?: React.FormEvent) => {
    e?.preventDefault();
    const targetPath = playPath.trim();
    if (!targetPath) return;
    setPlayRunning(true);
    const t0 = performance.now();
    try {
      const headers: Record<string, string> = { Accept: "application/json" };
      const token = localStorage.getItem("token");
      if (token) headers.Authorization = `Bearer ${token}`;
      const res = await fetch(targetPath, {
        method: "GET",
        headers,
        credentials: "include",
      });
      const elapsed = Math.round(performance.now() - t0);
      setPlayStatus(res.status);
      setPlayLatency(elapsed);
      const raw = await res.text();
      try {
        setPlayOutput(JSON.stringify(JSON.parse(raw), null, 2));
      } catch {
        setPlayOutput(raw);
      }
    } catch (err) {
      setPlayStatus(0);
      setPlayLatency(Math.round(performance.now() - t0));
      setPlayOutput(err instanceof Error ? err.message : "Request failed");
    } finally {
      setPlayRunning(false);
    }
  };

  const codeExample = `import hashlib, secrets, requests

API_KEY = "${generatedKey || "YOUR_API_KEY"}"
BASE = "https://api.verdyx.dev/api/v1"
HEADERS = {"Authorization": f"Bearer {API_KEY}"}

# 1. Submit a binary, .eml phishing message, or URL
resp = requests.post(
    f"{BASE}/submissions/file",
    headers=HEADERS,
    files={"file": open("suspicious_sample.exe", "rb")},
    data={"bountyAmount": "0.1", "analysisType": "full", "priority": "true"},
)
submission = resp.json()
sub_id = submission["id"]

# 2. Fetch 8-engine detections & Bayesian consensus
consensus = requests.get(f"{BASE}/submissions/{sub_id}/consensus", headers=HEADERS).json()
print("Verdict:", consensus["finalVerdict"], "Confidence:", consensus["confidenceScore"])

# 3. Seal a Commit-Reveal vote on a bounty
salt = secrets.token_hex(16)
preimage = f"{bounty_id}:{user_id}:malicious:0.9500:{salt}".encode()
commitment = hashlib.sha256(preimage).hexdigest()
requests.post(f"{BASE}/voting/bounty/{bounty_id}/commit", headers=HEADERS, json={
    "engine_id": user_id,
    "commitment": commitment,
})`;

  return (
    <div className="min-h-screen flex flex-col bg-background text-foreground">
      <SEO
        title="Developer API & Live Playground — Verdyx"
        description="Integrate Verdyx 8-engine malware analysis, 36-module Website OSINT, Commit-Reveal consensus, and HMAC webhooks into CI/CD and SOAR pipelines."
      />
      <Navigation />

      <div id="main-content" tabIndex={-1} className="relative z-10 flex-1 py-10">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 space-y-10">
          <div className="max-w-2xl">
            <h1 className="text-3xl font-medium tracking-[-0.035em] sm:text-5xl">
              API
            </h1>
            <p className="mt-3 text-base leading-relaxed text-muted-foreground">
              Submit a file or a URL, read the engine votes, and receive the quorum. Webhooks and the websocket carry the same case when the scan finishes.
            </p>
          </div>

          <Tabs defaultValue="reference" className="space-y-8">
            <TabsList className="grid w-full max-w-md mx-auto grid-cols-2">
              <TabsTrigger value="reference">API Reference &amp; Keys</TabsTrigger>
              <TabsTrigger value="playground" data-testid="tab-api-playground">
                <Terminal className="h-4 w-4 mr-1.5" />
                Live API Playground
              </TabsTrigger>
            </TabsList>

            {/* Tab 1: Complete Reference & SDK Snippet */}
            <TabsContent value="reference" className="space-y-8">
              <div className="grid lg:grid-cols-12 gap-8 items-start">
                <div className="lg:col-span-7 space-y-6">
                  {ENDPOINT_GROUPS.map((group) => (
                    <Card key={group.category} className="glassmorphism border-primary/20">
                      <CardHeader className="pb-3">
                        <CardTitle className="text-lg font-display">{group.category}</CardTitle>
                      </CardHeader>
                      <CardContent className="space-y-3">
                        {group.items.map((endpoint) => (
                          <div
                            key={`${endpoint.method}-${endpoint.path}`}
                            className="rounded-xl border border-border/70 bg-card/60 p-3.5 space-y-1.5"
                          >
                            <div className="flex flex-wrap items-center justify-between gap-2">
                              <Badge className={`font-mono text-xs ${endpoint.methodColor}`}>
                                {endpoint.method}
                              </Badge>
                              <code className="text-xs font-mono text-primary break-all">
                                {endpoint.path}
                              </code>
                            </div>
                            <p className="text-xs text-muted-foreground">{endpoint.description}</p>
                          </div>
                        ))}
                      </CardContent>
                    </Card>
                  ))}
                </div>

                <div className="lg:col-span-5 space-y-6">
                  <Card className="glassmorphism neon-border">
                    <CardHeader>
                      <div className="flex items-center justify-between">
                        <CardTitle className="text-lg">Python SDK &amp; Commit-Reveal Example</CardTitle>
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => copyToClipboard(codeExample)}
                          data-testid="button-copy-code"
                        >
                          <Copy className="w-4 h-4" />
                        </Button>
                      </div>
                      <CardDescription>
                        End-to-end example covering artifact upload, consensus lookup, and SHA-256 commit-reveal sealing.
                      </CardDescription>
                    </CardHeader>
                    <CardContent>
                      <div className="rounded-xl bg-background border border-border/80 p-4">
                        <pre className="text-xs font-mono text-[#141513] overflow-x-auto">
                          <code className="whitespace-pre-wrap text-[#141513]">{codeExample}</code>
                        </pre>
                      </div>

                      <div className="space-y-3 mt-6 text-xs">
                        <div className="flex items-center justify-between">
                          <span className="text-muted-foreground">Gateway Base Path</span>
                          <Badge variant="outline" className="font-mono">/api/v1</Badge>
                        </div>
                        <div className="flex items-center justify-between">
                          <span className="text-muted-foreground">Authentication</span>
                          <Badge variant="outline" className="font-mono">Bearer JWT / API Key</Badge>
                        </div>
                        <div className="flex items-center justify-between">
                          <span className="text-muted-foreground">Active Engines</span>
                          <Badge variant="outline" className="font-mono">8 Analyzers + MIME Email</Badge>
                        </div>
                      </div>

                      {generatedKey && (
                        <div className="mt-4 p-3 rounded-lg bg-primary/10 border border-primary/30 flex items-center justify-between gap-2">
                          <code
                            className="text-xs font-mono text-primary truncate"
                            data-testid="text-generated-api-key"
                          >
                            {generatedKey}
                          </code>
                          <Button
                            size="sm"
                            variant="ghost"
                            onClick={() => copyToClipboard(generatedKey, "API key copied to clipboard")}
                          >
                            <Check className="w-4 h-4 mr-1" />
                            Copy
                          </Button>
                        </div>
                      )}

                      <Button
                        className="w-full mt-6"
                        onClick={handleGenerateApiKey}
                        disabled={generating}
                        data-testid="button-get-api-key"
                      >
                        <Key className="w-4 h-4 mr-2" />
                        {generating
                          ? "Generating..."
                          : generatedKey
                            ? "Generate New API Key"
                            : "Get API Key"}
                      </Button>
                    </CardContent>
                  </Card>

                  <Card className="glassmorphism border-primary/20">
                    <CardHeader className="pb-2">
                      <CardTitle className="text-base flex items-center gap-2">
                        <Webhook className="h-4 w-4 text-primary" />
                        WebSocket &amp; Webhook Streams
                      </CardTitle>
                    </CardHeader>
                    <CardContent className="space-y-2 text-xs text-muted-foreground">
                      <p>
                        Subscribe to live browser events over <code className="text-accent font-mono">/ws</code> or configure HMAC-SHA256 webhooks in your Profile to push <code className="font-mono text-foreground">analysis.completed</code> and <code className="font-mono text-foreground">bounty.finalized</code> payloads to your SOAR.
                      </p>
                    </CardContent>
                  </Card>
                </div>
              </div>
            </TabsContent>

            {/* Tab 2: Live Interactive API Playground */}
            <TabsContent value="playground">
              <Card className="glassmorphism neon-border">
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Terminal className="h-5 w-5 text-primary" />
                    Interactive API Explorer
                  </CardTitle>
                  <CardDescription>
                    Execute live GET requests against your connected Verdyx API Gateway and inspect the status code, latency, and JSON payload.
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="flex flex-wrap gap-2">
                    {PLAYGROUND_PRESETS.map((preset) => (
                      <Button
                        key={preset.path}
                        type="button"
                        size="sm"
                        variant={playPath === preset.path ? "default" : "outline"}
                        className="text-xs font-mono"
                        onClick={() => setPlayPath(preset.path)}
                      >
                        {preset.label}
                      </Button>
                    ))}
                  </div>

                  <form onSubmit={runPlayground} className="flex flex-col sm:flex-row gap-2">
                    <div className="flex items-center gap-2 flex-1">
                      <Badge className="bg-primary text-primary-foreground font-mono">GET</Badge>
                      <Input
                        value={playPath}
                        onChange={(e) => setPlayPath(e.target.value)}
                        className="font-mono text-xs"
                        placeholder="/api/health"
                        data-testid="input-playground-path"
                      />
                    </div>
                    <Button type="submit" disabled={playRunning} data-testid="button-run-playground">
                      <Play className="h-4 w-4 mr-1.5" />
                      {playRunning ? "Running..." : "Send Live Request"}
                    </Button>
                  </form>

                  <div className="rounded-xl bg-background border border-border/80 p-4 space-y-3">
                    <div className="flex items-center justify-between border-b border-border/50 pb-2 text-xs font-mono text-[#141513]">
                      <div className="flex items-center gap-2">
                        <Globe className="h-3.5 w-3.5 text-[#141513]" />
                        <span className="font-semibold text-[#141513]">Response Payload</span>
                      </div>
                      <div className="flex items-center gap-2">
                        {playStatus !== null && (
                          <Badge
                            variant={playStatus >= 200 && playStatus < 300 ? "default" : "destructive"}
                          >
                            {playStatus === 0 ? "NETWORK ERROR" : `HTTP ${playStatus}`}
                          </Badge>
                        )}
                        {playLatency !== null && (
                          <Badge variant="outline" className="text-[#141513]">
                            {playLatency} ms
                          </Badge>
                        )}
                      </div>
                    </div>
                    <pre className="text-xs font-mono font-medium text-[#141513] max-h-[420px] overflow-auto whitespace-pre-wrap">
                      <code className="text-[#141513]">{playOutput}</code>
                    </pre>
                  </div>
                </CardContent>
              </Card>
            </TabsContent>
          </Tabs>
        </div>
      </div>

      <Footer tag="api-v1" />
    </div>
  );
}
