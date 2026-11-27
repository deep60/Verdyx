import { useState } from "react";
import { Link } from "wouter";
import { ArrowUpRight, Check, Copy, Globe, KeyRound, Play, Terminal } from "lucide-react";
import { Navigation } from "@/components/navigation";
import { Footer } from "@/components/footer";
import { SEO } from "@/components/seo";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { useAuth } from "@/contexts/auth-context";
import { cn } from "@/lib/utils";
import { BOUNTIES_ENABLED } from "@/lib/features";

const REPO = "https://github.com/deep60/Verdyx";

type Snippet = { id: string; label: string; install?: string; code: string; doc: string };

const QUICKSTART: Snippet[] = [
  {
    id: "cli",
    label: "CLI",
    install: "git clone https://github.com/deep60/Verdyx.git && cd Verdyx/sdk/typescript && npm link",
    code: `export VERDYX_API_KEY=vdx_...

verdyx scan suspicious.exe https://example.com/login

# MALICIOUS  suspicious.exe             3/4 voting engines flagged it
# CLEAN      https://example.com/login  0/3 voting engines flagged it

# In CI: exit code 2 when a verdict reaches --fail-on
verdyx scan --fail-on suspicious dist/*.exe`,
    doc: `${REPO}/tree/main/sdk/typescript#the-command`,
  },
  {
    id: "python",
    label: "Python",
    install: 'pip install "git+https://github.com/deep60/Verdyx.git#subdirectory=sdk/python"',
    code: `from verdyx import Verdyx

client = Verdyx()  # reads VERDYX_API_KEY

result = client.scan("suspicious.exe")
print(result.verdict)     # "malicious" | "suspicious" | "clean" | "unknown"
print(result.votes)       # {"malicious": 3, "suspicious": 0, "clean": 1, "total": 4}
print(result.report_url)  # https://verdyx.dev/analysis/...

for e in result.engines:
    print(e.name, e.verdict, e.reason)`,
    doc: `${REPO}/tree/main/sdk/python`,
  },
  {
    id: "js",
    label: "JavaScript",
    install: "git clone https://github.com/deep60/Verdyx.git && cd Verdyx/sdk/typescript && npm link",
    code: `import { Verdyx } from "verdyx";

const client = new Verdyx(); // reads VERDYX_API_KEY

const result = await client.scan("https://example.com/login");
console.log(result.verdict);   // "malicious" | "suspicious" | "clean" | "unknown"
console.log(result.votes);     // { malicious: 0, suspicious: 0, clean: 3, total: 3 }
console.log(result.reportUrl); // https://verdyx.dev/analysis/...`,
    doc: `${REPO}/tree/main/sdk/typescript#the-sdk`,
  },
  {
    id: "action",
    label: "GitHub Action",
    code: `# .github/workflows/scan.yml
- uses: deep60/Verdyx/action@main
  with:
    api-key: \${{ secrets.VERDYX_API_KEY }}
    paths: |
      dist/**/*.exe
      dist/**/*.dll
    urls: https://downloads.example.com/latest
    fail-on: malicious`,
    doc: `${REPO}/tree/main/action`,
  },
  {
    id: "mcp",
    label: "AI assistants",
    code: `# Let Claude, Cursor or any MCP client scan files and links
claude mcp add verdyx \\
  --env VERDYX_API_KEY=vdx_... \\
  --env VERDYX_MCP_ROOTS="$HOME/Downloads" \\
  -- verdyx mcp`,
    doc: `${REPO}/tree/main/sdk/typescript#mcp-server-for-ai-assistants`,
  },
  {
    id: "curl",
    label: "curl",
    code: `# 1. Submit a file (or -F url=https://... for a link)
curl -s https://api.verdyx.dev/api/v1/submissions/file \\
  -H "X-API-Key: $VERDYX_API_KEY" \\
  -F file=@suspicious.exe -F analysisType=full

# 2. Read the verdict and every engine's vote
curl -s https://api.verdyx.dev/api/v1/submissions/$ID/consensus \\
  -H "X-API-Key: $VERDYX_API_KEY"`,
    doc: `${REPO}#api`,
  },
];

type Endpoint = { method: "GET" | "POST"; path: string; description: string };
type Group = { title: string; items: Endpoint[] };

const ENDPOINTS: Group[] = [
  {
    title: "Scanning",
    items: [
      {
        method: "POST",
        path: "/submissions/file",
        description: "Submit a file, an .eml message (field file) or a link (field url). Returns the scan id.",
      },
      {
        method: "POST",
        path: "/submissions/email",
        description: "Submit a raw email as the body (message/rfc822). Its attachments are scanned and its links looked up.",
      },
      {
        method: "GET",
        path: "/submissions/:id",
        description: "Status of a scan: pending, analyzing, completed or failed.",
      },
      {
        method: "GET",
        path: "/submissions/:id/consensus",
        description: "The verdict, and how each voting engine voted.",
      },
      {
        method: "GET",
        path: "/submissions/:id/analyses",
        description: "Each engine's full result: detections, file metadata, entropy, email headers.",
      },
      {
        method: "GET",
        path: "/submissions/:id/similar",
        description: "Files that look like this one, by TLSH, ssdeep or imphash.",
      },
    ],
  },
  {
    title: "Websites",
    items: [
      {
        method: "GET",
        path: "/analysis/web-intel?url=",
        description: "Thirty-six checks on a site: DNS, TLS, open ports, WHOIS age, headers and page content.",
      },
      { method: "GET", path: "/submissions/:id/web-intel", description: "The same checks, saved with a link scan." },
    ],
  },
  {
    title: "Platform",
    items: [
      {
        method: "GET",
        path: "/engines",
        description: "Every engine and whether it's voting, advisory or off right now.",
      },
      { method: "POST", path: "/webhooks", description: "Get a signed POST to your endpoint when a scan finishes." },
    ],
  },
  ...(BOUNTIES_ENABLED
    ? [
        {
          title: "Analyst review (testnet)",
          items: [
            {
              method: "GET" as const,
              path: "/voting/bounty/:bountyId/phase",
              description: "Which review phase a bounty is in.",
            },
            {
              method: "POST" as const,
              path: "/voting/bounty/:bountyId/commit",
              description: "Submit a sealed vote.",
            },
            {
              method: "POST" as const,
              path: "/voting/bounty/:bountyId/reveal",
              description: "Open a sealed vote once voting closes.",
            },
          ],
        },
      ]
    : []),
];

const PLAYGROUND_PRESETS = [
  { label: "Health", path: "/api/health" },
  { label: "Engines", path: "/api/engines" },
  { label: "Platform stats", path: "/api/analysis/stats" },
  { label: "My scans", path: "/api/submissions" },
  { label: "Website checks", path: "/api/analysis/web-intel?url=https://example.com" },
];

function CopyButton({ text, label = "Copy" }: { text: string; label?: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      onClick={() => {
        void navigator.clipboard?.writeText(text).then(() => {
          setCopied(true);
          setTimeout(() => setCopied(false), 1500);
        });
      }}
      className="inline-flex items-center gap-1.5 rounded px-2 py-1 text-xs text-muted-foreground transition-colors hover:bg-muted/40 hover:text-foreground"
      aria-label={copied ? "Copied" : label}
    >
      {copied ? (
        <Check className="h-3.5 w-3.5 text-success" aria-hidden />
      ) : (
        <Copy className="h-3.5 w-3.5" aria-hidden />
      )}
      {copied ? "Copied" : label}
    </button>
  );
}

function CodeBlock({ code, title }: { code: string; title?: string }) {
  return (
    <div className="overflow-hidden rounded-lg border border-border bg-background">
      <div className="flex items-center justify-between border-b border-border px-3 py-1.5">
        <span className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted-foreground">{title ?? ""}</span>
        <CopyButton text={code} />
      </div>
      <pre className="overflow-x-auto p-4 text-[13px] leading-relaxed">
        <code className="font-mono text-foreground">{code}</code>
      </pre>
    </div>
  );
}

function MethodTag({ method }: { method: Endpoint["method"] }) {
  return (
    <span
      className={cn(
        "inline-flex w-12 shrink-0 justify-center rounded px-1.5 py-0.5 font-mono text-[11px] font-medium",
        method === "GET" ? "bg-muted/50 text-foreground" : "bg-foreground text-background",
      )}
    >
      {method}
    </span>
  );
}

export default function ApiDocs() {
  const { isAuthenticated } = useAuth();
  const [lang, setLang] = useState(QUICKSTART[0].id);
  const snippet = QUICKSTART.find((s) => s.id === lang) ?? QUICKSTART[0];

  const [playPath, setPlayPath] = useState("/api/engines");
  const [playStatus, setPlayStatus] = useState<number | null>(null);
  const [playLatency, setPlayLatency] = useState<number | null>(null);
  const [playOutput, setPlayOutput] = useState("// Pick a request and send it to see the live response.");
  const [playRunning, setPlayRunning] = useState(false);

  const runPlayground = async (e?: React.FormEvent) => {
    e?.preventDefault();
    const target = playPath.trim();
    // Same-origin API paths only: the playground is for reading Verdyx, not for fetching arbitrary URLs.
    if (!target.startsWith("/api/")) {
      setPlayStatus(null);
      setPlayOutput("// Paths start with /api/, for example /api/engines");
      return;
    }
    setPlayRunning(true);
    const t0 = performance.now();
    try {
      const res = await fetch(target, { headers: { Accept: "application/json" }, credentials: "include" });
      setPlayStatus(res.status);
      setPlayLatency(Math.round(performance.now() - t0));
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

  const keyHref = isAuthenticated ? "/profile#developer" : "/login?redirect=%2Fprofile%23developer";

  return (
    <div className="flex min-h-screen flex-col bg-background text-foreground">
      <SEO
        title="API, CLI and SDKs — Verdyx"
        description="Scan files and links from your terminal, your code, your CI or your AI assistant. A CLI, Python and JavaScript SDKs, a GitHub Action and a REST API."
      />
      <Navigation />

      <main id="main-content" tabIndex={-1} className="relative z-10 flex-1 pb-20 pt-10 sm:pt-14">
        <div className="mx-auto max-w-6xl space-y-16 px-4 sm:px-6 lg:px-8">
          {/* Hero */}
          <header className="grid animate-fade-up gap-8 lg:grid-cols-12 lg:items-end">
            <div className="lg:col-span-7">
              <p className="inline-flex items-center gap-2 font-mono text-[11px] uppercase tracking-[0.2em] text-muted-foreground">
                <span className="h-2 w-2 rounded-full bg-mark" aria-hidden />
                Developers
              </p>
              <h1 className="mt-3 font-display text-4xl font-medium leading-[1.02] tracking-[-0.045em] sm:text-6xl">
                Scan from anywhere you ship.
              </h1>
              <p className="mt-4 max-w-xl text-base leading-relaxed text-muted-foreground">
                One command in your terminal, three lines in your code, or one step in CI. Every scan runs every engine
                and comes back with the verdict and each engine's reason.
              </p>
            </div>
            <div className="flex flex-wrap gap-2 lg:col-span-5 lg:justify-end">
              <Button asChild size="lg" variant="mark" data-testid="button-get-api-key">
                <Link href={keyHref}>
                  <KeyRound className="mr-2 h-4 w-4" aria-hidden />
                  Get an API key
                </Link>
              </Button>
              <Button asChild size="lg" variant="outline">
                <a href={`${REPO}/tree/main/sdk`} target="_blank" rel="noreferrer">
                  SDKs on GitHub
                  <ArrowUpRight className="ml-1.5 h-4 w-4" aria-hidden />
                </a>
              </Button>
            </div>
          </header>

          {/* Quickstart */}
          <section aria-labelledby="quickstart" className="animate-fade-up [animation-delay:120ms]">
            <div className="mb-5 flex flex-wrap items-end justify-between gap-3">
              <div>
                <h2 id="quickstart" className="text-xl font-medium tracking-tight">
                  Quickstart
                </h2>
                <p className="mt-1 text-sm text-muted-foreground">
                  Create a key with the <code className="font-mono text-foreground">read</code> and{" "}
                  <code className="font-mono text-foreground">scan</code> scopes, set{" "}
                  <code className="font-mono text-foreground">VERDYX_API_KEY</code>, and run one of these.
                </p>
              </div>
            </div>

            <Card className="overflow-hidden">
              <div
                className="flex gap-1 overflow-x-auto border-b border-border px-2 [&::-webkit-scrollbar]:hidden"
                role="tablist"
                aria-label="Language"
              >
                {QUICKSTART.map((s) => (
                  <button
                    key={s.id}
                    type="button"
                    role="tab"
                    aria-selected={lang === s.id}
                    onClick={() => setLang(s.id)}
                    data-testid={`quickstart-${s.id}`}
                    className={cn(
                      "relative shrink-0 px-3 py-3 text-sm transition-colors",
                      "after:absolute after:inset-x-2 after:-bottom-px after:h-0.5 after:rounded-full after:bg-foreground after:transition-transform after:duration-300 after:ease-expo-out",
                      lang === s.id
                        ? "text-foreground after:scale-x-100"
                        : "text-muted-foreground after:scale-x-0 hover:text-foreground",
                    )}
                  >
                    {s.label}
                  </button>
                ))}
              </div>
              <div key={snippet.id} className="animate-fade-in space-y-4 p-4 sm:p-6">
                {snippet.install && <CodeBlock title="Install" code={snippet.install} />}
                <CodeBlock title={snippet.install ? "Use" : snippet.label} code={snippet.code} />
                <a
                  href={snippet.doc}
                  target="_blank"
                  rel="noreferrer"
                  className="inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground"
                >
                  Full {snippet.label} guide
                  <ArrowUpRight className="h-3.5 w-3.5" aria-hidden />
                </a>
              </div>
            </Card>
          </section>

          {/* Reference */}
          <section aria-labelledby="reference" className="grid gap-10 lg:grid-cols-12">
            <div className="lg:col-span-4">
              <h2 id="reference" className="text-xl font-medium tracking-tight">
                REST API
              </h2>
              <p className="mt-2 text-sm leading-relaxed text-muted-foreground">
                The clients above wrap these. Send your key in the{" "}
                <code className="font-mono text-foreground">X-API-Key</code> header.
              </p>
              <dl className="mt-6 divide-y divide-border rounded-lg border border-border text-sm">
                {[
                  ["Base URL", "https://api.verdyx.dev/api/v1"],
                  ["Auth", "X-API-Key header"],
                  ["Format", "JSON · multipart for uploads"],
                  ["Live updates", "Webhooks or /ws"],
                ].map(([k, v]) => (
                  <div key={k} className="flex items-baseline justify-between gap-4 px-4 py-2.5">
                    <dt className="shrink-0 text-muted-foreground">{k}</dt>
                    <dd className="min-w-0 break-all text-right font-mono text-xs">{v}</dd>
                  </div>
                ))}
              </dl>
              <p className="mt-4 text-xs leading-relaxed text-muted-foreground">
                Webhooks are signed with HMAC-SHA256. Set them up under{" "}
                <Link href="/profile#developer" className="text-foreground underline-offset-2 hover:underline">
                  API and webhooks
                </Link>{" "}
                on your profile. Reads retry safely on 429; uploads don't, so a lost response never makes a second scan.
              </p>
            </div>

            <div className="space-y-8 lg:col-span-8">
              {ENDPOINTS.map((group) => (
                <div key={group.title}>
                  <h3 className="mb-2 font-mono text-[11px] uppercase tracking-[0.18em] text-muted-foreground">
                    {group.title}
                  </h3>
                  <Card className="divide-y divide-border overflow-hidden">
                    {group.items.map((e) => (
                      <div
                        key={`${e.method}-${e.path}`}
                        className="flex flex-col gap-1.5 px-4 py-3 transition-colors hover:bg-muted/20 sm:flex-row sm:items-baseline sm:gap-4"
                      >
                        <div className="flex min-w-0 items-center gap-3 sm:w-[46%] sm:shrink-0">
                          <MethodTag method={e.method} />
                          <code className="truncate font-mono text-[13px]">{e.path}</code>
                        </div>
                        <p className="text-sm text-muted-foreground">{e.description}</p>
                      </div>
                    ))}
                  </Card>
                </div>
              ))}
            </div>
          </section>

          {/* Playground */}
          <section aria-labelledby="playground">
            <div className="mb-5">
              <h2 id="playground" className="flex items-center gap-2 text-xl font-medium tracking-tight">
                <Terminal className="h-5 w-5" aria-hidden />
                Try it live
              </h2>
              <p className="mt-1 text-sm text-muted-foreground">
                Read-only requests against Verdyx, sent with your browser session.
              </p>
            </div>
            <Card className="space-y-4 p-4 sm:p-6">
              <div className="flex flex-wrap gap-2">
                {PLAYGROUND_PRESETS.map((p) => (
                  <button
                    key={p.path}
                    type="button"
                    onClick={() => setPlayPath(p.path)}
                    className={cn(
                      "rounded-md border px-2.5 py-1 text-xs transition-colors",
                      playPath === p.path
                        ? "border-foreground bg-foreground text-background"
                        : "border-border text-muted-foreground hover:border-foreground/40 hover:text-foreground",
                    )}
                  >
                    {p.label}
                  </button>
                ))}
              </div>
              <form onSubmit={runPlayground} className="flex flex-col gap-2 sm:flex-row">
                <div className="flex flex-1 items-center gap-2 rounded-md border border-input bg-background pl-2 focus-within:ring-2 focus-within:ring-ring">
                  <MethodTag method="GET" />
                  <Input
                    value={playPath}
                    onChange={(e) => setPlayPath(e.target.value)}
                    className="border-0 font-mono text-xs shadow-none focus-visible:ring-0"
                    placeholder="/api/engines"
                    aria-label="Request path"
                    data-testid="input-playground-path"
                  />
                </div>
                <Button type="submit" disabled={playRunning} data-testid="button-run-playground">
                  <Play className="mr-1.5 h-4 w-4" aria-hidden />
                  {playRunning ? "Sending…" : "Send"}
                </Button>
              </form>
              <div className="overflow-hidden rounded-lg border border-border bg-background">
                <div className="flex items-center justify-between border-b border-border px-3 py-1.5 font-mono text-[11px] text-muted-foreground">
                  <span className="inline-flex items-center gap-1.5">
                    <Globe className="h-3.5 w-3.5" aria-hidden />
                    Response
                  </span>
                  <span className="flex items-center gap-3">
                    {playStatus !== null && (
                      <span
                        className={cn(
                          "inline-flex items-center gap-1.5",
                          playStatus >= 200 && playStatus < 300 ? "text-success" : "text-destructive",
                        )}
                      >
                        <span className="h-1.5 w-1.5 rounded-full bg-current" aria-hidden />
                        {playStatus === 0 ? "Network error" : `HTTP ${playStatus}`}
                      </span>
                    )}
                    {playLatency !== null && <span>{playLatency} ms</span>}
                  </span>
                </div>
                <pre className="max-h-[420px] overflow-auto whitespace-pre-wrap p-4 text-xs leading-relaxed">
                  <code className="font-mono text-foreground">{playOutput}</code>
                </pre>
              </div>
            </Card>
          </section>
        </div>
      </main>

      <Footer tag="api · v1" />
    </div>
  );
}
