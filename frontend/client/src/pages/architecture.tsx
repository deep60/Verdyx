import { Link } from "wouter";
import { useQuery } from "@tanstack/react-query";
import { ArrowRight, Boxes, Database, Gauge, Layers, Network, Radio, ShieldCheck, Workflow } from "lucide-react";
import { Navigation } from "@/components/navigation";
import { Footer } from "@/components/footer";
import { SEO } from "@/components/seo";
import { Button } from "@/components/ui/button";
import { LiveFlow } from "@/components/diagrams/live-flow";
import type { ApiEngine } from "@/lib/api-types";
import { engineState } from "@/lib/engines";

const SERVICES = [
  {
    icon: Network,
    name: "api-gateway",
    role: "The front door",
    text: "Sessions, API keys, rate limits and CSRF. Routes every call and holds the WebSocket.",
    stack: ["Rust", "axum", "WebSocket"],
  },
  {
    icon: Layers,
    name: "submission-service",
    role: "Ingest",
    text: "Hashes the upload, matches it to earlier scans, stores the bytes and queues the job.",
    stack: ["Rust", "S3", "Postgres"],
  },
  {
    icon: Workflow,
    name: "analysis-engine",
    role: "Every engine, in parallel",
    text: "Unpacks archives and runs hash, static, signature, YARA, heuristic, ClamAV, ML, URL and email checks.",
    stack: ["Rust", "tokio", "YARA"],
  },
  {
    icon: ShieldCheck,
    name: "consensus-service",
    role: "One verdict",
    text: "Majority of the engines that answered. Advisory and failed engines are named, never counted as clean.",
    stack: ["Rust", "Postgres"],
  },
  {
    icon: Gauge,
    name: "reputation-service",
    role: "Track record",
    text: "Keeps how often each engine agreed with the final verdict, so accuracy is measured, not claimed.",
    stack: ["Rust", "Redis"],
  },
  {
    icon: Radio,
    name: "notification-service",
    role: "Delivery",
    text: "Pushes results to the console as they land and delivers webhooks to your endpoints.",
    stack: ["Rust", "WebSocket", "Webhooks"],
  },
  {
    icon: Boxes,
    name: "user-service",
    role: "Accounts",
    text: "Accounts, teams, API keys and retention settings.",
    stack: ["Rust", "Postgres"],
  },
  {
    icon: Database,
    name: "Data",
    role: "State",
    text: "Postgres for records, Redis for jobs and caching, S3-compatible storage for the samples.",
    stack: ["Postgres", "Redis", "S3"],
  },
];

const IDEAS = [
  {
    n: "01",
    title: "The upload never waits",
    text: "A scan is a job on a queue. The API answers in milliseconds and the result follows over WebSocket.",
  },
  {
    n: "02",
    title: "Same bytes, every engine",
    text: "Each engine reads the stored sample by its SHA-256, so no engine sees a different file.",
  },
  {
    n: "03",
    title: "Every vote is kept",
    text: "The case stores each engine's verdict, confidence and evidence, including the ones that had no answer.",
  },
];

export default function Architecture() {
  const { data } = useQuery<ApiEngine[]>({ queryKey: ["/api/engines"], refetchInterval: 60_000 });
  const engines = Array.isArray(data) ? data : [];
  const voting = engines.filter((e) => engineState(e) === "voting").length;
  const advisory = engines.filter((e) => engineState(e) === "advisory").length;

  return (
    <div className="flex min-h-screen flex-col bg-background text-foreground">
      <SEO
        title="Architecture — Verdyx"
        description="Watch a scan move through Verdyx: API gateway, queue, every engine in parallel, then a consensus verdict, with engine states live."
      />
      <Navigation />

      <main id="main-content" tabIndex={-1} className="flex-1">
        {/* Hero */}
        <section className="border-b border-border">
          <div className="mx-auto grid max-w-7xl gap-8 px-4 pb-10 pt-12 sm:px-6 lg:grid-cols-12 lg:items-end lg:px-8 lg:pb-12 lg:pt-16">
            <div className="animate-fade-up lg:col-span-8">
              <p className="inline-flex items-center gap-2 font-mono text-[11px] uppercase tracking-[0.2em] text-muted-foreground">
                <span className="h-2 w-2 rounded-full bg-mark" aria-hidden />
                Architecture · live
              </p>
              <h1 className="mt-4 font-display text-[2.25rem] font-medium leading-[1.02] tracking-[-0.045em] text-balance sm:text-5xl lg:text-[3.6rem]">
                Follow one scan through <span className="mark-highlight">every engine</span>.
              </h1>
              <p className="mt-5 max-w-xl text-[15px] leading-relaxed text-foreground/80 sm:text-base">
                Seven Rust services, one queue, and a vote you can read. The replay below is an example scan; the engine
                dots and counts are live from the analysis engine.
              </p>
            </div>
            <dl className="grid animate-fade-up grid-cols-3 gap-px overflow-hidden rounded-lg border border-border bg-border [animation-delay:120ms] lg:col-span-4">
              {[
                { k: "Voting now", v: engines.length ? String(voting) : "—" },
                { k: "Advisory", v: engines.length ? String(advisory) : "—" },
                { k: "Services", v: "7" },
              ].map((s) => (
                <div key={s.k} className="bg-card px-4 py-3">
                  <dt className="text-[11px] text-muted-foreground">{s.k}</dt>
                  <dd className="mt-1 font-mono text-2xl tabular-nums">{s.v}</dd>
                </div>
              ))}
            </dl>
          </div>
        </section>

        {/* Flow */}
        <section className="border-b border-border" aria-label="Live flow">
          <div className="mx-auto max-w-7xl animate-fade-up px-4 py-10 [animation-delay:180ms] sm:px-6 lg:px-8 lg:py-14">
            <LiveFlow />
            <p className="mt-3 text-xs text-muted-foreground">
              Switch between a file, a URL and an email. Click a box to pin what that part does. On a phone, scroll the
              chart sideways.
            </p>
          </div>
        </section>

        {/* Ideas */}
        <section className="border-b border-border">
          <ol className="mx-auto grid max-w-7xl sm:grid-cols-3">
            {IDEAS.map((idea) => (
              <li
                key={idea.n}
                className="border-b border-border px-4 py-7 sm:border-b-0 sm:border-r sm:px-6 sm:last:border-r-0 lg:px-8"
              >
                <span className="font-mono text-xs text-mark-ink">{idea.n}</span>
                <h2 className="mt-2 text-lg font-medium tracking-[-0.03em]">{idea.title}</h2>
                <p className="mt-1.5 text-sm leading-relaxed text-muted-foreground">{idea.text}</p>
              </li>
            ))}
          </ol>
        </section>

        {/* Services */}
        <section className="border-b border-border">
          <div className="mx-auto max-w-7xl px-4 py-14 sm:px-6 lg:px-8 lg:py-20">
            <div className="max-w-xl">
              <h2 className="text-2xl font-medium tracking-[-0.03em] sm:text-3xl">The services</h2>
              <p className="mt-2 text-sm leading-relaxed text-muted-foreground">
                Each one is a small Rust binary with its own job. They talk over HTTP and Redis, and share Postgres.
              </p>
            </div>
            <ul className="mt-8 grid gap-px overflow-hidden rounded-lg border border-border bg-border sm:grid-cols-2 lg:grid-cols-4">
              {SERVICES.map(({ icon: Icon, ...s }) => (
                <li key={s.name} className="group flex flex-col bg-card p-5 transition-colors hover:bg-background">
                  <div className="flex items-center justify-between">
                    <span className="inline-flex h-9 w-9 items-center justify-center rounded-md bg-foreground text-background transition-colors group-hover:bg-mark group-hover:text-mark-foreground">
                      <Icon className="h-4 w-4" aria-hidden />
                    </span>
                    <span className="font-mono text-[10px] uppercase tracking-[0.14em] text-muted-foreground">
                      {s.role}
                    </span>
                  </div>
                  <h3 className="mt-4 font-mono text-sm font-medium">{s.name}</h3>
                  <p className="mt-1.5 flex-1 text-sm leading-relaxed text-muted-foreground">{s.text}</p>
                  <div className="mt-4 flex flex-wrap gap-1.5">
                    {s.stack.map((tag) => (
                      <span
                        key={tag}
                        className="rounded-sm border border-border px-1.5 py-0.5 font-mono text-[10px] text-muted-foreground"
                      >
                        {tag}
                      </span>
                    ))}
                  </div>
                </li>
              ))}
            </ul>
          </div>
        </section>

        {/* CTA */}
        <section>
          <div className="mx-auto max-w-7xl px-4 py-14 sm:px-6 lg:px-8 lg:py-16">
            <div className="flex flex-col gap-6 rounded-lg bg-foreground px-5 py-8 text-background sm:px-8 sm:py-10 lg:flex-row lg:items-end lg:justify-between">
              <div className="max-w-xl">
                <h2 className="text-2xl font-medium tracking-[-0.03em] sm:text-3xl">Send it a real sample.</h2>
                <p className="mt-2 text-sm leading-relaxed text-background/70">
                  The console shows every engine's vote for your scan as it lands, with the evidence behind it.
                </p>
              </div>
              <div className="flex flex-col gap-3 sm:flex-row">
                <Link href="/dashboard">
                  <Button size="lg" variant="mark" className="w-full sm:w-auto">
                    Open the console
                    <ArrowRight aria-hidden />
                  </Button>
                </Link>
                <Link href="/api">
                  <Button
                    size="lg"
                    variant="outline"
                    className="w-full border-background/25 bg-transparent text-background hover:bg-background/10 hover:text-background sm:w-auto"
                  >
                    CLI and API
                  </Button>
                </Link>
              </div>
            </div>
          </div>
        </section>
      </main>

      <Footer tag="architecture · live" />
    </div>
  );
}
