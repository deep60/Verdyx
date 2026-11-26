import { Navigation } from "@/components/navigation";
import { Footer } from "@/components/footer";
import { Check, Minus } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Link } from "wouter";
import { SEO } from "@/components/seo";

const GITHUB_ISSUES = "https://github.com/deep60/Verdyx/issues/new";

/** What the free beta includes today. Every line maps to something running. */
const INCLUDED = [
  "File scans with every voting engine, per-engine evidence, and the consensus",
  "URL scans: redirect chain, TLS, DNS and mail auth, page checks, domain age, URLhaus, ThreatFox, VirusTotal and Google Safe Browsing",
  "Email scans: upload an .eml and get the headers, links and attachments checked",
  "36 website inspection checks",
  "Uploads up to 100 MB",
  "The CLI, Python and JavaScript SDKs, the GitHub Action and the REST API",
  "Private results: your scans are tied to your account",
];

/** Limits the gateway enforces today. Fair-use: heavy automated use may be throttled. */
const LIMITS = [
  ["File and URL scans", "10/min, 100/day"],
  ["Website inspections", "30/min, 300/day"],
  ["Upload size", "100 MB"],
  ["Sign-in attempts", "30 per 15 minutes"],
];

/** On the roadmap, not available yet. Listed so nobody pays for a promise. */
const NOT_YET = [
  "Paid plans and higher limits",
  "ClamAV signatures (being set up on a dedicated server)",
  "A trained ML model (today's model is advisory only)",
  "Sandbox (run-the-file) analysis",
];

const FAQ = [
  {
    q: "What happens when the beta ends?",
    a: "Paid plans will add higher limits and team features. They'll be announced on this page before anything changes for your account.",
  },
  {
    q: "Who can see my scans?",
    a: "Only you, and the teams you choose to save them to. Results are tied to your account and nobody else can list them.",
  },
  {
    q: "Can I use it in CI?",
    a: "Yes. The CLI and the GitHub Action exit with a failing code when a verdict reaches the level you choose, so a malicious artifact stops the build.",
  },
];

export default function Pricing() {
  return (
    <div className="min-h-screen bg-background text-muted-foreground font-sans selection:bg-primary/30">
      <SEO
        title="Pricing"
        description="Verdyx is free during the beta. Every live engine, URL scanning, and the API are included, with published rate limits."
      />
      <Navigation />

      <main id="main-content" tabIndex={-1} className="pb-20 pt-12 sm:pt-16">
        <div className="mx-auto max-w-5xl px-4 sm:px-6 lg:px-8">
          <div className="mb-12 max-w-xl animate-fade-up">
            <p className="font-mono text-[11px] uppercase tracking-[0.2em] text-muted-foreground">Pricing</p>
            <h1 className="mt-3 font-display text-4xl font-medium leading-[1.02] tracking-[-0.045em] text-foreground sm:text-6xl">
              Free during the beta
            </h1>
            <p className="mt-3 text-base leading-relaxed text-muted-foreground">
              No card, no credits. Everything that runs today is included. Paid plans will come with
              higher limits once there's something worth paying for, and they'll be announced here first.
            </p>
          </div>

          <div className="grid animate-fade-up gap-8 [animation-delay:120ms] lg:grid-cols-[minmax(0,3fr)_minmax(0,2fr)]">
            <section className="flex flex-col rounded-lg border border-border bg-card p-6 shadow-sm sm:p-8" aria-labelledby="beta-heading">
              <div className="mb-2 inline-flex w-fit border border-border px-2 py-1 font-mono text-[11px] uppercase tracking-[0.12em] text-muted-foreground">
                Beta
              </div>
              <h2 id="beta-heading" className="text-2xl font-medium tracking-[-0.03em] text-foreground">
                Everything that's live
              </h2>
              <div className="mt-3 flex items-baseline gap-2">
                <span className="font-display text-5xl font-medium tracking-[-0.04em] text-foreground">$0</span>
                <span className="font-mono text-sm text-muted-foreground">while in beta</span>
              </div>

              <ul className="mt-6 flex-grow space-y-3">
                {INCLUDED.map((feature) => (
                  <li key={feature} className="flex items-start gap-3">
                    <Check className="mt-0.5 h-4 w-4 shrink-0 text-primary" aria-hidden />
                    <span className="text-sm text-foreground/90">{feature}</span>
                  </li>
                ))}
              </ul>

              <Link href="/register">
                <Button className="mt-8 h-11 w-full">Create a free account</Button>
              </Link>
            </section>

            <div className="flex flex-col gap-8">
              <section className="rounded-lg border border-border p-6" aria-labelledby="limits-heading">
                <h2 id="limits-heading" className="text-base font-medium text-foreground">
                  Limits
                </h2>
                <dl className="mt-4 divide-y divide-border border-y border-border">
                  {LIMITS.map(([label, value]) => (
                    <div key={label} className="flex justify-between gap-4 py-2.5 text-sm">
                      <dt>{label}</dt>
                      <dd className="font-mono text-foreground">{value}</dd>
                    </div>
                  ))}
                </dl>
                <p className="mt-3 text-xs leading-relaxed">
                  Scan limits count per account, or per IP address when signed out. Going over returns
                  HTTP 429 with a <code className="font-mono">Retry-After</code> header.
                </p>
              </section>

              <section className="rounded-lg border border-border p-6" aria-labelledby="not-yet-heading">
                <h2 id="not-yet-heading" className="text-base font-medium text-foreground">
                  Not available yet
                </h2>
                <ul className="mt-4 space-y-2.5">
                  {NOT_YET.map((item) => (
                    <li key={item} className="flex items-start gap-3 text-sm">
                      <Minus className="mt-0.5 h-4 w-4 shrink-0" aria-hidden />
                      <span>{item}</span>
                    </li>
                  ))}
                </ul>
                <p className="mt-5 text-sm leading-relaxed">
                  Need higher limits or something on this list?{" "}
                  <a
                    href={GITHUB_ISSUES}
                    target="_blank"
                    rel="noreferrer"
                    className="text-foreground underline underline-offset-4"
                  >
                    Open an issue on GitHub
                  </a>
                  .
                </p>
              </section>
            </div>
          </div>

          <section className="mt-16 grid gap-8 border-t border-border pt-12 lg:grid-cols-3" aria-label="Questions">
            {FAQ.map((f) => (
              <div key={f.q}>
                <h2 className="text-base font-medium text-foreground">{f.q}</h2>
                <p className="mt-2 text-sm leading-relaxed">{f.a}</p>
              </div>
            ))}
          </section>
        </div>
      </main>
      <Footer tag="pricing" />
    </div>
  );
}
