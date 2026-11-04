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
  "URL scans: redirect chain, TLS, DNS and mail auth, page checks, URLhaus and ThreatFox",
  "36 website inspection checks",
  "Uploads up to 100 MB",
  "REST API with the same submissions as the console",
  "Private results: your scans are tied to your account",
];

/** Limits the gateway enforces today. Fair-use: heavy automated use may be throttled. */
const LIMITS = [
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
          <div className="mb-12 max-w-xl">
            <h1 className="text-3xl font-medium tracking-[-0.035em] text-foreground sm:text-5xl">
              Free during the beta
            </h1>
            <p className="mt-3 text-base leading-relaxed text-muted-foreground">
              No card, no credits. Everything that runs today is included. Paid plans will come with
              higher limits once there's something worth paying for, and they'll be announced here first.
            </p>
          </div>

          <div className="grid gap-8 lg:grid-cols-[minmax(0,3fr)_minmax(0,2fr)]">
            <section className="flex flex-col border border-border bg-card/50 p-6 sm:p-8" aria-labelledby="beta-heading">
              <div className="mb-2 inline-flex w-fit border border-border px-2 py-1 font-mono text-[11px] uppercase tracking-[0.12em] text-muted-foreground">
                Beta
              </div>
              <h2 id="beta-heading" className="text-2xl font-medium tracking-[-0.03em] text-foreground">
                Everything that's live
              </h2>
              <div className="mt-3 flex items-baseline gap-2">
                <span className="text-4xl font-medium text-foreground">$0</span>
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
              <section className="border border-border p-6" aria-labelledby="limits-heading">
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
                  Fair use applies: heavy automated scanning may be slowed down during the beta.
                </p>
              </section>

              <section className="border border-border p-6" aria-labelledby="not-yet-heading">
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
        </div>
      </main>
      <Footer tag="pricing" />
    </div>
  );
}
