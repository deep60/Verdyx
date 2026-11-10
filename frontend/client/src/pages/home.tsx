import { Navigation } from "@/components/navigation";
import { ArchitectureDiagram } from "@/components/diagrams/ArchitectureDiagram";
import { CasePreview } from "@/components/case-preview";
import { Footer } from "@/components/footer";
import { Button } from "@/components/ui/button";
import { Link } from "wouter";
import { useEffect } from "react";
import { useQuery } from "@tanstack/react-query";
import { SEO } from "@/components/seo";
import type { ApiEngine } from "@/lib/api-types";
import { ENGINE_STATE_LABEL, engineState, votingEngines } from "@/lib/engines";

/** Shown until the live engine list loads, so the section is never empty. */
const FALLBACK_ENGINES: ApiEngine[] = [
  { id: "static", name: "Static Analyzer", description: "Executable header parsing (PE/ELF/Mach-O), section entropy, and string/IoC extraction" },
  { id: "hash", name: "Hash Analyzer", description: "SHA-256, MD5 and SHA-1, checked against MalwareBazaar" },
  { id: "heuristic", name: "Heuristic Engine", description: "Behavioral patterns that don't need a named signature" },
  { id: "signature", name: "Signature Matcher", description: "Known-bad byte sequences and packer names" },
  { id: "yara", name: "YARA Engine", description: "The YARA-Forge core rule pack, over 5,000 rules" },
  { id: "clamav", name: "ClamAV Scanner", description: "Signature sweep when a ClamAV server is connected" },
  { id: "ml", name: "Machine Learning Classifier", description: "Advisory only until it's trained on real data" },
];

const STATE_STYLE = {
  voting: "border-[#9CBFAE]/60 text-foreground",
  advisory: "border-[#E4C27A]/70 text-foreground",
  off: "border-border text-muted-foreground",
} as const;

const RECON: { name: string; detail: string }[] = [
  { name: "Network and host", detail: "IP, ASN, open ports, co-hosted names, redirect chain." },
  { name: "TLS and headers", detail: "Certificate, grade, HSTS, CSP, WAF, mixed content." },
  { name: "DNS and mail", detail: "Records, DNSSEC, SPF, DKIM, DMARC, RDAP, crt.sh." },
  { name: "Page and threats", detail: "Forms, scripts, trackers, blocklists, favicon hash." },
];

const STEPS = [
  { n: "1", title: "Ingest", text: "The gateway stores the file or URL with its SHA-256." },
  { n: "2", title: "Engines", text: "Every engine reads the same artifact, in parallel." },
  { n: "3", title: "Consensus", text: "A majority vote of the engines that returned a verdict. The rest are named, not counted." },
  { n: "4", title: "Report", text: "The case keeps each vote, its confidence, and the evidence behind it." },
];

const PRINCIPLES = [
  {
    title: "No invented verdicts",
    text: "A hash no source knows comes back as No verdict, not Clean. Confidence is what the engine reported, never a default.",
  },
  {
    title: "Advisory engines don't vote",
    text: "The ML model is shown on every case, but until it's trained on real data its prediction doesn't count.",
  },
  {
    title: "Failures are visible",
    text: "An engine that errors or is switched off is listed on the case with the reason, instead of silently counting as clean.",
  },
  {
    title: "Your scans are yours",
    text: "Submissions and results are tied to your account. Nobody else can list them.",
  },
];

function scrollToLocationHash() {
  const id = window.location.hash.replace(/^#/, "");
  if (!id) return;
  document.getElementById(id)?.scrollIntoView({ behavior: "smooth" });
}

export default function Home() {
  const { data: liveEngines } = useQuery<ApiEngine[]>({
    queryKey: ["/api/engines"],
  });
  const engines = liveEngines && liveEngines.length > 0 ? liveEngines : null;
  const voting = engines ? votingEngines(engines).length : null;

  useEffect(() => {
    scrollToLocationHash();
    window.addEventListener("hashchange", scrollToLocationHash);
    window.addEventListener("pushState", scrollToLocationHash);
    window.addEventListener("replaceState", scrollToLocationHash);
    return () => {
      window.removeEventListener("hashchange", scrollToLocationHash);
      window.removeEventListener("pushState", scrollToLocationHash);
      window.removeEventListener("replaceState", scrollToLocationHash);
    };
  }, []);

  return (
    <div className="flex min-h-screen flex-col bg-background text-foreground">
      <SEO
        title="Verdyx — Malware verdicts you can audit"
        description="Verdyx runs several engines on one file and shows every vote, its confidence, and the evidence. URL scans cover DNS, TLS, mail auth, and the page."
      />
      <Navigation />

      <main id="main-content" tabIndex={-1}>
        <section className="border-b border-border">
          <div className="mx-auto grid max-w-7xl items-start gap-10 px-4 py-10 sm:px-6 sm:py-14 lg:grid-cols-12 lg:gap-12 lg:px-8 lg:py-16">
            <div className="lg:col-span-5 lg:pt-2">
              <p className="text-sm text-muted-foreground">File and URL threat analysis</p>
              <h1 className="mt-3 text-[2rem] font-medium leading-[1.08] tracking-[-0.035em] text-balance sm:text-5xl lg:text-[3.15rem]">
                A malware verdict you can audit, engine by engine.
              </h1>
              <p className="mt-5 max-w-md text-[15px] leading-relaxed text-foreground/80 sm:text-base">
                Static parsing, YARA-Forge rules, hash reputation, heuristics, and signatures read the same file.
                Every engine's verdict, confidence, and evidence stays on the case, and an engine that can't
                give a verdict is named instead of counted.
              </p>
              <div className="mt-7 flex flex-col gap-3 sm:flex-row">
                <Link href="/dashboard">
                  <Button size="lg" className="w-full sm:w-auto">
                    Open the console
                  </Button>
                </Link>
                <Link href="/api">
                  <Button size="lg" variant="outline" className="w-full bg-transparent sm:w-auto">
                    API reference
                  </Button>
                </Link>
              </div>
              <dl className="mt-10 grid grid-cols-3 gap-3 border-t border-border pt-5">
                <div>
                  <dt className="text-xs text-muted-foreground">Voting engines</dt>
                  <dd className="mt-1 font-mono text-lg tabular-nums">{voting ?? "—"}</dd>
                </div>
                <div>
                  <dt className="text-xs text-muted-foreground">Site checks</dt>
                  <dd className="mt-1 font-mono text-lg tabular-nums">36</dd>
                </div>
                <div>
                  <dt className="text-xs text-muted-foreground">Price</dt>
                  <dd className="mt-1 font-mono text-lg">Free beta</dd>
                </div>
              </dl>
            </div>
            <div className="lg:col-span-7">
              <CasePreview />
            </div>
          </div>
        </section>

        <section className="border-b border-border" aria-label="How a case moves">
          <ol className="mx-auto grid max-w-7xl sm:grid-cols-2 lg:grid-cols-4">
            {STEPS.map((step) => (
              <li
                key={step.n}
                className="border-b border-border px-4 py-5 sm:px-6 sm:[&:nth-child(odd)]:border-r lg:border-b-0 lg:border-r lg:px-8 lg:py-6 lg:last:border-r-0"
              >
                <div className="font-mono text-xs text-muted-foreground">{step.n}</div>
                <h2 className="mt-2 text-lg font-medium tracking-[-0.03em]">{step.title}</h2>
                <p className="mt-1.5 text-sm leading-relaxed text-muted-foreground">{step.text}</p>
              </li>
            ))}
          </ol>
        </section>

        <section id="capabilities" className="scroll-mt-14 border-b border-border">
          <div className="mx-auto grid max-w-7xl gap-12 px-4 py-14 sm:px-6 lg:grid-cols-2 lg:gap-16 lg:px-8 lg:py-20">
            <div>
              <h2 className="text-2xl font-medium tracking-[-0.03em] sm:text-3xl">File engines</h2>
              <p className="mt-2 max-w-md text-sm leading-relaxed text-muted-foreground">
                Live status from the analysis engine. Only engines marked Votes count toward the verdict.
              </p>
              <ul className="mt-6 border-t border-border">
                {(engines ?? FALLBACK_ENGINES).map((engine) => {
                  const state = engines ? engineState(engine) : null;
                  return (
                    <li
                      key={engine.id}
                      className="grid gap-1 border-b border-border py-3 sm:grid-cols-[12rem_minmax(0,1fr)_auto] sm:items-baseline sm:gap-4"
                    >
                      <span className="text-sm font-medium">{engine.name}</span>
                      <span className="text-sm text-muted-foreground">{engine.description}</span>
                      {state && (
                        <span
                          className={`w-fit border px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-[0.08em] ${STATE_STYLE[state]}`}
                        >
                          {ENGINE_STATE_LABEL[state]}
                        </span>
                      )}
                    </li>
                  );
                })}
              </ul>
            </div>
            <div>
              <h2 className="text-2xl font-medium tracking-[-0.03em] sm:text-3xl">Site inspection</h2>
              <p className="mt-2 max-w-md text-sm leading-relaxed text-muted-foreground">
                A URL scan returns infrastructure, mail authentication, and a script-stripped look at the page. Favicons stay on the same host.
              </p>
              <ul className="mt-6 border-t border-border">
                {RECON.map((group) => (
                  <li key={group.name} className="border-b border-border py-4">
                    <h3 className="text-sm font-medium">{group.name}</h3>
                    <p className="mt-1 text-sm leading-relaxed text-muted-foreground">{group.detail}</p>
                  </li>
                ))}
              </ul>
              <Link
                href="/dashboard"
                className="mt-5 inline-block text-sm underline decoration-[#141513] underline-offset-4"
              >
                Run a URL in the console
              </Link>
            </div>
          </div>
        </section>

        <section id="architecture" className="scroll-mt-14 border-b border-border">
          <div className="mx-auto max-w-7xl px-4 py-14 sm:px-6 lg:px-8 lg:py-20">
            <div className="max-w-xl">
              <h2 className="text-2xl font-medium tracking-[-0.03em] sm:text-3xl">
                Where a submission goes
              </h2>
              <p className="mt-2 text-sm leading-relaxed text-muted-foreground">
                Gateway, queue, engines, then consensus. Hover a layer for what that service actually does.
              </p>
            </div>
            <div className="mt-8 overflow-x-auto">
              <ArchitectureDiagram />
            </div>
          </div>
        </section>

        <section className="border-b border-border" aria-labelledby="principles-heading">
          <div className="mx-auto max-w-7xl px-4 py-14 sm:px-6 lg:px-8 lg:py-20">
            <h2 id="principles-heading" className="text-2xl font-medium tracking-[-0.03em] sm:text-3xl">
              What a verdict here means
            </h2>
            <ul className="mt-8 grid border-t border-border sm:grid-cols-2 lg:grid-cols-4">
              {PRINCIPLES.map((p) => (
                <li
                  key={p.title}
                  className="border-b border-border py-5 sm:px-5 sm:[&:nth-child(odd)]:border-r lg:border-r lg:last:border-r-0 lg:first:pl-0"
                >
                  <h3 className="text-sm font-medium">{p.title}</h3>
                  <p className="mt-1.5 text-sm leading-relaxed text-muted-foreground">{p.text}</p>
                </li>
              ))}
            </ul>
          </div>
        </section>

        <section>
          <div className="mx-auto max-w-7xl px-4 py-14 sm:px-6 lg:px-8 lg:py-16">
            <div className="flex flex-col gap-6 border border-[#32342C] bg-[#141513] px-5 py-8 text-[#F3F1EA] sm:px-8 sm:py-10 lg:flex-row lg:items-end lg:justify-between">
              <div className="max-w-xl">
                <h2 className="text-2xl font-medium tracking-[-0.03em] sm:text-3xl">
                  Open a file or a URL.
                </h2>
                <p className="mt-2 text-sm leading-relaxed text-[#F3F1EA]/70">
                  The console keeps the engine votes, the site report, and the export. The API takes the same submission.
                </p>
              </div>
              <div className="flex flex-col gap-3 sm:flex-row">
                <Link href="/dashboard">
                  <Button size="lg" className="w-full bg-[#F3F1EA] text-[#141513] hover:bg-[#F3F1EA]/90 sm:w-auto">
                    Open the console
                  </Button>
                </Link>
                <Link href="/pricing">
                  <Button
                    size="lg"
                    variant="outline"
                    className="w-full border-[#32342C] bg-transparent text-[#F3F1EA] hover:bg-[#23251F] hover:text-[#F3F1EA] sm:w-auto"
                  >
                    Pricing
                  </Button>
                </Link>
              </div>
            </div>
          </div>
        </section>
      </main>

      <Footer tag="file · url · consensus" />
    </div>
  );
}
