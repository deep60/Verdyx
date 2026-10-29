import { Navigation } from "@/components/navigation";
import { ArchitectureDiagram } from "@/components/diagrams/ArchitectureDiagram";
import { ComparisonTable } from "@/components/tables/ComparisonTable";
import { CasePreview } from "@/components/case-preview";
import { Footer } from "@/components/footer";
import { Button } from "@/components/ui/button";
import { Link } from "wouter";
import { useEffect } from "react";
import { useQuery } from "@tanstack/react-query";
import { SEO } from "@/components/seo";
import type { ApiStats } from "@/lib/api-types";

const ENGINES: { name: string; detail: string }[] = [
  { name: "ClamAV", detail: "Signature sweep against the clamd rule set." },
  { name: "YARA 4.5", detail: "Pattern match on strings, hex, and conditions." },
  { name: "Goblin", detail: "PE and ELF imports, sections, and packer marks." },
  { name: "Byte entropy", detail: "Histogram and packing score for the whole file." },
  { name: "Heuristics", detail: "Behavioral flags that do not need a named signature." },
  { name: "Signatures", detail: "Known-bad byte sequences and packer names." },
  { name: "Hash intel", detail: "SHA-256 and related digests against prior cases." },
];

const RECON: { name: string; detail: string }[] = [
  { name: "Network and host", detail: "IP, ASN, open ports, co-hosted names, redirect chain." },
  { name: "TLS and headers", detail: "Certificate, grade, HSTS, CSP, WAF, mixed content." },
  { name: "DNS and mail", detail: "Records, DNSSEC, SPF, DKIM, DMARC, RDAP, crt.sh." },
  { name: "Page and threats", detail: "Forms, scripts, trackers, blocklists, favicon hash." },
];

const STEPS = [
  { n: "1", title: "Ingest", text: "The gateway stores the file or URL and the SHA-256." },
  { n: "2", title: "Engines", text: "The workers read the same artifact in parallel." },
  { n: "3", title: "Commit", text: "Each vote is sealed as a hash before anyone sees it." },
  { n: "4", title: "Reveal", text: "The case opens the votes and records the quorum." },
];

function scrollToLocationHash() {
  const id = window.location.hash.replace(/^#/, "");
  if (!id) return;
  document.getElementById(id)?.scrollIntoView({ behavior: "smooth" });
}

export default function Home() {
  const { data: stats } = useQuery<ApiStats>({
    queryKey: ["/api/analysis/stats"],
  });

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

  const indexed =
    typeof stats?.totalSubmissions === "number"
      ? stats.totalSubmissions.toLocaleString()
      : null;

  return (
    <div className="flex min-h-screen flex-col bg-background text-foreground">
      <SEO
        title="Verdyx — Malware verdicts you can audit"
        description="Verdyx runs eight engines on one file, seals each vote, then reveals the quorum. URL scans cover DNS, TLS, mail auth, and the page."
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
                ClamAV, YARA, static parsing, and the rest of the set read the same artifact.
                Each vote is hashed before it is shown. The case keeps the quorum, the confidence, and the evidence.
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
                  <dt className="text-xs text-muted-foreground">Engines</dt>
                  <dd className="mt-1 font-mono text-lg tabular-nums">8</dd>
                </div>
                <div>
                  <dt className="text-xs text-muted-foreground">Site checks</dt>
                  <dd className="mt-1 font-mono text-lg tabular-nums">36</dd>
                </div>
                <div>
                  <dt className="text-xs text-muted-foreground">
                    {indexed ? "Cases indexed" : "Vote"}
                  </dt>
                  <dd className="mt-1 font-mono text-lg tabular-nums">
                    {indexed ?? "Sealed"}
                  </dd>
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
                Always-on static, hash, heuristic, and signature passes. YARA, ClamAV, and the entropy model join the same case.
              </p>
              <ul className="mt-6 border-t border-border">
                {ENGINES.map((engine) => (
                  <li
                    key={engine.name}
                    className="grid gap-1 border-b border-border py-3 sm:grid-cols-[9.5rem_minmax(0,1fr)] sm:gap-4"
                  >
                    <span className="text-sm font-medium">{engine.name}</span>
                    <span className="text-sm text-muted-foreground">{engine.detail}</span>
                  </li>
                ))}
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

        <section className="border-b border-border">
          <div className="mx-auto max-w-7xl px-4 py-14 sm:px-6 lg:px-8 lg:py-20">
            <ComparisonTable />
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

      <Footer tag="file · url · quorum" />
    </div>
  );
}
