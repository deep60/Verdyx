import type { ReactNode } from "react";
import { Navigation } from "@/components/navigation";
import { Footer } from "@/components/footer";
import { SEO } from "@/components/seo";
import rawData from "@/data/benchmark.json";
import {
  BENCHMARK_DIR,
  MANIFEST_URL,
  REPO,
  fileTypeLabel,
  ofTotal,
  parseFamily,
  pct,
  runDate,
  shortEngine,
  sourceLabel,
  type BenchmarkData,
  type GroupResult,
  type Tally,
} from "@/lib/benchmark";

const data = rawData as BenchmarkData;

function Stat({ label, value, detail }: { label: string; value: string; detail: string }) {
  return (
    <div className="border border-border bg-card/50 p-6">
      <p className="font-mono text-[11px] uppercase tracking-[0.12em] text-muted-foreground">{label}</p>
      <p className="mt-2 text-4xl font-medium tracking-[-0.03em] text-foreground sm:text-5xl">{value}</p>
      <p className="mt-2 text-sm text-muted-foreground">{detail}</p>
    </div>
  );
}

function Section({ id, title, intro, children }: { id: string; title: string; intro?: ReactNode; children: ReactNode }) {
  return (
    <section className="mt-14" aria-labelledby={id}>
      <h2 id={id} className="text-xl font-medium tracking-[-0.02em] text-foreground">
        {title}
      </h2>
      {intro && <p className="mt-2 max-w-3xl text-sm leading-relaxed text-muted-foreground">{intro}</p>}
      <div className="mt-5">{children}</div>
    </section>
  );
}

/** A flagged rate, or "no verdict" when the engine never answered for the group. */
function Rate({ t }: { t: Tally | undefined }) {
  if (!t || !t.total) return <span className="text-muted-foreground">–</span>;
  return <>{pct(t.flagged, t.total)}</>;
}

function GroupTable({ caption, groups, first }: { caption: string; groups: GroupResult[]; first: string }) {
  const engines = data.engines.map((e) => e.name);
  return (
    <div className="overflow-x-auto border border-border">
      <table className="w-full min-w-[640px] text-sm">
        <caption className="sr-only">{caption}</caption>
        <thead>
          <tr className="border-b border-border text-left text-xs text-muted-foreground">
            <th scope="col" className="px-4 py-2.5 font-normal">{first}</th>
            <th scope="col" className="px-4 py-2.5 text-right font-normal">Files</th>
            <th scope="col" className="px-4 py-2.5 text-right font-medium text-foreground">Verdyx</th>
            {engines.map((e) => (
              <th key={e} scope="col" className="px-4 py-2.5 text-right font-normal">
                {shortEngine(e)}
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="divide-y divide-border">
          {groups.map((g) => (
            <tr key={g.name}>
              <th scope="row" className="px-4 py-2.5 text-left font-normal text-foreground">
                {first === "File type" ? fileTypeLabel(g.name) : sourceLabel(g.name)}
              </th>
              <td className="px-4 py-2.5 text-right font-mono">{g.consensus.total.toLocaleString("en-US")}</td>
              <td className="px-4 py-2.5 text-right font-mono font-medium text-foreground">
                <Rate t={g.consensus} />
              </td>
              {engines.map((e) => (
                <td key={e} className="px-4 py-2.5 text-right font-mono">
                  <Rate t={g.engines[e]} />
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default function Benchmark() {
  const { consensus: c, set } = data;
  const missed = data.missedFamilies.map(parseFamily);
  const commit = data.revision ? data.revision.slice(0, 7) : null;

  return (
    <div className="min-h-screen bg-background text-muted-foreground font-sans selection:bg-primary/30">
      <SEO
        title="Detection benchmark"
        description={`How often Verdyx flags known malware and wrongly flags clean software, measured on ${set.malicious} malware samples and ${set.clean.toLocaleString("en-US")} clean files.`}
        url="https://verdyx.dev/benchmark"
      />
      <Navigation />

      <main id="main-content" tabIndex={-1} className="pb-20 pt-12 sm:pt-16">
        <div className="mx-auto max-w-5xl px-4 sm:px-6 lg:px-8">
          <div className="max-w-2xl">
            <h1 className="text-3xl font-medium tracking-[-0.035em] text-foreground sm:text-5xl">Detection benchmark</h1>
            <p className="mt-3 text-base leading-relaxed">
              How often Verdyx flags known malware, and how often it wrongly flags clean software. Every number below
              comes from one run of the production engines over a fixed, public set of files. The weak spots are
              shown too.
            </p>
            <p className="mt-4 font-mono text-xs" data-testid="benchmark-run">
              Run on {runDate(data.ranAt)}
              {commit && (
                <>
                  {" · engine build "}
                  <a href={`${REPO}/commit/${data.revision}`} className="text-foreground underline underline-offset-4">
                    {commit}
                  </a>
                </>
              )}
              {" · ClamAV "}
              {data.clamav ? "on" : "off"}
              {" · hash lookups "}
              {data.feeds ? "on" : "off"}
            </p>
          </div>

          <div className="mt-10 grid gap-4 sm:grid-cols-2">
            <Stat
              label="Malware flagged"
              value={pct(c.malware.flagged, c.malware.total)}
              detail={`${ofTotal(c.malware.flagged, c.malware.total)} samples from ${set.families} families were called Malicious or Suspicious.`}
            />
            <Stat
              label="Clean files flagged"
              value={pct(c.clean.flagged, c.clean.total)}
              detail={`${ofTotal(c.clean.flagged, c.clean.total)} files from well-known software were wrongly called Malicious or Suspicious.`}
            />
          </div>

          {!data.feeds && (
            <p className="mt-4 max-w-3xl text-sm leading-relaxed">
              <span className="text-foreground">These are the engines on their own.</span> Every sample here is
              already listed on MalwareBazaar, so looking up its hash would catch all of them and prove nothing. Hash
              lookups (VirusTotal, MalwareBazaar) are switched off, and what's left is what the engines find in the
              file itself. That's what decides how Verdyx does on malware nobody has seen yet. On a real scan, the
              hash lookups run too.
            </p>
          )}

          <Section
            id="engines-heading"
            title="Each engine"
            intro={
              <>
                <span className="text-foreground">Verdyx</span> is the combined verdict, the one shown on a scan.
                Each engine below votes on it. Some only look at one kind of file, such as Office documents, so
                they're scored on those files alone.
              </>
            }
          >
            <div className="overflow-x-auto border border-border">
              <table className="w-full min-w-[560px] text-sm">
                <caption className="sr-only">Detection and false-positive rate per engine</caption>
                <thead>
                  <tr className="border-b border-border text-left text-xs text-muted-foreground">
                    <th scope="col" className="px-4 py-2.5 font-normal">Engine</th>
                    <th scope="col" className="px-4 py-2.5 text-right font-normal">Malware it checked</th>
                    <th scope="col" className="px-4 py-2.5 text-right font-normal">Malware flagged</th>
                    <th scope="col" className="px-4 py-2.5 text-right font-normal">Clean files flagged</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  <tr className="bg-card/50">
                    <th scope="row" className="px-4 py-2.5 text-left font-medium text-foreground">Verdyx (combined)</th>
                    <td className="px-4 py-2.5 text-right font-mono">{c.malware.total}</td>
                    <td className="px-4 py-2.5 text-right font-mono font-medium text-foreground">
                      {pct(c.malware.flagged, c.malware.total)}
                    </td>
                    <td className="px-4 py-2.5 text-right font-mono font-medium text-foreground">
                      {pct(c.clean.flagged, c.clean.total)}
                    </td>
                  </tr>
                  {data.engines.map((e) => (
                    <tr key={e.name}>
                      <th scope="row" className="px-4 py-2.5 text-left font-normal text-foreground">
                        {e.name}
                      </th>
                      <td className="px-4 py-2.5 text-right font-mono">{e.malware.total}</td>
                      <td className="px-4 py-2.5 text-right font-mono">{pct(e.malware.flagged, e.malware.total)}</td>
                      <td className="px-4 py-2.5 text-right font-mono">{pct(e.clean.flagged, e.clean.total)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <p className="mt-3 text-xs leading-relaxed">
              {data.notMeasured.length > 0 && (
                <>
                  Not measured in this run, because they weren't reachable from it or no sample was of their kind:{" "}
                  {data.notMeasured.join(", ")}.{" "}
                </>
              )}
              The generic ML engine isn't listed: its model is a placeholder that was never trained, so it doesn't
              vote.
            </p>
          </Section>

          <Section
            id="types-heading"
            title="Malware flagged, by file type"
            intro="Share of each kind of malware that was called Malicious or Suspicious."
          >
            <GroupTable caption="Malware flagged by file type" groups={data.byFileType} first="File type" />
          </Section>

          <Section
            id="clean-heading"
            title="Clean files flagged, by software"
            intro="Official releases, unpacked file by file. Any file flagged here is a false positive."
          >
            <GroupTable caption="Clean files flagged by software" groups={data.bySource} first="Software" />
            {data.falsePositives.length > 0 && (
              <details className="mt-4 border border-border p-4 text-sm">
                <summary className="cursor-pointer text-foreground">
                  The {data.falsePositives.length} clean {data.falsePositives.length === 1 ? "file" : "files"} Verdyx
                  flagged
                </summary>
                <ul className="mt-3 space-y-1.5">
                  {data.falsePositives.map((fp) => (
                    <li key={fp.file} className="flex flex-wrap justify-between gap-x-4">
                      <span className="break-all font-mono text-xs text-foreground">{fp.file}</span>
                      <span className="text-xs">{fp.engines.map(shortEngine).join(", ")}</span>
                    </li>
                  ))}
                </ul>
              </details>
            )}
          </Section>

          {missed.length > 0 && (
            <Section
              id="missed-heading"
              title="Families Verdyx missed entirely"
              intro={`In ${missed.length} of the ${set.families} families, no sample was flagged. This is where detection work goes next.`}
            >
              <ul className="flex flex-wrap gap-2" data-testid="missed-families">
                {missed.map((f) => (
                  <li key={f.name} className="border border-border px-2 py-1 font-mono text-xs text-foreground">
                    {f.name}
                    {f.samples > 1 && <span className="text-muted-foreground"> ×{f.samples}</span>}
                  </li>
                ))}
              </ul>
            </Section>
          )}

          <Section id="method-heading" title="How it's measured">
            <div className="grid gap-6 text-sm leading-relaxed md:grid-cols-2">
              <div className="space-y-3">
                <p>
                  <span className="text-foreground">Malware:</span> {set.malicious} samples from MalwareBazaar,
                  across {set.families} families, covering Windows programs, scripts, Office documents, Linux and
                  Android apps, shortcuts and PDFs. Each family is capped at 4 samples (10 for Linux), so no single
                  family can skew the result.
                </p>
                <p>
                  <span className="text-foreground">Clean files:</span> {set.clean.toLocaleString("en-US")} files
                  from official releases of Python, Git, PuTTY, Notepad++, Pester, PSScriptAnalyzer, jQuery and
                  Bootstrap, plus the Linux system programs in the engine's own image.
                </p>
                <p>
                  <span className="text-foreground">Flagged</span> means a Malicious or Suspicious verdict. Each
                  file is judged fresh, with no remembered verdicts from earlier files.
                </p>
                {set.skipped > 0 && (
                  <p>
                    {set.skipped} {set.skipped === 1 ? "sample" : "samples"} on the list couldn't be fetched or read
                    in this run and {set.skipped === 1 ? "isn't" : "aren't"} counted.
                  </p>
                )}
              </div>
              <div className="space-y-3">
                <p>
                  The samples are live malware, so they stay on the server: they're downloaded and read inside a
                  container, and never run.
                </p>
                <p>
                  The set is fixed: the{" "}
                  <a href={MANIFEST_URL} className="text-foreground underline underline-offset-4">
                    list of SHA-256 hashes
                  </a>{" "}
                  is public, so anyone can fetch the same files and check these numbers. The{" "}
                  <a href={BENCHMARK_DIR} className="text-foreground underline underline-offset-4">
                    benchmark program and scripts
                  </a>{" "}
                  are open source too.
                </p>
                <p>
                  Detection changes are checked against this set before they ship, and this page is updated from
                  the run.
                </p>
              </div>
            </div>
          </Section>
        </div>
      </main>
      <Footer tag="benchmark" />
    </div>
  );
}
