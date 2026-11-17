import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { AlertTriangle, Code2, FileText, Link2, Lock, Package, Play, Rocket } from "lucide-react";
import type { ApiAnalysis } from "@/lib/api-types";

/** Engine name the analysis engine reports for PDFs. */
export const PDF_ENGINE_NAME = "PDF Analyzer";

interface Indicator {
  kind?: string;
  keyword?: string;
  description?: string;
}

interface Script {
  object?: string;
  automatic?: boolean;
  bytes?: number;
  preview?: string;
}

interface AutoAction {
  trigger?: string;
  action?: string;
  target?: string | null;
}

interface LaunchAction {
  object?: string;
  target?: string | null;
  parameters?: string | null;
  automatic?: boolean;
  runsCommand?: boolean;
}

interface EmbeddedFile {
  name?: string | null;
  bytes?: number;
  kind?: string | null;
  executable?: boolean;
}

interface Structure {
  version?: string | null;
  headerOffset?: number;
  objects?: number;
  objectStreams?: number;
  pages?: number;
  incrementalUpdates?: number;
  trailingBytes?: number;
  encrypted?: boolean;
  polyglot?: string | null;
}

export const KIND_LABEL: Record<string, string> = {
  autorun: "Runs on open",
  exploit: "Exploit",
  shellcode: "Shellcode",
  obfuscation: "Obfuscation",
  launch: "Launches",
  drop: "Drops a file",
  network: "Network",
  evasion: "Hiding",
  embedded: "Embedded",
};

/** Indicator kinds shown in red. */
export const DANGEROUS_KINDS = new Set(["exploit", "shellcode", "launch", "drop", "autorun"]);

/** What triggers an automatic action, in words. */
export function triggerLabel(trigger?: string): string {
  if (trigger === "OpenAction") return "when the document opens";
  if (trigger === "AA") return "when a page opens";
  return "automatically";
}

function asArray<T>(value: unknown): T[] {
  return Array.isArray(value) ? (value as T[]) : [];
}

function strings(value: unknown): string[] {
  return asArray<unknown>(value).filter((v): v is string => typeof v === "string" && v.length > 0);
}

function formatBytes(n?: number): string {
  if (!n) return "0 B";
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

export function hasPdfAnalysis(analyses: ApiAnalysis[]): boolean {
  return analyses.some((a) => a.engine?.name === PDF_ENGINE_NAME);
}

export function PdfForensicsPanel({ analyses }: { analyses: ApiAnalysis[] }) {
  const pdf = analyses.find((a) => a.engine?.name === PDF_ENGINE_NAME);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const raw = (pdf as Record<string, any> | undefined)?.metadata;
  const meta: Record<string, unknown> = raw && typeof raw === "object" && !Array.isArray(raw) ? raw : {};

  if (!pdf) {
    return (
      <Card className="glassmorphism">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <FileText className="h-5 w-5 text-primary" />
            PDF forensics
          </CardTitle>
          <CardDescription>Waiting for the PDF analyzer to finish.</CardDescription>
        </CardHeader>
      </Card>
    );
  }

  const summary = typeof meta.summary === "string" ? meta.summary : "";
  const s: Structure =
    meta.pdfStructure && typeof meta.pdfStructure === "object" ? (meta.pdfStructure as Structure) : {};
  const indicators = asArray<Indicator>(meta.indicators);
  const scripts = asArray<Script>(meta.scripts);
  const autoActions = asArray<AutoAction>(meta.autoActions);
  const launches = asArray<LaunchAction>(meta.launchActions);
  const files = asArray<EmbeddedFile>(meta.embeddedFiles);
  const uris = strings(meta.uris);
  const unc = strings(meta.uncPaths);
  const escaped = strings(meta.hexEscapedNames);
  const keywords =
    meta.pdfKeywords && typeof meta.pdfKeywords === "object" ? (meta.pdfKeywords as Record<string, number>) : {};
  const errors = strings(meta.parseErrors);

  return (
    <div className="space-y-6" data-testid="pdf-forensics">
      <Card className="glassmorphism border-primary/20">
        <CardContent className="space-y-2 p-4 text-sm">
          <div className="flex flex-wrap items-center gap-2">
            <Badge variant="outline" className="font-mono">
              PDF {s.version ?? ""}
            </Badge>
            {s.encrypted && (
              <Badge variant="secondary" className="gap-1">
                <Lock className="h-3 w-3" /> Encrypted
              </Badge>
            )}
            <Badge variant="outline">{s.pages ?? 0} page(s)</Badge>
            <Badge variant="outline">{s.objects ?? 0} objects</Badge>
            {(s.objectStreams ?? 0) > 0 && <Badge variant="outline">{s.objectStreams} compressed object stream(s)</Badge>}
            {(s.incrementalUpdates ?? 0) > 0 && <Badge variant="outline">{s.incrementalUpdates} later edit(s)</Badge>}
            {s.polyglot && <Badge variant="destructive">{s.polyglot}</Badge>}
          </div>
          {summary && <p className="text-muted-foreground">{summary}</p>}
        </CardContent>
      </Card>

      <div className="grid gap-6 lg:grid-cols-2">
        <Card className="glassmorphism">
          <CardHeader className="pb-3">
            <CardTitle className="flex items-center gap-2 text-base">
              <AlertTriangle className="h-4 w-4 text-primary" />
              Findings ({indicators.length})
            </CardTitle>
            <CardDescription>What the file's scripts and actions can do</CardDescription>
          </CardHeader>
          <CardContent>
            {indicators.length === 0 ? (
              <p className="text-xs text-muted-foreground">Nothing risky found.</p>
            ) : (
              <ul className="space-y-1.5">
                {indicators.map((ind, i) => (
                  <li
                    key={`${ind.kind}-${ind.keyword}-${i}`}
                    className="flex items-start justify-between gap-3 rounded border border-border/60 bg-muted/20 px-2.5 py-1.5 text-xs"
                  >
                    <span className="min-w-0">
                      <span className="break-all font-mono">{ind.keyword}</span>
                      <span className="text-muted-foreground"> · {ind.description}</span>
                    </span>
                    <Badge
                      variant={DANGEROUS_KINDS.has(ind.kind ?? "") ? "destructive" : "secondary"}
                      className="shrink-0 text-[10px]"
                    >
                      {KIND_LABEL[ind.kind ?? ""] ?? ind.kind}
                    </Badge>
                  </li>
                ))}
              </ul>
            )}
            {escaped.length > 0 && (
              <p className="mt-3 text-xs text-muted-foreground">
                Names written with hex escapes: <span className="font-mono">{escaped.map((n) => `/${n}`).join(" ")}</span>
              </p>
            )}
          </CardContent>
        </Card>

        <Card className="glassmorphism">
          <CardHeader className="pb-3">
            <CardTitle className="flex items-center gap-2 text-base">
              <Play className="h-4 w-4 text-primary" />
              Actions
            </CardTitle>
            <CardDescription>What happens without a click, and what the file can launch</CardDescription>
          </CardHeader>
          <CardContent className="space-y-2 text-xs">
            {autoActions.length === 0 && launches.length === 0 ? (
              <p className="text-muted-foreground">Nothing runs on its own and nothing is launched.</p>
            ) : null}
            {autoActions.map((a, i) => (
              <div key={`auto-${i}`} className="rounded border border-border/60 bg-muted/20 px-2.5 py-1.5">
                <span className="font-semibold">{a.action}</span>{" "}
                <span className="text-muted-foreground">{triggerLabel(a.trigger)}</span>
                {a.target && <div className="break-all font-mono">{a.target}</div>}
              </div>
            ))}
            {launches.map((l, i) => (
              <div
                key={`launch-${i}`}
                className={`rounded border px-2.5 py-1.5 ${l.runsCommand ? "border-destructive/30 bg-destructive/10" : "border-border/60 bg-muted/20"}`}
              >
                <div className="flex items-center gap-1.5 font-semibold">
                  <Rocket className="h-3.5 w-3.5" /> Launch{l.automatic ? " on open" : ""}
                </div>
                <div className="break-all font-mono">
                  {l.target ?? "(no target)"} {l.parameters ?? ""}
                </div>
              </div>
            ))}
          </CardContent>
        </Card>
      </div>

      {scripts.length > 0 && (
        <Card className="glassmorphism">
          <CardHeader className="pb-3">
            <CardTitle className="flex items-center gap-2 text-base">
              <Code2 className="h-4 w-4 text-primary" />
              JavaScript ({scripts.length})
            </CardTitle>
            <CardDescription>Decoded from the file, first part of each script. Shown as text, never run.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {scripts.map((sc, i) => (
              <div key={`${sc.object}-${i}`}>
                <div className="mb-1 flex flex-wrap items-center gap-2 text-xs">
                  <span className="font-mono font-semibold">object {sc.object}</span>
                  <span className="text-muted-foreground">{formatBytes(sc.bytes)}</span>
                  {sc.automatic && <Badge variant="destructive" className="text-[10px]">Runs on open</Badge>}
                </div>
                <pre className="max-h-64 overflow-auto rounded border border-border/60 bg-muted/30 p-3 font-mono text-[11px] leading-relaxed whitespace-pre-wrap break-all">
                  {sc.preview}
                </pre>
              </div>
            ))}
          </CardContent>
        </Card>
      )}

      <div className="grid gap-6 lg:grid-cols-2">
        <Card className="glassmorphism">
          <CardHeader className="pb-3">
            <CardTitle className="flex items-center gap-2 text-base">
              <Package className="h-4 w-4 text-primary" />
              Embedded files ({files.length})
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-1.5 text-xs">
            {files.length === 0 ? <p className="text-muted-foreground">None.</p> : null}
            {files.map((f, i) => (
              <div key={`${f.name}-${i}`} className="flex items-center justify-between gap-2 rounded border border-border/60 bg-muted/20 px-2.5 py-1.5">
                <span className="min-w-0 break-all font-mono">
                  {f.name ?? "(unnamed)"} <span className="text-muted-foreground">· {formatBytes(f.bytes)}{f.kind ? ` · ${f.kind}` : ""}</span>
                </span>
                {f.executable && <Badge variant="destructive">Program</Badge>}
              </div>
            ))}
          </CardContent>
        </Card>

        <Card className="glassmorphism">
          <CardHeader className="pb-3">
            <CardTitle className="flex items-center gap-2 text-base">
              <Link2 className="h-4 w-4 text-primary" />
              Links ({uris.length + unc.length})
            </CardTitle>
            <CardDescription>Addresses the file points to. Not opened by Verdyx.</CardDescription>
          </CardHeader>
          <CardContent>
            {uris.length === 0 && unc.length === 0 ? <p className="text-xs text-muted-foreground">None.</p> : null}
            <ul className="max-h-48 space-y-1 overflow-y-auto">
              {unc.map((u) => (
                <li key={u} className="break-all rounded border border-destructive/30 bg-destructive/10 px-2 py-1 font-mono text-xs">
                  {u} <span className="text-muted-foreground">· network share</span>
                </li>
              ))}
              {uris.map((u) => (
                <li key={u} className="break-all rounded bg-muted/20 px-2 py-1 font-mono text-xs">
                  {u}
                </li>
              ))}
            </ul>
          </CardContent>
        </Card>
      </div>

      {Object.keys(keywords).length > 0 && (
        <p className="text-xs text-muted-foreground">
          Keywords:{" "}
          <span className="font-mono">
            {Object.entries(keywords)
              .map(([k, n]) => `/${k} ×${n}`)
              .join("  ")}
          </span>
        </p>
      )}
      {errors.length > 0 && <p className="text-xs text-muted-foreground">Could not read: {errors.join("; ")}</p>}
    </div>
  );
}
