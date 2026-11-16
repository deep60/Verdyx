import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { AlertTriangle, Code2, FileText, Link2, Lock, Package, Table2 } from "lucide-react";
import type { ApiAnalysis } from "@/lib/api-types";

/** Engine name the analysis engine reports for Office documents. */
export const OFFICE_ENGINE_NAME = "Office Document Analyzer";

interface MacroModule {
  project?: string;
  module?: string;
  lines?: number;
  bytes?: number;
  preview?: string;
}

interface Indicator {
  kind?: string;
  keyword?: string;
  description?: string;
}

interface ExternalLink {
  part?: string;
  relationship?: string;
  target?: string;
  dangerous?: boolean;
  reason?: string;
}

interface EmbeddedObject {
  location?: string;
  name?: string | null;
  executable?: boolean;
}

interface Excel4Macros {
  macro_sheets?: string[];
  hidden_sheets?: string[];
  auto_open?: boolean;
  dangerous_functions?: string[];
}

const KIND_LABEL: Record<string, string> = {
  autoexec: "Runs automatically",
  execute: "Launches programs",
  download: "Downloads",
  drop: "Writes files",
  inject: "Memory injection",
  obfuscation: "Obfuscation",
};

function asArray<T>(value: unknown): T[] {
  return Array.isArray(value) ? (value as T[]) : [];
}

function strings(value: unknown): string[] {
  return asArray<unknown>(value).filter((v): v is string => typeof v === "string" && v.length > 0);
}

export function hasOfficeAnalysis(analyses: ApiAnalysis[]): boolean {
  return analyses.some((a) => a.engine?.name === OFFICE_ENGINE_NAME);
}

export function OfficeForensicsPanel({ analyses }: { analyses: ApiAnalysis[] }) {
  const office = analyses.find((a) => a.engine?.name === OFFICE_ENGINE_NAME);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const raw = (office as Record<string, any> | undefined)?.metadata;
  const meta: Record<string, unknown> = raw && typeof raw === "object" && !Array.isArray(raw) ? raw : {};

  if (!office) {
    return (
      <Card className="glassmorphism">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <FileText className="h-5 w-5 text-primary" />
            Document forensics
          </CardTitle>
          <CardDescription>Waiting for the Office document analyzer to finish.</CardDescription>
        </CardHeader>
      </Card>
    );
  }

  const summary = typeof meta.summary === "string" ? meta.summary : "";
  const format = typeof meta.format === "string" ? meta.format : "";
  const encrypted = Boolean(meta.encrypted);
  const modules = asArray<MacroModule>(meta.macroModules);
  const indicators = asArray<Indicator>(meta.indicators);
  const iocs = strings(meta.iocs);
  const links = asArray<ExternalLink>(meta.externalLinks);
  const dde = strings(meta.dde);
  const objects = asArray<EmbeddedObject>(meta.embeddedObjects);
  const xlm: Excel4Macros =
    meta.excel4Macros && typeof meta.excel4Macros === "object" ? (meta.excel4Macros as Excel4Macros) : {};
  const macroSheets = strings(xlm.macro_sheets);
  const hiddenSheets = strings(xlm.hidden_sheets);
  const xlmFunctions = strings(xlm.dangerous_functions);
  const errors = strings(meta.parseErrors);

  return (
    <div className="space-y-6" data-testid="office-forensics">
      <Card className="glassmorphism border-primary/20">
        <CardContent className="space-y-2 p-4 text-sm">
          <div className="flex flex-wrap items-center gap-2">
            <Badge variant="outline" className="font-mono uppercase">
              {format === "ole" ? "OLE (97-2003)" : format === "ooxml" ? "Office Open XML" : "Office"}
            </Badge>
            {encrypted && (
              <Badge variant="secondary" className="gap-1">
                <Lock className="h-3 w-3" /> Encrypted
              </Badge>
            )}
            <Badge variant="outline">{modules.length} macro module(s)</Badge>
          </div>
          {summary && <p className="text-muted-foreground">{summary}</p>}
        </CardContent>
      </Card>

      <div className="grid gap-6 lg:grid-cols-2">
        <Card className="glassmorphism">
          <CardHeader className="pb-3">
            <CardTitle className="flex items-center gap-2 text-base">
              <AlertTriangle className="h-4 w-4 text-primary" />
              Macro behaviour ({indicators.length})
            </CardTitle>
            <CardDescription>What the macro code can do, found in its decompressed source</CardDescription>
          </CardHeader>
          <CardContent>
            {indicators.length === 0 ? (
              <p className="text-xs text-muted-foreground">No risky macro behaviour found.</p>
            ) : (
              <ul className="space-y-1.5">
                {indicators.map((ind, i) => (
                  <li
                    key={`${ind.kind}-${ind.keyword}-${i}`}
                    className="flex items-start justify-between gap-3 rounded border border-border/60 bg-muted/20 px-2.5 py-1.5 text-xs"
                  >
                    <span>
                      <span className="font-mono">{ind.keyword}</span>
                      <span className="text-muted-foreground"> · {ind.description}</span>
                    </span>
                    <Badge
                      variant={ind.kind === "obfuscation" || ind.kind === "drop" ? "secondary" : "destructive"}
                      className="shrink-0 text-[10px]"
                    >
                      {KIND_LABEL[ind.kind ?? ""] ?? ind.kind}
                    </Badge>
                  </li>
                ))}
              </ul>
            )}
            {iocs.length > 0 && (
              <div className="mt-4">
                <div className="mb-2 text-xs text-muted-foreground">Indicators in the code ({iocs.length})</div>
                <ul className="max-h-40 space-y-1 overflow-y-auto">
                  {iocs.map((ioc) => (
                    <li key={ioc} className="break-all rounded bg-muted/20 px-2 py-1 font-mono text-xs">
                      {ioc}
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </CardContent>
        </Card>

        <Card className="glassmorphism">
          <CardHeader className="pb-3">
            <CardTitle className="flex items-center gap-2 text-base">
              <Link2 className="h-4 w-4 text-primary" />
              Links, DDE and embedded objects
            </CardTitle>
            <CardDescription>Ways a document loads or runs code without a macro</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3 text-xs">
            {links.length === 0 && dde.length === 0 && objects.length === 0 && macroSheets.length === 0 ? (
              <p className="text-muted-foreground">None found.</p>
            ) : null}
            {links.map((l, i) => (
              <div
                key={`${l.target}-${i}`}
                className={`rounded border px-2.5 py-1.5 ${l.dangerous ? "border-destructive/30 bg-destructive/10" : "border-border/60 bg-muted/20"}`}
              >
                <div className="font-mono break-all">{l.target}</div>
                <div className="text-muted-foreground">
                  {l.relationship} · {l.reason}
                </div>
              </div>
            ))}
            {dde.map((d) => (
              <div key={d} className="rounded border border-destructive/30 bg-destructive/10 px-2.5 py-1.5 font-mono break-all">
                DDE: {d}
              </div>
            ))}
            {objects.map((o, i) => (
              <div key={`${o.location}-${i}`} className="flex items-center justify-between gap-2 rounded border border-border/60 bg-muted/20 px-2.5 py-1.5">
                <span className="flex items-center gap-1.5 break-all font-mono">
                  <Package className="h-3.5 w-3.5 shrink-0" />
                  {o.name || o.location}
                </span>
                {o.executable && <Badge variant="destructive">Program</Badge>}
              </div>
            ))}
            {macroSheets.length > 0 && (
              <div className="rounded border border-border/60 bg-muted/20 px-2.5 py-1.5">
                <div className="flex items-center gap-1.5 font-semibold">
                  <Table2 className="h-3.5 w-3.5" /> Excel 4.0 macro sheets: {macroSheets.join(", ")}
                </div>
                <div className="text-muted-foreground">
                  {hiddenSheets.length > 0 && <>Hidden: {hiddenSheets.join(", ")}. </>}
                  {xlm.auto_open && <>Runs on open (Auto_Open). </>}
                  {xlmFunctions.length > 0 && <>Calls {xlmFunctions.join(", ")}.</>}
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      {modules.length > 0 && (
        <Card className="glassmorphism">
          <CardHeader className="pb-3">
            <CardTitle className="flex items-center gap-2 text-base">
              <Code2 className="h-4 w-4 text-primary" />
              Macro source
            </CardTitle>
            <CardDescription>Decompressed VBA, first part of each module. Shown as text, never run.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {modules.map((m, i) => (
              <div key={`${m.project}-${m.module}-${i}`}>
                <div className="mb-1 flex flex-wrap items-center gap-2 text-xs">
                  <span className="font-mono font-semibold">{m.module}</span>
                  <span className="text-muted-foreground">
                    {m.project} · {m.lines ?? 0} lines
                  </span>
                </div>
                <pre className="max-h-64 overflow-auto rounded border border-border/60 bg-muted/30 p-3 font-mono text-[11px] leading-relaxed whitespace-pre-wrap break-all">
                  {m.preview}
                </pre>
              </div>
            ))}
          </CardContent>
        </Card>
      )}

      {errors.length > 0 && (
        <p className="text-xs text-muted-foreground">Could not read: {errors.join("; ")}</p>
      )}
    </div>
  );
}
