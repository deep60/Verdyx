import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { AlertTriangle, Cpu, KeyRound, Link2, Package, Smartphone } from "lucide-react";
import type { ApiAnalysis } from "@/lib/api-types";

/** Engine name the analysis engine reports for Android apps. */
export const APK_ENGINE_NAME = "Android App Analyzer";

interface Indicator {
  kind?: string;
  evidence?: string;
  description?: string;
}

interface Component {
  kind?: string;
  name?: string;
  permission?: string | null;
  actions?: string[];
}

interface Signing {
  v1?: boolean;
  v2_plus?: boolean;
  debug_certificate?: boolean;
}

/** Permissions Android itself classes as dangerous, plus a few abused ones. */
const SENSITIVE = new Set([
  "RECEIVE_SMS",
  "READ_SMS",
  "SEND_SMS",
  "SYSTEM_ALERT_WINDOW",
  "REQUEST_INSTALL_PACKAGES",
  "READ_CONTACTS",
  "READ_CALL_LOG",
  "RECORD_AUDIO",
  "CAMERA",
  "ACCESS_FINE_LOCATION",
  "ACCESS_BACKGROUND_LOCATION",
  "READ_PHONE_STATE",
  "CALL_PHONE",
  "QUERY_ALL_PACKAGES",
  "MANAGE_EXTERNAL_STORAGE",
]);

function asArray<T>(value: unknown): T[] {
  return Array.isArray(value) ? (value as T[]) : [];
}

function strings(value: unknown): string[] {
  return asArray<unknown>(value).filter((v): v is string => typeof v === "string" && v.length > 0);
}

function shortName(p: string): string {
  return p.split(".").pop() || p;
}

export function hasApkAnalysis(analyses: ApiAnalysis[]): boolean {
  return analyses.some((a) => a.engine?.name === APK_ENGINE_NAME);
}

export function ApkForensicsPanel({ analyses }: { analyses: ApiAnalysis[] }) {
  const apk = analyses.find((a) => a.engine?.name === APK_ENGINE_NAME);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const raw = (apk as Record<string, any> | undefined)?.metadata;
  const meta: Record<string, unknown> = raw && typeof raw === "object" && !Array.isArray(raw) ? raw : {};

  if (!apk) {
    return (
      <Card className="glassmorphism">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Smartphone className="h-5 w-5 text-primary" />
            App forensics
          </CardTitle>
          <CardDescription>Waiting for the Android app analyzer to finish.</CardDescription>
        </CardHeader>
      </Card>
    );
  }

  const text = (k: string) => (typeof meta[k] === "string" ? (meta[k] as string) : null);
  const num = (k: string) => (typeof meta[k] === "number" ? (meta[k] as number) : null);
  const summary = text("summary") ?? "";
  const pkg = text("package");
  const version = text("versionName");
  const minSdk = num("minSdk");
  const targetSdk = num("targetSdk");
  const riskScore = num("riskScore") ?? 0;
  const permissions = strings(meta.permissions);
  const indicators = asArray<Indicator>(meta.indicators);
  const apis = asArray<Indicator>(meta.apis);
  const components = asArray<Component>(meta.components);
  const packers = strings(meta.packers);
  const payloads = strings(meta.embeddedPayloads);
  const abis = strings(meta.nativeAbis);
  const libs = strings(meta.nativeLibraries);
  const iocs = strings(meta.iocs);
  const signing: Signing =
    meta.signing && typeof meta.signing === "object" ? (meta.signing as Signing) : {};
  const errors = strings(meta.parseErrors);
  const sensitive = permissions.filter((p) => SENSITIVE.has(shortName(p)));

  return (
    <div className="space-y-6" data-testid="apk-forensics">
      <Card className="glassmorphism border-primary/20">
        <CardContent className="space-y-2 p-4 text-sm">
          <div className="flex flex-wrap items-center gap-2">
            {pkg && <span className="font-mono font-semibold break-all">{pkg}</span>}
            {version && <Badge variant="outline">v{version}</Badge>}
            {(minSdk !== null || targetSdk !== null) && (
              <Badge variant="outline" className="font-mono">
                SDK {minSdk ?? "?"}–{targetSdk ?? "?"}
              </Badge>
            )}
            <Badge variant="outline">Risk score {riskScore.toFixed(1)}</Badge>
            {signing.v1 || signing.v2_plus ? (
              <Badge variant={signing.debug_certificate ? "secondary" : "outline"} className="gap-1">
                <KeyRound className="h-3 w-3" />
                {signing.debug_certificate ? "Debug-signed" : `Signed (${[signing.v1 && "v1", signing.v2_plus && "v2+"].filter(Boolean).join(", ")})`}
              </Badge>
            ) : (
              <Badge variant="destructive">Unsigned</Badge>
            )}
          </div>
          {summary && <p className="text-muted-foreground">{summary}</p>}
        </CardContent>
      </Card>

      <div className="grid gap-6 lg:grid-cols-2">
        <Card className="glassmorphism">
          <CardHeader className="pb-3">
            <CardTitle className="flex items-center gap-2 text-base">
              <AlertTriangle className="h-4 w-4 text-primary" />
              Risky abilities ({indicators.length})
            </CardTitle>
            <CardDescription>From the manifest, the code and how the app is packaged</CardDescription>
          </CardHeader>
          <CardContent>
            {indicators.length === 0 ? (
              <p className="text-xs text-muted-foreground">No risky abilities found.</p>
            ) : (
              <ul className="space-y-1.5">
                {indicators.map((ind, i) => (
                  <li key={`${ind.kind}-${i}`} className="rounded border border-border/60 bg-muted/20 px-2.5 py-1.5 text-xs">
                    <div>{ind.description}</div>
                    {ind.evidence && (
                      <div className="mt-0.5 break-all font-mono text-[11px] text-muted-foreground">{ind.evidence}</div>
                    )}
                  </li>
                ))}
              </ul>
            )}
          </CardContent>
        </Card>

        <Card className="glassmorphism">
          <CardHeader className="pb-3">
            <CardTitle className="flex items-center gap-2 text-base">
              <Smartphone className="h-4 w-4 text-primary" />
              Permissions ({permissions.length})
            </CardTitle>
            <CardDescription>{sensitive.length} sensitive</CardDescription>
          </CardHeader>
          <CardContent>
            {permissions.length === 0 ? (
              <p className="text-xs text-muted-foreground">No permissions requested.</p>
            ) : (
              <div className="flex max-h-56 flex-wrap gap-1.5 overflow-y-auto">
                {permissions.map((p) => (
                  <Badge
                    key={p}
                    variant={SENSITIVE.has(shortName(p)) ? "secondary" : "outline"}
                    className="font-mono text-[10px]"
                    title={p}
                  >
                    {shortName(p)}
                  </Badge>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        <Card className="glassmorphism">
          <CardHeader className="pb-3">
            <CardTitle className="flex items-center gap-2 text-base">
              <Cpu className="h-4 w-4 text-primary" />
              Code and packaging
            </CardTitle>
            <CardDescription>APIs found in the app code, native libraries and hidden files</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3 text-xs">
            {apis.length > 0 ? (
              <ul className="space-y-1">
                {apis.map((a, i) => (
                  <li key={`${a.evidence}-${i}`} className="flex flex-wrap justify-between gap-2 rounded bg-muted/20 px-2 py-1">
                    <span className="break-all font-mono">{a.evidence}</span>
                    <span className="text-muted-foreground">{a.description}</span>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-muted-foreground">No risky APIs found in the code.</p>
            )}
            {packers.length > 0 && (
              <div className="rounded border border-destructive/30 bg-destructive/10 px-2.5 py-1.5">
                Packed with {packers.join(", ")}
              </div>
            )}
            {payloads.map((p) => (
              <div key={p} className="flex items-center gap-1.5 rounded border border-destructive/30 bg-destructive/10 px-2.5 py-1.5 font-mono break-all">
                <Package className="h-3.5 w-3.5 shrink-0" /> {p}
              </div>
            ))}
            {libs.length > 0 && (
              <div className="text-muted-foreground">
                Native code ({abis.join(", ")}): <span className="font-mono">{libs.slice(0, 12).join(", ")}</span>
                {libs.length > 12 && ` and ${libs.length - 12} more`}
              </div>
            )}
          </CardContent>
        </Card>

        <Card className="glassmorphism">
          <CardHeader className="pb-3">
            <CardTitle className="flex items-center gap-2 text-base">
              <Link2 className="h-4 w-4 text-primary" />
              Components and addresses
            </CardTitle>
            <CardDescription>Services and receivers with special access, and addresses in the code</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3 text-xs">
            {components.length === 0 && iocs.length === 0 && (
              <p className="text-muted-foreground">Nothing notable.</p>
            )}
            {components.map((c, i) => (
              <div key={`${c.name}-${i}`} className="rounded border border-border/60 bg-muted/20 px-2.5 py-1.5">
                <div className="break-all font-mono">
                  {c.kind} {c.name}
                </div>
                {(c.permission || (c.actions && c.actions.length > 0)) && (
                  <div className="break-all text-muted-foreground">
                    {[c.permission && shortName(c.permission), ...(c.actions ?? []).map(shortName)]
                      .filter(Boolean)
                      .join(" · ")}
                  </div>
                )}
              </div>
            ))}
            {iocs.length > 0 && (
              <ul className="max-h-40 space-y-1 overflow-y-auto">
                {iocs.map((ioc) => (
                  <li key={ioc} className="break-all rounded bg-muted/20 px-2 py-1 font-mono">
                    {ioc}
                  </li>
                ))}
              </ul>
            )}
          </CardContent>
        </Card>
      </div>

      {errors.length > 0 && <p className="text-xs text-muted-foreground">Could not read: {errors.join("; ")}</p>}
    </div>
  );
}
