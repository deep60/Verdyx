import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { useToast } from "@/hooks/use-toast";
import { AlertTriangle, Copy, Crosshair, Download, FileCode, History, KeyRound, Layers, RefreshCw } from "lucide-react";

export interface ReconSubdomain {
  name: string;
  status: "live" | "no-address" | "nxdomain" | "error" | "unchecked";
  ips: string[];
  cname: string | null;
}

export interface TakeoverCandidate {
  subdomain: string;
  cname: string;
  service: string | null;
  level: "likely" | "check";
  evidence: string;
}

export interface ExposedKey {
  kind: string;
  masked: string;
  source: string;
  note: string;
}

export interface ReconData {
  host: string;
  rootDomain: string;
  durationMs: number;
  subdomains: {
    available: boolean;
    source: string;
    error: string | null;
    total: number;
    truncated: boolean;
    checked: number;
    live: number;
    items: ReconSubdomain[];
  };
  takeovers: { checked: number; withCname: number; candidates: TakeoverCandidate[] };
  archivedUrls: {
    available: boolean;
    source?: string;
    error?: string;
    partialErrors?: string[];
    total?: number;
    truncated?: boolean;
    withParams?: string[];
    paramNames?: string[];
    interestingFiles?: string[];
    javascriptFiles?: string[];
    interestingPaths?: string[];
    all?: string[];
  };
  javascript: {
    available: boolean;
    error?: string;
    scripts?: { url: string; status: string; bytes?: number; error?: string }[];
    endpointCount?: number;
    endpoints?: string[];
    exposedKeys?: ExposedKey[];
  };
  scope: string;
}

export const STATUS_LABEL: Record<ReconSubdomain["status"], string> = {
  live: "Live",
  "no-address": "No address",
  nxdomain: "Doesn't resolve",
  error: "Lookup failed",
  unchecked: "Not checked",
};

type SubdomainFilter = "all" | "live" | "dead" | "unchecked";

export function filterSubdomains(items: ReconSubdomain[], filter: SubdomainFilter, search: string): ReconSubdomain[] {
  const q = search.trim().toLowerCase();
  return items.filter((s) => {
    if (filter === "live" && s.status !== "live") return false;
    if (filter === "dead" && s.status !== "nxdomain" && s.status !== "no-address") return false;
    if (filter === "unchecked" && s.status !== "unchecked") return false;
    return !q || s.name.includes(q) || (s.cname ?? "").includes(q) || s.ips.some((ip) => ip.includes(q));
  });
}

type UrlList = "withParams" | "paramNames" | "interestingPaths" | "interestingFiles" | "javascriptFiles" | "all";

export const URL_LISTS: { key: UrlList; label: string }[] = [
  { key: "withParams", label: "With parameters" },
  { key: "paramNames", label: "Parameter names" },
  { key: "interestingPaths", label: "Interesting paths" },
  { key: "interestingFiles", label: "Interesting files" },
  { key: "javascriptFiles", label: "JavaScript files" },
  { key: "all", label: "All" },
];

async function fetchRecon(url: string): Promise<ReconData> {
  let res: Response;
  try {
    res = await fetch(`/api/analysis/web-recon?url=${encodeURIComponent(url)}`, { credentials: "include" });
  } catch {
    throw new Error("Verdyx couldn't be reached to run recon. Try again.");
  }
  if (!res.ok) {
    throw new Error(
      res.status === 429 ? "Too many checks. Wait a minute and try again." : `Recon failed (HTTP ${res.status}).`,
    );
  }
  return res.json();
}

function saveText(filename: string, lines: string[]) {
  const blob = new Blob([lines.join("\n") + "\n"], { type: "text/plain" });
  const href = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = href;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(href);
}

function ListActions({ lines, filename, label }: { lines: string[]; filename: string; label: string }) {
  const { toast } = useToast();
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(lines.join("\n"));
      toast({ title: `Copied ${lines.length} ${label}` });
    } catch {
      toast({ title: "Couldn't copy", description: "Use Download instead.", variant: "destructive" });
    }
  };
  return (
    <div className="flex gap-1.5">
      <Button size="sm" variant="outline" className="h-7 px-2 text-xs" onClick={copy} disabled={!lines.length}>
        <Copy className="h-3.5 w-3.5 mr-1" /> Copy
      </Button>
      <Button
        size="sm"
        variant="outline"
        className="h-7 px-2 text-xs"
        onClick={() => saveText(filename, lines)}
        disabled={!lines.length}
      >
        <Download className="h-3.5 w-3.5 mr-1" /> .txt
      </Button>
    </div>
  );
}

function Unavailable({ what, error }: { what: string; error?: string | null }) {
  return (
    <p className="text-xs text-muted-foreground flex items-start gap-1.5">
      <AlertTriangle className="h-3.5 w-3.5 mt-0.5 shrink-0 text-destructive" />
      <span>
        {what} unavailable{error ? `: ${error}` : ""}. Nothing is shown rather than a guess.
      </span>
    </p>
  );
}

function Stat({ label, value, detail }: { label: string; value: string | number; detail?: string }) {
  return (
    <div className="rounded-lg border border-border/60 bg-card/50 p-3">
      <div className="text-xs text-muted-foreground">{label}</div>
      <div className="font-mono text-lg font-semibold">{value}</div>
      {detail && <div className="text-[11px] text-muted-foreground">{detail}</div>}
    </div>
  );
}

export function ReconPanel({ url }: { url: string }) {
  const { data, isLoading, isError, error, refetch, isFetching } = useQuery<ReconData>({
    queryKey: ["/api/analysis/web-recon", url],
    queryFn: () => fetchRecon(url),
    enabled: Boolean(url),
    staleTime: 10 * 60 * 1000,
    retry: 1,
  });
  const [subFilter, setSubFilter] = useState<SubdomainFilter>("all");
  const [subSearch, setSubSearch] = useState("");
  const [urlList, setUrlList] = useState<UrlList>("withParams");
  const [endpointSearch, setEndpointSearch] = useState("");

  const subdomains = useMemo(
    () => filterSubdomains(data?.subdomains.items ?? [], subFilter, subSearch),
    [data, subFilter, subSearch],
  );
  const endpoints = useMemo(() => {
    const q = endpointSearch.trim().toLowerCase();
    return (data?.javascript.endpoints ?? []).filter((e) => !q || e.toLowerCase().includes(q));
  }, [data, endpointSearch]);

  if (!url) return null;

  if (isLoading) {
    return (
      <Card className="bento-card" data-testid="recon-loading">
        <CardContent className="p-8 text-center space-y-2">
          <RefreshCw className="h-6 w-6 text-primary animate-spin mx-auto" />
          <div className="font-semibold">Running recon…</div>
          <p className="text-xs text-muted-foreground">
            Reading certificate logs, resolving subdomains, checking for takeovers, and reading the Wayback Machine and
            the site's JavaScript. This can take up to 30 seconds.
          </p>
        </CardContent>
      </Card>
    );
  }

  if (isError || !data) {
    return (
      <Card className="bento-card border-destructive/30">
        <CardContent className="p-6 text-center space-y-2">
          <div className="font-semibold">Recon unavailable</div>
          <p className="text-sm text-muted-foreground">{error instanceof Error ? error.message : "Try again."}</p>
          <Button size="sm" variant="outline" onClick={() => refetch()} disabled={isFetching}>
            Try again
          </Button>
        </CardContent>
      </Card>
    );
  }

  const subs = data.subdomains;
  const takeovers = data.takeovers.candidates;
  const archive = data.archivedUrls;
  const js = data.javascript;
  const keys = js.exposedKeys ?? [];
  const currentUrls = (archive[urlList] as string[] | undefined) ?? [];
  const slug = data.rootDomain.replace(/[^a-z0-9.-]/gi, "_");

  return (
    <div className="space-y-4" data-testid="recon-panel">
      <Card className="bento-card border-mark/40">
        <CardContent className="p-5 space-y-3">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div>
              <div className="flex items-center gap-2">
                <Crosshair className="h-5 w-5 text-mark" />
                <h3 className="text-lg font-bold font-display">Recon for bug bounty hunters</h3>
                <Badge variant="outline" className="font-mono text-[10px]">
                  {data.rootDomain}
                </Badge>
              </div>
              <p className="text-xs text-muted-foreground mt-1">{data.scope}</p>
            </div>
            <Button size="sm" variant="outline" onClick={() => refetch()} disabled={isFetching}>
              <RefreshCw className={`h-3.5 w-3.5 mr-1.5 ${isFetching ? "animate-spin" : ""}`} />
              Run again
            </Button>
          </div>
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
            <Stat
              label="Subdomains"
              value={subs.available ? subs.total : "—"}
              detail={subs.available ? `${subs.live} live of ${subs.checked} checked` : "logs unavailable"}
            />
            <Stat
              label="Takeover candidates"
              value={takeovers.length}
              detail={`${data.takeovers.withCname} CNAMEs checked`}
            />
            <Stat
              label="Archived URLs"
              value={archive.available ? (archive.total ?? 0) : "—"}
              detail={archive.available ? `${archive.paramNames?.length ?? 0} parameter names` : "Wayback unavailable"}
            />
            <Stat
              label="JS endpoints"
              value={js.available ? (js.endpointCount ?? 0) : "—"}
              detail={js.available ? `${keys.length} exposed keys` : "page unavailable"}
            />
          </div>
        </CardContent>
      </Card>

      {takeovers.length > 0 && (
        <Card className="bento-card border-destructive/40" data-testid="recon-takeovers">
          <CardHeader className="pb-2">
            <CardTitle className="text-base flex items-center gap-2">
              <AlertTriangle className="h-4 w-4 text-destructive" />
              Possible subdomain takeovers ({takeovers.length})
            </CardTitle>
            <CardDescription>
              A CNAME pointing at something no one has claimed. Confirm by hand before reporting.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-2 text-xs">
            {takeovers.map((t) => (
              <div key={t.subdomain} className="rounded border border-border/50 p-2 space-y-1">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-mono font-semibold">{t.subdomain}</span>
                  <Badge variant={t.level === "likely" ? "destructive" : "outline"}>
                    {t.level === "likely" ? "Likely" : "Check"}
                  </Badge>
                  {t.service && <Badge variant="secondary">{t.service}</Badge>}
                </div>
                <div className="font-mono text-muted-foreground">CNAME → {t.cname}</div>
                <div>{t.evidence}</div>
              </div>
            ))}
          </CardContent>
        </Card>
      )}

      <div className="grid gap-4 lg:grid-cols-2">
        <Card className="bento-card border-primary/20">
          <CardHeader className="pb-2">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <CardTitle className="text-base flex items-center gap-2">
                <Layers className="h-4 w-4 text-primary" />
                Subdomains {subs.available ? `(${subs.total})` : ""}
              </CardTitle>
              <ListActions
                lines={subdomains.map((s) => s.name)}
                filename={`${slug}-subdomains.txt`}
                label="subdomains"
              />
            </div>
            <CardDescription>
              From {subs.source}. DNS checked for the first {subs.checked}
              {subs.truncated ? `; ${subs.items.length} of ${subs.total} listed` : ""}.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-2">
            {!subs.available ? (
              <Unavailable what="Certificate logs" error={subs.error} />
            ) : (
              <>
                <div className="flex flex-wrap gap-1.5">
                  {(
                    [
                      ["all", "All"],
                      ["live", "Live"],
                      ["dead", "No DNS"],
                      ["unchecked", "Not checked"],
                    ] as const
                  ).map(([key, label]) => (
                    <Button
                      key={key}
                      size="sm"
                      variant={subFilter === key ? "default" : "outline"}
                      className="h-7 px-2 text-xs"
                      onClick={() => setSubFilter(key)}
                    >
                      {label}
                    </Button>
                  ))}
                  <Input
                    value={subSearch}
                    onChange={(e) => setSubSearch(e.target.value)}
                    placeholder="Search names, IPs, CNAMEs"
                    className="h-7 text-xs flex-1 min-w-[140px]"
                  />
                </div>
                <div className="max-h-80 overflow-y-auto text-xs divide-y divide-border/30">
                  {subdomains.length === 0 ? (
                    <p className="py-2 text-muted-foreground">No subdomains match.</p>
                  ) : (
                    subdomains.map((s) => (
                      <div key={s.name} className="py-1.5 flex flex-wrap items-center gap-x-2 gap-y-0.5">
                        <a
                          href={`https://${s.name}`}
                          target="_blank"
                          rel="noreferrer noopener"
                          className="font-mono hover:underline break-all"
                        >
                          {s.name}
                        </a>
                        <Badge variant={s.status === "live" ? "brand" : "outline"} className="text-[10px]">
                          {STATUS_LABEL[s.status]}
                        </Badge>
                        {s.cname && <span className="font-mono text-muted-foreground">→ {s.cname}</span>}
                        {s.ips.length > 0 && (
                          <span className="font-mono text-muted-foreground">{s.ips.slice(0, 3).join(", ")}</span>
                        )}
                      </div>
                    ))
                  )}
                </div>
              </>
            )}
          </CardContent>
        </Card>

        <Card className="bento-card border-primary/20">
          <CardHeader className="pb-2">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <CardTitle className="text-base flex items-center gap-2">
                <History className="h-4 w-4 text-primary" />
                Archived URLs {archive.available ? `(${archive.total ?? 0})` : ""}
              </CardTitle>
              <ListActions lines={currentUrls} filename={`${slug}-${urlList}.txt`} label="lines" />
            </div>
            <CardDescription>
              URLs seen for {data.host}
              {archive.source ? ` by ${archive.source}` : ""}, sorted into the lists hunters start from.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-2">
            {!archive.available ? (
              <Unavailable what="The Wayback Machine" error={archive.error} />
            ) : (
              <>
                <div className="flex flex-wrap gap-1.5">
                  {URL_LISTS.map(({ key, label }) => (
                    <Button
                      key={key}
                      size="sm"
                      variant={urlList === key ? "default" : "outline"}
                      className="h-7 px-2 text-xs"
                      onClick={() => setUrlList(key)}
                    >
                      {label} ({(archive[key] as string[] | undefined)?.length ?? 0})
                    </Button>
                  ))}
                </div>
                <div className="max-h-80 overflow-y-auto text-xs font-mono divide-y divide-border/30">
                  {currentUrls.length === 0 ? (
                    <p className="py-2 text-muted-foreground font-sans">Nothing in this list.</p>
                  ) : (
                    currentUrls.map((u) => (
                      <div key={u} className="py-1 break-all">
                        {u}
                      </div>
                    ))
                  )}
                </div>
                {archive.truncated && (
                  <p className="text-[11px] text-muted-foreground">The Wayback Machine has more than were read.</p>
                )}
                {(archive.partialErrors ?? []).length > 0 && (
                  <p className="text-[11px] text-muted-foreground">
                    Not included: {(archive.partialErrors ?? []).join("; ")}.
                  </p>
                )}
              </>
            )}
          </CardContent>
        </Card>

        <Card className="bento-card border-primary/20">
          <CardHeader className="pb-2">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <CardTitle className="text-base flex items-center gap-2">
                <FileCode className="h-4 w-4 text-primary" />
                Endpoints in JavaScript {js.available ? `(${js.endpointCount ?? 0})` : ""}
              </CardTitle>
              <ListActions lines={endpoints} filename={`${slug}-endpoints.txt`} label="endpoints" />
            </div>
            <CardDescription>
              Paths and URLs found in the page and {js.scripts?.length ?? 0} of the site's own scripts.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-2">
            {!js.available ? (
              <Unavailable what="The page" error={js.error} />
            ) : (
              <>
                <Input
                  value={endpointSearch}
                  onChange={(e) => setEndpointSearch(e.target.value)}
                  placeholder="Filter, e.g. api, admin, graphql"
                  className="h-7 text-xs"
                />
                <div className="max-h-72 overflow-y-auto text-xs font-mono divide-y divide-border/30">
                  {endpoints.length === 0 ? (
                    <p className="py-2 text-muted-foreground font-sans">No endpoints found.</p>
                  ) : (
                    endpoints.map((e) => (
                      <div key={e} className="py-1 break-all">
                        {e}
                      </div>
                    ))
                  )}
                </div>
              </>
            )}
          </CardContent>
        </Card>

        <Card className="bento-card border-primary/20" data-testid="recon-keys">
          <CardHeader className="pb-2">
            <CardTitle className="text-base flex items-center gap-2">
              <KeyRound className="h-4 w-4 text-primary" />
              Exposed keys ({keys.length})
            </CardTitle>
            <CardDescription>
              Keys in public JavaScript, masked. Open the script to see the full value, and report it rather than using
              it.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-2 text-xs">
            {!js.available ? (
              <Unavailable what="The page" error={js.error} />
            ) : keys.length === 0 ? (
              <p className="text-muted-foreground">
                No known key formats in the page or the {js.scripts?.length ?? 0} scripts read.
              </p>
            ) : (
              keys.map((k) => (
                <div key={`${k.kind}-${k.masked}`} className="rounded border border-border/50 p-2 space-y-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <Badge variant="destructive">{k.kind}</Badge>
                    <span className="font-mono">{k.masked}</span>
                  </div>
                  <div className="font-mono text-muted-foreground break-all">{k.source}</div>
                  <div>{k.note}</div>
                </div>
              ))
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
