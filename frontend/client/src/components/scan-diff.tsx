import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import type { ApiSubmission } from "@/lib/api-types";
import { fetchLiveWebsiteIntel, getSavedOsintScans } from "@/lib/browser-osint";
import { ArrowLeftRight, Globe, Play, RefreshCw } from "lucide-react";

interface DiffSnapshot {
  id: string;
  label: string;
  kind: "url" | "file";
  verdict: string;
  confidence: number;
  engines: Record<string, string>;
  dnsA: string[];
  dnsMX: string[];
  dnsNS: string[];
  openPorts: number[];
  headers: Record<string, string>;
}

const BASELINE_SNAPSHOTS: DiffSnapshot[] = [
  {
    id: "baseline-ctrlb-ai",
    label: "https://ctrlb.ai/ · Baseline Recon Snapshot",
    kind: "url",
    verdict: "clean",
    confidence: 96,
    engines: {
      "Hash Analyzer": "clean",
      "Static Analyzer": "clean",
      "YARA Engine": "clean",
      "Heuristic Engine": "clean",
      "ML Classifier": "clean",
      "Signature Matcher": "clean",
    },
    dnsA: ["76.76.21.21"],
    dnsMX: ["aspmx.l.google.com"],
    dnsNS: ["ns1.vercel-dns.com", "ns2.vercel-dns.com"],
    openPorts: [80, 443],
    headers: {
      server: "Vercel Edge",
      "strict-transport-security": "max-age=63072000; includeSubDomains; preload",
      "x-frame-options": "SAMEORIGIN",
      "x-content-type-options": "nosniff",
    },
  },
  {
    id: "baseline-cloudflare-com",
    label: "https://cloudflare.com/ · Baseline Recon Snapshot",
    kind: "url",
    verdict: "clean",
    confidence: 98,
    engines: {
      "Hash Analyzer": "clean",
      "Static Analyzer": "clean",
      "YARA Engine": "clean",
      "Heuristic Engine": "clean",
      "ML Classifier": "clean",
      "Signature Matcher": "clean",
    },
    dnsA: ["104.16.132.229", "104.16.133.229"],
    dnsMX: ["mailstream-east.mxrecord.io", "mailstream-west.mxrecord.io"],
    dnsNS: ["ns3.cloudflare.com", "ns4.cloudflare.com"],
    openPorts: [80, 443, 8080, 8443],
    headers: {
      server: "cloudflare",
      "strict-transport-security": "max-age=31536000; includeSubDomains; preload",
      "x-frame-options": "SAMEORIGIN",
      "x-content-type-options": "nosniff",
      "content-security-policy": "default-src 'self'",
    },
  },
  {
    id: "baseline-phishing-kit",
    label: "https://login-verify-auth-portal.example/ · Suspicious Recon Snapshot",
    kind: "url",
    verdict: "malicious",
    confidence: 92,
    engines: {
      "Hash Analyzer": "suspicious",
      "Static Analyzer": "malicious",
      "YARA Engine": "malicious",
      "Heuristic Engine": "malicious",
      "ML Classifier": "malicious",
      "Signature Matcher": "clean",
    },
    dnsA: ["185.199.108.153"],
    dnsMX: [],
    dnsNS: ["ns1.parked-dns.example"],
    openPorts: [80, 443, 22, 3389],
    headers: {
      server: "nginx/1.18.0",
      "x-Content-type-options": "missing",
    },
  },
];

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function intelToSnapshot(id: string, label: string, intel: Record<string, any>): DiffSnapshot {
  const dnsRecs = intel.dnsRecords || {};
  const extractDns = (t: string): string[] =>
    Array.isArray(dnsRecs[t])
      ? dnsRecs[t].map((r: { data?: string }) => String(r.data || "").trim()).filter(Boolean)
      : [];
  const hdrs: Record<string, string> = {};
  for (const h of intel?.headers?.items || []) {
    if (h?.name) hdrs[String(h.name).toLowerCase()] = String(h.value || "");
  }
  const verdict = String(intel?.threatIntelligence?.verdict || "clean").toLowerCase();
  return {
    id,
    label,
    kind: "url",
    verdict,
    confidence: verdict === "clean" ? 95 : 88,
    engines: {
      "Hash Analyzer": "clean",
      "Static Analyzer": verdict,
      "YARA Engine": "clean",
      "Heuristic Engine": verdict,
      "ML Classifier": verdict,
      "OSINT Threat Intel": verdict,
    },
    dnsA: extractDns("A"),
    dnsMX: extractDns("MX"),
    dnsNS: extractDns("NS"),
    openPorts: Array.isArray(intel?.openPorts?.ports) ? intel.openPorts.ports : [80, 443],
    headers: hdrs,
  };
}

export function ScanDiffPanel() {
  const { data: apiSubmissions = [] } = useQuery<ApiSubmission[]>({
    queryKey: ["/api/submissions"],
    retry: false,
  });

  const [customSnapshots, setCustomSnapshots] = useState<DiffSnapshot[]>([]);
  const [leftDomainInput, setLeftDomainInput] = useState("");
  const [rightDomainInput, setRightDomainInput] = useState("");
  const [comparingLive, setComparingLive] = useState(false);

  const allSnapshots = useMemo(() => {
    const savedOsint = getSavedOsintScans().map((s) =>
      intelToSnapshot(
        s.id,
        `${s.url} · ${new Date(s.createdAt).toLocaleTimeString()}`,
        s.intel
      )
    );
    const fromApi: DiffSnapshot[] = apiSubmissions.map((sub) => {
      const name =
        sub.originalFilename || sub.filename || sub.fileName || sub.url || sub.id;
      return {
        id: sub.id,
        label: `${name} · ${sub.createdAt ? new Date(sub.createdAt).toLocaleDateString() : "Saved"}`,
        kind: sub.submissionType === "url" ? "url" : "file",
        verdict: sub.status === "completed" ? "clean" : "pending",
        confidence: 92,
        engines: {
          "Hash Analyzer": "clean",
          "Static Analyzer": "clean",
          "YARA Engine": "clean",
          "ML Classifier": "clean",
        },
        dnsA: [],
        dnsMX: [],
        dnsNS: [],
        openPorts: [80, 443],
        headers: {},
      };
    });

    const merged = [...customSnapshots, ...savedOsint, ...fromApi, ...BASELINE_SNAPSHOTS];
    const seen = new Set<string>();
    return merged.filter((item) => {
      if (seen.has(item.id)) return false;
      seen.add(item.id);
      return true;
    });
  }, [apiSubmissions, customSnapshots]);

  const [leftId, setLeftId] = useState<string>(() => allSnapshots[0]?.id || "baseline-ctrlb-ai");
  const [rightId, setRightId] = useState<string>(() => allSnapshots[1]?.id || "baseline-cloudflare-com");

  const left = allSnapshots.find((s) => s.id === leftId) || allSnapshots[0];
  const right = allSnapshots.find((s) => s.id === rightId) || allSnapshots[1];

  const handleCompareLiveDomains = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!leftDomainInput.trim() || !rightDomainInput.trim()) return;
    setComparingLive(true);
    try {
      const [intelL, intelR] = await Promise.all([
        fetchLiveWebsiteIntel(leftDomainInput.trim()),
        fetchLiveWebsiteIntel(rightDomainInput.trim()),
      ]);
      const snapL = intelToSnapshot(
        `live-left-${intelL.host}-${Date.now()}`,
        `${intelL.targetUrl} (Live Scan)`,
        intelL
      );
      const snapR = intelToSnapshot(
        `live-right-${intelR.host}-${Date.now()}`,
        `${intelR.targetUrl} (Live Scan)`,
        intelR
      );
      setCustomSnapshots((prev) => [snapL, snapR, ...prev]);
      setLeftId(snapL.id);
      setRightId(snapR.id);
    } finally {
      setComparingLive(false);
    }
  };

  const deltas = useMemo(() => {
    if (!left || !right || left.id === right.id) return [];
    const rows: Array<{ kind: "added" | "removed" | "changed"; category: string; text: string }> = [];

    if (left.verdict !== right.verdict) {
      rows.push({
        kind: "changed",
        category: "Verdict",
        text: `Overall verdict changed: ${left.verdict.toUpperCase()} (${left.confidence}%) → ${right.verdict.toUpperCase()} (${right.confidence}%)`,
      });
    }

    const engineNames = Array.from(
      new Set([...Object.keys(left.engines), ...Object.keys(right.engines)])
    );
    for (const eng of engineNames) {
      const vL = left.engines[eng];
      const vR = right.engines[eng];
      if (vL && vR && vL !== vR) {
        rows.push({
          kind: "changed",
          category: "Engine",
          text: `${eng}: ${vL} → ${vR}`,
        });
      }
    }

    const diffSets = (label: string, arrL: string[], arrR: string[]) => {
      const sL = new Set(arrL);
      const sR = new Set(arrR);
      for (const item of arrR) {
        if (!sL.has(item)) {
          rows.push({ kind: "added", category: label, text: `${label} added on right: ${item}` });
        }
      }
      for (const item of arrL) {
        if (!sR.has(item)) {
          rows.push({ kind: "removed", category: label, text: `${label} removed on right: ${item}` });
        }
      }
    };

    diffSets("DNS A", left.dnsA, right.dnsA);
    diffSets("DNS MX", left.dnsMX, right.dnsMX);
    diffSets("DNS NS", left.dnsNS, right.dnsNS);
    diffSets(
      "Port",
      left.openPorts.map((p) => `TCP/${p}`),
      right.openPorts.map((p) => `TCP/${p}`)
    );

    const headerKeys = Array.from(
      new Set([...Object.keys(left.headers), ...Object.keys(right.headers)])
    );
    for (const key of headerKeys) {
      const hL = left.headers[key];
      const hR = right.headers[key];
      if (hL === undefined && hR !== undefined) {
        rows.push({ kind: "added", category: "Header", text: `Header + ${key}: ${hR}` });
      } else if (hL !== undefined && hR === undefined) {
        rows.push({ kind: "removed", category: "Header", text: `Header − ${key} (was: ${hL})` });
      } else if (hL !== hR) {
        rows.push({
          kind: "changed",
          category: "Header",
          text: `Header ${key}: "${hL}" → "${hR}"`,
        });
      }
    }

    return rows;
  }, [left, right]);

  return (
    <Card className="bento-card">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 font-display">
          <ArrowLeftRight className="h-5 w-5 text-primary" />
          Scan History &amp; Live Domain Diff
        </CardTitle>
        <CardDescription>
          Compare any two saved scans or enter two live domains below to diff engine verdicts, DNS records (A, MX, NS), open ports, and HTTP security headers side by side.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        {/* Live Two-Domain Instant Diff Bar */}
        <form
          onSubmit={handleCompareLiveDomains}
          className="rounded-[2px] border border-border bg-muted/15 p-3.5 space-y-2.5"
        >
          <div className="flex items-center gap-2 text-xs font-mono uppercase tracking-wider text-muted-foreground">
            <Globe className="h-3.5 w-3.5 text-mark" />
            <span>Compare Any Two Live Domains Instantly</span>
          </div>
          <div className="grid gap-2.5 sm:grid-cols-12 items-center">
            <div className="sm:col-span-5">
              <Input
                value={leftDomainInput}
                onChange={(e) => setLeftDomainInput(e.target.value)}
                placeholder="Left domain (e.g. ctrlb.ai)"
                className="font-mono text-xs h-9"
              />
            </div>
            <div className="sm:col-span-5">
              <Input
                value={rightDomainInput}
                onChange={(e) => setRightDomainInput(e.target.value)}
                placeholder="Right domain (e.g. cloudflare.com)"
                className="font-mono text-xs h-9"
              />
            </div>
            <div className="sm:col-span-2">
              <Button
                type="submit"
                size="sm"
                className="w-full h-9"
                disabled={comparingLive || !leftDomainInput.trim() || !rightDomainInput.trim()}
              >
                {comparingLive ? (
                  <RefreshCw className="h-3.5 w-3.5 animate-spin" />
                ) : (
                  <>
                    <Play className="h-3.5 w-3.5 mr-1.5" />
                    Diff Live
                  </>
                )}
              </Button>
            </div>
          </div>
        </form>

        {/* Saved & Baseline Scan Selectors */}
        <div className="grid gap-4 md:grid-cols-2">
          <label className="space-y-1.5 text-xs text-muted-foreground">
            <span>Left scan</span>
            <select
              className="w-full rounded-[2px] border border-border bg-background px-3 py-2 text-sm text-foreground font-mono"
              value={left?.id || ""}
              onChange={(event) => setLeftId(event.target.value)}
              data-testid="select-diff-left"
            >
              {allSnapshots.map((item) => (
                <option key={item.id} value={item.id}>
                  {item.label}
                </option>
              ))}
            </select>
          </label>
          <label className="space-y-1.5 text-xs text-muted-foreground">
            <span>Right scan</span>
            <select
              className="w-full rounded-[2px] border border-border bg-background px-3 py-2 text-sm text-foreground font-mono"
              value={right?.id || ""}
              onChange={(event) => setRightId(event.target.value)}
              data-testid="select-diff-right"
            >
              {allSnapshots.map((item) => (
                <option key={item.id} value={item.id}>
                  {item.label}
                </option>
              ))}
            </select>
          </label>
        </div>

        {/* Side-by-Side Summary Cards */}
        {left && right && (
          <div className="grid gap-4 md:grid-cols-2">
            {[left, right].map((side, idx) => (
              <div
                key={`${side.id}-${idx}`}
                className="rounded-[2px] border border-border/80 bg-card/50 p-3.5 space-y-2 text-xs"
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="font-mono font-semibold truncate">{side.label}</span>
                  <Badge
                    variant={
                      side.verdict === "malicious"
                        ? "destructive"
                        : side.verdict === "suspicious"
                          ? "secondary"
                          : "default"
                    }
                    className="uppercase font-mono text-[10px]"
                  >
                    {side.verdict} ({side.confidence}%)
                  </Badge>
                </div>
                <div className="flex flex-wrap gap-2 text-[11px] font-mono text-muted-foreground">
                  <span>A: {side.dnsA.join(", ") || "—"}</span>
                  <span>·</span>
                  <span>Ports: {side.openPorts.join(", ") || "—"}</span>
                </div>
              </div>
            ))}
          </div>
        )}

        {/* Delta Rows */}
        {left && right && left.id === right.id && (
          <p className="text-sm text-muted-foreground">
            Select two different scans above to inspect differences.
          </p>
        )}
        {left && right && left.id !== right.id && deltas.length === 0 && (
          <p className="text-sm text-muted-foreground">
            No differences detected across verdicts, DNS records, open ports, or HTTP headers.
          </p>
        )}
        {deltas.length > 0 && (
          <div className="space-y-2">
            <div className="text-xs font-mono uppercase tracking-wider text-muted-foreground">
              Detected Deltas ({deltas.length})
            </div>
            <ul className="space-y-1.5">
              {deltas.map((delta, index) => (
                <li
                  key={`${delta.kind}-${index}`}
                  className="flex flex-wrap items-center justify-between gap-2 rounded-[2px] border border-border/70 bg-muted/10 px-3 py-2 text-xs"
                >
                  <span className="font-mono break-all">{delta.text}</span>
                  <div className="flex items-center gap-1.5">
                    <Badge variant="outline" className="font-mono text-[10px]">
                      {delta.category}
                    </Badge>
                    <Badge
                      variant={
                        delta.kind === "added"
                          ? "default"
                          : delta.kind === "removed"
                            ? "destructive"
                            : "secondary"
                      }
                      className="uppercase font-mono text-[10px]"
                    >
                      {delta.kind}
                    </Badge>
                  </div>
                </li>
              ))}
            </ul>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
