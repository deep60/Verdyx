import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Progress } from "@/components/ui/progress";
import {
  Globe,
  Shield,
  Lock,
  Server,
  MapPin,
  Network,
  FileCode,
  Cookie,
  Bot,
  Activity,
  Compass,
  GitBranch,
  FileText,
  Wifi,
  Cpu,
  AlertTriangle,
  Search,
  CheckCircle2,
  XCircle,
  Mail,
  Layers,
  Share2,
  ExternalLink,
  History,
  Award,
  Ban,
  Database,
  Eye,
  Camera,
  Leaf,
  RefreshCw,
} from "lucide-react";

interface WebsiteIntelligencePanelProps {
  submissionId?: string;
  initialUrl?: string;
}

type CategoryFilter = "all" | "network" | "tls" | "dns" | "http" | "threat";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type IntelData = Record<string, any>;

export function WebsiteIntelligencePanel({ submissionId, initialUrl }: WebsiteIntelligencePanelProps) {
  const [customUrl, setCustomUrl] = useState(initialUrl || "https://google.com");
  const [activeTargetUrl, setActiveTargetUrl] = useState(initialUrl || "https://google.com");
  const [category, setCategory] = useState<CategoryFilter>("all");
  const [moduleFilter, setModuleFilter] = useState("");

  const queryEndpoint = submissionId
    ? `/api/submissions/${submissionId}/web-intel`
    : `/api/analysis/web-intel?url=${encodeURIComponent(activeTargetUrl)}`;

  const { data: intel, isLoading, isError, refetch, isFetching } = useQuery<IntelData>({
    queryKey: [queryEndpoint],
    enabled: Boolean(submissionId || activeTargetUrl),
    retry: 1,
  });

  const handleInspectSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!customUrl.trim()) return;
    setActiveTargetUrl(customUrl.trim());
  };

  const showCategory = (cat: CategoryFilter, title: string) => {
    const matchesCat = category === "all" || category === cat;
    const matchesSearch =
      !moduleFilter.trim() || title.toLowerCase().includes(moduleFilter.toLowerCase());
    return matchesCat && matchesSearch;
  };

  return (
    <div className="space-y-6">
      {/* Top Bar: Live URL Recon Input + Category Tabs */}
      <Card className="glassmorphism border-primary/30">
        <CardContent className="p-6 space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-4">
            <div>
              <div className="flex items-center gap-2">
                <Globe className="h-5 w-5 text-primary" />
                <h2 className="text-xl font-bold font-display">
                  Deep Website Intelligence & OSINT Reconnaissance
                </h2>
                <Badge variant="outline" className="border-primary/40 text-primary font-mono">
                  36 Live Modules
                </Badge>
              </div>
              <p className="text-sm text-muted-foreground mt-1">
                Live network, TLS, DNS-over-HTTPS, Shodan InternetDB, RDAP/WHOIS, Certificate Transparency, HTTP security, and DOM telemetry.
              </p>
            </div>

            {!submissionId && (
              <form onSubmit={handleInspectSubmit} className="flex items-center gap-2 w-full sm:w-auto">
                <Input
                  value={customUrl}
                  onChange={(e) => setCustomUrl(e.target.value)}
                  placeholder="https://example.com"
                  className="w-full sm:w-72 font-mono text-sm"
                />
                <Button type="submit" disabled={isFetching}>
                  <Search className="h-4 w-4 mr-1.5" />
                  {isFetching ? "Scanning..." : "Inspect Site"}
                </Button>
              </form>
            )}
            {submissionId && (
              <Button variant="outline" size="sm" onClick={() => refetch()} disabled={isFetching}>
                <RefreshCw className={`h-4 w-4 mr-1.5 ${isFetching ? "animate-spin" : ""}`} />
                Re-run Live Recon
              </Button>
            )}
          </div>

          <div className="flex flex-wrap items-center justify-between gap-3 pt-2 border-t border-border/50">
            <div className="flex flex-wrap gap-1.5">
              {(
                [
                  ["all", "All Modules (36)"],
                  ["network", "Network & Server"],
                  ["tls", "SSL / TLS & Security"],
                  ["dns", "DNS, Mail & WHOIS"],
                  ["http", "HTTP, Tech & DOM"],
                  ["threat", "Threat, OSINT & Carbon"],
                ] as const
              ).map(([key, label]) => (
                <Button
                  key={key}
                  size="sm"
                  variant={category === key ? "default" : "outline"}
                  onClick={() => setCategory(key)}
                >
                  {label}
                </Button>
              ))}
            </div>
            <Input
              value={moduleFilter}
              onChange={(e) => setModuleFilter(e.target.value)}
              placeholder="Filter modules (e.g., DNS, TLS, Ports, Whois)..."
              className="w-full sm:w-64 h-8 text-xs"
            />
          </div>
        </CardContent>
      </Card>

      {isLoading ? (
        <Card className="glassmorphism">
          <CardContent className="p-12 text-center space-y-3">
            <RefreshCw className="h-8 w-8 text-primary animate-spin mx-auto" />
            <div className="font-semibold">Running Live OSINT & Network Reconnaissance...</div>
            <p className="text-xs text-muted-foreground">
              Probing DNS-over-HTTPS, TLS handshake, Shodan InternetDB, RDAP WHOIS, Certificate Transparency, Wayback Machine, and DOM headers...
            </p>
          </CardContent>
        </Card>
      ) : isError || !intel ? (
        <Card className="glassmorphism border-destructive/30">
          <CardContent className="p-8 text-center space-y-3">
            <AlertTriangle className="h-8 w-8 text-destructive mx-auto" />
            <div className="font-semibold">Website Reconnaissance Unavailable</div>
            <p className="text-sm text-muted-foreground">
              This artifact may be a binary file rather than a domain/URL, or the target host could not be reached.
            </p>
          </CardContent>
        </Card>
      ) : (
        <>
          {/* Summary Banner */}
          <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-6 gap-3">
            <div className="rounded-lg border border-border/60 bg-card/50 p-3">
              <div className="text-xs text-muted-foreground">Target Host</div>
              <div className="font-mono text-sm font-semibold truncate">{intel.host}</div>
            </div>
            <div className="rounded-lg border border-border/60 bg-card/50 p-3">
              <div className="text-xs text-muted-foreground">Primary IP</div>
              <div className="font-mono text-sm font-semibold text-primary">
                {intel.ipInfo?.primaryIp || "N/A"}
              </div>
            </div>
            <div className="rounded-lg border border-border/60 bg-card/50 p-3">
              <div className="text-xs text-muted-foreground">Server Status</div>
              <div className="text-sm font-semibold flex items-center gap-1.5">
                {intel.serverStatus?.isUp ? (
                  <CheckCircle2 className="h-4 w-4 text-emerald-400" />
                ) : (
                  <XCircle className="h-4 w-4 text-destructive" />
                )}
                <span>
                  HTTP {intel.serverStatus?.statusCode || "—"} ({intel.serverStatus?.responseTimeMs ?? 0}ms)
                </span>
              </div>
            </div>
            <div className="rounded-lg border border-border/60 bg-card/50 p-3">
              <div className="text-xs text-muted-foreground">TLS Audit Grade</div>
              <div className="text-sm font-bold text-emerald-400">
                Grade {intel.tlsSecurityAudit?.grade || "A"}
              </div>
            </div>
            <div className="rounded-lg border border-border/60 bg-card/50 p-3">
              <div className="text-xs text-muted-foreground">HTTP Security</div>
              <div className="text-sm font-bold text-primary">
                Grade {intel.httpSecurity?.grade} ({intel.httpSecurity?.score}/100)
              </div>
            </div>
            <div className="rounded-lg border border-border/60 bg-card/50 p-3">
              <div className="text-xs text-muted-foreground">Carbon Rating</div>
              <div className="text-sm font-bold text-accent">
                Grade {intel.carbonFootprint?.rating} ({intel.carbonFootprint?.co2GramsPerView}g CO₂)
              </div>
            </div>
          </div>

          {/* 36-Module Grid */}
          <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-3">
            {/* 1. IP Info */}
            {showCategory("network", "IP Info") && (
              <Card className="glassmorphism border-primary/20">
                <CardHeader className="pb-2">
                  <CardTitle className="text-base flex items-center gap-2">
                    <Network className="h-4 w-4 text-primary" />
                    IP Info
                  </CardTitle>
                  <CardDescription>Resolved IPv4/IPv6 addresses for host</CardDescription>
                </CardHeader>
                <CardContent className="space-y-2 text-sm">
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Primary IP</span>
                    <span className="font-mono font-semibold">{intel.ipInfo?.primaryIp || "—"}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">IP Family</span>
                    <Badge variant="outline">{intel.ipInfo?.ipVersion}</Badge>
                  </div>
                  <div>
                    <span className="text-xs text-muted-foreground block mb-1">IPv4 Addresses</span>
                    <div className="flex flex-wrap gap-1">
                      {(intel.ipInfo?.ipv4Addresses || []).map((ip: string) => (
                        <Badge key={ip} variant="secondary" className="font-mono text-xs">
                          {ip}
                        </Badge>
                      ))}
                    </div>
                  </div>
                  {(intel.ipInfo?.ipv6Addresses || []).length > 0 && (
                    <div>
                      <span className="text-xs text-muted-foreground block mb-1">IPv6 Addresses</span>
                      <div className="flex flex-wrap gap-1">
                        {(intel.ipInfo?.ipv6Addresses || []).map((ip: string) => (
                          <Badge key={ip} variant="outline" className="font-mono text-[11px]">
                            {ip}
                          </Badge>
                        ))}
                      </div>
                    </div>
                  )}
                </CardContent>
              </Card>
            )}

            {/* 2. Server Location */}
            {showCategory("network", "Server Location") && (
              <Card className="glassmorphism border-primary/20">
                <CardHeader className="pb-2">
                  <CardTitle className="text-base flex items-center gap-2">
                    <MapPin className="h-4 w-4 text-primary" />
                    Server Location
                  </CardTitle>
                  <CardDescription>Where in the world the server is physically hosted</CardDescription>
                </CardHeader>
                <CardContent className="space-y-2 text-sm">
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Country</span>
                    <span className="font-medium">
                      {intel.serverLocation?.country} ({intel.serverLocation?.countryCode})
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">City / Region</span>
                    <span>
                      {intel.serverLocation?.city}, {intel.serverLocation?.region}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Coordinates</span>
                    <span className="font-mono text-xs">
                      {intel.serverLocation?.latitude ?? "—"}, {intel.serverLocation?.longitude ?? "—"}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Timezone</span>
                    <span className="font-mono text-xs">{intel.serverLocation?.timezone}</span>
                  </div>
                </CardContent>
              </Card>
            )}

            {/* 3. Server Status */}
            {showCategory("network", "Server Status") && (
              <Card className="glassmorphism border-primary/20">
                <CardHeader className="pb-2">
                  <CardTitle className="text-base flex items-center gap-2">
                    <Activity className="h-4 w-4 text-primary" />
                    Server Status
                  </CardTitle>
                  <CardDescription>Whether the site is up, and how quickly it responded</CardDescription>
                </CardHeader>
                <CardContent className="space-y-2 text-sm">
                  <div className="flex justify-between items-center">
                    <span className="text-muted-foreground">Availability</span>
                    <Badge variant={intel.serverStatus?.isUp ? "default" : "destructive"}>
                      {intel.serverStatus?.isUp ? "Online (Up)" : "Unreachable"}
                    </Badge>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Response Code</span>
                    <span className="font-mono font-semibold">{intel.serverStatus?.statusCode}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Response Latency</span>
                    <span className="font-mono text-emerald-400">{intel.serverStatus?.responseTimeMs} ms</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Document Size</span>
                    <span className="font-mono">
                      {((intel.serverStatus?.contentLengthBytes || 0) / 1024).toFixed(1)} KB
                    </span>
                  </div>
                </CardContent>
              </Card>
            )}

            {/* 4. Server Info */}
            {showCategory("network", "Server Info") && (
              <Card className="glassmorphism border-primary/20">
                <CardHeader className="pb-2">
                  <CardTitle className="text-base flex items-center gap-2">
                    <Server className="h-4 w-4 text-primary" />
                    Server Info
                  </CardTitle>
                  <CardDescription>Operating system, ASN and the network the host sits on</CardDescription>
                </CardHeader>
                <CardContent className="space-y-2 text-sm">
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Server Banner</span>
                    <span className="font-mono">{intel.serverInfo?.serverBanner}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">ASN</span>
                    <Badge variant="outline" className="font-mono">{intel.serverInfo?.asn}</Badge>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">ISP / Network</span>
                    <span className="truncate max-w-[180px]">{intel.serverInfo?.isp}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Organization</span>
                    <span className="truncate max-w-[180px]">{intel.serverInfo?.organization}</span>
                  </div>
                </CardContent>
              </Card>
            )}

            {/* 5. Open Ports */}
            {showCategory("network", "Open Ports") && (
              <Card className="glassmorphism border-primary/20">
                <CardHeader className="pb-2">
                  <CardTitle className="text-base flex items-center gap-2">
                    <Wifi className="h-4 w-4 text-primary" />
                    Open Ports
                  </CardTitle>
                  <CardDescription>Which common ports are open and reachable on the host</CardDescription>
                </CardHeader>
                <CardContent className="space-y-3 text-sm">
                  <div className="flex flex-wrap gap-1.5">
                    {(intel.openPorts?.ports || []).map((port: number) => (
                      <Badge key={port} variant="secondary" className="font-mono">
                        TCP/{port}
                      </Badge>
                    ))}
                  </div>
                  <p className="text-xs text-muted-foreground">
                    Source: {intel.openPorts?.source} ({intel.openPorts?.totalOpen || 0} reachable ports)
                  </p>
                </CardContent>
              </Card>
            )}

            {/* 6. Associated Hosts */}
            {showCategory("network", "Associated Hosts") && (
              <Card className="glassmorphism border-primary/20">
                <CardHeader className="pb-2">
                  <CardTitle className="text-base flex items-center gap-2">
                    <Compass className="h-4 w-4 text-primary" />
                    Associated Hosts
                  </CardTitle>
                  <CardDescription>Other hostnames Shodan has seen on the same IP address</CardDescription>
                </CardHeader>
                <CardContent className="space-y-2 text-sm max-h-48 overflow-y-auto">
                  {(intel.associatedHosts?.hostnames || []).length > 0 ? (
                    (intel.associatedHosts.hostnames as string[]).map((h) => (
                      <div key={h} className="font-mono text-xs py-1 border-b border-border/40 truncate">
                        {h}
                      </div>
                    ))
                  ) : (
                    <p className="text-xs text-muted-foreground">
                      No additional co-hosted domains reported on this IP.
                    </p>
                  )}
                </CardContent>
              </Card>
            )}

            {/* 7. Traceroute */}
            {showCategory("network", "Traceroute") && (
              <Card className="glassmorphism border-primary/20">
                <CardHeader className="pb-2">
                  <CardTitle className="text-base flex items-center gap-2">
                    <GitBranch className="h-4 w-4 text-primary" />
                    Traceroute
                  </CardTitle>
                  <CardDescription>The network path packets travel to reach the server</CardDescription>
                </CardHeader>
                <CardContent className="space-y-2 text-xs">
                  {(intel.traceroute?.hops || []).map(
                    (hop: { hop: number; node: string; ip: string; rttMs: number }) => (
                      <div key={hop.hop} className="flex items-center justify-between py-1 border-b border-border/30">
                        <span className="font-mono text-muted-foreground">#{hop.hop}</span>
                        <span className="truncate max-w-[160px] font-medium">{hop.node}</span>
                        <span className="font-mono text-primary">{hop.rttMs} ms</span>
                      </div>
                    )
                  )}
                </CardContent>
              </Card>
            )}

            {/* 8. Redirect Chain */}
            {showCategory("network", "Redirect Chain") && (
              <Card className="glassmorphism border-primary/20">
                <CardHeader className="pb-2">
                  <CardTitle className="text-base flex items-center gap-2">
                    <Share2 className="h-4 w-4 text-primary" />
                    Redirect Chain
                  </CardTitle>
                  <CardDescription>The full chain of redirects before the final page loads</CardDescription>
                </CardHeader>
                <CardContent className="space-y-2 text-xs max-h-48 overflow-y-auto">
                  {(intel.redirectChain?.hops || []).map(
                    (hop: { step: number; url: string; statusCode: number; latencyMs: number }) => (
                      <div key={hop.step} className="p-2 rounded bg-muted/20 border border-border/40 space-y-1">
                        <div className="flex justify-between">
                          <Badge variant="outline" className="font-mono text-[10px]">
                            Hop {hop.step} · HTTP {hop.statusCode}
                          </Badge>
                          <span className="font-mono text-muted-foreground">{hop.latencyMs}ms</span>
                        </div>
                        <div className="font-mono truncate">{hop.url}</div>
                      </div>
                    )
                  )}
                </CardContent>
              </Card>
            )}

            {/* 9. SSL Certificate */}
            {showCategory("tls", "SSL Certificate") && (
              <Card className="glassmorphism border-primary/20">
                <CardHeader className="pb-2">
                  <CardTitle className="text-base flex items-center gap-2">
                    <Lock className="h-4 w-4 text-primary" />
                    SSL Certificate
                  </CardTitle>
                  <CardDescription>Certificate issuer, subject, validity, and serial</CardDescription>
                </CardHeader>
                <CardContent className="space-y-2 text-sm">
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Common Name</span>
                    <span className="font-mono text-xs">{intel.sslCertificate?.commonName}</span>
                  </div>
                  <div>
                    <span className="text-xs text-muted-foreground block">Issuer</span>
                    <span className="text-xs font-medium break-all">{intel.sslCertificate?.issuer}</span>
                  </div>
                  <div className="flex justify-between text-xs">
                    <span className="text-muted-foreground">Not Before</span>
                    <span className="font-mono">{intel.sslCertificate?.notBefore || "—"}</span>
                  </div>
                  <div className="flex justify-between text-xs">
                    <span className="text-muted-foreground">Not After</span>
                    <span className="font-mono">{intel.sslCertificate?.notAfter || "—"}</span>
                  </div>
                </CardContent>
              </Card>
            )}

            {/* 10. TLS Connection */}
            {showCategory("tls", "TLS Connection") && (
              <Card className="glassmorphism border-primary/20">
                <CardHeader className="pb-2">
                  <CardTitle className="text-base flex items-center gap-2">
                    <Shield className="h-4 w-4 text-primary" />
                    TLS Connection
                  </CardTitle>
                  <CardDescription>The TLS versions accepted, and cipher details of handshake</CardDescription>
                </CardHeader>
                <CardContent className="space-y-2 text-sm">
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Protocol</span>
                    <Badge variant="default" className="font-mono">{intel.tlsConnection?.protocol}</Badge>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Cipher Family</span>
                    <span className="font-mono text-xs">{intel.tlsConnection?.cipherSuite}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">ALPN</span>
                    <span className="font-mono text-xs">{intel.tlsConnection?.alpn}</span>
                  </div>
                </CardContent>
              </Card>
            )}

            {/* 11. TLS Security Audit */}
            {showCategory("tls", "TLS Security Audit") && (
              <Card className="glassmorphism border-primary/20">
                <CardHeader className="pb-2">
                  <CardTitle className="text-base flex items-center gap-2">
                    <Award className="h-4 w-4 text-primary" />
                    TLS Security Audit
                  </CardTitle>
                  <CardDescription>Audit grade for the server's TLS configuration</CardDescription>
                </CardHeader>
                <CardContent className="space-y-2 text-sm">
                  <div className="flex items-center justify-between">
                    <span className="text-muted-foreground">Overall TLS Grade</span>
                    <span className="text-2xl font-bold text-emerald-400">
                      {intel.tlsSecurityAudit?.grade}
                    </span>
                  </div>
                  <div className="flex justify-between text-xs">
                    <span className="text-muted-foreground">Forward Secrecy</span>
                    <span>{intel.tlsSecurityAudit?.forwardSecrecy ? "Supported" : "No"}</span>
                  </div>
                  <div className="flex justify-between text-xs">
                    <span className="text-muted-foreground">HSTS Preload Ready</span>
                    <span>{intel.tlsSecurityAudit?.hstsPresent ? "Yes" : "No"}</span>
                  </div>
                  <div className="flex justify-between text-xs">
                    <span className="text-muted-foreground">CAA Restriction</span>
                    <span>{intel.tlsSecurityAudit?.caaPresent ? "Present" : "Not Set"}</span>
                  </div>
                </CardContent>
              </Card>
            )}

            {/* 12. TLS Client Compatibility */}
            {showCategory("tls", "TLS Client Compatibility") && (
              <Card className="glassmorphism border-primary/20">
                <CardHeader className="pb-2">
                  <CardTitle className="text-base flex items-center gap-2">
                    <Cpu className="h-4 w-4 text-primary" />
                    TLS Client Compatibility
                  </CardTitle>
                  <CardDescription>Whether Chrome, Safari, Java and older Android can connect</CardDescription>
                </CardHeader>
                <CardContent className="space-y-1.5 text-xs">
                  {(intel.tlsClientCompatibility?.clients || []).map(
                    (c: { client: string; supported: boolean; protocol: string }) => (
                      <div key={c.client} className="flex items-center justify-between py-1 border-b border-border/30">
                        <span>{c.client}</span>
                        <Badge variant={c.supported ? "default" : "outline"} className="text-[10px] font-mono">
                          {c.protocol}
                        </Badge>
                      </div>
                    )
                  )}
                </CardContent>
              </Card>
            )}

            {/* 13. HSTS */}
            {showCategory("tls", "HSTS") && (
              <Card className="glassmorphism border-primary/20">
                <CardHeader className="pb-2">
                  <CardTitle className="text-base flex items-center gap-2">
                    <Lock className="h-4 w-4 text-primary" />
                    HSTS
                  </CardTitle>
                  <CardDescription>Whether browsers are told to only ever connect over HTTPS</CardDescription>
                </CardHeader>
                <CardContent className="space-y-2 text-sm">
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">HSTS Enabled</span>
                    <Badge variant={intel.hsts?.enabled ? "default" : "secondary"}>
                      {intel.hsts?.enabled ? "Enabled" : "Not Enabled"}
                    </Badge>
                  </div>
                  <div className="flex justify-between text-xs">
                    <span className="text-muted-foreground">Max-Age</span>
                    <span className="font-mono">{intel.hsts?.maxAgeSeconds}s</span>
                  </div>
                  <div className="flex justify-between text-xs">
                    <span className="text-muted-foreground">IncludeSubDomains</span>
                    <span>{intel.hsts?.includeSubDomains ? "Yes" : "No"}</span>
                  </div>
                  <div className="flex justify-between text-xs">
                    <span className="text-muted-foreground">Preload</span>
                    <span>{intel.hsts?.preload ? "Yes" : "No"}</span>
                  </div>
                </CardContent>
              </Card>
            )}

            {/* 14. HTTP Security */}
            {showCategory("tls", "HTTP Security") && (
              <Card className="glassmorphism border-primary/20">
                <CardHeader className="pb-2">
                  <CardTitle className="text-base flex items-center gap-2">
                    <Shield className="h-4 w-4 text-primary" />
                    HTTP Security
                  </CardTitle>
                  <CardDescription>Protective headers such as CSP, X-Frame-Options and nosniff</CardDescription>
                </CardHeader>
                <CardContent className="space-y-1.5 text-xs">
                  <div className="flex justify-between">
                    <span>Content-Security-Policy</span>
                    <Badge variant={intel.httpSecurity?.contentSecurityPolicy ? "default" : "outline"}>
                      {intel.httpSecurity?.contentSecurityPolicy ? "Present" : "Missing"}
                    </Badge>
                  </div>
                  <div className="flex justify-between">
                    <span>Strict-Transport-Security</span>
                    <Badge variant={intel.httpSecurity?.strictTransportSecurity ? "default" : "outline"}>
                      {intel.httpSecurity?.strictTransportSecurity ? "Present" : "Missing"}
                    </Badge>
                  </div>
                  <div className="flex justify-between">
                    <span>X-Frame-Options</span>
                    <span className="font-mono">{intel.httpSecurity?.xFrameOptions || "Missing"}</span>
                  </div>
                  <div className="flex justify-between">
                    <span>X-Content-Type-Options</span>
                    <span className="font-mono">{intel.httpSecurity?.xContentTypeOptions || "Missing"}</span>
                  </div>
                  <div className="flex justify-between">
                    <span>Referrer-Policy</span>
                    <span className="font-mono">{intel.httpSecurity?.referrerPolicy || "Missing"}</span>
                  </div>
                </CardContent>
              </Card>
            )}

            {/* 15. Firewall */}
            {showCategory("tls", "Firewall") && (
              <Card className="glassmorphism border-primary/20">
                <CardHeader className="pb-2">
                  <CardTitle className="text-base flex items-center gap-2">
                    <Shield className="h-4 w-4 text-primary" />
                    Firewall (WAF)
                  </CardTitle>
                  <CardDescription>Which web application firewall sits in front of the site</CardDescription>
                </CardHeader>
                <CardContent className="space-y-2 text-sm">
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">WAF Detected</span>
                    <Badge variant={intel.firewall?.detected ? "default" : "outline"}>
                      {intel.firewall?.detected ? "Protected" : "Direct / Unfingerprinted"}
                    </Badge>
                  </div>
                  <div className="flex flex-wrap gap-1.5">
                    {(intel.firewall?.providers || []).map((p: string) => (
                      <Badge key={p} variant="secondary" className="text-xs">
                        {p}
                      </Badge>
                    ))}
                  </div>
                </CardContent>
              </Card>
            )}

            {/* 16. Mixed Content & SRI */}
            {showCategory("tls", "Mixed Content & SRI") && (
              <Card className="glassmorphism border-primary/20">
                <CardHeader className="pb-2">
                  <CardTitle className="text-base flex items-center gap-2">
                    <FileCode className="h-4 w-4 text-primary" />
                    Mixed Content & SRI
                  </CardTitle>
                  <CardDescription>Insecure resources and third-party scripts without SRI</CardDescription>
                </CardHeader>
                <CardContent className="space-y-2 text-sm">
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Mixed Content (`http://`)</span>
                    <Badge variant={intel.mixedContentSri?.mixedContentCount === 0 ? "default" : "destructive"}>
                      {intel.mixedContentSri?.mixedContentCount ?? 0} found
                    </Badge>
                  </div>
                  <div className="flex justify-between text-xs">
                    <span className="text-muted-foreground">Scripts with SRI (`integrity=`)</span>
                    <span className="font-mono">{intel.mixedContentSri?.sriProtectedScripts ?? 0}</span>
                  </div>
                  <div className="flex justify-between text-xs">
                    <span className="text-muted-foreground">External Scripts without SRI</span>
                    <span className="font-mono">{intel.mixedContentSri?.sriMissingScripts ?? 0}</span>
                  </div>
                </CardContent>
              </Card>
            )}

            {/* 17. Security.txt */}
            {showCategory("tls", "Security.txt") && (
              <Card className="glassmorphism border-primary/20">
                <CardHeader className="pb-2">
                  <CardTitle className="text-base flex items-center gap-2">
                    <FileText className="h-4 w-4 text-primary" />
                    Security.txt
                  </CardTitle>
                  <CardDescription>The security.txt file and vulnerability disclosure contacts</CardDescription>
                </CardHeader>
                <CardContent className="space-y-2 text-xs">
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Published</span>
                    <Badge variant={intel.securityTxt?.present ? "default" : "outline"}>
                      {intel.securityTxt?.present ? "Present" : "Not Found"}
                    </Badge>
                  </div>
                  {(intel.securityTxt?.contacts || []).slice(0, 3).map((c: string) => (
                    <div key={c} className="font-mono truncate text-primary">
                      {c}
                    </div>
                  ))}
                  {intel.securityTxt?.expires && (
                    <div className="text-muted-foreground">Expires: {intel.securityTxt.expires}</div>
                  )}
                </CardContent>
              </Card>
            )}

            {/* 18. DNS Records */}
            {showCategory("dns", "DNS Records") && (
              <Card className="glassmorphism border-primary/20">
                <CardHeader className="pb-2">
                  <CardTitle className="text-base flex items-center gap-2">
                    <Database className="h-4 w-4 text-primary" />
                    DNS Records
                  </CardTitle>
                  <CardDescription>A, AAAA, MX, NS, CNAME and SOA records held for the domain</CardDescription>
                </CardHeader>
                <CardContent className="space-y-2 text-xs max-h-56 overflow-y-auto">
                  {(["A", "AAAA", "MX", "NS", "CNAME"] as const).map((rtype) => {
                    const list = intel.dnsRecords?.[rtype] || [];
                    if (list.length === 0) return null;
                    return (
                      <div key={rtype} className="space-y-1">
                        <Badge variant="outline" className="font-mono text-[10px]">
                          {rtype} ({list.length})
                        </Badge>
                        {list.slice(0, 4).map((rec: { data: string; ttl: number }, idx: number) => (
                          <div key={idx} className="flex justify-between font-mono pl-2 text-[11px]">
                            <span className="truncate max-w-[200px]">{rec.data}</span>
                            <span className="text-muted-foreground">{rec.ttl}s</span>
                          </div>
                        ))}
                      </div>
                    );
                  })}
                </CardContent>
              </Card>
            )}

            {/* 19. TXT Records */}
            {showCategory("dns", "TXT Records") && (
              <Card className="glassmorphism border-primary/20">
                <CardHeader className="pb-2">
                  <CardTitle className="text-base flex items-center gap-2">
                    <FileText className="h-4 w-4 text-primary" />
                    TXT Records
                  </CardTitle>
                  <CardDescription>TXT records including domain verification and policy entries</CardDescription>
                </CardHeader>
                <CardContent className="space-y-1.5 text-xs max-h-48 overflow-y-auto">
                  {(intel.txtRecords?.entries || []).length > 0 ? (
                    (intel.txtRecords.entries as string[]).map((txt, idx) => (
                      <div key={idx} className="p-1.5 rounded bg-muted/20 font-mono text-[11px] break-all">
                        {txt}
                      </div>
                    ))
                  ) : (
                    <p className="text-muted-foreground">No TXT records returned.</p>
                  )}
                </CardContent>
              </Card>
            )}

            {/* 20. CAA Records */}
            {showCategory("dns", "CAA Records") && (
              <Card className="glassmorphism border-primary/20">
                <CardHeader className="pb-2">
                  <CardTitle className="text-base flex items-center gap-2">
                    <Shield className="h-4 w-4 text-primary" />
                    CAA Records
                  </CardTitle>
                  <CardDescription>Which certificate authorities may issue certificates</CardDescription>
                </CardHeader>
                <CardContent className="space-y-2 text-xs">
                  {(intel.caaRecords?.records || []).length > 0 ? (
                    (intel.caaRecords.records as Array<{ data: string }>).map((r, i) => (
                      <div key={i} className="font-mono p-1.5 bg-muted/20 rounded break-all">
                        {r.data}
                      </div>
                    ))
                  ) : (
                    <p className="text-muted-foreground">
                      No CAA restrictions published (any trusted CA may issue certificates).
                    </p>
                  )}
                </CardContent>
              </Card>
            )}

            {/* 21. DNSSEC */}
            {showCategory("dns", "DNSSEC") && (
              <Card className="glassmorphism border-primary/20">
                <CardHeader className="pb-2">
                  <CardTitle className="text-base flex items-center gap-2">
                    <CheckCircle2 className="h-4 w-4 text-primary" />
                    DNSSEC
                  </CardTitle>
                  <CardDescription>DNSSEC records proving DNS answers have not been tampered with</CardDescription>
                </CardHeader>
                <CardContent className="space-y-2 text-sm">
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Validation Status</span>
                    <Badge variant={intel.dnssec?.enabled ? "default" : "secondary"}>
                      {intel.dnssec?.enabled ? "Signed (AD=true)" : "Unsigned"}
                    </Badge>
                  </div>
                  <div className="text-xs text-muted-foreground">{intel.dnssec?.status}</div>
                </CardContent>
              </Card>
            )}

            {/* 22. DNS Server */}
            {showCategory("dns", "DNS Server") && (
              <Card className="glassmorphism border-primary/20">
                <CardHeader className="pb-2">
                  <CardTitle className="text-base flex items-center gap-2">
                    <Server className="h-4 w-4 text-primary" />
                    DNS Server
                  </CardTitle>
                  <CardDescription>Which nameservers answer for the domain</CardDescription>
                </CardHeader>
                <CardContent className="space-y-1.5 text-xs">
                  {(intel.dnsServer?.authoritativeNameservers || []).map((ns: string) => (
                    <div key={ns} className="font-mono py-1 border-b border-border/30">
                      {ns}
                    </div>
                  ))}
                </CardContent>
              </Card>
            )}

            {/* 23. Email Configuration */}
            {showCategory("dns", "Email Configuration") && (
              <Card className="glassmorphism border-primary/20">
                <CardHeader className="pb-2">
                  <CardTitle className="text-base flex items-center gap-2">
                    <Mail className="h-4 w-4 text-primary" />
                    Email Configuration
                  </CardTitle>
                  <CardDescription>MX, SPF, DKIM and DMARC records for sending and receiving mail</CardDescription>
                </CardHeader>
                <CardContent className="space-y-2 text-xs">
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Mail Hardened</span>
                    <Badge variant={intel.emailConfiguration?.mailHardened ? "default" : "secondary"}>
                      {intel.emailConfiguration?.mailHardened ? "SPF + DMARC Active" : "Partial"}
                    </Badge>
                  </div>
                  <div>
                    <span className="text-muted-foreground block">SPF Policy:</span>
                    <span className="font-mono text-[11px] break-all">
                      {intel.emailConfiguration?.spfRecord || "None"}
                    </span>
                  </div>
                  <div>
                    <span className="text-muted-foreground block">DMARC Policy:</span>
                    <span className="font-mono text-[11px] break-all">
                      {intel.emailConfiguration?.dmarcRecord || "None"}
                    </span>
                  </div>
                </CardContent>
              </Card>
            )}

            {/* 24. Whois Lookup */}
            {showCategory("dns", "Whois Lookup") && (
              <Card className="glassmorphism border-primary/20">
                <CardHeader className="pb-2">
                  <CardTitle className="text-base flex items-center gap-2">
                    <Search className="h-4 w-4 text-primary" />
                    Whois Lookup (RDAP)
                  </CardTitle>
                  <CardDescription>Registrar, registration dates and nameservers from WHOIS</CardDescription>
                </CardHeader>
                <CardContent className="space-y-2 text-xs">
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Domain Handle</span>
                    <span className="font-mono">{intel.whoisLookup?.handle}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Registered</span>
                    <span className="font-mono">{intel.whoisLookup?.registrationDate?.slice(0, 10) || "—"}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Expires</span>
                    <span className="font-mono">{intel.whoisLookup?.expirationDate?.slice(0, 10) || "—"}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Last Updated</span>
                    <span className="font-mono">{intel.whoisLookup?.lastUpdated?.slice(0, 10) || "—"}</span>
                  </div>
                </CardContent>
              </Card>
            )}

            {/* 25. Domain Info */}
            {showCategory("dns", "Domain Info") && (
              <Card className="glassmorphism border-primary/20">
                <CardHeader className="pb-2">
                  <CardTitle className="text-base flex items-center gap-2">
                    <Globe className="h-4 w-4 text-primary" />
                    Domain Info
                  </CardTitle>
                  <CardDescription>Registry status and transfer lock protection</CardDescription>
                </CardHeader>
                <CardContent className="space-y-2 text-xs">
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Transfer Lock</span>
                    <Badge variant={intel.domainInfo?.transferLocked ? "default" : "outline"}>
                      {intel.domainInfo?.transferLocked ? "Locked (Protected)" : "Standard"}
                    </Badge>
                  </div>
                  <div className="flex flex-wrap gap-1">
                    {(intel.domainInfo?.statusCodes || []).map((st: string) => (
                      <Badge key={st} variant="secondary" className="text-[10px] font-mono">
                        {st}
                      </Badge>
                    ))}
                  </div>
                </CardContent>
              </Card>
            )}

            {/* 26. Subdomains */}
            {showCategory("dns", "Subdomains") && (
              <Card className="glassmorphism border-primary/20">
                <CardHeader className="pb-2">
                  <CardTitle className="text-base flex items-center gap-2">
                    <Layers className="h-4 w-4 text-primary" />
                    Subdomains ({intel.subdomains?.count || 0})
                  </CardTitle>
                  <CardDescription>Subdomains discovered in public Certificate Transparency logs</CardDescription>
                </CardHeader>
                <CardContent className="space-y-1 text-xs max-h-48 overflow-y-auto">
                  {(intel.subdomains?.items || []).length > 0 ? (
                    (intel.subdomains.items as string[]).map((sub) => (
                      <div key={sub} className="font-mono py-0.5 border-b border-border/30 truncate">
                        {sub}
                      </div>
                    ))
                  ) : (
                    <p className="text-muted-foreground">No additional CT log subdomains listed.</p>
                  )}
                </CardContent>
              </Card>
            )}

            {/* 27. Headers */}
            {showCategory("http", "Headers") && (
              <Card className="glassmorphism border-primary/20">
                <CardHeader className="pb-2">
                  <CardTitle className="text-base flex items-center gap-2">
                    <FileCode className="h-4 w-4 text-primary" />
                    HTTP Headers ({intel.headers?.count || 0})
                  </CardTitle>
                  <CardDescription>Every HTTP response header the server sends back</CardDescription>
                </CardHeader>
                <CardContent className="space-y-1.5 text-xs max-h-52 overflow-y-auto">
                  {(intel.headers?.items || []).map((h: { name: string; value: string }, i: number) => (
                    <div key={i} className="border-b border-border/30 pb-1">
                      <span className="font-mono font-semibold text-primary">{h.name}: </span>
                      <span className="font-mono break-all text-muted-foreground">{h.value}</span>
                    </div>
                  ))}
                </CardContent>
              </Card>
            )}

            {/* 28. Cookies */}
            {showCategory("http", "Cookies") && (
              <Card className="glassmorphism border-primary/20">
                <CardHeader className="pb-2">
                  <CardTitle className="text-base flex items-center gap-2">
                    <Cookie className="h-4 w-4 text-primary" />
                    Cookies ({intel.cookies?.count || 0})
                  </CardTitle>
                  <CardDescription>Cookies set on arrival, and how tightly each one is scoped</CardDescription>
                </CardHeader>
                <CardContent className="space-y-2 text-xs max-h-48 overflow-y-auto">
                  {(intel.cookies?.items || []).length > 0 ? (
                    (
                      intel.cookies.items as Array<{
                        name: string;
                        secure: boolean;
                        httpOnly: boolean;
                        sameSite: string;
                        scopeRating: string;
                      }>
                    ).map((c, idx) => (
                      <div key={idx} className="p-2 rounded bg-muted/20 border border-border/40 space-y-1">
                        <div className="flex justify-between font-mono font-semibold">
                          <span>{c.name}</span>
                          <Badge variant="outline" className="text-[10px]">{c.scopeRating}</Badge>
                        </div>
                        <div className="text-[11px] text-muted-foreground">
                          Secure: {String(c.secure)} · HttpOnly: {String(c.httpOnly)} · SameSite: {c.sameSite}
                        </div>
                      </div>
                    ))
                  ) : (
                    <p className="text-muted-foreground">No Set-Cookie headers sent on initial page load.</p>
                  )}
                </CardContent>
              </Card>
            )}

            {/* 29. Crawl Rules */}
            {showCategory("http", "Crawl Rules") && (
              <Card className="glassmorphism border-primary/20">
                <CardHeader className="pb-2">
                  <CardTitle className="text-base flex items-center gap-2">
                    <Bot className="h-4 w-4 text-primary" />
                    Crawl Rules (robots.txt)
                  </CardTitle>
                  <CardDescription>Crawl rules published for search engines and AI crawlers</CardDescription>
                </CardHeader>
                <CardContent className="space-y-2 text-xs max-h-48 overflow-y-auto">
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">robots.txt</span>
                    <Badge variant={intel.crawlRules?.present ? "default" : "outline"}>
                      {intel.crawlRules?.present ? `${intel.crawlRules.rulesCount} rules` : "Not Found"}
                    </Badge>
                  </div>
                  {(intel.crawlRules?.preview || []).map((line: string, i: number) => (
                    <div key={i} className="font-mono text-[11px] text-muted-foreground truncate">
                      {line}
                    </div>
                  ))}
                </CardContent>
              </Card>
            )}

            {/* 30. Sitemap */}
            {showCategory("http", "Sitemap") && (
              <Card className="glassmorphism border-primary/20">
                <CardHeader className="pb-2">
                  <CardTitle className="text-base flex items-center gap-2">
                    <Compass className="h-4 w-4 text-primary" />
                    Sitemap
                  </CardTitle>
                  <CardDescription>The pages a site lists in its own sitemap.xml</CardDescription>
                </CardHeader>
                <CardContent className="space-y-2 text-xs max-h-48 overflow-y-auto">
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Discovered Entries</span>
                    <Badge variant="secondary">{intel.sitemap?.urlCount || 0}</Badge>
                  </div>
                  {(intel.sitemap?.sampleUrls || []).map((u: string, i: number) => (
                    <div key={i} className="font-mono text-[11px] truncate text-primary">
                      {u}
                    </div>
                  ))}
                </CardContent>
              </Card>
            )}

            {/* 31. Tech Stack */}
            {showCategory("http", "Tech Stack") && (
              <Card className="glassmorphism border-primary/20">
                <CardHeader className="pb-2">
                  <CardTitle className="text-base flex items-center gap-2">
                    <Cpu className="h-4 w-4 text-primary" />
                    Tech Stack
                  </CardTitle>
                  <CardDescription>Frameworks, analytics and services the site is built with</CardDescription>
                </CardHeader>
                <CardContent className="space-y-2 text-xs">
                  <div className="flex flex-wrap gap-1.5">
                    {(intel.techStack?.technologies || []).map(
                      (t: { name: string; category: string }, idx: number) => (
                        <Badge key={idx} variant="secondary">
                          {t.name} <span className="text-muted-foreground ml-1">({t.category})</span>
                        </Badge>
                      )
                    )}
                  </div>
                </CardContent>
              </Card>
            )}

            {/* 32. Linked Pages */}
            {showCategory("http", "Linked Pages") && (
              <Card className="glassmorphism border-primary/20">
                <CardHeader className="pb-2">
                  <CardTitle className="text-base flex items-center gap-2">
                    <ExternalLink className="h-4 w-4 text-primary" />
                    Linked Pages
                  </CardTitle>
                  <CardDescription>Internal and external links found in anchor tags</CardDescription>
                </CardHeader>
                <CardContent className="space-y-2 text-xs">
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Internal Links</span>
                    <Badge variant="outline">{intel.linkedPages?.internalCount || 0}</Badge>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">External Links</span>
                    <Badge variant="outline">{intel.linkedPages?.externalCount || 0}</Badge>
                  </div>
                  <div className="max-h-28 overflow-y-auto space-y-1 pt-1">
                    {(intel.linkedPages?.external || []).slice(0, 6).map((l: string, i: number) => (
                      <div key={i} className="font-mono text-[11px] truncate text-muted-foreground">
                        {l}
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
            )}

            {/* 33. Social Tags & Presence */}
            {showCategory("http", "Social Tags") && (
              <Card className="glassmorphism border-primary/20">
                <CardHeader className="pb-2">
                  <CardTitle className="text-base flex items-center gap-2">
                    <Share2 className="h-4 w-4 text-primary" />
                    Social Tags & Presence
                  </CardTitle>
                  <CardDescription>Open Graph, Twitter tags, and linked social profiles</CardDescription>
                </CardHeader>
                <CardContent className="space-y-2 text-xs">
                  <div>
                    <span className="text-muted-foreground block">Title:</span>
                    <span className="font-medium">{intel.socialTags?.title || intel.socialTags?.ogTitle || "—"}</span>
                  </div>
                  <div>
                    <span className="text-muted-foreground block">Description:</span>
                    <span className="text-muted-foreground line-clamp-2">
                      {intel.socialTags?.description || intel.socialTags?.ogDescription || "—"}
                    </span>
                  </div>
                  <div className="flex flex-wrap gap-1 pt-1">
                    {(intel.socialPresence?.profiles || []).map(
                      (p: { platform: string; url: string }, idx: number) => (
                        <a key={idx} href={p.url} target="_blank" rel="noreferrer">
                          <Badge variant="outline" className="cursor-pointer hover:border-primary">
                            {p.platform}
                          </Badge>
                        </a>
                      )
                    )}
                  </div>
                </CardContent>
              </Card>
            )}

            {/* 34. Quality Metrics */}
            {showCategory("http", "Quality Metrics") && (
              <Card className="glassmorphism border-primary/20">
                <CardHeader className="pb-2">
                  <CardTitle className="text-base flex items-center gap-2">
                    <Award className="h-4 w-4 text-primary" />
                    Quality Metrics
                  </CardTitle>
                  <CardDescription>Performance, accessibility, SEO and best practice scores</CardDescription>
                </CardHeader>
                <CardContent className="space-y-2.5 text-xs">
                  {(
                    [
                      ["Performance", intel.qualityMetrics?.performance ?? 90],
                      ["Accessibility", intel.qualityMetrics?.accessibility ?? 85],
                      ["Best Practices", intel.qualityMetrics?.bestPractices ?? 90],
                      ["SEO", intel.qualityMetrics?.seo ?? 90],
                    ] as const
                  ).map(([label, val]) => (
                    <div key={label} className="space-y-1">
                      <div className="flex justify-between">
                        <span>{label}</span>
                        <span className="font-mono font-semibold">{val}/100</span>
                      </div>
                      <Progress value={Number(val)} className="h-1.5" />
                    </div>
                  ))}
                </CardContent>
              </Card>
            )}

            {/* 35. Vulnerabilities */}
            {showCategory("threat", "Vulnerabilities") && (
              <Card className="glassmorphism border-primary/20">
                <CardHeader className="pb-2">
                  <CardTitle className="text-base flex items-center gap-2">
                    <AlertTriangle className="h-4 w-4 text-primary" />
                    Vulnerabilities (CVEs)
                  </CardTitle>
                  <CardDescription>CVEs Shodan links to the services running on the host</CardDescription>
                </CardHeader>
                <CardContent className="space-y-2 text-xs">
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Linked CVEs</span>
                    <Badge variant={(intel.vulnerabilities?.count || 0) === 0 ? "default" : "destructive"}>
                      {intel.vulnerabilities?.count || 0} CVEs
                    </Badge>
                  </div>
                  <p className="text-muted-foreground">{intel.vulnerabilities?.status}</p>
                  <div className="flex flex-wrap gap-1">
                    {(intel.vulnerabilities?.cves || []).slice(0, 8).map((cve: string) => (
                      <Badge key={cve} variant="destructive" className="font-mono text-[10px]">
                        {cve}
                      </Badge>
                    ))}
                  </div>
                </CardContent>
              </Card>
            )}

            {/* 36. Malware & Phishing + Block Detection */}
            {showCategory("threat", "Malware & Phishing") && (
              <Card className="glassmorphism border-primary/20">
                <CardHeader className="pb-2">
                  <CardTitle className="text-base flex items-center gap-2">
                    <Ban className="h-4 w-4 text-primary" />
                    Malware, Phishing & Blocklists
                  </CardTitle>
                  <CardDescription>Threat heuristics and protective DNS resolver block checks</CardDescription>
                </CardHeader>
                <CardContent className="space-y-2 text-xs">
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Risk Assessment</span>
                    <Badge variant={intel.malwarePhishing?.riskLevel === "Clean" ? "default" : "destructive"}>
                      {intel.malwarePhishing?.riskLevel}
                    </Badge>
                  </div>
                  <div className="text-muted-foreground">{intel.malwarePhishing?.verdict}</div>
                  <div className="pt-1 space-y-1">
                    {(intel.blockDetection?.resolvers || []).map(
                      (r: { provider: string; blocked: boolean }) => (
                        <div key={r.provider} className="flex justify-between">
                          <span>{r.provider}</span>
                          <span className={r.blocked ? "text-destructive" : "text-emerald-400"}>
                            {r.blocked ? "Blocked" : "Allowed"}
                          </span>
                        </div>
                      )
                    )}
                  </div>
                </CardContent>
              </Card>
            )}

            {/* 37. Data Breaches */}
            {showCategory("threat", "Data Breaches") && (
              <Card className="glassmorphism border-primary/20">
                <CardHeader className="pb-2">
                  <CardTitle className="text-base flex items-center gap-2">
                    <Database className="h-4 w-4 text-primary" />
                    Data Breaches (HIBP)
                  </CardTitle>
                  <CardDescription>Known historical data breaches recorded for the domain</CardDescription>
                </CardHeader>
                <CardContent className="space-y-2 text-xs max-h-48 overflow-y-auto">
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Recorded Incidents</span>
                    <Badge variant="outline">{intel.dataBreaches?.count || 0}</Badge>
                  </div>
                  {(intel.dataBreaches?.breaches || []).map(
                    (b: { title: string; breachDate: string; pwnCount: number }, idx: number) => (
                      <div key={idx} className="flex justify-between py-1 border-b border-border/30">
                        <span className="font-medium truncate max-w-[150px]">{b.title}</span>
                        <span className="font-mono text-muted-foreground">{b.breachDate}</span>
                      </div>
                    )
                  )}
                </CardContent>
              </Card>
            )}

            {/* 38. Trackers & Third Parties */}
            {showCategory("threat", "Trackers & Third Parties") && (
              <Card className="glassmorphism border-primary/20">
                <CardHeader className="pb-2">
                  <CardTitle className="text-base flex items-center gap-2">
                    <Eye className="h-4 w-4 text-primary" />
                    Trackers & Third Parties
                  </CardTitle>
                  <CardDescription>Analytics, ad trackers and external script hosts loaded</CardDescription>
                </CardHeader>
                <CardContent className="space-y-2 text-xs">
                  <div className="flex flex-wrap gap-1">
                    {(intel.trackersThirdParties?.detectedTrackers || []).map((t: string) => (
                      <Badge key={t} variant="secondary">
                        {t}
                      </Badge>
                    ))}
                  </div>
                  <div className="space-y-1 max-h-28 overflow-y-auto">
                    {(intel.trackersThirdParties?.thirdPartyScriptHosts || []).map((h: string) => (
                      <div key={h} className="font-mono text-[11px] text-muted-foreground truncate">
                        {h}
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
            )}

            {/* 39. Archive History & Global Ranking */}
            {showCategory("threat", "Archive History") && (
              <Card className="glassmorphism border-primary/20">
                <CardHeader className="pb-2">
                  <CardTitle className="text-base flex items-center gap-2">
                    <History className="h-4 w-4 text-primary" />
                    Archive History & Global Rank
                  </CardTitle>
                  <CardDescription>Wayback Machine snapshots and domain ranking tier</CardDescription>
                </CardHeader>
                <CardContent className="space-y-2 text-xs">
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Global Tier</span>
                    <Badge variant="outline">{intel.globalRanking?.tier}</Badge>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Wayback Archive</span>
                    <span>{intel.archiveHistory?.available ? "Archived" : "No Snapshot"}</span>
                  </div>
                  {intel.archiveHistory?.waybackOverviewUrl && (
                    <a
                      href={intel.archiveHistory.waybackOverviewUrl}
                      target="_blank"
                      rel="noreferrer"
                      className="text-primary hover:underline inline-flex items-center gap-1"
                    >
                      View Wayback Machine Timeline <ExternalLink className="h-3 w-3" />
                    </a>
                  )}
                </CardContent>
              </Card>
            )}

            {/* 40. Carbon Footprint */}
            {showCategory("threat", "Carbon Footprint") && (
              <Card className="glassmorphism border-primary/20">
                <CardHeader className="pb-2">
                  <CardTitle className="text-base flex items-center gap-2">
                    <Leaf className="h-4 w-4 text-emerald-400" />
                    Carbon Footprint
                  </CardTitle>
                  <CardDescription>Estimated CO₂ from the data needed to load the page</CardDescription>
                </CardHeader>
                <CardContent className="space-y-2 text-xs">
                  <div className="flex justify-between items-center">
                    <span className="text-muted-foreground">Sustainability Grade</span>
                    <Badge className="bg-emerald-500/20 text-emerald-300 border-emerald-500/40">
                      Grade {intel.carbonFootprint?.rating}
                    </Badge>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">CO₂ per Page View</span>
                    <span className="font-mono">{intel.carbonFootprint?.co2GramsPerView} g</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Energy per View</span>
                    <span className="font-mono">{intel.carbonFootprint?.energyKwhPerView} kWh</span>
                  </div>
                </CardContent>
              </Card>
            )}

            {/* 41. Live Screenshot */}
            {showCategory("http", "Screenshot") && (
              <Card className="glassmorphism border-primary/20 md:col-span-2 lg:col-span-3">
                <CardHeader className="pb-2">
                  <CardTitle className="text-base flex items-center gap-2">
                    <Camera className="h-4 w-4 text-primary" />
                    Live Website Render Preview
                  </CardTitle>
                  <CardDescription>Visual render of {intel.targetUrl}</CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="rounded-lg overflow-hidden border border-border bg-black/40 max-h-96 flex items-center justify-center">
                    <img
                      src={intel.screenshot?.imageUrl}
                      alt={`Screenshot of ${intel.host}`}
                      className="w-full h-auto max-h-96 object-cover object-top"
                      loading="lazy"
                    />
                  </div>
                </CardContent>
              </Card>
            )}
          </div>
        </>
      )}
    </div>
  );
}
