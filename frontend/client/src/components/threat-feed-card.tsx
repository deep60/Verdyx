import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { useToast } from "@/hooks/use-toast";
import { taxiiDiscoveryUrl } from "@/lib/api-origin";
import { Copy, Rss } from "lucide-react";

/**
 * How to connect a TAXII 2.1 client (OpenCTI, MISP, a SIEM) to the feed.
 * With a team, names that team's collection and says to use a team key.
 */
export function ThreatFeedCard({ team, origin }: { team?: { id: string; name: string }; origin?: string }) {
  const { toast } = useToast();
  const url = taxiiDiscoveryUrl(origin);
  const copy = async (value: string) => {
    try {
      await navigator.clipboard.writeText(value);
      toast({ title: "Copied" });
    } catch {
      toast({ title: "Copy failed", description: "Select it and copy it.", variant: "destructive" });
    }
  };
  const row = (label: string, value: string) => (
    <div className="space-y-1">
      <div className="text-xs text-muted-foreground">{label}</div>
      <div className="flex items-center gap-2">
        <code className="flex-1 break-all rounded bg-muted/40 px-2 py-1 font-mono text-xs">{value}</code>
        <Button size="sm" variant="outline" onClick={() => copy(value)} aria-label={`Copy ${label}`}>
          <Copy className="h-3.5 w-3.5" />
        </Button>
      </div>
    </div>
  );
  return (
    <Card className="glassmorphism" data-testid="threat-feed-card">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Rss className="h-5 w-5 text-primary" /> Threat feed (TAXII 2.1)
        </CardTitle>
        <CardDescription>
          {team ? `Scans saved to ${team.name}` : "Your scans"} that come out malicious or suspicious, as STIX 2.1
          indicators (file hashes, URLs, and the domains and IP addresses engines found). Connect OpenCTI, MISP or a SIEM.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-3 text-sm">
        {row("Discovery URL", url)}
        {team && row("Collection ID", team.id)}
        <p className="text-xs text-muted-foreground">
          Sign in with HTTP Basic: any username, and {team ? "a team key" : "an API key"} with the{" "}
          <span className="font-mono">read</span> scope as the password. {team ? "" : "Your client lists “My scans” and one collection per team you're in."}
        </p>
      </CardContent>
    </Card>
  );
}
