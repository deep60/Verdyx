import { Link } from "wouter";
import { useQuery } from "@tanstack/react-query";
import { Badge } from "@/components/ui/badge";
import { useNowSec } from "@/hooks/use-now";
import { bountiesOnArtifact, bountyStatusLabel, formatThreat } from "@/lib/chain";

/** Bounties already posted on this scan's file or URL, from the server's index of the chain. */
export function ScanBounties({ artifact }: { artifact: string }) {
  const now = useNowSec(30_000);
  const query = useQuery({
    queryKey: ["scan-bounties", artifact],
    queryFn: () => bountiesOnArtifact(artifact),
    enabled: !!artifact,
    staleTime: 15_000,
    refetchInterval: 30_000,
  });
  const list = query.data?.bounties ?? [];
  if (!artifact || query.isLoading || query.isError || !query.data?.indexed || list.length === 0) return null;
  return (
    <div className="mb-6 space-y-2" data-testid="scan-bounties">
      <h3 className="text-sm font-medium text-foreground">
        {list.length === 1 ? "1 bounty on this" : `${list.length} bounties on this`} {artifact.startsWith("http") ? "URL" : "file"}
      </h3>
      <ul className="divide-y divide-border border border-border text-sm">
        {list.map((b) => (
          <li key={b.id.toString()} className="flex flex-wrap items-center gap-x-4 gap-y-1 px-4 py-2">
            <Link href={`/marketplace/bounties/${b.id}`} className="font-mono text-primary underline">
              #{b.id.toString()}
            </Link>
            <span className="font-mono">{formatThreat(b.rewardAmount)} THREAT</span>
            <Badge variant="outline">{bountyStatusLabel(b, now)}</Badge>
            <span className="text-muted-foreground">
              {b.analysisCount.toString()} {b.analysisCount === BigInt(1) ? "analysis" : "analyses"}
            </span>
          </li>
        ))}
      </ul>
    </div>
  );
}
