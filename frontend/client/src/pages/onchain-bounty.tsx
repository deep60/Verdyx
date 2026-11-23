import { Link, useRoute } from "wouter";
import { useQuery } from "@tanstack/react-query";
import { ArrowLeft } from "lucide-react";
import { Navigation } from "@/components/navigation";
import { SEO } from "@/components/seo";
import { Badge } from "@/components/ui/badge";
import { BountyActions } from "@/components/bounty-actions";
import { useChainInfo } from "@/hooks/use-wallet";
import { useNowSec } from "@/hooks/use-now";
import {
  BOUNTY_VERDICT,
  bountyStatusLabel,
  bountyWithAnalyses,
  evidenceLink,
  explorerAddress,
  formatThreat,
  shortAddress,
  type ChainInfo,
  type OnChainAnalysis,
} from "@/lib/chain";

export default function OnChainBountyPage() {
  const [, params] = useRoute("/marketplace/bounties/:id");
  const raw = params?.id ?? "";
  const id = /^\d{1,30}$/.test(raw) && raw !== "0" ? BigInt(raw) : null;
  const { data: info, isLoading } = useChainInfo();

  return (
    <div className="min-h-screen bg-background text-foreground">
      <SEO noindex title={id ? `Bounty #${id}` : "Bounty"} description="An on-chain bounty: analyses, stakes and the outcome." />
      <Navigation />
      <main id="main-content" tabIndex={-1} className="relative z-10 py-8">
        <div className="mx-auto max-w-5xl space-y-8 px-4 sm:px-6 lg:px-8">
          <Link href="/marketplace" className="inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground">
            <ArrowLeft className="h-4 w-4" /> Marketplace
          </Link>
          {isLoading ? null : !info?.enabled || !info.contracts ? (
            <p className="text-sm text-muted-foreground" data-testid="marketplace-not-deployed">
              The on-chain marketplace isn't deployed yet.
            </p>
          ) : id === null ? (
            <p className="text-sm text-destructive">That isn't a bounty number.</p>
          ) : (
            <BountyDetail info={info} id={id} />
          )}
        </div>
      </main>
    </div>
  );
}

function BountyDetail({ info, id }: { info: ChainInfo; id: bigint }) {
  const now = useNowSec();
  const query = useQuery({
    queryKey: ["onchain-bounty", info.chainId, info.contracts?.bountyManager, id.toString()],
    queryFn: () => bountyWithAnalyses(info, id),
    staleTime: 10_000,
    refetchInterval: 30_000,
    retry: false,
  });

  if (query.isLoading) return <p className="text-sm text-muted-foreground">Reading bounty #{id.toString()}…</p>;
  if (query.isError || !query.data) {
    const msg = String((query.error as Error | null)?.message ?? "");
    return (
      <p className="text-sm text-destructive" data-testid="bounty-not-found">
        {msg.includes("Invalid bounty ID")
          ? `There's no bounty #${id} on ${info.chainName}.`
          : `Couldn't read bounty #${id} from ${info.chainName}. Try again shortly.`}
      </p>
    );
  }
  const { bounty: b, analyses } = query.data;
  const deadline = new Date(Number(b.deadline) * 1000);
  const creatorLink = explorerAddress(info, b.creator);

  return (
    <>
      <header className="space-y-3">
        <div className="flex flex-wrap items-center gap-3">
          <h1 className="font-display text-3xl font-bold tracking-[-0.03em]">Bounty #{b.id.toString()}</h1>
          <Badge variant="outline" data-testid="bounty-status">
            {bountyStatusLabel(b, now)}
          </Badge>
        </div>
        <p className="text-muted-foreground">{b.description}</p>
        <dl className="grid gap-x-8 gap-y-3 text-sm sm:grid-cols-2 lg:grid-cols-4">
          <Fact label="Reward" value={`${formatThreat(b.rewardAmount)} THREAT`} testId="bounty-reward" />
          <Fact label="Staked by analysts" value={`${formatThreat(b.totalStaked)} THREAT`} />
          <Fact label={now > Number(b.deadline) ? "Closed" : "Closes"} value={deadline.toLocaleString()} />
          <Fact
            label="Posted by"
            value={
              creatorLink ? (
                <a className="underline" href={creatorLink} target="_blank" rel="noreferrer">
                  {shortAddress(b.creator)}
                </a>
              ) : (
                shortAddress(b.creator)
              )
            }
            mono
          />
        </dl>
        <div className="text-sm">
          <span className="text-muted-foreground">{b.artifactType === "url" ? "URL" : "SHA-256"}: </span>
          <span className="break-all font-mono text-xs">{b.artifactHash}</span>
        </div>
      </header>

      <BountyActions info={info} bounty={b} analyses={analyses} now={now} />

      <section aria-labelledby="analyses-heading" className="space-y-3">
        <h2 id="analyses-heading" className="text-xl font-semibold">
          Analyses ({analyses.length})
        </h2>
        {analyses.length === 0 ? (
          <p className="text-sm text-muted-foreground" data-testid="no-analyses">
            No analyses yet.
          </p>
        ) : (
          <AnalysesTable info={info} analyses={analyses} />
        )}
      </section>
    </>
  );
}

function Fact({ label, value, mono, testId }: { label: string; value: React.ReactNode; mono?: boolean; testId?: string }) {
  return (
    <div>
      <dt className="text-muted-foreground">{label}</dt>
      <dd className={mono ? "font-mono" : undefined} data-testid={testId}>
        {value}
      </dd>
    </div>
  );
}

function AnalysesTable({ info, analyses }: { info: ChainInfo; analyses: OnChainAnalysis[] }) {
  return (
    <div className="overflow-x-auto border border-border" data-testid="analyses-table">
      <table className="w-full text-sm">
        <thead className="bg-muted/40 text-left text-muted-foreground">
          <tr>
            <th className="px-4 py-2 font-medium">Analyst</th>
            <th className="px-4 py-2 font-medium">Verdict</th>
            <th className="px-4 py-2 font-medium">Confidence</th>
            <th className="px-4 py-2 font-medium">Stake</th>
            <th className="px-4 py-2 font-medium">Evidence</th>
          </tr>
        </thead>
        <tbody>
          {analyses.map((a) => {
            const link = evidenceLink(a.analysisHash);
            const who = explorerAddress(info, a.analyst);
            return (
              <tr key={a.analyst} className="border-t border-border align-top">
                <td className="px-4 py-2 font-mono text-xs">
                  {who ? (
                    <a className="underline" href={who} target="_blank" rel="noreferrer">
                      {shortAddress(a.analyst)}
                    </a>
                  ) : (
                    shortAddress(a.analyst)
                  )}
                </td>
                <td className="px-4 py-2">{BOUNTY_VERDICT[a.verdict] ?? "Unknown"}</td>
                <td className="px-4 py-2 font-mono">{a.confidence.toString()}%</td>
                <td className="px-4 py-2 font-mono">{formatThreat(a.stakeAmount)}</td>
                <td className="max-w-[20rem] px-4 py-2 text-xs">
                  {link ? (
                    <a className="break-all text-primary underline" href={link} target="_blank" rel="noreferrer nofollow ugc">
                      {link}
                    </a>
                  ) : (
                    <span className="break-words">{a.analysisHash}</span>
                  )}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
