import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { WalletGate } from "@/components/wallet-gate";
import { useChainInfo, useWallet } from "@/hooks/use-wallet";
import { useToast } from "@/hooks/use-toast";
import {
  BOUNTY_STATUS,
  BOUNTY_VERDICT,
  bountyManagerAbi,
  explorerAddress,
  explorerTx,
  formatThreat,
  latestBounties,
  publicClientFor,
  shortAddress,
  tokenAbi,
  walletErrorMessage,
  type ChainInfo,
  type OnChainBounty,
} from "@/lib/chain";

/** Bounties as the contract records them, and the person's own balance. */
export function OnChainBounties() {
  const { data: info, isLoading, isError } = useChainInfo();
  if (isLoading) return null;
  if (isError || !info?.enabled || !info.contracts) {
    return (
      <p className="text-sm text-muted-foreground" data-testid="marketplace-not-deployed">
        The on-chain marketplace isn't deployed yet. When it is, bounties posted from any wallet appear here, read
        straight from the contract.
      </p>
    );
  }
  return (
    <div className="space-y-8">
      <YourWallet info={info} />
      <BountyList info={info} />
    </div>
  );
}

function YourWallet({ info }: { info: ChainInfo }) {
  const wallet = useWallet();
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const contracts = info.contracts!;
  const [withdrawing, setWithdrawing] = useState(false);
  const ready = !!wallet.account && wallet.chainId === info.chainId;

  const balances = useQuery({
    queryKey: ["threat-balance", info.chainId, wallet.account, "with-pending"],
    enabled: ready,
    // The chain changes outside this app (rewards, refunds), so don't keep it forever.
    staleTime: 10_000,
    refetchInterval: 30_000,
    queryFn: async () => {
      const client = publicClientFor(info);
      const [balance, owed] = await Promise.all([
        client.readContract({ address: contracts.threatToken, abi: tokenAbi, functionName: "balanceOf", args: [wallet.account!] }),
        client.readContract({
          address: contracts.bountyManager,
          abi: bountyManagerAbi,
          functionName: "pendingWithdrawals",
          args: [wallet.account!],
        }),
      ]);
      return { balance, owed };
    },
  });

  async function withdraw() {
    const client = wallet.client(info);
    if (!client) return;
    setWithdrawing(true);
    try {
      const hash = await client.writeContract({ address: contracts.bountyManager, abi: bountyManagerAbi, functionName: "withdraw" });
      await publicClientFor(info).waitForTransactionReceipt({ hash });
      const link = explorerTx(info, hash);
      toast({ title: "Withdrawn to your wallet", description: link ?? hash });
      queryClient.invalidateQueries({ queryKey: ["threat-balance"] });
    } catch (err) {
      toast({ title: "The withdrawal failed", description: walletErrorMessage(err), variant: "destructive" });
    } finally {
      setWithdrawing(false);
    }
  }

  return (
    <div className="border border-border bg-card/50 p-6" data-testid="your-wallet">
      <h3 className="mb-3 text-lg font-medium text-foreground">Your wallet</h3>
      <WalletGate info={info} wallet={wallet}>
        <div className="flex flex-wrap items-center gap-x-8 gap-y-3 text-sm">
          <div>
            <div className="text-muted-foreground">Account</div>
            <div className="font-mono">{shortAddress(wallet.account ?? "")}</div>
          </div>
          <div>
            <div className="text-muted-foreground">THREAT</div>
            <div className="font-mono" data-testid="text-threat-balance">
              {balances.data ? formatThreat(balances.data.balance) : "…"}
            </div>
          </div>
          <div>
            <div className="text-muted-foreground">Owed to you</div>
            <div className="font-mono" data-testid="text-threat-owed">
              {balances.data ? formatThreat(balances.data.owed) : "…"}
            </div>
          </div>
          {balances.data && balances.data.owed > BigInt(0) && (
            <Button size="sm" onClick={withdraw} disabled={withdrawing} data-testid="button-withdraw">
              {withdrawing ? "Confirm in your wallet…" : "Withdraw"}
            </Button>
          )}
        </div>
        <p className="mt-3 text-xs text-muted-foreground">
          Rewards and returned stakes wait in the contract until you withdraw them. Only your wallet can.
        </p>
      </WalletGate>
    </div>
  );
}

function BountyList({ info }: { info: ChainInfo }) {
  const bounties = useQuery({
    queryKey: ["onchain-bounties", info.chainId, info.contracts?.bountyManager],
    queryFn: () => latestBounties(info, 20),
    staleTime: 10_000,
    refetchInterval: 30_000,
  });

  if (bounties.isLoading) return <p className="text-sm text-muted-foreground">Reading bounties from {info.chainName}…</p>;
  if (bounties.isError) {
    return <p className="text-sm text-destructive">Couldn't read bounties from {info.chainName}. Try again shortly.</p>;
  }
  const list = bounties.data ?? [];
  if (list.length === 0) {
    return (
      <p className="text-sm text-muted-foreground" data-testid="no-onchain-bounties">
        No bounties yet. Open a scan report and post one from its Bounty section.
      </p>
    );
  }
  return (
    <div className="overflow-x-auto border border-border" data-testid="onchain-bounty-list">
      <table className="w-full text-sm">
        <thead className="bg-muted/40 text-left text-muted-foreground">
          <tr>
            <th className="px-4 py-2 font-medium">#</th>
            <th className="px-4 py-2 font-medium">Artifact</th>
            <th className="px-4 py-2 font-medium">Reward</th>
            <th className="px-4 py-2 font-medium">Status</th>
            <th className="px-4 py-2 font-medium">Analyses</th>
            <th className="px-4 py-2 font-medium">Deadline</th>
            <th className="px-4 py-2 font-medium">Posted by</th>
          </tr>
        </thead>
        <tbody>
          {list.map((b) => (
            <BountyRow key={b.id.toString()} b={b} info={info} />
          ))}
        </tbody>
      </table>
    </div>
  );
}

function BountyRow({ b, info }: { b: OnChainBounty; info: ChainInfo }) {
  const status = BOUNTY_STATUS[b.status] ?? "Unknown";
  const verdict = BOUNTY_VERDICT[b.consensusVerdict] ?? "Pending";
  const deadline = new Date(Number(b.deadline) * 1000);
  const creatorLink = explorerAddress(info, b.creator);
  return (
    <tr className="border-t border-border align-top">
      <td className="px-4 py-2 font-mono">{b.id.toString()}</td>
      <td className="max-w-[16rem] px-4 py-2">
        <div className="truncate font-mono text-xs" title={b.artifactHash}>
          {b.artifactHash}
        </div>
        <div className="truncate text-xs text-muted-foreground" title={b.description}>
          {b.artifactType} · {b.description}
        </div>
      </td>
      <td className="px-4 py-2 font-mono">{formatThreat(b.rewardAmount)}</td>
      <td className="px-4 py-2">
        <Badge variant="outline">{status === "Completed" ? `${status}: ${verdict}` : status}</Badge>
      </td>
      <td className="px-4 py-2 font-mono">{b.analysisCount.toString()}</td>
      <td className="px-4 py-2 whitespace-nowrap">{deadline.toLocaleString()}</td>
      <td className="px-4 py-2 font-mono text-xs">
        {creatorLink ? (
          <a className="underline" href={creatorLink} target="_blank" rel="noreferrer">
            {shortAddress(b.creator)}
          </a>
        ) : (
          shortAddress(b.creator)
        )}
      </td>
    </tr>
  );
}
