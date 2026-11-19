import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import type { Address } from "viem";
import { Button } from "@/components/ui/button";
import type { WalletState } from "@/hooks/use-wallet";
import { useToast } from "@/hooks/use-toast";
import {
  explorerTx,
  faucetAbi,
  faucetState,
  formatThreat,
  publicClientFor,
  testEthFaucetUrl,
  tokenAbi,
  walletErrorMessage,
  type ChainInfo,
} from "@/lib/chain";

/**
 * Test THREAT from the faucet contract, claimed from the person's own wallet.
 * Renders nothing when the network has no faucet (always the case on a mainnet).
 */
export function FaucetButton({ info, wallet }: { info: ChainInfo; wallet: WalletState }) {
  const faucet = info.contracts?.threatFaucet;
  const account = wallet.account;
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [claiming, setClaiming] = useState(false);

  const state = useQuery({
    queryKey: ["faucet", info.chainId, faucet, account],
    enabled: !!faucet && !!account,
    staleTime: 10_000,
    refetchInterval: 60_000,
    // People leave to get test ETH from another site; re-read when they return.
    refetchOnWindowFocus: true,
    queryFn: async () => {
      const reader = publicClientFor(info);
      const [drip, next, faucetBalance, eth] = await Promise.all([
        reader.readContract({ address: faucet as Address, abi: faucetAbi, functionName: "dripAmount" }),
        reader.readContract({ address: faucet as Address, abi: faucetAbi, functionName: "nextClaimAt", args: [account!] }),
        reader.readContract({ address: info.contracts!.threatToken, abi: tokenAbi, functionName: "balanceOf", args: [faucet as Address] }),
        reader.getBalance({ address: account! }),
      ]);
      return { faucet: faucetState(drip, next, faucetBalance), eth };
    },
  });

  if (!faucet || !account || !state.data) return null;

  async function claim() {
    const client = wallet.client(info);
    if (!client) return;
    setClaiming(true);
    try {
      const hash = await client.writeContract({ address: faucet as Address, abi: faucetAbi, functionName: "claim" });
      const receipt = await publicClientFor(info).waitForTransactionReceipt({ hash });
      if (receipt.status !== "success") throw new Error("The transaction was reverted.");
      toast({ title: "Test THREAT sent to your wallet", description: explorerTx(info, hash) ?? hash });
      queryClient.invalidateQueries({ queryKey: ["faucet"] });
      queryClient.invalidateQueries({ queryKey: ["threat-balance"] });
      queryClient.invalidateQueries({ queryKey: ["is-analyst"] });
    } catch (err) {
      toast({ title: "The faucet didn't send anything", description: walletErrorMessage(err), variant: "destructive" });
    } finally {
      setClaiming(false);
    }
  }

  const { faucet: f, eth } = state.data;
  const ethUrl = testEthFaucetUrl(info.chainId);
  return (
    <div className="space-y-2 text-sm" data-testid="faucet">
      {f.kind === "ready" && (
        <Button size="sm" variant="outline" onClick={claim} disabled={claiming || eth === BigInt(0)} data-testid="button-faucet">
          {claiming ? "Confirm in your wallet…" : `Get ${formatThreat(f.drip)} test THREAT`}
        </Button>
      )}
      {f.kind === "wait" && (
        <p className="text-muted-foreground" data-testid="faucet-wait">
          You've had your test THREAT. You can claim {formatThreat(f.drip)} more after{" "}
          {new Date(f.until * 1000).toLocaleString()}.
        </p>
      )}
      {f.kind === "empty" && (
        <p className="text-muted-foreground" data-testid="faucet-empty">
          The test THREAT faucet is empty for now.
        </p>
      )}
      {eth === BigInt(0) && (
        <p className="text-muted-foreground" data-testid="faucet-needs-eth">
          Every transaction needs a little test ETH for network fees, and this wallet has none.{" "}
          {ethUrl ? (
            <a className="underline" href={ethUrl} target="_blank" rel="noreferrer">
              Get test ETH
            </a>
          ) : (
            "Get some from a faucet for this network"
          )}
          , then come back.
        </p>
      )}
    </div>
  );
}
