import { useState } from "react";
import { Link } from "wouter";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { parseUnits, type Hex } from "viem";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { ScanBounties } from "@/components/scan-bounties";
import { WalletGate } from "@/components/wallet-gate";
import { useChainInfo, useWallet } from "@/hooks/use-wallet";
import { useToast } from "@/hooks/use-toast";
import {
  DEADLINE_CHOICES,
  bountyArtifact,
  bountyManagerAbi,
  createdBountyId,
  ensureAllowance,
  explorerTx,
  formatThreat,
  parseReward,
  publicClientFor,
  tokenAbi,
  walletErrorMessage,
  type ChainInfo,
} from "@/lib/chain";

interface Scan {
  id: string;
  targetType: string;
  sha256?: string | null;
  url?: string | null;
  verdictLabel: string;
}

type Step = "idle" | "approving" | "creating" | "done";

/** Post a THREAT bounty on this scan, signed in the person's own wallet. */
export function PostBountyPanel({ scan }: { scan: Scan }) {
  const { data: info, isLoading } = useChainInfo();
  if (isLoading) return null;
  if (!info?.enabled || !info.contracts) {
    return (
      <p className="text-sm text-muted-foreground" data-testid="marketplace-not-deployed">
        The bounty marketplace isn't deployed yet. Once its contracts are live on a test network, you can post a bounty
        here and analysts can stake on a verdict.
      </p>
    );
  }
  return (
    <>
      <ScanBounties artifact={bountyArtifact(scan).artifactHash} />
      <PostBountyForm info={info} scan={scan} />
    </>
  );
}

function PostBountyForm({ info, scan }: { info: ChainInfo; scan: Scan }) {
  const wallet = useWallet();
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const contracts = info.contracts!;
  const artifact = bountyArtifact(scan);
  const [reward, setReward] = useState("50");
  const [hours, setHours] = useState<number>(DEADLINE_CHOICES[1].hours);
  const [description, setDescription] = useState(
    `Verdyx scan ${scan.id} (${scan.verdictLabel}). Is it malicious? Stake on your verdict.`,
  );
  const [step, setStep] = useState<Step>("idle");
  const [result, setResult] = useState<{ id: bigint | null; hash: Hex } | null>(null);

  const ready = wallet.account && wallet.chainId === info.chainId;
  const balance = useQuery({
    queryKey: ["threat-balance", info.chainId, wallet.account],
    enabled: !!ready,
    staleTime: 10_000,
    queryFn: () =>
      publicClientFor(info).readContract({
        address: contracts.threatToken,
        abi: tokenAbi,
        functionName: "balanceOf",
        args: [wallet.account!],
      }),
  });

  const parsed = parseReward(reward);
  const amount = parsed.ok ? parseUnits(parsed.value, 18) : BigInt(0);
  const tooMuch = balance.data !== undefined && amount > balance.data;
  const busy = step === "approving" || step === "creating";

  async function post() {
    const client = wallet.client(info);
    if (!client || !wallet.account || !parsed.ok || !artifact.artifactHash) return;
    const reader = publicClientFor(info);
    try {
      setStep("approving");
      // Approve exactly this bounty's reward, never an unlimited amount.
      await ensureAllowance(info, wallet.account, amount, (spender, value) =>
        client.writeContract({ address: contracts.threatToken, abi: tokenAbi, functionName: "approve", args: [spender, value] }),
      );
      setStep("creating");
      const deadline = BigInt(Math.floor(Date.now() / 1000) + hours * 3600);
      const hash = await client.writeContract({
        address: contracts.bountyManager,
        abi: bountyManagerAbi,
        functionName: "createBounty",
        args: [artifact.artifactHash, artifact.artifactType, amount, deadline, description.trim()],
      });
      const receipt = await reader.waitForTransactionReceipt({ hash });
      if (receipt.status !== "success") throw new Error("The transaction was reverted.");
      setResult({ id: createdBountyId(receipt), hash });
      setStep("done");
      queryClient.invalidateQueries({ queryKey: ["threat-balance"] });
      queryClient.invalidateQueries({ queryKey: ["onchain-bounties"] });
      queryClient.invalidateQueries({ queryKey: ["scan-bounties"] });
    } catch (err) {
      setStep("idle");
      toast({ title: "The bounty wasn't posted", description: walletErrorMessage(err), variant: "destructive" });
    }
  }

  if (step === "done" && result) {
    const link = explorerTx(info, result.hash);
    return (
      <div className="space-y-1 text-sm" data-testid="bounty-posted">
        <p className="font-medium text-foreground">
          Bounty {result.id !== null ? `#${result.id}` : ""} posted: {reward} THREAT on {info.chainName}.
        </p>
        {result.id !== null && (
          <Link href={`/marketplace/bounties/${result.id}`} className="mr-4 text-primary underline">
            Open the bounty
          </Link>
        )}
        {link ? (
          <a className="text-primary underline" href={link} target="_blank" rel="noreferrer">
            View the transaction
          </a>
        ) : (
          <p className="font-mono text-xs text-muted-foreground break-all">{result.hash}</p>
        )}
      </div>
    );
  }

  return (
    <WalletGate info={info} wallet={wallet}>
      <form
        className="grid gap-4 sm:grid-cols-2"
        onSubmit={(e) => {
          e.preventDefault();
          post();
        }}
      >
        <div className="space-y-1.5">
          <Label htmlFor="bounty-reward">Reward (THREAT)</Label>
          <Input
            id="bounty-reward"
            inputMode="decimal"
            value={reward}
            onChange={(e) => setReward(e.target.value)}
            disabled={busy}
            data-testid="input-bounty-reward"
          />
          <p className="text-xs text-muted-foreground">
            {balance.data !== undefined ? `You have ${formatThreat(balance.data)} THREAT.` : "Checking your balance…"}
            {!parsed.ok && reward ? ` ${parsed.error}.` : ""}
            {tooMuch ? " That's more than you have." : ""}
          </p>
        </div>
        <div className="space-y-1.5">
          <Label>Analysts have</Label>
          <div className="flex gap-2">
            {DEADLINE_CHOICES.map((c) => (
              <Button
                key={c.hours}
                type="button"
                size="sm"
                variant={hours === c.hours ? "default" : "outline"}
                onClick={() => setHours(c.hours)}
                disabled={busy}
              >
                {c.label}
              </Button>
            ))}
          </div>
        </div>
        <div className="space-y-1.5 sm:col-span-2">
          <Label htmlFor="bounty-description">Description</Label>
          <Textarea
            id="bounty-description"
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            maxLength={500}
            disabled={busy}
          />
          <p className="text-xs text-muted-foreground break-all">
            Points at {artifact.artifactType === "url" ? "the URL" : "SHA-256"} {artifact.artifactHash}. The reward is held
            by the BountyManager contract until the bounty resolves; Verdyx never holds it.
          </p>
        </div>
        <div className="sm:col-span-2">
          <Button
            type="submit"
            disabled={busy || !parsed.ok || tooMuch || !description.trim() || !artifact.artifactHash}
            data-testid="button-post-onchain-bounty"
          >
            {step === "approving"
              ? "Approve the reward in your wallet…"
              : step === "creating"
                ? "Confirm the bounty in your wallet…"
                : "Post bounty"}
          </Button>
          <p className="mt-2 text-xs text-muted-foreground">
            Your wallet asks twice: once to let the contract take this reward (exactly this amount), then to create the
            bounty.
          </p>
        </div>
      </form>
    </WalletGate>
  );
}
