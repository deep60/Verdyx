import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "wouter";
import { parseUnits } from "viem";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { FaucetButton } from "@/components/faucet";
import { WalletGate } from "@/components/wallet-gate";
import { useWallet, type WalletState } from "@/hooks/use-wallet";
import { useToast } from "@/hooks/use-toast";
import {
  ANALYST_VERDICTS,
  BOUNTY_VERDICT,
  MIN_ANALYSES_TO_RESOLVE,
  MIN_STAKE_THREAT,
  acceptsAnalyses,
  bountyManagerAbi,
  canResolve,
  ensureAllowance,
  explorerTx,
  formatThreat,
  outcomeText,
  parseStake,
  previewOutcome,
  publicClientFor,
  tokenAbi,
  walletErrorMessage,
  type ChainInfo,
  type OnChainAnalysis,
  type OnChainBounty,
} from "@/lib/chain";

interface Props {
  info: ChainInfo;
  bounty: OnChainBounty;
  analyses: OnChainAnalysis[];
  now: number;
}

/** What someone can do on a bounty right now: analyze it, or resolve it. */
export function BountyActions({ info, bounty, analyses, now }: Props) {
  const wallet = useWallet();
  const open = acceptsAnalyses(bounty, now);
  const resolvable = canResolve(bounty, now);

  if (bounty.status !== 0) {
    return (
      <section className="border border-border bg-card/50 p-6 text-sm" data-testid="bounty-settled">
        <h2 className="mb-2 text-lg font-medium">Settled</h2>
        <p className="text-muted-foreground">
          {bounty.status === 3
            ? "Nobody analyzed it before the deadline, so the reward went back to the poster."
            : bounty.consensusVerdict === 0
              ? "The analysts didn't reach a consensus, so every stake went back and the poster got the reward back less the platform fee."
              : `The analysts agreed it's ${BOUNTY_VERDICT[bounty.consensusVerdict]}. Those who said so shared the reward and the stakes of those who didn't.`}{" "}
          Payouts wait in the contract until each person withdraws them from{" "}
          <Link href="/marketplace" className="underline">
            Your wallet
          </Link>
          .
        </p>
      </section>
    );
  }

  return (
    <div className="space-y-6">
      {resolvable && <ResolvePanel info={info} bounty={bounty} analyses={analyses} wallet={wallet} />}
      {open && (
        <section className="border border-border bg-card/50 p-6" aria-labelledby="analyze-heading">
          <h2 id="analyze-heading" className="mb-1 text-lg font-medium">
            Submit your analysis
          </h2>
          <p className="mb-4 text-sm text-muted-foreground">
            Stake THREAT on your verdict. If it matches the consensus you get your stake back plus a share of the reward
            and of the losing stakes; if it doesn't, your stake goes to those who were right. With no consensus every
            stake is returned. It can be resolved after the deadline, or as soon as {MIN_ANALYSES_TO_RESOLVE} analyses
            are in.
          </p>
          <WalletGate info={info} wallet={wallet}>
            <AnalystForm info={info} bounty={bounty} analyses={analyses} wallet={wallet} />
          </WalletGate>
        </section>
      )}
    </div>
  );
}

function ResolvePanel({ info, bounty, analyses, wallet }: Omit<Props, "now"> & { wallet: WalletState }) {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [busy, setBusy] = useState(false);
  const outcome = previewOutcome(analyses);

  async function resolve() {
    const client = wallet.client(info);
    if (!client) return;
    setBusy(true);
    try {
      const hash = await client.writeContract({
        address: info.contracts!.bountyManager,
        abi: bountyManagerAbi,
        functionName: "resolveBounty",
        args: [bounty.id],
      });
      const receipt = await publicClientFor(info).waitForTransactionReceipt({ hash });
      if (receipt.status !== "success") throw new Error("The transaction was reverted.");
      toast({ title: `Bounty #${bounty.id} resolved`, description: explorerTx(info, hash) ?? hash });
      queryClient.invalidateQueries({ queryKey: ["onchain-bounty"] });
      queryClient.invalidateQueries({ queryKey: ["onchain-bounties"] });
      queryClient.invalidateQueries({ queryKey: ["threat-balance"] });
    } catch (err) {
      toast({ title: "It wasn't resolved", description: walletErrorMessage(err), variant: "destructive" });
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="border border-primary/40 bg-card/50 p-6" data-testid="resolve-panel">
      <h2 className="mb-1 text-lg font-medium">Ready to resolve</h2>
      <p className="mb-4 text-sm text-muted-foreground" data-testid="resolve-preview">
        {outcomeText(outcome, formatThreat(bounty.rewardAmount))} Anyone can resolve it; it costs only network fees.
      </p>
      <WalletGate info={info} wallet={wallet}>
        <Button onClick={resolve} disabled={busy} data-testid="button-resolve">
          {busy ? "Confirm in your wallet…" : "Resolve bounty"}
        </Button>
      </WalletGate>
    </section>
  );
}

type Step = "idle" | "registering" | "approving" | "submitting";

function AnalystForm({ info, bounty, analyses, wallet }: Omit<Props, "now"> & { wallet: WalletState }) {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const contracts = info.contracts!;
  const account = wallet.account!;
  const [verdict, setVerdict] = useState<number>(2);
  const [confidence, setConfidence] = useState("80");
  const [stake, setStake] = useState(String(MIN_STAKE_THREAT));
  const [evidence, setEvidence] = useState("");
  const [step, setStep] = useState<Step>("idle");

  const mine = analyses.find((a) => a.analyst.toLowerCase() === account.toLowerCase());
  const isCreator = bounty.creator.toLowerCase() === account.toLowerCase();

  const status = useQuery({
    queryKey: ["is-analyst", info.chainId, account],
    staleTime: 10_000,
    queryFn: async () => {
      const reader = publicClientFor(info);
      const [isAnalyst, balance] = await Promise.all([
        reader.readContract({ address: contracts.bountyManager, abi: bountyManagerAbi, functionName: "isAnalyst", args: [account] }),
        reader.readContract({ address: contracts.threatToken, abi: tokenAbi, functionName: "balanceOf", args: [account] }),
      ]);
      return { isAnalyst, balance };
    },
  });

  if (mine) {
    return (
      <p className="text-sm" data-testid="already-submitted">
        You said <strong>{BOUNTY_VERDICT[mine.verdict]}</strong> at {mine.confidence.toString()}% confidence, staking{" "}
        {formatThreat(mine.stakeAmount)} THREAT. Each wallet can submit once.
      </p>
    );
  }
  if (status.isLoading) return <p className="text-sm text-muted-foreground">Checking your analyst status…</p>;
  if (status.isError || !status.data) return <p className="text-sm text-destructive">Couldn't read your analyst status.</p>;

  const busy = step !== "idle";

  async function register() {
    const client = wallet.client(info);
    if (!client) return;
    setStep("registering");
    try {
      const hash = await client.writeContract({ address: contracts.bountyManager, abi: bountyManagerAbi, functionName: "registerAnalyst" });
      const receipt = await publicClientFor(info).waitForTransactionReceipt({ hash });
      if (receipt.status !== "success") throw new Error("The transaction was reverted.");
      toast({ title: "You're registered as an analyst" });
      await queryClient.invalidateQueries({ queryKey: ["is-analyst"] });
    } catch (err) {
      toast({ title: "Registration failed", description: walletErrorMessage(err), variant: "destructive" });
    } finally {
      setStep("idle");
    }
  }

  if (!status.data.isAnalyst) {
    return (
      <div className="space-y-3 text-sm" data-testid="analyst-register">
        <p>
          First, register this wallet as an analyst. It's one transaction, free apart from network fees, and starts you
          at a reputation of 100 that rises and falls with how often you agree with the consensus.
        </p>
        <Button onClick={register} disabled={busy} data-testid="button-register-analyst">
          {step === "registering" ? "Confirm in your wallet…" : "Register as analyst"}
        </Button>
      </div>
    );
  }

  const parsedStake = parseStake(stake);
  const amount = parsedStake.ok ? parseUnits(parsedStake.value, 18) : BigInt(0);
  const tooMuch = amount > status.data.balance;
  const conf = Number(confidence);
  const confOk = Number.isInteger(conf) && conf >= 1 && conf <= 100;
  const evidenceOk = evidence.trim().length > 0;

  async function submit() {
    const client = wallet.client(info);
    if (!client || !parsedStake.ok || !confOk || !evidenceOk) return;
    try {
      setStep("approving");
      await ensureAllowance(info, account, amount, (spender, value) =>
        client.writeContract({ address: contracts.threatToken, abi: tokenAbi, functionName: "approve", args: [spender, value] }),
      );
      setStep("submitting");
      const hash = await client.writeContract({
        address: contracts.bountyManager,
        abi: bountyManagerAbi,
        functionName: "submitAnalysis",
        args: [bounty.id, verdict, BigInt(conf), amount, evidence.trim()],
      });
      const receipt = await publicClientFor(info).waitForTransactionReceipt({ hash });
      if (receipt.status !== "success") throw new Error("The transaction was reverted.");
      toast({ title: "Analysis submitted", description: explorerTx(info, hash) ?? hash });
      queryClient.invalidateQueries({ queryKey: ["onchain-bounty"] });
      queryClient.invalidateQueries({ queryKey: ["onchain-bounties"] });
      queryClient.invalidateQueries({ queryKey: ["threat-balance"] });
      queryClient.invalidateQueries({ queryKey: ["is-analyst"] });
    } catch (err) {
      toast({ title: "The analysis wasn't submitted", description: walletErrorMessage(err), variant: "destructive" });
    } finally {
      setStep("idle");
    }
  }

  return (
    <form
      className="grid gap-4 sm:grid-cols-2"
      data-testid="analysis-form"
      onSubmit={(e) => {
        e.preventDefault();
        submit();
      }}
    >
      {isCreator && (
        <p className="text-sm text-muted-foreground sm:col-span-2">
          You posted this bounty. You can analyze it too, but others can see that the same wallet did both.
        </p>
      )}
      <div className="space-y-1.5 sm:col-span-2">
        <Label>Verdict</Label>
        <div className="flex flex-wrap gap-2">
          {ANALYST_VERDICTS.map((v) => (
            <Button
              key={v.value}
              type="button"
              size="sm"
              variant={verdict === v.value ? "default" : "outline"}
              onClick={() => setVerdict(v.value)}
              disabled={busy}
              aria-pressed={verdict === v.value}
              data-testid={`verdict-${v.label.toLowerCase()}`}
            >
              {v.label}
            </Button>
          ))}
        </div>
        {verdict === 3 && (
          <p className="text-xs text-muted-foreground">
            Suspicious can't win a consensus: only Malicious or Benign can. If the others agree on one of those, a
            Suspicious stake is lost; with no consensus it's returned.
          </p>
        )}
      </div>
      <div className="space-y-1.5">
        <Label htmlFor="analysis-confidence">Confidence (%)</Label>
        <Input
          id="analysis-confidence"
          inputMode="numeric"
          value={confidence}
          onChange={(e) => setConfidence(e.target.value)}
          disabled={busy}
          data-testid="input-confidence"
        />
        <p className="text-xs text-muted-foreground">
          {confOk ? "Your vote weighs stake × confidence." : "Enter a whole number from 1 to 100."}
        </p>
      </div>
      <div className="space-y-1.5">
        <Label htmlFor="analysis-stake">Stake (THREAT)</Label>
        <Input
          id="analysis-stake"
          inputMode="decimal"
          value={stake}
          onChange={(e) => setStake(e.target.value)}
          disabled={busy}
          data-testid="input-stake"
        />
        <p className="text-xs text-muted-foreground">
          You have {formatThreat(status.data.balance)} THREAT.
          {!parsedStake.ok && stake ? ` ${parsedStake.error}.` : ""}
          {tooMuch ? " That's more than you have." : ""}
        </p>
        {status.data.balance < parseUnits(String(MIN_STAKE_THREAT), 18) && <FaucetButton info={info} wallet={wallet} />}
      </div>
      <div className="space-y-1.5 sm:col-span-2">
        <Label htmlFor="analysis-evidence">Evidence</Label>
        <Textarea
          id="analysis-evidence"
          value={evidence}
          onChange={(e) => setEvidence(e.target.value)}
          maxLength={500}
          placeholder="A short reason, or a link to your write-up"
          disabled={busy}
          data-testid="input-evidence"
        />
        <p className="text-xs text-muted-foreground">Stored on the chain with your verdict, so anyone can read it.</p>
      </div>
      <div className="sm:col-span-2">
        <Button
          type="submit"
          disabled={busy || !parsedStake.ok || tooMuch || !confOk || !evidenceOk}
          data-testid="button-submit-analysis"
        >
          {step === "approving"
            ? "Approve the stake in your wallet…"
            : step === "submitting"
              ? "Confirm the analysis in your wallet…"
              : "Submit analysis"}
        </Button>
        <p className="mt-2 text-xs text-muted-foreground">
          Your wallet asks twice: once to let the contract take exactly this stake, then to submit.
        </p>
      </div>
    </form>
  );
}
