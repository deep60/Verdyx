import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { parseUnits } from "viem";
import { BountyActions } from "@/components/bounty-actions";
import {
  acceptsAnalyses,
  bountyStatusLabel,
  canResolve,
  evidenceLink,
  outcomeText,
  parseStake,
  previewOutcome,
  type ChainInfo,
  type OnChainAnalysis,
  type OnChainBounty,
} from "@/lib/chain";

const T = (n: number) => parseUnits(String(n), 18);
const vote = (verdict: number, stake: number, confidence = 100) => ({
  verdict,
  stakeAmount: T(stake),
  confidence: BigInt(confidence),
});
const MALICIOUS = 2;
const BENIGN = 1;
const SUSPICIOUS = 3;

const bounty = (over: Partial<OnChainBounty> = {}): OnChainBounty => ({
  id: BigInt(7),
  creator: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
  artifactHash: "ab12",
  artifactType: "file",
  rewardAmount: T(100),
  deadline: BigInt(2_000),
  description: "Is it malicious?",
  status: 0,
  consensusVerdict: 0,
  totalStaked: BigInt(0),
  analysisCount: BigInt(0),
  createdAt: BigInt(1_000),
  ...over,
});

describe("what resolving a bounty would do", () => {
  it("refunds the poster when nobody analyzed it", () => {
    expect(previewOutcome([])).toEqual({ kind: "refund", agreementPercent: 0, winners: 0 });
  });

  it("weighs stake × confidence like the contract and needs 66%", () => {
    // 20×100 + 10×100 malicious vs 10×100 benign: 75%.
    const o = previewOutcome([vote(MALICIOUS, 20), vote(MALICIOUS, 10), vote(BENIGN, 10)]);
    expect(o).toEqual({ kind: "consensus", verdict: "Malicious", agreementPercent: 75, winners: 2 });
    // Equal weight both ways: nobody wins.
    expect(previewOutcome([vote(MALICIOUS, 10), vote(BENIGN, 10)])).toMatchObject({ kind: "no-consensus", agreementPercent: 50 });
    // Low confidence counts for less: 10×30 vs 10×100 → benign 76%.
    expect(previewOutcome([vote(MALICIOUS, 10, 30), vote(BENIGN, 10)])).toMatchObject({ kind: "consensus", verdict: "Benign", agreementPercent: 76 });
  });

  it("counts Suspicious toward the total but never lets it win", () => {
    expect(previewOutcome([vote(SUSPICIOUS, 50), vote(MALICIOUS, 10)])).toMatchObject({ kind: "no-consensus" });
    expect(previewOutcome([vote(SUSPICIOUS, 10), vote(MALICIOUS, 30)])).toMatchObject({ kind: "consensus", verdict: "Malicious", winners: 1 });
  });

  it("explains each outcome in a sentence", () => {
    expect(outcomeText(previewOutcome([]), "100")).toContain("returns all 100 THREAT to the poster");
    expect(outcomeText(previewOutcome([vote(MALICIOUS, 10)]), "100")).toContain("The analyst who said so gets the reward");
    expect(outcomeText(previewOutcome([vote(BENIGN, 10), vote(BENIGN, 10)]), "100")).toContain("The 2 analysts who said so share");
    expect(outcomeText(previewOutcome([vote(MALICIOUS, 10), vote(BENIGN, 10)]), "100")).toContain("returns every stake");
  });
});

describe("bounty timing", () => {
  it("accepts analyses up to and including the deadline", () => {
    expect(acceptsAnalyses(bounty(), 2_000)).toBe(true);
    expect(acceptsAnalyses(bounty(), 2_001)).toBe(false);
    expect(acceptsAnalyses(bounty({ status: 2 }), 1_500)).toBe(false);
  });

  it("can be resolved after the deadline or once 5 analyses are in", () => {
    expect(canResolve(bounty(), 2_000)).toBe(false);
    expect(canResolve(bounty(), 2_001)).toBe(true);
    expect(canResolve(bounty({ analysisCount: BigInt(5) }), 1_500)).toBe(true);
    expect(canResolve(bounty({ status: 3 }), 9_999)).toBe(false);
  });

  it("labels an expired open bounty and the outcome of a settled one", () => {
    expect(bountyStatusLabel(bounty(), 1_500)).toBe("Open");
    expect(bountyStatusLabel(bounty(), 2_001)).toBe("Awaiting resolution");
    expect(bountyStatusLabel(bounty({ status: 2, consensusVerdict: 2 }), 0)).toBe("Completed: Malicious");
    expect(bountyStatusLabel(bounty({ status: 2, consensusVerdict: 0 }), 0)).toBe("Completed: no consensus");
    expect(bountyStatusLabel(bounty({ status: 3 }), 0)).toBe("Cancelled");
  });
});

describe("analyst inputs", () => {
  it("requires at least the contract's 10 THREAT stake", () => {
    expect(parseStake("10")).toEqual({ ok: true, value: "10" });
    expect(parseStake("9.99")).toMatchObject({ ok: false, error: "The stake must be at least 10 THREAT" });
    expect(parseStake("abc")).toMatchObject({ ok: false });
  });

  it("only links evidence that is a plain http(s) URL", () => {
    expect(evidenceLink(" https://example.org/report ")).toBe("https://example.org/report");
    expect(evidenceLink("javascript:alert(1)")).toBeNull();
    expect(evidenceLink("see https://example.org and more")).toBeNull();
  });
});

describe("the bounty page's actions", () => {
  const info: ChainInfo = {
    enabled: true,
    chainId: 84532,
    chainName: "Base Sepolia",
    nativeCurrency: "ETH",
    rpcUrl: "https://sepolia.base.org",
    explorerUrl: "https://sepolia.basescan.org",
    contracts: {
      threatToken: "0x5FbDB2315678afecb367f032d93F642f64180aa3",
      bountyManager: "0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0",
    },
  };
  const render = (b: OnChainBounty, analyses: OnChainAnalysis[], now: number) =>
    renderToStaticMarkup(
      <QueryClientProvider client={new QueryClient()}>
        <BountyActions info={info} bounty={b} analyses={analyses} now={now} />
      </QueryClientProvider>,
    );

  it("offers the analysis form while open, behind the wallet", () => {
    const html = render(bounty(), [], 1_500);
    expect(html).toContain("Submit your analysis");
    expect(html).toContain("Install a browser wallet");
    expect(html).not.toContain("Ready to resolve");
  });

  it("offers resolving once the deadline has passed, with what would happen", () => {
    const html = render(bounty(), [], 2_001);
    expect(html).toContain("Ready to resolve");
    expect(html).toContain("returns all 100 THREAT to the poster");
    expect(html).not.toContain("Submit your analysis");
  });

  it("explains a settled bounty instead of offering actions", () => {
    const html = render(bounty({ status: 2, consensusVerdict: 2 }), [], 9_999);
    expect(html).toContain("agreed it&#x27;s Malicious");
    expect(html).not.toContain("Resolve bounty");
  });
});
