/**
 * The marketplace contracts, read and written straight from the browser.
 *
 * The marketplace is non-custodial: every transaction is signed in the
 * person's own wallet (MetaMask, Coinbase Wallet, Rabby…), and the Verdyx
 * server never holds their tokens. The server only publishes which network
 * and contracts to use (GET /api/v1/chain).
 */
import {
  createPublicClient,
  formatUnits,
  http,
  parseAbi,
  parseEventLogs,
  type Address,
  type Chain,
  type Hex,
  type TransactionReceipt,
} from "viem";

export interface ChainInfo {
  enabled: boolean;
  chainId: number;
  chainName: string;
  nativeCurrency: string;
  rpcUrl?: string | null;
  explorerUrl?: string | null;
  contracts?: {
    threatToken: Address;
    bountyManager: Address;
    reputationSystem?: Address | null;
  } | null;
}

/** The parts of the contracts the website uses. */
export const tokenAbi = parseAbi([
  "function balanceOf(address) view returns (uint256)",
  "function allowance(address owner, address spender) view returns (uint256)",
  "function approve(address spender, uint256 amount) returns (bool)",
  "function decimals() view returns (uint8)",
  "function symbol() view returns (string)",
]);

export const bountyManagerAbi = parseAbi([
  "struct Bounty { uint256 id; address creator; string artifactHash; string artifactType; uint256 rewardAmount; uint256 deadline; string description; uint8 status; uint8 consensusVerdict; uint256 totalStaked; uint256 analysisCount; uint256 createdAt; }",
  "function createBounty(string artifactHash, string artifactType, uint256 rewardAmount, uint256 deadline, string description) returns (uint256)",
  "function getBounty(uint256 bountyId) view returns (Bounty)",
  "function getTotalBounties() view returns (uint256)",
  "function pendingWithdrawals(address) view returns (uint256)",
  "function withdraw()",
  "function paused() view returns (bool)",
  "struct Analysis { uint256 bountyId; address analyst; uint8 verdict; uint256 confidence; uint256 stakeAmount; string analysisHash; uint256 submittedAt; bool rewarded; }",
  "function getAnalysis(uint256 bountyId, address analyst) view returns (Analysis)",
  "function getBountyAnalysts(uint256 bountyId) view returns (address[])",
  "function isAnalyst(address account) view returns (bool)",
  "function registerAnalyst()",
  "function submitAnalysis(uint256 bountyId, uint8 verdict, uint256 confidence, uint256 stakeAmount, string analysisHash)",
  "function resolveBounty(uint256 bountyId)",
  "event BountyCreated(uint256 indexed bountyId, address indexed creator, string artifactHash, uint256 reward, uint256 deadline)",
]);

/** Fixed in the BountyManager contract. */
export const MIN_STAKE_THREAT = 10;
export const MIN_ANALYSES_TO_RESOLVE = 5;
export const CONSENSUS_THRESHOLD_PERCENT = 66;
export const PLATFORM_FEE_PERCENT = 5;

/** The verdicts an analyst can stake on, as the contract numbers them. */
export const ANALYST_VERDICTS = [
  { value: 2, label: "Malicious" },
  { value: 1, label: "Benign" },
  { value: 3, label: "Suspicious" },
] as const;

export const BOUNTY_STATUS = ["Open", "In review", "Completed", "Cancelled", "Disputed"] as const;
export const BOUNTY_VERDICT = ["Pending", "Benign", "Malicious", "Suspicious"] as const;

/** The contract requires a deadline more than an hour away. */
export const DEADLINE_CHOICES = [
  { label: "1 day", hours: 24 },
  { label: "3 days", hours: 72 },
  { label: "7 days", hours: 168 },
] as const;

export interface OnChainBounty {
  id: bigint;
  creator: Address;
  artifactHash: string;
  artifactType: string;
  rewardAmount: bigint;
  deadline: bigint;
  description: string;
  status: number;
  consensusVerdict: number;
  totalStaked: bigint;
  analysisCount: bigint;
  createdAt: bigint;
}

export interface OnChainAnalysis {
  bountyId: bigint;
  analyst: Address;
  verdict: number;
  confidence: bigint;
  stakeAmount: bigint;
  analysisHash: string;
  submittedAt: bigint;
  rewarded: boolean;
}

/** The status to show, including an open bounty whose deadline has passed. */
export function bountyStatusLabel(b: Pick<OnChainBounty, "status" | "deadline" | "consensusVerdict">, nowSec: number): string {
  if (b.status === 0 && nowSec > Number(b.deadline)) return "Awaiting resolution";
  if (b.status === 2) {
    return b.consensusVerdict === 0 ? "Completed: no consensus" : `Completed: ${BOUNTY_VERDICT[b.consensusVerdict]}`;
  }
  return BOUNTY_STATUS[b.status] ?? "Unknown";
}

/** Whether analysts can still submit (the contract allows it up to and including the deadline). */
export function acceptsAnalyses(b: Pick<OnChainBounty, "status" | "deadline">, nowSec: number): boolean {
  return b.status === 0 && nowSec <= Number(b.deadline);
}

/** Whether anyone can resolve the bounty now, mirroring resolveBounty's checks. */
export function canResolve(b: Pick<OnChainBounty, "status" | "deadline" | "analysisCount">, nowSec: number): boolean {
  if (b.status !== 0) return false;
  return nowSec > Number(b.deadline) || b.analysisCount >= BigInt(MIN_ANALYSES_TO_RESOLVE);
}

export interface Outcome {
  /** "refund" when nobody analyzed, "no-consensus" or the winning verdict. */
  kind: "refund" | "no-consensus" | "consensus";
  verdict?: "Malicious" | "Benign";
  /** Each analysis's weight is stake × confidence; this is the winner's share, 0-100. */
  agreementPercent: number;
  winners: number;
}

/**
 * What resolving would do, computed the way the contract does: each analysis
 * weighs stake × confidence, and Malicious or Benign needs at least 66% of the
 * total weight. Suspicious counts toward the total but can never win.
 */
export function previewOutcome(analyses: Pick<OnChainAnalysis, "verdict" | "confidence" | "stakeAmount">[]): Outcome {
  if (analyses.length === 0) return { kind: "refund", agreementPercent: 0, winners: 0 };
  let total = BigInt(0);
  let malicious = BigInt(0);
  let benign = BigInt(0);
  for (const a of analyses) {
    const w = (a.stakeAmount * a.confidence) / BigInt(100);
    total += w;
    if (a.verdict === 2) malicious += w;
    else if (a.verdict === 1) benign += w;
  }
  if (total === BigInt(0)) return { kind: "no-consensus", agreementPercent: 0, winners: 0 };
  const malPct = Number((malicious * BigInt(100)) / total);
  const benPct = Number((benign * BigInt(100)) / total);
  if (malPct >= CONSENSUS_THRESHOLD_PERCENT) {
    return { kind: "consensus", verdict: "Malicious", agreementPercent: malPct, winners: analyses.filter((a) => a.verdict === 2).length };
  }
  if (benPct >= CONSENSUS_THRESHOLD_PERCENT) {
    return { kind: "consensus", verdict: "Benign", agreementPercent: benPct, winners: analyses.filter((a) => a.verdict === 1).length };
  }
  return { kind: "no-consensus", agreementPercent: Math.max(malPct, benPct), winners: 0 };
}

/** One sentence on what resolving would do. */
export function outcomeText(o: Outcome, rewardThreat: string): string {
  if (o.kind === "refund") return `Nobody analyzed it, so resolving cancels it and returns all ${rewardThreat} THREAT to the poster.`;
  if (o.kind === "no-consensus") {
    return `No verdict has the ${CONSENSUS_THRESHOLD_PERCENT}% of the weight it needs (the closest has ${o.agreementPercent}%), so resolving returns every stake and gives the poster the reward back less the ${PLATFORM_FEE_PERCENT}% fee.`;
  }
  const who = o.winners === 1 ? "The analyst who said so gets" : `The ${o.winners} analysts who said so share`;
  return `Resolving settles it as ${o.verdict} (${o.agreementPercent}% of the weight). ${who} the reward less the ${PLATFORM_FEE_PERCENT}% fee, plus the stakes of anyone who disagreed.`;
}

/** A stake the person typed, or an error to show. */
export function parseStake(input: string): { ok: true; value: string } | { ok: false; error: string } {
  const r = parseReward(input);
  if (!r.ok) return { ok: false, error: r.error.replace("reward", "stake") };
  if (Number(r.value) < MIN_STAKE_THREAT) return { ok: false, error: `The stake must be at least ${MIN_STAKE_THREAT} THREAT` };
  return r;
}

/** A link if the analyst's evidence is one, so it isn't rendered as a clickable javascript: URL. */
export function evidenceLink(text: string): string | null {
  const t = text.trim();
  return /^https?:\/\/\S+$/i.test(t) ? t : null;
}

export function viemChain(info: ChainInfo): Chain {
  const rpc = info.rpcUrl ?? "";
  return {
    id: info.chainId,
    name: info.chainName,
    nativeCurrency: { name: "Ether", symbol: info.nativeCurrency || "ETH", decimals: 18 },
    rpcUrls: { default: { http: [rpc] } },
    blockExplorers: info.explorerUrl ? { default: { name: "Explorer", url: info.explorerUrl } } : undefined,
  };
}

export function publicClientFor(info: ChainInfo) {
  return createPublicClient({ chain: viemChain(info), transport: http(info.rpcUrl ?? undefined) });
}

/** Parameters for wallet_addEthereumChain, when the wallet doesn't know the network yet. */
export function addChainParams(info: ChainInfo) {
  return {
    chainId: toHexChainId(info.chainId),
    chainName: info.chainName,
    nativeCurrency: { name: "Ether", symbol: info.nativeCurrency || "ETH", decimals: 18 },
    rpcUrls: info.rpcUrl ? [info.rpcUrl] : [],
    blockExplorerUrls: info.explorerUrl ? [info.explorerUrl] : undefined,
  };
}

export function toHexChainId(id: number): Hex {
  return `0x${id.toString(16)}`;
}

/** "12.5" from 12.5 THREAT in wei, trimmed to at most 4 decimals. */
export function formatThreat(amount: bigint, decimals = 18): string {
  const s = formatUnits(amount, decimals);
  const [whole, frac = ""] = s.split(".");
  const trimmed = frac.slice(0, 4).replace(/0+$/, "");
  return trimmed ? `${Number(whole).toLocaleString("en-US")}.${trimmed}` : Number(whole).toLocaleString("en-US");
}

/** A reward the person typed, or an error to show. */
export function parseReward(input: string): { ok: true; value: string } | { ok: false; error: string } {
  const v = input.trim();
  if (!/^\d+(\.\d{1,18})?$/.test(v)) return { ok: false, error: "Enter an amount like 50 or 12.5" };
  if (Number(v) <= 0) return { ok: false, error: "The reward must be more than 0" };
  return { ok: true, value: v };
}

/** What a bounty points at: the file's SHA-256, or the URL. */
export function bountyArtifact(scan: { targetType: string; sha256?: string | null; url?: string | null }) {
  if (scan.targetType === "url") return { artifactHash: scan.url ?? "", artifactType: "url" };
  return { artifactHash: scan.sha256 ?? "", artifactType: scan.targetType === "email" ? "email" : "file" };
}

/** The bounty id from a createBounty receipt. */
export function createdBountyId(receipt: Pick<TransactionReceipt, "logs">): bigint | null {
  const logs = parseEventLogs({ abi: bountyManagerAbi, eventName: "BountyCreated", logs: receipt.logs });
  return logs[0]?.args.bountyId ?? null;
}

export function explorerTx(info: ChainInfo, hash: string): string | null {
  return info.explorerUrl ? `${info.explorerUrl}/tx/${hash}` : null;
}

export function explorerAddress(info: ChainInfo, address: string): string | null {
  return info.explorerUrl ? `${info.explorerUrl}/address/${address}` : null;
}

export function shortAddress(a: string): string {
  return a.length > 12 ? `${a.slice(0, 6)}…${a.slice(-4)}` : a;
}

/** The newest bounties first, at most `limit`. */
export async function latestBounties(info: ChainInfo, limit = 20): Promise<OnChainBounty[]> {
  if (!info.enabled || !info.contracts) return [];
  const client = publicClientFor(info);
  const address = info.contracts.bountyManager;
  const total = await client.readContract({ address, abi: bountyManagerAbi, functionName: "getTotalBounties" });
  const ids: bigint[] = [];
  for (let id = total; id > BigInt(0) && ids.length < limit; id--) ids.push(id);
  const results = await Promise.all(
    ids.map((id) => client.readContract({ address, abi: bountyManagerAbi, functionName: "getBounty", args: [id] })),
  );
  return results as OnChainBounty[];
}

/** One bounty and every analysis submitted on it, in submission order. */
export async function bountyWithAnalyses(
  info: ChainInfo,
  id: bigint,
): Promise<{ bounty: OnChainBounty; analyses: OnChainAnalysis[] }> {
  const client = publicClientFor(info);
  const address = info.contracts!.bountyManager;
  const [bounty, analysts] = await Promise.all([
    client.readContract({ address, abi: bountyManagerAbi, functionName: "getBounty", args: [id] }),
    client.readContract({ address, abi: bountyManagerAbi, functionName: "getBountyAnalysts", args: [id] }),
  ]);
  const analyses = await Promise.all(
    analysts.map((a) => client.readContract({ address, abi: bountyManagerAbi, functionName: "getAnalysis", args: [id, a] })),
  );
  return { bounty: bounty as OnChainBounty, analyses: analyses as OnChainAnalysis[] };
}

/**
 * Make sure the BountyManager may take `amount` from `owner`. If the current
 * allowance is short, `approve` is asked for exactly that amount (never an
 * unlimited one) and the approval is awaited. Returns whether it was asked.
 */
export async function ensureAllowance(
  info: ChainInfo,
  owner: Address,
  amount: bigint,
  approve: (spender: Address, amount: bigint) => Promise<Hex>,
): Promise<boolean> {
  const reader = publicClientFor(info);
  const { threatToken, bountyManager } = info.contracts!;
  const allowance = await reader.readContract({
    address: threatToken,
    abi: tokenAbi,
    functionName: "allowance",
    args: [owner, bountyManager],
  });
  if (allowance >= amount) return false;
  const hash = await approve(bountyManager, amount);
  const receipt = await reader.waitForTransactionReceipt({ hash });
  if (receipt.status !== "success") throw new Error("The approval was reverted.");
  return true;
}

/** A short reason for a failed wallet action, without the wallet's stack of details. */
export function walletErrorMessage(err: unknown): string {
  type WalletError = { shortMessage?: string; message?: string; code?: number; name?: string; cause?: WalletError };
  const e = err as WalletError;
  // viem wraps the wallet's own error a few levels deep.
  for (let c: WalletError | undefined = e, depth = 0; c && depth < 6; c = c.cause, depth++) {
    if (c.code === 4001 || c.name === "UserRejectedRequestError") return "You rejected the request in your wallet.";
  }
  const msg = e?.shortMessage || e?.message || "The wallet reported an error.";
  const reason = msg.match(/reverted with the following reason:\s*(.+)/)?.[1];
  return (reason ?? msg).split("\n")[0];
}
