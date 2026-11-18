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
  "event BountyCreated(uint256 indexed bountyId, address indexed creator, string artifactHash, uint256 reward, uint256 deadline)",
]);

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
