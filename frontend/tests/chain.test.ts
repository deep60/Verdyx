import { describe, expect, it } from "vitest";
import { encodeAbiParameters, encodeEventTopics, parseUnits } from "viem";
import {
  addChainParams,
  bountyArtifact,
  bountyManagerAbi,
  createdBountyId,
  explorerTx,
  formatThreat,
  parseReward,
  toHexChainId,
  walletErrorMessage,
  type ChainInfo,
} from "@/lib/chain";

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

describe("marketplace chain helpers", () => {
  it("asks the wallet to add the network with its public RPC and explorer", () => {
    expect(toHexChainId(84532)).toBe("0x14a34");
    expect(addChainParams(info)).toEqual({
      chainId: "0x14a34",
      chainName: "Base Sepolia",
      nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
      rpcUrls: ["https://sepolia.base.org"],
      blockExplorerUrls: ["https://sepolia.basescan.org"],
    });
    expect(explorerTx(info, "0xabc")).toBe("https://sepolia.basescan.org/tx/0xabc");
    expect(explorerTx({ ...info, explorerUrl: null }, "0xabc")).toBeNull();
  });

  it("reads rewards the way people type them", () => {
    expect(parseReward("50")).toEqual({ ok: true, value: "50" });
    expect(parseReward(" 12.5 ")).toEqual({ ok: true, value: "12.5" });
    expect(parseReward("0").ok).toBe(false);
    expect(parseReward("-3").ok).toBe(false);
    expect(parseReward("1e18").ok).toBe(false);
    expect(parseReward("abc").ok).toBe(false);
  });

  it("formats THREAT amounts", () => {
    expect(formatThreat(parseUnits("100000", 18))).toBe("100,000");
    expect(formatThreat(parseUnits("12.5", 18))).toBe("12.5");
    expect(formatThreat(parseUnits("0.123456", 18))).toBe("0.1234");
  });

  it("points a bounty at the file's SHA-256 or the URL", () => {
    expect(bountyArtifact({ targetType: "file", sha256: "ab12" })).toEqual({ artifactHash: "ab12", artifactType: "file" });
    expect(bountyArtifact({ targetType: "email", sha256: "cd34" })).toEqual({ artifactHash: "cd34", artifactType: "email" });
    expect(bountyArtifact({ targetType: "url", url: "https://phish.example/x" })).toEqual({
      artifactHash: "https://phish.example/x",
      artifactType: "url",
    });
  });

  it("finds the new bounty's id in the createBounty receipt", () => {
    const topics = encodeEventTopics({
      abi: bountyManagerAbi,
      eventName: "BountyCreated",
      args: { bountyId: BigInt(7), creator: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266" },
    });
    const data = encodeAbiParameters(
      [{ type: "string" }, { type: "uint256" }, { type: "uint256" }],
      ["ab12", parseUnits("50", 18), BigInt(1_800_000_000)],
    );
    const log = {
      address: info.contracts!.bountyManager,
      topics,
      data,
      blockHash: null,
      blockNumber: null,
      logIndex: null,
      transactionHash: null,
      transactionIndex: null,
      removed: false,
    };
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    expect(createdBountyId({ logs: [log as any] })).toBe(BigInt(7));
    expect(createdBountyId({ logs: [] })).toBeNull();
  });

  it("explains wallet errors in one line", () => {
    expect(walletErrorMessage({ code: 4001, message: "User rejected the request." })).toBe(
      "You rejected the request in your wallet.",
    );
    // How viem reports it from writeContract: the rejection three levels down.
    expect(
      walletErrorMessage({
        shortMessage: "User rejected the request.",
        cause: { name: "TransactionExecutionError", cause: { name: "UserRejectedRequestError", code: 4001 } },
      }),
    ).toBe("You rejected the request in your wallet.");
    expect(
      walletErrorMessage({
        shortMessage: 'The contract function "createBounty" reverted with the following reason:\nDeadline too soon',
      }),
    ).toBe("Deadline too soon");
  });
});
