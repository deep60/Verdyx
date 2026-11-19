import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { parseUnits } from "viem";
import { FaucetButton } from "@/components/faucet";
import type { WalletState } from "@/hooks/use-wallet";
import { faucetState, testEthFaucetUrl, type ChainInfo } from "@/lib/chain";

const T = (n: number) => parseUnits(String(n), 18);

describe("test THREAT faucet", () => {
  it("is ready, waiting out the cooldown, or empty", () => {
    expect(faucetState(T(100), BigInt(0), T(1_000))).toEqual({ kind: "ready", drip: T(100) });
    expect(faucetState(T(100), BigInt(1_800_000_000), T(1_000))).toEqual({ kind: "wait", drip: T(100), until: 1_800_000_000 });
    expect(faucetState(T(100), BigInt(0), T(99))).toEqual({ kind: "empty", drip: T(100) });
  });

  it("points to a test ETH faucet only for networks that have one", () => {
    expect(testEthFaucetUrl(84532)).toContain("base.org");
    expect(testEthFaucetUrl(31337)).toBeNull();
    expect(testEthFaucetUrl(8453)).toBeNull();
  });

  it("shows nothing when the network has no faucet", () => {
    const info: ChainInfo = {
      enabled: true,
      chainId: 8453,
      chainName: "Base",
      nativeCurrency: "ETH",
      rpcUrl: "https://mainnet.base.org",
      contracts: {
        threatToken: "0x5FbDB2315678afecb367f032d93F642f64180aa3",
        bountyManager: "0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0",
        threatFaucet: null,
      },
    };
    const wallet: WalletState = {
      available: true,
      account: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
      chainId: 8453,
      connecting: false,
      connect: async () => {},
      switchTo: async () => {},
      client: () => null,
    };
    const html = renderToStaticMarkup(
      <QueryClientProvider client={new QueryClient()}>
        <FaucetButton info={info} wallet={wallet} />
      </QueryClientProvider>,
    );
    expect(html).toBe("");
  });
});
