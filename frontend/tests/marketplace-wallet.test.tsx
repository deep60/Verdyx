import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReactNode } from "react";
import { PostBountyPanel } from "@/components/post-bounty-panel";
import { OnChainBounties } from "@/components/onchain-bounties";
import { WalletGate } from "@/components/wallet-gate";
import type { WalletState } from "@/hooks/use-wallet";
import type { ChainInfo } from "@/lib/chain";

const deployed: ChainInfo = {
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

function withChain(info: ChainInfo, node: ReactNode) {
  const qc = new QueryClient();
  qc.setQueryData(["/api/v1/chain"], info);
  return renderToStaticMarkup(<QueryClientProvider client={qc}>{node}</QueryClientProvider>);
}

const scan = { id: "s1", targetType: "file", sha256: "ab12", verdictLabel: "Malicious" };

const wallet = (over: Partial<WalletState>): WalletState => ({
  available: true,
  account: null,
  chainId: null,
  connecting: false,
  connect: async () => {},
  switchTo: async () => {},
  client: () => null,
  ...over,
});

describe("marketplace in the website", () => {
  it("says so while the contracts aren't deployed", () => {
    const off: ChainInfo = { enabled: false, chainId: 11155111, chainName: "Sepolia", nativeCurrency: "ETH" };
    expect(withChain(off, <PostBountyPanel scan={scan} />)).toContain("deployed yet");
    expect(withChain(off, <OnChainBounties />)).toContain("deployed yet");
  });

  it("asks for a wallet before posting", () => {
    // No injected wallet in the test environment.
    expect(withChain(deployed, <PostBountyPanel scan={scan} />)).toContain("Install a browser wallet");
  });

  it("walks through connect, then the right network, then the content", () => {
    const content = <span>the form</span>;
    expect(renderToStaticMarkup(<WalletGate info={deployed} wallet={wallet({ available: false })}>{content}</WalletGate>)).toContain(
      "Verdyx never holds your tokens",
    );
    expect(renderToStaticMarkup(<WalletGate info={deployed} wallet={wallet({})}>{content}</WalletGate>)).toContain("Connect wallet");
    const wrong = renderToStaticMarkup(
      <WalletGate info={deployed} wallet={wallet({ account: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8", chainId: 1 })}>
        {content}
      </WalletGate>,
    );
    expect(wrong).toContain("Switch to Base Sepolia");
    expect(wrong).not.toContain("the form");
    const ready = renderToStaticMarkup(
      <WalletGate info={deployed} wallet={wallet({ account: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8", chainId: 84532 })}>
        {content}
      </WalletGate>,
    );
    expect(ready).toContain("the form");
  });
});
