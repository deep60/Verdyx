import { useCallback, useEffect, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { createWalletClient, custom, getAddress, type Address, type EIP1193Provider } from "viem";
import { addChainParams, toHexChainId, viemChain, type ChainInfo } from "@/lib/chain";

type Provider = EIP1193Provider & {
  on?: (event: string, handler: (...args: unknown[]) => void) => void;
  removeListener?: (event: string, handler: (...args: unknown[]) => void) => void;
};

/** The injected wallet (MetaMask, Coinbase Wallet, Rabby…), if there is one. */
export function injectedProvider(): Provider | null {
  if (typeof window === "undefined") return null;
  return ((window as unknown as { ethereum?: Provider }).ethereum ?? null) as Provider | null;
}

/** Which network and contracts the marketplace uses. */
export function useChainInfo() {
  return useQuery<ChainInfo>({
    queryKey: ["/api/v1/chain"],
    queryFn: async () => {
      const res = await fetch("/api/v1/chain");
      if (!res.ok) throw new Error(`Chain info: HTTP ${res.status}`);
      return res.json();
    },
    staleTime: 5 * 60 * 1000,
  });
}

export interface WalletState {
  available: boolean;
  account: Address | null;
  chainId: number | null;
  connecting: boolean;
  connect: () => Promise<void>;
  switchTo: (info: ChainInfo) => Promise<void>;
  /** A viem wallet client for the connected account on `info`'s network. */
  client: (info: ChainInfo) => ReturnType<typeof walletClientFor> | null;
}

function walletClientFor(provider: Provider, account: Address, info: ChainInfo) {
  return createWalletClient({ account, chain: viemChain(info), transport: custom(provider) });
}

/** The person's own wallet. Nothing here signs or sends without them approving it in the wallet. */
export function useWallet(): WalletState {
  const provider = injectedProvider();
  const [account, setAccount] = useState<Address | null>(null);
  const [chainId, setChainId] = useState<number | null>(null);
  const [connecting, setConnecting] = useState(false);

  useEffect(() => {
    if (!provider) return;
    const onAccounts = (...args: unknown[]) => {
      const list = (args[0] as string[] | undefined) ?? [];
      setAccount(list[0] ? getAddress(list[0]) : null);
    };
    const onChain = (...args: unknown[]) => setChainId(Number.parseInt(String(args[0]), 16));
    // Already-authorised accounts only; this never opens a wallet prompt.
    provider
      .request({ method: "eth_accounts" })
      .then((a) => onAccounts(a))
      .catch(() => {});
    provider
      .request({ method: "eth_chainId" })
      .then((c) => onChain(c))
      .catch(() => {});
    provider.on?.("accountsChanged", onAccounts);
    provider.on?.("chainChanged", onChain);
    return () => {
      provider.removeListener?.("accountsChanged", onAccounts);
      provider.removeListener?.("chainChanged", onChain);
    };
  }, [provider]);

  const connect = useCallback(async () => {
    if (!provider) return;
    setConnecting(true);
    try {
      const list = (await provider.request({ method: "eth_requestAccounts" })) as string[];
      setAccount(list[0] ? getAddress(list[0]) : null);
      setChainId(Number.parseInt(String(await provider.request({ method: "eth_chainId" })), 16));
    } finally {
      setConnecting(false);
    }
  }, [provider]);

  const switchTo = useCallback(
    async (info: ChainInfo) => {
      if (!provider) return;
      try {
        await provider.request({ method: "wallet_switchEthereumChain", params: [{ chainId: toHexChainId(info.chainId) }] });
      } catch (err) {
        // 4902: the wallet doesn't know this network yet, so offer to add it.
        const code = (err as { code?: number; data?: { originalError?: { code?: number } } })?.code;
        const nested = (err as { data?: { originalError?: { code?: number } } })?.data?.originalError?.code;
        if (code !== 4902 && nested !== 4902) throw err;
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        await provider.request({ method: "wallet_addEthereumChain", params: [addChainParams(info) as any] });
      }
      setChainId(info.chainId);
    },
    [provider],
  );

  const client = useCallback(
    (info: ChainInfo) => (provider && account ? walletClientFor(provider, account, info) : null),
    [provider, account],
  );

  return { available: !!provider, account, chainId, connecting, connect, switchTo, client };
}
