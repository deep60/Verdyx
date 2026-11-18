import type { ReactNode } from "react";
import { Button } from "@/components/ui/button";
import { Wallet } from "lucide-react";
import type { ChainInfo } from "@/lib/chain";
import type { WalletState } from "@/hooks/use-wallet";
import { shortAddress, walletErrorMessage } from "@/lib/chain";
import { useToast } from "@/hooks/use-toast";

/**
 * Shows its children only when a wallet is connected on the marketplace's
 * network; otherwise the one step that's missing.
 */
export function WalletGate({ info, wallet, children }: { info: ChainInfo; wallet: WalletState; children: ReactNode }) {
  const { toast } = useToast();
  const fail = (title: string) => (err: unknown) =>
    toast({ title, description: walletErrorMessage(err), variant: "destructive" });

  if (!wallet.available) {
    return (
      <p className="text-sm text-muted-foreground" data-testid="wallet-missing">
        Install a browser wallet such as MetaMask, then reload this page. Every transaction is signed in your wallet;
        Verdyx never holds your tokens.
      </p>
    );
  }
  if (!wallet.account) {
    return (
      <Button
        onClick={() => wallet.connect().catch(fail("Couldn't connect your wallet"))}
        disabled={wallet.connecting}
        data-testid="button-connect-wallet"
      >
        <Wallet className="mr-2 h-4 w-4" />
        {wallet.connecting ? "Waiting for your wallet…" : "Connect wallet"}
      </Button>
    );
  }
  if (wallet.chainId !== info.chainId) {
    return (
      <div className="space-y-2">
        <p className="text-sm text-muted-foreground">
          Your wallet ({shortAddress(wallet.account)}) is on another network. The marketplace runs on {info.chainName}.
        </p>
        <Button
          variant="outline"
          onClick={() => wallet.switchTo(info).catch(fail("Couldn't switch network"))}
          data-testid="button-switch-chain"
        >
          Switch to {info.chainName}
        </Button>
      </div>
    );
  }
  return <>{children}</>;
}
