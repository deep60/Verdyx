import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { apiRequest } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import { Wallet, ArrowUpRight, Coins, Lock, Award, History } from "lucide-react";

interface WalletBalanceResponse {
  address: string;
  balance: string;
  staked: string;
  available: string;
  pending_rewards: string;
  total_earned: string;
  total_spent: string;
}

interface WalletTransaction {
  id: string;
  transaction_hash?: string | null;
  transaction_type: string;
  amount: string;
  to_address?: string | null;
  status: string;
  timestamp: string;
}

interface TransactionListResponse {
  transactions: WalletTransaction[];
  total: number;
}

export function WalletLedgerPanel({ defaultAddress }: { defaultAddress?: string | null }) {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [withdrawAmount, setWithdrawAmount] = useState("");
  const [withdrawAddress, setWithdrawAddress] = useState(defaultAddress || "");

  const { data: balanceData, isLoading: balanceLoading } = useQuery<WalletBalanceResponse>({
    queryKey: ["/api/wallet/balance"],
  });

  const { data: txData, isLoading: txLoading } = useQuery<TransactionListResponse>({
    queryKey: ["/api/wallet/transactions"],
  });

  const withdrawMutation = useMutation({
    mutationFn: async () => {
      const res = await apiRequest("POST", "/api/wallet/withdraw", {
        amount: withdrawAmount.trim(),
        to_address: (withdrawAddress || balanceData?.address || "").trim(),
      });
      return res.json();
    },
    onSuccess: (data) => {
      toast({
        title: "Withdrawal queued",
        description: `Payout request for ${data.amount} ETH submitted (${data.status}).`,
      });
      setWithdrawAmount("");
      queryClient.invalidateQueries({ queryKey: ["/api/wallet/balance"] });
      queryClient.invalidateQueries({ queryKey: ["/api/wallet/transactions"] });
    },
    onError: (err) => {
      toast({
        title: "Withdrawal failed",
        description:
          err instanceof Error
            ? err.message
            : "Provide a valid positive ETH amount and 0x recipient address.",
        variant: "destructive",
      });
    },
  });

  const transactions = txData?.transactions ?? [];

  return (
    <div className="space-y-6">
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <Card className="glassmorphism border-primary/20">
          <CardContent className="p-4 space-y-1">
            <div className="text-xs text-muted-foreground flex items-center justify-between">
              <span>Available Balance</span>
              <Wallet className="h-4 w-4 text-primary" />
            </div>
            <div className="text-2xl font-bold font-display text-foreground">
              {balanceLoading ? "…" : `${balanceData?.available || "0"} ETH`}
            </div>
            <div className="font-mono text-[11px] text-muted-foreground truncate">
              {balanceData?.address || defaultAddress || "No wallet linked"}
            </div>
          </CardContent>
        </Card>

        <Card className="glassmorphism border-primary/20">
          <CardContent className="p-4 space-y-1">
            <div className="text-xs text-muted-foreground flex items-center justify-between">
              <span>Active Staked Escrow</span>
              <Lock className="h-4 w-4 text-amber-400" />
            </div>
            <div className="text-2xl font-bold font-display text-amber-400">
              {balanceLoading ? "…" : `${balanceData?.staked || "0"} ETH`}
            </div>
            <div className="text-[11px] text-muted-foreground">Locked in open verdict bounties</div>
          </CardContent>
        </Card>

        <Card className="glassmorphism border-primary/20">
          <CardContent className="p-4 space-y-1">
            <div className="text-xs text-muted-foreground flex items-center justify-between">
              <span>Pending Rewards</span>
              <Coins className="h-4 w-4 text-accent" />
            </div>
            <div className="text-2xl font-bold font-display text-accent">
              {balanceLoading ? "…" : `${balanceData?.pending_rewards || "0"} ETH`}
            </div>
            <div className="text-[11px] text-muted-foreground">Awaiting 30-day grade / payout</div>
          </CardContent>
        </Card>

        <Card className="glassmorphism border-primary/20">
          <CardContent className="p-4 space-y-1">
            <div className="text-xs text-muted-foreground flex items-center justify-between">
              <span>Total Earned</span>
              <Award className="h-4 w-4 text-emerald-400" />
            </div>
            <div className="text-2xl font-bold font-display text-emerald-400">
              {balanceLoading ? "…" : `${balanceData?.total_earned || "0"} ETH`}
            </div>
            <div className="text-[11px] text-muted-foreground">
              Spent on bounties: {balanceData?.total_spent || "0"} ETH
            </div>
          </CardContent>
        </Card>
      </div>

      <Card className="glassmorphism border-primary/20">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-lg">
            <ArrowUpRight className="h-5 w-5 text-primary" />
            Request Reward Withdrawal
          </CardTitle>
          <CardDescription>
            Queue a payout to your Ethereum address. Staked tokens unlock automatically when a bounty resolves.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form
            className="grid gap-4 sm:grid-cols-3 items-end"
            onSubmit={(e) => {
              e.preventDefault();
              if (!withdrawAmount.trim()) return;
              withdrawMutation.mutate();
            }}
          >
            <div className="space-y-1.5">
              <Label htmlFor="withdraw-amount">Amount (ETH)</Label>
              <Input
                id="withdraw-amount"
                type="number"
                step="0.001"
                placeholder="0.25"
                value={withdrawAmount}
                onChange={(e) => setWithdrawAmount(e.target.value)}
                required
                data-testid="input-withdraw-amount"
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="withdraw-address">Recipient 0x Address</Label>
              <Input
                id="withdraw-address"
                placeholder="0x71C...89A"
                value={withdrawAddress}
                onChange={(e) => setWithdrawAddress(e.target.value)}
                required
                className="font-mono text-xs"
                data-testid="input-withdraw-address"
              />
            </div>
            <Button
              type="submit"
              disabled={withdrawMutation.isPending || !withdrawAmount.trim()}
              data-testid="button-submit-withdraw"
            >
              {withdrawMutation.isPending ? "Submitting..." : "Queue Withdrawal"}
            </Button>
          </form>
        </CardContent>
      </Card>

      <Card className="glassmorphism border-primary/20">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-lg">
            <History className="h-5 w-5 text-primary" />
            Payout &amp; Withdrawal Ledger ({transactions.length})
          </CardTitle>
          <CardDescription>Recorded bounty settlements and withdrawal requests</CardDescription>
        </CardHeader>
        <CardContent>
          {txLoading ? (
            <p className="text-sm text-muted-foreground">Loading ledger…</p>
          ) : transactions.length === 0 ? (
            <p className="text-sm text-muted-foreground">
              No payout or withdrawal transactions recorded yet.
            </p>
          ) : (
            <div className="space-y-2">
              {transactions.map((tx) => (
                <div
                  key={tx.id}
                  className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-border/60 bg-muted/15 px-3.5 py-2.5 text-xs"
                >
                  <div className="flex items-center gap-2.5">
                    <Badge variant="outline" className="uppercase font-mono text-[10px]">
                      {tx.transaction_type}
                    </Badge>
                    <span className="font-mono font-semibold text-sm text-foreground">
                      {tx.amount} ETH
                    </span>
                    {tx.to_address && (
                      <span className="font-mono text-muted-foreground">
                        → {tx.to_address.slice(0, 10)}…
                      </span>
                    )}
                  </div>
                  <div className="flex items-center gap-2">
                    <Badge
                      variant={
                        tx.status === "completed"
                          ? "default"
                          : tx.status === "pending"
                            ? "secondary"
                            : "outline"
                      }
                    >
                      {tx.status}
                    </Badge>
                    <span className="font-mono text-muted-foreground">
                      {new Date(tx.timestamp).toLocaleString()}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
