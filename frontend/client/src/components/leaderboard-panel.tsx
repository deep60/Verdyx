import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Card, CardContent } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ErrorState } from "@/components/error-state";
import { EmptyState } from "@/components/empty-state";
import { Trophy } from "lucide-react";
import type { ApiEngine } from "@/lib/api-types";

interface AnalystStanding {
  rank?: number;
  userId?: string;
  username?: string;
  score?: number;
  accuracyRate?: string | number | null;
  totalSubmissions?: number | null;
  currentStreak?: number | null;
  totalEarned?: string | number | null;
}

type SortKey = "accuracy" | "streak" | "stake";

function asNumber(value: string | number | null | undefined): number {
  if (value === null || value === undefined || value === "") return Number.NEGATIVE_INFINITY;
  const n = typeof value === "number" ? value : Number(value);
  return Number.isFinite(n) ? n : Number.NEGATIVE_INFINITY;
}

export function LeaderboardPanel({ engines }: { engines: ApiEngine[] }) {
  const [sort, setSort] = useState<SortKey>("accuracy");
  const { data, isError, isLoading, refetch } = useQuery<{ analysts?: AnalystStanding[] }>({
    queryKey: ["/api/reputation/standings"],
  });

  const analysts = useMemo(() => {
    const rows = [...(data?.analysts ?? [])];
    rows.sort((a, b) => {
      if (sort === "streak") return asNumber(b.currentStreak) - asNumber(a.currentStreak);
      if (sort === "stake") return asNumber(b.totalEarned) - asNumber(a.totalEarned);
      return asNumber(b.accuracyRate) - asNumber(a.accuracyRate);
    });
    return rows;
  }, [data, sort]);

  const rankedEngines = useMemo(() => {
    const rows = [...engines];
    rows.sort((a, b) => {
      if (sort === "stake") return asNumber(b.stakeAmount) - asNumber(a.stakeAmount);
      return asNumber(b.accuracy || b.accuracyRate) - asNumber(a.accuracy || a.accuracyRate);
    });
    return rows;
  }, [engines, sort]);

  return (
    <section className="mb-16">
      <div className="text-center mb-8">
        <h1 className="text-4xl md:text-5xl font-bold font-display tracking-[-0.03em] mb-4">
          Reputation Leaderboard
        </h1>
        <p className="text-xl text-muted-foreground">
          Engines and researchers, ranked by accuracy, win streak, and what they have staked.
        </p>
      </div>

      <div className="flex justify-center mb-8">
        <div className="flex gap-2">
          {(
            [
              ["accuracy", "Accuracy"],
              ["streak", "Win streak"],
              ["stake", "Staked volume"],
            ] as const
          ).map(([key, label]) => (
            <button
              key={key}
              type="button"
              onClick={() => setSort(key)}
              className={`rounded-full border px-4 py-1.5 text-sm ${
                sort === key ? "bg-primary text-primary-foreground border-primary" : "border-border text-muted-foreground"
              }`}
              data-testid={`sort-${key}`}
            >
              {label}
            </button>
          ))}
        </div>
      </div>

      <Tabs defaultValue="analysts">
        <TabsList className="mb-6">
          <TabsTrigger value="analysts">Researchers</TabsTrigger>
          <TabsTrigger value="engines">Engines</TabsTrigger>
        </TabsList>

        <TabsContent value="analysts">
          {isError ? (
            <ErrorState title="Leaderboard unavailable" message="Could not load researcher standings." onRetry={() => refetch()} />
          ) : isLoading ? (
            <p className="text-sm text-muted-foreground">Loading standings…</p>
          ) : analysts.length === 0 ? (
            <EmptyState icon={Trophy} title="No researchers yet" description="Accuracy and streaks appear after reputation-service records graded verdicts." />
          ) : (
            <div className="space-y-3">
              {analysts.map((row, index) => (
                <Card key={row.userId || index} className="glassmorphism">
                  <CardContent className="p-4 grid grid-cols-2 md:grid-cols-6 gap-3 items-center">
                    <div className="font-display text-2xl text-primary">#{row.rank ?? index + 1}</div>
                    <div className="md:col-span-2">
                      <div className="font-semibold">{row.username || "Analyst"}</div>
                      <div className="text-xs text-muted-foreground">{row.totalSubmissions ?? "—"} submissions</div>
                    </div>
                    <Stat label="Accuracy" value={formatRate(row.accuracyRate)} />
                    <Stat label="Win streak" value={row.currentStreak ?? "—"} />
                    <Stat label="Earned" value={row.totalEarned ?? "—"} />
                  </CardContent>
                </Card>
              ))}
            </div>
          )}
        </TabsContent>

        <TabsContent value="engines">
          {rankedEngines.length === 0 ? (
            <EmptyState icon={Trophy} title="No engines yet" description="Registered engines show their accuracy and stake here." />
          ) : (
            <div className="space-y-3">
              {rankedEngines.map((engine, index) => (
                <Card key={engine.id} className="glassmorphism">
                  <CardContent className="p-4 grid grid-cols-2 md:grid-cols-5 gap-3 items-center">
                    <div className="font-display text-2xl text-primary">#{index + 1}</div>
                    <div>
                      <div className="font-semibold">{engine.name}</div>
                      <div className="text-xs text-muted-foreground capitalize">{engine.type || engine.engineType}</div>
                    </div>
                    <Stat label="Accuracy" value={formatRate(engine.accuracy || engine.accuracyRate)} />
                    <Stat label="Analyses" value={engine.totalAnalyses ?? "—"} />
                    <Stat label="Stake" value={engine.stakeAmount ? `${engine.stakeAmount} ETH` : "—"} />
                  </CardContent>
                </Card>
              ))}
            </div>
          )}
        </TabsContent>
      </Tabs>
    </section>
  );
}

function Stat({ label, value }: { label: string; value: string | number }) {
  return (
    <div>
      <div className="text-xs text-muted-foreground">{label}</div>
      <div className="font-medium">{value}</div>
    </div>
  );
}

function formatRate(value: string | number | null | undefined): string {
  if (value === null || value === undefined || value === "") return "—";
  const n = typeof value === "number" ? value : Number(value);
  if (!Number.isFinite(n)) return String(value);
  return n <= 1 ? `${(n * 100).toFixed(1)}%` : `${n.toFixed(1)}%`;
}
