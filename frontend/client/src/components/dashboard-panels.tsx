import { ArrowUpRight } from "lucide-react";
import { Card } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/utils";
import type { ApiEngine, ApiStats } from "@/lib/api-types";
import type { ScanCounts } from "@/lib/profile";
import { type EngineState, engineState, engineSummary, verdictMix } from "@/lib/dashboard";

const DOT: Record<EngineState, string> = {
  online: "bg-success",
  advisory: "bg-warning",
  off: "bg-muted-foreground/50",
};

const STATE_LABEL: Record<EngineState, string> = {
  online: "Voting",
  advisory: "Advisory",
  off: "Off",
};

function Eyebrow({ children }: { children: React.ReactNode }) {
  return <p className="font-mono text-[11px] uppercase tracking-[0.18em] text-muted-foreground">{children}</p>;
}

// ─── Header status ──────────────────────────────────────────────

export function SystemStatus({
  engines,
  enginesLoading,
  live,
}: {
  engines: ApiEngine[];
  enginesLoading: boolean;
  live: boolean;
}) {
  const sum = engineSummary(engines);
  const voting = sum.online;
  const healthy = sum.total > 0 && sum.off === 0;
  return (
    <div className="flex flex-wrap items-center gap-2 text-xs" data-testid="system-status">
      <a
        href="#engines"
        className="inline-flex items-center gap-2 rounded-md border border-border bg-card px-2.5 py-1.5 transition-colors hover:border-foreground/40"
      >
        <span className={cn("h-2 w-2 rounded-full", enginesLoading ? "bg-muted-foreground/50" : healthy ? "bg-success" : "bg-warning")} />
        {enginesLoading ? "Checking engines" : sum.total === 0 ? "Engines unavailable" : `${voting} of ${sum.total} engines voting`}
      </a>
      <span className="inline-flex items-center gap-2 rounded-md border border-border bg-card px-2.5 py-1.5" title="Results arrive without a reload">
        <span className={cn("h-2 w-2 rounded-full", live ? "animate-pulse bg-success" : "bg-muted-foreground/50")} />
        {live ? "Live" : "Refreshing every 30s"}
      </span>
    </div>
  );
}

// ─── Numbers ────────────────────────────────────────────────────

function Tile({
  label,
  value,
  sub,
  tone,
  loading,
}: {
  label: string;
  value: string | number;
  sub: string;
  tone?: "threat";
  loading?: boolean;
}) {
  return (
    <div className="flex min-w-0 flex-col justify-between gap-3 bg-card p-4 sm:p-5">
      <Eyebrow>{label}</Eyebrow>
      {loading ? (
        <Skeleton className="h-8 w-16" />
      ) : (
        <p className={cn("font-mono text-3xl tabular-nums tracking-tight", tone === "threat" && Number(value) > 0 && "text-destructive")}>
          {value}
        </p>
      )}
      <p className="truncate text-xs text-muted-foreground">{sub}</p>
    </div>
  );
}

export function KpiStrip({
  counts,
  loading,
  stats,
}: {
  counts: ScanCounts;
  loading: boolean;
  stats: ApiStats | undefined;
}) {
  const threats = counts.malicious + counts.suspicious;
  const rate = counts.total > 0 ? Math.round((threats / counts.total) * 100) : null;
  return (
    <Card
      className="grid grid-cols-2 gap-px overflow-hidden bg-border"
      data-testid="kpi-strip"
    >
      <Tile label="Your scans" value={counts.total} sub={`${counts.thisWeek} in the last 7 days`} loading={loading} />
      <Tile
        label="Threats caught"
        value={threats}
        sub={threats > 0 ? `${counts.malicious} malicious · ${counts.suspicious} suspicious` : "Nothing caught yet"}
        tone="threat"
        loading={loading}
      />
      <Tile
        label="Threat rate"
        value={rate === null ? "—" : `${rate}%`}
        sub={rate === null ? "After your first scan" : `${counts.clean} came back clean`}
        loading={loading}
      />
      <Tile
        label="Time to verdict"
        value={stats?.avgResponseTime ?? "—"}
        sub="Average across Verdyx"
        loading={!stats && loading}
      />
    </Card>
  );
}

// ─── Engines ────────────────────────────────────────────────────

export function EngineHealth({ engines, loading, error }: { engines: ApiEngine[]; loading: boolean; error: boolean }) {
  const sum = engineSummary(engines);
  const order: Record<EngineState, number> = { online: 0, advisory: 1, off: 2 };
  const sorted = [...engines].sort((a, b) => order[engineState(a)] - order[engineState(b)]);
  return (
    <Card className="overflow-hidden" id="engines" data-testid="engine-health">
      <div className="flex items-center justify-between border-b border-border px-5 py-4">
        <div>
          <h2 className="text-sm font-medium">Engines</h2>
          <p className="mt-0.5 text-xs text-muted-foreground">
            {loading ? "Checking…" : error ? "Couldn't reach the analysis engine" : `${sum.online} voting · ${sum.advisory} advisory · ${sum.off} off`}
          </p>
        </div>
        {sum.total > 0 && (
          <div className="flex h-1.5 w-24 overflow-hidden rounded-full bg-muted" aria-hidden>
            <span className="bg-success" style={{ width: `${(sum.online / sum.total) * 100}%` }} />
            <span className="bg-warning" style={{ width: `${(sum.advisory / sum.total) * 100}%` }} />
          </div>
        )}
      </div>
      {loading ? (
        <div className="space-y-3 p-5">
          {Array.from({ length: 5 }).map((_, i) => (
            <Skeleton key={i} className="h-4 w-full" />
          ))}
        </div>
      ) : (
        <ul className="max-h-[22rem] divide-y divide-border overflow-y-auto">
          {sorted.map((e) => {
            const state = engineState(e);
            return (
              <li key={e.id} className="flex items-center gap-3 px-5 py-2.5" title={e.description ?? undefined}>
                <span className={cn("h-2 w-2 shrink-0 rounded-full", DOT[state])} aria-hidden />
                <span className="min-w-0 flex-1 truncate text-sm">{e.name}</span>
                <span className={cn("font-mono text-[11px] uppercase tracking-wider", state === "online" ? "text-muted-foreground" : state === "advisory" ? "text-warning" : "text-muted-foreground/70")}>
                  {STATE_LABEL[state]}
                </span>
              </li>
            );
          })}
        </ul>
      )}
    </Card>
  );
}

// ─── Verdicts across Verdyx ─────────────────────────────────────

export function VerdictMixCard({
  stats,
  loading,
  onOpenAnalytics,
}: {
  stats: ApiStats | undefined;
  loading: boolean;
  onOpenAnalytics: () => void;
}) {
  const mix = verdictMix(stats);
  const rows = mix
    ? [
        { label: "Malicious", n: mix.malicious, bar: "bg-destructive" },
        { label: "Suspicious", n: mix.suspicious, bar: "bg-warning" },
        { label: "Clean", n: mix.clean, bar: "bg-success/70" },
      ]
    : [];
  return (
    <Card className="p-5" data-testid="verdict-mix">
      <div className="flex items-start justify-between gap-3">
        <div>
          <h2 className="text-sm font-medium">Across Verdyx</h2>
          <p className="mt-0.5 text-xs text-muted-foreground">
            {mix ? `${mix.total.toLocaleString()} verdicts from every analyst` : loading ? "Loading…" : "No verdicts yet"}
          </p>
        </div>
        <button type="button" onClick={onOpenAnalytics} className="inline-flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground">
          Analytics
          <ArrowUpRight className="h-3.5 w-3.5" aria-hidden />
        </button>
      </div>
      {mix && (
        <>
          <div className="mt-4 flex h-2 overflow-hidden rounded-full bg-muted" aria-hidden>
            {rows.map((r) => (
              <span key={r.label} className={r.bar} style={{ width: `${(r.n / mix.total) * 100}%` }} />
            ))}
          </div>
          <dl className="mt-4 grid grid-cols-3 gap-2">
            {rows.map((r) => (
              <div key={r.label}>
                <dt className="flex items-center gap-1.5 text-xs text-muted-foreground">
                  <span className={cn("h-1.5 w-1.5 rounded-full", r.bar)} aria-hidden />
                  {r.label}
                </dt>
                <dd className="mt-1 font-mono text-lg tabular-nums">{r.n.toLocaleString()}</dd>
              </div>
            ))}
          </dl>
        </>
      )}
    </Card>
  );
}
