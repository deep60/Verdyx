import { useQuery } from "@tanstack/react-query";
import { Link } from "wouter";
import { Badge } from "@/components/ui/badge";
import { meter, planName, resetDate, type TeamUsage, type Tone } from "@/lib/plans";

const barClass: Record<Tone, string> = {
  ok: "bg-primary",
  warning: "bg-amber-500",
  danger: "bg-red-500",
};

export function Meter({ label, used, limit, testId }: { label: string; used: number; limit: number | null; testId: string }) {
  const m = meter(used, limit);
  return (
    <div className="space-y-1" data-testid={testId}>
      <div className="flex justify-between gap-3 text-sm">
        <span>{label}</span>
        <span className={`font-mono ${m.tone === "danger" ? "text-red-500" : m.tone === "warning" ? "text-amber-500" : ""}`}>
          {m.text}
        </span>
      </div>
      {limit !== null && (
        <div
          className="h-1.5 overflow-hidden rounded-full bg-muted"
          role="progressbar"
          aria-label={label}
          aria-valuenow={m.percent}
          aria-valuemin={0}
          aria-valuemax={100}
        >
          <div className={`h-full ${barClass[m.tone]}`} style={{ width: `${m.percent}%` }} />
        </div>
      )}
    </div>
  );
}

/** The team's plan, its limits and how much of them is used. */
export function TeamPlan({ teamId }: { teamId: string }) {
  const { data, isLoading, isError } = useQuery<TeamUsage>({ queryKey: [`/api/orgs/${teamId}/usage`] });
  if (isLoading) return <p className="text-sm text-muted-foreground">Loading…</p>;
  if (isError || !data) return <p className="text-sm text-muted-foreground">The plan isn&apos;t available right now.</p>;

  const { limits, usage } = data;
  return (
    <section className="space-y-4" data-testid="team-plan" aria-labelledby="team-plan-heading">
      <div className="flex flex-wrap items-center gap-2">
        <h3 id="team-plan-heading" className="text-sm font-medium">
          Plan
        </h3>
        <Badge>{planName(data.plan)}</Badge>
        {data.custom && <Badge variant="outline">Custom limits</Badge>}
      </div>
      <Meter
        label={`Scans this month (starts again ${resetDate(data.resetsAt)})`}
        used={usage.scansThisMonth}
        limit={limits.teamScansPerMonth}
        testId="usage-scans"
      />
      <Meter label="Members and open invitations" used={usage.seats} limit={limits.seats} testId="usage-seats" />
      <Meter label="Active team API keys" used={usage.teamKeys} limit={limits.teamKeys} testId="usage-keys" />
      <Meter
        label="Storage connections"
        used={usage.storageConnections}
        limit={limits.storageConnections}
        testId="usage-storage"
      />
      <p className="text-xs text-muted-foreground">
        Each member may start {limits.scansPerMinute.toLocaleString("en-US")} scans a minute and{" "}
        {limits.scansPerDay.toLocaleString("en-US")} a day.{" "}
        <Link href="/pricing" className="text-primary hover:underline">
          Compare plans
        </Link>
      </p>
    </section>
  );
}
