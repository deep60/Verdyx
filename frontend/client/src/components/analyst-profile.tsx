import { useMemo, useState } from "react";
import { Link } from "wouter";
import {
  Activity,
  ArrowUpRight,
  Award,
  ChevronRight,
  Copy,
  FileArchive,
  FileText,
  Flame,
  Globe,
  Mail,
  Radar,
  ShieldAlert,
  Trophy,
  Wallet,
} from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/utils";
import type { ApiSubmission } from "@/lib/api-types";
import {
  OUTCOME_LABEL,
  type ActivityDay,
  type ScanCounts,
  type ScanKind,
  type ScanOutcome,
  activityDays,
  currentStreak,
  isThreat,
  maskEmail,
  scanKind,
  scanName,
  scanOutcome,
  shortAddress,
} from "@/lib/profile";

const OUTCOME_PILL: Record<ScanOutcome, string> = {
  malicious: "bg-destructive/15 text-destructive border-destructive/40",
  suspicious: "bg-warning/15 text-warning border-warning/40",
  clean: "bg-success/10 text-success border-success/30",
  unknown: "bg-muted/40 text-muted-foreground border-border",
  running: "bg-muted/40 text-foreground border-border",
  failed: "bg-muted/40 text-muted-foreground border-border",
};

const OUTCOME_CELL: Record<ScanOutcome, string> = {
  malicious: "bg-destructive",
  suspicious: "bg-warning",
  clean: "bg-success/70",
  unknown: "bg-foreground/30",
  running: "bg-foreground/30",
  failed: "bg-foreground/20",
};

export function OutcomePill({ outcome }: { outcome: ScanOutcome }) {
  return (
    <span
      className={cn(
        "inline-flex shrink-0 items-center gap-1.5 rounded border px-2 py-0.5 text-xs font-medium",
        OUTCOME_PILL[outcome],
      )}
      data-testid="outcome-pill"
    >
      {outcome === "running" && <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-current" />}
      {OUTCOME_LABEL[outcome]}
    </span>
  );
}

const KIND_ICON: Record<ScanKind, typeof FileText> = { file: FileText, url: Globe, email: Mail };

function kindIcon(s: ApiSubmission) {
  const kind = scanKind(s);
  if (kind === "file" && /\.(zip|7z|rar|tar|gz|tgz)$/i.test(scanName(s))) return FileArchive;
  return KIND_ICON[kind];
}

function shortDate(iso?: string): string {
  const d = new Date(iso ?? "");
  if (Number.isNaN(d.getTime())) return "";
  return d.toLocaleDateString(undefined, { day: "numeric", month: "short" });
}

function timeAgo(iso?: string): string {
  const t = new Date(iso ?? "").getTime();
  if (!Number.isFinite(t)) return "";
  const mins = Math.max(0, Math.round((Date.now() - t) / 60_000));
  if (mins < 60) return mins <= 1 ? "Caught just now" : `Caught ${mins} minutes ago`;
  const hours = Math.round(mins / 60);
  if (hours < 24) return `Caught ${hours} ${hours === 1 ? "hour" : "hours"} ago`;
  const days = Math.round(hours / 24);
  return `Caught ${days} ${days === 1 ? "day" : "days"} ago`;
}

// ─── Header ─────────────────────────────────────────────────────

interface HeroProps {
  username: string;
  email: string;
  createdAt: string;
  walletAddress?: string | null;
  rank: { rank: number; of: number } | null;
  onConnectWallet: () => void;
}

export function ProfileHero({ username, email, createdAt, walletAddress, rank, onConnectWallet }: HeroProps) {
  const [copied, setCopied] = useState(false);
  const initials =
    username
      .split(/[\s._-]+/)
      .filter(Boolean)
      .map((n) => n[0])
      .join("")
      .slice(0, 2)
      .toUpperCase() || "?";
  const since = new Date(createdAt);
  const sinceText = Number.isNaN(since.getTime())
    ? null
    : since.toLocaleDateString(undefined, { month: "short", year: "numeric" });

  return (
    <Card className="glassmorphism relative overflow-hidden border-primary/20" data-testid="profile-hero">
      {/* A faint grid, so the header reads as a console rather than a form. */}
      <div
        aria-hidden
        className="pointer-events-none absolute inset-0 opacity-[0.06] [background-image:linear-gradient(to_right,currentColor_1px,transparent_1px),linear-gradient(to_bottom,currentColor_1px,transparent_1px)] [background-size:28px_28px]"
      />
      <CardContent className="relative flex flex-col gap-5 p-6 sm:flex-row sm:items-center sm:p-8">
        <div className="relative h-20 w-20 shrink-0">
          <div className="flex h-20 w-20 items-center justify-center rounded-full border border-foreground/20 bg-foreground/[0.06] font-display text-2xl tracking-tight">
            {initials}
          </div>
          <span
            className="absolute -bottom-1 -right-1 flex h-7 w-7 items-center justify-center rounded-full border border-border bg-background"
            title="Security analyst"
          >
            <Radar className="h-3.5 w-3.5" aria-hidden />
          </span>
        </div>

        <div className="min-w-0 flex-1">
          <p className="font-mono text-[11px] uppercase tracking-[0.2em] text-muted-foreground">Security analyst</p>
          <h1 className="mt-1 truncate font-display text-3xl tracking-[-0.02em]" data-testid="profile-username">
            {username}
          </h1>
          <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-sm text-muted-foreground">
            <span title="Shown in full under Account">{maskEmail(email)}</span>
            {sinceText && <span>Member since {sinceText}</span>}
            {rank ? (
              <Link
                href="/marketplace#leaderboard"
                className="inline-flex items-center gap-1 text-foreground hover:underline"
                data-testid="profile-rank"
              >
                <Trophy className="h-3.5 w-3.5" aria-hidden />
                Rank #{rank.rank} of {rank.of}
              </Link>
            ) : (
              <Link href="/marketplace#leaderboard" className="inline-flex items-center gap-1 hover:underline">
                <Trophy className="h-3.5 w-3.5" aria-hidden />
                Not ranked yet
              </Link>
            )}
          </div>
        </div>

        <div className="flex shrink-0 flex-col gap-2 sm:items-end">
          <Button asChild data-testid="profile-new-scan">
            <Link href="/dashboard">
              <ShieldAlert className="mr-2 h-4 w-4" aria-hidden />
              New scan
            </Link>
          </Button>
          {walletAddress ? (
            <button
              type="button"
              onClick={() => {
                void navigator.clipboard?.writeText(walletAddress).then(() => {
                  setCopied(true);
                  setTimeout(() => setCopied(false), 1500);
                });
              }}
              className="inline-flex items-center gap-2 rounded border border-border px-3 py-1.5 font-mono text-xs text-muted-foreground hover:text-foreground"
              title={walletAddress}
              data-testid="profile-wallet"
            >
              <span className="h-1.5 w-1.5 rounded-full bg-success" aria-hidden />
              {copied ? "Copied" : shortAddress(walletAddress)}
              <Copy className="h-3 w-3" aria-hidden />
            </button>
          ) : (
            <Button variant="outline" size="sm" onClick={onConnectWallet} data-testid="profile-connect-wallet">
              <Wallet className="mr-2 h-4 w-4" aria-hidden />
              Connect wallet
            </Button>
          )}
        </div>
      </CardContent>
    </Card>
  );
}

// ─── Stat tiles ─────────────────────────────────────────────────

function Tile({
  label,
  value,
  hint,
  icon: Icon,
  tone,
  loading,
  testId,
}: {
  label: string;
  value: string | number;
  hint: string;
  icon: typeof Activity;
  tone?: "danger";
  loading?: boolean;
  testId: string;
}) {
  return (
    <Card className="glassmorphism border-primary/20" data-testid={testId}>
      <CardContent className="p-4 sm:p-5">
        <div className="flex items-center justify-between text-muted-foreground">
          <span className="text-sm">{label}</span>
          <Icon className="h-4 w-4" aria-hidden />
        </div>
        {loading ? (
          <Skeleton className="mt-3 h-8 w-16" />
        ) : (
          <p
            className={cn(
              "mt-2 font-display text-2xl tracking-tight tabular-nums sm:text-3xl",
              tone === "danger" && "text-destructive",
            )}
          >
            {value}
          </p>
        )}
        <p className="mt-1 truncate text-xs text-muted-foreground" title={hint}>
          {hint}
        </p>
      </CardContent>
    </Card>
  );
}

export function ProfileStats({
  counts,
  reputation,
  rank,
  accuracy,
  rewards,
  bountiesJoined,
  loading,
}: {
  counts: ScanCounts;
  reputation: number;
  rank: { rank: number; of: number } | null;
  accuracy: number | null;
  rewards: number | null;
  bountiesJoined: number | null;
  loading?: boolean;
}) {
  const threats = counts.malicious + counts.suspicious;
  return (
    <div className="grid grid-cols-2 gap-3 sm:gap-4 lg:grid-cols-4">
      <Tile
        label="Scans"
        value={counts.total}
        hint={counts.thisWeek > 0 ? `${counts.thisWeek} this week` : "None this week"}
        icon={Activity}
        loading={loading}
        testId="stat-scans"
      />
      <Tile
        label="Threats caught"
        value={threats}
        hint={threats > 0 ? `${counts.malicious} malicious · ${counts.suspicious} suspicious` : "Nothing caught yet"}
        icon={ShieldAlert}
        tone={threats > 0 ? "danger" : undefined}
        loading={loading}
        testId="stat-threats"
      />
      <Tile
        label="Reputation"
        value={reputation}
        hint={
          rank
            ? `Rank #${rank.rank} of ${rank.of}${accuracy !== null ? ` · ${accuracy.toFixed(0)}% accurate` : ""}`
            : "Earned by verdicts that match consensus"
        }
        icon={Award}
        testId="stat-reputation"
      />
      <Tile
        label="Rewards earned"
        value={rewards === null ? "—" : rewards.toLocaleString(undefined, { maximumFractionDigits: 4 })}
        hint={
          bountiesJoined ? `From ${bountiesJoined} ${bountiesJoined === 1 ? "bounty" : "bounties"}` : "Win bounties in the marketplace"
        }
        icon={Trophy}
        testId="stat-rewards"
      />
    </div>
  );
}

// ─── Activity grid ──────────────────────────────────────────────

const WEEKS = 16;

export function ActivityGrid({ submissions }: { submissions: ApiSubmission[] }) {
  const days = useMemo(() => activityDays(submissions, WEEKS * 7), [submissions]);
  const streak = currentStreak(days);
  const active = days.filter((d) => d.scans > 0).length;
  // Columns are weeks, oldest on the left.
  const weeks: ActivityDay[][] = [];
  for (let i = 0; i < days.length; i += 7) weeks.push(days.slice(i, i + 7));
  const busiest = days.reduce<ActivityDay | null>((best, d) => (d.scans > (best?.scans ?? 0) ? d : best), null);
  const done = submissions.filter((s) => {
    const o = scanOutcome(s);
    return o !== "running" && o !== "failed";
  });
  const threatShare = done.length > 0 ? Math.round((done.filter((s) => isThreat(scanOutcome(s))).length / done.length) * 100) : null;
  const lastWeek = days.slice(-7).reduce((n, d) => n + d.scans, 0);

  return (
    <Card className="glassmorphism border-primary/20" data-testid="activity-grid">
      <CardContent className="p-5">
        <div className="flex flex-wrap items-baseline justify-between gap-2">
          <h2 className="text-sm font-medium">Activity, last {WEEKS} weeks</h2>
          <p className="text-xs text-muted-foreground">
            {active} active {active === 1 ? "day" : "days"}
            {streak > 1 && (
              <span className="ml-2 inline-flex items-center gap-1 text-foreground">
                <Flame className="h-3 w-3" aria-hidden />
                {streak}-day streak
              </span>
            )}
          </p>
        </div>
        <div className="mt-4 flex flex-col gap-6 sm:flex-row sm:items-start">
        <div
          className="flex shrink-0 gap-[3px] overflow-x-auto pb-1"
          role="img"
          aria-label={`${active} days with scans in the last ${WEEKS} weeks`}
        >
          {weeks.map((week, w) => (
            <div key={w} className="flex flex-col gap-[3px]">
              {week.map((d) => (
                <div
                  key={d.date}
                  className={cn(
                    "h-3.5 w-3.5 rounded-[3px]",
                    d.worst ? OUTCOME_CELL[d.worst] : "bg-foreground/[0.06]",
                  )}
                  title={
                    d.scans === 0
                      ? `${d.date}: no scans`
                      : `${d.date}: ${d.scans} ${d.scans === 1 ? "scan" : "scans"}${d.worst && isThreat(d.worst) ? `, ${OUTCOME_LABEL[d.worst].toLowerCase()} found` : ""}`
                  }
                />
              ))}
            </div>
          ))}
        </div>
        <dl className="grid flex-1 grid-cols-3 gap-4 sm:grid-cols-1 sm:gap-3 sm:border-l sm:border-border sm:pl-6">
          <div>
            <dt className="text-xs text-muted-foreground">Last 7 days</dt>
            <dd className="font-display text-lg tabular-nums sm:text-xl">{lastWeek} {lastWeek === 1 ? "scan" : "scans"}</dd>
          </div>
          <div>
            <dt className="text-xs text-muted-foreground">Threat rate</dt>
            <dd className="font-display text-lg tabular-nums sm:text-xl">{threatShare === null ? "—" : `${threatShare}%`}</dd>
          </div>
          <div>
            <dt className="text-xs text-muted-foreground">Busiest day</dt>
            <dd className="font-display text-lg tabular-nums sm:text-xl">
              {busiest ? shortDate(`${busiest.date}T12:00:00`) : "—"}
            </dd>
            <dd className="text-xs text-muted-foreground">
              {busiest ? `${busiest.scans} ${busiest.scans === 1 ? "scan" : "scans"}` : ""}
            </dd>
          </div>
        </dl>
        </div>
        <div className="mt-3 flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-muted-foreground">
          <Legend className="bg-destructive" label="Malicious found" />
          <Legend className="bg-warning" label="Suspicious found" />
          <Legend className="bg-success/70" label="No threats" />
          <Legend className="bg-foreground/[0.06]" label="No scans" />
        </div>
      </CardContent>
    </Card>
  );
}

function Legend({ className, label }: { className: string; label: string }) {
  return (
    <span className="inline-flex items-center gap-1.5">
      <span className={cn("h-2.5 w-2.5 rounded-[2px]", className)} aria-hidden />
      {label}
    </span>
  );
}

// ─── Latest catch ───────────────────────────────────────────────

export function LatestCatch({ scan }: { scan: ApiSubmission | undefined }) {
  if (!scan) {
    return (
      <Card className="glassmorphism border-primary/20" data-testid="latest-catch">
        <CardContent className="flex h-full flex-col justify-between gap-4 p-5">
          <div>
            <p className="font-mono text-[11px] uppercase tracking-[0.2em] text-muted-foreground">Latest catch</p>
            <p className="mt-3 text-sm text-muted-foreground">
              No threats caught yet. Scan a suspicious file, link or email and the first catch shows up here.
            </p>
          </div>
          <Button asChild variant="outline" size="sm" className="self-start">
            <Link href="/dashboard">Scan something</Link>
          </Button>
        </CardContent>
      </Card>
    );
  }
  const outcome = scanOutcome(scan);
  const Icon = kindIcon(scan);
  return (
    <Link href={`/analysis/${scan.id}`} className="group block h-full" data-testid="latest-catch">
      <Card
        className={cn(
          "glassmorphism h-full border transition-colors",
          outcome === "malicious" ? "border-destructive/40 group-hover:border-destructive/70" : "border-warning/40 group-hover:border-warning/70",
        )}
      >
        <CardContent className="flex h-full flex-col justify-between gap-4 p-5">
          <div className="flex items-center justify-between">
            <p className="font-mono text-[11px] uppercase tracking-[0.2em] text-muted-foreground">Latest catch</p>
            <ArrowUpRight className="h-4 w-4 text-muted-foreground transition-transform group-hover:-translate-y-0.5 group-hover:translate-x-0.5" aria-hidden />
          </div>
          <div
            className={cn(
              "flex h-12 w-12 items-center justify-center rounded-full border",
              outcome === "malicious" ? "border-destructive/40 bg-destructive/15 text-destructive" : "border-warning/40 bg-warning/15 text-warning",
            )}
          >
            <ShieldAlert className="h-5 w-5" aria-hidden />
          </div>
          <div className="min-w-0">
            <div className="flex min-w-0 items-center gap-2">
              <Icon className="h-4 w-4 shrink-0 text-muted-foreground" aria-hidden />
              <p className="truncate font-medium" title={scanName(scan)}>
                {scanName(scan)}
              </p>
            </div>
            <div className="mt-3 flex items-center gap-3">
              <OutcomePill outcome={outcome} />
              <span className="text-xs text-muted-foreground">{timeAgo(scan.createdAt)}</span>
            </div>
            <p className="mt-4 text-xs text-muted-foreground group-hover:text-foreground">Open the report</p>
          </div>
        </CardContent>
      </Card>
    </Link>
  );
}

// ─── Submission list ────────────────────────────────────────────

type Filter = "all" | "threats" | ScanKind;

const FILTERS: { value: Filter; label: string }[] = [
  { value: "all", label: "All" },
  { value: "threats", label: "Threats" },
  { value: "file", label: "Files" },
  { value: "url", label: "URLs" },
  { value: "email", label: "Emails" },
];

export function SubmissionList({
  submissions,
  limit,
  title = "Your submissions",
  onShowAll,
}: {
  submissions: ApiSubmission[];
  limit?: number;
  title?: string;
  onShowAll?: () => void;
}) {
  const [filter, setFilter] = useState<Filter>("all");
  const filtered = submissions.filter((s) => {
    if (filter === "all") return true;
    if (filter === "threats") return isThreat(scanOutcome(s));
    return scanKind(s) === filter;
  });
  const shown = limit ? filtered.slice(0, limit) : filtered;

  return (
    <Card className="glassmorphism overflow-hidden border-primary/20" data-testid="submission-list">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-border px-5 py-4">
        <h2 className="text-sm font-medium">{title}</h2>
        <div className="flex flex-wrap gap-1" role="group" aria-label="Filter submissions">
          {FILTERS.map((f) => (
            <button
              key={f.value}
              type="button"
              onClick={() => setFilter(f.value)}
              aria-pressed={filter === f.value}
              className={cn(
                "rounded px-2.5 py-1 text-xs transition-colors",
                filter === f.value ? "bg-foreground text-background" : "text-muted-foreground hover:bg-muted/50 hover:text-foreground",
              )}
            >
              {f.label}
            </button>
          ))}
        </div>
      </div>

      {shown.length === 0 ? (
        <div className="px-5 py-12 text-center">
          <p className="text-sm text-muted-foreground">
            {submissions.length === 0 ? "Your scans show up here." : "No scans match this filter."}
          </p>
          {submissions.length === 0 && (
            <Button asChild size="sm" className="mt-4">
              <Link href="/dashboard">Run your first scan</Link>
            </Button>
          )}
        </div>
      ) : (
        <ul className="divide-y divide-border">
          {shown.map((s) => {
            const Icon = kindIcon(s);
            const name = scanName(s);
            return (
              <li key={s.id}>
                <Link
                  href={`/analysis/${s.id}`}
                  className="grid grid-cols-[1.25rem_minmax(0,1fr)_auto] items-center gap-x-3 gap-y-1 px-5 py-3 transition-colors hover:bg-muted/30 sm:grid-cols-[1.25rem_minmax(0,1fr)_auto_4.5rem_1rem]"
                  data-testid="submission-row"
                >
                  <Icon className="h-4 w-4 text-muted-foreground" aria-hidden />
                  <span className="truncate text-sm" title={name}>
                    {name}
                  </span>
                  <OutcomePill outcome={scanOutcome(s)} />
                  <span className="hidden text-right text-xs text-muted-foreground sm:block">{shortDate(s.createdAt)}</span>
                  <ChevronRight className="hidden h-4 w-4 text-muted-foreground sm:block" aria-hidden />
                </Link>
              </li>
            );
          })}
        </ul>
      )}

      {limit && filtered.length > limit && onShowAll && (
        <button
          type="button"
          onClick={onShowAll}
          className="w-full border-t border-border px-5 py-3 text-left text-xs text-muted-foreground hover:text-foreground"
        >
          Show all {filtered.length}
        </button>
      )}
    </Card>
  );
}
