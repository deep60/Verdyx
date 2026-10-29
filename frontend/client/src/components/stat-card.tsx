import { type LucideIcon, TrendingUp, TrendingDown } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/utils";

type Accent = "primary" | "accent" | "warning" | "destructive";

const accentMap: Record<
  Accent,
  {
    text: string;
    ring: string;
    iconBg: string;
    beam: string;
    dot: string;
  }
> = {
  primary: {
    text: "text-primary",
    ring: "border-primary/25 hover:border-primary/50",
    iconBg: "bg-primary/15 text-primary border border-primary/30",
    beam: "from-primary/80 via-cyan-400/60 to-transparent",
    dot: "bg-primary",
  },
  accent: {
    text: "text-accent",
    ring: "border-accent/25 hover:border-accent/50",
    iconBg: "bg-accent/15 text-accent border border-accent/30",
    beam: "from-accent/80 via-emerald-400/60 to-transparent",
    dot: "bg-accent",
  },
  warning: {
    text: "text-warning",
    ring: "border-warning/25 hover:border-warning/50",
    iconBg: "bg-warning/15 text-warning border border-warning/30",
    beam: "from-warning/80 via-amber-400/60 to-transparent",
    dot: "bg-warning",
  },
  destructive: {
    text: "text-destructive",
    ring: "border-destructive/25 hover:border-destructive/50",
    iconBg: "bg-destructive/15 text-destructive border border-destructive/30",
    beam: "from-destructive/80 via-rose-400/60 to-transparent",
    dot: "bg-destructive",
  },
};

interface StatCardProps {
  label: string;
  value: string | number;
  icon: LucideIcon;
  accent?: Accent;
  hint?: string;
  trend?: number;
  loading?: boolean;
}

export function StatCard({
  label,
  value,
  icon: Icon,
  accent = "primary",
  hint,
  trend,
  loading,
}: StatCardProps) {
  const colors = accentMap[accent];

  return (
    <Card className={cn("bento-card group", colors.ring)}>
      <div
        className={cn(
          "absolute inset-x-0 top-0 h-[2px] bg-gradient-to-r opacity-75 group-hover:opacity-100 transition-opacity",
          colors.beam
        )}
      />
      <CardContent className="p-6">
        <div className="flex items-start justify-between gap-3">
          <div className="space-y-1.5 min-w-0">
            <div className="flex items-center gap-2">
              <span className={cn("h-1.5 w-1.5 rounded-full", colors.dot)} />
              <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground truncate">
                {label}
              </p>
            </div>
            {loading ? (
              <Skeleton className="h-9 w-24" />
            ) : (
              <p className="text-3xl md:text-4xl font-extrabold font-display tracking-tight tabular-nums text-foreground">
                {value}
              </p>
            )}
          </div>
          <div
            className={cn(
              "flex h-11 w-11 shrink-0 items-center justify-center rounded-xl transition-transform duration-300 group-hover:scale-110",
              colors.iconBg
            )}
          >
            <Icon className="h-5 w-5" />
          </div>
        </div>

        <div className="mt-4 pt-3 border-t border-border/40 flex items-center justify-between">
          {loading ? (
            <Skeleton className="h-4 w-28" />
          ) : trend !== undefined ? (
            <div
              className={cn(
                "flex items-center gap-1 text-xs font-mono font-medium",
                trend >= 0 ? "text-accent" : "text-destructive"
              )}
            >
              {trend >= 0 ? (
                <TrendingUp className="h-3.5 w-3.5" />
              ) : (
                <TrendingDown className="h-3.5 w-3.5" />
              )}
              <span>
                {trend >= 0 ? "+" : ""}
                {trend}% vs 24h avg
              </span>
            </div>
          ) : hint ? (
            <p className="text-xs font-mono text-muted-foreground truncate">{hint}</p>
          ) : null}
          <span className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground/70">
            LIVE
          </span>
        </div>
      </CardContent>
    </Card>
  );
}
