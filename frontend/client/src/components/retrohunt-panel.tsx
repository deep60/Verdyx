import { useState } from "react";
import { Link } from "wouter";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { apiRequest } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import { serverMessage, type TeamSummary } from "@/lib/teams";
import { History, Loader2, Search, X } from "lucide-react";

export type HuntStatus = "queued" | "running" | "completed" | "failed" | "cancelled";

export interface Hunt {
  id: string;
  teamId?: string | null;
  teamName?: string | null;
  status: HuntStatus;
  filesTotal: number;
  filesScanned: number;
  filesFailed: number;
  matches: number;
  message?: string | null;
  createdAt: string;
  finishedAt?: string | null;
  ruleNames: string[];
}

export interface HuntResult {
  submissionId: string;
  rules: string[];
  filename?: string | null;
  url?: string | null;
  sha256?: string | null;
  type?: string;
  createdAt: string;
}

export interface HuntDetail extends Hunt {
  rule: string;
  results: HuntResult[];
}

const HUNTS = "/api/retrohunts";

export const isActive = (s: HuntStatus) => s === "queued" || s === "running";

/** "12 of 40 files", "queued", "3 matches in 40 files". */
export function progressText(h: Hunt): string {
  if (h.status === "queued") return "Waiting to start";
  const done = h.filesScanned + h.filesFailed;
  if (h.status === "running") return `Scanning: ${done} of ${h.filesTotal} files`;
  if (h.status === "failed") return h.message ?? "Failed";
  if (h.status === "cancelled") return `Cancelled after ${done} of ${h.filesTotal} files`;
  const m = `${h.matches} ${h.matches === 1 ? "match" : "matches"} in ${h.filesScanned} ${h.filesScanned === 1 ? "file" : "files"}`;
  const skipped = h.filesFailed > 0 ? `; ${h.filesFailed} couldn't be read` : "";
  return `${m}${skipped}${h.message ? ` (${h.message})` : ""}`;
}

export const STATUS_VARIANT: Record<HuntStatus, "default" | "secondary" | "destructive" | "outline"> = {
  queued: "outline",
  running: "default",
  completed: "secondary",
  failed: "destructive",
  cancelled: "outline",
};

function HuntResults({ id }: { id: string }) {
  const { data } = useQuery<HuntDetail>({
    queryKey: [`${HUNTS}/${id}`],
    refetchInterval: (q) => (q.state.data && isActive(q.state.data.status) ? 2000 : false),
  });
  if (!data) return <p className="text-xs text-muted-foreground">Loading…</p>;
  if (data.results.length === 0) {
    return (
      <p className="text-xs text-muted-foreground">
        {isActive(data.status) ? "No matches yet." : "No files matched."}
      </p>
    );
  }
  return (
    <ul className="space-y-1" data-testid="hunt-results">
      {data.results.map((r) => (
        <li key={r.submissionId} className="flex items-center justify-between gap-2 rounded bg-muted/20 px-2 py-1 text-xs">
          <Link href={`/analysis/${r.submissionId}`} className="min-w-0 truncate font-mono hover:underline">
            {r.filename ?? r.url ?? r.sha256 ?? r.submissionId}
          </Link>
          <span className="flex shrink-0 gap-1">
            {r.rules.map((n) => (
              <Badge key={n} variant="secondary" className="font-mono text-[10px]">
                {n}
              </Badge>
            ))}
          </span>
        </li>
      ))}
    </ul>
  );
}

/** Runs the studio's rule over past uploads on the server, with real YARA. */
export function RetrohuntPanel({ rule }: { rule: string }) {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [scope, setScope] = useState("personal");
  const [open, setOpen] = useState<string | null>(null);
  const { data: teams = [] } = useQuery<TeamSummary[]>({ queryKey: ["/api/orgs"] });
  const { data: hunts = [] } = useQuery<Hunt[]>({
    queryKey: [HUNTS],
    refetchInterval: (q) => ((q.state.data ?? []).some((h) => isActive(h.status)) ? 2000 : false),
  });
  const running = hunts.some((h) => isActive(h.status));

  const start = useMutation({
    mutationFn: async () =>
      (await apiRequest("POST", HUNTS, { rule, teamId: scope === "personal" ? null : scope })).json(),
    onSuccess: (h: { id: string }) => {
      setOpen(h.id);
      queryClient.invalidateQueries({ queryKey: [HUNTS] });
    },
    onError: (err) =>
      toast({ title: "Couldn't start the hunt", description: serverMessage(err, "Please try again."), variant: "destructive" }),
  });
  const cancel = useMutation({
    mutationFn: async (id: string) => apiRequest("DELETE", `${HUNTS}/${id}`),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: [HUNTS] }),
  });

  return (
    <div className="space-y-3 border-t border-border/60 pt-4" data-testid="retrohunt-panel">
      <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <div className="flex items-center gap-2 text-sm font-semibold">
            <History className="h-4 w-4 text-primary" /> Retrohunt
          </div>
          <p className="text-xs text-muted-foreground">
            Run this rule with real YARA over the files you&apos;ve uploaded (or a team&apos;s), from the last 30
            days. Older files are deleted under the retention policy.
          </p>
        </div>
        <div className="flex gap-2">
          <Select value={scope} onValueChange={setScope}>
            <SelectTrigger className="h-9 w-[170px]" aria-label="Files to search">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="personal">My uploads</SelectItem>
              {teams.map((t) => (
                <SelectItem key={t.id} value={t.id}>
                  Team: {t.name}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Button
            size="sm"
            className="h-9"
            onClick={() => start.mutate()}
            disabled={!rule.trim() || running || start.isPending}
            data-testid="button-retrohunt"
          >
            <Search className="mr-1 h-3.5 w-3.5" /> Hunt
          </Button>
        </div>
      </div>

      {hunts.length > 0 && (
        <ul className="space-y-2" data-testid="hunt-list">
          {hunts.slice(0, 10).map((h) => (
            <li key={h.id} className="rounded border border-border/60 p-2">
              <div className="flex flex-wrap items-center justify-between gap-2 text-xs">
                <button
                  type="button"
                  className="flex min-w-0 items-center gap-2 text-left"
                  onClick={() => setOpen(open === h.id ? null : h.id)}
                  aria-expanded={open === h.id}
                >
                  <Badge variant={STATUS_VARIANT[h.status]} className="shrink-0">
                    {isActive(h.status) && <Loader2 className="mr-1 h-3 w-3 animate-spin" />}
                    {h.status}
                  </Badge>
                  <span className="truncate font-mono">{h.ruleNames.join(", ") || "rule"}</span>
                  <span className="text-muted-foreground">{h.teamName ? `· ${h.teamName}` : "· my uploads"}</span>
                </button>
                <span className="flex items-center gap-2 text-muted-foreground">
                  {progressText(h)}
                  {isActive(h.status) && (
                    <Button size="sm" variant="ghost" className="h-6 px-1.5" onClick={() => cancel.mutate(h.id)} aria-label="Cancel hunt">
                      <X className="h-3.5 w-3.5" />
                    </Button>
                  )}
                </span>
              </div>
              {open === h.id && (
                <div className="mt-2">
                  <HuntResults id={h.id} />
                </div>
              )}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
