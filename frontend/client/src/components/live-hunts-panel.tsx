import { useState } from "react";
import { Link } from "wouter";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { apiRequest } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import { serverMessage, type TeamSummary } from "@/lib/teams";
import { BellRing, Pencil, Radar, Trash2 } from "lucide-react";
import { LIVE_HUNTS, matchSummary, timeAgo, type LiveHunt, type LiveHuntDetail } from "@/lib/live-hunts";

function HuntMatches({ id }: { id: string }) {
  const queryClient = useQueryClient();
  const { data } = useQuery<LiveHuntDetail>({ queryKey: [`${LIVE_HUNTS}/${id}`], refetchInterval: 15000 });
  const seen = useMutation({
    mutationFn: async () => apiRequest("POST", `${LIVE_HUNTS}/${id}/seen`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: [LIVE_HUNTS] });
      queryClient.invalidateQueries({ queryKey: [`${LIVE_HUNTS}/${id}`] });
    },
  });
  if (!data) return <p className="text-xs text-muted-foreground">Loading…</p>;
  return (
    <div className="space-y-2">
      {data.lastError && (
        <p className="text-xs text-destructive" data-testid="live-hunt-error">
          Turned off: {data.lastError}. Fix the rule and save it again.
        </p>
      )}
      {data.results.length === 0 ? (
        <p className="text-xs text-muted-foreground">
          No matches yet. Every new file {data.teamName ? `saved to ${data.teamName}` : "you upload"} is checked
          against it.
        </p>
      ) : (
        <>
          <ul className="space-y-1" data-testid="live-hunt-results">
            {data.results.map((r) => (
              <li
                key={r.submissionId}
                className="flex items-center justify-between gap-2 rounded bg-muted/20 px-2 py-1 text-xs"
              >
                <span className="flex min-w-0 items-center gap-2">
                  {!r.seen && <span className="h-1.5 w-1.5 shrink-0 rounded-full bg-primary" aria-label="new" />}
                  <Link href={`/analysis/${r.submissionId}`} className="truncate font-mono hover:underline">
                    {r.filename ?? r.url ?? r.sha256 ?? r.submissionId}
                  </Link>
                  <span className="shrink-0 text-muted-foreground">{timeAgo(r.matchedAt)}</span>
                </span>
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
          {data.unseen > 0 && (
            <Button size="sm" variant="ghost" className="h-7 text-xs" onClick={() => seen.mutate()}>
              Mark {data.unseen} as seen
            </Button>
          )}
        </>
      )}
    </div>
  );
}

/**
 * Saves the studio's rule as a live hunt: it runs with real YARA on every new
 * upload (yours, or a team's) and lists the files it matches.
 */
export function LiveHuntsPanel({ rule, onEditRule }: { rule: string; onEditRule?: (rule: string) => void }) {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [name, setName] = useState("");
  const [scope, setScope] = useState("personal");
  const [open, setOpen] = useState<string | null>(null);
  const { data: teams = [] } = useQuery<TeamSummary[]>({ queryKey: ["/api/orgs"] });
  const { data: hunts = [] } = useQuery<LiveHunt[]>({ queryKey: [LIVE_HUNTS], refetchInterval: 30000 });
  const refresh = (id?: string) => {
    queryClient.invalidateQueries({ queryKey: [LIVE_HUNTS] });
    if (id) queryClient.invalidateQueries({ queryKey: [`${LIVE_HUNTS}/${id}`] });
  };
  const failed = (title: string) => (err: unknown) =>
    toast({ title, description: serverMessage(err, "Please try again."), variant: "destructive" });

  const create = useMutation({
    mutationFn: async () =>
      (
        await apiRequest("POST", LIVE_HUNTS, {
          name: name.trim(),
          rule,
          teamId: scope === "personal" ? null : scope,
        })
      ).json(),
    onSuccess: (h: LiveHunt) => {
      setName("");
      setOpen(h.id);
      refresh();
      toast({ title: "Live hunt saved", description: "It runs on every new upload in its scope." });
    },
    onError: failed("Couldn't save the hunt"),
  });
  const toggle = useMutation({
    mutationFn: async ({ id, enabled }: { id: string; enabled: boolean }) =>
      apiRequest("PATCH", `${LIVE_HUNTS}/${id}`, { enabled }),
    onSuccess: (_r, v) => refresh(v.id),
    onError: failed("Couldn't change the hunt"),
  });
  const replaceRule = useMutation({
    mutationFn: async (id: string) => apiRequest("PATCH", `${LIVE_HUNTS}/${id}`, { rule, enabled: true }),
    onSuccess: (_r, id) => {
      refresh(id);
      toast({ title: "Rule updated", description: "The hunt now uses the rule in the editor." });
    },
    onError: failed("Couldn't update the rule"),
  });
  const remove = useMutation({
    mutationFn: async (id: string) => apiRequest("DELETE", `${LIVE_HUNTS}/${id}`),
    onSuccess: () => refresh(),
    onError: failed("Couldn't delete the hunt"),
  });
  const loadRule = async (id: string) => {
    if (!onEditRule) return;
    const res = await apiRequest("GET", `${LIVE_HUNTS}/${id}`);
    const detail: LiveHuntDetail = await res.json();
    onEditRule(detail.rule);
  };

  const unseen = hunts.reduce((n, h) => n + h.unseen, 0);

  return (
    <div className="space-y-3 border-t border-border/60 pt-4" data-testid="live-hunts-panel">
      <div>
        <div className="flex items-center gap-2 text-sm font-semibold">
          <Radar className="h-4 w-4 text-primary" /> Live hunts
          {unseen > 0 && (
            <Badge className="gap-1" data-testid="live-hunts-unseen">
              <BellRing className="h-3 w-3" /> {unseen} new
            </Badge>
          )}
        </div>
        <p className="text-xs text-muted-foreground">
          Save this rule to run with real YARA on every new file you upload, or that&apos;s saved to a team, and see
          each match here. Up to 10 hunts on at a time.
        </p>
      </div>

      <div className="flex flex-col gap-2 sm:flex-row">
        <Input
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="Name, e.g. Emotet loaders"
          maxLength={100}
          className="h-9"
          aria-label="Hunt name"
          data-testid="input-live-hunt-name"
        />
        <Select value={scope} onValueChange={setScope}>
          <SelectTrigger className="h-9 sm:w-[170px]" aria-label="Uploads to watch">
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
          className="h-9 shrink-0"
          onClick={() => create.mutate()}
          disabled={!rule.trim() || !name.trim() || create.isPending}
          data-testid="button-save-live-hunt"
        >
          <Radar className="mr-1 h-3.5 w-3.5" /> Save as live hunt
        </Button>
      </div>

      {hunts.length > 0 && (
        <ul className="space-y-2" data-testid="live-hunt-list">
          {hunts.map((h) => (
            <li key={h.id} className="rounded border border-border/60 p-2">
              <div className="flex flex-wrap items-center justify-between gap-2 text-xs">
                <button
                  type="button"
                  className="flex min-w-0 items-center gap-2 text-left"
                  onClick={() => setOpen(open === h.id ? null : h.id)}
                  aria-expanded={open === h.id}
                >
                  <span className="truncate font-medium">{h.name}</span>
                  {h.unseen > 0 && <Badge className="shrink-0">{h.unseen} new</Badge>}
                  {h.lastError && (
                    <Badge variant="destructive" className="shrink-0">
                      rule error
                    </Badge>
                  )}
                  <span className="truncate font-mono text-muted-foreground">{h.ruleNames.join(", ")}</span>
                  <span className="shrink-0 text-muted-foreground">{h.teamName ? `· ${h.teamName}` : "· my uploads"}</span>
                </button>
                <span className="flex items-center gap-2 text-muted-foreground">
                  {matchSummary(h)}
                  {onEditRule && (
                    <Button
                      size="sm"
                      variant="ghost"
                      className="h-6 px-1.5"
                      onClick={() => void loadRule(h.id)}
                      aria-label={`Open ${h.name}'s rule in the editor`}
                      title="Open its rule in the editor"
                    >
                      <Pencil className="h-3.5 w-3.5" />
                    </Button>
                  )}
                  <Switch
                    checked={h.enabled}
                    onCheckedChange={(enabled) => toggle.mutate({ id: h.id, enabled })}
                    aria-label={h.enabled ? `Turn ${h.name} off` : `Turn ${h.name} on`}
                  />
                  <Button
                    size="sm"
                    variant="ghost"
                    className="h-6 px-1.5"
                    onClick={() => {
                      if (window.confirm(`Delete "${h.name}" and its matches?`)) remove.mutate(h.id);
                    }}
                    aria-label={`Delete ${h.name}`}
                  >
                    <Trash2 className="h-3.5 w-3.5" />
                  </Button>
                </span>
              </div>
              {open === h.id && (
                <div className="mt-2 space-y-2">
                  <HuntMatches id={h.id} />
                  <Button
                    size="sm"
                    variant="outline"
                    className="h-7 text-xs"
                    onClick={() => replaceRule.mutate(h.id)}
                    disabled={!rule.trim() || replaceRule.isPending}
                  >
                    Replace its rule with the one in the editor
                  </Button>
                </div>
              )}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
