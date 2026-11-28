import { useEffect, useState, type FormEvent } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Navigation } from "@/components/navigation";
import { SEO } from "@/components/seo";
import { Meter } from "@/components/team-plan";
import { formatWhen } from "@/components/api-keys-manager";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { useAuth } from "@/contexts/auth-context";
import { useToast } from "@/hooks/use-toast";
import { apiRequest } from "@/lib/queryClient";
import { serverMessage } from "@/lib/teams";
import { PLANS, formatLimit, planName, type PlanId } from "@/lib/plans";
import {
  LIMIT_FIELDS,
  PLAN_FILTERS,
  describeChange,
  describeOverrides,
  effectiveLimits,
  formFromTeam,
  isUnchanged,
  overridesFromForm,
  teamsQuery,
  type AdminTeam,
  type AdminTeamPlan,
  type MonthlyMode,
  type Overrides,
  type PlanFilter,
  type PlanForm,
} from "@/lib/admin";

const number = (n: number) => n.toLocaleString("en-US");

function readTeamParam(): string | null {
  try {
    return new URLSearchParams(window.location.search).get("team");
  } catch {
    return null;
  }
}

function writeTeamParam(id: string | null) {
  try {
    const url = new URL(window.location.href);
    if (id) url.searchParams.set("team", id);
    else url.searchParams.delete("team");
    window.history.replaceState(null, "", url.toString());
  } catch {
    // Not in a browser; nothing to remember.
  }
}

/** Teams, searchable by name or id and filterable by plan. */
export function TeamTable({
  teams,
  selected,
  onSelect,
}: {
  teams: AdminTeam[];
  selected: string | null;
  onSelect: (id: string) => void;
}) {
  if (teams.length === 0) return <p className="text-sm text-muted-foreground">No teams match.</p>;
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm" data-testid="admin-team-table">
        <thead>
          <tr className="border-b text-left text-muted-foreground">
            <th className="py-2 pr-3 font-medium">Team</th>
            <th className="py-2 pr-3 font-medium">Plan</th>
            <th className="py-2 pr-3 text-right font-medium">Members</th>
            <th className="py-2 pr-3 text-right font-medium">Scans this month</th>
            <th className="py-2 font-medium">Created</th>
          </tr>
        </thead>
        <tbody>
          {teams.map((t) => (
            <tr
              key={t.id}
              className={`border-b last:border-0 ${t.id === selected ? "bg-primary/10" : "hover:bg-muted/50"}`}
              aria-selected={t.id === selected}
            >
              <td className="py-2 pr-3">
                <button
                  type="button"
                  className="max-w-[16rem] truncate text-left font-medium text-primary hover:underline"
                  onClick={() => onSelect(t.id)}
                >
                  {t.name}
                </button>
              </td>
              <td className="py-2 pr-3">
                <span className="flex flex-wrap gap-1">
                  <Badge variant={t.plan === "free" ? "secondary" : "default"}>{planName(t.plan)}</Badge>
                  {t.custom && <Badge variant="outline">Custom</Badge>}
                </span>
              </td>
              <td className="py-2 pr-3 text-right font-mono">{number(t.members)}</td>
              <td className="py-2 pr-3 text-right font-mono">{number(t.scansThisMonth)}</td>
              <td className="py-2 text-muted-foreground">{formatWhen(t.createdAt)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/** Sets a team's plan and custom limits, after a confirmation. */
export function PlanEditor({ teamId, data }: { teamId: string; data: AdminTeamPlan }) {
  const { toast } = useToast();
  const qc = useQueryClient();
  const [form, setForm] = useState<PlanForm>(() => formFromTeam(data.plan, data.overrides));
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState<Overrides | null>(null);

  // A different team, or the same team after a save: start from what's stored.
  useEffect(() => {
    setForm(formFromTeam(data.plan, data.overrides));
    setError(null);
  }, [teamId, data.plan, data.overrides]);

  const set = (patch: Partial<PlanForm>) => setForm((f) => ({ ...f, ...patch }));
  const planDefaults = (PLANS.find((p) => p.id === form.plan) ?? PLANS[0]).limits;

  const save = useMutation({
    mutationFn: (overrides: Overrides) =>
      apiRequest("PUT", `/api/admin/teams/${teamId}/plan`, { plan: form.plan, overrides }),
    onSuccess: () => {
      toast({ title: "Plan saved", description: `The team is on ${planName(form.plan)}.` });
      // The team's plan and every team list.
      qc.invalidateQueries({
        predicate: (q) => typeof q.queryKey[0] === "string" && q.queryKey[0].startsWith("/api/admin/teams"),
      });
      setPending(null);
    },
    onError: (err) => {
      toast({ title: "The plan wasn't saved", description: serverMessage(err, "Please try again."), variant: "destructive" });
      setPending(null);
    },
  });

  const submit = (e: FormEvent) => {
    e.preventDefault();
    const result = overridesFromForm(form);
    if ("error" in result) {
      setError(result.error);
      return;
    }
    setError(null);
    if (isUnchanged(data.plan, data.overrides, form.plan, result.overrides)) {
      setError("Nothing has changed.");
      return;
    }
    setPending(result.overrides);
  };

  const after = pending ? effectiveLimits(form.plan, pending) : null;

  return (
    <form onSubmit={submit} className="space-y-4" data-testid="plan-editor" noValidate>
      <div className="grid gap-4 sm:grid-cols-2">
        <div className="space-y-1.5">
          <Label htmlFor="admin-plan">Plan</Label>
          <Select value={form.plan} onValueChange={(v) => set({ plan: v as PlanId })}>
            <SelectTrigger id="admin-plan">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {PLANS.map((p) => (
                <SelectItem key={p.id} value={p.id}>
                  {p.name}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <div className="space-y-1.5">
          <Label htmlFor="admin-monthly">Team scans a month</Label>
          <div className="flex gap-2">
            <Select value={form.monthly} onValueChange={(v) => set({ monthly: v as MonthlyMode })}>
              <SelectTrigger id="admin-monthly" className="min-w-0 flex-1">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="plan">Plan&apos;s ({formatLimit(planDefaults.teamScansPerMonth)})</SelectItem>
                <SelectItem value="limit">Set a limit</SelectItem>
                <SelectItem value="unlimited">No limit</SelectItem>
              </SelectContent>
            </Select>
            {form.monthly === "limit" && (
              <Input
                aria-label="Team scans a month"
                inputMode="numeric"
                className="w-36"
                value={form.teamScansPerMonth}
                onChange={(e) => set({ teamScansPerMonth: e.target.value })}
                placeholder={formatLimit(planDefaults.teamScansPerMonth ?? 50000)}
              />
            )}
          </div>
        </div>
        {LIMIT_FIELDS.map((f) => (
          <div key={f.key} className="space-y-1.5">
            <Label htmlFor={`admin-${f.key}`}>{f.label}</Label>
            <Input
              id={`admin-${f.key}`}
              inputMode="numeric"
              value={form[f.key]}
              onChange={(e) => set({ [f.key]: e.target.value })}
              placeholder={`Plan's: ${formatLimit(planDefaults[f.key])}`}
            />
          </div>
        ))}
      </div>
      <p className="text-xs text-muted-foreground">
        Leave a field empty to use the plan&apos;s limit. Nothing the team already has is removed when a limit goes
        down; it just can&apos;t add more.
      </p>
      {error && (
        <p className="text-sm text-red-500" role="alert">
          {error}
        </p>
      )}
      <div className="flex flex-wrap gap-2">
        <Button type="submit" disabled={save.isPending}>
          Save plan
        </Button>
        <Button
          type="button"
          variant="outline"
          onClick={() => setForm(formFromTeam(form.plan, {}))}
          disabled={save.isPending}
        >
          Use the plan&apos;s limits
        </Button>
      </div>

      <AlertDialog open={pending !== null} onOpenChange={(open) => !open && setPending(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Change this team&apos;s plan?</AlertDialogTitle>
            <AlertDialogDescription>
              {pending && describeChange(data.plan, data.overrides, form.plan, pending)} It applies at once, and is
              written to the team&apos;s activity log.
            </AlertDialogDescription>
          </AlertDialogHeader>
          {after && (
            <ul className="space-y-1 text-sm" data-testid="plan-preview">
              <li>
                Scans per person: {number(after.scansPerMinute)} a minute, {number(after.scansPerDay)} a day
              </li>
              <li>Team scans a month: {formatLimit(after.teamScansPerMonth)}</li>
              <li>Members and open invitations: {number(after.seats)}</li>
              <li>Team API keys: {number(after.teamKeys)}</li>
              <li>Storage connections: {number(after.storageConnections)}</li>
            </ul>
          )}
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={(e) => {
                e.preventDefault();
                if (pending) save.mutate(pending);
              }}
              disabled={save.isPending}
            >
              Change plan
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </form>
  );
}

/** One team: usage against its limits, the plan editor and recent changes. */
export function TeamAdmin({ teamId }: { teamId: string }) {
  const { data, isLoading, isError } = useQuery<AdminTeamPlan>({ queryKey: [`/api/admin/teams/${teamId}/plan`] });
  if (isLoading) return <p className="text-sm text-muted-foreground">Loading…</p>;
  if (isError || !data) return <p className="text-sm text-muted-foreground">This team isn&apos;t available.</p>;

  const { limits, usage } = data;
  return (
    <div className="space-y-6" data-testid="team-admin">
      <div className="flex flex-wrap items-center gap-2">
        <h2 className="text-lg font-semibold">{data.name}</h2>
        <Badge>{planName(data.plan)}</Badge>
        {data.custom && <Badge variant="outline">Custom limits</Badge>}
        <span className="font-mono text-xs text-muted-foreground">{teamId}</span>
      </div>
      {data.custom && (
        <p className="text-sm text-muted-foreground" data-testid="custom-limits">
          Custom: {describeOverrides(data.overrides)}
        </p>
      )}

      <section className="space-y-3" aria-label="Usage">
        <Meter label="Scans this month" used={usage.scansThisMonth} limit={limits.teamScansPerMonth} testId="admin-usage-scans" />
        <Meter label="Members and open invitations" used={usage.seats} limit={limits.seats} testId="admin-usage-seats" />
        <Meter label="Active team API keys" used={usage.teamKeys} limit={limits.teamKeys} testId="admin-usage-keys" />
        <Meter
          label="Storage connections"
          used={usage.storageConnections}
          limit={limits.storageConnections}
          testId="admin-usage-storage"
        />
      </section>

      <section className="space-y-3">
        <h3 className="text-sm font-medium">Change the plan</h3>
        <PlanEditor teamId={teamId} data={data} />
      </section>

      <section className="space-y-2" aria-label="Plan history">
        <h3 className="text-sm font-medium">Plan history</h3>
        {data.history.length === 0 ? (
          <p className="text-sm text-muted-foreground">The plan hasn&apos;t been changed.</p>
        ) : (
          <ul className="space-y-1 text-sm" data-testid="plan-history">
            {data.history.map((h, i) => (
              <li key={`${h.at}-${i}`} className="flex flex-wrap justify-between gap-2">
                <span>
                  {planName(h.from ?? "free")} → {planName(h.plan ?? "free")}
                  {h.custom && h.overrides ? `, ${describeOverrides(h.overrides)}` : h.custom ? ", custom limits" : ""}
                </span>
                <span className="text-muted-foreground">{formatWhen(h.at)}</span>
              </li>
            ))}
          </ul>
        )}
      </section>
    </div>
  );
}

export default function Admin() {
  const { user } = useAuth();
  const isAdmin = user?.isAdmin === true;
  const [draft, setDraft] = useState("");
  const [q, setQ] = useState("");
  const [plan, setPlan] = useState<PlanFilter>("all");
  const [selected, setSelected] = useState<string | null>(readTeamParam);

  const { data, isLoading, isError } = useQuery<{ teams: AdminTeam[] }>({
    queryKey: [teamsQuery(q, plan)],
    enabled: isAdmin,
  });
  const teams = data?.teams ?? [];

  const select = (id: string) => {
    setSelected(id);
    writeTeamParam(id);
  };

  return (
    <div className="min-h-screen bg-background text-foreground">
      <SEO title="Admin — Verdyx" description="Plans and limits for Verdyx teams." />
      <Navigation />
      <div id="main-content" tabIndex={-1} className="relative z-10 mx-auto max-w-6xl space-y-6 px-4 py-12 sm:px-6 lg:px-8">
        <div>
          <h1 className="text-3xl font-bold">Admin</h1>
          <p className="text-muted-foreground">Find a team, see what it uses, and set its plan and limits.</p>
        </div>

        {!isAdmin ? (
          <Card className="glassmorphism" data-testid="admin-only">
            <CardContent className="p-6 text-sm text-muted-foreground">
              This page is for Verdyx administrators.
            </CardContent>
          </Card>
        ) : (
          <div className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
            <Card className="glassmorphism h-fit">
              <CardHeader>
                <CardTitle className="text-base">Teams</CardTitle>
                <CardDescription>Newest first. Search by name or paste a team&apos;s id.</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <form
                  className="flex flex-col gap-2 sm:flex-row"
                  onSubmit={(e) => {
                    e.preventDefault();
                    setQ(draft);
                  }}
                  role="search"
                >
                  <Input
                    aria-label="Search teams"
                    placeholder="Team name or id"
                    value={draft}
                    onChange={(e) => setDraft(e.target.value)}
                    className="min-w-0 flex-1"
                  />
                  <Select value={plan} onValueChange={(v) => setPlan(v as PlanFilter)}>
                    <SelectTrigger aria-label="Filter by plan" className="sm:w-40">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {PLAN_FILTERS.map((f) => (
                        <SelectItem key={f.value} value={f.value}>
                          {f.label}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                  <Button type="submit" variant="outline">
                    Search
                  </Button>
                </form>
                {isLoading ? (
                  <p className="text-sm text-muted-foreground">Loading…</p>
                ) : isError ? (
                  <p className="text-sm text-muted-foreground">The teams couldn&apos;t be loaded.</p>
                ) : (
                  <TeamTable teams={teams} selected={selected} onSelect={select} />
                )}
              </CardContent>
            </Card>

            <Card className="glassmorphism h-fit">
              <CardContent className="p-6">
                {selected ? (
                  <TeamAdmin teamId={selected} />
                ) : (
                  <p className="text-sm text-muted-foreground">Choose a team to see its plan.</p>
                )}
              </CardContent>
            </Card>
          </div>
        )}
      </div>
    </div>
  );
}
