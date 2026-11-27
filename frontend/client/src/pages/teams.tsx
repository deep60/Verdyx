import { useEffect, useState, type ReactNode } from "react";
import { Link } from "wouter";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Navigation } from "@/components/navigation";
import { SEO } from "@/components/seo";
import { ApiKeysManager } from "@/components/api-keys-manager";
import { AuditLog } from "@/components/audit-log";
import { ThreatFeedCard } from "@/components/threat-feed-card";
import { TeamSso } from "@/components/team-sso";
import { TeamStorage } from "@/components/team-storage";
import { TeamPlan } from "@/components/team-plan";
import { RetentionSelect, retentionLabel } from "@/components/data-controls";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
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
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog";
import { apiRequest } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import { formatWhen } from "@/components/api-keys-manager";
import type { ApiSubmission } from "@/lib/api-types";
import {
  ROLE_HELP,
  assignableRoles,
  canEditMember,
  canManage,
  inviteLink,
  serverMessage,
  type MyInvitation,
  type TeamDetail,
  type TeamRole,
  type TeamSummary,
} from "@/lib/teams";
import { Building2, Copy, Database, FileSearch, History, KeyRound, LogOut, Mail, Plus, Trash2, Users } from "lucide-react";
import { BOUNTIES_ENABLED } from "@/lib/features";

const TEAMS = "/api/orgs";
const MY_INVITES = "/api/invitations";

function readParam(name: string): string | null {
  try {
    return new URLSearchParams(window.location.search).get(name);
  } catch {
    return null;
  }
}

function dropParam(name: string) {
  const url = new URL(window.location.href);
  url.searchParams.delete(name);
  window.history.replaceState(null, "", url.pathname + url.search + url.hash);
}

function ConfirmButton({
  label,
  title,
  description,
  confirm,
  onConfirm,
  disabled,
  icon,
}: {
  label: string;
  title: string;
  description: ReactNode;
  confirm: string;
  onConfirm: () => void;
  disabled?: boolean;
  icon?: ReactNode;
}) {
  return (
    <AlertDialog>
      <AlertDialogTrigger asChild>
        <Button size="sm" variant="outline" disabled={disabled}>
          {icon}
          {label}
        </Button>
      </AlertDialogTrigger>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>{title}</AlertDialogTitle>
          <AlertDialogDescription>{description}</AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogCancel>Cancel</AlertDialogCancel>
          <AlertDialogAction onClick={onConfirm}>{confirm}</AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}

function RoleSelect({
  value,
  options,
  onChange,
  disabled,
  label,
}: {
  value: TeamRole;
  options: TeamRole[];
  onChange: (r: TeamRole) => void;
  disabled?: boolean;
  label: string;
}) {
  return (
    <Select value={value} onValueChange={(v) => onChange(v as TeamRole)} disabled={disabled}>
      <SelectTrigger className="h-8 w-[120px]" aria-label={label}>
        <SelectValue />
      </SelectTrigger>
      <SelectContent>
        {options.map((r) => (
          <SelectItem key={r} value={r}>
            {r}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  );
}

/** An invitation link someone opened: offer to join. */
function InviteBanner({ code, onJoined }: { code: string; onJoined: (teamId: string) => void }) {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const accept = useMutation({
    mutationFn: async () => (await apiRequest("POST", `${MY_INVITES}/accept`, { code })).json(),
    onSuccess: (data: { teamId: string; teamName: string; role: string }) => {
      toast({ title: `You joined ${data.teamName}`, description: `Your role: ${data.role}.` });
      queryClient.invalidateQueries({ queryKey: [TEAMS] });
      queryClient.invalidateQueries({ queryKey: [MY_INVITES] });
      onJoined(data.teamId);
    },
    onError: (err) =>
      toast({
        title: "Couldn't join",
        description: serverMessage(err, "The invitation may have expired. Ask for a new one."),
        variant: "destructive",
      }),
  });
  return (
    <Card className="border-primary/40 bg-primary/10" data-testid="invite-banner">
      <CardContent className="flex flex-col gap-3 p-4 sm:flex-row sm:items-center sm:justify-between">
        <div className="text-sm">
          <div className="font-medium">You&apos;ve been invited to a team.</div>
          <div className="text-muted-foreground">
            It only works for the email address it was sent to, so make sure you&apos;re signed in with that one.
          </div>
        </div>
        <Button onClick={() => accept.mutate()} disabled={accept.isPending}>
          {accept.isPending ? "Joining…" : "Join the team"}
        </Button>
      </CardContent>
    </Card>
  );
}

function PendingInvitations({ onJoined }: { onJoined: (teamId: string) => void }) {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const { data: invites = [] } = useQuery<MyInvitation[]>({ queryKey: [MY_INVITES] });
  const refresh = () => {
    queryClient.invalidateQueries({ queryKey: [MY_INVITES] });
    queryClient.invalidateQueries({ queryKey: [TEAMS] });
  };
  const accept = useMutation({
    mutationFn: async (id: string) => (await apiRequest("POST", `${MY_INVITES}/accept`, { id })).json(),
    onSuccess: (data: { teamId: string; teamName: string }) => {
      toast({ title: `You joined ${data.teamName}` });
      refresh();
      onJoined(data.teamId);
    },
    onError: (err) =>
      toast({
        title: "Couldn't join",
        description: serverMessage(err, "Please try again."),
        variant: "destructive",
      }),
  });
  const decline = useMutation({
    mutationFn: async (id: string) => apiRequest("DELETE", `${MY_INVITES}/${id}`),
    onSuccess: refresh,
  });
  if (invites.length === 0) return null;
  return (
    <Card className="glassmorphism" data-testid="pending-invitations">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <Mail className="h-4 w-4 text-primary" /> Invitations for you
        </CardTitle>
      </CardHeader>
      <CardContent>
        <ul className="divide-y divide-border/60">
          {invites.map((i) => (
            <li key={i.id} className="flex flex-col gap-2 py-3 sm:flex-row sm:items-center sm:justify-between">
              <div className="text-sm">
                <span className="font-medium">{i.teamName}</span> as <Badge variant="secondary">{i.role}</Badge>
                <div className="text-xs text-muted-foreground">
                  {i.invitedBy ? `From ${i.invitedBy} · ` : ""}expires {formatWhen(i.expiresAt)}
                </div>
              </div>
              <div className="flex gap-2">
                <Button size="sm" onClick={() => accept.mutate(i.id)} disabled={accept.isPending}>
                  Join
                </Button>
                <Button size="sm" variant="outline" onClick={() => decline.mutate(i.id)} disabled={decline.isPending}>
                  Decline
                </Button>
              </div>
            </li>
          ))}
        </ul>
      </CardContent>
    </Card>
  );
}

function CreateTeam({ onCreated }: { onCreated: (id: string) => void }) {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [name, setName] = useState("");
  const create = useMutation({
    mutationFn: async () => (await apiRequest("POST", TEAMS, { name })).json(),
    onSuccess: (team: TeamSummary) => {
      setName("");
      queryClient.invalidateQueries({ queryKey: [TEAMS] });
      onCreated(team.id);
    },
    onError: (err) =>
      toast({
        title: "Couldn't create the team",
        description: serverMessage(err, "Please try again."),
        variant: "destructive",
      }),
  });
  return (
    <form
      className="flex flex-col gap-2"
      onSubmit={(e) => {
        e.preventDefault();
        if (name.trim()) create.mutate();
      }}
    >
      <Input
        placeholder="New team name"
        aria-label="New team name"
        maxLength={100}
        value={name}
        onChange={(e) => setName(e.target.value)}
      />
      <Button type="submit" disabled={!name.trim() || create.isPending}>
        <Plus className="mr-1 h-4 w-4" /> Create
      </Button>
    </form>
  );
}

function Members({ team }: { team: TeamDetail }) {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const refresh = () => {
    queryClient.invalidateQueries({ queryKey: [`${TEAMS}/${team.id}`] });
    queryClient.invalidateQueries({ queryKey: [TEAMS] });
  };
  const fail = (title: string) => (err: unknown) =>
    toast({ title, description: serverMessage(err, "Please try again."), variant: "destructive" });
  const setRole = useMutation({
    mutationFn: async ({ userId, role }: { userId: string; role: TeamRole }) =>
      apiRequest("PATCH", `${TEAMS}/${team.id}/members/${userId}`, { role }),
    onSuccess: refresh,
    onError: fail("Couldn't change the role"),
  });
  const remove = useMutation({
    mutationFn: async (userId: string) => apiRequest("DELETE", `${TEAMS}/${team.id}/members/${userId}`),
    onSuccess: refresh,
    onError: fail("Couldn't remove them"),
  });
  const options = assignableRoles(team.role);
  return (
    <ul className="divide-y divide-border/60" data-testid="team-members">
      {team.members.map((m) => {
        const editable = !m.isYou && canEditMember(team.role, m.role);
        return (
          <li key={m.userId} className="flex flex-col gap-2 py-3 sm:flex-row sm:items-center sm:justify-between">
            <div className="min-w-0 text-sm">
              <div className="font-medium">
                {m.username ?? "Unknown user"}
                {m.isYou && <span className="text-muted-foreground"> (you)</span>}
              </div>
              <div className="truncate text-xs text-muted-foreground">
                {m.email ?? ""} · joined {formatWhen(m.joinedAt)}
              </div>
            </div>
            <div className="flex items-center gap-2">
              {editable ? (
                <RoleSelect
                  value={m.role}
                  options={options.includes(m.role) ? options : [m.role, ...options]}
                  onChange={(role) => setRole.mutate({ userId: m.userId, role })}
                  disabled={setRole.isPending}
                  label={`Role of ${m.username ?? "member"}`}
                />
              ) : (
                <Badge variant="secondary">{m.role}</Badge>
              )}
              {editable && (
                <ConfirmButton
                  label="Remove"
                  icon={<Trash2 className="mr-1 h-3.5 w-3.5" />}
                  title={`Remove ${m.username ?? "this member"}?`}
                  description="They lose access to the team's scans at once. Team keys they made stop working."
                  confirm="Remove"
                  onConfirm={() => remove.mutate(m.userId)}
                />
              )}
            </div>
          </li>
        );
      })}
    </ul>
  );
}

function Invite({ team }: { team: TeamDetail }) {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [email, setEmail] = useState("");
  const [role, setRole] = useState<TeamRole>("member");
  const [link, setLink] = useState<{ email: string; url: string } | null>(null);
  const refresh = () => queryClient.invalidateQueries({ queryKey: [`${TEAMS}/${team.id}`] });
  const invite = useMutation({
    mutationFn: async () => (await apiRequest("POST", `${TEAMS}/${team.id}/invitations`, { email, role })).json(),
    onSuccess: (data: { email: string; code: string }) => {
      setLink({ email: data.email, url: inviteLink(data.code) });
      setEmail("");
      refresh();
    },
    onError: (err) =>
      toast({ title: "Couldn't invite", description: serverMessage(err, "Please try again."), variant: "destructive" }),
  });
  const revoke = useMutation({
    mutationFn: async (id: string) => apiRequest("DELETE", `${TEAMS}/${team.id}/invitations/${id}`),
    onSuccess: refresh,
  });
  const copy = async (value: string) => {
    try {
      await navigator.clipboard.writeText(value);
      toast({ title: "Link copied" });
    } catch {
      toast({ title: "Copy failed", description: "Select the link and copy it.", variant: "destructive" });
    }
  };
  return (
    <div className="space-y-4">
      <form
        className="grid gap-2 sm:grid-cols-[1fr_auto_auto]"
        onSubmit={(e) => {
          e.preventDefault();
          if (email.trim()) invite.mutate();
        }}
      >
        <Input
          type="email"
          placeholder="colleague@company.com"
          aria-label="Email to invite"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
        />
        <RoleSelect
          value={role}
          options={assignableRoles(team.role).filter((r) => r !== "owner")}
          onChange={setRole}
          label="Role for the invitation"
        />
        <Button type="submit" disabled={!email.trim() || invite.isPending}>
          Invite
        </Button>
      </form>
      <p className="text-xs text-muted-foreground">{ROLE_HELP[role]}.</p>
      {link && (
        <div className="space-y-2 rounded-lg border border-primary/40 bg-primary/10 p-3" data-testid="invite-link">
          <div className="text-sm">
            Send this link to <span className="font-medium">{link.email}</span>. It works for 7 days, only when
            they&apos;re signed in with that address, and it isn&apos;t shown again.
          </div>
          <div className="flex items-center gap-2">
            <code className="flex-1 break-all rounded bg-background/60 px-2 py-1.5 font-mono text-xs">{link.url}</code>
            <Button size="sm" variant="outline" onClick={() => copy(link.url)}>
              <Copy className="mr-1 h-3.5 w-3.5" /> Copy
            </Button>
          </div>
        </div>
      )}
      {team.invitations.length > 0 && (
        <ul className="divide-y divide-border/60">
          {team.invitations.map((i) => (
            <li key={i.id} className="flex items-center justify-between gap-2 py-2 text-sm">
              <span className="min-w-0 truncate">
                {i.email} <Badge variant="secondary">{i.role}</Badge>{" "}
                <span className="text-xs text-muted-foreground">
                  {i.expired ? "expired" : `expires ${formatWhen(i.expiresAt)}`}
                </span>
              </span>
              <Button size="sm" variant="ghost" onClick={() => revoke.mutate(i.id)} disabled={revoke.isPending}>
                Withdraw
              </Button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function TeamScans({ team }: { team: TeamDetail }) {
  const { data: scans = [], isLoading } = useQuery<ApiSubmission[]>({
    queryKey: [`/api/submissions?organization=${team.id}&limit=50`],
  });
  const names = new Map(team.members.map((m) => [m.userId, m.username ?? "former member"]));
  if (isLoading) return <p className="text-sm text-muted-foreground">Loading…</p>;
  if (scans.length === 0)
    return (
      <p className="text-sm text-muted-foreground">
        No scans yet. When you upload a file or URL, choose <span className="font-medium">{team.name}</span> under
        &ldquo;Save to&rdquo;.
      </p>
    );
  return (
    <ul className="divide-y divide-border/60" data-testid="team-scans">
      {scans.map((s) => (
        <li key={s.id} className="flex items-center justify-between gap-2 py-2 text-sm">
          <Link href={`/analysis/${s.id}`} className="min-w-0 truncate font-medium hover:underline">
            {s.originalFilename ?? s.filename ?? s.url ?? s.id}
          </Link>
          <span className="shrink-0 text-xs text-muted-foreground">
            {s.isMalicious === true ? "malicious · " : ""}
            {s.analysisStatus ?? s.status} · {names.get(s.submitterId ?? "") ?? "former member"} ·{" "}
            {formatWhen(s.createdAt)}
          </span>
        </li>
      ))}
    </ul>
  );
}

function TeamSettings({ team, onGone }: { team: TeamDetail; onGone: () => void }) {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [name, setName] = useState(team.name);
  useEffect(() => setName(team.name), [team.name]);
  const me = team.members.find((m) => m.isYou);
  const refreshAll = () => {
    queryClient.invalidateQueries({ queryKey: [TEAMS] });
    queryClient.invalidateQueries({ queryKey: [`${TEAMS}/${team.id}`] });
  };
  const fail = (title: string) => (err: unknown) =>
    toast({ title, description: serverMessage(err, "Please try again."), variant: "destructive" });
  const rename = useMutation({
    mutationFn: async () => apiRequest("PATCH", `${TEAMS}/${team.id}`, { name }),
    onSuccess: () => {
      toast({ title: "Team renamed" });
      refreshAll();
    },
    onError: fail("Couldn't rename"),
  });
  const leave = useMutation({
    mutationFn: async () => apiRequest("DELETE", `${TEAMS}/${team.id}/members/${me?.userId}`),
    onSuccess: () => {
      toast({ title: `You left ${team.name}` });
      onGone();
      refreshAll();
    },
    onError: fail("Couldn't leave"),
  });
  const remove = useMutation({
    mutationFn: async () => apiRequest("DELETE", `${TEAMS}/${team.id}`),
    onSuccess: () => {
      toast({ title: `${team.name} deleted` });
      onGone();
      refreshAll();
    },
    onError: fail("Couldn't delete the team"),
  });
  const retain = useMutation({
    mutationFn: async (days: number | null) =>
      apiRequest("PUT", `${TEAMS}/${team.id}/retention`, { scanRetentionDays: days }),
    onSuccess: (_r, days) => {
      toast({ title: "Saved", description: `Team scans: ${retentionLabel(days).toLowerCase()}.` });
      refreshAll();
    },
    onError: fail("Couldn't save"),
  });
  return (
    <div className="space-y-6">
      <div className="space-y-2">
        <h3 className="text-sm font-medium">Keep the team&apos;s scans</h3>
        {canManage(team.role) ? (
          <RetentionSelect
            value={team.scanRetentionDays}
            onChange={(d) => retain.mutate(d)}
            disabled={retain.isPending}
            label="How long to keep the team's scans"
          />
        ) : (
          <p className="text-sm">{retentionLabel(team.scanRetentionDays)}</p>
        )}
        <p className="text-xs text-muted-foreground">
          Older scans and their results are deleted every day.{BOUNTIES_ENABLED && " Scans that carry a bounty are kept."}
        </p>
      </div>
      {canManage(team.role) && (
        <form
          className="flex gap-2"
          onSubmit={(e) => {
            e.preventDefault();
            if (name.trim() && name.trim() !== team.name) rename.mutate();
          }}
        >
          <Input aria-label="Team name" maxLength={100} value={name} onChange={(e) => setName(e.target.value)} />
          <Button type="submit" variant="outline" disabled={rename.isPending || !name.trim() || name.trim() === team.name}>
            Rename
          </Button>
        </form>
      )}
      <div className="flex flex-wrap gap-2">
        {me && (
          <ConfirmButton
            label="Leave team"
            icon={<LogOut className="mr-1 h-3.5 w-3.5" />}
            title={`Leave ${team.name}?`}
            description="You lose access to its scans. Scans you saved to it stay with the team. A team's last owner can't leave: make someone else owner, or delete the team."
            confirm="Leave"
            onConfirm={() => leave.mutate()}
          />
        )}
        {team.role === "owner" && (
          <ConfirmButton
            label="Delete team"
            icon={<Trash2 className="mr-1 h-3.5 w-3.5" />}
            title={`Delete ${team.name}?`}
            description="Members lose access, invitations and team keys are deleted, and each scan goes back to the person who uploaded it. This can't be undone."
            confirm="Delete team"
            onConfirm={() => remove.mutate()}
          />
        )}
      </div>
    </div>
  );
}

export function TeamPanel({ teamId, onGone }: { teamId: string; onGone: () => void }) {
  const { data: team, isLoading, isError } = useQuery<TeamDetail>({ queryKey: [`${TEAMS}/${teamId}`] });
  if (isLoading) return <p className="text-sm text-muted-foreground">Loading…</p>;
  if (isError || !team) return <p className="text-sm text-muted-foreground">This team isn&apos;t available.</p>;
  const manager = canManage(team.role);
  return (
    <Card className="glassmorphism border-primary/20" data-testid="team-panel">
      <CardHeader>
        <CardTitle className="flex flex-wrap items-center gap-2">
          {team.name} <Badge variant="outline">{team.role}</Badge>
        </CardTitle>
        <CardDescription>
          {team.members.length} {team.members.length === 1 ? "member" : "members"} · {ROLE_HELP[team.role]}.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <Tabs defaultValue="scans">
          <TabsList className="flex-wrap">
            <TabsTrigger value="scans">
              <FileSearch className="mr-1 h-3.5 w-3.5" /> Scans
            </TabsTrigger>
            <TabsTrigger value="members">
              <Users className="mr-1 h-3.5 w-3.5" /> Members
            </TabsTrigger>
            {manager && (
              <TabsTrigger value="keys">
                <KeyRound className="mr-1 h-3.5 w-3.5" /> API keys
              </TabsTrigger>
            )}
            {manager && (
              <TabsTrigger value="sso">
                <Building2 className="mr-1 h-3.5 w-3.5" /> Sign-in
              </TabsTrigger>
            )}
            {manager && (
              <TabsTrigger value="storage">
                <Database className="mr-1 h-3.5 w-3.5" /> Storage
              </TabsTrigger>
            )}
            {manager && (
              <TabsTrigger value="audit">
                <History className="mr-1 h-3.5 w-3.5" /> Audit log
              </TabsTrigger>
            )}
            <TabsTrigger value="settings">Settings</TabsTrigger>
          </TabsList>
          <TabsContent value="scans" className="pt-4">
            <TeamScans team={team} />
          </TabsContent>
          <TabsContent value="members" className="space-y-6 pt-4">
            <Members team={team} />
            {manager && (
              <div className="space-y-2">
                <h3 className="text-sm font-medium">Invite someone</h3>
                <Invite team={team} />
              </div>
            )}
          </TabsContent>
          {manager && (
            <TabsContent value="keys" className="pt-4">
              <ApiKeysManager
                endpoints={{
                  list: `${TEAMS}/${team.id}/api-keys`,
                  create: `${TEAMS}/${team.id}/api-keys`,
                  revoke: (id) => `${TEAMS}/${team.id}/api-keys/${id}`,
                }}
                listTitle="Team keys"
                limitNote="The team's plan sets how many keys can be active (see Settings)."
                intro={
                  <>
                    Scans made with a team key are saved to {team.name}, and it can only read the team&apos;s scans
                    and engine status. It stops working if the admin who made it leaves or stops being an admin.
                  </>
                }
              />
              <div className="mt-6">
                <ThreatFeedCard team={{ id: team.id, name: team.name }} />
              </div>
            </TabsContent>
          )}
          {manager && (
            <TabsContent value="sso" className="pt-4">
              <TeamSso teamId={team.id} teamName={team.name} />
            </TabsContent>
          )}
          {manager && (
            <TabsContent value="storage" className="pt-4">
              <TeamStorage teamId={team.id} teamName={team.name} />
            </TabsContent>
          )}
          {manager && (
            <TabsContent value="audit" className="pt-4">
              <AuditLog endpoint={`${TEAMS}/${team.id}/audit`} viewerId={team.members.find((m) => m.isYou)?.userId} />
            </TabsContent>
          )}
          <TabsContent value="settings" className="space-y-8 pt-4">
            <TeamPlan teamId={team.id} />
            <TeamSettings team={team} onGone={onGone} />
          </TabsContent>
        </Tabs>
      </CardContent>
    </Card>
  );
}

export default function Teams() {
  const [invite, setInvite] = useState<string | null>(() => readParam("invite"));
  const [selected, setSelected] = useState<string | null>(() => readParam("team"));
  const { data: teams = [], isLoading } = useQuery<TeamSummary[]>({ queryKey: [TEAMS] });

  // Fall back to the first team when nothing (or a team you've left) is selected.
  const current = teams.find((t) => t.id === selected)?.id ?? teams[0]?.id ?? null;

  const joined = (teamId: string) => {
    dropParam("invite");
    setInvite(null);
    setSelected(teamId);
  };

  return (
    <div className="min-h-screen bg-background text-foreground">
      <SEO title="Teams — Verdyx" description="Share scans and API keys with your team." />
      <Navigation />
      <div id="main-content" tabIndex={-1} className="relative z-10 mx-auto max-w-6xl space-y-6 px-4 py-12 sm:px-6 lg:px-8">
        <div>
          <h1 className="text-3xl font-bold">Teams</h1>
          <p className="text-muted-foreground">
            Scans saved to a team are visible to everyone in it. Team API keys scan on the team&apos;s behalf.
          </p>
        </div>

        {invite && <InviteBanner code={invite} onJoined={joined} />}
        <PendingInvitations onJoined={joined} />

        <div className="grid gap-6 lg:grid-cols-[280px_1fr]">
          <Card className="glassmorphism h-fit">
            <CardHeader>
              <CardTitle className="text-base">Your teams</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              {isLoading ? (
                <p className="text-sm text-muted-foreground">Loading…</p>
              ) : teams.length === 0 ? (
                <p className="text-sm text-muted-foreground">You&apos;re not in a team yet.</p>
              ) : (
                <ul className="space-y-1" data-testid="team-list">
                  {teams.map((t) => (
                    <li key={t.id}>
                      <button
                        type="button"
                        onClick={() => setSelected(t.id)}
                        className={`flex w-full items-center justify-between rounded px-2 py-1.5 text-left text-sm hover:bg-muted ${
                          t.id === current ? "bg-muted font-medium" : ""
                        }`}
                        aria-current={t.id === current ? "true" : undefined}
                      >
                        <span className="truncate">{t.name}</span>
                        <span className="text-xs text-muted-foreground">{t.role}</span>
                      </button>
                    </li>
                  ))}
                </ul>
              )}
              <CreateTeam onCreated={setSelected} />
            </CardContent>
          </Card>

          <div>
            {current ? (
              <TeamPanel key={current} teamId={current} onGone={() => setSelected(null)} />
            ) : (
              !isLoading && (
                <Card className="glassmorphism">
                  <CardContent className="space-y-2 p-6 text-sm text-muted-foreground">
                    <Label className="text-base text-foreground">Start a team</Label>
                    <p>
                      Create a team, invite colleagues by email, and save scans to it so everyone sees the results.
                      You can also create API keys that scan for the team.
                    </p>
                  </CardContent>
                </Card>
              )
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
