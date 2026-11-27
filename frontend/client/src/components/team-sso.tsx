import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { CheckCircle2, Circle, Copy, Globe, KeyRound, RefreshCw, Trash2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Switch } from "@/components/ui/switch";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { apiRequest } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import { serverMessage } from "@/lib/teams";
import { setupSteps, type TeamSsoSettings } from "@/lib/sso";

const DOCS = "https://github.com/deep60/Verdyx/blob/main/docs/integrations/sso.md";

function CopyField({ label, value, testId }: { label: string; value: string; testId?: string }) {
  const { toast } = useToast();
  return (
    <div className="space-y-1">
      <Label className="text-xs text-muted-foreground">{label}</Label>
      <div className="flex gap-2">
        <Input readOnly value={value} className="font-mono text-xs" data-testid={testId} />
        <Button
          type="button"
          variant="outline"
          size="icon"
          aria-label={`Copy ${label}`}
          onClick={() => {
            navigator.clipboard?.writeText(value);
            toast({ title: "Copied" });
          }}
        >
          <Copy className="h-4 w-4" />
        </Button>
      </div>
    </div>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="space-y-3 border-t border-border pt-5 first:border-t-0 first:pt-0">
      <h3 className="text-sm font-medium">{title}</h3>
      {children}
    </section>
  );
}

/** A team's single sign-on and provisioning settings, for owners and admins. */
export function TeamSso({ teamId, teamName }: { teamId: string; teamName: string }) {
  const key = [`/api/orgs/${teamId}/sso`];
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const { data, isLoading, isError } = useQuery<TeamSsoSettings>({ queryKey: key });
  const refresh = () => queryClient.invalidateQueries({ queryKey: key });
  const fail = (title: string) => (err: unknown) =>
    toast({ title, description: serverMessage(err, "Please try again."), variant: "destructive" });

  const [domain, setDomain] = useState("");
  const [issuer, setIssuer] = useState("");
  const [clientId, setClientId] = useState("");
  const [clientSecret, setClientSecret] = useState("");
  const [newToken, setNewToken] = useState("");

  const savedIssuer = data?.sso.issuer ?? "";
  const savedClientId = data?.sso.clientId ?? "";
  useEffect(() => {
    setIssuer(savedIssuer);
    setClientId(savedClientId);
  }, [savedIssuer, savedClientId]);

  const addDomain = useMutation({
    mutationFn: () => apiRequest("POST", `/api/orgs/${teamId}/sso/domains`, { domain }),
    onSuccess: () => {
      setDomain("");
      refresh();
    },
    onError: fail("Couldn't add the domain"),
  });
  const verifyDomain = useMutation({
    mutationFn: (d: string) => apiRequest("POST", `/api/orgs/${teamId}/sso/domains/${encodeURIComponent(d)}/verify`),
    onSuccess: (_r, d) => {
      toast({ title: `${d} is verified` });
      refresh();
    },
    onError: fail("Not verified yet"),
  });
  const removeDomain = useMutation({
    mutationFn: (d: string) => apiRequest("DELETE", `/api/orgs/${teamId}/sso/domains/${encodeURIComponent(d)}`),
    onSuccess: refresh,
    onError: fail("Couldn't remove the domain"),
  });
  const save = useMutation({
    mutationFn: (next: Partial<{ enabled: boolean; required: boolean; joinRole: string }>) =>
      apiRequest("PUT", `/api/orgs/${teamId}/sso`, {
        issuer,
        clientId,
        clientSecret: clientSecret || undefined,
        enabled: next.enabled ?? data?.sso.enabled ?? false,
        required: next.required ?? data?.sso.required ?? false,
        joinRole: next.joinRole ?? data?.sso.joinRole ?? "member",
      }),
    onSuccess: () => {
      setClientSecret("");
      toast({ title: "Saved" });
      refresh();
    },
    onError: fail("Couldn't save"),
  });
  const makeToken = useMutation({
    mutationFn: async () => {
      const res = await apiRequest("POST", `/api/orgs/${teamId}/sso/scim-token`);
      return (await res.json()) as { token: string };
    },
    onSuccess: (r) => {
      setNewToken(r.token);
      refresh();
    },
    onError: fail("Couldn't make a token"),
  });
  const revokeToken = useMutation({
    mutationFn: () => apiRequest("DELETE", `/api/orgs/${teamId}/sso/scim-token`),
    onSuccess: () => {
      setNewToken("");
      refresh();
    },
    onError: fail("Couldn't revoke the token"),
  });

  if (isLoading) return <p className="text-sm text-muted-foreground">Loading…</p>;
  if (isError || !data) return <p className="text-sm text-muted-foreground">Sign-in settings aren&apos;t available.</p>;

  const steps = setupSteps(data);
  const verified = data.domains.some((d) => d.verified);
  const connected = steps[1].done;
  const editedConnection =
    issuer.trim() !== (data.sso.issuer ?? "") || clientId.trim() !== (data.sso.clientId ?? "") || clientSecret !== "";

  return (
    <div className="space-y-6" data-testid="team-sso">
      <div className="space-y-2">
        <p className="text-sm text-muted-foreground">
          Let {teamName}&apos;s people sign in with your company&apos;s identity provider (Okta, Microsoft Entra ID,
          Google Workspace, or any OpenID Connect provider), and add or remove them automatically.{" "}
          <a href={DOCS} target="_blank" rel="noreferrer" className="text-primary hover:underline">
            Setup guide
          </a>
        </p>
        <ol className="flex flex-wrap gap-x-4 gap-y-1 text-xs">
          {steps.map((s) => (
            <li key={s.label} className={s.done ? "text-emerald-500" : "text-muted-foreground"}>
              {s.done ? <CheckCircle2 className="mr-1 inline h-3.5 w-3.5" /> : <Circle className="mr-1 inline h-3.5 w-3.5" />}
              {s.label}
            </li>
          ))}
        </ol>
      </div>

      <Section title="1. Email domains">
        <p className="text-xs text-muted-foreground">
          Prove you own each domain your people sign in with. Only addresses in verified domains can sign in through
          your identity provider or be provisioned.
        </p>
        {data.domains.map((d) => (
          <div key={d.domain} className="space-y-2 rounded-md border border-border p-3" data-testid={`domain-${d.domain}`}>
            <div className="flex flex-wrap items-center justify-between gap-2">
              <span className="flex items-center gap-2 font-mono text-sm">
                <Globe className="h-4 w-4 text-muted-foreground" /> {d.domain}
                {d.verified ? <Badge>Verified</Badge> : <Badge variant="outline">Not verified</Badge>}
              </span>
              <div className="flex gap-2">
                {!d.verified && (
                  <Button size="sm" variant="outline" disabled={verifyDomain.isPending} onClick={() => verifyDomain.mutate(d.domain)}>
                    <RefreshCw className="mr-1 h-3.5 w-3.5" /> Verify
                  </Button>
                )}
                <Button
                  size="sm"
                  variant="ghost"
                  aria-label={`Remove ${d.domain}`}
                  disabled={removeDomain.isPending}
                  onClick={() => removeDomain.mutate(d.domain)}
                >
                  <Trash2 className="h-3.5 w-3.5" />
                </Button>
              </div>
            </div>
            {!d.verified && (
              <div className="space-y-2">
                <p className="text-xs text-muted-foreground">Add this TXT record at your DNS provider, then press Verify.</p>
                <CopyField label="Name" value={d.record.name} />
                <CopyField label="Value" value={d.record.value} testId={`txt-${d.domain}`} />
              </div>
            )}
          </div>
        ))}
        <form
          className="flex gap-2"
          onSubmit={(e) => {
            e.preventDefault();
            if (domain.trim()) addDomain.mutate();
          }}
        >
          <Input aria-label="Email domain" placeholder="example.com" value={domain} onChange={(e) => setDomain(e.target.value)} />
          <Button type="submit" variant="outline" disabled={addDomain.isPending || !domain.trim()}>
            Add domain
          </Button>
        </form>
      </Section>

      <Section title="2. Identity provider">
        <p className="text-xs text-muted-foreground">
          Create an OpenID Connect web app in your identity provider with this redirect URI, then enter its details.
        </p>
        <CopyField label="Redirect URI" value={data.callbackUrl} testId="sso-callback-url" />
        <form
          className="space-y-3"
          onSubmit={(e) => {
            e.preventDefault();
            save.mutate({});
          }}
        >
          <div className="space-y-1">
            <Label htmlFor="sso-issuer">Issuer URL</Label>
            <Input
              id="sso-issuer"
              placeholder="https://your-company.okta.com"
              value={issuer}
              onChange={(e) => setIssuer(e.target.value)}
            />
          </div>
          <div className="space-y-1">
            <Label htmlFor="sso-client-id">Client ID</Label>
            <Input id="sso-client-id" value={clientId} onChange={(e) => setClientId(e.target.value)} />
          </div>
          <div className="space-y-1">
            <Label htmlFor="sso-client-secret">Client secret</Label>
            <Input
              id="sso-client-secret"
              type="password"
              autoComplete="off"
              placeholder={data.sso.hasClientSecret ? "Saved. Enter a new one to replace it" : ""}
              value={clientSecret}
              onChange={(e) => setClientSecret(e.target.value)}
            />
            <p className="text-xs text-muted-foreground">Stored encrypted, and never shown again.</p>
          </div>
          <Button type="submit" variant="outline" disabled={save.isPending || !editedConnection}>
            Save
          </Button>
        </form>
      </Section>

      <Section title="3. Turn it on">
        <div className="flex items-start justify-between gap-4">
          <div>
            <label htmlFor="sso-enabled" className="text-sm">
              Single sign-on
            </label>
            <p className="text-xs text-muted-foreground">
              People sign in at {data.signInUrl.replace(/^https?:\/\//, "")} with &quot;Sign in with SSO&quot;. Someone
              signing in for the first time joins {teamName}.
            </p>
          </div>
          <Switch
            id="sso-enabled"
            data-testid="sso-enabled"
            checked={data.sso.enabled}
            disabled={save.isPending || (!data.sso.enabled && (!verified || !connected))}
            onCheckedChange={(enabled) => save.mutate({ enabled, required: enabled ? data.sso.required : false })}
          />
        </div>
        <div className="flex items-start justify-between gap-4">
          <div>
            <label htmlFor="sso-required" className="text-sm">
              Require single sign-on
            </label>
            <p className="text-xs text-muted-foreground">
              People with an address in your domains can&apos;t use a password, Google or GitHub. Owners still can, so
              a problem with your identity provider can&apos;t lock the team out.
            </p>
          </div>
          <Switch
            id="sso-required"
            data-testid="sso-required"
            checked={data.sso.required}
            disabled={save.isPending || !data.sso.enabled}
            onCheckedChange={(required) => save.mutate({ required })}
          />
        </div>
        <div className="flex flex-wrap items-center gap-3">
          <Label className="text-sm">New people join as</Label>
          <Select value={data.sso.joinRole} onValueChange={(joinRole) => save.mutate({ joinRole })}>
            <SelectTrigger className="w-36" aria-label="Role for new people">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="admin">Admin</SelectItem>
              <SelectItem value="member">Member</SelectItem>
              <SelectItem value="viewer">Viewer</SelectItem>
            </SelectContent>
          </Select>
        </div>
      </Section>

      <Section title="Automatic provisioning (SCIM)">
        <p className="text-xs text-muted-foreground">
          Your identity provider adds people to {teamName} when they&apos;re assigned the app, and removes them when
          they&apos;re unassigned or leave. Their own account and scans stay theirs.
          {data.scim.provisionedUsers > 0 && ` ${data.scim.provisionedUsers} provisioned now.`}
        </p>
        <CopyField label="SCIM base URL" value={data.scim.baseUrl} testId="scim-base-url" />
        {newToken ? (
          <div className="space-y-1 rounded-md border border-primary/40 bg-primary/10 p-3">
            <CopyField label="Provisioning token (shown once)" value={newToken} testId="scim-token" />
            <p className="text-xs text-muted-foreground">Copy it into your identity provider now. It won&apos;t be shown again.</p>
          </div>
        ) : (
          data.scim.hasToken && (
            <p className="text-sm">
              <KeyRound className="mr-1 inline h-3.5 w-3.5" /> Token <span className="font-mono">{data.scim.tokenHint}</span>
            </p>
          )
        )}
        <div className="flex flex-wrap gap-2">
          <Button variant="outline" size="sm" disabled={makeToken.isPending} onClick={() => makeToken.mutate()} data-testid="scim-new-token">
            {data.scim.hasToken ? "Replace token" : "Make a token"}
          </Button>
          {data.scim.hasToken && (
            <Button variant="ghost" size="sm" disabled={revokeToken.isPending} onClick={() => revokeToken.mutate()}>
              Revoke token
            </Button>
          )}
        </div>
      </Section>
    </div>
  );
}
