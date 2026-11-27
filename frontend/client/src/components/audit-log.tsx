import { useState } from "react";
import { planName } from "@/lib/plans";
import { Link } from "wouter";
import { useInfiniteQuery } from "@tanstack/react-query";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Download, History } from "lucide-react";

export interface AuditPerson {
  id: string;
  username?: string | null;
}

export interface AuditEvent {
  id: number;
  occurredAt: string;
  action: string;
  actor?: AuditPerson | null;
  via: string;
  apiKeyId?: string | null;
  teamId?: string | null;
  subject?: AuditPerson | null;
  targetType?: string | null;
  targetId?: string | null;
  ip?: string | null;
  userAgent?: string | null;
  details?: Record<string, unknown>;
}

interface AuditPage {
  events: AuditEvent[];
  nextBefore: number | null;
}

export const CATEGORIES: { value: string; label: string; personal: boolean }[] = [
  { value: "all", label: "Everything", personal: true },
  { value: "auth.", label: "Sign-ins", personal: true },
  { value: "account.", label: "Account", personal: true },
  { value: "api_key.", label: "API keys", personal: true },
  { value: "team.member", label: "Members", personal: false },
  { value: "team.invitation", label: "Invitations", personal: false },
  { value: "team.api_key", label: "Team keys", personal: false },
  { value: "team.", label: "Teams", personal: true },
  { value: "scan.", label: "Scans", personal: true },
];

/** Deleted accounts keep their id but are renamed `deleted_<32 hex>`. */
export const isDeleted = (username?: string | null) => !username || /^deleted_[0-9a-f]{32}$/.test(username);
const who = (p?: AuditPerson | null) => (p ? (isDeleted(p.username) ? "a deleted account" : p.username!) : "someone");
const text = (v: unknown) => (typeof v === "string" ? v : "");
const quoted = (v: unknown) => (text(v) ? `“${text(v)}”` : "");

/** One line describing an event, from the point of view of `viewerId`. */
export function describe(e: AuditEvent, viewerId?: string): string {
  const d = e.details ?? {};
  const subject = e.subject?.id && e.subject.id === viewerId ? "you" : who(e.subject);
  switch (e.action) {
    case "auth.register":
      return "Created the account";
    case "auth.login": {
      const method = text(d.method);
      if (method === "sso") return "Signed in with single sign-on";
      return method && method !== "password" ? `Signed in with ${method[0].toUpperCase()}${method.slice(1)}` : "Signed in";
    }
    case "auth.login_failed":
      return d.reason === "sso_required"
        ? "Password sign-in refused: the team requires single sign-on"
        : "Failed sign-in: wrong password";
    case "auth.password_reset_requested":
      return "Password reset link requested";
    case "account.updated": {
      const fields = Array.isArray(d.fields) ? (d.fields as string[]).join(", ") : "";
      return fields ? `Updated profile (${fields})` : "Updated profile";
    }
    case "account.deleted":
      return "Deleted the account";
    case "api_key.created":
      return `Created API key ${quoted(d.name)}`.trim();
    case "api_key.revoked":
      return "Revoked an API key";
    case "team.created":
      return `Created team ${quoted(d.name)}`.trim();
    case "team.renamed":
      return `Renamed the team to ${quoted(d.name)}`.trim();
    case "team.deleted":
      return "Deleted a team";
    case "team.member.role_changed":
      return `Changed ${subject === "you" ? "your" : `${subject}'s`} role from ${text(d.from)} to ${text(d.to)}`;
    case "team.member.removed":
      return `Removed ${subject} from the team`;
    case "team.member.left":
      return "Left the team";
    case "team.invitation.sent":
      return `Invited ${text(d.email)} as ${text(d.role)}`;
    case "team.invitation.withdrawn":
      return "Withdrew an invitation";
    case "team.invitation.accepted":
      return `Joined the team as ${text(d.role)}`;
    case "team.invitation.declined":
      return "Declined an invitation";
    case "team.api_key.created":
      return `Created team key ${quoted(d.name)}`.trim();
    case "team.api_key.revoked":
      return "Revoked a team key";
    case "team.member.joined_sso":
      return `Joined the team through single sign-on as ${text(d.role)}`;
    case "team.member.provisioned":
      return `${subject === "you" ? "You were" : `${subject} was`} added by the identity provider`;
    case "team.member.deprovisioned":
      return `${subject === "you" ? "You were" : `${subject} was`} removed by the identity provider`;
    case "team.sso_changed":
      return d.enabled ? `Turned single sign-on on${d.required ? ", and required it" : ""}` : "Turned single sign-on off";
    case "team.domain_added":
      return `Added the domain ${text(d.domain)}`;
    case "team.domain_verified":
      return `Verified the domain ${text(d.domain)}`;
    case "team.domain_removed":
      return `Removed the domain ${text(d.domain)}`;
    case "team.scim_token_created":
      return "Made a new provisioning token";
    case "team.scim_token_revoked":
      return "Revoked the provisioning token";
    case "team.plan_changed":
      return `Moved the team to the ${planName(text(d.plan))} plan${d.custom ? ", with custom limits" : ""}`;
    case "team.storage_added":
      return `Connected the bucket ${text(d.bucket)}${d.name ? ` as ${quoted(d.name)}` : ""}`;
    case "team.storage_changed":
      return `Changed the storage connection ${quoted(d.name)}${d.changed ? `: ${text(d.changed)}` : ""}`.trim();
    case "team.storage_removed":
      return `Disconnected the bucket ${text(d.bucket)}`;
    case "team.storage_scan_requested":
      return `Asked for a scan of ${quoted(d.name)}`.trim();
    case "scan.created":
      return `Submitted a ${text(d.type) || "new"} scan`;
    default:
      return e.action;
  }
}

/** Failed sign-ins and resets are worth a second look. */
export const isWarning = (e: AuditEvent) =>
  e.action === "auth.login_failed" || e.action === "auth.password_reset_requested";

export function shortAgent(ua?: string | null): string {
  if (!ua) return "";
  const browser = /Edg\//.test(ua)
    ? "Edge"
    : /Firefox\//.test(ua)
      ? "Firefox"
      : /Chrome\//.test(ua)
        ? "Chrome"
        : /Safari\//.test(ua)
          ? "Safari"
          : /curl\//.test(ua)
            ? "curl"
            : "";
  const os = /Windows/.test(ua)
    ? "Windows"
    : /Mac OS X|Macintosh/.test(ua)
      ? "macOS"
      : /Android/.test(ua)
        ? "Android"
        : /iPhone|iPad/.test(ua)
          ? "iOS"
          : /Linux/.test(ua)
            ? "Linux"
            : "";
  return [browser, os].filter(Boolean).join(" on ") || ua.slice(0, 40);
}

function when(iso: string): string {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? "" : d.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

export function auditUrl(endpoint: string, category: string, before?: number | null, csv = false): string {
  const p = new URLSearchParams();
  if (category !== "all") p.set("action", category);
  if (before) p.set("before", String(before));
  if (csv) p.set("format", "csv");
  const qs = p.toString();
  return qs ? `${endpoint}?${qs}` : endpoint;
}

interface AuditLogProps {
  /** `/api/users/me/audit` or `/api/orgs/{id}/audit`. */
  endpoint: string;
  /** Your own log: shows IP addresses and browsers, and says "you". */
  personal?: boolean;
  viewerId?: string;
  title?: string;
  description?: string;
}

export function AuditLog({ endpoint, personal = false, viewerId, title, description }: AuditLogProps) {
  const [category, setCategory] = useState("all");
  const query = useInfiniteQuery<AuditPage>({
    queryKey: [endpoint, "audit", category],
    initialPageParam: null as number | null,
    queryFn: async ({ pageParam }) => {
      const res = await fetch(auditUrl(endpoint, category, pageParam as number | null), { credentials: "include" });
      if (!res.ok) throw new Error(`${res.status}`);
      return (await res.json()) as AuditPage;
    },
    getNextPageParam: (last) => last.nextBefore ?? undefined,
  });
  const events = query.data?.pages.flatMap((p) => p.events) ?? [];
  const categories = CATEGORIES.filter((c) => personal ? c.personal : c.value === "all" || c.value.startsWith("team.") || c.value === "scan.");

  return (
    <Card className="glassmorphism" data-testid="audit-log">
      <CardHeader className="gap-3 sm:flex-row sm:items-start sm:justify-between sm:space-y-0">
        <div className="space-y-1.5">
          <CardTitle className="flex items-center gap-2">
            <History className="h-5 w-5 text-primary" /> {title ?? (personal ? "Activity" : "Audit log")}
          </CardTitle>
          <CardDescription>
            {description ??
              (personal
                ? "Sign-ins, account and key changes, team actions and scans, with where they came from. Kept for 12 months."
                : "Everything done in this team. Kept for 12 months.")}
          </CardDescription>
        </div>
        <div className="flex gap-2">
          <Select value={category} onValueChange={setCategory}>
            <SelectTrigger className="h-9 w-[150px]" aria-label="Show">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {categories.map((c) => (
                <SelectItem key={c.value} value={c.value}>
                  {c.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Button asChild size="sm" variant="outline" className="h-9">
            <a href={auditUrl(endpoint, category, null, true)} download>
              <Download className="mr-1 h-3.5 w-3.5" /> CSV
            </a>
          </Button>
        </div>
      </CardHeader>
      <CardContent>
        {query.isLoading ? (
          <p className="text-sm text-muted-foreground">Loading…</p>
        ) : query.isError ? (
          <p className="text-sm text-muted-foreground">The log couldn&apos;t be loaded. Please try again.</p>
        ) : events.length === 0 ? (
          <p className="text-sm text-muted-foreground">Nothing here yet.</p>
        ) : (
          <ul className="divide-y divide-border/60">
            {events.map((e) => {
              const actor = e.actor?.id && e.actor.id === viewerId ? "You" : who(e.actor);
              return (
                <li key={e.id} className="flex flex-col gap-1 py-2.5 text-sm sm:flex-row sm:items-baseline sm:justify-between">
                  <div className="min-w-0">
                    <span className={isWarning(e) ? "font-medium text-destructive" : "font-medium"}>{describe(e, viewerId)}</span>
                    {e.action === "scan.created" && e.targetId && (
                      <Link href={`/analysis/${e.targetId}`} className="ml-2 text-xs text-primary hover:underline">
                        open
                      </Link>
                    )}
                    <div className="text-xs text-muted-foreground">
                      {e.actor ? actor : "Not signed in"}
                      {e.via === "api_key" && (
                        <Badge variant="secondary" className="ml-1.5 px-1 py-0 text-[10px]">
                          API key
                        </Badge>
                      )}
                      {personal && (e.ip || e.userAgent) && (
                        <span>
                          {" · "}
                          {[e.ip, shortAgent(e.userAgent)].filter(Boolean).join(" · ")}
                        </span>
                      )}
                    </div>
                  </div>
                  <time className="shrink-0 text-xs text-muted-foreground" dateTime={e.occurredAt}>
                    {when(e.occurredAt)}
                  </time>
                </li>
              );
            })}
          </ul>
        )}
        {query.hasNextPage && (
          <Button
            variant="ghost"
            size="sm"
            className="mt-2"
            onClick={() => query.fetchNextPage()}
            disabled={query.isFetchingNextPage}
          >
            {query.isFetchingNextPage ? "Loading…" : "Show older"}
          </Button>
        )}
      </CardContent>
    </Card>
  );
}
