import { useState, type ReactNode } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Checkbox } from "@/components/ui/checkbox";
import { apiRequest } from "@/lib/queryClient";
import { serverMessage } from "@/lib/teams";
import { useToast } from "@/hooks/use-toast";
import { Copy, KeyRound, Plus, Trash2 } from "lucide-react";

export interface ApiKeyItem {
  id: string;
  name: string;
  prefix?: string | null;
  permissions: string[];
  isActive: boolean;
  expired?: boolean;
  lastUsedAt?: string | null;
  createdAt: string;
  expiresAt?: string | null;
  /** Team keys: who made it. */
  createdBy?: string | null;
}

interface CreatedKey {
  api_key: string;
  name: string;
}

export const SCOPES: { id: string; label: string; help: string }[] = [
  { id: "read", label: "Read", help: "View submissions, results and engine status" },
  { id: "scan", label: "Scan", help: "Submit files and URLs for analysis" },
  { id: "write", label: "Write", help: "Manage webhooks, bounties and votes" },
];

const EXPIRY_OPTIONS = [
  { days: 30, label: "30 days" },
  { days: 90, label: "90 days" },
  { days: 365, label: "1 year" },
  { days: 0, label: "Never" },
];

export function formatWhen(iso?: string | null): string {
  if (!iso) return "never";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? "unknown" : d.toLocaleDateString(undefined, { dateStyle: "medium" });
}

/** "active", "expired" or "revoked", for a key row. */
export function keyStatus(k: ApiKeyItem): "active" | "expired" | "revoked" {
  if (k.expired) return "expired";
  return k.isActive ? "active" : "revoked";
}

export interface KeyEndpoints {
  list: string;
  create: string;
  revoke: (id: string) => string;
}

export const PERSONAL_KEYS: KeyEndpoints = {
  list: "/api/users/me/api-keys",
  create: "/api/auth/api-key",
  revoke: (id) => `/api/users/me/api-keys/${id}`,
};

interface ApiKeysManagerProps {
  endpoints?: KeyEndpoints;
  /** Replaces the explanation under "Create an API key". */
  intro?: ReactNode;
  listTitle?: string;
  /** How many active keys there may be, shown above the list. */
  limitNote?: string;
}

export function ApiKeysManager({
  endpoints = PERSONAL_KEYS,
  intro,
  listTitle = "Your keys",
  limitNote = "Up to 10 active keys.",
}: ApiKeysManagerProps = {}) {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [name, setName] = useState("");
  const [scopes, setScopes] = useState<string[]>(["read", "scan"]);
  const [expiryDays, setExpiryDays] = useState(90);
  const [created, setCreated] = useState<CreatedKey | null>(null);

  const { data: keys = [], isLoading } = useQuery<ApiKeyItem[]>({
    queryKey: [endpoints.list],
  });

  const createMutation = useMutation({
    mutationFn: async () => {
      const res = await apiRequest("POST", endpoints.create, {
        name: name.trim() || "API key",
        scopes,
        expires_in_days: expiryDays > 0 ? expiryDays : null,
      });
      return (await res.json()) as CreatedKey;
    },
    onSuccess: (data) => {
      setCreated(data);
      setName("");
      queryClient.invalidateQueries({ queryKey: [endpoints.list] });
    },
    onError: (err) => {
      const msg = err instanceof Error ? err.message : "";
      toast({
        title: "Could not create the key",
        description: msg.startsWith("409")
          ? serverMessage(err, "There are already as many active keys as allowed. Revoke one first.")
          : "Please try again.",
        variant: "destructive",
      });
    },
  });

  const revokeMutation = useMutation({
    mutationFn: async (id: string) => {
      await apiRequest("DELETE", endpoints.revoke(id));
    },
    onSuccess: () => {
      toast({ title: "Key revoked", description: "Requests using it are now refused." });
      queryClient.invalidateQueries({ queryKey: [endpoints.list] });
    },
    onError: () => toast({ title: "Could not revoke the key", variant: "destructive" }),
  });

  const toggleScope = (id: string, on: boolean) =>
    setScopes((s) => (on ? (s.includes(id) ? s : [...s, id]) : s.filter((x) => x !== id)));

  const copy = async (value: string) => {
    try {
      await navigator.clipboard.writeText(value);
      toast({ title: "Copied" });
    } catch {
      toast({ title: "Copy failed", description: "Select the key and copy it manually.", variant: "destructive" });
    }
  };

  return (
    <div className="space-y-6" data-testid="api-keys-manager">
      <Card className="glassmorphism border-primary/20">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <KeyRound className="h-5 w-5 text-primary" />
            Create an API key
          </CardTitle>
          <CardDescription>
            {intro ?? (
              <>
                Send it as <code className="font-mono">X-API-Key: vdx_…</code> or{" "}
                <code className="font-mono">Authorization: Bearer vdx_…</code>. Keys act as you, but can never sign
                in, manage keys or teams, change your account or move funds.
              </>
            )}
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {created && (
            <div className="space-y-2 rounded-lg border border-primary/40 bg-primary/10 p-3" data-testid="new-api-key">
              <div className="text-sm font-medium">
                “{created.name}” created. Copy it now: it won&apos;t be shown again.
              </div>
              <div className="flex items-center gap-2">
                <code className="flex-1 break-all rounded bg-background/60 px-2 py-1.5 font-mono text-xs">
                  {created.api_key}
                </code>
                <Button size="sm" variant="outline" onClick={() => copy(created.api_key)}>
                  <Copy className="mr-1 h-3.5 w-3.5" /> Copy
                </Button>
              </div>
              <Button size="sm" variant="ghost" onClick={() => setCreated(null)}>
                I&apos;ve stored it
              </Button>
            </div>
          )}

          <div className="space-y-2">
            <Label htmlFor="api-key-name">Name</Label>
            <Input
              id="api-key-name"
              placeholder="e.g. SOC pipeline"
              maxLength={100}
              value={name}
              onChange={(e) => setName(e.target.value)}
            />
          </div>

          <div className="space-y-2">
            <Label>Permissions</Label>
            <div className="grid gap-2 sm:grid-cols-3">
              {SCOPES.map((s) => (
                <label key={s.id} className="flex cursor-pointer items-start gap-2 rounded border border-border/60 p-2 text-sm">
                  <Checkbox
                    checked={scopes.includes(s.id)}
                    onCheckedChange={(v) => toggleScope(s.id, v === true)}
                    aria-label={s.label}
                  />
                  <span>
                    <span className="font-medium">{s.label}</span>
                    <span className="block text-xs text-muted-foreground">{s.help}</span>
                  </span>
                </label>
              ))}
            </div>
          </div>

          <div className="space-y-2">
            <Label>Expires</Label>
            <div className="flex flex-wrap gap-2">
              {EXPIRY_OPTIONS.map((o) => (
                <Button
                  key={o.days}
                  type="button"
                  size="sm"
                  variant={expiryDays === o.days ? "default" : "outline"}
                  onClick={() => setExpiryDays(o.days)}
                >
                  {o.label}
                </Button>
              ))}
            </div>
          </div>

          <Button
            onClick={() => createMutation.mutate()}
            disabled={scopes.length === 0 || createMutation.isPending}
            data-testid="button-create-api-key"
          >
            <Plus className="mr-1.5 h-4 w-4" />
            {createMutation.isPending ? "Creating…" : "Create key"}
          </Button>
        </CardContent>
      </Card>

      <Card className="glassmorphism">
        <CardHeader>
          <CardTitle>{listTitle}</CardTitle>
          <CardDescription>{limitNote} Revoking takes effect immediately.</CardDescription>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <p className="text-sm text-muted-foreground">Loading…</p>
          ) : keys.length === 0 ? (
            <p className="text-sm text-muted-foreground">No keys yet.</p>
          ) : (
            <ul className="divide-y divide-border/60">
              {keys.map((k) => {
                const status = keyStatus(k);
                return (
                  <li key={k.id} className="flex flex-col gap-2 py-3 sm:flex-row sm:items-center sm:justify-between">
                    <div className="min-w-0 space-y-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="font-medium">{k.name}</span>
                        <code className="font-mono text-xs text-muted-foreground">
                          {k.prefix ? `${k.prefix}…` : "legacy key"}
                        </code>
                        <Badge variant={status === "active" ? "outline" : "secondary"}>{status}</Badge>
                      </div>
                      <div className="flex flex-wrap gap-1">
                        {k.permissions.map((p) => (
                          <Badge key={p} variant="secondary" className="text-[10px]">
                            {p}
                          </Badge>
                        ))}
                      </div>
                      <div className="text-xs text-muted-foreground">
                        Created {formatWhen(k.createdAt)}
                        {k.createdBy ? ` by ${k.createdBy}` : ""} · last used {formatWhen(k.lastUsedAt)} ·{" "}
                        {k.expiresAt ? `expires ${formatWhen(k.expiresAt)}` : "no expiry"}
                      </div>
                    </div>
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => revokeMutation.mutate(k.id)}
                      disabled={revokeMutation.isPending}
                      aria-label={`Revoke ${k.name}`}
                    >
                      <Trash2 className="mr-1 h-3.5 w-3.5" />
                      {status === "active" ? "Revoke" : "Remove"}
                    </Button>
                  </li>
                );
              })}
            </ul>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
