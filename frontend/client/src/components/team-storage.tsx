import { useState } from "react";
import { Link } from "wouter";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ChevronDown, ChevronRight, Database, Plus, RefreshCw, Trash2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Switch } from "@/components/ui/switch";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { apiRequest } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import { serverMessage } from "@/lib/teams";
import { formatBytes } from "@/lib/report";
import {
  INTERVALS,
  PROVIDERS,
  connectionStatus,
  createBody,
  emptyForm,
  formProblem,
  intervalLabel,
  locationOf,
  objectStatus,
  providerInfo,
  type ConnectionForm,
  type StorageConnection,
  type StorageList,
  type StorageObject,
  type Tone,
} from "@/lib/storage";

const DOCS = "https://github.com/deep60/Verdyx/blob/main/docs/integrations/cloud-storage.md";

const toneClass: Record<Tone, string> = {
  danger: "text-red-500",
  warning: "text-amber-500",
  ok: "text-emerald-500",
  muted: "text-muted-foreground",
};

function RecentFiles({ teamId, connectionId }: { teamId: string; connectionId: string }) {
  const { data, isLoading } = useQuery<{ objects: StorageObject[] }>({
    queryKey: [`/api/orgs/${teamId}/storage/${connectionId}/objects?limit=25`],
    refetchInterval: 15000,
  });
  if (isLoading) return <p className="text-xs text-muted-foreground">Loading…</p>;
  const objects = data?.objects ?? [];
  if (objects.length === 0) {
    return <p className="text-xs text-muted-foreground">No files scanned yet.</p>;
  }
  return (
    <ul className="divide-y divide-border text-xs" data-testid={`storage-files-${connectionId}`}>
      {objects.map((o) => {
        const status = objectStatus(o);
        return (
          <li key={`${o.key}-${o.seenAt}`} className="flex items-center justify-between gap-3 py-1.5">
            {o.submissionId ? (
              <Link href={`/analysis/${o.submissionId}`} className="min-w-0 truncate font-mono hover:underline">
                {o.key}
              </Link>
            ) : (
              <span className="min-w-0 truncate font-mono">{o.key}</span>
            )}
            <span className="flex shrink-0 items-center gap-3">
              <span className="text-muted-foreground">{formatBytes(o.size)}</span>
              <span className={toneClass[status.tone]}>{status.text}</span>
            </span>
          </li>
        );
      })}
    </ul>
  );
}

function ConnectionCard({ teamId, c, onChanged }: { teamId: string; c: StorageConnection; onChanged: () => void }) {
  const { toast } = useToast();
  const [open, setOpen] = useState(false);
  const fail = (title: string) => (err: unknown) =>
    toast({ title, description: serverMessage(err, "Please try again."), variant: "destructive" });
  const base = `/api/orgs/${teamId}/storage/${c.id}`;

  const patch = useMutation({
    mutationFn: (body: Record<string, unknown>) => apiRequest("PATCH", base, body),
    onSuccess: onChanged,
    onError: fail("Couldn't save"),
  });
  const scan = useMutation({
    mutationFn: () => apiRequest("POST", `${base}/scan`),
    onSuccess: () => {
      toast({ title: "Looking for new files", description: "Within a minute." });
      onChanged();
    },
    onError: fail("Couldn't start a scan"),
  });
  const remove = useMutation({
    mutationFn: () => apiRequest("DELETE", base),
    onSuccess: onChanged,
    onError: fail("Couldn't remove the connection"),
  });

  const status = connectionStatus(c);
  return (
    <div className="space-y-3 rounded-md border border-border p-3" data-testid={`storage-${c.id}`}>
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0 space-y-1">
          <p className="flex items-center gap-2 text-sm font-medium">
            <Database className="h-4 w-4 text-muted-foreground" /> {c.name}
            <Badge variant="outline">{providerInfo(c.provider).label}</Badge>
          </p>
          <p className="truncate font-mono text-xs text-muted-foreground">{locationOf(c)}</p>
          <p className={`text-xs ${toneClass[status.tone]}`} data-testid={`storage-status-${c.id}`}>
            {status.text}
          </p>
          <p className="text-xs text-muted-foreground">
            {intervalLabel(c.intervalMinutes)} · {c.analysisType} analysis · up to {c.maxObjectMb} MB ·{" "}
            {c.stats.files} {c.stats.files === 1 ? "file" : "files"} scanned
            {c.stats.flagged > 0 && <span className="text-red-500"> · {c.stats.flagged} flagged</span>}
            {c.stats.waiting > 0 && ` · ${c.stats.waiting} waiting`}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Switch
            aria-label={`Scan ${c.name}`}
            checked={c.enabled}
            disabled={patch.isPending}
            onCheckedChange={(enabled) => patch.mutate({ enabled })}
          />
          <Button size="sm" variant="outline" disabled={!c.enabled || scan.isPending} onClick={() => scan.mutate()}>
            <RefreshCw className="mr-1 h-3.5 w-3.5" /> Scan now
          </Button>
          <Button
            size="sm"
            variant="ghost"
            aria-label={`Remove ${c.name}`}
            disabled={remove.isPending}
            onClick={() => {
              if (window.confirm(`Stop scanning ${c.bucket}? The scans already made stay with the team.`)) remove.mutate();
            }}
          >
            <Trash2 className="h-3.5 w-3.5" />
          </Button>
        </div>
      </div>
      <button
        type="button"
        className="flex items-center gap-1 text-xs text-primary hover:underline"
        onClick={() => setOpen((o) => !o)}
        aria-expanded={open}
      >
        {open ? <ChevronDown className="h-3.5 w-3.5" /> : <ChevronRight className="h-3.5 w-3.5" />} Recent files
      </button>
      {open && <RecentFiles teamId={teamId} connectionId={c.id} />}
    </div>
  );
}

function Field({
  id,
  label,
  hint,
  children,
}: {
  id: string;
  label: string;
  hint?: string;
  children: React.ReactNode;
}) {
  return (
    <div className="space-y-1">
      <Label htmlFor={id}>{label}</Label>
      {children}
      {hint && <p className="text-xs text-muted-foreground">{hint}</p>}
    </div>
  );
}

function AddConnection({
  teamId,
  maxObjectMb,
  onDone,
}: {
  teamId: string;
  maxObjectMb: number;
  onDone: () => void;
}) {
  const { toast } = useToast();
  const [f, setF] = useState<ConnectionForm>(() => emptyForm(maxObjectMb));
  const set = <K extends keyof ConnectionForm>(k: K, v: ConnectionForm[K]) => setF((prev) => ({ ...prev, [k]: v }));
  const p = providerInfo(f.provider);
  const problem = formProblem(f);
  const create = useMutation({
    mutationFn: () => apiRequest("POST", `/api/orgs/${teamId}/storage`, createBody(f)),
    onSuccess: () => {
      toast({ title: "Connected", description: `Verdyx can read ${f.bucket}.` });
      onDone();
    },
    onError: (err) =>
      toast({ title: "Couldn't connect", description: serverMessage(err, "Please try again."), variant: "destructive" }),
  });

  return (
    <form
      className="space-y-3 rounded-md border border-border p-3"
      data-testid="storage-form"
      onSubmit={(e) => {
        e.preventDefault();
        if (!problem) create.mutate();
      }}
    >
      <div className="grid gap-3 sm:grid-cols-2">
        <Field id="storage-provider" label="Storage">
          <Select value={f.provider} onValueChange={(v) => set("provider", v as ConnectionForm["provider"])}>
            <SelectTrigger id="storage-provider" aria-label="Storage provider">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {PROVIDERS.map((x) => (
                <SelectItem key={x.value} value={x.value}>
                  {x.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </Field>
        <Field id="storage-name" label="Name">
          <Input id="storage-name" placeholder="Customer uploads" value={f.name} onChange={(e) => set("name", e.target.value)} />
        </Field>
        {p.needsEndpoint && (
          <Field id="storage-endpoint" label="Endpoint">
            <Input
              id="storage-endpoint"
              placeholder={p.endpointHint}
              value={f.endpoint}
              onChange={(e) => set("endpoint", e.target.value)}
            />
          </Field>
        )}
        {p.needsRegion && (
          <Field id="storage-region" label="Region">
            <Input id="storage-region" placeholder={p.regionHint} value={f.region} onChange={(e) => set("region", e.target.value)} />
          </Field>
        )}
        <Field id="storage-bucket" label="Bucket">
          <Input id="storage-bucket" value={f.bucket} onChange={(e) => set("bucket", e.target.value)} />
        </Field>
        <Field id="storage-prefix" label="Folder (optional)" hint="Only files whose key starts with this are scanned.">
          <Input id="storage-prefix" placeholder="incoming/" value={f.prefix} onChange={(e) => set("prefix", e.target.value)} />
        </Field>
        <Field id="storage-key-id" label="Access key ID" hint={p.keyHint}>
          <Input
            id="storage-key-id"
            autoComplete="off"
            value={f.accessKeyId}
            onChange={(e) => set("accessKeyId", e.target.value)}
          />
        </Field>
        <Field id="storage-key" label="Secret access key" hint="Stored encrypted, and never shown again.">
          <Input
            id="storage-key"
            type="password"
            autoComplete="off"
            value={f.secretAccessKey}
            onChange={(e) => set("secretAccessKey", e.target.value)}
          />
        </Field>
        <Field id="storage-interval" label="Look for new files">
          <Select value={String(f.intervalMinutes)} onValueChange={(v) => set("intervalMinutes", Number(v))}>
            <SelectTrigger id="storage-interval" aria-label="How often">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {INTERVALS.map((i) => (
                <SelectItem key={i.value} value={String(i.value)}>
                  {i.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </Field>
        <Field id="storage-analysis" label="Analysis">
          <Select value={f.analysisType} onValueChange={(v) => set("analysisType", v as ConnectionForm["analysisType"])}>
            <SelectTrigger id="storage-analysis" aria-label="Analysis type">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="quick">Quick</SelectItem>
              <SelectItem value="full">Full</SelectItem>
              <SelectItem value="deep">Deep</SelectItem>
            </SelectContent>
          </Select>
        </Field>
        <Field id="storage-max" label="Largest file to scan (MB)" hint={`Up to ${maxObjectMb} MB. Larger files are listed as not scanned.`}>
          <Input
            id="storage-max"
            type="number"
            min={1}
            max={maxObjectMb}
            value={f.maxObjectMb}
            onChange={(e) => set("maxObjectMb", Math.max(1, Math.min(maxObjectMb, Number(e.target.value) || 1)))}
          />
        </Field>
      </div>
      <div className="flex items-start justify-between gap-4">
        <div>
          <label htmlFor="storage-existing" className="text-sm">
            Also scan the files already there
          </label>
          <p className="text-xs text-muted-foreground">
            Otherwise only files added or changed from now on are scanned. A large bucket takes a while: up to 25 files a
            minute.
          </p>
        </div>
        <Switch id="storage-existing" checked={f.scanExisting} onCheckedChange={(v) => set("scanExisting", v)} />
      </div>
      <div className="flex flex-wrap items-center gap-3">
        <Button type="submit" disabled={!!problem || create.isPending} data-testid="storage-connect">
          {create.isPending ? "Checking…" : "Connect"}
        </Button>
        <Button type="button" variant="ghost" onClick={onDone}>
          Cancel
        </Button>
        {problem && <span className="text-xs text-muted-foreground">{problem}</span>}
      </div>
    </form>
  );
}

/** A team's cloud storage connections, for owners and admins. */
export function TeamStorage({ teamId, teamName }: { teamId: string; teamName: string }) {
  const key = [`/api/orgs/${teamId}/storage`];
  const queryClient = useQueryClient();
  const { data, isLoading, isError } = useQuery<StorageList>({ queryKey: key, refetchInterval: 30000 });
  const [adding, setAdding] = useState(false);
  const refresh = () => queryClient.invalidateQueries({ queryKey: [`/api/orgs/${teamId}/storage`] });

  if (isLoading) return <p className="text-sm text-muted-foreground">Loading…</p>;
  if (isError || !data) return <p className="text-sm text-muted-foreground">Storage connections aren&apos;t available.</p>;

  const full = data.connections.length >= data.limit;
  return (
    <div className="space-y-4" data-testid="team-storage">
      <p className="text-sm text-muted-foreground">
        Connect a bucket in Amazon S3, Cloudflare R2, Google Cloud Storage or any S3-compatible storage, and Verdyx scans
        the files that arrive in it. Scans are saved to {teamName}, so your webhooks and SIEM get them too. A read-only key
        is enough.{" "}
        <a href={DOCS} target="_blank" rel="noreferrer" className="text-primary hover:underline">
          Setup guide
        </a>
      </p>
      {data.connections.map((c) => (
        <ConnectionCard key={c.id} teamId={teamId} c={c} onChanged={refresh} />
      ))}
      {adding ? (
        <AddConnection
          teamId={teamId}
          maxObjectMb={data.maxObjectMb}
          onDone={() => {
            setAdding(false);
            refresh();
          }}
        />
      ) : (
        <Button variant="outline" size="sm" disabled={full} onClick={() => setAdding(true)} data-testid="storage-add">
          <Plus className="mr-1 h-3.5 w-3.5" /> {full ? `Up to ${data.limit} connections` : "Connect storage"}
        </Button>
      )}
    </div>
  );
}
