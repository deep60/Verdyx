import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Checkbox } from "@/components/ui/checkbox";
import { apiRequest } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import { Webhook, Plus, Trash2, Send, Copy, CheckCircle2, XCircle, Clock } from "lucide-react";
import {
  DESTINATIONS,
  DESTINATION_KINDS,
  apiErrorMessage,
  createBody,
  destinationSummary,
  kindOf,
  missing,
  type DestinationKind,
} from "@/lib/destinations";

interface WebhookItem {
  id: string;
  url: string;
  events: string[];
  secret?: string | null;
  is_active: boolean;
  description?: string | null;
  last_triggered_at?: string | null;
  created_at: string;
  kind?: string;
  config?: Record<string, unknown> | null;
  has_credential?: boolean;
}

interface WebhookListResponse {
  webhooks: WebhookItem[];
  total: number;
}

interface WebhookDelivery {
  id: string;
  webhook_id: string;
  event_type: string;
  status: string;
  status_code?: number | null;
  error_message?: string | null;
  triggered_at: string;
}

interface DeliveryListResponse {
  deliveries: WebhookDelivery[];
  total: number;
}

// The events the server delivers (shared::webhooks::EVENTS in the backend).
const DEFAULT_EVENTS = [
  { id: "analysis.completed", label: "analysis.completed", desc: "A scan you submitted finished, with its verdict" },
  { id: "analysis.updated", label: "analysis.updated", desc: "A finished scan's verdict changed, e.g. a sandbox report arrived" },
  { id: "livehunt.match", label: "livehunt.match", desc: "One of your live YARA hunts matched a new upload" },
];

export function WebhooksManager() {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [kind, setKind] = useState<DestinationKind>("webhook");
  const [url, setUrl] = useState("");
  const [description, setDescription] = useState("");
  const [credential, setCredential] = useState("");
  const [config, setConfig] = useState<Record<string, string>>({});
  const [selectedEvents, setSelectedEvents] = useState<string[]>([
    "analysis.completed",
    "livehunt.match",
  ]);
  const [selectedWebhookId, setSelectedWebhookId] = useState<string | null>(null);

  const { data: listData, isLoading } = useQuery<WebhookListResponse>({
    queryKey: ["/api/webhooks"],
  });

  const { data: deliveriesData, refetch: refetchDeliveries } = useQuery<DeliveryListResponse>({
    queryKey: [`/api/webhooks/${selectedWebhookId}/deliveries`],
    enabled: Boolean(selectedWebhookId),
  });

  const draft = { kind, url, description, events: selectedEvents, credential, config };
  const spec = DESTINATIONS[kind];
  const notReady = missing(draft);

  const createMutation = useMutation({
    mutationFn: async () => {
      const res = await apiRequest("POST", "/api/webhooks", createBody(draft));
      return (await res.json()) as WebhookItem;
    },
    onSuccess: (created) => {
      toast({
        title: `${DESTINATIONS[kindOf(created.kind)].label} added`,
        description:
          kindOf(created.kind) === "webhook"
            ? `Deliveries to ${created.url} are signed with the key shown in the list.`
            : "Send a test event to check it's set up.",
      });
      setUrl("");
      setDescription("");
      setCredential("");
      setConfig({});
      setSelectedWebhookId(created.id);
      queryClient.invalidateQueries({ queryKey: ["/api/webhooks"] });
    },
    onError: (err) => {
      toast({
        title: "Couldn't add it",
        description: apiErrorMessage(
          err,
          "Check the address: it must be public (local and private addresses are refused).",
        ),
        variant: "destructive",
      });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: async (id: string) => {
      await apiRequest("DELETE", `/api/webhooks/${id}`);
      return id;
    },
    onSuccess: (deletedId) => {
      toast({
        title: "Webhook deleted",
        description: "Endpoint removed from event dispatch.",
      });
      if (selectedWebhookId === deletedId) setSelectedWebhookId(null);
      queryClient.invalidateQueries({ queryKey: ["/api/webhooks"] });
    },
    onError: (err) => {
      toast({
        title: "Delete failed",
        description: err instanceof Error ? err.message : "Could not delete webhook",
        variant: "destructive",
      });
    },
  });

  const testMutation = useMutation({
    mutationFn: async (id: string) => {
      const res = await apiRequest("POST", `/api/webhooks/${id}/test`, {
        event_type: "analysis.completed",
        // The same shape as a real analysis.completed delivery's `data`.
        sample_payload: {
          test: true,
          submissionId: "00000000-0000-0000-0000-000000000001",
          status: "completed",
          type: "file",
          target: "invoice.exe",
          sha256: "0".repeat(64),
          isMalicious: true,
          confidence: 0.75,
          engineResults: 9,
          teamId: null,
        },
      });
      return (await res.json()) as WebhookDelivery;
    },
    onSuccess: (delivery) => {
      toast({
        title: delivery.status === "success" ? "Test ping delivered" : "Test ping recorded",
        description: delivery.status_code
          ? `Remote server responded with HTTP ${delivery.status_code}`
          : delivery.error_message || "Delivery logged",
      });
      setSelectedWebhookId(delivery.webhook_id);
      void refetchDeliveries();
    },
    onError: (err) => {
      toast({
        title: "Test delivery failed",
        description: err instanceof Error ? err.message : "Could not send test event",
        variant: "destructive",
      });
    },
  });

  const toggleEvent = (eventId: string) => {
    setSelectedEvents((prev) =>
      prev.includes(eventId) ? prev.filter((item) => item !== eventId) : [...prev, eventId]
    );
  };

  const webhooks = listData?.webhooks ?? [];
  const deliveries = deliveriesData?.deliveries ?? [];

  return (
    <div className="space-y-6">
      <Card className="glassmorphism border-primary/20">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Webhook className="h-5 w-5 text-primary" />
            Send events out
          </CardTitle>
          <CardDescription>
            Get scan results and live-hunt matches as they happen: as a signed webhook, or straight into Splunk or
            Microsoft Sentinel. Failed deliveries are retried.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form
            className="space-y-4"
            onSubmit={(e) => {
              e.preventDefault();
              if (notReady) return;
              createMutation.mutate();
            }}
          >
            <div className="space-y-2">
              <Label id="destination-kind-label">Send to</Label>
              <div role="radiogroup" aria-labelledby="destination-kind-label" className="flex flex-wrap gap-2">
                {DESTINATION_KINDS.map((k) => (
                  <button
                    key={k}
                    type="button"
                    role="radio"
                    aria-checked={kind === k}
                    onClick={() => {
                      setKind(k);
                      setConfig({});
                      setCredential("");
                    }}
                    className={`border px-3 py-1.5 text-sm transition-colors ${
                      kind === k
                        ? "border-primary bg-primary/10 text-foreground"
                        : "border-border text-muted-foreground hover:border-primary/40"
                    }`}
                    data-testid={`destination-${k}`}
                  >
                    {DESTINATIONS[k].label}
                  </button>
                ))}
              </div>
              {spec.docs && (
                <p className="text-xs text-muted-foreground">
                  Setting it up on the {spec.label} side:{" "}
                  <a href={spec.docs} target="_blank" rel="noreferrer" className="text-primary hover:underline">
                    step-by-step guide
                  </a>
                  .
                </p>
              )}
            </div>

            <div className="grid gap-4 md:grid-cols-2">
              <div className="space-y-2">
                <Label htmlFor="webhook-url">{spec.urlLabel}</Label>
                <Input
                  id="webhook-url"
                  type="url"
                  placeholder={spec.urlPlaceholder}
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  required
                  aria-describedby="webhook-url-help"
                  data-testid="input-webhook-url"
                />
                <p id="webhook-url-help" className="text-[11px] text-muted-foreground">
                  {spec.urlHelp}
                </p>
              </div>
              <div className="space-y-2">
                <Label htmlFor="webhook-desc">Description (Optional)</Label>
                <Input
                  id="webhook-desc"
                  placeholder="SOC alerts / CI pipeline gate"
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  data-testid="input-webhook-description"
                />
              </div>
              {spec.credentialLabel && (
                <div className="space-y-2">
                  <Label htmlFor="destination-credential">{spec.credentialLabel}</Label>
                  <Input
                    id="destination-credential"
                    type="password"
                    autoComplete="off"
                    value={credential}
                    onChange={(e) => setCredential(e.target.value)}
                    aria-describedby="destination-credential-help"
                    data-testid="input-destination-credential"
                  />
                  <p id="destination-credential-help" className="text-[11px] text-muted-foreground">
                    {spec.credentialHelp} It's stored encrypted and never shown again.
                  </p>
                </div>
              )}
              {spec.fields.map((f) => (
                <div key={f.key} className="space-y-2">
                  <Label htmlFor={`destination-${f.key}`}>
                    {f.label}
                    {f.optional && <span className="text-muted-foreground"> (optional)</span>}
                  </Label>
                  <Input
                    id={`destination-${f.key}`}
                    placeholder={f.placeholder}
                    value={config[f.key] ?? ""}
                    onChange={(e) => setConfig((c) => ({ ...c, [f.key]: e.target.value }))}
                    data-testid={`input-destination-${f.key}`}
                  />
                </div>
              ))}
            </div>

            <div className="space-y-2">
              <Label>Subscribed Events</Label>
              <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
                {DEFAULT_EVENTS.map((ev) => (
                  <label
                    key={ev.id}
                    className="flex items-start gap-2.5 rounded-lg border border-border/60 bg-muted/20 p-2.5 text-xs cursor-pointer hover:border-primary/40"
                  >
                    <Checkbox
                      checked={selectedEvents.includes(ev.id)}
                      onCheckedChange={() => toggleEvent(ev.id)}
                    />
                    <div>
                      <div className="font-mono font-semibold text-foreground">{ev.label}</div>
                      <div className="text-muted-foreground text-[11px]">{ev.desc}</div>
                    </div>
                  </label>
                ))}
              </div>
            </div>

            <Button
              type="submit"
              disabled={createMutation.isPending || Boolean(notReady)}
              title={notReady ?? undefined}
              data-testid="button-create-webhook"
            >
              <Plus className="h-4 w-4 mr-1.5" />
              {createMutation.isPending ? "Adding…" : `Add ${spec.label}`}
            </Button>
          </form>
        </CardContent>
      </Card>

      <Card className="glassmorphism border-primary/20">
        <CardHeader>
          <CardTitle className="text-lg">Destinations ({webhooks.length})</CardTitle>
          <CardDescription>
            <strong>Test</strong> sends a sample <code>analysis.completed</code> event and shows what came back.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          {isLoading ? (
            <p className="text-sm text-muted-foreground">Loading webhooks…</p>
          ) : webhooks.length === 0 ? (
            <p className="text-sm text-muted-foreground">
              Nothing set up yet. Add a webhook, Splunk or Sentinel above to start receiving events.
            </p>
          ) : (
            webhooks.map((wh) => (
              <div
                key={wh.id}
                className="rounded-xl border border-border/70 bg-muted/15 p-4 space-y-3"
              >
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div className="space-y-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <Badge variant={wh.is_active ? "default" : "outline"}>
                        {wh.is_active ? "Active" : "Paused"}
                      </Badge>
                      <span className="font-mono text-sm font-semibold break-all">{wh.url}</span>
                    </div>
                    <p className="text-xs text-muted-foreground" data-testid={`destination-summary-${wh.id}`}>
                      {destinationSummary(kindOf(wh.kind), wh.config)}
                      {kindOf(wh.kind) !== "webhook" && !wh.has_credential && " · credential missing"}
                    </p>
                    {wh.description && (
                      <p className="text-xs text-muted-foreground">{wh.description}</p>
                    )}
                  </div>
                  <div className="flex items-center gap-2">
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => testMutation.mutate(wh.id)}
                      disabled={testMutation.isPending}
                      data-testid={`button-test-webhook-${wh.id}`}
                    >
                      <Send className="h-3.5 w-3.5 mr-1.5" />
                      Test
                    </Button>
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() =>
                        setSelectedWebhookId(selectedWebhookId === wh.id ? null : wh.id)
                      }
                    >
                      {selectedWebhookId === wh.id ? "Hide Logs" : "Delivery Logs"}
                    </Button>
                    <Button
                      size="sm"
                      variant="destructive"
                      onClick={() => deleteMutation.mutate(wh.id)}
                      disabled={deleteMutation.isPending}
                      aria-label="Delete webhook"
                    >
                      <Trash2 className="h-3.5 w-3.5" />
                    </Button>
                  </div>
                </div>

                <div className="flex flex-wrap items-center justify-between gap-2 pt-2 border-t border-border/40 text-xs">
                  <div className="flex flex-wrap gap-1.5">
                    {wh.events.map((ev) => (
                      <Badge key={ev} variant="secondary" className="font-mono text-[10px]">
                        {ev}
                      </Badge>
                    ))}
                  </div>
                  {wh.secret && kindOf(wh.kind) === "webhook" && (
                    <button
                      type="button"
                      onClick={() => {
                        void navigator.clipboard.writeText(wh.secret || "");
                        toast({
                          title: "Signing secret copied",
                          description: "Use this whsec_ key to verify HMAC-SHA256 signatures.",
                        });
                      }}
                      className="inline-flex items-center gap-1 font-mono text-[11px] text-primary hover:underline"
                    >
                      <Copy className="h-3 w-3" />
                      {wh.secret.slice(0, 14)}…
                    </button>
                  )}
                </div>

                {selectedWebhookId === wh.id && (
                  <div className="mt-3 pt-3 border-t border-border/60 space-y-2">
                    <div className="text-xs font-semibold text-muted-foreground">
                      Recent Delivery Attempts ({deliveries.length})
                    </div>
                    {deliveries.length === 0 ? (
                      <p className="text-xs text-muted-foreground">
                        No deliveries recorded yet. Click Test Ping above to verify connectivity.
                      </p>
                    ) : (
                      <div className="space-y-1.5">
                        {deliveries.map((del) => (
                          <div
                            key={del.id}
                            className="flex flex-wrap items-center justify-between gap-2 rounded bg-background/70 border border-border/50 px-3 py-1.5 text-xs"
                          >
                            <div className="flex items-center gap-2">
                              {del.status === "success" ? (
                                <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />
                              ) : (
                                <XCircle className="h-3.5 w-3.5 text-destructive" />
                              )}
                              <span className="font-mono">{del.event_type}</span>
                              {del.status_code && (
                                <Badge variant="outline" className="font-mono text-[10px]">
                                  HTTP {del.status_code}
                                </Badge>
                              )}
                            </div>
                            <div className="flex items-center gap-2 text-muted-foreground font-mono text-[11px]">
                              {del.error_message && (
                                <span className="text-destructive">{del.error_message}</span>
                              )}
                              <Clock className="h-3 w-3" />
                              <span>{new Date(del.triggered_at).toLocaleTimeString()}</span>
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                )}
              </div>
            ))
          )}
        </CardContent>
      </Card>
    </div>
  );
}
