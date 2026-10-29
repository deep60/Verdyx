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

interface WebhookItem {
  id: string;
  url: string;
  events: string[];
  secret?: string | null;
  is_active: boolean;
  description?: string | null;
  last_triggered_at?: string | null;
  created_at: string;
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

const DEFAULT_EVENTS = [
  { id: "analysis.completed", label: "analysis.completed", desc: "Multi-engine scan & consensus completed" },
  { id: "bounty.created", label: "bounty.created", desc: "New threat bounty posted" },
  { id: "bounty.submission", label: "bounty.submission", desc: "Engine or analyst staked a verdict" },
  { id: "bounty.finalized", label: "bounty.finalized", desc: "Bounty quorum settled & rewards paid" },
  { id: "reputation.updated", label: "reputation.updated", desc: "Analyst or engine reputation changed" },
];

export function WebhooksManager() {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [url, setUrl] = useState("");
  const [description, setDescription] = useState("");
  const [selectedEvents, setSelectedEvents] = useState<string[]>([
    "analysis.completed",
    "bounty.finalized",
  ]);
  const [selectedWebhookId, setSelectedWebhookId] = useState<string | null>(null);

  const { data: listData, isLoading } = useQuery<WebhookListResponse>({
    queryKey: ["/api/webhooks"],
  });

  const { data: deliveriesData, refetch: refetchDeliveries } = useQuery<DeliveryListResponse>({
    queryKey: [`/api/webhooks/${selectedWebhookId}/deliveries`],
    enabled: Boolean(selectedWebhookId),
  });

  const createMutation = useMutation({
    mutationFn: async () => {
      const res = await apiRequest("POST", "/api/webhooks", {
        url: url.trim(),
        events: selectedEvents,
        description: description.trim() || undefined,
      });
      return (await res.json()) as WebhookItem;
    },
    onSuccess: (created) => {
      toast({
        title: "Webhook endpoint registered",
        description: `HMAC signing secret generated for ${created.url}`,
      });
      setUrl("");
      setDescription("");
      setSelectedWebhookId(created.id);
      queryClient.invalidateQueries({ queryKey: ["/api/webhooks"] });
    },
    onError: (err) => {
      toast({
        title: "Could not register webhook",
        description:
          err instanceof Error
            ? err.message
            : "Provide a public HTTPS URL (localhost/private IPs are blocked for SSRF protection).",
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
        sample_payload: {
          event: "analysis.completed",
          submissionId: "00000000-0000-0000-0000-000000000001",
          finalVerdict: "malicious",
          confidenceScore: 96.4,
          enginesCompleted: 8,
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
            Register Outbound Webhook
          </CardTitle>
          <CardDescription>
            Receive real-time HMAC-signed JSON callbacks when scans finish or bounties settle. Private/loopback IPs are blocked for SSRF safety.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form
            className="space-y-4"
            onSubmit={(e) => {
              e.preventDefault();
              if (!url.trim() || selectedEvents.length === 0) return;
              createMutation.mutate();
            }}
          >
            <div className="grid gap-4 md:grid-cols-2">
              <div className="space-y-2">
                <Label htmlFor="webhook-url">Endpoint URL (HTTPS)</Label>
                <Input
                  id="webhook-url"
                  type="url"
                  placeholder="https://soc.example.com/webhooks/verdyx"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  required
                  data-testid="input-webhook-url"
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="webhook-desc">Description (Optional)</Label>
                <Input
                  id="webhook-desc"
                  placeholder="Splunk SOAR / CI pipeline gate"
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  data-testid="input-webhook-description"
                />
              </div>
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
              disabled={createMutation.isPending || !url.trim() || selectedEvents.length === 0}
              data-testid="button-create-webhook"
            >
              <Plus className="h-4 w-4 mr-1.5" />
              {createMutation.isPending ? "Registering..." : "Create Webhook"}
            </Button>
          </form>
        </CardContent>
      </Card>

      <Card className="glassmorphism border-primary/20">
        <CardHeader>
          <CardTitle className="text-lg">Configured Endpoints ({webhooks.length})</CardTitle>
          <CardDescription>
            Click <strong>Test Ping</strong> to dispatch a sample `analysis.completed` payload and inspect the HTTP status code.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          {isLoading ? (
            <p className="text-sm text-muted-foreground">Loading webhooks…</p>
          ) : webhooks.length === 0 ? (
            <p className="text-sm text-muted-foreground">
              No webhooks registered yet. Add an HTTPS endpoint above to start receiving events.
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
                      Test Ping
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
                  {wh.secret && (
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
