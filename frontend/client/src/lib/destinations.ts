/**
 * Where events go: a plain webhook, Splunk (HTTP Event Collector) or
 * Microsoft Sentinel (Logs Ingestion API). Matches `services::siem` in the
 * gateway; the server checks everything again.
 */

export type DestinationKind = "webhook" | "splunk" | "sentinel";

export interface DestinationField {
  key: string;
  label: string;
  placeholder?: string;
  help?: string;
  optional?: boolean;
}

export interface DestinationSpec {
  kind: DestinationKind;
  label: string;
  urlLabel: string;
  urlPlaceholder: string;
  urlHelp: string;
  /** What the credential is called, or null when there's none to enter. */
  credentialLabel: string | null;
  credentialHelp?: string;
  fields: DestinationField[];
  docs?: string;
}

const DOCS = "https://github.com/deep60/Verdyx/blob/main/docs/integrations";

export const DESTINATIONS: Record<DestinationKind, DestinationSpec> = {
  webhook: {
    kind: "webhook",
    label: "Webhook",
    urlLabel: "Endpoint URL",
    urlPlaceholder: "https://soc.example.com/webhooks/verdyx",
    urlHelp: "Gets a signed JSON POST for each event.",
    credentialLabel: null,
    fields: [],
  },
  splunk: {
    kind: "splunk",
    label: "Splunk",
    urlLabel: "HEC URL",
    urlPlaceholder: "https://splunk.example.com:8088",
    urlHelp: "Your Splunk server's HTTP Event Collector address. /services/collector/event is added for you.",
    credentialLabel: "HEC token",
    credentialHelp: "Create one in Splunk under Settings → Data inputs → HTTP Event Collector.",
    fields: [
      { key: "index", label: "Index", placeholder: "default for the token", optional: true },
      { key: "sourcetype", label: "Sourcetype", placeholder: "verdyx:event", optional: true },
    ],
    docs: `${DOCS}/splunk.md`,
  },
  sentinel: {
    kind: "sentinel",
    label: "Microsoft Sentinel",
    urlLabel: "Logs Ingestion endpoint",
    urlPlaceholder: "https://verdyx-xxxx.eastus-1.ingest.monitor.azure.com",
    urlHelp: "The data collection endpoint's Logs Ingestion URL, without a path.",
    credentialLabel: "Client secret",
    credentialHelp: "The Entra app's client secret. The app needs the Monitoring Metrics Publisher role on the rule.",
    fields: [
      { key: "tenantId", label: "Tenant ID", placeholder: "00000000-0000-0000-0000-000000000000" },
      { key: "clientId", label: "Client ID", placeholder: "00000000-0000-0000-0000-000000000000" },
      { key: "dcrImmutableId", label: "Rule immutable ID", placeholder: "dcr-0123456789abcdef0123456789abcdef" },
      { key: "streamName", label: "Stream", placeholder: "Custom-VerdyxEvents_CL", optional: true },
    ],
    docs: `${DOCS}/sentinel.md`,
  },
};

export const DESTINATION_KINDS: DestinationKind[] = ["webhook", "splunk", "sentinel"];

export function kindOf(raw: string | undefined | null): DestinationKind {
  return raw === "splunk" || raw === "sentinel" ? raw : "webhook";
}

export interface DestinationDraft {
  kind: DestinationKind;
  url: string;
  description: string;
  events: string[];
  credential: string;
  config: Record<string, string>;
}

/** What's missing before the form can be sent, or null when it's complete. */
export function missing(d: DestinationDraft): string | null {
  const spec = DESTINATIONS[d.kind];
  if (!d.url.trim()) return `Enter the ${spec.urlLabel.toLowerCase()}`;
  if (spec.credentialLabel && !d.credential.trim()) return `Enter the ${spec.credentialLabel.toLowerCase()}`;
  const field = spec.fields.find((f) => !f.optional && !d.config[f.key]?.trim());
  if (field) return `Enter the ${field.label.toLowerCase()}`;
  if (d.events.length === 0) return "Choose at least one event";
  return null;
}

/** The body for `POST /api/webhooks`. Empty optional settings are left out. */
export function createBody(d: DestinationDraft) {
  const spec = DESTINATIONS[d.kind];
  const config: Record<string, string> = {};
  for (const f of spec.fields) {
    const v = d.config[f.key]?.trim();
    if (v) config[f.key] = v;
  }
  return {
    kind: d.kind,
    url: d.url.trim(),
    events: d.events,
    description: d.description.trim() || undefined,
    ...(spec.credentialLabel ? { credential: d.credential.trim(), config } : {}),
  };
}

/** "400: {"error":"enter the HEC token"}" → "Enter the HEC token". */
export function apiErrorMessage(err: unknown, fallback: string): string {
  if (!(err instanceof Error)) return fallback;
  const json = err.message.replace(/^\d{3}:\s*/, "");
  try {
    const parsed = JSON.parse(json) as { error?: unknown };
    if (typeof parsed.error === "string" && parsed.error) {
      return parsed.error.charAt(0).toUpperCase() + parsed.error.slice(1);
    }
  } catch {
    // not JSON
  }
  return /^\d{3}:/.test(err.message) ? fallback : err.message;
}

/** One line about where a destination sends, for the list. */
export function destinationSummary(kind: DestinationKind, config: Record<string, unknown> | null | undefined): string {
  const c = config ?? {};
  if (kind === "splunk") {
    return `Splunk HEC · index ${typeof c.index === "string" ? c.index : "default"} · ${typeof c.sourcetype === "string" ? c.sourcetype : "verdyx:event"}`;
  }
  if (kind === "sentinel") {
    return `Microsoft Sentinel · ${typeof c.streamName === "string" ? c.streamName : "Custom-VerdyxEvents_CL"}`;
  }
  return "Webhook · signed JSON";
}
