import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { WebhooksManager } from "@/components/webhooks-manager";

const at = "2026-11-27T10:00:00Z";

describe("webhooks manager", () => {
  it("offers the three destinations and lists each with what it sends to", () => {
    const client = new QueryClient();
    client.setQueryData(["/api/webhooks"], {
      total: 3,
      webhooks: [
        { id: "w1", url: "https://soc.example.com/hook", events: ["*"], secret: "whsec_abcdef1234567890", is_active: true, created_at: at, kind: "webhook", config: {} },
        { id: "w2", url: "https://splunk.example.com:8088", events: ["*"], secret: "whsec_zzzzzzzzzzzzzzzzzz", is_active: true, created_at: at, kind: "splunk", config: { index: "sec", sourcetype: "verdyx:event" }, has_credential: true },
        { id: "w3", url: "https://x.eastus-1.ingest.monitor.azure.com", events: ["*"], is_active: true, created_at: at, kind: "sentinel", config: { streamName: "Custom-VerdyxEvents_CL" }, has_credential: false },
      ],
    });
    const html = renderToStaticMarkup(
      <QueryClientProvider client={client}>
        <WebhooksManager />
      </QueryClientProvider>,
    );
    for (const k of ["webhook", "splunk", "sentinel"]) expect(html).toContain(`data-testid="destination-${k}"`);
    expect(html).toContain("Destinations (3)");
    expect(html).toContain("Webhook · signed JSON");
    expect(html).toContain("Splunk HEC · index sec · verdyx:event");
    expect(html).toContain("Microsoft Sentinel · Custom-VerdyxEvents_CL · credential missing");
    // The signing key is only offered where it's used: plain webhooks.
    expect(html).toContain("whsec_abcdef12");
    expect(html).not.toContain("whsec_zzzzzzzz");
  });
});
