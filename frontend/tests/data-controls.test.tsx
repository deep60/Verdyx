import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { DataControls, fromValue, policySentence, retentionLabel, toValue } from "@/components/data-controls";

describe("retention choices", () => {
  it("label and round-trip", () => {
    expect(retentionLabel(null)).toBe("Keep until deleted");
    expect(retentionLabel(90)).toBe("Delete after 90 days");
    expect(retentionLabel(365)).toBe("Delete after 1 year");
    for (const d of [null, 30, 90, 180, 365]) expect(fromValue(toValue(d))).toBe(d);
  });

  it("describe what Verdyx deletes by itself", () => {
    expect(policySentence({ sampleRetentionDays: 30, guestScanRetentionDays: 90 })).toBe(
      "Uploaded files are deleted 30 days after a scan; its results stay. Scans made while signed out are deleted after 90 days.",
    );
    // Bounty scans are only mentioned when the bounty features are switched on.
    expect(policySentence({ sampleRetentionDays: null, guestScanRetentionDays: null })).toBe("");
  });
});

describe("data tab", () => {
  it("shows the current choice, the policy and the export link", () => {
    const client = new QueryClient();
    client.setQueryData(["/api/users/me/retention"], {
      scanRetentionDays: 180,
      sampleRetentionDays: 30,
      guestScanRetentionDays: 90,
      choices: [30, 90, 180, 365],
    });
    const html = renderToStaticMarkup(
      <QueryClientProvider client={client}>
        <DataControls />
      </QueryClientProvider>,
    );
    expect(html).toContain("Keep my scans");
    // Radix renders the selected label only in the browser; check the control.
    expect(html).toContain('aria-label="How long to keep my scans"');
    expect(html).toContain("Uploaded files are deleted 30 days after a scan");
    expect(html).toContain('href="/api/users/me/export"');
    expect(html).toContain("Download my data");
  });
});
