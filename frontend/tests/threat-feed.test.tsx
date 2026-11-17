import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { ThreatFeedCard } from "@/components/threat-feed-card";
import { taxiiDiscoveryUrl } from "@/lib/api-origin";

describe("threat feed card", () => {
  it("points TAXII clients at the gateway", () => {
    expect(taxiiDiscoveryUrl("https://api.verdyx.dev")).toBe("https://api.verdyx.dev/taxii2/");
  });

  it("explains personal access", () => {
    const html = renderToStaticMarkup(<ThreatFeedCard origin="https://api.verdyx.dev" />);
    expect(html).toContain("https://api.verdyx.dev/taxii2/");
    expect(html).toContain("an API key");
    expect(html).toContain("My scans");
    expect(html).not.toContain("Collection ID");
  });

  it("names a team's collection", () => {
    const html = renderToStaticMarkup(
      <ThreatFeedCard origin="https://api.verdyx.dev" team={{ id: "4f0c2a3e-1111-4222-8333-944455556666", name: "Blue Team" }} />,
    );
    expect(html).toContain("Scans saved to Blue Team");
    expect(html).toContain("Collection ID");
    expect(html).toContain("4f0c2a3e-1111-4222-8333-944455556666");
    expect(html).toContain("a team key");
  });
});
