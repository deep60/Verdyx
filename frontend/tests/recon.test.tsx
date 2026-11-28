import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { ReconPanel, filterSubdomains, type ReconData, type ReconSubdomain } from "@/components/recon-panel";

const items: ReconSubdomain[] = [
  { name: "api.example.com", status: "live", ips: ["198.51.100.4"], cname: null },
  { name: "old.example.com", status: "nxdomain", ips: [], cname: "gone.herokuapp.com" },
  { name: "mail.example.com", status: "no-address", ips: [], cname: null },
  { name: "zz.example.com", status: "unchecked", ips: [], cname: null },
];

const data: ReconData = {
  host: "www.example.com",
  rootDomain: "example.com",
  durationMs: 4200,
  subdomains: {
    available: true,
    source: "Certificate Transparency (Cert Spotter)",
    error: null,
    total: 4,
    truncated: false,
    checked: 3,
    live: 1,
    items,
  },
  takeovers: {
    checked: 3,
    withCname: 1,
    candidates: [
      {
        subdomain: "old.example.com",
        cname: "gone.herokuapp.com",
        service: "Heroku",
        level: "likely",
        evidence: "CNAME points to gone.herokuapp.com on Heroku, which doesn't exist.",
      },
    ],
  },
  archivedUrls: {
    available: true,
    total: 3,
    withParams: ["https://www.example.com/search?q=1"],
    paramNames: ["q"],
    interestingFiles: ["https://www.example.com/backup.sql"],
    javascriptFiles: [],
    interestingPaths: ["https://www.example.com/admin/"],
    all: [],
  },
  javascript: {
    available: true,
    scripts: [{ url: "https://www.example.com/app.js", status: "read", bytes: 1000 }],
    endpointCount: 2,
    endpoints: ["/api/v2/orders", "https://api.example.com/graphql"],
    exposedKeys: [
      {
        kind: "AWS access key ID",
        masked: "AKIA…MNOP",
        source: "https://www.example.com/app.js",
        note: "Look nearby.",
      },
    ],
  },
  scope: "Only test what a program's scope allows.",
};

function render(value: ReconData | undefined) {
  const client = new QueryClient();
  if (value) client.setQueryData(["/api/analysis/web-recon", "https://www.example.com/"], value);
  return renderToStaticMarkup(
    <QueryClientProvider client={client}>
      <ReconPanel url="https://www.example.com/" />
    </QueryClientProvider>,
  );
}

describe("recon", () => {
  it("filters subdomains by status and search", () => {
    expect(filterSubdomains(items, "all", "").length).toBe(4);
    expect(filterSubdomains(items, "live", "").map((s) => s.name)).toEqual(["api.example.com"]);
    expect(filterSubdomains(items, "dead", "").map((s) => s.name)).toEqual(["old.example.com", "mail.example.com"]);
    expect(filterSubdomains(items, "unchecked", "").map((s) => s.name)).toEqual(["zz.example.com"]);
    expect(filterSubdomains(items, "all", "heroku").map((s) => s.name)).toEqual(["old.example.com"]);
    expect(filterSubdomains(items, "all", "198.51").map((s) => s.name)).toEqual(["api.example.com"]);
  });

  it("shows subdomains, takeovers, archived URLs, endpoints and masked keys", () => {
    const html = render(data);
    expect(html).toContain("Recon for bug bounty hunters");
    expect(html).toContain("1 live of 3 checked");
    expect(html).toContain("Possible subdomain takeovers (1)");
    expect(html).toContain("gone.herokuapp.com");
    expect(html).toContain("Likely");
    expect(html).toContain("Doesn&#x27;t resolve");
    expect(html).toContain("Not checked");
    expect(html).toContain("https://www.example.com/search?q=1");
    expect(html).toContain("With parameters (1)");
    expect(html).toContain("/api/v2/orders");
    expect(html).toContain("AKIA…MNOP");
  });

  it("says a source was unavailable instead of showing zero", () => {
    const html = render({
      ...data,
      subdomains: {
        ...data.subdomains,
        available: false,
        error: "Cert Spotter: timed out; crt.sh: HTTP 502",
        total: 0,
        live: 0,
        checked: 0,
        items: [],
      },
      takeovers: { checked: 0, withCname: 0, candidates: [] },
      archivedUrls: { available: false, error: "Wayback Machine: timed out" },
    });
    expect(html).toContain("Certificate logs unavailable: Cert Spotter: timed out; crt.sh: HTTP 502");
    expect(html).toContain("The Wayback Machine unavailable: Wayback Machine: timed out");
    expect(html).not.toContain("Subdomains (0)");
    expect(html).not.toContain("Possible subdomain takeovers");
  });
});
