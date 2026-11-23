import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { canonicalUrl, pageTitle } from "@/lib/seo";

const root = resolve(__dirname, "..");
const read = (p: string) => readFileSync(resolve(root, p), "utf8");

describe("SEO helpers", () => {
  it("appends the brand once", () => {
    expect(pageTitle("Pricing")).toBe("Pricing | Verdyx");
    expect(pageTitle("Verdyx — Malware verdicts you can audit")).toBe(
      "Verdyx — Malware verdicts you can audit",
    );
    expect(pageTitle("Teams — Verdyx")).toBe("Teams — Verdyx");
  });

  it("builds clean canonical URLs", () => {
    expect(canonicalUrl("/")).toBe("https://verdyx.dev/");
    expect(canonicalUrl("")).toBe("https://verdyx.dev/");
    expect(canonicalUrl("/pricing/")).toBe("https://verdyx.dev/pricing");
    expect(canonicalUrl("/api?tab=keys#top")).toBe("https://verdyx.dev/api");
  });
});

describe("static SEO files", () => {
  const html = read("client/index.html");

  it("index.html has a title, description, share image and valid JSON-LD", () => {
    expect(html).toMatch(/<title[^>]*>[^<]*Verdyx[^<]*<\/title>/);
    expect(html).toMatch(/<meta[^>]*name="description"/);
    expect(html).toContain('content="https://verdyx.dev/og-image.png"');
    const ld = html.match(/<script type="application\/ld\+json">([\s\S]*?)<\/script>/)?.[1];
    expect(ld).toBeTruthy();
    const data = JSON.parse(ld!);
    const types = data["@graph"].map((n: { "@type": string }) => n["@type"]);
    expect(types).toContain("Organization");
    expect(types).toContain("WebSite");
  });

  it("robots.txt points at the sitemap and keeps the API out", () => {
    const robots = read("client/public/robots.txt");
    expect(robots).toContain("Sitemap: https://verdyx.dev/sitemap.xml");
    expect(robots).toMatch(/^Disallow: \/api\/$/m);
    expect(robots).not.toMatch(/^Disallow: \/$/m);
  });

  it("sitemap lists only public pages that robots.txt allows", () => {
    const sitemap = read("client/public/sitemap.xml");
    const robots = read("client/public/robots.txt");
    const locs = [...sitemap.matchAll(/<loc>([^<]+)<\/loc>/g)].map((m) => m[1]);
    expect(locs).toContain("https://verdyx.dev/");
    const disallowed = [...robots.matchAll(/^Disallow: (\S+)$/gm)].map((m) => m[1]);
    for (const loc of locs) {
      const path = new URL(loc).pathname;
      expect(disallowed.some((d) => path.startsWith(d))).toBe(false);
    }
  });
});
