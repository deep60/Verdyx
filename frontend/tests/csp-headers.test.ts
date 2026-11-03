import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

const root = resolve(__dirname, "..");
const headers = readFileSync(resolve(root, "client/public/_headers"), "utf8");
const csp = headers.match(/Content-Security-Policy: (.+)/)?.[1] ?? "";

describe("Content-Security-Policy", () => {
  it("allows each inline script in index.html by its hash", () => {
    const html = readFileSync(resolve(root, "client/index.html"), "utf8");
    const inline = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map((m) => m[1]);
    expect(inline.length).toBeGreaterThan(0);
    for (const script of inline) {
      const hash = createHash("sha256").update(script).digest("base64");
      expect(csp).toContain(`'sha256-${hash}'`);
    }
  });

  it("never allows arbitrary inline or eval'd script", () => {
    const scriptSrc = csp.match(/script-src ([^;]+)/)?.[1] ?? "";
    expect(scriptSrc).not.toContain("'unsafe-inline'");
    expect(scriptSrc).not.toContain("'unsafe-eval'");
    expect(csp).toContain("frame-ancestors 'none'");
  });
});
