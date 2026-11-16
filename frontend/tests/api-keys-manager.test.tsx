import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { ApiKeysManager, formatWhen, keyStatus, type ApiKeyItem } from "@/components/api-keys-manager";

const base: ApiKeyItem = {
  id: "k1",
  name: "SOC pipeline",
  prefix: "vdx_1a2b3c4d",
  permissions: ["read", "scan"],
  isActive: true,
  expired: false,
  lastUsedAt: null,
  createdAt: "2026-11-16T10:00:00Z",
  expiresAt: null,
};

describe("API keys manager", () => {
  it("labels key status", () => {
    expect(keyStatus(base)).toBe("active");
    expect(keyStatus({ ...base, isActive: false })).toBe("revoked");
    expect(keyStatus({ ...base, isActive: false, expired: true })).toBe("expired");
  });

  it("formats dates and never-used", () => {
    expect(formatWhen(null)).toBe("never");
    expect(formatWhen("not a date")).toBe("unknown");
    expect(formatWhen("2026-11-16T10:00:00Z")).toMatch(/2026/);
  });

  it("renders the create form with the safe defaults", () => {
    const client = new QueryClient();
    client.setQueryData(["/api/users/me/api-keys"], [base]);
    const html = renderToStaticMarkup(
      <QueryClientProvider client={client}>
        <ApiKeysManager />
      </QueryClientProvider>,
    );
    expect(html).toContain("Create an API key");
    expect(html).toContain("X-API-Key: vdx_…");
    expect(html).toContain("SOC pipeline");
    expect(html).toContain("vdx_1a2b3c4d…");
    expect(html).toContain("last used never");
    expect(html).toContain("no expiry");
  });
});
