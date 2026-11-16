import { describe, expect, it } from "vitest";
import { reportError, scrubEvent, stripQuery } from "@/lib/error-reporting";

describe("error reporting", () => {
  it("strips query strings and fragments", () => {
    expect(stripQuery("https://verdyx.dev/reset-password?token=abc#x")).toBe("https://verdyx.dev/reset-password");
    expect(stripQuery("https://verdyx.dev/scan")).toBe("https://verdyx.dev/scan");
    expect(stripQuery(undefined)).toBeUndefined();
  });

  it("removes secrets and personal data from events", () => {
    const event = scrubEvent({
      request: {
        url: "https://verdyx.dev/reset-password?token=abc",
        query_string: "token=abc",
        cookies: { verdyx_access: "x" },
        headers: { Cookie: "x" },
        data: "password=hunter2",
      },
      breadcrumbs: [
        { category: "navigation", data: { from: "/a?token=1", to: "/reset-password?token=abc" } },
        { category: "fetch", data: { url: "https://api.verdyx.dev/api/v1/x?key=y", method: "GET" } },
      ],
    });
    expect(event.request.url).toBe("https://verdyx.dev/reset-password");
    expect(event.request).not.toHaveProperty("query_string");
    expect(event.request).not.toHaveProperty("cookies");
    expect(event.request).not.toHaveProperty("headers");
    expect(event.request).not.toHaveProperty("data");
    expect(event.breadcrumbs[0].data).toEqual({ from: "/a", to: "/reset-password" });
    expect(event.breadcrumbs[1].data.url).toBe("https://api.verdyx.dev/api/v1/x");
  });

  it("does nothing without a DSN", () => {
    expect(() => reportError(new Error("boom"))).not.toThrow();
  });
});
