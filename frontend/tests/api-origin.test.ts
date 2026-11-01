import { afterEach, describe, expect, it, vi } from "vitest";
import { directApiUrl, installDirectApi, webSocketUrl } from "../client/src/lib/api-origin";

const ORIGIN = "https://api.example.com";

describe("directApiUrl", () => {
  it.each([
    ["/api/v1/health", "/api/v1/health"],
    ["/api/submissions/file", "/api/v1/submissions/file"],
    ["/api/stats?range=24h", "/api/v1/stats?range=24h"],
  ])("sends %s to the gateway", (path, expected) => {
    expect(directApiUrl(path, ORIGIN)).toBe(`${ORIGIN}${expected}`);
  });

  it.each(["/api", "/apiary", "/dashboard", "https://rdap.org/domain/a.com"])(
    "leaves %s alone",
    (path) => {
      expect(directApiUrl(path, ORIGIN)).toBeNull();
    }
  );

  it("stays same-origin when no origin is configured", () => {
    expect(directApiUrl("/api/v1/health", "")).toBeNull();
  });
});

describe("webSocketUrl", () => {
  it("connects to the gateway over a secure socket", () => {
    expect(webSocketUrl(ORIGIN)).toBe("wss://api.example.com/ws");
  });
});

describe("installDirectApi", () => {
  const originalFetch = window.fetch;

  afterEach(() => {
    window.fetch = originalFetch;
  });

  it("rewrites API calls, keeps their options and drops the CSRF header", async () => {
    const native = vi.fn(async () => new Response("{}"));
    window.fetch = native as typeof window.fetch;
    installDirectApi(ORIGIN);

    await window.fetch("/api/submissions", {
      method: "POST",
      credentials: "include",
      headers: { Authorization: "Bearer t", "X-CSRF-Token": "c" },
    });

    const [url, init] = native.mock.calls[0] as unknown as [string, RequestInit];
    const headers = new Headers(init.headers);
    expect(url).toBe(`${ORIGIN}/api/v1/submissions`);
    expect(init.method).toBe("POST");
    expect(init.credentials).toBe("include");
    expect(headers.get("Authorization")).toBe("Bearer t");
    expect(headers.has("X-CSRF-Token")).toBe(false);
  });

  it("does not touch other requests", async () => {
    const native = vi.fn(async () => new Response("{}"));
    window.fetch = native as typeof window.fetch;
    installDirectApi(ORIGIN);

    await window.fetch("https://rdap.org/domain/a.com");

    expect(native.mock.calls[0][0 as never]).toBe("https://rdap.org/domain/a.com");
  });
});
