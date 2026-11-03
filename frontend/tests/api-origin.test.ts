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

  it("rewrites API calls, keeps their options and marks them as web app calls", async () => {
    const native = vi.fn(async () => new Response("{}"));
    window.fetch = native as typeof window.fetch;
    installDirectApi(ORIGIN);

    await window.fetch("/api/submissions", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": "c" },
    });

    const [url, init] = native.mock.calls[0] as unknown as [string, RequestInit];
    const headers = new Headers(init.headers);
    expect(url).toBe(`${ORIGIN}/api/v1/submissions`);
    expect(init.method).toBe("POST");
    expect(init.credentials).toBe("include");
    expect(headers.get("Content-Type")).toBe("application/json");
    expect(headers.get("X-Verdyx-Client")).toBe("web");
    expect(headers.has("X-CSRF-Token")).toBe(false);
  });

  it("sends the session cookie on same-origin API calls too", async () => {
    const native = vi.fn(async () => new Response("{}"));
    window.fetch = native as typeof window.fetch;
    installDirectApi("");

    await window.fetch("/api/v1/auth/verify");

    const [url, init] = native.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe("/api/v1/auth/verify");
    expect(init.credentials).toBe("include");
    expect(new Headers(init.headers).get("X-Verdyx-Client")).toBe("web");
  });

  it("does not touch other requests", async () => {
    const native = vi.fn(async () => new Response("{}"));
    window.fetch = native as typeof window.fetch;
    installDirectApi(ORIGIN);

    await window.fetch("https://rdap.org/domain/a.com");

    expect(native.mock.calls[0]).toEqual(["https://rdap.org/domain/a.com", undefined]);
  });
});
