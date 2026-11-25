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

  describe("renewing an expired session", () => {
    const status = (code: number) => new Response("{}", { status: code });
    const calls = (native: ReturnType<typeof vi.fn>) =>
      native.mock.calls.map((c) => {
        const [url, init] = c as unknown as [string, RequestInit | undefined];
        return `${init?.method ?? "GET"} ${url}`;
      });

    it("renews once on 401 and retries the call with the same body", async () => {
      const replies = [status(401), status(200), new Response('{"api_key":"vdx_x"}', { status: 200 })];
      const native = vi.fn(async () => replies.shift()!);
      window.fetch = native as typeof window.fetch;
      installDirectApi("");

      const body = JSON.stringify({ name: "CLI" });
      const res = await window.fetch("/api/auth/api-key", { method: "POST", body });

      expect(res.status).toBe(200);
      expect(await res.json()).toEqual({ api_key: "vdx_x" });
      expect(calls(native)).toEqual(["POST /api/auth/api-key", "POST /api/v1/auth/refresh", "POST /api/auth/api-key"]);
      const retry = native.mock.calls[2] as unknown as [string, RequestInit];
      expect(retry[1].body).toBe(body);
      expect(retry[1].credentials).toBe("include");
      expect(new Headers(retry[1].headers).get("X-Verdyx-Client")).toBe("web");
      const refresh = native.mock.calls[1] as unknown as [string, RequestInit];
      expect(new Headers(refresh[1].headers).get("X-Verdyx-Client")).toBe("web");
    });

    it("renews against the gateway when an API origin is set", async () => {
      const replies = [status(401), status(200), status(200)];
      const native = vi.fn(async () => replies.shift()!);
      window.fetch = native as typeof window.fetch;
      installDirectApi(ORIGIN);

      await window.fetch("/api/users/me");

      expect(calls(native)).toEqual([
        `GET ${ORIGIN}/api/v1/users/me`,
        `POST ${ORIGIN}/api/v1/auth/refresh`,
        `GET ${ORIGIN}/api/v1/users/me`,
      ]);
    });

    it("returns the original 401 when renewal fails, without retrying", async () => {
      const replies = [status(401), status(401)];
      const native = vi.fn(async () => replies.shift()!);
      window.fetch = native as typeof window.fetch;
      installDirectApi("");

      const res = await window.fetch("/api/auth/api-key", { method: "POST" });

      expect(res.status).toBe(401);
      expect(native).toHaveBeenCalledTimes(2);
    });

    it.each([
      "/api/v1/auth/login",
      "/api/auth/register",
      "/api/v1/auth/refresh",
      "/api/v1/auth/verify",
      "/api/v1/auth/logout",
      "/api/v1/auth/oauth/github",
    ])("leaves a 401 from %s alone", async (path) => {
      const native = vi.fn(async () => status(401));
      window.fetch = native as typeof window.fetch;
      installDirectApi("");

      const res = await window.fetch(path, { method: "POST" });

      expect(res.status).toBe(401);
      expect(native).toHaveBeenCalledTimes(1);
    });

    it("shares one renewal between calls that fail together", async () => {
      let refreshes = 0;
      let expired = true;
      const native = vi.fn(async (url: string) => {
        if (url.endsWith("/auth/refresh")) {
          refreshes++;
          await new Promise((r) => setTimeout(r, 10));
          expired = false;
          return status(200);
        }
        return status(expired ? 401 : 200);
      });
      window.fetch = native as unknown as typeof window.fetch;
      installDirectApi("");

      const results = await Promise.all([window.fetch("/api/users/me"), window.fetch("/api/submissions")]);

      expect(results.map((r) => r.status)).toEqual([200, 200]);
      expect(refreshes).toBe(1);
    });

    it("does not retry other errors", async () => {
      const native = vi.fn(async () => status(403));
      window.fetch = native as typeof window.fetch;
      installDirectApi("");

      expect((await window.fetch("/api/users/me")).status).toBe(403);
      expect(native).toHaveBeenCalledTimes(1);
    });
  });

  it("does not touch other requests", async () => {
    const native = vi.fn(async () => new Response("{}"));
    window.fetch = native as typeof window.fetch;
    installDirectApi(ORIGIN);

    await window.fetch("https://rdap.org/domain/a.com");

    expect(native.mock.calls[0]).toEqual(["https://rdap.org/domain/a.com", undefined]);
  });
});
