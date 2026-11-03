// Cloudflare's Pages proxy intermittently fails to reach the Oracle VM with error
// 1016, and retrying inside the Function doesn't help. Pages builds therefore set
// VITE_API_ORIGIN so the browser calls the gateway directly. Without it, requests
// stay same-origin for the local BFF.
const API_ORIGIN = String(import.meta.env.VITE_API_ORIGIN ?? "").replace(/\/$/, "");

const API_PREFIX = new RegExp("^/api/(?:v1/)?");

/** Mirrors normalizeToV1 in functions/api/[[path]].ts. */
export function directApiUrl(path: string, origin: string = API_ORIGIN): string | null {
  if (!origin || !API_PREFIX.test(path)) return null;
  return `${origin}${path.replace(API_PREFIX, "/api/v1/")}`;
}

export function webSocketUrl(origin: string = API_ORIGIN): string {
  if (origin) return `${origin.replace(/^http/, "ws")}/ws`;
  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  return `${protocol}//${window.location.host}/ws`;
}

/** Header the gateway requires before it accepts the session cookie (CSRF guard). */
export const WEB_CLIENT_HEADER = "X-Verdyx-Client";

/**
 * Marks every relative /api call as coming from the web app and sends the
 * HttpOnly session cookie with it. With an API origin configured, also sends
 * the call to the gateway directly, so call sites stay unchanged.
 */
export function installDirectApi(origin: string = API_ORIGIN): void {
  const nativeFetch = window.fetch.bind(window);
  window.fetch = (input, init) => {
    if (typeof input !== "string" || !API_PREFIX.test(input)) return nativeFetch(input, init);

    const headers = new Headers(init?.headers);
    headers.set(WEB_CLIENT_HEADER, "web");
    // The gateway ignores this header and its CORS rules reject it.
    headers.delete("X-CSRF-Token");
    const url = directApiUrl(input, origin) ?? input;
    return nativeFetch(url, { ...init, headers, credentials: "include" });
  };
}
