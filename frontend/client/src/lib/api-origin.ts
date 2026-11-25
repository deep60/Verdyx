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

/** Where TAXII clients find the threat feed (served at the gateway's root). */
export function taxiiDiscoveryUrl(origin: string = API_ORIGIN): string {
  return `${origin || window.location.origin}/taxii2/`;
}

/** Header the gateway requires before it accepts the session cookie (CSRF guard). */
export const WEB_CLIENT_HEADER = "X-Verdyx-Client";

/**
 * Auth routes that must not trigger a session renewal on 401: a wrong password
 * is a real 401, refreshing can't help a refresh, and the session check at
 * page load (auth-context) already renews on its own.
 */
const NO_RENEW = new RegExp(
  "^/api/(?:v1/)?auth/(?:login|register|refresh|logout|verify|forgot-password|reset-password|oauth)(?:[/?]|$)"
);

/**
 * Marks every relative /api call as coming from the web app and sends the
 * HttpOnly session cookie with it. With an API origin configured, also sends
 * the call to the gateway directly, so call sites stay unchanged.
 *
 * A session lasts a day but is only renewed when a page loads, so a tab left
 * open longer kept showing the user as signed in while every action failed
 * with 401. Now a 401 renews the session once (with the refresh cookie) and
 * retries the call; if renewal fails the original 401 is returned as before.
 */
export function installDirectApi(origin: string = API_ORIGIN): void {
  const nativeFetch = window.fetch.bind(window);

  const send = (path: string, init?: RequestInit) => {
    const headers = new Headers(init?.headers);
    headers.set(WEB_CLIENT_HEADER, "web");
    // The gateway ignores this header and its CORS rules reject it.
    headers.delete("X-CSRF-Token");
    const url = directApiUrl(path, origin) ?? path;
    return nativeFetch(url, { ...init, headers, credentials: "include" });
  };

  // One renewal at a time: calls that fail together wait for the same one.
  let renewing: Promise<boolean> | null = null;
  const renew = () => {
    renewing ??= send("/api/v1/auth/refresh", { method: "POST" })
      .then((r) => r.ok)
      .catch(() => false)
      .finally(() => {
        renewing = null;
      });
    return renewing;
  };

  window.fetch = async (input, init) => {
    if (typeof input !== "string" || !API_PREFIX.test(input)) return nativeFetch(input, init);

    const res = await send(input, init);
    // A streamed body can't be sent twice; everything the app sends (JSON
    // strings, FormData, Blobs) can.
    const replayable = !(typeof ReadableStream !== "undefined" && init?.body instanceof ReadableStream);
    if (res.status !== 401 || NO_RENEW.test(input) || !replayable) return res;
    if (!(await renew())) return res;
    return send(input, init);
  };
}
