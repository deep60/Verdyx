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

/** Sends every relative /api call to the gateway, so call sites stay unchanged. */
export function installDirectApi(origin: string = API_ORIGIN): void {
  if (!origin) return;

  const nativeFetch = window.fetch.bind(window);
  window.fetch = (input, init) => {
    const url = typeof input === "string" ? directApiUrl(input, origin) : null;
    if (!url) return nativeFetch(input, init);

    // The gateway ignores this header and its CORS rules reject it.
    const headers = new Headers(init?.headers);
    headers.delete("X-CSRF-Token");
    return nativeFetch(url, { ...init, headers });
  };
}
