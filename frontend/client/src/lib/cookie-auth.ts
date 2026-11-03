/**
 * Older versions copied login tokens into cookies that page scripts could read.
 * Sessions now live in HttpOnly cookies set by the API, so this only removes
 * those leftovers.
 */
const LEGACY_COOKIES = ["verdyx_access_token", "verdyx_refresh_token", "verdyx_user"];

export function clearAuthCookies(): void {
  if (typeof document === "undefined") return;
  for (const name of LEGACY_COOKIES) {
    document.cookie = `${name}=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/`;
  }
}
