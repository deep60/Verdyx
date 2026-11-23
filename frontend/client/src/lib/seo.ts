export const SITE = "https://verdyx.dev";
export const OG_IMAGE = `${SITE}/og-image.png`;

/** Page title with the brand appended once (never "Verdyx — … | Verdyx"). */
export function pageTitle(title: string): string {
  return /verdyx/i.test(title) ? title : `${title} | Verdyx`;
}

/** Canonical URL for a path: no query string, hash or trailing slash. */
export function canonicalUrl(path: string): string {
  const clean = path.split(/[?#]/)[0].replace(/\/+$/, "");
  return `${SITE}${clean || "/"}`;
}
