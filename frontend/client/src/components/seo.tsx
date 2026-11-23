import { useEffect } from "react";
import { OG_IMAGE, canonicalUrl, pageTitle } from "@/lib/seo";

export function SEO({
  title,
  description,
  path,
  noindex = false,
}: {
  title: string;
  description: string;
  /** Path for the canonical URL. Defaults to the current location. */
  path?: string;
  /** Keep private or per-user pages (dashboard, scans, sign-in flows) out of search. */
  noindex?: boolean;
}) {
  // index.html carries default tags for crawlers that do not run JavaScript.
  // Remove them so this page's tags are the only ones (the browser uses the
  // first <title>, and React 19 appends hoisted tags after the static ones).
  useEffect(() => {
    document.head.querySelectorAll("[data-seo-default]").forEach((el) => el.remove());
  }, []);

  const fullTitle = pageTitle(title);
  const url = canonicalUrl(
    path ?? (typeof window !== "undefined" ? window.location.pathname : "/"),
  );

  // In React 19, these tags are automatically hoisted to the document <head>.
  // NOTE: <title> must have exactly ONE string child, so pass a single string.
  return (
    <>
      <title>{fullTitle}</title>
      <meta name="description" content={description} />
      {noindex ? (
        <meta name="robots" content="noindex, nofollow" />
      ) : (
        <link rel="canonical" href={url} />
      )}

      {/* Open Graph */}
      <meta property="og:type" content="website" />
      <meta property="og:url" content={url} />
      <meta property="og:title" content={fullTitle} />
      <meta property="og:description" content={description} />
      <meta property="og:image" content={OG_IMAGE} />
      <meta property="og:image:width" content="1200" />
      <meta property="og:image:height" content="630" />

      {/* Twitter */}
      <meta name="twitter:card" content="summary_large_image" />
      <meta name="twitter:title" content={fullTitle} />
      <meta name="twitter:description" content={description} />
      <meta name="twitter:image" content={OG_IMAGE} />
    </>
  );
}
