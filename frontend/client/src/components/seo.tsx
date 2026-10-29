export function SEO({ title, description, url = "https://verdyx.io" }: { title: string; description: string; url?: string }) {
  // In React 19, these tags are automatically hoisted to the document <head>.
  // NOTE: <title> must have exactly ONE string child — `{title} | Verdyx` would
  // pass two children and React silently declines to hoist it, leaving the page
  // with no title at all. Keep the template literal.
  return (
    <>
      <title>{`${title} | Verdyx`}</title>
      <meta name="description" content={description} />
      
      {/* Open Graph */}
      <meta property="og:type" content="website" />
      <meta property="og:url" content={url} />
      <meta property="og:title" content={`${title} | Verdyx`} />
      <meta property="og:description" content={description} />
      <meta property="og:image" content={`${url}/verdyx-logo.svg`} />
      
      {/* Twitter */}
      <meta name="twitter:card" content="summary_large_image" />
      <meta name="twitter:url" content={url} />
      <meta name="twitter:title" content={`${title} | Verdyx`} />
      <meta name="twitter:description" content={description} />
      <meta name="twitter:image" content={`${url}/verdyx-logo.svg`} />
    </>
  );
}
