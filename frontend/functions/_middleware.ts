/**
 * Sends verdyx.pages.dev visitors to verdyx.dev.
 *
 * The login session is an HttpOnly cookie on api.verdyx.dev. Browsers treat it as
 * a third-party cookie on verdyx.pages.dev and won't send it, so signing in only
 * works on verdyx.dev. Preview deployments (<hash>.verdyx.pages.dev) are left alone.
 */
export const onRequest: PagesFunction = async ({ request, next }) => {
  const url = new URL(request.url);
  if (url.hostname === "verdyx.pages.dev") {
    url.hostname = "verdyx.dev";
    return Response.redirect(url.toString(), 301);
  }
  return next();
};
