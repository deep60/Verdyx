/**
 * Error reporting to Sentry.
 *
 * Off unless the site was built with VITE_SENTRY_DSN. When on, the Sentry
 * SDK is loaded as a separate chunk after the app starts, so pages without
 * errors don't pay for it up front.
 *
 * Sent: uncaught errors, unhandled promise rejections, errors caught by the
 * error boundary, and the page address with its query string removed (reset
 * links carry their code in the query). Not sent: IP addresses, cookies,
 * request bodies, form input, or performance traces.
 */

type SentryModule = typeof import("@sentry/react");

let sentry: SentryModule | null = null;
const queued: { error: unknown; context?: Record<string, unknown> }[] = [];

/** `https://verdyx.dev/reset-password?token=x#y` → `https://verdyx.dev/reset-password`. */
export function stripQuery(url: string | undefined): string | undefined {
  if (!url) return url;
  const cut = url.search(/[?#]/);
  return cut === -1 ? url : url.slice(0, cut);
}

/** Remove query strings from everything in an event that holds a URL. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function scrubEvent<T extends Record<string, any>>(event: T): T {
  if (event.request) {
    event.request.url = stripQuery(event.request.url);
    delete event.request.query_string;
    delete event.request.cookies;
    delete event.request.headers;
    delete event.request.data;
  }
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const crumbs: any[] | undefined = event.breadcrumbs;
  for (const crumb of crumbs ?? []) {
    if (crumb?.data) {
      for (const key of ["url", "from", "to"]) {
        if (typeof crumb.data[key] === "string") crumb.data[key] = stripQuery(crumb.data[key]);
      }
    }
  }
  return event;
}

export async function initErrorReporting(): Promise<void> {
  const dsn = import.meta.env.VITE_SENTRY_DSN as string | undefined;
  if (!dsn || sentry) return;
  const S = await import("@sentry/react");
  S.init({
    dsn,
    environment: import.meta.env.MODE,
    release: (import.meta.env.VITE_RELEASE as string | undefined) || undefined,
    sendDefaultPii: false,
    tracesSampleRate: 0,
    // No replay, no feedback widget: errors only.
    integrations: (defaults) => defaults.filter((i) => i.name !== "Replay"),
    beforeSend: (event) => scrubEvent(event),
    beforeBreadcrumb: (crumb) => {
      // Console lines can echo anything a page logged; keep warnings and errors only.
      if (crumb.category === "console" && crumb.level !== "warning" && crumb.level !== "error") return null;
      return crumb;
    },
  });
  S.setTag("service", "website");
  sentry = S;
  for (const q of queued.splice(0)) S.captureException(q.error, q.context ? { extra: q.context } : undefined);
}

/** Report a caught error. Queued until Sentry has loaded; dropped if it's off. */
export function reportError(error: unknown, context?: Record<string, unknown>): void {
  if (sentry) {
    sentry.captureException(error, context ? { extra: context } : undefined);
  } else if (import.meta.env.VITE_SENTRY_DSN && queued.length < 20) {
    queued.push({ error, context });
  }
}
