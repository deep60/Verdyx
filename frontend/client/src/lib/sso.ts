// Single sign-on for teams: types and helpers for the login page and the
// team's sign-in settings. The server checks everything; these decide what
// to show.

import type { TeamRole } from "@/lib/teams";

export interface TeamDomain {
  domain: string;
  verified: boolean;
  verifiedAt?: string | null;
  record: { type: "TXT"; name: string; value: string };
}

export interface TeamSsoSettings {
  domains: TeamDomain[];
  sso: {
    issuer: string | null;
    clientId: string | null;
    hasClientSecret: boolean;
    enabled: boolean;
    required: boolean;
    joinRole: Exclude<TeamRole, "owner">;
  };
  callbackUrl: string;
  signInUrl: string;
  scim: {
    baseUrl: string;
    hasToken: boolean;
    tokenHint: string | null;
    tokenCreatedAt: string | null;
    provisionedUsers: number;
  };
}

/** Messages for the fixed codes the API puts in `?sso_error=` on /login. */
const SSO_ERRORS: Record<string, string> = {
  not_set_up: "Single sign-on isn't set up for that email domain. Sign in another way, or ask your team's admin.",
  cancelled: "Sign-in was cancelled.",
  expired: "That sign-in took too long or was opened in another browser. Please try again.",
  no_email: "Your identity provider didn't send an email address. Ask your admin to include the email claim.",
  unverified_email: "Your identity provider says your email address isn't verified.",
  wrong_domain: "Your identity provider signed you in with an address outside your team's verified domains.",
  two_factor:
    "This account uses Verdyx two-factor authentication. Sign in with your password and code instead.",
  suspended: "This account is suspended.",
  provider: "Your identity provider refused the sign-in, or couldn't be reached. Ask your team's admin to check the setup.",
  failed: "Sign-in didn't work. Please try again.",
};

export function ssoErrorFromUrl(search = typeof window === "undefined" ? "" : window.location.search): string {
  const code = new URLSearchParams(search).get("sso_error");
  return code ? (SSO_ERRORS[code] ?? SSO_ERRORS.failed) : "";
}

/** Whether the login page should open on "Sign in with SSO". */
export function ssoRequestedInUrl(search = typeof window === "undefined" ? "" : window.location.search): boolean {
  const params = new URLSearchParams(search);
  return params.get("sso") === "1" || params.has("sso_error");
}

/** The domain of a work email, or "" if it isn't one. */
export function domainOf(email: string): string {
  const e = email.trim().toLowerCase();
  const at = e.lastIndexOf("@");
  if (at < 1) return "";
  const domain = e.slice(at + 1);
  return /^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(domain) ? domain : "";
}

/**
 * Where to send the browser. Only the domain goes in the URL, so the address
 * itself never lands in a link or a server log.
 */
export function ssoStartPath(domain: string): string {
  return `/api/v1/auth/sso/start?domain=${encodeURIComponent(domain)}`;
}

/** The API refused a password sign-in because the team requires SSO. */
export function isSsoRequired(err: unknown): boolean {
  return err instanceof Error && /single sign-on/i.test(err.message);
}

/** What the team's sign-in tab says is left to do, in order. */
export function setupSteps(s: TeamSsoSettings): { label: string; done: boolean }[] {
  return [
    { label: "Prove an email domain", done: s.domains.some((d) => d.verified) },
    {
      label: "Connect your identity provider",
      done: Boolean(s.sso.issuer && s.sso.clientId && s.sso.hasClientSecret),
    },
    { label: "Turn on single sign-on", done: s.sso.enabled },
  ];
}
