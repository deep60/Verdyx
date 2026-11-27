import { describe, expect, it, vi } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { TeamSso } from "@/components/team-sso";
import { describe as describeEvent } from "@/components/audit-log";
import {
  domainOf,
  isSsoRequired,
  setupSteps,
  ssoErrorFromUrl,
  ssoRequestedInUrl,
  ssoStartPath,
  type TeamSsoSettings,
} from "@/lib/sso";

const settings = (over: Partial<TeamSsoSettings> = {}): TeamSsoSettings => ({
  domains: [
    {
      domain: "acme.com",
      verified: false,
      record: { type: "TXT", name: "_verdyx-challenge.acme.com", value: "verdyx-domain-verification=abc" },
    },
  ],
  sso: { issuer: null, clientId: null, hasClientSecret: false, enabled: false, required: false, joinRole: "member" },
  callbackUrl: "https://verdyx.dev/api/v1/auth/sso/callback",
  signInUrl: "https://verdyx.dev/login?sso=1",
  scim: { baseUrl: "https://api.verdyx.dev/scim/v2", hasToken: false, tokenHint: null, tokenCreatedAt: null, provisionedUsers: 0 },
  ...over,
});

describe("signing in with SSO", () => {
  it("sends only the domain, never the address", () => {
    expect(domainOf(" Ada@Acme.COM ")).toBe("acme.com");
    expect(domainOf("ada")).toBe("");
    expect(domainOf("ada@localhost")).toBe("");
    expect(ssoStartPath("acme.com")).toBe("/api/v1/auth/sso/start?domain=acme.com");
    expect(ssoStartPath("acme.com")).not.toContain("@");
  });

  it("explains each failure the API sends back, and nothing else", () => {
    expect(ssoErrorFromUrl("?sso_error=wrong_domain")).toMatch(/outside your team's verified domains/);
    expect(ssoErrorFromUrl("?sso_error=<script>")).toBe("Sign-in didn't work. Please try again.");
    expect(ssoErrorFromUrl("?other=1")).toBe("");
    expect(ssoRequestedInUrl("?sso=1")).toBe(true);
    expect(ssoRequestedInUrl("?sso_error=expired")).toBe(true);
    expect(ssoRequestedInUrl("")).toBe(false);
  });

  it("recognises a team that requires SSO", () => {
    expect(isSsoRequired(new Error("Acme signs in with single sign-on. Use \"Sign in with SSO\"."))).toBe(true);
    expect(isSsoRequired(new Error("Invalid credentials"))).toBe(false);
    expect(isSsoRequired("single sign-on")).toBe(false);
  });

  it("checks the domain before leaving the page", async () => {
    const { SsoSignIn } = await import("@/components/sso-sign-in");
    expect(renderToStaticMarkup(<SsoSignIn onError={vi.fn()} initialEmail="ada@acme.com" />)).toContain(
      'value="ada@acme.com"',
    );
  });
});

const render = (data: TeamSsoSettings) => {
  const client = new QueryClient();
  client.setQueryData(["/api/orgs/t1/sso"], data);
  return renderToStaticMarkup(
    <QueryClientProvider client={client}>
      <TeamSso teamId="t1" teamName="Blue Team" />
    </QueryClientProvider>,
  );
};

describe("team sign-in settings", () => {
  it("walks through the setup in order", () => {
    expect(setupSteps(settings()).map((s) => s.done)).toEqual([false, false, false]);
    const ready = settings({
      domains: [{ ...settings().domains[0], verified: true }],
      sso: { issuer: "https://acme.okta.com", clientId: "c", hasClientSecret: true, enabled: true, required: false, joinRole: "member" },
    });
    expect(setupSteps(ready).map((s) => s.done)).toEqual([true, true, true]);
  });

  it("shows the TXT record to add, and can't be turned on before a domain is proven", () => {
    const html = render(settings());
    expect(html).toContain("_verdyx-challenge.acme.com");
    expect(html).toContain("verdyx-domain-verification=abc");
    expect(html).toContain("https://verdyx.dev/api/v1/auth/sso/callback");
    expect(html).toContain("https://api.verdyx.dev/scim/v2");
    expect(html).toMatch(/data-testid="sso-enabled"[^>]*disabled|disabled[^>]*data-testid="sso-enabled"/);
    expect(html).toMatch(/data-testid="sso-required"[^>]*disabled|disabled[^>]*data-testid="sso-required"/);
    expect(html).toContain("Make a token");
  });

  it("never shows a saved client secret or token", () => {
    const html = render(
      settings({
        domains: [{ ...settings().domains[0], verified: true }],
        sso: { issuer: "https://acme.okta.com", clientId: "client-1", hasClientSecret: true, enabled: true, required: true, joinRole: "viewer" },
        scim: { baseUrl: "https://api.verdyx.dev/scim/v2", hasToken: true, tokenHint: "scim_…a1b2", tokenCreatedAt: null, provisionedUsers: 3 },
      }),
    );
    expect(html).toContain("Saved. Enter a new one to replace it");
    expect(html).toContain("scim_…a1b2");
    expect(html).toContain("3 provisioned now.");
    expect(html).toContain("Replace token");
    expect(html).not.toContain("_verdyx-challenge.acme.com"); // verified: no record to add
  });
});

describe("activity log", () => {
  const event = (action: string, details: Record<string, unknown> = {}) =>
    ({ id: 1, action, details, createdAt: "2026-11-27T00:00:00Z" }) as never;
  it("describes the SSO events", () => {
    expect(describeEvent(event("auth.login", { method: "sso" }))).toBe("Signed in with single sign-on");
    expect(describeEvent(event("auth.login_failed", { reason: "sso_required" }))).toMatch(/requires single sign-on/);
    expect(describeEvent(event("team.sso_changed", { enabled: true, required: true }))).toBe(
      "Turned single sign-on on, and required it",
    );
    expect(describeEvent(event("team.domain_verified", { domain: "acme.com" }))).toBe("Verified the domain acme.com");
    expect(describeEvent(event("team.member.deprovisioned"))).toBe("someone was removed by the identity provider");
  });
});
