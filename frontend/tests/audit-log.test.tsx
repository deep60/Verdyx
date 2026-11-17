import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { AuditLog, auditUrl, describe as say, isWarning, shortAgent, type AuditEvent } from "@/components/audit-log";

const me = "11111111-1111-1111-1111-111111111111";
const base: AuditEvent = {
  id: 1,
  occurredAt: "2026-11-17T10:00:00Z",
  action: "auth.login",
  actor: { id: me, username: "ana" },
  via: "session",
  details: {},
};

describe("audit log wording", () => {
  it("describes events plainly", () => {
    expect(say(base)).toBe("Signed in");
    expect(say({ ...base, details: { method: "github" } })).toBe("Signed in with Github");
    expect(say({ ...base, action: "auth.login_failed", actor: null, subject: { id: me } })).toBe(
      "Failed sign-in: wrong password",
    );
    expect(say({ ...base, action: "api_key.created", details: { name: "ci" } })).toBe("Created API key “ci”");
    expect(say({ ...base, action: "account.updated", details: { fields: ["username", "bio"] } })).toBe(
      "Updated profile (username, bio)",
    );
    expect(
      say(
        { ...base, action: "team.member.role_changed", subject: { id: me, username: "ana" }, details: { from: "member", to: "admin" } },
        me,
      ),
    ).toBe("Changed your role from member to admin");
    expect(
      say({ ...base, action: "team.member.role_changed", subject: { id: "x", username: "ben" }, details: { from: "admin", to: "viewer" } }, me),
    ).toBe("Changed ben's role from admin to viewer");
    expect(say({ ...base, action: "team.member.removed", subject: { id: "x", username: "ben" } })).toBe(
      "Removed ben from the team",
    );
    expect(say({ ...base, action: "team.member.removed", subject: { id: "x", username: null } })).toBe(
      "Removed a deleted account from the team",
    );
    expect(say({ ...base, action: "something.new" })).toBe("something.new");
  });

  it("flags failed sign-ins and resets", () => {
    expect(isWarning({ ...base, action: "auth.login_failed" })).toBe(true);
    expect(isWarning(base)).toBe(false);
  });

  it("shortens browsers and builds query URLs", () => {
    expect(
      shortAgent("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15"),
    ).toBe("Safari on macOS");
    expect(shortAgent("Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 Chrome/131.0 Safari/537.36")).toBe("Chrome on Windows");
    expect(shortAgent("curl/8.7.1")).toBe("curl");
    expect(shortAgent(null)).toBe("");
    expect(auditUrl("/api/users/me/audit", "all")).toBe("/api/users/me/audit");
    expect(auditUrl("/api/users/me/audit", "auth.", 42)).toBe("/api/users/me/audit?action=auth.&before=42");
    expect(auditUrl("/api/orgs/t/audit", "all", null, true)).toBe("/api/orgs/t/audit?format=csv");
  });
});

describe("audit log view", () => {
  function render(events: AuditEvent[], personal: boolean) {
    const endpoint = personal ? "/api/users/me/audit" : "/api/orgs/t/audit";
    const client = new QueryClient();
    client.setQueryData([endpoint, "audit", "all"], { pages: [{ events, nextBefore: null }], pageParams: [null] });
    return renderToStaticMarkup(
      <QueryClientProvider client={client}>
        <AuditLog endpoint={endpoint} personal={personal} viewerId={me} />
      </QueryClientProvider>,
    );
  }

  it("shows where your own events came from", () => {
    const html = render(
      [{ ...base, ip: "203.0.113.9", userAgent: "curl/8.7.1" }, { ...base, id: 2, action: "auth.login_failed", actor: null, subject: { id: me } }],
      true,
    );
    expect(html).toContain("Activity");
    expect(html).toContain("You");
    expect(html).toContain("203.0.113.9 · curl");
    expect(html).toContain("Not signed in");
    expect(html).toContain("text-destructive");
    expect(html).toContain("format=csv");
  });

  it("shows a team's log without addresses, and marks API keys", () => {
    const html = render(
      [{ ...base, action: "scan.created", via: "api_key", targetId: "s1", details: { type: "url" }, ip: "203.0.113.9" }],
      false,
    );
    expect(html).toContain("Audit log");
    expect(html).toContain("Submitted a url scan");
    expect(html).toContain("/analysis/s1");
    expect(html).toContain("API key");
    expect(html).not.toContain("203.0.113.9");
  });
});
