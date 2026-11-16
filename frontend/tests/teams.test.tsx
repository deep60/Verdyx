import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { TeamPanel } from "@/pages/teams";
import {
  assignableRoles,
  canEditMember,
  canManage,
  canScan,
  inviteLink,
  serverMessage,
  type TeamDetail,
} from "@/lib/teams";

const team: TeamDetail = {
  id: "t1",
  name: "Blue Team",
  role: "admin",
  createdAt: "2026-11-17T10:00:00Z",
  members: [
    { userId: "u1", role: "owner", joinedAt: "2026-11-17T10:00:00Z", username: "ana", email: "ana@example.com", isYou: false },
    { userId: "u2", role: "admin", joinedAt: "2026-11-17T11:00:00Z", username: "ben", email: "ben@example.com", isYou: true },
    { userId: "u3", role: "viewer", joinedAt: "2026-11-17T12:00:00Z", username: "cy", email: "cy@example.com", isYou: false },
  ],
  invitations: [
    { id: "i1", email: "dee@example.com", role: "member", createdAt: "2026-11-17T12:00:00Z", expiresAt: "2026-11-24T12:00:00Z", expired: false },
  ],
};

function render(detail: TeamDetail, scans: unknown[] = []) {
  const client = new QueryClient();
  client.setQueryData([`/api/orgs/${detail.id}`], detail);
  client.setQueryData([`/api/submissions?organization=${detail.id}&limit=50`], scans);
  return renderToStaticMarkup(
    <QueryClientProvider client={client}>
      <TeamPanel teamId={detail.id} onGone={() => {}} />
    </QueryClientProvider>,
  );
}

describe("team rules", () => {
  it("mirror the server's roles", () => {
    expect(canManage("owner") && canManage("admin")).toBe(true);
    expect(canManage("member") || canManage("viewer")).toBe(false);
    expect(canScan("member")).toBe(true);
    expect(canScan("viewer")).toBe(false);
    expect(assignableRoles("owner")).toContain("owner");
    expect(assignableRoles("admin")).not.toContain("owner");
    expect(assignableRoles("member")).toEqual([]);
    expect(canEditMember("admin", "owner")).toBe(false);
    expect(canEditMember("admin", "member")).toBe(true);
    expect(canEditMember("owner", "owner")).toBe(true);
    expect(canEditMember("viewer", "viewer")).toBe(false);
  });

  it("builds invitation links and reads server errors", () => {
    expect(inviteLink("inv_abc", "https://verdyx.dev")).toBe("https://verdyx.dev/teams?invite=inv_abc");
    expect(serverMessage(new Error('409: {"error":"they\'re already in this team","status":409}'), "x")).toBe(
      "They're already in this team.",
    );
    expect(serverMessage(new Error("500: Internal Server Error"), "fallback")).toBe("fallback");
    expect(serverMessage("nope", "fallback")).toBe("fallback");
  });
});

describe("team panel", () => {
  it("shows an admin the team, its tabs and the key tab", () => {
    const html = render(team);
    expect(html).toContain("Blue Team");
    expect(html).toContain("3 members");
    expect(html).toContain("API keys");
    expect(html).toContain("Scans");
    expect(html).toContain("No scans yet");
  });

  it("hides team keys from members and viewers", () => {
    const html = render({ ...team, role: "viewer" });
    expect(html).not.toContain("API keys");
    expect(html).toContain("See the team&#x27;s scans");
  });

  it("lists team scans with who uploaded them", () => {
    const html = render(team, [
      { id: "s1", originalFilename: "invoice.docm", submitterId: "u1", analysisStatus: "completed", isMalicious: true, createdAt: "2026-11-17T13:00:00Z" },
      { id: "s2", url: "https://example.com", submitterId: "gone", analysisStatus: "pending", createdAt: "2026-11-17T14:00:00Z" },
    ]);
    expect(html).toContain("invoice.docm");
    expect(html).toContain("/analysis/s1");
    expect(html).toContain("malicious · completed · ana");
    expect(html).toContain("former member");
  });
});
