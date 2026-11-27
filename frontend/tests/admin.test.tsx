import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { TeamAdmin, TeamTable } from "@/pages/admin";
import {
  LIMIT_FIELDS,
  MONTHLY_MAX,
  describeChange,
  effectiveLimits,
  formFromTeam,
  isUnchanged,
  overridesFromForm,
  teamsQuery,
  type AdminTeam,
  type AdminTeamPlan,
} from "@/lib/admin";
import { PLANS } from "@/lib/plans";

describe("the admin console's plan form", () => {
  it("starts from what the team has", () => {
    expect(formFromTeam("team", {})).toMatchObject({ plan: "team", monthly: "plan", seats: "" });
    expect(formFromTeam("enterprise", { seats: 5000, unlimitedMonthlyScans: true })).toMatchObject({
      plan: "enterprise",
      monthly: "unlimited",
      seats: "5000",
    });
    expect(formFromTeam("free", { teamScansPerMonth: 1000 })).toMatchObject({ monthly: "limit", teamScansPerMonth: "1000" });
    expect(formFromTeam("gold").plan).toBe("free");
  });

  it("turns the form into overrides, leaving empty fields to the plan", () => {
    const f = { ...formFromTeam("enterprise"), seats: "5,000", monthly: "limit" as const, teamScansPerMonth: "2 000 000" };
    expect(overridesFromForm(f)).toEqual({ overrides: { seats: 5000, teamScansPerMonth: 2_000_000 } });
    expect(overridesFromForm(formFromTeam("team"))).toEqual({ overrides: {} });
    expect(overridesFromForm({ ...formFromTeam("team"), monthly: "unlimited" })).toEqual({
      overrides: { unlimitedMonthlyScans: true },
    });
  });

  it("refuses what the gateway would refuse", () => {
    const bad = (patch: object) => "error" in overridesFromForm({ ...formFromTeam("team"), ...patch });
    expect(bad({ seats: "0" })).toBe(true);
    expect(bad({ seats: "-5" })).toBe(true);
    expect(bad({ seats: "1.5" })).toBe(true);
    expect(bad({ teamKeys: "lots" })).toBe(true);
    expect(bad({ scansPerMinute: "1000001" })).toBe(true);
    expect(bad({ scansPerMinute: "1000000" })).toBe(false);
    expect(bad({ monthly: "limit", teamScansPerMonth: "" })).toBe(true);
    expect(bad({ monthly: "limit", teamScansPerMonth: String(MONTHLY_MAX + 1) })).toBe(true);
  });

  it("uses the same bounds as the gateway", () => {
    const rust = readFileSync(resolve(__dirname, "../../backend/api-gateway/src/services/plans.rs"), "utf8");
    expect(rust).toContain("(1..=1_000_000).contains(&n)");
    expect(rust).toContain("(1..=100_000_000).contains(&n)");
    expect(LIMIT_FIELDS.find((f) => f.key === "scansPerMinute")?.max).toBe(1_000_000);
    expect(LIMIT_FIELDS.find((f) => f.key === "seats")?.max).toBe(100_000_000);
    expect(MONTHLY_MAX).toBe(100_000_000);
  });

  it("works out the limits a change gives", () => {
    expect(effectiveLimits("team", {})).toEqual(PLANS[1].limits);
    expect(effectiveLimits("team", { seats: 500, unlimitedMonthlyScans: true })).toMatchObject({
      seats: 500,
      teamScansPerMonth: null,
      teamKeys: 50,
    });
  });

  it("describes the change before it's made", () => {
    expect(describeChange("free", {}, "team", {})).toBe("Free → Team.");
    expect(describeChange("team", {}, "enterprise", { seats: 5000 })).toBe(
      "Team → Enterprise, with custom limits: 5,000 members.",
    );
    expect(describeChange("team", { seats: 500 }, "team", {})).toBe("Stays on Team, and its custom limits are removed.");
    expect(isUnchanged("team", { seats: 500 }, "team", { seats: 500 })).toBe(true);
    expect(isUnchanged("team", {}, "enterprise", {})).toBe(false);
  });

  it("searches the team list", () => {
    expect(teamsQuery("", "all")).toBe("/api/admin/teams");
    expect(teamsQuery(" acme ", "custom")).toBe("/api/admin/teams?q=acme&plan=custom");
    expect(teamsQuery("a&b", "team")).toBe("/api/admin/teams?q=a%26b&plan=team");
  });
});

const team = (over: Partial<AdminTeam> = {}): AdminTeam => ({
  id: "t1",
  name: "Acme Security",
  plan: "team",
  custom: true,
  overrides: { seats: 500 },
  members: 12,
  scansThisMonth: 45000,
  planChangedAt: "2026-11-20T10:00:00Z",
  createdAt: "2026-11-01T10:00:00Z",
  ...over,
});

describe("the admin console", () => {
  it("lists teams with their plans and use", () => {
    const html = renderToStaticMarkup(
      <TeamTable teams={[team(), team({ id: "t2", name: "Free Folk", plan: "free", custom: false })]} selected="t1" onSelect={() => {}} />,
    );
    expect(html).toContain("Acme Security");
    expect(html).toContain("45,000");
    expect(html).toContain("Custom");
    expect(html).toContain("Free Folk");
    expect(html).toContain('aria-selected="true"');
    expect(renderToStaticMarkup(<TeamTable teams={[]} selected={null} onSelect={() => {}} />)).toContain("No teams match.");
  });

  it("shows a team's use, its custom limits, the plan form and its history", () => {
    const data: AdminTeamPlan = {
      name: "Acme Security",
      plan: "team",
      custom: true,
      limits: { ...PLANS[1].limits, seats: 500 },
      usage: { scansThisMonth: 45000, seats: 12, teamKeys: 3, storageConnections: 1 },
      periodStart: "2026-11-01T00:00:00Z",
      resetsAt: "2026-12-01T00:00:00Z",
      overrides: { seats: 500 },
      history: [
        { at: "2026-11-20T10:00:00Z", actorId: "a1", from: "free", plan: "team", custom: true, overrides: { seats: 500 } },
      ],
    };
    const client = new QueryClient();
    client.setQueryData(["/api/admin/teams/t1/plan"], data);
    const html = renderToStaticMarkup(
      <QueryClientProvider client={client}>
        <TeamAdmin teamId="t1" />
      </QueryClientProvider>,
    );
    expect(html).toContain("Acme Security");
    expect(html).toContain("Custom: 500 members");
    expect(html).toContain("45,000 of 50,000");
    expect(html).toContain("12 of 500");
    expect(html).toContain('data-testid="plan-editor"');
    expect(html).toContain('value="500"');
    expect(html).toContain("Plan&#x27;s: 50");
    expect(html).toContain("Free → Team, 500 members");
  });
});
