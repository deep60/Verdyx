import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { TeamPlan } from "@/components/team-plan";
import { describe as describeEvent } from "@/components/audit-log";
import { COMPARISON, PLANS, formatLimit, meter, planName, resetDate, type TeamUsage } from "@/lib/plans";

describe("plans", () => {
  it("says how much of a limit is used", () => {
    expect(meter(10, 100)).toEqual({ percent: 10, text: "10 of 100", tone: "ok" });
    expect(meter(80, 100).tone).toBe("warning");
    expect(meter(120, 100)).toEqual({ percent: 100, text: "120 of 100", tone: "danger" });
    expect(meter(5000, null)).toEqual({ percent: 0, text: "5,000 (no limit)", tone: "ok" });
    expect(formatLimit(50000)).toBe("50,000");
    expect(formatLimit(null)).toBe("No limit");
    expect(resetDate("2026-12-01T00:00:00Z")).toBe("1 December");
    expect(planName("enterprise")).toBe("Enterprise");
    expect(planName("gold")).toBe("Free");
  });

  it("describes the same plans the gateway enforces", () => {
    const rust = readFileSync(resolve(__dirname, "../../backend/api-gateway/src/services/plans.rs"), "utf8");
    const block = (plan: string) => {
      const start = plan === "free" ? rust.indexOf("_ => Limits {") : rust.indexOf(`"${plan}" => Limits {`);
      expect(start).toBeGreaterThan(-1);
      return rust.slice(start, rust.indexOf("},", start));
    };
    const field = (text: string, name: string) => text.match(new RegExp(`${name}: ([^,\\n]+),`))?.[1]?.trim();
    const num = (v?: string) => (v ? Number(v.replace(/_/g, "").replace(/.*max\((\d+)\).*/, "$1")) : NaN);
    for (const p of PLANS.filter((p) => p.id !== "free")) {
      const b = block(p.id);
      expect(num(field(b, "seats")), p.id).toBe(p.limits.seats);
      expect(num(field(b, "team_keys")), p.id).toBe(p.limits.teamKeys);
      expect(num(field(b, "storage_connections")), p.id).toBe(p.limits.storageConnections);
      expect(num(field(b, "scans_per_minute")), p.id).toBe(p.limits.scansPerMinute);
      expect(num(field(b, "scans_per_day")), p.id).toBe(p.limits.scansPerDay);
      const monthly = field(b, "team_scans_per_month");
      expect(monthly === "None" ? null : num(monthly?.replace(/Some\((.*)\)/, "$1")), p.id).toBe(
        p.limits.teamScansPerMonth,
      );
    }
    const free = block("free");
    expect(num(field(free, "seats"))).toBe(PLANS[0].limits.seats);
    expect(num(field(free, "team_keys"))).toBe(PLANS[0].limits.teamKeys);
    expect(num(field(free, "storage_connections"))).toBe(PLANS[0].limits.storageConnections);
    expect(field(free, "team_scans_per_month")).toBe("None");
    expect(rust).toContain('env_u32("SCAN_RATE_LIMIT_PER_MINUTE", 10)');
    expect(rust).toContain('env_u32("SCAN_RATE_LIMIT_PER_DAY", 100)');
  });

  it("compares the plans row by row", () => {
    expect(COMPARISON.map((r) => r.value(PLANS[1].limits))).toEqual(["60/min, 2,000/day", "50,000", "200", "50", "10"]);
    expect(COMPARISON[1].value(PLANS[2].limits)).toBe("No limit");
  });
});

const usage = (over: Partial<TeamUsage> = {}): TeamUsage => ({
  plan: "team",
  custom: false,
  limits: { ...PLANS[1].limits },
  usage: { scansThisMonth: 45000, seats: 12, teamKeys: 3, storageConnections: 1 },
  periodStart: "2026-11-01T00:00:00Z",
  resetsAt: "2026-12-01T00:00:00Z",
  ...over,
});

const render = (data: TeamUsage) => {
  const client = new QueryClient();
  client.setQueryData(["/api/orgs/t1/usage"], data);
  return renderToStaticMarkup(
    <QueryClientProvider client={client}>
      <TeamPlan teamId="t1" />
    </QueryClientProvider>,
  );
};

describe("a team's plan", () => {
  it("shows the plan and how much is used", () => {
    const html = render(usage());
    expect(html).toContain("Team");
    expect(html).toContain("45,000 of 50,000");
    expect(html).toContain("starts again 1 December");
    expect(html).toContain("12 of 200");
    expect(html).toContain("text-amber-500"); // 90% of the month's scans
    expect(html).toContain("60 scans a minute and 2,000 a day");
    expect(html).not.toContain("Custom limits");
  });

  it("shows unlimited scans without a bar, and custom limits", () => {
    const html = render(
      usage({ plan: "enterprise", custom: true, limits: { ...PLANS[2].limits, teamScansPerMonth: null } }),
    );
    expect(html).toContain("45,000 (no limit)");
    expect(html).toContain("Custom limits");
    expect(html.match(/role="progressbar"/g)).toHaveLength(3);
  });
});

describe("activity log", () => {
  it("describes a plan change", () => {
    const event = { id: 1, action: "team.plan_changed", details: { plan: "enterprise", custom: true }, createdAt: "" };
    expect(describeEvent(event as never)).toBe("Moved the team to the Enterprise plan, with custom limits");
  });
});
