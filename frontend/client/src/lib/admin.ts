// The admin console: Verdyx administrators find a team and set its plan and
// limits. The gateway checks every change (handlers/plans.rs); the checks here
// only give a clear message before sending.

import { PLANS, formatLimit, planName, type PlanId, type PlanLimits, type TeamUsage } from "@/lib/plans";

/** Limits an administrator set for one team. Missing fields take the plan's. */
export interface Overrides {
  scansPerMinute?: number;
  scansPerDay?: number;
  teamScansPerMonth?: number;
  unlimitedMonthlyScans?: boolean;
  seats?: number;
  teamKeys?: number;
  storageConnections?: number;
}

export interface AdminTeam {
  id: string;
  name: string;
  plan: PlanId;
  custom: boolean;
  overrides: Overrides;
  members: number;
  scansThisMonth: number;
  planChangedAt: string | null;
  createdAt: string;
}

export interface PlanChange {
  at: string;
  actorId: string | null;
  from: string | null;
  plan: string | null;
  custom: boolean;
  overrides?: Overrides | null;
}

export interface AdminTeamPlan extends TeamUsage {
  name: string;
  overrides: Overrides;
  history: PlanChange[];
}

export type PlanFilter = "all" | PlanId | "custom";

export const PLAN_FILTERS: { value: PlanFilter; label: string }[] = [
  { value: "all", label: "All plans" },
  { value: "free", label: "Free" },
  { value: "team", label: "Team" },
  { value: "enterprise", label: "Enterprise" },
  { value: "custom", label: "Custom limits" },
];

/** The team list's address for a search and a plan filter. */
export function teamsQuery(q: string, plan: PlanFilter): string {
  const params = new URLSearchParams();
  if (q.trim()) params.set("q", q.trim());
  if (plan !== "all") params.set("plan", plan);
  const s = params.toString();
  return s ? `/api/admin/teams?${s}` : "/api/admin/teams";
}

type NumberField = "scansPerMinute" | "scansPerDay" | "seats" | "teamKeys" | "storageConnections";

/** The limits an administrator can set, with the most each may be. */
export const LIMIT_FIELDS: { key: NumberField; label: string; max: number }[] = [
  { key: "scansPerMinute", label: "Scans per person a minute", max: 1_000_000 },
  { key: "scansPerDay", label: "Scans per person a day", max: 1_000_000 },
  { key: "seats", label: "Members and open invitations", max: 100_000_000 },
  { key: "teamKeys", label: "Active team API keys", max: 100_000_000 },
  { key: "storageConnections", label: "Storage connections", max: 100_000_000 },
];

export const MONTHLY_MAX = 100_000_000;

/** How the monthly team quota is set: the plan's, a number, or none. */
export type MonthlyMode = "plan" | "limit" | "unlimited";

/** The form's state. An empty field means "the plan's value". */
export interface PlanForm {
  plan: PlanId;
  monthly: MonthlyMode;
  teamScansPerMonth: string;
  scansPerMinute: string;
  scansPerDay: string;
  seats: string;
  teamKeys: string;
  storageConnections: string;
}

const str = (n?: number) => (n === undefined ? "" : String(n));

export function formFromTeam(plan: string, o: Overrides = {}): PlanForm {
  return {
    plan: PLANS.some((p) => p.id === plan) ? (plan as PlanId) : "free",
    monthly: o.unlimitedMonthlyScans ? "unlimited" : o.teamScansPerMonth !== undefined ? "limit" : "plan",
    teamScansPerMonth: str(o.teamScansPerMonth),
    scansPerMinute: str(o.scansPerMinute),
    scansPerDay: str(o.scansPerDay),
    seats: str(o.seats),
    teamKeys: str(o.teamKeys),
    storageConnections: str(o.storageConnections),
  };
}

/** A whole number from a field, allowing "50,000" and "50 000". */
function whole(text: string): number | null {
  const t = text.replace(/[,\s_]/g, "");
  return /^\d+$/.test(t) ? Number(t) : null;
}

/** The overrides the form describes, or what's wrong with it. */
export function overridesFromForm(f: PlanForm): { overrides: Overrides } | { error: string } {
  const o: Overrides = {};
  for (const { key, label, max } of LIMIT_FIELDS) {
    if (!f[key].trim()) continue;
    const n = whole(f[key]);
    if (n === null || n < 1 || n > max) {
      return { error: `${label} must be a whole number from 1 to ${max.toLocaleString("en-US")}.` };
    }
    o[key] = n;
  }
  if (f.monthly === "unlimited") o.unlimitedMonthlyScans = true;
  if (f.monthly === "limit") {
    const n = whole(f.teamScansPerMonth);
    if (n === null || n < 1 || n > MONTHLY_MAX) {
      return { error: `Team scans a month must be a whole number from 1 to ${MONTHLY_MAX.toLocaleString("en-US")}.` };
    }
    o.teamScansPerMonth = n;
  }
  return { overrides: o };
}

/** The limits a team would have: the plan's, with the overrides on top. */
export function effectiveLimits(plan: PlanId, o: Overrides): PlanLimits {
  const base = (PLANS.find((p) => p.id === plan) ?? PLANS[0]).limits;
  return {
    scansPerMinute: o.scansPerMinute ?? base.scansPerMinute,
    scansPerDay: o.scansPerDay ?? base.scansPerDay,
    teamScansPerMonth: o.unlimitedMonthlyScans ? null : (o.teamScansPerMonth ?? base.teamScansPerMonth),
    seats: o.seats ?? base.seats,
    teamKeys: o.teamKeys ?? base.teamKeys,
    storageConnections: o.storageConnections ?? base.storageConnections,
  };
}

export const hasOverrides = (o: Overrides) => Object.keys(o).length > 0;

/** "Seats 500, no monthly limit": the custom limits, in a line. */
export function describeOverrides(o: Overrides): string {
  const parts: string[] = [];
  if (o.scansPerMinute !== undefined) parts.push(`${formatLimit(o.scansPerMinute)} scans a minute`);
  if (o.scansPerDay !== undefined) parts.push(`${formatLimit(o.scansPerDay)} scans a day`);
  if (o.unlimitedMonthlyScans) parts.push("no monthly limit");
  if (o.teamScansPerMonth !== undefined) parts.push(`${formatLimit(o.teamScansPerMonth)} team scans a month`);
  if (o.seats !== undefined) parts.push(`${formatLimit(o.seats)} members`);
  if (o.teamKeys !== undefined) parts.push(`${formatLimit(o.teamKeys)} team keys`);
  if (o.storageConnections !== undefined) parts.push(`${formatLimit(o.storageConnections)} storage connections`);
  return parts.join(", ");
}

/** The confirmation's summary: "Team → Enterprise, with custom limits: …". */
export function describeChange(fromPlan: string, fromOverrides: Overrides, toPlan: PlanId, to: Overrides): string {
  const samePlan = fromPlan === toPlan;
  const head = samePlan ? `Stays on ${planName(toPlan)}` : `${planName(fromPlan)} → ${planName(toPlan)}`;
  if (hasOverrides(to)) return `${head}, with custom limits: ${describeOverrides(to)}.`;
  if (hasOverrides(fromOverrides)) return `${head}, and its custom limits are removed.`;
  return `${head}.`;
}

/** Whether the form changes anything. */
export function isUnchanged(fromPlan: string, fromOverrides: Overrides, toPlan: PlanId, to: Overrides): boolean {
  const norm = (o: Overrides) => JSON.stringify(Object.entries(o).sort(([a], [b]) => a.localeCompare(b)));
  return fromPlan === toPlan && norm(fromOverrides) === norm(to);
}
