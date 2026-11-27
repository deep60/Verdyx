// Plans and usage. The numbers here describe the gateway's plans
// (backend/api-gateway/src/services/plans.rs); the gateway enforces them.

export type PlanId = "free" | "team" | "enterprise";

export interface PlanLimits {
  scansPerMinute: number;
  scansPerDay: number;
  teamScansPerMonth: number | null;
  seats: number;
  teamKeys: number;
  storageConnections: number;
}

export interface TeamUsage {
  plan: PlanId;
  custom: boolean;
  limits: PlanLimits;
  usage: { scansThisMonth: number; seats: number; teamKeys: number; storageConnections: number };
  periodStart: string;
  resetsAt: string;
}

export interface PlanInfo {
  id: PlanId;
  name: string;
  price: string;
  blurb: string;
  limits: PlanLimits;
}

export const PLANS: PlanInfo[] = [
  {
    id: "free",
    name: "Free",
    price: "$0",
    blurb: "Every engine, the API and teams, during the beta.",
    limits: {
      scansPerMinute: 10,
      scansPerDay: 100,
      teamScansPerMonth: null,
      seats: 50,
      teamKeys: 10,
      storageConnections: 5,
    },
  },
  {
    id: "team",
    name: "Team",
    price: "Ask us",
    blurb: "For security teams scanning every day.",
    limits: {
      scansPerMinute: 60,
      scansPerDay: 2000,
      teamScansPerMonth: 50000,
      seats: 200,
      teamKeys: 50,
      storageConnections: 10,
    },
  },
  {
    id: "enterprise",
    name: "Enterprise",
    price: "Ask us",
    blurb: "Limits set to fit your organisation.",
    limits: {
      scansPerMinute: 300,
      scansPerDay: 20000,
      teamScansPerMonth: null,
      seats: 1000,
      teamKeys: 200,
      storageConnections: 25,
    },
  },
];

export const planName = (id: string): string => PLANS.find((p) => p.id === id)?.name ?? "Free";

const number = (n: number) => n.toLocaleString("en-US");

/** A limit as written in tables: "50,000" or "No limit". */
export const formatLimit = (n: number | null): string => (n === null ? "No limit" : number(n));

export type Tone = "ok" | "warning" | "danger";

/** How much of a limit is used, for a meter. */
export function meter(used: number, limit: number | null): { percent: number; text: string; tone: Tone } {
  if (limit === null) return { percent: 0, text: `${number(used)} (no limit)`, tone: "ok" };
  const ratio = limit > 0 ? used / limit : 1;
  const percent = Math.min(100, Math.round(ratio * 100));
  const tone: Tone = ratio >= 1 ? "danger" : ratio >= 0.8 ? "warning" : "ok";
  return { percent, text: `${number(used)} of ${number(limit)}`, tone };
}

/** "1 December": when the monthly count starts again. */
export function resetDate(iso: string): string {
  const d = new Date(iso);
  return Number.isNaN(d.getTime())
    ? ""
    : d.toLocaleDateString("en-GB", { day: "numeric", month: "long", timeZone: "UTC" });
}

/** The rows of the plan comparison on the pricing page. */
export const COMPARISON: { label: string; value: (l: PlanLimits) => string }[] = [
  { label: "Scans per person", value: (l) => `${number(l.scansPerMinute)}/min, ${number(l.scansPerDay)}/day` },
  { label: "Team scans per month", value: (l) => formatLimit(l.teamScansPerMonth) },
  { label: "Team members", value: (l) => number(l.seats) },
  { label: "Team API keys", value: (l) => number(l.teamKeys) },
  { label: "Storage connections", value: (l) => number(l.storageConnections) },
];
