// Types and labels for live hunts (components/live-hunts-panel.tsx).

export interface LiveHunt {
  id: string;
  name: string;
  teamId?: string | null;
  teamName?: string | null;
  enabled: boolean;
  matches: number;
  unseen: number;
  lastMatchAt?: string | null;
  lastError?: string | null;
  createdAt: string;
  ruleNames: string[];
}

export interface LiveHuntMatch {
  submissionId: string;
  rules: string[];
  matchedAt: string;
  seen: boolean;
  filename?: string | null;
  url?: string | null;
  sha256?: string | null;
  isMalicious?: boolean | null;
}

export interface LiveHuntDetail extends LiveHunt {
  rule: string;
  results: LiveHuntMatch[];
}

export const LIVE_HUNTS = "/api/livehunts";

/** "3 matches · last 2 hours ago", "No matches yet". */
export function matchSummary(h: Pick<LiveHunt, "matches" | "lastMatchAt">, now = Date.now()): string {
  if (h.matches === 0) return "No matches yet";
  const count = `${h.matches} ${h.matches === 1 ? "match" : "matches"}`;
  return h.lastMatchAt ? `${count} · last ${timeAgo(h.lastMatchAt, now)}` : count;
}

export function timeAgo(iso: string, now = Date.now()): string {
  const s = Math.max(0, Math.round((now - new Date(iso).getTime()) / 1000));
  if (s < 60) return "just now";
  const m = Math.round(s / 60);
  if (m < 60) return `${m} ${m === 1 ? "minute" : "minutes"} ago`;
  const h = Math.round(m / 60);
  if (h < 48) return `${h} ${h === 1 ? "hour" : "hours"} ago`;
  const d = Math.round(h / 24);
  return `${d} days ago`;
}
