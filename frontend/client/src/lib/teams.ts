// Teams: types and rules shared by the Teams page and the upload form.
// The server enforces every rule; these only decide what to show.

export type TeamRole = "owner" | "admin" | "member" | "viewer";

export interface TeamSummary {
  id: string;
  name: string;
  role: TeamRole;
  memberCount: number;
  createdAt?: string;
}

export interface TeamMember {
  userId: string;
  role: TeamRole;
  joinedAt: string;
  username?: string | null;
  email?: string | null;
  isYou: boolean;
}

export interface TeamInvitation {
  id: string;
  email: string;
  role: TeamRole;
  createdAt: string;
  expiresAt: string;
  expired: boolean;
}

export interface TeamDetail {
  id: string;
  name: string;
  role: TeamRole;
  createdAt: string;
  members: TeamMember[];
  invitations: TeamInvitation[];
}

export interface MyInvitation {
  id: string;
  teamId: string;
  teamName: string;
  role: TeamRole;
  expiresAt: string;
  invitedBy?: string | null;
}

export const ROLE_HELP: Record<TeamRole, string> = {
  owner: "Everything, including deleting the team",
  admin: "Invite and remove people, manage team keys",
  member: "Scan into the team and see its scans",
  viewer: "See the team's scans",
};

export const canManage = (role?: TeamRole | null) => role === "owner" || role === "admin";
export const canScan = (role?: TeamRole | null) => role === "owner" || role === "admin" || role === "member";

/** Roles `actor` may hand out (mirrors `can_assign` on the server). */
export function assignableRoles(actor: TeamRole): TeamRole[] {
  if (actor === "owner") return ["owner", "admin", "member", "viewer"];
  if (actor === "admin") return ["admin", "member", "viewer"];
  return [];
}

/** May `actor` change or remove a member whose role is `target`? */
export function canEditMember(actor: TeamRole, target: TeamRole): boolean {
  if (actor === "owner") return true;
  return actor === "admin" && target !== "owner";
}

export function inviteLink(code: string, origin = window.location.origin): string {
  return `${origin}/teams?invite=${encodeURIComponent(code)}`;
}

/**
 * The server's message from an `apiRequest` error ("409: {\"error\":\"…\"}"),
 * or `fallback`.
 */
export function serverMessage(err: unknown, fallback: string): string {
  const raw = err instanceof Error ? err.message : "";
  const body = raw.replace(/^\d{3}:\s*/, "");
  try {
    const parsed = JSON.parse(body);
    if (typeof parsed?.error === "string" && parsed.error) {
      return parsed.error.charAt(0).toUpperCase() + parsed.error.slice(1) + ".";
    }
  } catch {
    // not JSON
  }
  return fallback;
}
