/**
 * Who can open a scan, and whether its file left Verdyx. Matches `can_view`
 * and `handlers::privacy` in the gateway.
 */

export const NIL_ID = "00000000-0000-0000-0000-000000000000";

export interface ScanAccessInput {
  submitterId?: string;
  organizationId?: string | null;
  bountyId?: string | null;
  sharedByLink?: boolean;
  mayUploadFile?: boolean;
  submissionType?: string;
}

export interface PrivacySettings {
  shareFilesWithVirusTotal: boolean;
  teams: { id: string; name: string; canEdit: boolean; shareFilesWithVirusTotal: boolean }[];
}

/** One line: who can open this report. */
export function whoCanSee(s: ScanAccessInput): string {
  if (!s.submitterId || s.submitterId === NIL_ID) {
    return "Made while signed out: anyone with this link can open it.";
  }
  if (s.sharedByLink) return "Shared: anyone with this link can open it.";
  if (s.bountyId) return "Posted with a bounty: any signed-in analyst can open it.";
  if (s.organizationId) return "Private to the team it's saved to.";
  return "Private: only you can open it.";
}

/** One line: where the file went, for file scans. */
export function whereFileWent(s: ScanAccessInput): string | null {
  if (s.submissionType === "url") return null;
  return s.mayUploadFile
    ? "Behavioral analysis may upload this file to VirusTotal, which shares uploads with its customers."
    : "The file stays with Verdyx. Only its hash is looked up elsewhere.";
}

/** May this person change who can see the scan? The server checks again. */
export function canChangeSharing(s: ScanAccessInput, userId: string | undefined): boolean {
  if (!userId || !s.submitterId || s.submitterId === NIL_ID) return false;
  return s.submitterId === userId || Boolean(s.organizationId);
}
