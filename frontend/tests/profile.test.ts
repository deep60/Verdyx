import { describe, expect, it } from "vitest";
import type { ApiSubmission } from "@/lib/api-types";
import {
  activityDays,
  currentStreak,
  findStanding,
  latestCatch,
  maskEmail,
  scanCounts,
  scanName,
  scanOutcome,
  shortAddress,
} from "@/lib/profile";

const NOW = new Date(2026, 10, 25, 12); // 25 Nov 2026, local time

const scan = (extra: Partial<ApiSubmission>): ApiSubmission => ({
  id: Math.random().toString(36).slice(2),
  analysisStatus: "completed",
  createdAt: NOW.toISOString(),
  ...extra,
});

const daysAgo = (n: number) => new Date(2026, 10, 25 - n, 12).toISOString();

describe("analyst profile", () => {
  it("shows the verdict, not just that the scan finished", () => {
    expect(scanOutcome(scan({ verdict: "malicious" }))).toBe("malicious");
    expect(scanOutcome(scan({ verdict: "suspicious" }))).toBe("suspicious");
    expect(scanOutcome(scan({ verdict: "benign" }))).toBe("clean");
    expect(scanOutcome(scan({ verdict: "unknown" }))).toBe("unknown");
    // Older scans only have is_malicious.
    expect(scanOutcome(scan({ isMalicious: true }))).toBe("malicious");
    expect(scanOutcome(scan({ analysisStatus: "analyzing", verdict: "malicious" }))).toBe("running");
    expect(scanOutcome(scan({ analysisStatus: "failed" }))).toBe("failed");
  });

  it("counts threats and this week's scans", () => {
    const c = scanCounts(
      [
        scan({ verdict: "malicious" }),
        scan({ verdict: "suspicious", createdAt: daysAgo(3) }),
        scan({ verdict: "benign", createdAt: daysAgo(10) }),
      ],
      NOW,
    );
    expect(c).toEqual({ total: 3, malicious: 1, suspicious: 1, clean: 1, thisWeek: 2 });
  });

  it("colours each day by the worst thing found and counts the streak", () => {
    const days = activityDays(
      [
        scan({ verdict: "benign" }),
        scan({ verdict: "malicious" }),
        scan({ verdict: "benign", createdAt: daysAgo(1) }),
        scan({ verdict: "benign", createdAt: daysAgo(5) }),
        scan({ verdict: "malicious", createdAt: daysAgo(200) }), // outside the window
      ],
      84,
      NOW,
    );
    expect(days).toHaveLength(84);
    expect(days[83]).toMatchObject({ scans: 2, worst: "malicious" });
    expect(days[82]).toMatchObject({ scans: 1, worst: "clean" });
    expect(days.reduce((n, d) => n + d.scans, 0)).toBe(4);
    expect(currentStreak(days)).toBe(2);
  });

  it("keeps a streak alive before today's first scan", () => {
    const days = activityDays([scan({ createdAt: daysAgo(1) }), scan({ createdAt: daysAgo(2) })], 10, NOW);
    expect(currentStreak(days)).toBe(2);
  });

  it("picks the most recent threat as the latest catch", () => {
    const older = scan({ verdict: "malicious", createdAt: daysAgo(4) });
    const newer = scan({ verdict: "suspicious", createdAt: daysAgo(1) });
    expect(latestCatch([older, scan({ verdict: "benign" }), newer])?.id).toBe(newer.id);
    expect(latestCatch([scan({ verdict: "benign" })])).toBeUndefined();
  });

  it("hides most of the email and wallet on a shared screen", () => {
    expect(maskEmail("arjunp2989@proton.me")).toBe("ar•••@proton.me");
    expect(maskEmail("a@b.co")).toBe("a•••@b.co");
    expect(shortAddress("0x1234567890abcdef1234")).toBe("0x1234…1234");
  });

  it("drops the scheme from URLs in the list", () => {
    expect(scanName(scan({ submissionType: "url", url: "https://example.com/a" }))).toBe("example.com/a");
    expect(scanName(scan({ originalFilename: "eicar.com" }))).toBe("eicar.com");
  });

  it("finds the user's rank, or none", () => {
    const list = [{ userId: "a", rank: 1 }, { userId: "b", rank: 2 }];
    expect(findStanding(list, "b")).toMatchObject({ rank: 2, of: 2 });
    expect(findStanding(list, "c")).toBeNull();
    expect(findStanding(undefined, "a")).toBeNull();
  });
});
