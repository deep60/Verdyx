import { describe, expect, it } from "vitest";
import { matchSummary, timeAgo } from "./live-hunts";

const NOW = Date.parse("2026-11-25T12:00:00Z");
const ago = (seconds: number) => new Date(NOW - seconds * 1000).toISOString();

describe("timeAgo", () => {
  it("rounds to the nearest sensible unit", () => {
    expect(timeAgo(ago(5), NOW)).toBe("just now");
    expect(timeAgo(ago(60), NOW)).toBe("1 minute ago");
    expect(timeAgo(ago(45 * 60), NOW)).toBe("45 minutes ago");
    expect(timeAgo(ago(3600), NOW)).toBe("1 hour ago");
    expect(timeAgo(ago(30 * 3600), NOW)).toBe("30 hours ago");
    expect(timeAgo(ago(5 * 86400), NOW)).toBe("5 days ago");
  });

  it("never shows a time in the future", () => {
    expect(timeAgo(new Date(NOW + 60_000).toISOString(), NOW)).toBe("just now");
  });
});

describe("matchSummary", () => {
  it("says when there are none", () => {
    expect(matchSummary({ matches: 0, lastMatchAt: null }, NOW)).toBe("No matches yet");
  });

  it("counts matches and says when the last one was", () => {
    expect(matchSummary({ matches: 1, lastMatchAt: ago(120) }, NOW)).toBe("1 match · last 2 minutes ago");
    expect(matchSummary({ matches: 7, lastMatchAt: ago(7200) }, NOW)).toBe("7 matches · last 2 hours ago");
  });
});
