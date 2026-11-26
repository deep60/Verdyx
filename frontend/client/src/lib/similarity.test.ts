import { describe, expect, it } from "vitest";
import { matchEvidence, similarSummary, type SimilarResponse } from "./similarity";

const base = { tlshDistance: null, ssdeepScore: null, sameImphash: false };

describe("matchEvidence", () => {
  it("lists what the match rests on", () => {
    expect(matchEvidence({ ...base, closeness: "very_similar", tlshDistance: 12, ssdeepScore: 88, sameImphash: true })).toBe(
      "TLSH distance 12 · ssdeep 88% · same imphash",
    );
    expect(matchEvidence({ ...base, closeness: "identical", tlshDistance: 0 })).toBe("Same SHA-256");
    expect(matchEvidence({ ...base, closeness: "same_imports", sameImphash: true, tlshDistance: 240 })).toBe(
      "same imphash",
    );
  });

  it("leaves out scores too weak to count", () => {
    expect(matchEvidence({ ...base, closeness: "related", tlshDistance: 90, ssdeepScore: 10 })).toBe("TLSH distance 90");
  });
});

describe("similarSummary", () => {
  const r = (over: Partial<SimilarResponse>): SimilarResponse => ({
    submissionId: "x",
    status: "ready",
    hashes: null,
    similar: [],
    compared: 0,
    ...over,
  });

  it("counts results and what was searched", () => {
    expect(similarSummary(r({ compared: 1 }))).toBe("Nothing similar among 1 file you can see.");
    const one = { submissionId: "a", sha256: null, filename: null, fileSize: null, createdAt: "", verdict: null, reportUrl: "", match: { ...base, closeness: "similar" as const } };
    expect(similarSummary(r({ compared: 1200, similar: [one, one] }))).toBe("2 similar files among 1,200 files you can see.");
  });

  it("explains when there's nothing to compare", () => {
    expect(similarSummary(r({ status: "pending" }))).toMatch(/once the scan finishes/);
    expect(similarSummary(r({ status: "not_a_file" }))).toMatch(/not web pages/);
    expect(similarSummary(r({ status: "unavailable" }))).toMatch(/no fuzzy hashes/);
  });
});
