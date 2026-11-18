import { describe, expect, it } from "vitest";
import type { ApiAnalysis, ApiConsensus } from "@/lib/api-types";
import {
  decidedBy,
  engineFacts,
  engineRole,
  flaggedSummary,
  isMacMetadata,
  markdownReport,
  mimeLabel,
  notVotingSummary,
  sortEngines,
  verdictLabel,
} from "@/lib/report";

const engine = (name: string, extra: Partial<ApiAnalysis>): ApiAnalysis => ({
  id: name,
  engine: { name, version: "1" },
  ...extra,
});

describe("scan report", () => {
  it("never calls a scan clean, only that nothing was found", () => {
    expect(verdictLabel("clean").label).toBe("No threats found");
    expect(verdictLabel("benign").label).toBe("No threats found");
    expect(verdictLabel("malicious").tone).toBe("danger");
    expect(verdictLabel(undefined).label).toBe("No verdict");
  });

  it("says how each engine took part", () => {
    expect(engineRole(engine("URLhaus", { verdict: "unknown", vote: "no_record" })).label).toBe("No record");
    expect(engineRole(engine("ML", { verdict: "unknown", vote: "advisory" })).label).toBe("Advisory");
    expect(engineRole(engine("ClamAV", { verdict: "unknown", vote: "unavailable" })).label).toBe("Unavailable");
    expect(engineRole(engine("YARA", { verdict: "clean", vote: "counted" })).label).toBe("Nothing found");
    expect(engineRole(engine("YARA", { verdict: "malicious" })).role).toBe("flagged");
  });

  it("lists the files scanned inside an archive, worst first", () => {
    const archive = engine("Archive contents", {
      verdict: "malicious",
      metadata: {
        format: "zip",
        password_used: "infected",
        skipped: ["big.iso: larger than 32 MB unpacked"],
        files: [
          { path: "readme.txt", verdict: "Benign" },
          { path: "invoice.exe", verdict: "Malicious" },
        ],
      },
    });
    const facts = engineFacts(archive);
    expect(facts[0]).toMatchObject({ label: "Inside the zip", value: "invoice.exe: malicious", tone: "danger" });
    expect(facts[1].value).toBe("readme.txt: nothing found");
    expect(facts.find((f) => f.label === "Opened with password")?.value).toBe("infected");
    expect(facts.find((f) => f.label === "Not scanned")?.value).toContain("1 file");
  });

  it("shows the signature an engine found", () => {
    const clam = engine("ClamAV", { verdict: "malicious", metadata: { signature: "Eicar-Test-Signature" } });
    expect(engineFacts(clam)).toContainEqual({ label: "Signature", value: "Eicar-Test-Signature", tone: "danger" });
  });

  it("names the engine and signature that flagged a file inside an archive", () => {
    const archive = engine("Archive contents", {
      verdict: "malicious",
      metadata: {
        format: "zip",
        files: [
          {
            path: "eicar.txt",
            verdict: "Malicious",
            engines: [{ name: "ClamAV", verdict: "Malicious", signature: "Eicar-Test-Signature" }],
          },
          { path: "__MACOSX/._eicar.txt", verdict: "Benign", engines: [] },
        ],
      },
    });
    const facts = engineFacts(archive);
    expect(facts[0].value).toBe("eicar.txt: malicious by ClamAV (Eicar-Test-Signature)");
    expect(facts.map((f) => f.value)).not.toContain("__MACOSX/._eicar.txt: nothing found");
    expect(facts[1].value).toBe("1 macOS metadata file (added by Finder when zipping): not flagged");
  });

  it("reads the flagging engines from older scans' reasons", () => {
    const archive = engine("Archive contents", {
      verdict: "malicious",
      metadata: {
        format: "zip",
        reasons: ["eicar.txt: Malicious (ClamAV)"],
        files: [{ path: "eicar.txt", verdict: "Malicious" }],
      },
    });
    expect(engineFacts(archive)[0].value).toBe("eicar.txt: malicious by ClamAV");
  });

  it("still lists macOS metadata that was flagged", () => {
    const archive = engine("Archive contents", {
      verdict: "malicious",
      metadata: { format: "zip", files: [{ path: "__MACOSX/._x", verdict: "Malicious", engines: [{ name: "YARA" }] }] },
    });
    expect(engineFacts(archive)[0].value).toBe("__MACOSX/._x: malicious by YARA");
  });

  it("recognises Finder metadata and standard MIME types", () => {
    expect(isMacMetadata("__MACOSX/._eicar.txt")).toBe(true);
    expect(isMacMetadata("docs/.DS_Store")).toBe(true);
    expect(isMacMetadata("docs/._notes")).toBe(true);
    expect(isMacMetadata("eicar.txt")).toBe(false);
    expect(mimeLabel("zip")).toBe("application/zip");
    expect(mimeLabel("executable")).toBe("application/vnd.microsoft.portable-executable");
    expect(mimeLabel("text/plain")).toBe("text/plain");
    expect(mimeLabel(null)).toBeUndefined();
  });

  it("summarises flags from the vote counts", () => {
    const c: ApiConsensus = { totalVotes: 3, flaggedVotes: 1 };
    expect(flaggedSummary(c)).toBe("Flagged by 1 of 3 voting engines");
    expect(flaggedSummary({ totalVotes: 2, flaggedVotes: 0 })).toBe("None of 2 voting engines flagged it");
    expect(flaggedSummary({ totalVotes: 0 })).toBe("No engine gave a verdict");
  });

  it("explains a list match and the engines that didn't vote", () => {
    const c: ApiConsensus = {
      explanation: "Known malicious: listed by URLhaus. A match in a curated malware list decides the verdict. 2 of 3",
      unavailableEngines: [
        { engineName: "ThreatFox", reason: "Not listed", kind: "no_record" },
        { engineName: "ClamAV", reason: "down" },
      ],
    };
    expect(decidedBy(c)).toBe("Known malicious: listed by URLhaus.");
    expect(decidedBy({ explanation: "None of the 3 voting engines flagged it." })).toBeNull();
    expect(notVotingSummary(c)).toBe("Not voting: no record (ThreatFox); unavailable (ClamAV).");
    expect(notVotingSummary({})).toBeNull();
  });

  it("shows the evidence an engine recorded", () => {
    const urlhaus = engine("URLhaus", {
      verdict: "malicious",
      metadata: {
        listings: [{ matched: "url", indicator: "https://bad.example/a", malware: "Emotet", status: "online" }],
      },
    });
    expect(engineFacts(urlhaus)[0]).toMatchObject({ label: "Listed (url)", tone: "danger" });
    expect(engineFacts(urlhaus)[0].value).toContain("Emotet");

    const checks = engine("URL checks", {
      verdict: "clean",
      metadata: { tls: { valid: true, issuer: "Let's Encrypt", expires_in_days: 40 }, redirects: 0, page_title: "Home" },
    });
    const labels = engineFacts(checks).map((f) => f.label);
    expect(labels).toEqual(["TLS certificate", "Redirects", "Page title"]);

    const noRecord = engine("ThreatFox", { verdict: "unknown", vote: "no_record", reason: "Not listed on ThreatFox" });
    expect(engineFacts(noRecord)).toEqual([{ label: "Why no vote", value: "Not listed on ThreatFox" }]);
  });

  it("lists voting engines first, flagged before clear", () => {
    const sorted = sortEngines([
      engine("ThreatFox", { verdict: "unknown", vote: "no_record" }),
      engine("YARA", { verdict: "clean" }),
      engine("URLhaus", { verdict: "malicious" }),
    ]).map((a) => a.engine?.name);
    expect(sorted).toEqual(["URLhaus", "YARA", "ThreatFox"]);
  });

  it("exports Markdown with no invented numbers", () => {
    const md = markdownReport(
      {
        submissionId: "id-1",
        target: "https://example.com",
        targetType: "url",
        sha256: "should-not-appear-for-urls",
        consensus: {
          finalVerdict: "clean",
          totalVotes: 2,
          flaggedVotes: 0,
          explanation: "None of the 2 voting engines flagged it.",
          unavailableEngines: [{ engineName: "URLhaus", reason: "Not listed on URLhaus", kind: "no_record" }],
        },
        analyses: [
          engine("YARA", { verdict: "clean", confidence: 50 }),
          engine("URLhaus", { verdict: "unknown", vote: "no_record", reason: "Not listed on URLhaus" }),
        ],
      },
      new Date("2026-01-01T00:00:00Z"),
    );
    expect(md).toContain("**No threats found.** None of 2 voting engines flagged it.");
    expect(md).toContain("Not voting: no record (URLhaus).");
    expect(md).toContain("| YARA | Nothing found | 50% | — |");
    expect(md).toContain("| URLhaus | No record | — | Why no vote: Not listed on URLhaus |");
    expect(md).not.toContain("should-not-appear");
    expect(md).not.toMatch(/ETH|stake/i);
  });
});
