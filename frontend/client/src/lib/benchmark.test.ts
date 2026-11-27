import { describe, expect, it } from "vitest";
import data from "@/data/benchmark.json";
import { fileTypeLabel, ofTotal, parseFamily, pct, runDate, shortEngine, sourceLabel, type BenchmarkData } from "./benchmark";

describe("pct", () => {
  it("rounds to one decimal and never shows a real hit as 0", () => {
    expect(pct(81, 197)).toBe("41.1%");
    expect(pct(0, 197)).toBe("0.0%");
    expect(pct(1, 5000)).toBe("<0.1%");
    expect(pct(3, 0)).toBe("–");
  });
});

describe("labels", () => {
  it("names clean-software releases plainly", () => {
    expect(sourceLabel("MinGit-2.47.0-64-bit")).toBe("MinGit 2.47.0");
    expect(sourceLabel("notepad++-8.7-portable-x64")).toBe("notepad++ 8.7");
    expect(sourceLabel("python-3.12.7-embed-amd64")).toBe("python 3.12.7");
    expect(sourceLabel("putty-0.81-w64")).toBe("putty 0.81");
    expect(sourceLabel("bootstrap-5.3.3-dist")).toBe("bootstrap 5.3.3");
    expect(sourceLabel("system-usr-bin")).toBe("Debian /usr/bin");
  });

  it("names file types and engines", () => {
    expect(fileTypeLabel("pe")).toBe("Windows programs and DLLs");
    expect(fileTypeLabel("wasm")).toBe("wasm");
    expect(shortEngine("Verdyx Static Analyzer")).toBe("Static");
    expect(shortEngine("Office Document Analyzer")).toBe("Office");
    expect(shortEngine("Android App Analyzer")).toBe("Android");
    expect(shortEngine("Verdyx Heuristic Engine")).toBe("Heuristic Engine");
  });

  it("reads family sample counts and run dates", () => {
    expect(parseFamily("MassLogger (4)")).toEqual({ name: "MassLogger", samples: 4 });
    expect(parseFamily("Odd name")).toEqual({ name: "Odd name", samples: 1 });
    expect(ofTotal(1200, 2038)).toBe("1,200 of 2,038");
    expect(runDate("2026-11-26T09:00:00Z")).toBe("26 November 2026");
  });
});

describe("published data", () => {
  const d = data as BenchmarkData;

  it("comes from a dated run", () => {
    expect(Number.isNaN(new Date(d.ranAt).getTime())).toBe(false);
  });

  it("adds up", () => {
    expect(d.consensus.malware.total).toBe(d.set.malicious);
    expect(d.consensus.clean.total).toBe(d.set.clean);
    expect(d.byFileType.reduce((n, g) => n + g.consensus.total, 0)).toBe(d.set.malicious);
    expect(d.bySource.reduce((n, g) => n + g.consensus.total, 0)).toBe(d.set.clean);
    expect(d.falsePositives).toHaveLength(d.consensus.clean.flagged);
    for (const e of d.engines) {
      expect(e.malware.flagged + e.malware.noVerdict).toBeLessThanOrEqual(e.malware.total);
    }
  });
});
