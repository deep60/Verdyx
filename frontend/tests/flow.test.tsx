import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { LiveFlow } from "@/components/diagrams/live-flow";
import { CasePreview } from "@/components/case-preview";
import { SCENARIOS, buildLog, buildTimeline, findLiveEngine, progress, tally, withLiveEngines } from "@/lib/flow";

describe("tally", () => {
  it("lets a hash match decide on its own", () => {
    const t = tally([
      { id: "hash", name: "Hash", vote: "malicious", work: 1, note: "" },
      { id: "a", name: "A", vote: "clean", work: 1, note: "" },
      { id: "b", name: "B", vote: "clean", work: 1, note: "" },
    ]);
    expect(t.verdict).toBe("malicious");
  });

  it("never counts advisory engines or engines with no verdict", () => {
    const t = tally([
      { id: "a", name: "A", vote: "clean", work: 1, note: "" },
      { id: "ml", name: "ML", vote: "malicious", work: 1, note: "", advisory: true },
      { id: "c", name: "C", vote: "none", work: 1, note: "" },
    ]);
    expect(t).toMatchObject({ verdict: "clean", counted: 1, malicious: 0 });
  });

  it("says no verdict when nothing voted", () => {
    expect(tally([{ id: "a", name: "A", vote: "none", work: 1, note: "" }]).verdict).toBe("none");
  });

  it("gives each example the verdict its votes add up to", () => {
    expect(tally(SCENARIOS.file.engines).verdict).toBe("malicious");
    expect(tally(SCENARIOS.url.engines).verdict).toBe("malicious");
    expect(tally(SCENARIOS.email.engines).verdict).toBe("malicious");
  });
});

// What production's /api/engines returns: UUIDs, so engines are matched by name.
const PRODUCTION = [
  { id: "79617261-5f65", name: "YARA Engine", status: "online" },
  { id: "636c616d-6176", name: "ClamAV Scanner", status: "online" },
  { id: "6d6c5f65-6e67", name: "Machine Learning Classifier", status: "advisory" },
  { id: "70655f6d-6f64", name: "Windows Program Model (EMBER2024)", status: "online" },
];

describe("findLiveEngine", () => {
  it("matches engines by name, not by id", () => {
    expect(findLiveEngine("clamav", PRODUCTION)?.name).toBe("ClamAV Scanner");
    expect(findLiveEngine("pe_model", PRODUCTION)?.name).toBe("Windows Program Model (EMBER2024)");
    expect(findLiveEngine("ml", PRODUCTION)?.name).toBe("Machine Learning Classifier");
    expect(findLiveEngine("hash", PRODUCTION)).toBeUndefined();
  });
});

describe("withLiveEngines", () => {
  it("matches production: ClamAV and EMBER2024 vote, the untrained classifier advises", () => {
    const s = withLiveEngines(SCENARIOS.file, PRODUCTION);
    const by = (id: string) => s.engines.find((e) => e.id === id)!;
    expect(by("clamav")).toMatchObject({ vote: "malicious" });
    expect(by("clamav").advisory).toBeFalsy();
    expect(by("pe_model").advisory).toBeFalsy();
    expect(by("ml")).toMatchObject({ advisory: true, vote: "none" });
  });

  it("shows an engine that is off right now as not voting", () => {
    const s = withLiveEngines(SCENARIOS.file, [{ id: "x", name: "ClamAV Scanner", status: "unavailable" }]);
    expect(s.engines.find((e) => e.id === "clamav")).toMatchObject({ advisory: true, vote: "none" });
  });

  it("lets the classifier vote once it is trained", () => {
    const s = withLiveEngines(SCENARIOS.file, [{ id: "x", name: "Machine Learning Classifier", status: "online" }]);
    expect(s.engines.find((e) => e.id === "ml")).toMatchObject({ advisory: false, vote: "malicious" });
  });

  it("leaves URL and email examples alone", () => {
    expect(withLiveEngines(SCENARIOS.url, PRODUCTION)).toBe(SCENARIOS.url);
  });
});

describe("CasePreview", () => {
  const render = (engines?: unknown) => {
    const client = new QueryClient();
    if (engines) client.setQueryData(["/api/engines"], engines);
    return renderToStaticMarkup(
      <QueryClientProvider client={client}>
        <CasePreview />
      </QueryClientProvider>,
    );
  };

  it("counts ClamAV and EMBER2024, and leaves only the untrained classifier out", () => {
    const html = render(PRODUCTION);
    expect(html).toContain("7 of 8 · 5 malicious · 1 suspicious · 1 benign");
    expect(html).toContain("ML advisory");
    expect(html).not.toContain("ClamAV off");
  });

  it("shows an engine as off when production says so", () => {
    const html = render([{ id: "x", name: "ClamAV Scanner", status: "unavailable" }]);
    expect(html).toContain("ClamAV off");
    expect(html).toContain("6 of 8");
  });
});

describe("timeline", () => {
  it("runs ingest, engines, consensus and delivery in order", () => {
    const tl = buildTimeline(SCENARIOS.file);
    expect(tl.src[1]).toBeLessThanOrEqual(tl.gw[0]);
    expect(tl.queue[1]).toBeLessThanOrEqual(Math.min(...tl.engines.map((e) => e.start)));
    expect(tl.consensus[0]).toBe(Math.max(...tl.engines.map((e) => e.voted)));
    expect(tl.out[0]).toBe(tl.consensus[1]);
    expect(tl.end).toBeGreaterThan(tl.out[1]);
  });

  it("logs the consensus after every engine", () => {
    const tl = buildTimeline(SCENARIOS.email);
    const log = buildLog(SCENARIOS.email, tl);
    const consensus = log.findIndex((l) => l.who === "consensus");
    expect(consensus).toBeGreaterThan(log.findIndex((l) => l.who === "attachments"));
    expect(log[consensus].text).toMatch(/^MALICIOUS/);
  });

  it("clamps progress to 0..1", () => {
    expect(progress(-5, [0, 10])).toBe(0);
    expect(progress(50, [0, 10])).toBe(1);
    expect(progress(5, [0, 10])).toBeGreaterThan(0.5);
  });
});

describe("LiveFlow", () => {
  it("renders every stage and the file example by default", () => {
    const html = renderToStaticMarkup(
      <QueryClientProvider client={new QueryClient()}>
        <LiveFlow />
      </QueryClientProvider>,
    );
    for (const text of ["API gateway", "Redis queue", "Analysis engine", "Consensus", "Case report", "invoice.exe"]) {
      expect(html).toContain(text);
    }
  });
});
