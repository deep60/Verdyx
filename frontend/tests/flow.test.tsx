import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { LiveFlow } from "@/components/diagrams/live-flow";
import { SCENARIOS, buildLog, buildTimeline, progress, tally, withLiveEngines } from "@/lib/flow";

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

describe("withLiveEngines", () => {
  it("shows an engine that is off right now as not voting", () => {
    const s = withLiveEngines(SCENARIOS.file, [{ id: "yara", name: "YARA", status: "unavailable" }]);
    const yara = s.engines.find((e) => e.id === "yara")!;
    expect(yara).toMatchObject({ advisory: true, vote: "none" });
  });

  it("lets ClamAV vote once it is online", () => {
    const s = withLiveEngines(SCENARIOS.file, [{ id: "clamav", name: "ClamAV", status: "online" }]);
    expect(s.engines.find((e) => e.id === "clamav")).toMatchObject({ advisory: false, vote: "malicious" });
  });

  it("leaves URL and email examples alone", () => {
    expect(withLiveEngines(SCENARIOS.url, [{ id: "yara", name: "YARA", status: "off" }])).toBe(SCENARIOS.url);
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
