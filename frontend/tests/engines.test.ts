import { describe, expect, it } from "vitest";
import { engineState, votingEngines } from "../client/src/lib/engines";

describe("engineState", () => {
  it("maps the analysis engine's live status", () => {
    expect(engineState({ id: "y", name: "YARA", status: "online" })).toBe("voting");
    expect(engineState({ id: "m", name: "ML", status: "advisory" })).toBe("advisory");
    expect(engineState({ id: "c", name: "ClamAV", status: "disabled" })).toBe("off");
    expect(engineState({ id: "c", name: "ClamAV", status: "unavailable" })).toBe("off");
  });

  it("falls back to isActive for registered engines without a status", () => {
    expect(engineState({ id: "r", name: "Remote", isActive: false })).toBe("off");
    expect(engineState({ id: "r", name: "Remote", isActive: true })).toBe("voting");
  });

  it("counts only voting engines", () => {
    const engines = [
      { id: "1", name: "a", status: "online" },
      { id: "2", name: "b", status: "advisory" },
      { id: "3", name: "c", status: "disabled" },
      { id: "4", name: "d", status: "online" },
    ];
    expect(votingEngines(engines).map((e) => e.id)).toEqual(["1", "4"]);
  });
});
