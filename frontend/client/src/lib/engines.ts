import type { ApiEngine } from "@/lib/api-types";

/** How an engine takes part in a verdict right now. */
export type EngineState = "voting" | "advisory" | "off";

export function engineState(engine: ApiEngine): EngineState {
  const status = (engine.status ?? "").toLowerCase();
  if (status === "advisory") return "advisory";
  if (status === "online") return "voting";
  if (status) return "off"; // disabled, unavailable, degraded
  return engine.isActive === false ? "off" : "voting";
}

export const ENGINE_STATE_LABEL: Record<EngineState, string> = {
  voting: "Votes",
  advisory: "Advisory",
  off: "Off",
};

/** Engines whose verdict counts toward the consensus. */
export function votingEngines(engines: ApiEngine[]): ApiEngine[] {
  return engines.filter((e) => engineState(e) === "voting");
}
