import type { ApiEngine } from "@/lib/api-types";
import { engineState } from "@/lib/engines";

/**
 * The example scans the architecture flow replays. Engine states come from the
 * live engine list, so an engine that is off or advisory right now is shown
 * that way in the replay too.
 */

export type FlowMode = "file" | "url" | "email";
export type Vote = "malicious" | "suspicious" | "clean" | "none";

export interface FlowEngine {
  id: string;
  name: string;
  vote: Vote;
  /** Time the engine spends on the sample in the replay, in ms. */
  work: number;
  note: string;
  /** Shown on the case but not counted. */
  advisory?: boolean;
}

export interface FlowScenario {
  mode: FlowMode;
  label: string;
  target: string;
  sourceId: string;
  sha: string;
  engines: FlowEngine[];
}

export const SCENARIOS: Record<FlowMode, FlowScenario> = {
  file: {
    mode: "file",
    label: "File",
    target: "invoice.exe",
    sourceId: "console",
    sha: "9f2c41d8…e07a",
    engines: [
      { id: "hash", name: "Hash", vote: "malicious", work: 320, note: "SHA-256 known to MalwareBazaar as AgentTesla" },
      { id: "static", name: "Static", vote: "suspicious", work: 620, note: "PE32, packed .text section, entropy 7.6" },
      {
        id: "signature",
        name: "Signature",
        vote: "malicious",
        work: 720,
        note: "UPX stub and credential-stealer strings",
      },
      { id: "yara", name: "YARA", vote: "malicious", work: 1150, note: "3 rules match, including AgentTesla_strings" },
      {
        id: "heuristic",
        name: "Heuristic",
        vote: "suspicious",
        work: 900,
        note: "Keylogger and clipboard API imports",
      },
      { id: "clamav", name: "ClamAV", vote: "malicious", work: 420, note: "Signature Win.Trojan.Agent" },
      {
        id: "pe_model",
        name: "EMBER2024 model",
        vote: "malicious",
        work: 540,
        note: "Trained on EMBER2024 features, scores it 0.97",
      },
      {
        id: "ml",
        name: "ML classifier",
        vote: "none",
        work: 380,
        note: "Not trained yet, so shown but not counted",
        advisory: true,
      },
    ],
  },
  url: {
    mode: "url",
    label: "URL",
    target: "paypa1.com/login",
    sourceId: "cli",
    sha: "url:4be1a07c…91d2",
    engines: [
      {
        id: "policy",
        name: "URL policy",
        vote: "none",
        work: 200,
        note: "Public host, allowed to fetch",
        advisory: true,
      },
      { id: "urlrep", name: "Reputation", vote: "malicious", work: 520, note: "URLhaus lists it as phishing" },
      {
        id: "recon",
        name: "Site recon",
        vote: "suspicious",
        work: 1300,
        note: "Domain is 3 days old; password form posts off-site",
      },
      { id: "vt", name: "VirusTotal", vote: "malicious", work: 950, note: "12 vendors flag it" },
    ],
  },
  email: {
    mode: "email",
    label: "Email",
    target: "invoice-reminder.eml",
    sourceId: "sdk",
    sha: "6d03aa5e…c41f",
    engines: [
      {
        id: "auth",
        name: "Sender auth",
        vote: "suspicious",
        work: 420,
        note: "DMARC fails and Reply-To differs from From",
      },
      { id: "links", name: "Links", vote: "malicious", work: 1200, note: "1 link to paypa1.com/login, known phishing" },
      {
        id: "attach",
        name: "Attachments",
        vote: "clean",
        work: 900,
        note: "invoice.pdf has no scripts or embedded files",
      },
    ],
  },
};

export const FLOW_MODES: FlowMode[] = ["file", "url", "email"];

/**
 * How to find each example engine in the live list. The API gives engines
 * UUIDs, so they are matched by name.
 */
const LIVE_NAME: Record<string, RegExp> = {
  hash: /hash/i,
  static: /static/i,
  signature: /signature/i,
  yara: /yara/i,
  heuristic: /heuristic/i,
  clamav: /clamav/i,
  pe_model: /ember|windows program model/i,
  ml: /machine learning|^ml\b/i,
};

/** The live engine an example engine stands for, if the API lists it. */
export function findLiveEngine(id: string, live: ApiEngine[] | undefined): ApiEngine | undefined {
  const pattern = LIVE_NAME[id];
  if (!pattern || !live) return undefined;
  return live.find((e) => pattern.test(e.name ?? ""));
}

/** Apply the live engine states to a scenario's file engines. */
export function withLiveEngines(scenario: FlowScenario, live: ApiEngine[] | undefined): FlowScenario {
  if (!live || live.length === 0 || scenario.mode !== "file") return scenario;
  return {
    ...scenario,
    engines: scenario.engines.map((step) => {
      const engine = findLiveEngine(step.id, live);
      if (!engine) return step;
      const state = engineState(engine);
      if (state === "off") {
        return { ...step, vote: "none", advisory: true, note: "Switched off right now, so named on the case" };
      }
      if (state === "advisory") {
        return {
          ...step,
          advisory: true,
          vote: "none",
          note: step.advisory ? step.note : `${step.note}, advisory only`,
        };
      }
      // Voting. The untrained classifier only votes once it has been trained.
      if (step.advisory) return { ...step, advisory: false, vote: "malicious", note: "Predicts malicious (0.91)" };
      return step;
    }),
  };
}

export interface Tally {
  verdict: Vote;
  counted: number;
  malicious: number;
  suspicious: number;
  clean: number;
}

/**
 * Majority of the engines that returned a verdict. A hash match against a
 * curated malware list decides on its own, as it does in the consensus service.
 */
export function tally(engines: FlowEngine[]): Tally {
  const counted = engines.filter((e) => !e.advisory && e.vote !== "none");
  const n = (v: Vote) => counted.filter((e) => e.vote === v).length;
  const malicious = n("malicious");
  const suspicious = n("suspicious");
  const clean = n("clean");
  let verdict: Vote = "none";
  if (counted.some((e) => e.id === "hash" && e.vote === "malicious")) verdict = "malicious";
  else if (malicious + suspicious > clean) verdict = malicious >= suspicious ? "malicious" : "suspicious";
  else if (counted.length > 0) verdict = "clean";
  return { verdict, counted: counted.length, malicious, suspicious, clean };
}

/** Every moment of one replay, in ms from the start. */
export interface Timeline {
  src: [number, number];
  gw: [number, number];
  gwSub: [number, number];
  sub: [number, number];
  subOut: [number, number];
  queue: [number, number];
  engines: { start: number; arrive: number; done: number; voted: number }[];
  consensus: [number, number];
  out: [number, number];
  end: number;
}

export const HOLD_MS = 2600;

export function buildTimeline(scenario: FlowScenario): Timeline {
  const engines = scenario.engines.map((e, i) => {
    const start = 2050 + i * 45;
    const arrive = start + 550;
    const done = arrive + e.work;
    return { start, arrive, done, voted: done + 600 };
  });
  const lastVote = Math.max(...engines.map((e) => e.voted));
  const consensus: [number, number] = [lastVote, lastVote + 450];
  const out: [number, number] = [consensus[1], consensus[1] + 650];
  return {
    src: [0, 550],
    gw: [550, 800],
    gwSub: [800, 1300],
    sub: [1300, 1450],
    subOut: [1450, 1900],
    queue: [1900, 2050],
    engines,
    consensus,
    out,
    end: out[1] + HOLD_MS,
  };
}

/** 0→1 progress through [a, b], eased out. */
export function progress(t: number, [a, b]: [number, number]): number {
  if (t <= a) return 0;
  if (t >= b) return 1;
  const u = (t - a) / (b - a);
  return 1 - Math.pow(1 - u, 3);
}

export function within(t: number, [a, b]: [number, number]): boolean {
  return t >= a && t < b;
}

export const VOTE_LABEL: Record<Vote, string> = {
  malicious: "Malicious",
  suspicious: "Suspicious",
  clean: "Clean",
  none: "No verdict",
};

export interface LogLine {
  at: number;
  who: string;
  text: string;
  tone?: Vote | "mark";
}

/** What the services would print during the replay. */
export function buildLog(scenario: FlowScenario, tl: Timeline): LogLine[] {
  const endpoint = scenario.mode === "url" ? "url" : "file";
  const t = tally(scenario.engines);
  const lines: LogLine[] = [
    { at: tl.gw[0], who: "gateway", text: `POST /api/v1/submissions/${endpoint} · key ok · rate ok → 202` },
    { at: tl.sub[0], who: "submission", text: `${scenario.target} · sha256 ${scenario.sha} · stored` },
    { at: tl.queue[0], who: "queue", text: `job enqueued on redis · ${scenario.engines.length} engines` },
    ...scenario.engines.map((e, i) => ({
      at: tl.engines[i].done,
      who: e.name.toLowerCase(),
      text: `${e.advisory ? "advisory" : VOTE_LABEL[e.vote].toLowerCase()} · ${e.note}`,
      tone: e.advisory ? ("none" as const) : e.vote,
    })),
    {
      at: tl.consensus[1],
      who: "consensus",
      text: `${VOTE_LABEL[t.verdict].toUpperCase()} · ${t.counted} engines voted (${t.malicious} malicious, ${t.suspicious} suspicious, ${t.clean} clean)`,
      tone: t.verdict,
    },
    { at: tl.out[0] + 200, who: "notify", text: "ws analysis_completed · webhooks delivered", tone: "mark" },
  ];
  return lines.sort((a, b) => a.at - b.at);
}
