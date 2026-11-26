import { useEffect, useMemo, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { FileCode2, Globe, Mail, Pause, Play, RotateCcw } from "lucide-react";
import type { ApiEngine } from "@/lib/api-types";
import { engineState, type EngineState } from "@/lib/engines";
import { cn } from "@/lib/utils";
import {
  FLOW_MODES,
  type FlowMode,
  type Vote,
  SCENARIOS,
  VOTE_LABEL,
  buildLog,
  buildTimeline,
  findLiveEngine,
  progress,
  tally,
  withLiveEngines,
  within,
} from "@/lib/flow";

// ─── Geometry (SVG user units) ──────────────────────────────────

const W = 1400;
const H = 560;
const MID = 270;

type Pt = { x: number; y: number };
type Box = { x: number; y: number; w: number; h: number };

const SOURCES = [
  { id: "console", label: "Console", sub: "verdyx.dev" },
  { id: "cli", label: "CLI", sub: "verdyx scan" },
  { id: "sdk", label: "SDKs", sub: "Python · JS" },
  { id: "action", label: "GitHub Action", sub: "on every push" },
  { id: "mcp", label: "MCP server", sub: "AI assistants" },
].map((s, i) => ({ ...s, box: { x: 20, y: MID + (i - 2) * 54 - 20, w: 150, h: 40 } }));

const GATEWAY: Box = { x: 240, y: MID - 40, w: 160, h: 80 };
const SUBMISSION: Box = { x: 460, y: MID - 40, w: 160, h: 80 };
const STORAGE: Box = { x: 460, y: 400, w: 160, h: 56 };
const QUEUE: Box = { x: 680, y: MID - 35, w: 130, h: 70 };
const ENGINE_AREA: Box = { x: 860, y: 40, w: 210, h: 470 };
const CONSENSUS = { cx: 1160, cy: MID, r: 44 };

/** Centre of each part, for following the scan on a narrow screen. */
const COLUMN_X: Record<string, number> = {
  sources: 95,
  gateway: 320,
  submission: 540,
  queue: 745,
  engines: 965,
  consensus: 1160,
  outputs: 1317,
};

const OUTPUTS = [
  { id: "report", label: "Case report", sub: "every vote kept" },
  { id: "ws", label: "WebSocket", sub: "live in the console" },
  { id: "webhook", label: "Webhooks", sub: "your endpoints" },
  { id: "exit", label: "CI exit code", sub: "2 at --fail-on" },
].map((o, i) => ({ ...o, box: { x: 1250, y: MID + (i - 1.5) * 52 - 20, w: 135, h: 40 } }));

function engineBoxes(n: number): Box[] {
  const h = 36;
  const step = 46;
  const top = 285 - (n * step - (step - h)) / 2;
  return Array.from({ length: n }, (_, i) => ({ x: ENGINE_AREA.x + 16, y: top + i * step, w: 178, h }));
}

const right = (b: Box): Pt => ({ x: b.x + b.w, y: b.y + b.h / 2 });
const left = (b: Box): Pt => ({ x: b.x, y: b.y + b.h / 2 });

/** A horizontal S-curve from a to b, with its path and a point-at function. */
function curve(a: Pt, b: Pt) {
  const dx = (b.x - a.x) / 2;
  const c1 = { x: a.x + dx, y: a.y };
  const c2 = { x: b.x - dx, y: b.y };
  const at = (u: number): Pt => {
    const v = 1 - u;
    return {
      x: v * v * v * a.x + 3 * v * v * u * c1.x + 3 * v * u * u * c2.x + u * u * u * b.x,
      y: v * v * v * a.y + 3 * v * v * u * c1.y + 3 * v * u * u * c2.y + u * u * u * b.y,
    };
  };
  return { d: `M${a.x} ${a.y} C${c1.x} ${c1.y}, ${c2.x} ${c2.y}, ${b.x} ${b.y}`, at };
}

function line(a: Pt, b: Pt) {
  return {
    d: `M${a.x} ${a.y} L${b.x} ${b.y}`,
    at: (u: number) => ({ x: a.x + (b.x - a.x) * u, y: a.y + (b.y - a.y) * u }),
  };
}

// ─── Colours by vote ────────────────────────────────────────────

const VOTE_FILL: Record<Vote, string> = {
  malicious: "fill-destructive",
  suspicious: "fill-warning",
  clean: "fill-success",
  none: "fill-muted-foreground",
};
const VOTE_STROKE: Record<Vote, string> = {
  malicious: "stroke-destructive",
  suspicious: "stroke-warning",
  clean: "stroke-success",
  none: "stroke-muted-foreground",
};
const VOTE_TEXT: Record<Vote, string> = {
  malicious: "text-destructive",
  suspicious: "text-warning",
  clean: "text-success",
  none: "text-muted-foreground",
};
const VOTE_SHORT: Record<Vote, string> = { malicious: "MAL", suspicious: "SUS", clean: "CLEAN", none: "—" };

const LIVE_DOT: Record<EngineState, string> = {
  voting: "fill-success",
  advisory: "fill-warning",
  off: "fill-muted-foreground",
};

const MODE_ICON: Record<FlowMode, typeof Globe> = { file: FileCode2, url: Globe, email: Mail };

// ─── What each part does ────────────────────────────────────────

const INFO: Record<string, { title: string; tech: string; text: string }> = {
  sources: {
    title: "Where scans come from",
    tech: "Console · CLI · SDKs · Action · MCP",
    text: "The console, the verdyx CLI, the Python and JavaScript SDKs, the GitHub Action and the MCP server all call the same REST API, with a session or an API key.",
  },
  gateway: {
    title: "API gateway",
    tech: "api-gateway · Rust, axum",
    text: "Checks the session or X-API-Key, applies rate limits and CSRF, and routes each call to the right service. It also holds the WebSocket that pushes results back.",
  },
  submission: {
    title: "Submission service",
    tech: "submission-service · Rust, axum",
    text: "Hashes the upload with SHA-256, matches it against earlier scans, writes the bytes to object storage and the record to Postgres, then queues the job.",
  },
  storage: {
    title: "Storage",
    tech: "Postgres · S3-compatible object store",
    text: "Postgres keeps submissions, analyses and verdicts. The object store keeps the file itself, so every engine reads exactly the same bytes.",
  },
  queue: {
    title: "Job queue",
    tech: "Redis",
    text: "The upload returns as soon as the job is queued. A slow engine never holds up the request, and work spreads across analysis workers.",
  },
  engines: {
    title: "Analysis engine",
    tech: "analysis-engine · Rust, tokio",
    text: "Pulls jobs from Redis, unpacks archives, and runs every engine on the sample in parallel. Each one returns a verdict, a confidence and its evidence, or says it has none.",
  },
  consensus: {
    title: "Consensus",
    tech: "consensus-service · Rust",
    text: "A majority vote of the engines that returned a verdict. A hash match in a curated malware list decides on its own. Advisory and failed engines are named on the case, never counted as clean.",
  },
  outputs: {
    title: "Delivery",
    tech: "notification-service · WebSocket · webhooks",
    text: "The case report keeps every vote and its evidence. The console updates over WebSocket without a reload, webhooks reach your endpoints, and the CLI exits 2 when the verdict reaches your fail-on level.",
  },
};

// ─── Small parts ────────────────────────────────────────────────

type NodeState = "idle" | "active" | "done";

function stateAt(t: number, [a, b]: [number, number]): NodeState {
  if (t < a) return "idle";
  if (t < b) return "active";
  return "done";
}

function Node({
  box,
  title,
  sub,
  state,
  selected,
  onSelect,
  children,
}: {
  box: Box;
  title: string;
  sub?: string;
  state: NodeState;
  selected: boolean;
  onSelect: () => void;
  children?: React.ReactNode;
}) {
  const big = box.h >= 56;
  return (
    <g
      role="button"
      tabIndex={0}
      aria-label={`${title}${sub ? `, ${sub}` : ""}`}
      onClick={onSelect}
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          onSelect();
        }
      }}
      className="cursor-pointer outline-none [&:focus-visible>rect.frame]:stroke-foreground"
    >
      {state === "active" && (
        <rect
          x={box.x - 4}
          y={box.y - 4}
          width={box.w + 8}
          height={box.h + 8}
          rx={9}
          className="animate-pulse fill-mark/10 stroke-mark/30"
        />
      )}
      <rect
        x={box.x}
        y={box.y}
        width={box.w}
        height={box.h}
        rx={6}
        className={cn(
          "frame fill-card transition-[stroke] duration-300",
          state === "active" ? "stroke-mark" : state === "done" ? "stroke-mark/45" : "stroke-border",
          selected && "stroke-foreground/70",
        )}
        strokeWidth={state === "active" || selected ? 1.5 : 1}
      />
      <text
        x={box.x + 12}
        y={box.y + (sub ? (big ? 30 : 17) : box.h / 2 + 4)}
        className={cn("fill-foreground font-medium", big ? "text-[14px]" : "text-[12px]")}
      >
        {title}
      </text>
      {sub && (
        <text x={box.x + 12} y={box.y + (big ? 50 : 31)} className="fill-muted-foreground font-mono text-[10px]">
          {sub}
        </text>
      )}
      {children}
    </g>
  );
}

// ─── The flow ───────────────────────────────────────────────────

function prefersReducedMotion() {
  return typeof window !== "undefined" && window.matchMedia?.("(prefers-reduced-motion: reduce)").matches === true;
}

export function LiveFlow({ compact = false }: { compact?: boolean }) {
  const { data: liveEngines } = useQuery<ApiEngine[]>({ queryKey: ["/api/engines"], refetchInterval: 60_000 });
  const live = Array.isArray(liveEngines) && liveEngines.length > 0 ? liveEngines : undefined;

  const [mode, setMode] = useState<FlowMode>("file");
  const [tour, setTour] = useState(true);
  const [playing, setPlaying] = useState(() => !prefersReducedMotion());
  const [visible, setVisible] = useState(true);
  const [picked, setPicked] = useState<string | null>(null);

  const scenario = useMemo(() => withLiveEngines(SCENARIOS[mode], live), [mode, live]);
  const tl = useMemo(() => buildTimeline(scenario), [scenario]);
  const result = useMemo(() => tally(scenario.engines), [scenario]);
  const log = useMemo(() => buildLog(scenario, tl), [scenario, tl]);

  // Reduced motion starts on the finished picture.
  const [t, setT] = useState(() => (prefersReducedMotion() ? tl.out[1] : 0));
  const tRef = useRef(t);
  const tlRef = useRef(tl);
  const tourRef = useRef(tour);
  tlRef.current = tl;
  tourRef.current = tour;

  const wrapRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const el = wrapRef.current;
    if (!el || typeof IntersectionObserver === "undefined") return;
    const io = new IntersectionObserver(([entry]) => setVisible(entry.isIntersecting), { threshold: 0.15 });
    io.observe(el);
    return () => io.disconnect();
  }, []);

  useEffect(() => {
    if (!playing || !visible) return;
    let frame = 0;
    let last = performance.now();
    const tick = (now: number) => {
      // Keep real time on slow devices, but skip the gap after a hidden tab.
      const dt = Math.min(250, now - last);
      last = now;
      let next = tRef.current + dt;
      if (next >= tlRef.current.end) {
        next = 0;
        if (tourRef.current) setMode((m) => FLOW_MODES[(FLOW_MODES.indexOf(m) + 1) % FLOW_MODES.length]);
      }
      tRef.current = next;
      setT(next);
      frame = requestAnimationFrame(tick);
    };
    frame = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(frame);
  }, [playing, visible]);

  const restart = () => {
    tRef.current = 0;
    setT(0);
    setPlaying(true);
  };

  const chooseMode = (m: FlowMode) => {
    setTour(false);
    setMode(m);
    setPicked(null);
    restart();
  };

  // ── Geometry for this scenario ──
  const eBoxes = engineBoxes(scenario.engines.length);
  const source = SOURCES.find((s) => s.id === scenario.sourceId) ?? SOURCES[0];
  const consLeft = { x: CONSENSUS.cx - CONSENSUS.r, y: CONSENSUS.cy };
  const consRight = { x: CONSENSUS.cx + CONSENSUS.r, y: CONSENSUS.cy };

  const edges = {
    src: SOURCES.map((s) => curve(right(s.box), left(GATEWAY))),
    gwSub: curve(right(GATEWAY), left(SUBMISSION)),
    subStore: line(
      { x: SUBMISSION.x + SUBMISSION.w / 2, y: SUBMISSION.y + SUBMISSION.h },
      { x: STORAGE.x + STORAGE.w / 2, y: STORAGE.y },
    ),
    subQueue: curve(right(SUBMISSION), left(QUEUE)),
    fan: eBoxes.map((b) => curve(right(QUEUE), left(b))),
    vote: eBoxes.map((b) => curve(right(b), consLeft)),
    out: OUTPUTS.map((o) => curve(consRight, left(o.box))),
  };

  const edgeClass = (w: [number, number], highlight = true, tone = "stroke-mark") =>
    !highlight
      ? "stroke-border"
      : within(t, w)
        ? cn(tone, "flow-dash")
        : t >= w[1]
          ? tone === "stroke-mark"
            ? "stroke-mark/40"
            : cn(tone, "opacity-50")
          : "stroke-border";

  // ── Packets in flight ──
  const packets: { key: string; at: (u: number) => Pt; w: [number, number]; fill: string }[] = [];
  const srcIndex = SOURCES.indexOf(source);
  packets.push({ key: "src", at: edges.src[srcIndex].at, w: tl.src, fill: "fill-mark" });
  packets.push({ key: "gwSub", at: edges.gwSub.at, w: tl.gwSub, fill: "fill-mark" });
  packets.push({ key: "subStore", at: edges.subStore.at, w: tl.subOut, fill: "fill-mark" });
  packets.push({ key: "subQueue", at: edges.subQueue.at, w: tl.subOut, fill: "fill-mark" });
  scenario.engines.forEach((e, i) => {
    const step = tl.engines[i];
    packets.push({ key: `fan-${e.id}`, at: edges.fan[i].at, w: [step.start, step.arrive], fill: "fill-mark" });
    packets.push({
      key: `vote-${e.id}`,
      at: edges.vote[i].at,
      w: [step.done, step.voted],
      fill: e.advisory ? "fill-muted-foreground" : VOTE_FILL[e.vote],
    });
  });
  OUTPUTS.forEach((o, i) => packets.push({ key: `out-${o.id}`, at: edges.out[i].at, w: tl.out, fill: "fill-mark" }));
  const flying = packets.filter((p) => within(t, p.w));

  // ── Consensus ring ──
  const counted = scenario.engines
    .map((e, i) => ({ e, voted: tl.engines[i].voted }))
    .filter(({ e }) => !e.advisory && e.vote !== "none");
  const arrived = counted.filter((c) => t >= c.voted);
  const circ = 2 * Math.PI * CONSENSUS.r;
  const seg = counted.length > 0 ? circ / counted.length : circ;
  const consState = stateAt(t, [tl.engines[0].done + 600, tl.consensus[1]]);
  const decided = t >= tl.consensus[1];

  // ── Which part is "now" ──
  const current =
    t < tl.gw[1]
      ? t < tl.src[1]
        ? "sources"
        : "gateway"
      : t < tl.subOut[1]
        ? "submission"
        : t < tl.queue[1]
          ? "queue"
          : t < tl.consensus[0]
            ? "engines"
            : t < tl.out[0]
              ? "consensus"
              : "outputs";
  const shown = picked ?? current;
  const info = INFO[shown] ?? INFO.engines;

  const stages = [
    { id: "ingest", label: "Ingest", w: [0, tl.sub[1]] as [number, number] },
    { id: "queue", label: "Store and queue", w: [tl.sub[1], tl.queue[1]] as [number, number] },
    { id: "engines", label: "Engines", w: [tl.queue[1], tl.consensus[0]] as [number, number] },
    { id: "consensus", label: "Consensus", w: tl.consensus },
    { id: "deliver", label: "Deliver", w: tl.out },
  ];

  const visibleLog = log.filter((l) => l.at <= t).slice(compact ? -3 : -7);
  const voting = live ? live.filter((e) => engineState(e) === "voting").length : null;
  const select = (id: string) => setPicked((p) => (p === id ? null : id));

  // On a narrow screen the chart scrolls sideways; keep the active part in view.
  const scrollerRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const el = scrollerRef.current;
    if (!el || picked || el.scrollWidth <= el.clientWidth + 4) return;
    const scale = el.scrollWidth / W;
    const target = COLUMN_X[current] * scale - el.clientWidth / 2;
    el.scrollTo({ left: Math.max(0, target), behavior: prefersReducedMotion() ? "auto" : "smooth" });
  }, [current, picked]);

  return (
    <div
      ref={wrapRef}
      className="dark overflow-hidden rounded-xl border border-border bg-background text-foreground shadow-[0_30px_80px_-30px_rgba(20,21,19,0.55)]"
      data-testid="live-flow"
    >
      {/* Toolbar */}
      <div className="flex flex-col gap-3 border-b border-border px-4 py-3 sm:flex-row sm:items-center sm:justify-between sm:px-5">
        <div className="flex items-center gap-1 rounded-md bg-muted/60 p-1" role="tablist" aria-label="Example scan">
          {FLOW_MODES.map((m) => {
            const Icon = MODE_ICON[m];
            const active = m === mode;
            return (
              <button
                key={m}
                type="button"
                role="tab"
                aria-selected={active}
                onClick={() => chooseMode(m)}
                data-testid={`flow-mode-${m}`}
                className={cn(
                  "inline-flex items-center gap-1.5 rounded px-3 py-1.5 text-xs font-medium transition-colors",
                  active ? "bg-mark text-mark-foreground" : "text-muted-foreground hover:text-foreground",
                )}
              >
                <Icon className="h-3.5 w-3.5" aria-hidden />
                {SCENARIOS[m].label}
              </button>
            );
          })}
          <span className="ml-2 hidden truncate font-mono text-[11px] text-muted-foreground sm:inline">
            {scenario.target}
          </span>
        </div>
        <div className="flex items-center gap-2">
          <span className="mr-1 inline-flex items-center gap-2 font-mono text-[11px] text-muted-foreground">
            <span className="relative flex h-2 w-2">
              <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-mark opacity-60" />
              <span className="relative inline-flex h-2 w-2 rounded-full bg-mark" />
            </span>
            {voting !== null ? `${voting} engines voting now` : "Example replay"}
          </span>
          <button
            type="button"
            onClick={() => setPlaying((p) => !p)}
            className="inline-flex h-8 w-8 items-center justify-center rounded-md border border-border text-muted-foreground transition-colors hover:border-mark hover:text-mark"
            aria-label={playing ? "Pause" : "Play"}
            data-testid="flow-play"
          >
            {playing ? <Pause className="h-3.5 w-3.5" /> : <Play className="h-3.5 w-3.5" />}
          </button>
          <button
            type="button"
            onClick={restart}
            className="inline-flex h-8 w-8 items-center justify-center rounded-md border border-border text-muted-foreground transition-colors hover:border-mark hover:text-mark"
            aria-label="Replay from the start"
          >
            <RotateCcw className="h-3.5 w-3.5" />
          </button>
        </div>
      </div>

      {/* Chart */}
      <div
        ref={scrollerRef}
        className="relative overflow-x-auto bg-[radial-gradient(hsl(var(--foreground)/0.07)_1px,transparent_1px)] [background-size:22px_22px]"
      >
        <svg
          viewBox={`0 0 ${W} ${H}`}
          className="block h-auto w-full min-w-[920px]"
          role="img"
          aria-label={`How a ${SCENARIOS[mode].label.toLowerCase()} scan moves through Verdyx, from the API gateway through the queue and ${scenario.engines.length} engines to a consensus verdict.`}
        >
          <defs>
            <filter id="flow-glow" x="-200%" y="-200%" width="500%" height="500%">
              <feGaussianBlur stdDeviation="4" result="b" />
              <feMerge>
                <feMergeNode in="b" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>
          </defs>

          {/* Column captions */}
          {[
            { x: 20, label: "01 · Sources" },
            { x: 240, label: "02 · Gateway" },
            { x: 460, label: "03 · Ingest" },
            { x: 680, label: "04 · Queue" },
            { x: ENGINE_AREA.x, label: "05 · Engines" },
            { x: CONSENSUS.cx - 44, label: "06 · Verdict" },
            { x: 1250, label: "07 · Delivery" },
          ].map((c) => (
            <text
              key={c.label}
              x={c.x}
              y={24}
              className="fill-muted-foreground font-mono text-[10px] uppercase tracking-[0.18em]"
            >
              {c.label}
            </text>
          ))}

          {/* Edges */}
          <g fill="none" strokeWidth={1.25}>
            {edges.src.map((e, i) => (
              <path key={SOURCES[i].id} d={e.d} className={edgeClass(tl.src, i === srcIndex)} />
            ))}
            <path d={edges.gwSub.d} className={edgeClass(tl.gwSub)} />
            <path d={edges.subStore.d} className={edgeClass(tl.subOut)} />
            <path d={edges.subQueue.d} className={edgeClass(tl.subOut)} />
            {edges.fan.map((e, i) => (
              <path key={`f${i}`} d={e.d} className={edgeClass([tl.engines[i].start, tl.engines[i].arrive])} />
            ))}
            {edges.vote.map((e, i) => {
              const eng = scenario.engines[i];
              return (
                <path
                  key={`v${i}`}
                  d={e.d}
                  strokeDasharray={eng.advisory ? "2 4" : undefined}
                  className={edgeClass(
                    [tl.engines[i].done, tl.engines[i].voted],
                    true,
                    eng.advisory ? "stroke-muted-foreground" : VOTE_STROKE[eng.vote],
                  )}
                />
              );
            })}
            {edges.out.map((e, i) => (
              <path key={`o${i}`} d={e.d} className={edgeClass(tl.out)} />
            ))}
          </g>

          {/* Sources */}
          {SOURCES.map((s) => (
            <Node
              key={s.id}
              box={s.box}
              title={s.label}
              sub={s.sub}
              state={s.id === source.id ? stateAt(t, [0, tl.src[1]]) : "idle"}
              selected={shown === "sources"}
              onSelect={() => select("sources")}
            />
          ))}

          <Node
            box={GATEWAY}
            title="API gateway"
            sub="auth · rate limit · ws"
            state={stateAt(t, [tl.src[1] - 80, tl.gwSub[0] + 120])}
            selected={shown === "gateway"}
            onSelect={() => select("gateway")}
          />
          <Node
            box={SUBMISSION}
            title="Submission"
            sub="sha-256 · dedupe"
            state={stateAt(t, [tl.gwSub[1] - 80, tl.subOut[0] + 120])}
            selected={shown === "submission"}
            onSelect={() => select("submission")}
          />
          <Node
            box={STORAGE}
            title="Postgres + S3"
            sub="record · bytes"
            state={stateAt(t, [tl.subOut[1] - 60, tl.subOut[1] + 300])}
            selected={shown === "storage"}
            onSelect={() => select("storage")}
          />
          <Node
            box={QUEUE}
            title="Redis queue"
            sub="job"
            state={stateAt(t, [tl.subOut[1] - 60, tl.engines[tl.engines.length - 1].start + 200])}
            selected={shown === "queue"}
            onSelect={() => select("queue")}
          >
            {/* Job slots */}
            {[0, 1, 2, 3].map((k) => (
              <rect
                key={k}
                x={QUEUE.x + 70 + k * 13}
                y={QUEUE.y + 42}
                width={9}
                height={14}
                rx={1.5}
                className={cn(
                  "transition-colors duration-300",
                  k === 0 && within(t, [tl.subOut[1] - 60, tl.engines[0].start + 100]) ? "fill-mark" : "fill-muted",
                )}
              />
            ))}
          </Node>

          {/* Engine area */}
          <g
            role="button"
            tabIndex={0}
            aria-label="Analysis engine"
            onClick={() => select("engines")}
            onKeyDown={(e) => {
              if (e.key === "Enter" || e.key === " ") {
                e.preventDefault();
                select("engines");
              }
            }}
            className="cursor-pointer outline-none"
          >
            <rect
              x={ENGINE_AREA.x}
              y={ENGINE_AREA.y}
              width={ENGINE_AREA.w}
              height={ENGINE_AREA.h}
              rx={10}
              strokeDasharray="3 5"
              className={cn(
                "fill-card/40",
                shown === "engines"
                  ? "stroke-foreground/60"
                  : current === "engines"
                    ? "stroke-mark/60"
                    : "stroke-border",
              )}
            />
            <text x={ENGINE_AREA.x + 16} y={ENGINE_AREA.y + 26} className="fill-foreground text-[13px] font-medium">
              Analysis engine
            </text>
            <text x={ENGINE_AREA.x + 16} y={ENGINE_AREA.y + 42} className="fill-muted-foreground font-mono text-[10px]">
              rust · runs in parallel
            </text>
          </g>

          {scenario.engines.map((e, i) => {
            const b = eBoxes[i];
            const step = tl.engines[i];
            const state = stateAt(t, [step.arrive, step.done]);
            const work = state === "active" ? (t - step.arrive) / (step.done - step.arrive) : state === "done" ? 1 : 0;
            const liveEngine = findLiveEngine(e.id, live);
            return (
              <g key={e.id} className="animate-fade-in">
                <rect
                  x={b.x}
                  y={b.y}
                  width={b.w}
                  height={b.h}
                  rx={5}
                  className={cn(
                    "fill-card transition-[stroke] duration-300",
                    state === "active" ? "stroke-mark" : state === "done" ? "stroke-border" : "stroke-border/70",
                  )}
                  strokeWidth={state === "active" ? 1.5 : 1}
                />
                {/* Work bar */}
                <rect
                  x={b.x}
                  y={b.y + b.h - 2.5}
                  width={b.w * work}
                  height={2.5}
                  className={cn(
                    state === "done"
                      ? e.advisory
                        ? "fill-muted-foreground/40"
                        : `${VOTE_FILL[e.vote]} opacity-60`
                      : "fill-mark/80",
                  )}
                />
                <circle
                  cx={b.x + 13}
                  cy={b.y + b.h / 2}
                  r={3.5}
                  className={
                    liveEngine
                      ? LIVE_DOT[engineState(liveEngine)]
                      : e.advisory
                        ? "fill-warning"
                        : "fill-muted-foreground/60"
                  }
                >
                  <title>{liveEngine ? `Live: ${engineState(liveEngine)}` : "Example"}</title>
                </circle>
                <text x={b.x + 24} y={b.y + b.h / 2 + 4} className="fill-foreground text-[12px]">
                  {e.name}
                </text>
                {state === "done" && (
                  <text
                    x={b.x + b.w - 10}
                    y={b.y + b.h / 2 + 3.5}
                    textAnchor="end"
                    className={cn(
                      "animate-fade-in font-mono text-[10px] font-semibold tracking-wider",
                      e.advisory ? "fill-muted-foreground" : VOTE_FILL[e.vote],
                    )}
                  >
                    {e.advisory ? "ADVISORY" : VOTE_SHORT[e.vote]}
                  </text>
                )}
                {state === "active" && (
                  <text
                    x={b.x + b.w - 10}
                    y={b.y + b.h / 2 + 3.5}
                    textAnchor="end"
                    className="fill-mark font-mono text-[10px]"
                  >
                    {Math.round(work * 100)}%
                  </text>
                )}
              </g>
            );
          })}

          {/* Consensus */}
          <g
            role="button"
            tabIndex={0}
            aria-label="Consensus"
            onClick={() => select("consensus")}
            onKeyDown={(e) => {
              if (e.key === "Enter" || e.key === " ") {
                e.preventDefault();
                select("consensus");
              }
            }}
            className="cursor-pointer outline-none"
          >
            {consState === "active" && (
              <circle cx={CONSENSUS.cx} cy={CONSENSUS.cy} r={CONSENSUS.r + 12} className="animate-pulse fill-mark/10" />
            )}
            <circle
              cx={CONSENSUS.cx}
              cy={CONSENSUS.cy}
              r={CONSENSUS.r + 6}
              className={cn(
                "fill-card",
                shown === "consensus" ? "stroke-foreground/70" : decided ? "stroke-mark/50" : "stroke-border",
              )}
            />
            <circle
              cx={CONSENSUS.cx}
              cy={CONSENSUS.cy}
              r={CONSENSUS.r}
              fill="none"
              strokeWidth={7}
              className="stroke-muted"
            />
            <g transform={`rotate(-90 ${CONSENSUS.cx} ${CONSENSUS.cy})`}>
              {arrived.map(({ e }, k) => (
                <circle
                  key={e.id}
                  cx={CONSENSUS.cx}
                  cy={CONSENSUS.cy}
                  r={CONSENSUS.r}
                  fill="none"
                  strokeWidth={7}
                  strokeDasharray={`${Math.max(0, seg - 3)} ${circ}`}
                  strokeDashoffset={-k * seg}
                  className={cn("animate-fade-in", VOTE_STROKE[e.vote])}
                />
              ))}
            </g>
            {decided ? (
              <>
                <text
                  x={CONSENSUS.cx}
                  y={CONSENSUS.cy + 1}
                  textAnchor="middle"
                  className={cn("animate-fade-in text-[12px] font-semibold", VOTE_FILL[result.verdict])}
                >
                  {VOTE_LABEL[result.verdict]}
                </text>
                <text
                  x={CONSENSUS.cx}
                  y={CONSENSUS.cy + 16}
                  textAnchor="middle"
                  className="fill-muted-foreground font-mono text-[9.5px]"
                >
                  {result.counted} voted
                </text>
              </>
            ) : (
              <>
                <text
                  x={CONSENSUS.cx}
                  y={CONSENSUS.cy + 5}
                  textAnchor="middle"
                  className="fill-foreground font-mono text-[15px] tabular-nums"
                >
                  {arrived.length}/{counted.length}
                </text>
                <text
                  x={CONSENSUS.cx}
                  y={CONSENSUS.cy + 20}
                  textAnchor="middle"
                  className="fill-muted-foreground font-mono text-[9px]"
                >
                  votes
                </text>
              </>
            )}
            <text
              x={CONSENSUS.cx}
              y={CONSENSUS.cy + CONSENSUS.r + 30}
              textAnchor="middle"
              className="fill-foreground text-[13px] font-medium"
            >
              Consensus
            </text>
            <text
              x={CONSENSUS.cx}
              y={CONSENSUS.cy + CONSENSUS.r + 45}
              textAnchor="middle"
              className="fill-muted-foreground font-mono text-[10px]"
            >
              majority of votes
            </text>
          </g>

          {/* Outputs */}
          {OUTPUTS.map((o) => (
            <Node
              key={o.id}
              box={o.box}
              title={o.label}
              sub={o.sub}
              state={stateAt(t, [tl.out[1] - 120, tl.out[1] + 900])}
              selected={shown === "outputs"}
              onSelect={() => select("outputs")}
            />
          ))}

          {/* Packets */}
          <g filter="url(#flow-glow)" pointerEvents="none">
            {flying.map((p) => {
              const u = progress(t, p.w);
              const head = p.at(u);
              const tail1 = p.at(Math.max(0, u - 0.06));
              const tail2 = p.at(Math.max(0, u - 0.12));
              return (
                <g key={p.key} className={p.fill}>
                  <circle cx={tail2.x} cy={tail2.y} r={2} opacity={0.3} />
                  <circle cx={tail1.x} cy={tail1.y} r={3} opacity={0.55} />
                  <circle cx={head.x} cy={head.y} r={4.5} />
                </g>
              );
            })}
          </g>
        </svg>
      </div>

      {/* Stage strip */}
      <ol className="grid grid-cols-5 border-t border-border" aria-label="Stages">
        {stages.map((s, i) => {
          const p = progress(t, s.w);
          const active = within(t, s.w);
          return (
            <li key={s.id} className={cn("relative px-2 py-2.5 sm:px-4", i > 0 && "border-l border-border")}>
              <span className="absolute inset-x-0 top-0 h-0.5 bg-muted" aria-hidden>
                <span className="block h-full bg-mark" style={{ width: `${p * 100}%` }} />
              </span>
              <span className="block font-mono text-[10px] text-muted-foreground">0{i + 1}</span>
              <span
                className={cn(
                  "block truncate text-xs transition-colors sm:text-[13px]",
                  active ? "text-mark" : p >= 1 ? "text-foreground" : "text-muted-foreground",
                )}
              >
                {s.label}
              </span>
            </li>
          );
        })}
      </ol>

      {/* Log and details */}
      <div className={cn("grid border-t border-border", !compact && "lg:grid-cols-5")}>
        <div className={cn("min-w-0 bg-card/40 p-4 sm:p-5", !compact && "lg:col-span-3")}>
          <div className="mb-3 flex items-center justify-between">
            <p className="font-mono text-[10px] uppercase tracking-[0.18em] text-muted-foreground">Service log</p>
            <p className="font-mono text-[10px] text-muted-foreground">{(Math.min(t, tl.out[1]) / 1000).toFixed(2)}s</p>
          </div>
          <ul
            className={cn(
              "space-y-1.5 font-mono text-[11.5px] leading-snug",
              compact ? "min-h-[64px]" : "min-h-[168px]",
            )}
          >
            {visibleLog.length === 0 && <li className="text-muted-foreground">waiting for a submission…</li>}
            {visibleLog.map((l) => (
              <li key={`${l.at}-${l.who}`} className="flex min-w-0 animate-fade-in gap-3">
                <span className="shrink-0 text-mark">{(l.at / 1000).toFixed(2)}</span>
                <span className="w-16 shrink-0 truncate text-muted-foreground sm:w-20">{l.who}</span>
                <span
                  className={cn(
                    "min-w-0 sm:truncate",
                    l.tone === "mark" ? "text-mark" : l.tone ? VOTE_TEXT[l.tone] : "text-foreground/90",
                    l.tone === "none" && "text-muted-foreground",
                  )}
                >
                  {l.text}
                </span>
              </li>
            ))}
          </ul>
        </div>
        {!compact && (
          <div
            className="min-w-0 border-t border-border p-4 sm:p-5 lg:col-span-2 lg:border-l lg:border-t-0"
            aria-live="polite"
          >
            <p className="font-mono text-[10px] uppercase tracking-[0.18em] text-muted-foreground">
              {picked ? "Selected" : "Happening now"}
            </p>
            <h3 className="mt-2 text-lg font-medium tracking-tight">{info.title}</h3>
            <p className="mt-0.5 font-mono text-[11px] text-mark">{info.tech}</p>
            <p className="mt-3 text-sm leading-relaxed text-muted-foreground">{info.text}</p>
            <p className="mt-4 text-xs text-muted-foreground/80">
              {picked ? (
                <button
                  type="button"
                  className="underline underline-offset-4 hover:text-foreground"
                  onClick={() => setPicked(null)}
                >
                  Follow the scan again
                </button>
              ) : (
                "Click any box to pin it."
              )}
            </p>
          </div>
        )}
      </div>
    </div>
  );
}
