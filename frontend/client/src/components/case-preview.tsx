import { useQuery } from "@tanstack/react-query";
import type { ApiEngine } from "@/lib/api-types";
import { engineState } from "@/lib/engines";
import { findLiveEngine } from "@/lib/flow";

type Vote = "malicious" | "suspicious" | "benign";

type Row =
  | { id: string; engine: string; vote: Vote; confidence: number; note?: string }
  | { id: string; engine: string; vote: "advisory"; prediction: Vote; confidence: number; note?: string }
  | { id: string; engine: string; vote: "off"; note: string };

/**
 * An example case built the way the consensus really works: a majority of the
 * engines that returned a verdict. The votes are an example; which engines
 * vote, advise or are off follows the live engine list.
 */
const ROWS: Row[] = [
  { id: "yara", engine: "YARA Engine", vote: "malicious", confidence: 0.92, note: "2 rules" },
  { id: "hash", engine: "Hash Analyzer", vote: "malicious", confidence: 0.9, note: "MalwareBazaar" },
  { id: "clamav", engine: "ClamAV Scanner", vote: "malicious", confidence: 0.95, note: "Win.Trojan.Agent" },
  { id: "pe_model", engine: "EMBER2024 Model", vote: "malicious", confidence: 0.97, note: "trained" },
  { id: "heuristic", engine: "Heuristic Engine", vote: "malicious", confidence: 0.84 },
  { id: "static", engine: "Static Analyzer", vote: "suspicious", confidence: 0.78 },
  { id: "signature", engine: "Signature Matcher", vote: "benign", confidence: 0.88 },
  {
    id: "ml",
    engine: "ML Classifier",
    vote: "advisory",
    prediction: "malicious",
    confidence: 0.71,
    note: "not trained yet",
  },
];

/** Show an engine the way production runs it right now. */
function withLiveState(row: Row, live: ApiEngine[] | undefined): Row {
  const engine = findLiveEngine(row.id, live);
  if (!engine) return row;
  const state = engineState(engine);
  if (state === "off") return { id: row.id, engine: row.engine, vote: "off", note: "unavailable" };
  if (state === "advisory" && row.vote !== "advisory" && row.vote !== "off") {
    return { ...row, vote: "advisory", prediction: row.vote, note: "advisory" };
  }
  if (state === "voting" && row.vote === "advisory") {
    return { id: row.id, engine: row.engine, vote: row.prediction, confidence: row.confidence };
  }
  return row;
}

const NOT_COUNTED_LABEL: Record<string, string> = {
  advisory: "advisory",
  off: "off",
};

const VOTE_COLOR: Record<Vote, string> = {
  malicious: "#E7A3A8",
  suspicious: "#E4C27A",
  benign: "#9CBFAE",
};

function VoteText({ vote }: { vote: Vote }) {
  return (
    <span className="capitalize" style={{ color: VOTE_COLOR[vote] }}>
      {vote}
    </span>
  );
}

/** Illustrated case. The votes are an example, not a live scan. */
export function CasePreview() {
  const { data } = useQuery<ApiEngine[]>({ queryKey: ["/api/engines"] });
  const live = Array.isArray(data) && data.length > 0 ? data : undefined;
  const rows = ROWS.map((row) => withLiveState(row, live));
  const counted = rows.filter((r): r is Extract<Row, { vote: Vote }> => r.vote !== "advisory" && r.vote !== "off");
  const n = (v: Vote) => counted.filter((r) => r.vote === v).length;
  const tally = [
    `${counted.length} of ${rows.length}`,
    n("malicious") && `${n("malicious")} malicious`,
    n("suspicious") && `${n("suspicious")} suspicious`,
    n("benign") && `${n("benign")} benign`,
  ]
    .filter(Boolean)
    .join(" · ");
  const notCounted = rows
    .filter((r) => r.vote === "advisory" || r.vote === "off")
    .map(
      (r) =>
        `${r.engine.replace(/ (Scanner|Classifier|Engine|Analyzer|Matcher|Model)$/, "")} ${NOT_COUNTED_LABEL[r.vote]}`,
    )
    .join(" · ");
  const verdict: Vote =
    n("malicious") + n("suspicious") > n("benign")
      ? n("malicious") >= n("suspicious")
        ? "malicious"
        : "suspicious"
      : "benign";

  return (
    <figure className="min-w-0">
      <div className="overflow-hidden border border-[#32342C] bg-[#141513] text-[#F3F1EA]">
        <div className="flex items-start justify-between gap-4 border-b border-[#32342C] px-4 py-3 sm:px-5">
          <div className="min-w-0">
            <div className="text-sm">vd-1044</div>
            <div className="mt-1 truncate font-mono text-[11px] text-[#F3F1EA]/55 sm:text-xs">
              sha256 3b526452516dc82c…253c20e86a
            </div>
          </div>
          <div className="shrink-0 text-right">
            <div className="font-mono text-[10px] uppercase tracking-[0.08em] text-[#F3F1EA]/45">Consensus</div>
            <div className="mt-0.5 text-sm capitalize" style={{ color: VOTE_COLOR[verdict] }}>
              {verdict}
            </div>
          </div>
        </div>

        <div className="hidden grid-cols-[minmax(0,1.4fr)_6.5rem_4.75rem_4.5rem] gap-3 border-b border-[#32342C] px-4 py-2 font-mono text-[10px] uppercase tracking-[0.08em] text-[#F3F1EA]/40 sm:grid sm:px-5">
          <span>Engine</span>
          <span>Vote</span>
          <span className="text-right">Conf.</span>
          <span aria-hidden />
        </div>

        <ul>
          {rows.map((row) => {
            const counted = row.vote !== "advisory" && row.vote !== "off";
            return (
              <li
                key={row.engine}
                className="grid grid-cols-[minmax(0,1fr)_5.6rem_3.4rem] items-center gap-2 border-b border-[#32342C] px-4 py-2.5 text-sm last:border-b-0 sm:grid-cols-[minmax(0,1.4fr)_6.5rem_4.75rem_4.5rem] sm:gap-3 sm:px-5"
              >
                <span className={`truncate ${counted ? "" : "text-[#F3F1EA]/55"}`}>
                  {row.engine}
                  {"note" in row && row.note && (
                    <span className="ml-2 font-mono text-[10px] text-[#F3F1EA]/45">{row.note}</span>
                  )}
                </span>
                {row.vote === "off" ? (
                  <span className="text-[#F3F1EA]/45">Off</span>
                ) : row.vote === "advisory" ? (
                  <span className="text-[#F3F1EA]/55">Advisory</span>
                ) : (
                  <VoteText vote={row.vote} />
                )}
                <span className="text-right font-mono text-xs tabular-nums text-[#F3F1EA]/80">
                  {"confidence" in row ? row.confidence.toFixed(2) : "—"}
                </span>
                <span className="hidden h-1 bg-[#32342C] sm:block" aria-hidden>
                  {counted && (
                    <span
                      className="block h-full"
                      style={{
                        width: `${Math.round(row.confidence * 100)}%`,
                        background: VOTE_COLOR[row.vote],
                      }}
                    />
                  )}
                </span>
              </li>
            );
          })}
        </ul>

        <div className="grid border-t border-[#32342C] sm:grid-cols-2">
          <div className="border-b border-[#32342C] px-4 py-3 sm:border-b-0 sm:border-r sm:px-5">
            <div className="font-mono text-[10px] uppercase tracking-[0.08em] text-[#F3F1EA]/45">Votes counted</div>
            <div className="mt-1 font-mono text-xs text-[#F3F1EA]/85">{tally}</div>
          </div>
          <div className="px-4 py-3 sm:px-5">
            <div className="font-mono text-[10px] uppercase tracking-[0.08em] text-[#F3F1EA]/45">Not counted</div>
            <div className="mt-1 font-mono text-xs text-[#F3F1EA]/70">
              {notCounted || "Nothing. Every engine voted."}
            </div>
          </div>
        </div>
      </div>
      <figcaption className="mt-3 text-xs leading-relaxed text-muted-foreground">
        Example case. The votes are illustrative; which engines vote, advise or are off is live from production.
      </figcaption>
    </figure>
  );
}
