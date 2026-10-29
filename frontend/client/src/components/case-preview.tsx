type Vote = "malicious" | "suspicious" | "benign";

const ROWS: { engine: string; vote: Vote; confidence: number }[] = [
  { engine: "ClamAV", vote: "malicious", confidence: 0.99 },
  { engine: "YARA 4.5", vote: "malicious", confidence: 0.87 },
  { engine: "Goblin PE/ELF", vote: "suspicious", confidence: 0.62 },
  { engine: "Byte entropy", vote: "malicious", confidence: 0.91 },
  { engine: "Heuristics", vote: "malicious", confidence: 0.84 },
  { engine: "Signatures", vote: "benign", confidence: 0.22 },
  { engine: "Hash intel", vote: "malicious", confidence: 0.96 },
];

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

/** Illustrated case. The votes are an example of the console, not a live scan. */
export function CasePreview() {
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
            <div className="font-mono text-[10px] uppercase tracking-[0.08em] text-[#F3F1EA]/45">
              Quorum
            </div>
            <div className="mt-0.5 text-sm" style={{ color: VOTE_COLOR.malicious }}>
              Malicious
            </div>
          </div>
        </div>

        <div className="hidden grid-cols-[minmax(0,1.4fr)_6.5rem_4.75rem_4.5rem] gap-3 border-b border-[#32342C] px-4 py-2 font-mono text-[10px] uppercase tracking-[0.08em] text-[#F3F1EA]/40 sm:grid sm:px-5">
          <span>Engine</span>
          <span>Vote</span>
          <span className="text-right">Conf.</span>
          <span className="text-right">Weight</span>
        </div>

        <ul>
          {ROWS.map((row) => (
            <li
              key={row.engine}
              className="grid grid-cols-[minmax(0,1fr)_5.6rem_3.4rem] items-center gap-2 border-b border-[#32342C] px-4 py-2.5 text-sm last:border-b-0 sm:grid-cols-[minmax(0,1.4fr)_6.5rem_4.75rem_4.5rem] sm:gap-3 sm:px-5"
            >
              <span className="truncate">{row.engine}</span>
              <VoteText vote={row.vote} />
              <span className="text-right font-mono text-xs tabular-nums text-[#F3F1EA]/80">
                {row.confidence.toFixed(2)}
              </span>
              <span className="hidden h-1 bg-[#32342C] sm:block" aria-hidden>
                <span
                  className="block h-full"
                  style={{
                    width: `${Math.round(row.confidence * 100)}%`,
                    background: VOTE_COLOR[row.vote],
                  }}
                />
              </span>
            </li>
          ))}
        </ul>

        <div className="grid border-t border-[#32342C] sm:grid-cols-2">
          <div className="border-b border-[#32342C] px-4 py-3 sm:border-b-0 sm:border-r sm:px-5">
            <div className="font-mono text-[10px] uppercase tracking-[0.08em] text-[#F3F1EA]/45">
              Committed
            </div>
            <div className="mt-1 break-all font-mono text-xs text-[#F3F1EA]/85">
              3b526452516dc82cabc9…253c20e86a
            </div>
          </div>
          <div className="px-4 py-3 sm:px-5">
            <div className="font-mono text-[10px] uppercase tracking-[0.08em] text-[#F3F1EA]/45">
              Revealed
            </div>
            <div className="mt-1 font-mono text-xs">
              <span style={{ color: VOTE_COLOR.malicious }}>malicious</span>
              <span className="text-[#F3F1EA]/55"> · 0.9400</span>
            </div>
          </div>
        </div>
      </div>
      <figcaption className="mt-3 text-xs leading-relaxed text-muted-foreground">
        Example case. A live scan replaces these votes with the engines that ran on your file.
      </figcaption>
    </figure>
  );
}
