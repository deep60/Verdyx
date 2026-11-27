#!/usr/bin/env python3
"""Turn a benchmark run into the data behind the public /benchmark page.

    python3 benchmark/publish.py [--results DIR] [--out FILE]

Reads `results/report.json` and `results/run.json` (both written by
`run_on_server.sh`) and writes `frontend/client/src/data/benchmark.json`.

Only totals and clean-file names leave the report: no malware file names,
nothing an engine extracted from a sample. Commit the output with the PR that
changed detection, so the page always describes a real run.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
DEFAULT_OUT = REPO / "frontend" / "client" / "src" / "data" / "benchmark.json"

CONSENSUS = "Consensus"
# The generic ML engine runs placeholder models that were never trained (see
# analyzers/ml_analyzer.rs). It doesn't vote, and its prediction would read as
# a real engine's score, so neither of its rows is published.
HIDDEN = {"ML Engine", "ML Engine (advisory)"}
# Engines that run in production and should be named when a run lacks them.
EXPECTED = ["ClamAV", "Verdyx PE Model"]


def tally(t: dict | None) -> dict:
    t = t or {}
    return {
        "total": t.get("total", 0),
        "flagged": t.get("flagged", 0),
        "malicious": t.get("malicious_verdicts", 0),
        "noVerdict": t.get("no_verdict", 0),
    }


def answered(t: dict) -> bool:
    """Did the engine give a verdict on at least one file?"""
    return t["total"] > t["noVerdict"]


def build(report: dict, run: dict) -> dict:
    s = report["summary"]
    names = sorted(
        (set(s["detection"]) | set(s["false_positives"])) - {CONSENSUS} - HIDDEN
    )

    engines, not_measured = [], []
    for name in names:
        mal = tally(s["detection"].get(name))
        clean = tally(s["false_positives"].get(name))
        # Never answered, or saw no malware of its kind: nothing to score.
        if not answered(mal):
            not_measured.append(name)
            continue
        engines.append({"name": name, "malware": mal, "clean": clean})
    # Engines that check every file first, then by detection; ties broken by
    # fewer false positives.
    engines.sort(
        key=lambda e: (
            -e["malware"]["total"],
            -rate(e["malware"]["flagged"], e["malware"]["total"]),
            rate(e["clean"]["flagged"], e["clean"]["total"]),
        )
    )
    shown = [e["name"] for e in engines]
    not_measured += [n for n in EXPECTED if n not in shown and n not in not_measured]
    not_measured.sort()

    def groups(by: dict) -> list:
        out = []
        for group, per_engine in sorted(by.items()):
            out.append(
                {
                    "name": group,
                    "consensus": tally(per_engine.get(CONSENSUS)),
                    "engines": {n: tally(per_engine.get(n)) for n in shown},
                }
            )
        return out

    return {
        "ranAt": run.get("ranAt"),
        "revision": run.get("revision") or None,
        "image": run.get("image") or None,
        "clamav": bool(run.get("clamav", False)),
        "peModel": bool(run.get("peModel", False)),
        "feeds": bool(s.get("feeds_enabled", False)),
        "seconds": s.get("seconds", 0),
        "set": {
            "malicious": s["malicious_files"],
            "clean": s["clean_files"],
            "families": s["families"],
            "skipped": s.get("skipped", 0) + s.get("missing_from_manifest", 0),
        },
        "consensus": {
            "malware": tally(s["detection"].get(CONSENSUS)),
            "clean": tally(s["false_positives"].get(CONSENSUS)),
        },
        "engines": engines,
        "notMeasured": not_measured,
        "byFileType": groups(s["detection_by_category"]),
        "bySource": groups(s["false_positives_by_source"]),
        "missedFamilies": sorted(s.get("missed_families", [])),
        "falsePositives": [
            {"file": f, "engines": sorted(e)} for f, e in s["consensus_false_positives"]
        ],
    }


def rate(n: int, total: int) -> float:
    return n / total if total else 0.0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--results", type=Path, default=HERE / "results")
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = ap.parse_args(argv)

    report = json.loads((args.results / "report.json").read_text())
    run_path = args.results / "run.json"
    run = json.loads(run_path.read_text()) if run_path.exists() else {}
    if not run.get("ranAt"):
        print(f"{run_path} is missing: re-run run_on_server.sh so the page can say when", file=sys.stderr)
        return 1

    data = build(report, run)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(data, indent=2) + "\n")
    c = data["consensus"]
    print(
        f"Wrote {args.out}: consensus flags "
        f"{c['malware']['flagged']}/{c['malware']['total']} malware, "
        f"{c['clean']['flagged']}/{c['clean']['total']} clean files"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
