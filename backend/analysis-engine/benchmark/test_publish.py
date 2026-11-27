"""Tests for publish.py:  python3 -m unittest benchmark/test_publish.py"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import publish  # noqa: E402


def t(total, flagged=0, mal=0, nv=0):
    return {"total": total, "flagged": flagged, "malicious_verdicts": mal,
            "benign": total - flagged - nv, "no_verdict": nv}


REPORT = {
    "samples": [{"file": "SecretFamily/abc", "reasons": ["C2 at evil.example"]}],
    "skipped": [],
    "summary": {
        "malicious_files": 10, "clean_files": 100, "families": 3,
        "missing_from_manifest": 1, "skipped": 0, "feeds_enabled": False, "seconds": 42,
        "detection": {
            "Consensus": t(10, 6, 1), "YARA": t(10, 4, 2, 6), "Static": t(10, 5),
            "ClamAV": t(10, nv=10), "ML Engine": t(10, nv=10), "ML Engine (advisory)": t(10, 8, 8),
            "Archive contents": t(0),
        },
        "false_positives": {
            "Consensus": t(100, 1), "YARA": t(100, nv=100), "Static": t(100, 1),
            "ClamAV": t(100, nv=100), "ML Engine": t(100, nv=100), "ML Engine (advisory)": t(100, 20, 20),
        },
        "detection_by_category": {"pe": {"Consensus": t(10, 6), "Static": t(10, 5)}},
        "false_positives_by_source": {"putty-0.81-w64": {"Consensus": t(100, 1)}},
        "missed_families": ["Zeta (2)", "Alpha (1)"],
        "consensus_false_positives": [["putty-0.81-w64/PUTTY.EXE", ["Static"]]],
    },
}
RUN = {"ranAt": "2026-11-26T10:00:00Z", "image": "img@sha256:1", "revision": "abc1234", "clamav": False}


class PublishTest(unittest.TestCase):
    def test_build(self):
        d = publish.build(REPORT, RUN)
        self.assertEqual(d["ranAt"], RUN["ranAt"])
        self.assertEqual(d["set"], {"malicious": 10, "clean": 100, "families": 3, "skipped": 1})
        self.assertEqual(d["consensus"]["malware"], {"total": 10, "flagged": 6, "malicious": 1, "noVerdict": 0})
        # Best detection first; the untrained ML engine is never shown;
        # engines that never answered, and expected ones that are absent,
        # are listed apart.
        self.assertEqual([e["name"] for e in d["engines"]], ["Static", "YARA"])
        self.assertEqual(d["notMeasured"], ["Archive contents", "ClamAV", "Verdyx PE Model"])
        self.assertEqual(d["byFileType"][0]["engines"]["YARA"]["total"], 0)
        self.assertNotIn("Archive contents", [e["name"] for e in d["engines"]])
        self.assertNotIn("ML Engine (advisory)", json.dumps(d))
        self.assertEqual(d["missedFamilies"], ["Alpha (1)", "Zeta (2)"])
        self.assertEqual(d["falsePositives"], [{"file": "putty-0.81-w64/PUTTY.EXE", "engines": ["Static"]}])

    def test_no_sample_details_leak(self):
        text = json.dumps(publish.build(REPORT, RUN))
        self.assertNotIn("SecretFamily/abc", text)
        self.assertNotIn("evil.example", text)

    def test_refuses_an_undated_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "report.json").write_text(json.dumps(REPORT))
            out = Path(tmp, "out.json")
            self.assertEqual(publish.main(["--results", tmp, "--out", str(out)]), 1)
            self.assertFalse(out.exists())
            Path(tmp, "run.json").write_text(json.dumps(RUN))
            self.assertEqual(publish.main(["--results", tmp, "--out", str(out)]), 0)
            self.assertEqual(json.loads(out.read_text())["revision"], "abc1234")


if __name__ == "__main__":
    unittest.main()
