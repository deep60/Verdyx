"""Train on miniature EMBER-format data, then serve the bundle over HTTP."""

import json
import math
import random
import threading
import urllib.error
import urllib.request

import numpy as np
import pytest

from conftest import sample_pe
from verdyx_ml import bundle as bundle_mod
from verdyx_ml import dataset
from verdyx_ml.server import make_server


def test_dataset_is_sorted_oldest_first_and_skips_unlabelled(ember_dir, tmp_path):
    files = dataset.find_files(ember_dir, "train", dataset.PE_FILE_TYPES)
    split = dataset.build(files, tmp_path / "c", workers=2, log=lambda *_: None)
    assert len(split) == 700  # the unlabelled row is dropped
    assert np.all(np.diff(split.date) >= 0)
    # Reused from cache on a second call, with identical contents.
    again = dataset.build(files, tmp_path / "c", workers=2, log=lambda *_: None)
    assert np.array_equal(np.asarray(again.X), np.asarray(split.X))


def test_sampling_is_by_hash_and_reproducible():
    import hashlib

    shas = [hashlib.sha256(str(i).encode()).hexdigest() for i in range(1000)]
    kept = [s for s in shas if dataset.keep_by_hash(s, 0.3)]
    assert 250 < len(kept) < 350
    assert kept == [s for s in shas if dataset.keep_by_hash(s, 0.3)]


def test_find_files_selects_subset_and_type(ember_dir):
    assert [p.name for p in dataset.find_files(ember_dir, "test", ["Win32"])] == ["2024-03-11_2024-03-31_Win32_test.jsonl"]
    assert dataset.find_files(ember_dir, "train", ["Win64"]) == []
    assert len(dataset.find_files(ember_dir, "challenge", ["Win64"])) == 1


def test_parse_date_formats():
    assert dataset.parse_date("2024-01-02") == 1704153600
    assert dataset.parse_date("2024-01-02 00:00:00") == 1704153600
    assert dataset.parse_date("2024-01-02T00:00:00Z") == 1704153600
    assert dataset.parse_date(1704153600) == 1704153600
    assert dataset.parse_date(None) is None


def test_training_splits_by_time_and_writes_a_bundle(trained_bundle):
    for f in ("model.txt", "calibration.json", "bundle.json", "report.md"):
        assert (trained_bundle / f).exists(), f
    meta = json.loads((trained_bundle / "bundle.json").read_text())
    splits = meta["evaluation"]["splits"]
    order = ["fit", "valid", "calib", "test"]
    # Each later part starts no earlier than the previous one ends.
    for a, b in zip(order, order[1:]):
        assert splits[a]["date_range"][1] <= splits[b]["date_range"][0], (a, b)
    assert meta["thresholds"]["suspicious"] <= meta["thresholds"]["malicious"]
    assert meta["evaluation"]["challenge"]["malicious"] == 60
    assert meta["quality_gate"]["passed"] is True
    assert {c["check"].split(" ")[1] for c in meta["quality_gate"]["checks"]} >= {"AUC", "detection", "false-positive", "calibration"}
    report = (trained_bundle / "report.md").read_text()
    assert "Quality gate: **PASSED**" in report and "Challenge set" in report
    # The model learns the obvious signal in the synthetic data.
    assert meta["evaluation"]["test"]["auc"] > 0.9


def test_strict_gate_fails_the_model(ember_dir, tmp_path):
    from verdyx_ml import train_pe

    code = train_pe.main([
        "--data-dir", str(ember_dir), "--out-dir", str(tmp_path / "b"), "--cache-dir", str(tmp_path / "c"),
        "--max-rounds", "5", "--num-leaves", "4", "--min-data-in-leaf", "5", "--workers", "2",
        "--min-test-auc", "1.01",
    ])
    assert code == 2
    meta = json.loads((tmp_path / "b" / "bundle.json").read_text())
    assert meta["quality_gate"]["passed"] is False


@pytest.fixture()
def serve(trained_bundle):
    servers = []

    def start(bundle_dir=trained_bundle, **kw):
        srv = make_server("127.0.0.1", 0, bundle_dir, **kw)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        servers.append(srv)
        return f"http://127.0.0.1:{srv.server_address[1]}"

    yield start
    for s in servers:
        s.shutdown()


def _post(url, data, headers=None):
    req = urllib.request.Request(url + "/v1/pe/score", data=data, method="POST",
                                 headers={"Content-Type": "application/octet-stream", **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def test_service_scores_and_explains_a_pe(serve):
    url = serve()
    with urllib.request.urlopen(url + "/health") as r:
        health = json.loads(r.read())
    assert health["pe_model"]["loaded"] and health["pe_model"]["model_version"] == "pe-test"

    rng = random.Random(99)
    status, mal = _post(url, sample_pe(True, rng))
    assert status == 200 and mal["applicable"]
    status, clean = _post(url, sample_pe(False, rng))
    assert status == 200 and clean["applicable"]
    assert mal["probability"] > clean["probability"]
    assert mal["verdict"] in ("malicious", "suspicious")
    assert clean["verdict"] == "benign"

    exp = mal["explanation"]
    assert exp["reasons"] and exp["summary"].startswith("Main reasons")
    # SHAP values add up to the model's raw output (log-odds).
    raw = mal["raw_score"]
    assert exp["raw_log_odds"] == pytest.approx(math.log(raw / (1 - raw)), abs=1e-3)


def test_service_skips_non_pe_and_enforces_limits(serve):
    url = serve(max_bytes=4096, token="s3cret")
    assert _post(url, b"just text", {"X-Verdyx-ML-Token": "s3cret"}) == (200, {
        "applicable": False, "reason": "not a Windows PE file (pefile could not parse it)", "model_version": "pe-test"})
    assert _post(url, b"MZ")[0] == 401
    assert _post(url, b"MZ" * 4096, {"X-Verdyx-ML-Token": "s3cret"})[0] == 413


def test_service_refuses_a_bundle_with_another_feature_layout(serve, trained_bundle, tmp_path):
    import shutil

    bad = tmp_path / "bad"
    shutil.copytree(trained_bundle, bad)
    meta = json.loads((bad / bundle_mod.META_FILE).read_text())
    meta["feature_layout"] = "0" * 16
    (bad / bundle_mod.META_FILE).write_text(json.dumps(meta))
    url = serve(bad)
    with urllib.request.urlopen(url + "/health") as r:
        health = json.loads(r.read())
    assert not health["pe_model"]["loaded"]
    assert "feature layout" in health["pe_model"]["reason"]
    assert _post(url, sample_pe(True, random.Random(1)))[0] == 503


def test_service_without_a_bundle_reports_why(serve, tmp_path):
    url = serve(tmp_path / "empty")
    with urllib.request.urlopen(url + "/health") as r:
        assert json.loads(r.read())["pe_model"] == {"loaded": False, "reason": f"no model bundle in {tmp_path / 'empty'}"}
