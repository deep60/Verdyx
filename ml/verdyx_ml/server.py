"""HTTP service that scores Windows programs with the trained PE model.

    GET  /health        model status, version and quality gate
    POST /v1/pe/score   body: the file's raw bytes (application/octet-stream)

Only the analysis engine calls this, over the internal Docker network; the
port is never published. Built on the standard library's HTTP server to keep
the memory footprint small on a 1 GB box.

Environment:
    ML_PE_BUNDLE_DIR   model bundle directory (default /models/pe)
    ML_HOST, ML_PORT   bind address (default 0.0.0.0:8090)
    ML_MAX_BYTES       largest file accepted (default 64 MiB)
    ML_MAX_CONCURRENT  files scored at once (default 2; bounds memory)
    ML_SERVICE_TOKEN   if set, callers must send it as X-Verdyx-ML-Token
"""

from __future__ import annotations

import hmac
import json
import logging
import os
import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import numpy as np

from . import __version__
from .bundle import MODEL_FILE, BundleMeta, read_calibration, read_meta
from .explain import explain
from .pe_features import extract

log = logging.getLogger("verdyx_ml")


class PeModel:
    """A loaded bundle: LightGBM booster, calibration and thresholds."""

    def __init__(self, bundle_dir: Path):
        import lightgbm as lgb

        self.dir = bundle_dir
        self.meta: BundleMeta = read_meta(bundle_dir)
        self.calibrate = read_calibration(bundle_dir)
        self.booster = lgb.Booster(model_file=str(bundle_dir / MODEL_FILE))
        self.thresholds = self.meta.thresholds

    def score(self, data: bytes) -> dict[str, Any]:
        started = time.perf_counter()
        ext = extract(data)
        if not ext.is_pe:
            return {
                "applicable": False,
                "reason": "not a Windows PE file (pefile could not parse it)",
                "model_version": self.meta.version,
            }
        x = ext.vector.reshape(1, -1)
        raw = float(self.booster.predict(x)[0])
        contrib = self.booster.predict(x, pred_contrib=True)[0]
        prob = float(self.calibrate(raw))
        t = self.thresholds
        if raw >= t.malicious:
            verdict = "malicious"
        elif raw >= t.suspicious:
            verdict = "suspicious"
        else:
            verdict = "benign"
        return {
            "applicable": True,
            "verdict": verdict,
            "probability": round(prob, 6),
            "raw_score": round(raw, 6),
            "thresholds": {
                "malicious": t.malicious,
                "suspicious": t.suspicious,
                "malicious_fpr_target": t.malicious_fpr_target,
                "suspicious_fpr_target": t.suspicious_fpr_target,
            },
            "explanation": explain(contrib, ext.vector, ext.raw),
            "model_version": self.meta.version,
            "quality_gate_passed": self.meta.quality_gate_passed,
            "elapsed_ms": round((time.perf_counter() - started) * 1000, 1),
        }

    def status(self) -> dict[str, Any]:
        ev = self.meta.raw.get("evaluation", {}).get("test", {})
        mal = ev.get("at_malicious_threshold", {})
        return {
            "model_version": self.meta.version,
            "quality_gate_passed": self.meta.quality_gate_passed,
            "trained_at": self.meta.raw.get("created_at"),
            "test_auc": ev.get("auc"),
            "test_detection_rate": mal.get("tpr"),
            "test_false_positive_rate": mal.get("fpr"),
            "test_ece": ev.get("ece"),
        }


def load_model(bundle_dir: Path) -> tuple[PeModel | None, str | None]:
    if not (bundle_dir / MODEL_FILE).exists():
        return None, f"no model bundle in {bundle_dir}"
    try:
        return PeModel(bundle_dir), None
    except Exception as e:  # a bad bundle must not take the service down
        log.exception("failed to load model bundle")
        return None, f"model bundle in {bundle_dir} is unusable: {e}"


class Handler(BaseHTTPRequestHandler):
    server_version = f"verdyx-ml/{__version__}"
    protocol_version = "HTTP/1.1"

    # Set on the class by `make_server`.
    model: PeModel | None = None
    load_error: str | None = None
    max_bytes: int = 64 * 1024 * 1024
    token: str | None = None
    slots: threading.BoundedSemaphore = threading.BoundedSemaphore(2)

    def log_message(self, fmt: str, *args) -> None:
        log.info("%s %s", self.address_string(), fmt % args)

    def _send(self, status: HTTPStatus, body: dict) -> None:
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _authorized(self) -> bool:
        if not self.token:
            return True
        given = self.headers.get("X-Verdyx-ML-Token", "")
        return hmac.compare_digest(given.encode(), self.token.encode())

    def do_GET(self) -> None:
        if self.path != "/health":
            return self._send(HTTPStatus.NOT_FOUND, {"error": "not found"})
        body: dict[str, Any] = {"status": "ok", "service": "verdyx-ml", "version": __version__}
        if self.model is not None:
            body["pe_model"] = {"loaded": True, **self.model.status()}
        else:
            body["pe_model"] = {"loaded": False, "reason": self.load_error}
        self._send(HTTPStatus.OK, body)

    def do_POST(self) -> None:
        if self.path != "/v1/pe/score":
            return self._send(HTTPStatus.NOT_FOUND, {"error": "not found"})
        if not self._authorized():
            return self._send(HTTPStatus.UNAUTHORIZED, {"error": "missing or wrong service token"})
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            return self._send(HTTPStatus.LENGTH_REQUIRED, {"error": "Content-Length required"})
        if length <= 0:
            return self._send(HTTPStatus.BAD_REQUEST, {"error": "empty body"})
        if length > self.max_bytes:
            # Drain nothing: closing is cheaper than reading a huge body.
            self.close_connection = True
            return self._send(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"error": f"file larger than {self.max_bytes} bytes"})
        data = self.rfile.read(length)
        if len(data) != length:
            return self._send(HTTPStatus.BAD_REQUEST, {"error": "body shorter than Content-Length"})
        if self.model is None:
            return self._send(HTTPStatus.SERVICE_UNAVAILABLE, {"error": self.load_error or "model not loaded"})
        if not self.slots.acquire(timeout=30):
            return self._send(HTTPStatus.SERVICE_UNAVAILABLE, {"error": "busy, try again"})
        try:
            result = self.model.score(data)
        except Exception as e:
            log.exception("scoring failed")
            return self._send(HTTPStatus.UNPROCESSABLE_ENTITY, {"error": f"could not score file: {type(e).__name__}"})
        finally:
            self.slots.release()
        self._send(HTTPStatus.OK, result)


def make_server(
    host: str,
    port: int,
    bundle_dir: Path,
    max_bytes: int = 64 * 1024 * 1024,
    max_concurrent: int = 2,
    token: str | None = None,
) -> ThreadingHTTPServer:
    model, error = load_model(bundle_dir)
    if model is not None:
        log.info("loaded PE model %s (quality gate %s)", model.meta.version,
                 "passed" if model.meta.quality_gate_passed else "FAILED")
        # Warm up so the first real request isn't slow.
        model.booster.predict(np.zeros((1, model.booster.num_feature()), dtype=np.float32))
    else:
        log.warning("%s; scoring will return 503 until a bundle is installed", error)
    handler = type(
        "BoundHandler",
        (Handler,),
        {
            "model": model,
            "load_error": error,
            "max_bytes": max_bytes,
            "token": token or None,
            "slots": threading.BoundedSemaphore(max_concurrent),
        },
    )
    server = ThreadingHTTPServer((host, port), handler)
    server.daemon_threads = True
    return server


def main() -> None:
    logging.basicConfig(level=os.environ.get("ML_LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(message)s")
    server = make_server(
        os.environ.get("ML_HOST", "0.0.0.0"),
        int(os.environ.get("ML_PORT", "8090")),
        Path(os.environ.get("ML_PE_BUNDLE_DIR", "/models/pe")),
        max_bytes=int(os.environ.get("ML_MAX_BYTES", str(64 * 1024 * 1024))),
        max_concurrent=int(os.environ.get("ML_MAX_CONCURRENT", "2")),
        token=os.environ.get("ML_SERVICE_TOKEN"),
    )
    log.info("listening on %s:%s", *server.server_address[:2])
    server.serve_forever()


if __name__ == "__main__":
    main()
