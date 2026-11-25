"""Tests against a small in-process stand-in for the Verdyx API.

Run with: python -m unittest discover -s tests
"""

import email.parser
import email.policy
import hashlib
import json
import tempfile
import threading
import time
import unittest
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from verdyx import ScanTimeoutError, Verdyx, VerdyxError, meets_threshold

KEY = "vdx_" + "2" * 64
EICAR = "stand-in sample: the mock API treats any upload containing EICAR as malicious"


class MockApi:
    """Answers the routes the client calls, with backend/api-gateway's shapes."""

    def __init__(self):
        self.scans = {}
        self.requests = []
        self.replies = []  # queued (status, body, headers) overrides
        api = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def _send(self, status, data, headers=None):
                body = json.dumps(data).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                for k, v in (headers or {}).items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _handle(self):
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length) if length else b""
                api.requests.append((self.command, self.path, dict(self.headers), body))
                if api.replies:
                    return self._send(*api.replies.pop(0))
                if self.headers.get("X-API-Key") != KEY:
                    return self._send(401, {"message": "invalid API key"})
                path = self.path.split("?")[0].replace("/api/v1", "", 1)
                if self.command == "GET" and path == "/engines":
                    return self._send(200, [{"name": "YARA Engine", "status": "online"}])
                if self.command == "POST" and path == "/submissions/file":
                    form = _parse_form(self.headers["Content-Type"], body)
                    sid = str(uuid.uuid4())
                    if "file" in form:
                        name, data = form["file"]
                        content = data.decode("latin-1")
                    else:
                        name, data, content = form["url"], form["url"].encode(), form["url"]
                    verdict = "malicious" if "EICAR" in content else "suspicious" if "phish" in content else "clean"
                    api.scans[sid] = {"id": sid, "target": name, "url": "url" in form, "verdict": verdict,
                                      "hash": hashlib.sha256(data).hexdigest(), "polls": 0,
                                      "fail": "fail-me" in content, "form": form}
                    return self._send(200, {"id": sid, "analysis_status": "pending", "file_hash": api.scans[sid]["hash"],
                                            "original_filename": name, "submission_type": "url" if "url" in form else "file"})
                parts = path.strip("/").split("/")
                if self.command == "GET" and parts[0] == "submissions" and len(parts) >= 2:
                    scan = api.scans.get(parts[1])
                    if not scan:
                        return self._send(404, {"message": "not found"})
                    if len(parts) == 2:
                        scan["polls"] += 1
                        status = "analyzing" if scan["polls"] < 2 else ("failed" if scan["fail"] else "completed")
                        return self._send(200, {"id": scan["id"], "analysisStatus": status, "status": status,
                                                "originalFilename": scan["target"], "fileHash": scan["hash"],
                                                "url": scan["target"] if scan["url"] else None,
                                                **({"failureReason": "could not fetch"} if status == "failed" else {})})
                    flagged = scan["verdict"] != "clean"
                    if parts[2] == "consensus":
                        return self._send(200, {"finalVerdict": scan["verdict"], "explanation": "x",
                                                "maliciousVotes": int(scan["verdict"] == "malicious"),
                                                "suspiciousVotes": int(scan["verdict"] == "suspicious"),
                                                "cleanVotes": 1 if flagged else 2, "totalVotes": 2})
                    if parts[2] == "analyses":
                        return self._send(200, [
                            {"engine": {"name": "YARA", "type": "yara"},
                             "verdict": scan["verdict"] if flagged else "benign", "confidence": 90, "vote": "counted"},
                            {"engine": {"name": "MalwareBazaar"}, "verdict": None, "vote": "no_record",
                             "reason": "Not in MalwareBazaar"},
                            # Like the live API: "unknown" for an engine that didn't vote.
                            {"engine": {"name": "ClamAV"}, "verdict": "unknown",
                             "reason": "No known-bad pattern matched"},
                            {"engine": {"name": "Verdyx PE Model"}, "verdict": "clean", "confidence": 36,
                             "metadata": {"probability": 0.6421}},
                        ])
                return self._send(404, {"message": "no mock"})

            do_GET = do_POST = _handle

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


def _parse_form(ctype, body):
    msg = email.parser.BytesParser(policy=email.policy.HTTP).parsebytes(
        f"Content-Type: {ctype}\r\n\r\n".encode() + body)
    out = {}
    for part in msg.iter_parts():
        name = part.get_param("name", header="content-disposition")
        filename = part.get_filename()
        payload = part.get_payload(decode=True)
        out[name] = (filename, payload) if filename is not None else payload.decode()
    return out


class ClientTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.api = MockApi()
        cls.tmp = tempfile.TemporaryDirectory()

    @classmethod
    def tearDownClass(cls):
        cls.api.close()
        cls.tmp.cleanup()

    def setUp(self):
        self.api.replies.clear()
        self.client = Verdyx(api_key=KEY, api_url=self.api.url + "/", web_url="https://verdyx.dev")

    def test_scans_a_file_path(self):
        p = Path(self.tmp.name) / "eicar.com"
        p.write_text(EICAR)
        r = self.client.scan(p, poll_interval=0.02)
        self.assertEqual(r.status, "completed")
        self.assertEqual(r.verdict, "malicious")
        self.assertEqual(r.target, "eicar.com")
        self.assertEqual(len(r.sha256), 64)
        self.assertEqual(r.votes, {"malicious": 1, "suspicious": 0, "clean": 1, "total": 2})
        self.assertEqual(r.report_url, f"https://verdyx.dev/analysis/{r.id}")
        self.assertEqual([e.name for e in r.engines], ["YARA", "MalwareBazaar", "ClamAV", "Verdyx PE Model"])
        self.assertEqual(r.engines[1].vote, "no_record")
        self.assertTrue(r.meets("malicious"))
        method, path, headers, _ = next(x for x in self.api.requests if x[0] == "POST")
        headers = {k.lower(): v for k, v in headers.items()}  # header names are case-insensitive
        self.assertEqual(path, "/api/v1/submissions/file")
        self.assertEqual(headers["x-api-key"], KEY)
        self.assertTrue(headers["user-agent"].startswith("verdyx-python/"))

    def test_scans_urls(self):
        self.assertEqual(self.client.scan("https://example.com/", poll_interval=0.02).verdict, "clean")
        r = self.client.scan("https://phish.test/login", poll_interval=0.02)
        self.assertEqual(r.verdict, "suspicious")
        self.assertEqual(r.target, "https://phish.test/login")

    def test_engine_benign_is_reported_as_clean(self):
        r = self.client.scan("https://example.org/", poll_interval=0.02)
        self.assertEqual(r.engines[0].verdict, "clean")
        self.assertIsNone(r.engines[1].verdict)
        self.assertIsNone(r.engines[2].verdict, "unknown means the engine didn't vote")
        self.assertIsNone(r.engines[2].malware_chance)
        self.assertEqual(r.engines[3].malware_chance, 64)

    def test_bytes_with_options(self):
        sub = self.client.submit_file(b"hello", filename='odd"name.txt', description="note",
                                      team_id="team-1", priority=True)
        self.assertEqual(sub.status, "pending")
        form = self.api.scans[sub.id]["form"]
        self.assertEqual(form["file"], ('odd_name.txt', b"hello"))
        self.assertEqual(form["description"], "note")
        self.assertEqual(form["organizationId"], "team-1")
        self.assertEqual(form["priority"], "true")

    def test_failed_scan(self):
        r = self.client.scan("https://fail-me.test/", poll_interval=0.02)
        self.assertEqual(r.status, "failed")
        self.assertEqual(r.verdict, "unknown")
        self.assertEqual(r.failure_reason, "could not fetch")
        self.assertEqual(r.engines, [])

    def test_timeout(self):
        sub = self.client.submit_url("https://slow.test/")
        with self.assertRaises(ScanTimeoutError) as ctx:
            self.client.wait_for_result(sub.id, timeout=0.01, poll_interval=1)
        self.assertEqual(ctx.exception.submission_id, sub.id)

    def test_on_status(self):
        sub = self.client.submit_url("https://example.net/")
        seen = []
        self.client.wait_for_result(sub.id, poll_interval=0.02, on_status=seen.append)
        self.assertEqual(seen, ["analyzing", "completed"])

    def test_errors(self):
        bad = Verdyx(api_key="vdx_bad", api_url=self.api.url)
        with self.assertRaises(VerdyxError) as ctx:
            bad.list_engines()
        self.assertEqual(ctx.exception.status, 401)
        self.assertEqual(str(ctx.exception), "HTTP 401: invalid API key")
        with self.assertRaises(VerdyxError) as ctx:
            self.client.get_submission("nope")
        self.assertEqual(ctx.exception.status, 404)
        with self.assertRaises(VerdyxError):
            self.client.submit_file(b"")
        with self.assertRaises(VerdyxError):
            self.client.submit_url("ftp://example.com")

    def test_reads_retry_on_429_and_5xx(self):
        self.api.replies[:] = [(503, {}), (429, {"message": "slow"}, {"Retry-After": "1"})]
        t0 = time.monotonic()
        engines = self.client.list_engines()
        self.assertEqual(engines[0]["name"], "YARA Engine")
        self.assertGreaterEqual(time.monotonic() - t0, 1.0)

    def test_uploads_are_not_retried(self):
        self.api.replies[:] = [(429, {"message": "slow down"}, {"Retry-After": "7"})]
        before = len(self.api.scans)
        with self.assertRaises(VerdyxError) as ctx:
            self.client.submit_url("https://example.com/")
        self.assertEqual(ctx.exception.status, 429)
        self.assertEqual(ctx.exception.retry_after, 7.0)
        self.assertEqual(str(ctx.exception), "HTTP 429: slow down")
        self.assertEqual(len(self.api.scans), before)

    def test_unreachable(self):
        c = Verdyx(api_url="http://127.0.0.1:9", max_retries=0)
        with self.assertRaises(VerdyxError) as ctx:
            c.list_engines()
        self.assertIn("could not reach", str(ctx.exception))

    def test_repr_hides_the_key(self):
        self.assertNotIn(KEY, repr(self.client))

    def test_meets_threshold(self):
        self.assertTrue(meets_threshold("malicious", "suspicious"))
        self.assertFalse(meets_threshold("suspicious", "malicious"))
        self.assertFalse(meets_threshold("malicious", "never"))
        self.assertFalse(meets_threshold("unknown", "suspicious"))
        with self.assertRaises(VerdyxError):
            meets_threshold("malicious", "high")


if __name__ == "__main__":
    unittest.main()
