"""Verdyx API client. Standard library only."""

from __future__ import annotations

import json
import os
import random
import re
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Union
from urllib import error as urlerror
from urllib import request as urlrequest
from urllib.parse import quote

from . import __version__

DEFAULT_API_URL = "https://api.verdyx.dev"
DEFAULT_WEB_URL = "https://verdyx.dev"

_FINISHED = {"completed", "failed"}
_RANK = {"clean": 0, "unknown": 0, "suspicious": 1, "malicious": 2}
_RETRYABLE = {429, 502, 503, 504}


class VerdyxError(Exception):
    """An error from the API or the client.

    ``status`` is the HTTP status when the API answered, ``body`` its parsed
    response and ``retry_after`` the seconds from a Retry-After header.
    """

    def __init__(self, message: str, status: Optional[int] = None, body: Any = None,
                 retry_after: Optional[float] = None) -> None:
        super().__init__(message)
        self.status = status
        self.body = body
        self.retry_after = retry_after


class ScanTimeoutError(VerdyxError):
    """The scan didn't finish in time. It keeps running on the server."""

    def __init__(self, submission_id: str, seconds: float) -> None:
        super().__init__(f"scan {submission_id} did not finish within {seconds:g}s")
        self.submission_id = submission_id


@dataclass
class Submission:
    id: str
    status: str
    sha256: Optional[str] = None
    filename: Optional[str] = None
    type: Optional[str] = None


@dataclass
class EngineResult:
    name: str
    type: Optional[str] = None
    #: None when the engine gave no verdict.
    verdict: Optional[str] = None
    #: Percent: how sure the engine is of the verdict it gave.
    confidence: Optional[float] = None
    #: Percent: a model's calibrated chance that the file is malware (the
    #: Windows Program Model). It can say clean at 64% when its line for
    #: suspicious is higher.
    malware_chance: Optional[int] = None
    #: "counted", "no_record", "advisory" or "unavailable".
    vote: Optional[str] = None
    reason: Optional[str] = None


@dataclass
class ScanResult:
    id: str
    status: str
    #: "malicious", "suspicious", "clean" or "unknown".
    verdict: str
    report_url: str
    target: Optional[str] = None
    sha256: Optional[str] = None
    failure_reason: Optional[str] = None
    explanation: Optional[str] = None
    votes: Dict[str, int] = field(default_factory=dict)
    engines: List[EngineResult] = field(default_factory=list)
    #: The raw API objects, for fields not mapped above.
    submission: Dict[str, Any] = field(default_factory=dict, repr=False)
    consensus: Optional[Dict[str, Any]] = field(default=None, repr=False)

    def meets(self, threshold: str) -> bool:
        """True when this verdict is at least as bad as ``threshold``."""
        return meets_threshold(self.verdict, threshold)


def meets_threshold(verdict: str, threshold: str) -> bool:
    """True when ``verdict`` is at least as bad as ``threshold``
    ("malicious", "suspicious" or "never")."""
    if threshold in ("never", "none"):
        return False
    if threshold not in _RANK:
        raise VerdyxError(f'unknown threshold "{threshold}"')
    return _RANK.get(verdict, 0) >= _RANK[threshold]


def _is_url(target: str) -> bool:
    return re.match(r"^https?://", target, re.I) is not None


def _normalise_verdict(v: Any) -> str:
    s = str(v or "unknown").lower()
    if s == "benign":
        return "clean"
    return s if s in _RANK else "unknown"


class Verdyx:
    """A client for the Verdyx API.

    The API key defaults to the ``VERDYX_API_KEY`` environment variable and the
    API to ``VERDYX_API_URL``, then https://api.verdyx.dev.
    """

    def __init__(self, api_key: Optional[str] = None, api_url: Optional[str] = None,
                 web_url: Optional[str] = None, timeout: float = 60.0, max_retries: int = 3,
                 user_agent: Optional[str] = None) -> None:
        self.api_key = api_key if api_key is not None else os.environ.get("VERDYX_API_KEY")
        self.api_url = (api_url or os.environ.get("VERDYX_API_URL") or DEFAULT_API_URL).rstrip("/")
        self.web_url = (web_url or os.environ.get("VERDYX_WEB_URL") or DEFAULT_WEB_URL).rstrip("/")
        self.timeout = timeout
        self.max_retries = max_retries
        self.user_agent = user_agent or f"verdyx-python/{__version__}"

    def __repr__(self) -> str:  # never show the key
        return f"Verdyx(api_url={self.api_url!r}, api_key={'set' if self.api_key else 'unset'})"

    def report_url(self, submission_id: str) -> str:
        return f"{self.web_url}/analysis/{quote(submission_id, safe='')}"

    # ── HTTP ─────────────────────────────────────────────────────────────

    def request(self, method: str, path: str, body: Optional[bytes] = None,
                content_type: Optional[str] = None, retry: bool = True) -> Any:
        headers = {"Accept": "application/json", "User-Agent": self.user_agent}
        if self.api_key:
            headers["X-API-Key"] = self.api_key
        if content_type:
            headers["Content-Type"] = content_type
        url = f"{self.api_url}/api/v1{path}"
        attempt = 0
        while True:
            req = urlrequest.Request(url, data=body, method=method, headers=headers)
            try:
                with urlrequest.urlopen(req, timeout=self.timeout) as res:
                    return _parse(res.read())
            except urlerror.HTTPError as e:
                data = _parse(e.read())
                retry_after = _float(e.headers.get("Retry-After"))
                if retry and e.code in _RETRYABLE and attempt < self.max_retries:
                    time.sleep(min(retry_after, 60) if retry_after else _backoff(attempt))
                    attempt += 1
                    continue
                raise VerdyxError(_message(e.code, data), status=e.code, body=data,
                                  retry_after=retry_after) from None
            except (urlerror.URLError, OSError) as e:
                if retry and attempt < self.max_retries:
                    time.sleep(_backoff(attempt))
                    attempt += 1
                    continue
                reason = getattr(e, "reason", e)
                raise VerdyxError(f"could not reach {self.api_url}: {reason}") from None

    # ── Submitting ───────────────────────────────────────────────────────

    def submit_file(self, file: Union[str, os.PathLike, bytes], filename: Optional[str] = None,
                    description: Optional[str] = None, team_id: Optional[str] = None,
                    priority: bool = False) -> Submission:
        """Upload a file: a path, or bytes with ``filename``."""
        if isinstance(file, (bytes, bytearray)):
            data = bytes(file)
            name = filename or "upload.bin"
        else:
            p = Path(file)
            data = p.read_bytes()
            name = filename or p.name
        if not data:
            raise VerdyxError("the file is empty")
        fields = _common(description, team_id, priority)
        return self._submit(fields, ("file", name, data))

    def submit_url(self, url: str, description: Optional[str] = None,
                   team_id: Optional[str] = None, priority: bool = False) -> Submission:
        if not _is_url(url):
            raise VerdyxError(f"not an http(s) URL: {url}")
        fields = [("url", url)] + _common(description, team_id, priority)
        return self._submit(fields, None)

    def _submit(self, fields: List[tuple], file: Optional[tuple]) -> Submission:
        body, ctype = _multipart(fields, file)
        # Uploads aren't retried: a retry after a lost response could create a second scan.
        raw = self.request("POST", "/submissions/file", body=body, content_type=ctype, retry=False)
        if not isinstance(raw, dict) or not raw.get("id"):
            raise VerdyxError("unexpected response from the submit endpoint", body=raw)
        return Submission(
            id=str(raw["id"]),
            status=raw.get("analysis_status") or raw.get("analysisStatus") or "pending",
            sha256=raw.get("file_hash") or raw.get("fileHash"),
            filename=raw.get("original_filename") or raw.get("originalFilename"),
            type=raw.get("submission_type") or raw.get("submissionType"),
        )

    # ── Reading ──────────────────────────────────────────────────────────

    def get_submission(self, submission_id: str) -> Dict[str, Any]:
        return self.request("GET", f"/submissions/{quote(submission_id, safe='')}")

    def get_consensus(self, submission_id: str) -> Dict[str, Any]:
        return self.request("GET", f"/submissions/{quote(submission_id, safe='')}/consensus")

    def get_analyses(self, submission_id: str) -> List[Dict[str, Any]]:
        data = self.request("GET", f"/submissions/{quote(submission_id, safe='')}/analyses")
        return _as_list(data, "analyses")

    def list_engines(self) -> List[Dict[str, Any]]:
        """The engines and whether each is online."""
        return _as_list(self.request("GET", "/engines"), "engines")

    def wait_for_result(self, submission_id: str, timeout: float = 300,
                        poll_interval: Optional[float] = None,
                        on_status: Optional[Callable[[str], None]] = None) -> ScanResult:
        """Poll until the scan finishes. Raises ScanTimeoutError on timeout.

        By default polling starts at 2 s and backs off to 10 s.
        """
        deadline = time.monotonic() + timeout
        delay = poll_interval or 2.0
        while True:
            submission = self.get_submission(submission_id)
            status = submission.get("analysisStatus") or submission.get("status") or "pending"
            if on_status:
                on_status(status)
            if status in _FINISHED:
                return self.result(submission_id, submission)
            if time.monotonic() + delay > deadline:
                raise ScanTimeoutError(submission_id, timeout)
            time.sleep(delay)
            if not poll_interval:
                delay = min(delay * 1.5, 10.0)

    def result(self, submission_id: str, submission: Optional[Dict[str, Any]] = None) -> ScanResult:
        """The result of a scan as it stands now."""
        submission = submission if submission is not None else self.get_submission(submission_id)
        status = submission.get("analysisStatus") or submission.get("status") or "pending"
        consensus: Optional[Dict[str, Any]] = None
        analyses: List[Dict[str, Any]] = []
        if status == "completed":
            consensus = self.get_consensus(submission_id)
            analyses = self.get_analyses(submission_id)
        c = consensus or {}
        return ScanResult(
            id=submission_id,
            status=status,
            verdict=_normalise_verdict(c.get("finalVerdict")) if status == "completed" else "unknown",
            report_url=self.report_url(submission_id),
            target=submission.get("url") or submission.get("originalFilename") or submission.get("filename"),
            sha256=submission.get("fileHash"),
            failure_reason=submission.get("failureReason"),
            explanation=c.get("explanation"),
            votes={
                "malicious": c.get("maliciousVotes") or 0,
                "suspicious": c.get("suspiciousVotes") or 0,
                "clean": c.get("cleanVotes") or 0,
                "total": c.get("totalVotes") or 0,
            },
            engines=[_engine(a) for a in analyses],
            submission=submission,
            consensus=consensus,
        )

    def scan(self, target: Union[str, os.PathLike], timeout: float = 300,
             poll_interval: Optional[float] = None, **submit_options: Any) -> ScanResult:
        """Submit a file path or http(s) URL, then wait for the verdict."""
        t = os.fspath(target)
        sub = self.submit_url(t, **submit_options) if _is_url(t) else self.submit_file(t, **submit_options)
        return self.wait_for_result(sub.id, timeout=timeout, poll_interval=poll_interval)


# ── Helpers ──────────────────────────────────────────────────────────────

def _common(description: Optional[str], team_id: Optional[str], priority: bool) -> List[tuple]:
    out: List[tuple] = []
    if description:
        out.append(("description", description))
    if team_id:
        out.append(("organizationId", team_id))
    if priority:
        out.append(("priority", "true"))
    return out


def _multipart(fields: List[tuple], file: Optional[tuple]) -> tuple:
    boundary = f"----verdyx{uuid.uuid4().hex}"
    parts: List[bytes] = []
    for name, value in fields:
        parts.append(
            f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n'.encode()
            + str(value).encode() + b"\r\n"
        )
    if file:
        name, filename, data = file
        safe = filename.replace('"', "_").replace("\r", "_").replace("\n", "_")
        parts.append(
            f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"; filename="{safe}"\r\n'
            f"Content-Type: application/octet-stream\r\n\r\n".encode()
            + data + b"\r\n"
        )
    parts.append(f"--{boundary}--\r\n".encode())
    return b"".join(parts), f"multipart/form-data; boundary={boundary}"


def _parse(raw: bytes) -> Any:
    if not raw:
        return None
    text = raw.decode("utf-8", "replace")
    try:
        return json.loads(text)
    except ValueError:
        return text


def _float(v: Optional[str]) -> Optional[float]:
    try:
        return float(v) if v else None
    except ValueError:
        return None


def _as_list(data: Any, key: str) -> List[Dict[str, Any]]:
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        return data.get(key) or data.get("data") or []
    return []


def _engine(a: Dict[str, Any]) -> EngineResult:
    eng = a.get("engine") or {}
    # The API sends "unknown" for an engine that ran but didn't vote.
    verdict = _normalise_verdict(a["verdict"]) if a.get("verdict") else "unknown"
    probability = (a.get("metadata") or {}).get("probability")
    return EngineResult(
        name=eng.get("name") or a.get("engineName") or "engine",
        type=eng.get("type") or a.get("engineType"),
        verdict=None if verdict == "unknown" else verdict,
        confidence=a.get("confidence"),
        malware_chance=(
            round(probability * 100)
            if isinstance(probability, (int, float)) and not isinstance(probability, bool)
            else None
        ),
        vote=a.get("vote"),
        reason=a.get("reason"),
    )


def _message(status: int, data: Any) -> str:
    detail = ""
    if isinstance(data, dict):
        detail = data.get("message") or data.get("error") or data.get("detail") or ""
    elif isinstance(data, str) and len(data) < 300:
        detail = data
    hints = {
        401: "the API key is missing, revoked or expired",
        403: "the API key isn't allowed to do this",
        404: "not found, or not visible to this API key",
        413: "the file is larger than the 100 MB limit",
        429: "rate limited",
    }
    detail = detail or hints.get(status, "")
    return f"HTTP {status}: {detail}" if detail else f"HTTP {status}"


def _backoff(attempt: int) -> float:
    return min(2 ** attempt, 15) + random.random() / 4
