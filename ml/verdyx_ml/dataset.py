"""Load EMBER2024 raw-feature files into time-ordered arrays.

EMBER2024 ships one JSON object per line (`*.jsonl`): the raw features of a
file plus its metadata (label, first-submission date, family, file type).
This module turns those lines into:

    <cache>/X.f32        float32 memmap, one row per file, sorted oldest first
    <cache>/meta.npz     label, date, family, file type, sha256 per row
    <cache>/manifest.json  which source files built it, for cache checks

Rows are sorted by first-submission date so every split is "older trains,
newer tests" and each split is a contiguous slice that LightGBM can read
without copying the whole array into memory.

Sampling is by sha256, so it is reproducible: the same file is always in or
out, whatever machine or order the data is read in.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from multiprocessing import get_context
from pathlib import Path
from typing import Iterable, Iterator

import numpy as np

from .pe_features import FEATURE_DIM, vectorize_raw

SUBSETS = ("train", "test", "challenge")
PE_FILE_TYPES = ("Win32", "Win64", "Dot_Net")


# ── Source files ──────────────────────────────────────────────────────────────


def find_files(data_dir: Path, subset: str, file_types: Iterable[str]) -> list[Path]:
    """jsonl files of a subset (train/test/challenge), filtered by file type.

    EMBER2024 names files by subset and type (e.g. `..._Win32_train.jsonl`).
    The challenge set mixes types in one file, so it is never type-filtered by
    name; rows are filtered by their `file_type` field instead.
    """
    if subset not in SUBSETS:
        raise ValueError(f"subset must be one of {SUBSETS}")
    types = [t.lower() for t in file_types]
    out = []
    for p in sorted(Path(data_dir).rglob("*.jsonl")):
        name = p.name.lower()
        if subset not in name:
            continue
        if subset != "challenge" and types and not any(t in name for t in types):
            continue
        out.append(p)
    return out


def parse_date(value) -> int | None:
    """Seconds since the epoch from an int, numeric string or ISO date."""
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)):
        return int(value)
    s = str(value).strip()
    try:
        return int(float(s))
    except ValueError:
        pass
    s = s.replace("Z", "+00:00")
    for fmt in (None, "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            dt = datetime.fromisoformat(s) if fmt is None else datetime.strptime(s, fmt)
        except ValueError:
            continue
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return int(dt.timestamp())
    return None


def keep_by_hash(sha256: str, fraction: float) -> bool:
    if fraction >= 1.0:
        return True
    if not sha256:
        sha256 = "0" * 8
    return int(sha256[:8], 16) / 0xFFFFFFFF < fraction


# ── Vectorizing ───────────────────────────────────────────────────────────────


@dataclass
class Row:
    vector: np.ndarray | None
    label: int
    date: int
    family: str
    file_type: str
    sha256: str
    error: str | None = None


def _process_line(args: tuple[str, float, tuple[str, ...]]) -> Row | None:
    line, fraction, file_types = args
    try:
        obj = json.loads(line)
    except json.JSONDecodeError as e:
        return Row(None, -1, 0, "", "", "", f"bad json: {e}")
    label = obj.get("label")
    if label is None or int(label) not in (0, 1):
        return None  # unlabelled: not usable for supervised training
    ftype = str(obj.get("file_type") or "")
    if file_types and ftype and ftype not in file_types:
        return None
    sha = str(obj.get("sha256") or "")
    if not keep_by_hash(sha, fraction):
        return None
    date = parse_date(obj.get("first_submission_date"))
    if date is None:
        return Row(None, -1, 0, "", ftype, sha, "missing first_submission_date")
    try:
        vec = vectorize_raw(obj)
    except Exception as e:  # malformed record: skip it, but count it
        return Row(None, -1, 0, "", ftype, sha, f"{type(e).__name__}: {e}")
    return Row(vec, int(label), date, str(obj.get("family") or ""), ftype, sha)


def _lines(files: list[Path]) -> Iterator[str]:
    for p in files:
        with open(p, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    yield line


def _count_lines(files: list[Path]) -> int:
    n = 0
    for p in files:
        with open(p, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 24), b""):
                n += chunk.count(b"\n")
    return n + len(files)  # a last line may lack a newline


def _manifest(files: list[Path], fraction: float, file_types: tuple[str, ...]) -> dict:
    return {
        "files": [{"path": str(p), "size": p.stat().st_size} for p in files],
        "fraction": fraction,
        "file_types": list(file_types),
        "feature_dim": FEATURE_DIM,
    }


@dataclass
class Split:
    X: np.ndarray  # float32 [n, FEATURE_DIM], possibly a memmap
    y: np.ndarray  # int8
    date: np.ndarray  # int64 seconds
    family: np.ndarray
    file_type: np.ndarray
    sha256: np.ndarray
    errors: int = 0

    def __len__(self) -> int:
        return len(self.y)

    def slice(self, start: int, stop: int) -> "Split":
        return Split(
            self.X[start:stop], self.y[start:stop], self.date[start:stop],
            self.family[start:stop], self.file_type[start:stop], self.sha256[start:stop],
        )


def build(
    files: list[Path],
    cache_dir: Path,
    fraction: float = 1.0,
    file_types: tuple[str, ...] = PE_FILE_TYPES,
    workers: int | None = None,
    log=print,
) -> Split:
    """Vectorize `files` into `cache_dir`, or reuse a matching cache."""
    cache_dir = Path(cache_dir)
    cache_dir.mkdir(parents=True, exist_ok=True)
    manifest = _manifest(files, fraction, file_types)
    mpath, xpath, metapath = cache_dir / "manifest.json", cache_dir / "X.f32", cache_dir / "meta.npz"

    if mpath.exists() and xpath.exists() and metapath.exists():
        old = json.loads(mpath.read_text())
        if {k: v for k, v in old.items() if k != "rows" and k != "errors"} == manifest:
            log(f"  reusing cached features in {cache_dir}")
            return _load(cache_dir, old)

    if not files:
        raise FileNotFoundError("no matching .jsonl files")
    upper = _count_lines(files)
    log(f"  vectorizing up to {upper:,} records from {len(files)} file(s)")
    tmp = np.lib.format.open_memmap(
        cache_dir / "X.unsorted.npy", mode="w+", dtype=np.float32, shape=(upper, FEATURE_DIM)
    )
    labels, dates, families, ftypes, shas = [], [], [], [], []
    errors, n = 0, 0
    workers = workers or max(1, (os.cpu_count() or 2) - 1)
    ctx = get_context("spawn")  # fork is unsafe with threaded numpy on macOS
    jobs = ((line, fraction, file_types) for line in _lines(files))
    with ctx.Pool(workers) as pool:
        for row in pool.imap(_process_line, jobs, chunksize=64):
            if row is None:
                continue
            if row.vector is None:
                errors += 1
                continue
            tmp[n] = row.vector
            labels.append(row.label)
            dates.append(row.date)
            families.append(row.family)
            ftypes.append(row.file_type)
            shas.append(row.sha256)
            n += 1
            if n % 100_000 == 0:
                log(f"    {n:,} rows")
    tmp.flush()
    log(f"  kept {n:,} rows ({errors:,} unreadable records skipped)")

    # Sort oldest first; ties broken by sha256 so the order is deterministic.
    date_arr = np.asarray(dates, dtype=np.int64)
    sha_arr = np.asarray(shas)
    order = np.lexsort((sha_arr, date_arr))
    X = np.memmap(xpath, mode="w+", dtype=np.float32, shape=(n, FEATURE_DIM))
    step = 50_000
    for s in range(0, n, step):
        idx = order[s : s + step]
        X[s : s + len(idx)] = tmp[np.sort(idx)][np.argsort(np.argsort(idx))]
    X.flush()
    del tmp
    os.remove(cache_dir / "X.unsorted.npy")

    np.savez(
        metapath,
        y=np.asarray(labels, dtype=np.int8)[order],
        date=date_arr[order],
        family=np.asarray(families)[order],
        file_type=np.asarray(ftypes)[order],
        sha256=sha_arr[order],
    )
    manifest.update({"rows": n, "errors": errors})
    mpath.write_text(json.dumps(manifest, indent=2) + "\n")
    return _load(cache_dir, manifest)


def _load(cache_dir: Path, manifest: dict) -> Split:
    n = int(manifest["rows"])
    X = np.memmap(cache_dir / "X.f32", mode="r", dtype=np.float32, shape=(n, FEATURE_DIM))
    meta = np.load(cache_dir / "meta.npz")
    return Split(
        X, meta["y"], meta["date"], meta["family"], meta["file_type"], meta["sha256"],
        errors=int(manifest.get("errors", 0)),
    )


def fingerprint(paths: list[Path]) -> str:
    h = hashlib.sha256()
    for p in paths:
        h.update(f"{p.name}:{p.stat().st_size}\n".encode())
    return h.hexdigest()[:16]
