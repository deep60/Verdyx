"""EMBER2024 feature extraction for Windows programs (PE files).

Training and serving both go through this module, so the model always sees
features computed by the same code. That code is EMBER2024's own extractor
(`thrember/features.py`, EMBER feature version 3), loaded from the pinned
`thrember` install in requirements.txt.

The extractor file is loaded on its own, without running `thrember/__init__.py`.
The package's `__init__` also imports its training code (lightgbm, polars,
matplotlib), which the 1 GB production box should not pay for just to read
features.

This module also names all 2568 features, so explanations can say "max section
entropy" instead of "feature 1250". Several feature groups use the hashing
trick, where many names share one bucket. For those, `bucket_tokens` finds which
names from *this* file landed in a bucket, using the same hash as scikit-learn's
FeatureHasher.
"""

from __future__ import annotations

import importlib.util
import os
from dataclasses import dataclass
from functools import lru_cache
from types import ModuleType
from typing import Any

import numpy as np
from sklearn.utils import murmurhash3_32

FEATURE_DIM = 2568
FEATURE_VERSION = "ember-v3"

# Column indices LightGBM should treat as categorical, matching thrember's own
# `train_model`: is_pe and the four start bytes (general), and machine type and
# subsystem (header).
CATEGORICAL_FEATURES = [2, 3, 4, 5, 6, 701, 702]


@lru_cache(maxsize=1)
def _features_module() -> ModuleType:
    """Load thrember/features.py by path, without the package __init__."""
    spec = importlib.util.find_spec("thrember")
    if spec is None or not spec.submodule_search_locations:
        raise ImportError(
            "thrember is not installed; install ml/requirements.txt"
        )
    package_dir = list(spec.submodule_search_locations)[0]
    path = os.path.join(package_dir, "features.py")
    mod_spec = importlib.util.spec_from_file_location("thrember_features", path)
    if mod_spec is None or mod_spec.loader is None:
        raise ImportError(f"cannot load {path}")
    module = importlib.util.module_from_spec(mod_spec)
    mod_spec.loader.exec_module(module)
    return module


@lru_cache(maxsize=1)
def extractor() -> Any:
    """The shared EMBER2024 PEFeatureExtractor instance."""
    ext = _features_module().PEFeatureExtractor()
    if ext.dim != FEATURE_DIM:
        raise RuntimeError(
            f"EMBER extractor has {ext.dim} features, expected {FEATURE_DIM}; "
            "the pinned thrember version changed"
        )
    return ext


@dataclass(frozen=True)
class Extraction:
    raw: dict
    vector: np.ndarray  # float32 [FEATURE_DIM]

    @property
    def is_pe(self) -> bool:
        # GeneralFileInfo.is_pe: 1 only when pefile parsed the file.
        return bool(self.raw.get("general", {}).get("is_pe"))


def extract(data: bytes) -> Extraction:
    """Raw EMBER features and the model's input vector for one file."""
    if not data:
        raise ValueError("empty file")
    ext = extractor()
    raw = ext.raw_features(data)
    vector = ext.process_raw_features(raw)
    return Extraction(raw=raw, vector=vector)


def vectorize_raw(raw: dict) -> np.ndarray:
    """Model input vector from an EMBER2024 raw-feature record (a jsonl line)."""
    return extractor().process_raw_features(raw)


# ── Feature names ─────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class FeatureInfo:
    index: int
    group: str
    name: str
    # For hashing-trick buckets: (kind, bucket, n_buckets). None otherwise.
    hashed: tuple[str, int, int] | None = None


def _strings_regex_names() -> list[str]:
    ext = extractor()
    se = next(f for f in ext.features if f.name == "strings")
    return [k for k, _ in sorted(se.regex_idxs.items(), key=lambda kv: kv[1])]


@lru_cache(maxsize=1)
def feature_infos() -> tuple[FeatureInfo, ...]:
    """A name for every position of the feature vector, in order."""
    ext = extractor()
    byname = {f.name: f for f in ext.features}
    out: list[FeatureInfo] = []

    def add(group: str, name: str, hashed: tuple[str, int, int] | None = None):
        out.append(FeatureInfo(len(out), group, name, hashed))

    def add_hashed(group: str, kind: str, label: str, n: int):
        for b in range(n):
            add(group, f"{label} bucket {b}", (kind, b, n))

    for fe in ext.features:
        g = fe.name
        if g == "general":
            for n in ["file size", "file entropy", "is a parsable PE"] + [
                f"start byte {i}" for i in range(4)
            ]:
                add(g, n)
        elif g == "histogram":
            for b in range(256):
                add(g, f"share of byte 0x{b:02x}")
        elif g == "byteentropy":
            for e in range(16):
                for b in range(16):
                    add(g, f"bytes 0x{b * 16:02x}-0x{b * 16 + 15:02x} at local entropy {e / 2:.1f}-{(e + 1) / 2:.1f}")
        elif g == "strings":
            for n in ["number of strings", "average string length", "printable characters"]:
                add(g, n)
            for c in range(96):
                add(g, f"share of character {chr(0x20 + c)!r} in strings")
            add(g, "string character entropy")
            for k in _strings_regex_names():
                add(g, f"strings matching {k!r}")
        elif g == "header":
            for n in [
                "compile timestamp", "COFF number of sections", "COFF number of symbols",
                "size of optional header", "pointer to symbol table", "machine type",
                "subsystem", "major image version", "minor image version",
                "major linker version", "minor linker version", "major OS version",
                "minor OS version", "major subsystem version", "minor subsystem version",
                "size of code", "size of headers", "size of image",
                "size of initialized data", "size of uninitialized data",
                "stack reserve size", "stack commit size", "heap reserve size",
                "heap commit size", "entry point address", "base of code", "image base",
                "section alignment", "checksum", "number of data directories",
            ]:
                add(g, n)
            for ch in fe._image_characteristics:
                add(g, f"COFF flag {ch}")
            for ch in fe._dll_characteristics:
                add(g, f"DLL flag {ch}")
            for m in fe._dos_members:
                add(g, f"DOS header {m}")
        elif g == "section":
            for n in [
                "number of sections", "sections with zero size", "sections with no name",
                "readable+executable sections", "writable sections",
                "max section entropy", "min section entropy",
                "max section size ratio", "min section size ratio",
                "max raw/virtual size ratio", "min raw/virtual size ratio",
            ]:
                add(g, n)
            add_hashed(g, "section_size", "section size", 50)
            add_hashed(g, "section_vsize", "section virtual size", 50)
            add_hashed(g, "section_entropy", "section entropy", 50)
            add_hashed(g, "section_props", "section characteristics", 50)
            add_hashed(g, "entry_section", "entry-point section", 10)
            for n in ["overlay size", "overlay size ratio", "overlay entropy"]:
                add(g, n)
        elif g == "imports":
            add(g, "number of imported functions")
            add(g, "number of imported libraries")
            add_hashed(g, "import_library", "imported library", 256)
            add_hashed(g, "import_function", "imported function", 1024)
        elif g == "exports":
            add(g, "has exports")
            add_hashed(g, "export", "exported function", 128)
        elif g == "datadirectories":
            for d in byname["datadirectories"]._name_order:
                add(g, f"{d} directory size")
                add(g, f"{d} directory address")
            add(g, "has relocations")
            add(g, "has dynamic relocations")
        elif g == "richheader":
            add(g, "Rich header entries")
            add_hashed(g, "rich", "Rich header", 32)
        elif g == "authenticode":
            for n in [
                "number of signatures", "self-signed certificate", "empty program name",
                "no countersignature", "signature parse error", "certificate chain depth",
                "latest signing time", "signing time minus compile time",
            ]:
                add(g, n)
        elif g == "pefilewarnings":
            ids = sorted(fe.warning_ids.items(), key=lambda kv: kv[1])
            for w, _ in ids:
                add(g, f"pefile warning {w!r}")
            add(g, "number of pefile warnings")
        else:  # pragma: no cover - a new upstream group
            for i in range(fe.dim):
                add(g, f"{g}[{i}]")
        if len(out) != sum(f.dim for f in ext.features[: ext.features.index(fe) + 1]):
            raise RuntimeError(f"feature names for {g!r} do not match its width")

    if len(out) != FEATURE_DIM:
        raise RuntimeError(f"named {len(out)} features, expected {FEATURE_DIM}")
    return tuple(out)


def group_slices() -> dict[str, slice]:
    """The vector positions each feature group occupies."""
    ext = extractor()
    out, start = {}, 0
    for fe in ext.features:
        out[fe.name] = slice(start, start + fe.dim)
        start += fe.dim
    return out


# ── Hashing-trick attribution ─────────────────────────────────────────────────


def _bucket(token: str, n: int) -> int:
    # sklearn FeatureHasher: index = |murmurhash3_32(token, seed=0)| mod n.
    return abs(murmurhash3_32(token, seed=0)) % n


def _tokens(raw: dict, kind: str) -> list[str]:
    """The names a hashed block was built from, as thrember builds them."""
    if kind.startswith("section") or kind == "entry_section":
        sec = raw.get("section") or {}
        sections = sec.get("sections") or []
        if kind == "section_props":
            return [f"{s['name']}:{p}" for s in sections for p in s["props"]]
        if kind == "entry_section":
            return [sec.get("entry", "")] if sec else []
        return [s["name"] for s in sections]
    if kind == "import_library":
        return sorted({lib.lower() for lib in (raw.get("imports") or {})})
    if kind == "import_function":
        return [
            lib.lower() + ":" + fn
            for lib, fns in (raw.get("imports") or {}).items()
            for fn in fns
        ]
    if kind == "export":
        return list(raw.get("exports") or [])
    if kind == "rich":
        values = raw.get("richheader") or []
        return [str(values[i]) for i in range(0, len(values) - 1, 2)]
    return []


def bucket_tokens(raw: dict, info: FeatureInfo, limit: int = 5) -> list[str]:
    """Names from this file that fell into a hashed feature's bucket."""
    if info.hashed is None:
        return []
    kind, bucket, n = info.hashed
    hits = [t for t in _tokens(raw, kind) if _bucket(t, n) == bucket]
    # Keep order, drop duplicates.
    seen: set[str] = set()
    uniq = [t for t in hits if not (t in seen or seen.add(t))]
    return uniq[:limit]
