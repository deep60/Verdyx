"""Shared test helpers: a tiny PE builder and synthetic EMBER2024 data."""

from __future__ import annotations

import json
import random
import struct
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def build_pe(section_name: bytes = b".text", body: bytes = b"\xc3", overlay: bytes = b"") -> bytes:
    """A minimal, valid 32-bit Windows executable with one section.

    The code is a single `ret`; nothing here is runnable malware. It exists so
    tests can run the real EMBER extractor on a file pefile fully parses.
    """
    file_align, sect_align = 0x200, 0x1000
    raw_size = max(file_align, (len(body) + file_align - 1) // file_align * file_align)
    dos = bytearray(0x40)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x40)
    coff = struct.pack("<HHIIIHH", 0x014C, 1, 0x5F5E1000, 0, 0, 0xE0, 0x0102)
    opt = struct.pack(
        "<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII",
        0x10B, 14, 0,            # magic, linker version
        raw_size, 0, 0,          # code, init data, uninit data
        sect_align, sect_align,  # entry point, base of code
        0,                       # base of data
        0x400000, sect_align, file_align,
        6, 0, 0, 0, 6, 0,        # OS, image, subsystem versions
        0,                       # win32 version
        sect_align * 2,          # size of image
        file_align,              # size of headers
        0, 3, 0x8140,            # checksum, subsystem (console), dll flags
        0x100000, 0x1000, 0x100000, 0x1000, 0, 16,
    )
    opt += b"\x00" * (16 * 8)  # data directories, all empty
    name = section_name[:8].ljust(8, b"\x00")
    section = name + struct.pack(
        "<IIIIIIHHI", len(body), sect_align, raw_size, file_align, 0, 0, 0, 0, 0x60000020
    )
    headers = bytes(dos) + b"PE\x00\x00" + coff + opt + section
    headers = headers.ljust(file_align, b"\x00")
    return headers + body.ljust(raw_size, b"\x00") + overlay


def sample_pe(malicious: bool, rng: random.Random) -> bytes:
    """Clean-looking or packed-looking test programs, distinguishable by entropy."""
    if malicious:
        body = bytes(rng.getrandbits(8) for _ in range(rng.randint(1500, 3000)))
        name = rng.choice([b"UPX0", b".packed", b".xyz"])
        overlay = bytes(rng.getrandbits(8) for _ in range(rng.randint(0, 800)))
    else:
        words = [b"Hello ", b"report ", b"config ", b"window ", b"value "]
        body = b"".join(rng.choice(words) for _ in range(rng.randint(200, 400)))
        name, overlay = rng.choice([b".text", b".rdata"]), b""
    return build_pe(name, body, overlay)


@pytest.fixture(scope="session")
def ember_dir(tmp_path_factory) -> Path:
    """A miniature EMBER2024 layout: weekly-dated train/test/challenge jsonl."""
    from verdyx_ml.pe_features import extractor

    out = tmp_path_factory.mktemp("ember")
    rng = random.Random(1234)
    ext = extractor()
    start = datetime(2024, 1, 1, tzinfo=timezone.utc)

    def records(n: int, week0: int, weeks: int, mal_frac: float, families=("emotet", "qakbot", "agenttesla")):
        rows = []
        for i in range(n):
            mal = rng.random() < mal_frac
            raw = ext.raw_features(sample_pe(mal, rng))
            when = start + timedelta(weeks=week0 + i * weeks // n, hours=rng.randint(0, 100))
            raw.update(
                {
                    "label": int(mal),
                    "first_submission_date": when.strftime("%Y-%m-%d %H:%M:%S"),
                    "family": rng.choice(families) if mal else "",
                    "file_type": "Win32",
                }
            )
            rows.append(raw)
        return rows

    def write(name: str, rows):
        with open(out / name, "w") as f:
            for r in rows:
                f.write(json.dumps(r) + "\n")

    write("2024-01-01_2024-03-10_Win32_train.jsonl", records(700, 0, 10, 0.5))
    write("2024-03-11_2024-03-31_Win32_test.jsonl", records(300, 10, 3, 0.5))
    write("challenge_malicious.jsonl", records(60, 13, 1, 1.0))
    # Unlabelled rows must be ignored.
    with open(out / "2024-01-01_2024-03-10_Win32_train.jsonl", "a") as f:
        extra = ext.raw_features(sample_pe(False, rng))
        extra.update({"label": None, "first_submission_date": "2024-01-02", "file_type": "Win32"})
        f.write(json.dumps(extra) + "\n")
    return out


@pytest.fixture(scope="session")
def trained_bundle(ember_dir, tmp_path_factory) -> Path:
    from verdyx_ml import train_pe

    out = tmp_path_factory.mktemp("bundle")
    code = train_pe.main(
        [
            "--data-dir", str(ember_dir), "--out-dir", str(out),
            "--max-rounds", "60", "--early-stopping", "20", "--num-leaves", "8",
            "--min-data-in-leaf", "5", "--workers", "2", "--version", "pe-test",
            # Tiny data: loosen the gate so the test checks the mechanism.
            "--min-test-auc", "0.5", "--min-test-tpr-at-malicious-threshold", "0.0",
            "--max-test-fpr-at-malicious-threshold", "1.0", "--max-test-ece", "1.0",
        ]
    )
    assert code == 0
    return out
