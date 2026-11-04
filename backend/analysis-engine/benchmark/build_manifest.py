#!/usr/bin/env python3
"""Pick the malicious half of the benchmark set from MalwareBazaar metadata.

This only reads sample *metadata* (hash, type, family). It never downloads a
sample; fetch_samples.sh does that, on the server, when the benchmark runs.

The set is spread across file types, and each malware family is capped so one
prolific family can't dominate the detection rate. The output is written to
manifest.json and committed, so every benchmark run measures the same files.

Usage:
    ABUSE_CH_API_KEY=... python3 build_manifest.py > manifest.json
"""

import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict
from datetime import datetime, timezone

API = "https://mb-api.abuse.ch/api/v1/"

# MalwareBazaar file type -> (benchmark category, how many to take).
QUOTAS = [
    ("exe", "pe", 80),
    ("dll", "pe", 30),
    ("elf", "elf", 30),
    ("ps1", "script", 12),
    ("js", "script", 12),
    ("vbs", "script", 10),
    ("bat", "script", 8),
    ("hta", "script", 5),
    ("doc", "office", 6),
    ("docm", "office", 6),
    ("xls", "office", 6),
    ("xlsm", "office", 6),
    ("pdf", "pdf", 10),
    ("lnk", "lnk", 10),
    ("apk", "apk", 10),
]

PER_FAMILY_CAP = 4
UNKNOWN_FAMILY_CAP = 10
# Most Linux malware is a handful of botnet families (Mirai, Gafgyt), so a
# cap of 4 would leave the ELF category nearly empty.
ELF_FAMILY_CAP = 10
MAX_SIZE = 20 * 1024 * 1024


def query(key, **params):
    data = urllib.parse.urlencode(params).encode()
    for attempt in range(5):
        req = urllib.request.Request(API, data=data, headers={"Auth-Key": key})
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                return json.load(resp)
        except (urllib.error.URLError, TimeoutError) as err:
            print(f"retrying after {err}", file=sys.stderr)
            time.sleep(5 * (attempt + 1))
    return {"query_status": "request_failed"}


def main():
    key = os.environ.get("ABUSE_CH_API_KEY", "").strip()
    if not key:
        sys.exit("ABUSE_CH_API_KEY is not set")

    family_counts = defaultdict(int)
    samples = []
    seen = set()

    for file_type, category, quota in QUOTAS:
        reply = query(key, query="get_file_type", file_type=file_type, limit=1000)
        if reply.get("query_status") != "ok":
            print(f"{file_type}: {reply.get('query_status')}", file=sys.stderr)
            continue

        taken = 0
        for item in reply["data"]:
            if taken >= quota:
                break
            sha = item.get("sha256_hash")
            size = item.get("file_size") or 0
            if not sha or sha in seen or size > MAX_SIZE:
                continue
            family = item.get("signature") or "unknown"
            if family == "unknown":
                cap = UNKNOWN_FAMILY_CAP
            elif category == "elf":
                cap = ELF_FAMILY_CAP
            else:
                cap = PER_FAMILY_CAP
            if family_counts[family] >= cap:
                continue

            family_counts[family] += 1
            seen.add(sha)
            taken += 1
            samples.append(
                {
                    "sha256": sha,
                    "label": "malicious",
                    "category": category,
                    "file_type": file_type,
                    "family": family,
                    "size": size,
                    "first_seen": item.get("first_seen"),
                    "source": "MalwareBazaar",
                }
            )
        print(f"{file_type}: {taken}/{quota}", file=sys.stderr)

    manifest = {
        "version": 1,
        "created": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "malicious": samples,
        # Known-clean software, fetched from each project's official release.
        # Every file inside each archive counts as clean.
        "clean_sources": [
            {
                "name": "python-3.12.7-embed-amd64",
                "url": "https://www.python.org/ftp/python/3.12.7/python-3.12.7-embed-amd64.zip",
            },
            {
                "name": "MinGit-2.47.0-64-bit",
                "url": "https://github.com/git-for-windows/git/releases/download/v2.47.0.windows.1/MinGit-2.47.0-64-bit.zip",
            },
            {
                "name": "putty-0.81-w64",
                "url": "https://the.earth.li/~sgtatham/putty/0.81/w64/putty.zip",
            },
            {
                "name": "notepad++-8.7-portable-x64",
                "url": "https://github.com/notepad-plus-plus/notepad-plus-plus/releases/download/v8.7/npp.8.7.portable.x64.zip",
            },
        ],
    }
    json.dump(manifest, sys.stdout, indent=2)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
