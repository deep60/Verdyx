#!/usr/bin/env python3
"""Describe the benchmark's malicious scripts, without copying them anywhere.

Runs on the server, inside a container with no network (describe_on_server.sh),
and prints a short text profile of each script: its encoding, line shape,
character mix, most common words, how often common obfuscation markers occur,
and short excerpts with control bytes escaped. That is enough to see how a
script hides itself and write a detection for it; the files never leave the
server and are only read.

    python3 describe_scripts.py /bench/manifest.json /bench/samples/malicious [sha256-prefix ...]
"""

import collections
import json
import re
import sys

MARKERS = [
    "+", "&", "`", "^", "%", "chr(", "chrw(", "[char]", "replace", "split", "join",
    "reverse", "invoke", "iex", "frombase64", "-bxor", "substring", "mid(", "execute",
    "eval(", "createobject", "activexobject", "wscript", "powershell", "shell.application",
    "set ", "goto", "call ", "for /", "certutil", "http", "\\u00", "\\x",
]
WORD = re.compile(r"[A-Za-z_][A-Za-z0-9_\-.]{2,40}")
BASE64 = re.compile(r"[A-Za-z0-9+/]{64,}={0,2}")


def decode(data: bytes) -> tuple[str, str]:
    if data.startswith(b"\xff\xfe"):
        return "utf-16le (BOM)", data[2:].decode("utf-16le", "replace")
    if data.startswith(b"\xfe\xff"):
        return "utf-16be (BOM)", data[2:].decode("utf-16be", "replace")
    if data.startswith(b"\xef\xbb\xbf"):
        return "utf-8 (BOM)", data[3:].decode("utf-8", "replace")
    head = data[:4096]
    odd_zero = sum(1 for b in head[1::2] if b == 0)
    even_zero = sum(1 for b in head[0::2] if b == 0)
    half = max(1, len(head) // 2)
    if odd_zero > half * 0.8:
        return "utf-16le (no BOM)", data.decode("utf-16le", "replace")
    if even_zero > half * 0.8:
        return "utf-16be (no BOM)", data.decode("utf-16be", "replace")
    try:
        return "utf-8", data.decode("utf-8")
    except UnicodeDecodeError:
        return "binary or legacy codepage", data.decode("latin-1")


def excerpt(text: str, start: int, n: int) -> str:
    out = []
    for c in text[start:start + n]:
        if c == "\n":
            out.append("⏎")
        elif c == "\r":
            continue
        elif c == "\t" or c.isprintable():
            out.append(c)
        else:
            out.append(f"\\x{ord(c):02x}" if ord(c) < 256 else f"\\u{ord(c):04x}")
    return "".join(out)


def longest_run(text: str, ok) -> int:
    best = run = 0
    for c in text:
        run = run + 1 if ok(c) else 0
        best = max(best, run)
    return best


def describe(sha: str, entry: dict, data: bytes) -> str:
    encoding, text = decode(data)
    lines = text.splitlines() or [""]
    n = max(1, len(text))
    letters = sum(c.isalpha() for c in text)
    digits = sum(c.isdigit() for c in text)
    space = sum(c.isspace() for c in text)
    non_ascii = sum(ord(c) > 127 for c in text)
    punct = n - letters - digits - space
    low = text.lower()
    words = collections.Counter(WORD.findall(text))
    b64 = [len(m.group()) for m in BASE64.finditer(text)]
    out = [
        f"== {sha[:12]}  {entry.get('family')}  .{entry.get('file_type')}  {len(data):,} bytes",
        f"encoding: {encoding}; lines {len(lines):,}; longest line {max(map(len, lines)):,}; "
        f"median line {sorted(map(len, lines))[len(lines) // 2]:,}",
        f"chars: letters {letters * 100 // n}%, digits {digits * 100 // n}%, space {space * 100 // n}%, "
        f"punctuation {punct * 100 // n}%, non-ASCII {non_ascii * 100 // n}%",
        f"base64 runs (64+): {len(b64)}, longest {max(b64, default=0):,}; "
        f"longest letter/digit run {longest_run(text, str.isalnum):,}",
        "markers: " + ", ".join(f"{m!r} {low.count(m):,}" for m in MARKERS if low.count(m)),
        "top words: " + ", ".join(f"{w} {c:,}" for w, c in words.most_common(20)),
        f"distinct words: {len(words):,}",
        f"start:  {excerpt(text, 0, 400)}",
        f"middle: {excerpt(text, len(text) // 2, 300)}",
        f"end:    {excerpt(text, max(0, len(text) - 400), 400)}",
    ]
    return "\n".join(out)


def main() -> None:
    manifest, folder, *only = sys.argv[1:]
    entries = json.load(open(manifest))["malicious"]
    for e in entries:
        if e.get("category") != "script":
            continue
        sha = e["sha256"]
        if only and not any(sha.startswith(p) for p in only):
            continue
        try:
            data = open(f"{folder}/{sha}", "rb").read()
        except OSError as err:
            print(f"== {sha[:12]}  missing: {err}\n")
            continue
        print(describe(sha, e, data))
        print()


if __name__ == "__main__":
    main()
