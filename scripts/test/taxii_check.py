#!/usr/bin/env python3
"""Check the Verdyx TAXII 2.1 feed with a real TAXII client.

Uses the OASIS `taxii2-client` and validates every object with `stix2`
(strict: unknown properties and bad patterns fail).

    pip install taxii2-client stix2
    VERDYX_FEED_KEY=vdx_... python3 scripts/test/taxii_check.py https://api.verdyx.dev

Optional: VERDYX_EXPECT_SCANS="id1,id2" lists scan ids that must appear in
"My scans"; VERDYX_ABSENT_SCANS lists ids that must not. Exit code 0 on success.
"""
import os
import sys

import stix2
from taxii2client.v21 import Server, as_pages


def fail(msg):
    print(f"  ✗ {msg}")
    sys.exit(1)


def ok(msg):
    print(f"  ✓ {msg}")


def scan_ids(objects):
    out = set()
    for o in objects:
        for ref in o.get("external_references", []):
            if ref.get("source_name") == "Verdyx":
                out.add(ref.get("external_id"))
    return out


def main():
    base = (sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8080").rstrip("/")
    key = os.environ["VERDYX_FEED_KEY"]
    expect = {s for s in os.environ.get("VERDYX_EXPECT_SCANS", "").split(",") if s}
    absent = {s for s in os.environ.get("VERDYX_ABSENT_SCANS", "").split(",") if s}

    server = Server(f"{base}/taxii2/", user="taxii", password=key)
    if server.title != "Verdyx threat feed":
        fail(f"discovery title: {server.title!r}")
    root = server.api_roots[0]
    cols = {c.title: c for c in root.collections}
    ok(f"discovery, API root and collections: {sorted(cols)}")
    mine = cols.get("My scans")
    if mine is None or not mine.can_read or mine.can_write:
        fail("no readable 'My scans' collection")

    envelope = mine.get_objects()
    objects = envelope.get("objects", [])
    for o in objects:
        stix2.parse(o, allow_custom=False)
    indicators = [o for o in objects if o["type"] == "indicator"]
    ok(f"{len(objects)} objects, all valid STIX 2.1 ({len(indicators)} indicators)")

    seen = scan_ids(indicators)
    if expect - seen:
        fail(f"missing scans: {expect - seen}")
    if absent & seen:
        fail(f"scans that shouldn't be in the feed: {absent & seen}")
    if expect:
        ok("the expected scans are in the feed, and no others")

    paged = []
    for page in as_pages(mine.get_objects, per_request=1):
        paged.extend(page.get("objects", []))
    if {o["id"] for o in paged} != {o["id"] for o in objects}:
        fail("paging one at a time gives different objects")
    ok(f"paging with limit=1 returns the same {len(paged)} objects")

    later = mine.get_objects(added_after="2999-01-01T00:00:00Z").get("objects", [])
    if later:
        fail("added_after in the future should return nothing")
    only = mine.get_objects(type="indicator").get("objects", [])
    if any(o["type"] != "indicator" for o in only):
        fail("match[type]=indicator returned other types")
    ok("added_after and match[type] filter")

    manifest = mine.get_manifest().get("objects", [])
    if {m["id"] for m in manifest} != {o["id"] for o in objects}:
        fail("manifest doesn't list the same objects")
    if any(m.get("media_type") != "application/stix+json;version=2.1" for m in manifest):
        fail("manifest media types")
    ok("manifest lists every object")

    again = mine.get_objects().get("objects", [])
    if sorted(o["id"] for o in again) != sorted(o["id"] for o in objects):
        fail("ids change between polls")
    ok("ids are stable between polls")
    print("TAXII client checks passed.")


if __name__ == "__main__":
    main()
