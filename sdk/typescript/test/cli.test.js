import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { startMockServer } from "./mock-server.js";

const BIN = fileURLToPath(new URL("../bin/verdyx.js", import.meta.url));
const KEY = "vdx_" + "1".repeat(64);
const EICAR = "stand-in sample: the mock API treats any upload containing EICAR as malicious";

let srv;
let dir;

before(async () => {
  srv = await startMockServer({ apiKey: KEY });
  dir = await mkdtemp(join(tmpdir(), "verdyx-cli-"));
  await writeFile(join(dir, "eicar.com"), EICAR);
  await writeFile(join(dir, "clean.txt"), "hello");
});
after(() => srv.close());

function run(args, env = {}) {
  return new Promise((resolve) => {
    execFile(
      process.execPath,
      [BIN, ...args],
      {
        env: { PATH: process.env.PATH, VERDYX_API_URL: srv.url, VERDYX_API_KEY: KEY, VERDYX_POLL_INTERVAL: "0.02", NO_COLOR: "1", ...env },
      },
      (err, stdout, stderr) => resolve({ code: err ? err.code : 0, stdout, stderr }),
    );
  });
}

test("a clean file exits 0", async () => {
  const r = await run(["scan", join(dir, "clean.txt")]);
  assert.equal(r.code, 0, r.stderr);
  assert.match(r.stdout, /^CLEAN\s+\S*clean\.txt\s+0\/2 voting engines flagged it\s+https:\/\/verdyx\.dev\/analysis\//m);
  assert.ok(r.stdout.includes(join(dir, "clean.txt")), "shows the path as typed");
});

test("a malicious file exits 2 by default", async () => {
  const r = await run(["scan", join(dir, "eicar.com"), join(dir, "clean.txt")]);
  assert.equal(r.code, 2);
  assert.match(r.stdout, /^MALICIOUS\s+\S*eicar\.com\s+1\/2/m);
  assert.match(r.stdout, /^CLEAN\s+\S*clean\.txt/m);
  assert.match(r.stderr, /1 of 2 reached --fail-on malicious/);
});

test("--fail-on never always exits 0; suspicious catches suspicious", async () => {
  assert.equal((await run(["scan", "--fail-on", "never", join(dir, "eicar.com")])).code, 0);
  assert.equal((await run(["scan", "https://phish.test/"])).code, 0);
  assert.equal((await run(["scan", "--fail-on", "suspicious", "https://phish.test/"])).code, 2);
});

test("--json prints machine-readable results", async () => {
  const r = await run(["scan", "--json", "--fail-on", "never", join(dir, "eicar.com"), "https://example.com/"]);
  assert.equal(r.code, 0, r.stderr);
  const out = JSON.parse(r.stdout);
  assert.deepEqual(out.results.map((x) => x.verdict), ["malicious", "clean"]);
  assert.equal(out.results[0].submission, undefined, "raw objects are left out");
  assert.deepEqual(out.errors, []);
});

test("--output writes JSON while the table still prints", async () => {
  const out = join(dir, "results.json");
  const r = await run(["scan", "--output", out, join(dir, "eicar.com")]);
  assert.equal(r.code, 2);
  assert.match(r.stdout, /^MALICIOUS/m);
  const data = JSON.parse(await readFile(out, "utf8"));
  assert.equal(data.failOn, "malicious");
  assert.equal(data.results[0].verdict, "malicious");
  assert.equal(data.results[0].target, join(dir, "eicar.com"));
});

test("--verbose lists each engine", async () => {
  const r = await run(["scan", "-v", "https://example.com/"]);
  assert.match(r.stdout, /· MalwareBazaar: no vote — Not in MalwareBazaar/);
  assert.match(r.stdout, /· Heuristic Engine: clean \(60%\)/);
  assert.match(r.stdout, /· Verdyx PE Model: clean \(64% malware chance\)/);
});

test("--summary appends a Markdown table", async () => {
  const summary = join(dir, "summary.md");
  await run(["scan", "--summary", summary, join(dir, "eicar.com")]);
  const md = await readFile(summary, "utf8");
  assert.match(md, /### Verdyx scan/);
  assert.match(md, /\| 🔴 malicious \| `[^`]*eicar\.com` \| 1\/2 voting engines flagged it \| \[open\]\(https:\/\/verdyx\.dev\/analysis\/[0-9a-f-]+\) \|/);
});

test("--no-wait prints ids, and result fetches them later", async () => {
  const r = await run(["scan", "--no-wait", "https://example.com/"]);
  assert.equal(r.code, 0);
  const id = r.stdout.trim().split(/\s+/)[0];
  const later = await run(["result", id]);
  assert.equal(later.code, 0, later.stderr);
  assert.match(later.stdout, /^CLEAN\s+https:\/\/example\.com\//m);
});

test("a failed scan exits 1", async () => {
  const r = await run(["scan", "https://fail-me.test/"]);
  assert.equal(r.code, 1);
  assert.match(r.stdout, /^FAILED\s+.*scan failed: the sample could not be fetched/m);
});

test("errors are short and exit 1", async () => {
  const badKey = await run(["engines"], { VERDYX_API_KEY: "vdx_bad" });
  assert.equal(badKey.code, 1);
  assert.equal(badKey.stderr.trim(), "verdyx: HTTP 401: invalid API key");

  const missing = await run(["scan", join(dir, "nope.bin")]);
  assert.equal(missing.code, 1);
  assert.equal(missing.stderr.trim(), `verdyx: ${join(dir, "nope.bin")}: file not found`);

  assert.match((await run(["scan", "--fail-on", "high", "x"])).stderr, /--fail-on must be/);
  assert.match((await run(["scan"])).stderr, /at least one file or URL/);
  assert.match((await run(["frobnicate"])).stderr, /unknown command/);
});

test("engines, --help and --version", async () => {
  const e = await run(["engines"]);
  assert.match(e.stdout, /ClamAV Scanner\s+online/);
  assert.match((await run(["--help"])).stdout, /Exit codes: 0 ok/);
  assert.match((await run(["--version"])).stdout, /^\d+\.\d+\.\d+\n$/);
});
