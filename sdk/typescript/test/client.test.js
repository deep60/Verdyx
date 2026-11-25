import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { startMockServer } from "./mock-server.js";
import { Verdyx, VerdyxError, ScanTimeoutError, meetsThreshold } from "../src/index.js";

const KEY = "vdx_" + "0".repeat(64);
const EICAR = "stand-in sample: the mock API treats any upload containing EICAR as malicious";
const fast = { pollIntervalSeconds: 0.02, timeoutSeconds: 5 };

let srv;
let dir;
let client;

before(async () => {
  srv = await startMockServer({ apiKey: KEY });
  dir = await mkdtemp(join(tmpdir(), "verdyx-sdk-"));
  client = new Verdyx({ apiKey: KEY, apiUrl: srv.url + "/", webUrl: "https://verdyx.dev" });
});
after(() => srv.close());

test("scans a file by path and returns the verdict", async () => {
  const path = join(dir, "eicar.com");
  await writeFile(path, EICAR);
  const r = await client.scan(path, fast);
  assert.equal(r.status, "completed");
  assert.equal(r.verdict, "malicious");
  assert.equal(r.target, "eicar.com");
  assert.match(r.sha256, /^[0-9a-f]{64}$/);
  assert.deepEqual(r.votes, { malicious: 1, suspicious: 0, clean: 1, total: 2 });
  assert.equal(r.reportUrl, `https://verdyx.dev/analysis/${r.id}`);
  assert.equal(r.engines.length, 3);
  assert.equal(r.engines[1].verdict, "clean", "benign is reported as clean");
  assert.equal(r.engines[2].vote, "no_record");

  const upload = srv.log.find((l) => l.method === "POST");
  assert.equal(upload.path, "/api/v1/submissions/file");
  assert.equal(upload.headers["x-api-key"], KEY);
  assert.match(upload.headers["user-agent"], /^verdyx-js\//);
});

test("scans a URL", async () => {
  const r = await client.scan("https://example.com/", fast);
  assert.equal(r.verdict, "clean");
  assert.equal(r.target, "https://example.com/");
  const s = await client.scan("https://login.phish.test/verify", fast);
  assert.equal(s.verdict, "suspicious");
});

test("submits bytes with a filename and the optional fields", async () => {
  const sub = await client.submitFile(new TextEncoder().encode("hello"), {
    filename: "hello.txt",
    description: "from a test",
    teamId: "team-1",
    priority: true,
  });
  assert.equal(sub.status, "pending");
  assert.equal(sub.filename, "hello.txt");
  const form = srv.scans.get(sub.id).form;
  assert.equal(form.description, "from a test");
  assert.equal(form.organizationId, "team-1");
  assert.equal(form.priority, "true");
});

test("reports a failed scan without a verdict", async () => {
  const r = await client.scan("https://fail-me.test/", fast);
  assert.equal(r.status, "failed");
  assert.equal(r.verdict, "unknown");
  assert.equal(r.failureReason, "the sample could not be fetched");
  assert.deepEqual(r.engines, []);
});

test("times out with ScanTimeoutError", async () => {
  const sub = await client.submitUrl("https://slow.test/");
  // The first poll always says "analyzing"; a tiny timeout gives up after it.
  await assert.rejects(client.waitForResult(sub.id, { timeoutSeconds: 0.01, pollIntervalSeconds: 1 }), ScanTimeoutError);
});

test("reports status changes while waiting", async () => {
  const sub = await client.submitUrl("https://example.org/");
  const seen = [];
  await client.waitForResult(sub.id, { ...fast, onStatus: (s) => seen.push(s) });
  assert.deepEqual(seen, ["analyzing", "completed"]);
});

test("a bad API key is a 401 VerdyxError with a clear message", async () => {
  const bad = new Verdyx({ apiKey: "vdx_wrong", apiUrl: srv.url });
  const err = await bad.listEngines().catch((e) => e);
  assert.ok(err instanceof VerdyxError);
  assert.equal(err.status, 401);
  assert.equal(err.message, "HTTP 401: invalid API key");
});

test("an unknown scan is a 404", async () => {
  const err = await client.getSubmission("does-not-exist").catch((e) => e);
  assert.equal(err.status, 404);
});

test("rejects an empty file and a non-http URL before sending", async () => {
  await assert.rejects(client.submitFile(new Uint8Array()), /empty/);
  await assert.rejects(client.submitUrl("ftp://example.com"), /not an http/);
});

test("an upload that's rate limited isn't retried, so it can't create two scans", async () => {
  const limited = await startMockServer({ rateLimitFirst: true });
  try {
    const c = new Verdyx({ apiUrl: limited.url });
    await assert.rejects(c.submitUrl("https://example.com/"), (e) => e.status === 429 && e.retryAfter === 1);
    assert.equal(limited.scans.size, 0);
    const sub = await c.submitUrl("https://example.com/");
    assert.ok(limited.scans.has(sub.id));
  } finally {
    await limited.close();
  }
});

test("reads are retried on 429 and 5xx, honouring Retry-After", async () => {
  const replies = [
    new Response("", { status: 503 }),
    new Response(JSON.stringify({ message: "slow down" }), { status: 429, headers: { "Retry-After": "1" } }),
    new Response(JSON.stringify([{ name: "YARA Engine", status: "online" }]), { status: 200 }),
  ];
  let calls = 0;
  const c = new Verdyx({ apiUrl: "http://unused", fetch: async () => replies[calls++] });
  const t0 = Date.now();
  const engines = await c.listEngines();
  assert.equal(calls, 3);
  assert.equal(engines[0].name, "YARA Engine");
  assert.ok(Date.now() - t0 >= 1000, "waited for Retry-After");
});

test("gives up after maxRetries", async () => {
  let calls = 0;
  const c = new Verdyx({ apiUrl: "http://unused", maxRetries: 1, fetch: async () => (calls++, new Response("", { status: 502 })) });
  const err = await c.listEngines().catch((e) => e);
  assert.equal(err.status, 502);
  assert.equal(calls, 2);
});

test("lists engines", async () => {
  const engines = await client.listEngines();
  assert.equal(engines.length, 3);
  assert.equal(engines[2].status, "disabled");
});

test("meetsThreshold", () => {
  assert.equal(meetsThreshold("malicious", "malicious"), true);
  assert.equal(meetsThreshold("suspicious", "malicious"), false);
  assert.equal(meetsThreshold("suspicious", "suspicious"), true);
  assert.equal(meetsThreshold("malicious", "suspicious"), true);
  assert.equal(meetsThreshold("clean", "suspicious"), false);
  assert.equal(meetsThreshold("unknown", "suspicious"), false);
  assert.equal(meetsThreshold("malicious", "never"), false);
  assert.throws(() => meetsThreshold("malicious", "high"), VerdyxError);
});
