import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdir, mkdtemp, realpath, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { startMockServer } from "./mock-server.js";
import { allowedRoots, checkPath } from "../src/mcp.js";

const BIN = fileURLToPath(new URL("../bin/verdyx.js", import.meta.url));
const KEY = "vdx_" + "3".repeat(64);

let srv;
let base; // contains root/ (allowed) and outside/ (not)
let root;
let proc;
let nextId = 1;
const waiting = new Map();
let stderr = "";

before(async () => {
  srv = await startMockServer({ apiKey: KEY });
  base = await realpath(await mkdtemp(join(tmpdir(), "verdyx-mcp-")));
  root = join(base, "root");
  await mkdir(join(root, "downloads"), { recursive: true });
  await mkdir(join(root, ".ssh"));
  await mkdir(join(base, "outside"));
  await writeFile(join(root, "downloads", "invoice.exe"), "stand-in with EICAR marker");
  await writeFile(join(root, "notes.txt"), "hello");
  await writeFile(join(root, ".env"), "TOKEN=x");
  await writeFile(join(root, ".ssh", "id_ed25519"), "private");
  await writeFile(join(base, "outside", "secret.txt"), "private");
  await symlink(join(base, "outside", "secret.txt"), join(root, "link.txt"));

  proc = spawn(process.execPath, [BIN, "mcp"], {
    cwd: root,
    env: { PATH: process.env.PATH, VERDYX_API_URL: srv.url, VERDYX_API_KEY: KEY, HOME: base },
    stdio: ["pipe", "pipe", "pipe"],
  });
  proc.stderr.on("data", (d) => (stderr += d));
  let buf = "";
  proc.stdout.on("data", (d) => {
    buf += d;
    let nl;
    while ((nl = buf.indexOf("\n")) !== -1) {
      const msg = JSON.parse(buf.slice(0, nl));
      buf = buf.slice(nl + 1);
      waiting.get(msg.id)?.(msg);
      waiting.delete(msg.id);
    }
  });
});

after(async () => {
  proc.stdin.end();
  await new Promise((r) => proc.on("exit", r));
  await srv.close();
});

function rpc(method, params, id = nextId++) {
  return new Promise((resolve) => {
    waiting.set(id, resolve);
    proc.stdin.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
  });
}
const call = (name, args) => rpc("tools/call", { name, arguments: args }).then((m) => m.result);

test("initialize negotiates the protocol and advertises tools", async () => {
  const r = await rpc("initialize", {
    protocolVersion: "2025-06-18",
    capabilities: {},
    clientInfo: { name: "test", version: "1" },
  });
  assert.equal(r.result.protocolVersion, "2025-06-18");
  assert.deepEqual(r.result.capabilities, { tools: { listChanged: false } });
  assert.equal(r.result.serverInfo.name, "verdyx");
  assert.match(r.result.serverInfo.version, /^\d+\.\d+\.\d+$/);
  proc.stdin.write(JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }) + "\n");

  const old = await rpc("initialize", { protocolVersion: "2024-11-05", capabilities: {} });
  assert.equal(old.result.protocolVersion, "2024-11-05");
  const unknown = await rpc("initialize", { protocolVersion: "1999-01-01", capabilities: {} });
  assert.equal(unknown.result.protocolVersion, "2025-06-18");
});

test("tools/list", async () => {
  const r = await rpc("tools/list", {});
  assert.deepEqual(r.result.tools.map((t) => t.name), ["scan_url", "scan_file", "get_scan_result", "find_similar_files", "list_engines"]);
  for (const t of r.result.tools) {
    assert.equal(t.inputSchema.type, "object");
    assert.ok(t.description.length > 20);
  }
});

test("scan_url returns a readable verdict and structured data", async () => {
  const r = await call("scan_url", { url: "https://phish.test/login" });
  assert.equal(r.isError, undefined);
  const text = r.content[0].text;
  assert.match(text, /^Verdict: SUSPICIOUS$/m);
  assert.match(text, /1 of 2 voting engines flagged it \(0 malicious, 1 suspicious\)/);
  assert.match(text, /- MalwareBazaar: Not in MalwareBazaar/);
  assert.match(text, /^Report: https:\/\/verdyx\.dev\/analysis\//m);
  assert.equal(r.structuredContent.verdict, "suspicious");
  assert.equal(r.structuredContent.submission, undefined);
});

test("scan_url with wait_seconds 0 returns the id to check later", async () => {
  const r = await call("scan_url", { url: "https://example.com/", wait_seconds: 0 });
  assert.match(r.content[0].text, /Still analyzing\. Call get_scan_result with scan_id "([0-9a-f-]+)"/);
  const id = r.structuredContent.id;
  const later = await call("get_scan_result", { scan_id: id });
  assert.equal(later.structuredContent.status, "completed");
  assert.match(later.content[0].text, /^Verdict: CLEAN$/m);
});

test("scan_file reads files inside the allowed folder", async () => {
  const rel = await call("scan_file", { path: "downloads/invoice.exe" });
  assert.match(rel.content[0].text, /^Verdict: MALICIOUS$/m);
  const abs = await call("scan_file", { path: join(root, "notes.txt") });
  assert.match(abs.content[0].text, /^Verdict: CLEAN$/m);
  assert.match(stderr, /uploading .*invoice\.exe/);
});

test("scan_file refuses anything outside the allowed folder", async () => {
  const uploadsBefore = srv.log.filter((l) => l.method === "POST").length;
  const cases = [
    [join(base, "outside", "secret.txt"), /outside the allowed folders/],
    ["../outside/secret.txt", /outside the allowed folders/],
    ["link.txt", /outside the allowed folders/], // symlink pointing out
    [".env", /hidden file/],
    [".ssh/id_ed25519", /hidden file/],
    ["downloads", /not a file/],
    ["missing.bin", /file not found/],
    ["", /path is required/],
  ];
  for (const [path, why] of cases) {
    const r = await call("scan_file", { path });
    assert.equal(r.isError, true, path);
    assert.match(r.content[0].text, why, path);
  }
  assert.equal(srv.log.filter((l) => l.method === "POST").length, uploadsBefore, "nothing was uploaded");
});

test("find_similar_files", async () => {
  const scan = await call("scan_url", { url: "https://example.com/", wait_seconds: 5 });
  const id = scan.structuredContent.id;
  const r = await call("find_similar_files", { scan_id: id });
  assert.equal(r.isError, undefined);
  assert.match(r.content[0].text, /not a file/);
  const missing = await call("find_similar_files", {});
  assert.equal(missing.isError, true);
});

test("list_engines", async () => {
  const r = await call("list_engines", {});
  assert.match(r.content[0].text, /- ClamAV Scanner: online/);
  assert.equal(r.structuredContent.engines.length, 3);
});

test("API errors come back as tool errors the model can read", async () => {
  const r = await call("get_scan_result", { scan_id: "nope" });
  assert.equal(r.isError, true);
  assert.match(r.content[0].text, /^Error: HTTP 404/);
  const bad = await call("scan_url", { url: "file:///etc/passwd" });
  assert.equal(bad.isError, true);
  assert.match(bad.content[0].text, /not an http/);
});

test("protocol errors", async () => {
  assert.equal((await rpc("tools/call", { name: "rm_rf", arguments: {} })).error.code, -32602);
  assert.equal((await rpc("resources/list", {})).error.code, -32601);
  assert.deepEqual((await rpc("ping", {})).result, {});
});

test("allowedRoots: VERDYX_MCP_ROOTS, and never / or home by default", async () => {
  assert.deepEqual(await allowedRoots({ VERDYX_MCP_ROOTS: `${root}:${join(base, "outside")}` }, "/"), [
    root,
    join(base, "outside"),
  ]);
  assert.deepEqual(await allowedRoots({}, root, base), [root]);
  assert.deepEqual(await allowedRoots({}, "/", base), []);
  assert.deepEqual(await allowedRoots({}, base, base), [], "home is not a default root");
  await assert.rejects(checkPath("notes.txt", []), /set VERDYX_MCP_ROOTS/);
});
