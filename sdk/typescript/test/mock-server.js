// A stand-in for the Verdyx API, used by the SDK tests, the Python tests and
// the GitHub Action's CI. It answers the routes the clients call, with the
// same JSON shapes as backend/api-gateway.
//
// Verdicts are decided by content: a body containing "EICAR" or a URL
// containing "malware" is malicious, "phish" is suspicious, anything else is
// clean. A scan reports "analyzing" on its first poll and "completed" after.
//
//   node test/mock-server.js [port]     prints "listening <port>" when ready
//
// Env: MOCK_API_KEY  when set, requests without this X-API-Key get 401.

import { createServer } from "node:http";
import { createHash, randomUUID } from "node:crypto";
import { pathToFileURL } from "node:url";

export function startMockServer({ port = 0, apiKey = process.env.MOCK_API_KEY, rateLimitFirst = false } = {}) {
  const scans = new Map();
  const log = [];
  let limited = !rateLimitFirst;

  const server = createServer(async (req, res) => {
    const chunks = [];
    for await (const c of req) chunks.push(c);
    const body = Buffer.concat(chunks);
    const url = new URL(req.url, "http://x");
    log.push({ method: req.method, path: url.pathname, headers: req.headers, body });

    const send = (status, data, headers = {}) => {
      res.writeHead(status, { "Content-Type": "application/json", ...headers });
      res.end(JSON.stringify(data));
    };

    if (apiKey && req.headers["x-api-key"] !== apiKey) {
      return send(401, { error: "unauthorized", message: "invalid API key" });
    }

    const p = url.pathname.replace(/^\/api\/v1/, "");

    if (req.method === "GET" && p === "/engines") {
      return send(200, [
        { name: "YARA Engine", status: "online", isActive: true },
        { name: "ClamAV Scanner", status: "online", isActive: true },
        { name: "Windows Program Model (EMBER2024)", status: "disabled", isActive: false },
      ]);
    }

    if (req.method === "POST" && p === "/submissions/file") {
      if (!limited) {
        limited = true;
        return send(429, { message: "slow down" }, { "Retry-After": "1" });
      }
      const ctype = req.headers["content-type"] ?? "";
      if (!ctype.startsWith("multipart/form-data")) return send(400, { message: "expected multipart" });
      const form = parseMultipart(body, ctype);
      const id = randomUUID();
      const file = form.file;
      const target = file ? file.filename : form.url;
      if (!target) return send(400, { message: "file or url required" });
      const content = file ? file.data.toString("latin1") : form.url;
      const verdict = /EICAR/.test(content) ? "malicious" : /phish/i.test(content) ? "suspicious" : /malware/i.test(content) ? "malicious" : "clean";
      const hash = createHash("sha256").update(file ? file.data : Buffer.from(form.url)).digest("hex");
      scans.set(id, { id, target, isUrl: !file, verdict, hash, polls: 0, fail: /fail-me/.test(content), form });
      return send(200, {
        id,
        submitter_id: "00000000-0000-0000-0000-000000000000",
        original_filename: target,
        file_hash: hash,
        file_size: file ? file.data.length : form.url.length,
        submission_type: file ? "file" : "url",
        analysis_status: "pending",
        description: form.description ?? null,
        organization_id: form.organizationId ?? null,
        created_at: new Date().toISOString(),
      });
    }

    const sim = p.match(/^\/submissions\/([^/]+)\/similar$/);
    if (req.method === "GET" && sim) {
      const scan = scans.get(sim[1]);
      if (!scan) return send(404, { message: "not found" });
      if (scan.isUrl) return send(200, { submissionId: scan.id, status: "not_a_file", hashes: null, similar: [], compared: 0 });
      // Every other file scan counts as similar, so tests can check the shape.
      const similar = [...scans.values()]
        .filter((s) => s.id !== scan.id && !s.isUrl)
        .map((s) => ({
          submissionId: s.id,
          sha256: s.hash,
          filename: s.target,
          fileSize: null,
          createdAt: new Date().toISOString(),
          verdict: s.verdict,
          reportUrl: `https://verdyx.dev/analysis/${s.id}`,
          match: s.hash === scan.hash
            ? { closeness: "identical", tlshDistance: 0, ssdeepScore: 100, sameImphash: false }
            : { closeness: "similar", tlshDistance: 42, ssdeepScore: 61, sameImphash: true },
        }));
      return send(200, {
        submissionId: scan.id,
        status: "ready",
        hashes: { tlsh: "T1" + "A".repeat(70), ssdeep: "3:abc:def", imphash: null },
        similar,
        compared: similar.length,
      });
    }

    const m = p.match(/^\/submissions\/([^/]+)(\/consensus|\/analyses)?$/);
    if (req.method === "GET" && m) {
      const scan = scans.get(m[1]);
      if (!scan) return send(404, { message: "not found" });
      if (!m[2]) {
        scan.polls++;
        const status = scan.polls < 2 ? "analyzing" : scan.fail ? "failed" : "completed";
        return send(200, {
          id: scan.id,
          originalFilename: scan.isUrl ? scan.target : scan.target,
          url: scan.isUrl ? scan.target : null,
          fileHash: scan.hash,
          submissionType: scan.isUrl ? "url" : "file",
          analysisStatus: status,
          status,
          failureReason: status === "failed" ? "the sample could not be fetched" : undefined,
        });
      }
      const flagged = scan.verdict !== "clean";
      if (m[2] === "/consensus") {
        return send(200, {
          submissionId: scan.id,
          finalVerdict: scan.verdict === "clean" ? "clean" : scan.verdict,
          explanation: flagged ? "1 of 2 voting engines flagged it." : "None of 2 voting engines flagged it.",
          maliciousVotes: scan.verdict === "malicious" ? 1 : 0,
          suspiciousVotes: scan.verdict === "suspicious" ? 1 : 0,
          cleanVotes: flagged ? 1 : 2,
          totalVotes: 2,
          flaggedVotes: flagged ? 1 : 0,
          engineCount: 3,
          agreementScore: flagged ? 0.5 : 1,
          unavailableEngines: [],
        });
      }
      return send(200, [
        { id: randomUUID(), engine: { name: "YARA", type: "yara" }, verdict: flagged ? scan.verdict : "benign", confidence: 90, vote: "counted", reason: null },
        { id: randomUUID(), engine: { name: "Heuristic Engine", type: "heuristic" }, verdict: "benign", confidence: 60, vote: "counted", reason: null },
        // Like the live API: an engine that ran without voting says "unknown".
        { id: randomUUID(), engine: { name: "MalwareBazaar", type: "hash" }, verdict: "unknown", confidence: null, reason: "Not in MalwareBazaar's known-malware database" },
        { id: randomUUID(), engine: { name: "Verdyx PE Model", type: "ml" }, verdict: "clean", confidence: 36, reason: null, metadata: { probability: 0.6421 } },
      ]);
    }

    send(404, { message: `no mock for ${req.method} ${url.pathname}` });
  });

  return new Promise((resolve) => {
    server.listen(port, "127.0.0.1", () => {
      const { port: actual } = server.address();
      resolve({
        url: `http://127.0.0.1:${actual}`,
        port: actual,
        log,
        scans,
        close: () => new Promise((r) => server.close(r)),
      });
    });
  });
}

/** Just enough multipart/form-data parsing for the mock. */
function parseMultipart(body, ctype) {
  const boundary = ctype.match(/boundary=(?:"([^"]+)"|([^;]+))/i);
  const b = `--${boundary[1] ?? boundary[2]}`;
  const out = {};
  const text = body.toString("latin1");
  for (const part of text.split(b).slice(1, -1)) {
    const sep = part.indexOf("\r\n\r\n");
    const head = part.slice(0, sep);
    const data = Buffer.from(part.slice(sep + 4, part.length - 2), "latin1");
    const name = head.match(/name="([^"]*)"/)?.[1];
    const filename = head.match(/filename="([^"]*)"/)?.[1];
    if (filename !== undefined) out[name] = { filename, data };
    else out[name] = data.toString("utf8");
  }
  return out;
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  const srv = await startMockServer({ port: Number(process.argv[2] ?? 8787) });
  console.log(`listening ${srv.port}`);
}
