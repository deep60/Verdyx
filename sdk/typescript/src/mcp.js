// A Model Context Protocol server, so AI assistants and agents can scan with
// Verdyx. It speaks MCP over stdio (newline-delimited JSON-RPC 2.0) and needs
// no MCP library. Run it with `verdyx mcp`.
//
// File access is the risky part: an assistant that has read a malicious page
// could be talked into "scanning" ~/.ssh/id_ed25519, which would upload it.
// So scan_file only reads files under the allowed folders (VERDYX_MCP_ROOTS,
// default: the folder the server was started in), never follows a symlink out
// of them, and refuses hidden files and folders such as .ssh, .aws or .env.

import { realpath, stat } from "node:fs/promises";
import { homedir } from "node:os";
import { isAbsolute, parse, relative, resolve, sep, delimiter } from "node:path";
import { Verdyx, VerdyxError, ScanTimeoutError } from "./index.js";

export const PROTOCOL_VERSIONS = ["2025-06-18", "2025-03-26", "2024-11-05"];

const MAX_WAIT_SECONDS = 600;

const TOOLS = [
  {
    name: "scan_url",
    title: "Scan a URL",
    description:
      "Scan a web address with Verdyx (threat-intel feeds, reputation, phishing and malware checks) and return the verdict: malicious, suspicious, clean or unknown, with each engine's result and a link to the full report. Use before visiting, recommending or downloading from a link you aren't sure about.",
    inputSchema: {
      type: "object",
      properties: {
        url: { type: "string", description: "An http or https URL." },
        wait_seconds: {
          type: "integer",
          minimum: 0,
          maximum: MAX_WAIT_SECONDS,
          description: "How long to wait for the verdict (default 120). 0 submits and returns the scan id at once.",
        },
      },
      required: ["url"],
      additionalProperties: false,
    },
    annotations: { readOnlyHint: false, openWorldHint: true, idempotentHint: false },
  },
  {
    name: "scan_file",
    title: "Scan a file",
    description:
      "Upload a local file to Verdyx for malware analysis (YARA, ClamAV, static and heuristic engines, known-malware lookups) and return the verdict with each engine's result and a link to the report. The file is uploaded to Verdyx, so only scan files the user wants analysed. Only files inside the allowed folders can be read.",
    inputSchema: {
      type: "object",
      properties: {
        path: { type: "string", description: "Path to the file, absolute or relative to the first allowed folder." },
        wait_seconds: {
          type: "integer",
          minimum: 0,
          maximum: MAX_WAIT_SECONDS,
          description: "How long to wait for the verdict (default 120). 0 submits and returns the scan id at once.",
        },
      },
      required: ["path"],
      additionalProperties: false,
    },
    annotations: { readOnlyHint: false, openWorldHint: true, idempotentHint: false },
  },
  {
    name: "get_scan_result",
    title: "Get a scan's result",
    description: "Get the current status and, once finished, the verdict of an earlier Verdyx scan by its id.",
    inputSchema: {
      type: "object",
      properties: {
        scan_id: { type: "string", description: "The id returned when the scan was submitted." },
        wait_seconds: {
          type: "integer",
          minimum: 0,
          maximum: MAX_WAIT_SECONDS,
          description: "Wait up to this long for an unfinished scan (default 0: return the current state).",
        },
      },
      required: ["scan_id"],
      additionalProperties: false,
    },
    annotations: { readOnlyHint: true, openWorldHint: true, idempotentHint: true },
  },
  {
    name: "list_engines",
    title: "List Verdyx engines",
    description: "List Verdyx's detection engines and whether each is online, so you know what a verdict was based on.",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
    annotations: { readOnlyHint: true, openWorldHint: true, idempotentHint: true },
  },
];

/**
 * Folders scan_file may read from, resolved to real paths.
 *
 * Without VERDYX_MCP_ROOTS it's the folder the server started in, unless that
 * is the filesystem root or the home folder: desktop apps often start servers
 * there, and allowing everything would defeat the point.
 */
export async function allowedRoots(env = process.env, cwd = process.cwd(), home = homedir()) {
  const raw = (env.VERDYX_MCP_ROOTS ?? "").split(delimiter).map((s) => s.trim()).filter(Boolean);
  if (raw.length === 0) {
    const here = await realpath(cwd).catch(() => cwd);
    const homeReal = await realpath(home).catch(() => home);
    if (here === parse(here).root || here === homeReal) return [];
  }
  const roots = [];
  for (const r of raw.length ? raw : [cwd]) {
    try {
      roots.push(await realpath(resolve(cwd, r)));
    } catch {
      // A root that doesn't exist allows nothing.
    }
  }
  return roots;
}

/** Resolve `p` to a real file inside one of `roots`, or throw. */
export async function checkPath(p, roots) {
  if (typeof p !== "string" || !p.trim()) throw new VerdyxError("path is required");
  if (roots.length === 0) {
    throw new VerdyxError(
      "no folders are allowed for scan_file; set VERDYX_MCP_ROOTS to the folders whose files may be uploaded (separated by " +
        `"${delimiter}")`,
    );
  }
  const candidate = isAbsolute(p) ? p : resolve(roots[0], p);
  let real;
  try {
    real = await realpath(candidate);
  } catch {
    throw new VerdyxError(`${p}: file not found`);
  }
  const root = roots.find((r) => real === r || real.startsWith(r.endsWith(sep) ? r : r + sep));
  if (!root) {
    throw new VerdyxError(`${p} is outside the allowed folders (${roots.join(", ")}); set VERDYX_MCP_ROOTS to allow more`);
  }
  if (relative(root, real).split(sep).some((part) => part.startsWith("."))) {
    throw new VerdyxError(`${p} is a hidden file or inside a hidden folder, which may hold keys or settings; it won't be uploaded`);
  }
  const st = await stat(real);
  if (!st.isFile()) throw new VerdyxError(`${p} is not a file`);
  if (st.size > 100 * 1024 * 1024) throw new VerdyxError(`${p} is larger than the 100 MB limit`);
  return real;
}

function summarise(r) {
  const lines = [];
  if (r.status === "failed") {
    lines.push(`Scan failed${r.failureReason ? `: ${r.failureReason}` : ""}.`);
  } else if (r.status !== "completed") {
    lines.push(`Still ${r.status}. Call get_scan_result with scan_id "${r.id}" to check again.`);
  } else {
    lines.push(`Verdict: ${r.verdict.toUpperCase()}`);
    const flagged = r.votes.malicious + r.votes.suspicious;
    lines.push(
      r.votes.total === 0
        ? "No engine voted, so there is no evidence either way."
        : `${flagged} of ${r.votes.total} voting engines flagged it (${r.votes.malicious} malicious, ${r.votes.suspicious} suspicious).`,
    );
    if (r.explanation) lines.push(r.explanation);
    const voted = r.engines.filter((e) => e.verdict);
    const silent = r.engines.filter((e) => !e.verdict);
    if (voted.length) {
      lines.push("", "Engines:");
      for (const e of voted) lines.push(`- ${e.name}: ${e.verdict}${e.confidence != null ? ` (${e.confidence}%)` : ""}`);
    }
    if (silent.length) {
      lines.push("", "Not voting:");
      for (const e of silent) lines.push(`- ${e.name}: ${e.reason ?? e.vote ?? "no result"}`);
    }
  }
  lines.push("", `Target: ${r.target ?? "?"}`);
  if (r.sha256) lines.push(`SHA-256: ${r.sha256}`);
  lines.push(`Scan id: ${r.id}`, `Report: ${r.reportUrl}`);
  return lines.join("\n");
}

function structured(r) {
  const { submission, consensus, ...rest } = r;
  return rest;
}

export class McpServer {
  /**
   * @param {{ client?: Verdyx, roots?: string[], write: (msg: object) => void, log?: (s: string) => void, version?: string }} opts
   */
  constructor({ client, roots, write, log, version = "0.0.0" }) {
    this.client = client ?? new Verdyx();
    this.roots = roots;
    this.write = write;
    this.log = log ?? ((s) => process.stderr.write(`[verdyx-mcp] ${s}\n`));
    this.version = version;
  }

  async handle(msg) {
    if (!msg || typeof msg !== "object" || msg.jsonrpc !== "2.0") {
      return this.write({ jsonrpc: "2.0", id: null, error: { code: -32600, message: "invalid request" } });
    }
    const { id, method, params } = msg;
    const isRequest = id !== undefined && id !== null;
    if (!isRequest) return; // notifications (initialized, cancelled, ...) need no reply
    try {
      const result = await this.dispatch(method, params ?? {});
      this.write({ jsonrpc: "2.0", id, result });
    } catch (e) {
      const code = e?.rpcCode ?? -32603;
      this.write({ jsonrpc: "2.0", id, error: { code, message: e?.message ?? String(e) } });
    }
  }

  async dispatch(method, params) {
    switch (method) {
      case "initialize": {
        const asked = params.protocolVersion;
        return {
          protocolVersion: PROTOCOL_VERSIONS.includes(asked) ? asked : PROTOCOL_VERSIONS[0],
          capabilities: { tools: { listChanged: false } },
          serverInfo: { name: "verdyx", title: "Verdyx", version: this.version },
          instructions:
            "Verdyx scans files and URLs for malware and phishing. Use scan_url before trusting an unfamiliar link and scan_file on downloads or attachments the user asks about. Report the verdict with the engine counts and the report link; 'unknown' means no evidence either way, not 'safe'.",
        };
      }
      case "ping":
        return {};
      case "tools/list":
        return { tools: TOOLS };
      case "tools/call":
        return this.callTool(params.name, params.arguments ?? {});
      default: {
        const err = new Error(`method not found: ${method}`);
        err.rpcCode = -32601;
        throw err;
      }
    }
  }

  async callTool(name, args) {
    if (!TOOLS.some((t) => t.name === name)) {
      const err = new Error(`unknown tool: ${name}`);
      err.rpcCode = -32602;
      throw err;
    }
    try {
      const wait = clampWait(args.wait_seconds, name === "get_scan_result" ? 0 : 120);
      if (name === "list_engines") {
        const engines = await this.client.listEngines();
        const text = engines.map((e) => `- ${e.name}: ${e.status ?? (e.isActive ? "online" : "offline")}`).join("\n");
        return { content: [{ type: "text", text }], structuredContent: { engines } };
      }
      let id;
      if (name === "scan_url") {
        id = (await this.client.submitUrl(String(args.url ?? ""))).id;
      } else if (name === "scan_file") {
        const roots = this.roots ?? (this.roots = await allowedRoots());
        const real = await checkPath(args.path, roots);
        this.log(`uploading ${real}`);
        id = (await this.client.submitFile(real)).id;
      } else {
        id = String(args.scan_id ?? "");
        if (!id) throw new VerdyxError("scan_id is required");
      }
      let result;
      try {
        result = wait > 0 ? await this.client.waitForResult(id, { timeoutSeconds: wait }) : await this.client.result(id);
      } catch (e) {
        if (!(e instanceof ScanTimeoutError)) throw e;
        result = await this.client.result(id);
      }
      return { content: [{ type: "text", text: summarise(result) }], structuredContent: structured(result) };
    } catch (e) {
      // Tool failures go back to the model as results it can read and act on.
      return { content: [{ type: "text", text: `Error: ${e?.message ?? e}` }], isError: true };
    }
  }
}

function clampWait(v, dflt) {
  const n = v === undefined || v === null ? dflt : Number(v);
  if (!Number.isFinite(n) || n < 0) return dflt;
  return Math.min(n, MAX_WAIT_SECONDS);
}

/** Run the server on stdin/stdout until stdin closes. */
export async function runStdio({ version }) {
  const server = new McpServer({
    version,
    write: (msg) => process.stdout.write(JSON.stringify(msg) + "\n"),
  });
  const roots = await allowedRoots();
  server.roots = roots;
  server.log(`ready; scan_file may read under: ${roots.join(", ") || "(nothing)"}`);
  if (!server.client.apiKey) server.log("VERDYX_API_KEY is not set; scans will be anonymous and more tightly rate limited");

  let buffer = "";
  const pending = new Set();
  process.stdin.setEncoding("utf8");
  for await (const chunk of process.stdin) {
    buffer += chunk;
    let nl;
    while ((nl = buffer.indexOf("\n")) !== -1) {
      const line = buffer.slice(0, nl).trim();
      buffer = buffer.slice(nl + 1);
      if (!line) continue;
      let msg;
      try {
        msg = JSON.parse(line);
      } catch {
        server.write({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "parse error" } });
        continue;
      }
      // Handle requests concurrently: a long scan mustn't block a ping.
      const p = server.handle(msg).finally(() => pending.delete(p));
      pending.add(p);
    }
  }
  await Promise.all(pending);
}
