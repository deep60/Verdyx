#!/usr/bin/env node
// The `verdyx` command: scan files and URLs from a terminal or CI.

import { appendFile, readFile, writeFile } from "node:fs/promises";
import { parseArgs } from "node:util";
import { Verdyx, VerdyxError, ScanTimeoutError, meetsThreshold } from "../src/index.js";

const VERSION = JSON.parse(await readFile(new URL("../package.json", import.meta.url), "utf8")).version;

const HELP = `verdyx ${VERSION}: scan files and URLs with Verdyx

Usage:
  verdyx scan <file-or-url>...   Submit and wait for the verdicts
  verdyx result <scan-id>...     Show the result of earlier scans
  verdyx engines                 List the engines and whether they're online
  verdyx mcp                     Run as an MCP server (stdio) for AI assistants

Options for scan and result:
  --json                 Print JSON instead of a table
  --verbose, -v          Also show each engine's result
  --fail-on <level>      Exit with code 2 when a verdict is at least this bad:
                         malicious (default), suspicious or never
  --timeout <seconds>    Give up waiting after this long (default 300)
  --summary <file>       Append a Markdown table to this file
                         (in GitHub Actions: "$GITHUB_STEP_SUMMARY")
  --output <file>        Also write the JSON results to this file

Options for scan only:
  --no-wait              Submit and print the scan ids without waiting
  --team <id>            Save the scans to this team
  --description <text>   Attach a note to the scans

Environment:
  VERDYX_API_KEY         An API key with the scan and read scopes. Create one on
                         your profile page at https://verdyx.dev. Without one,
                         scans are anonymous and more tightly rate limited.
  VERDYX_API_URL         Default https://api.verdyx.dev
  VERDYX_MCP_ROOTS       For "verdyx mcp": the folders whose files may be uploaded
                         (default: the current folder, unless it's / or home)
  NO_COLOR               Turn off colours

Exit codes: 0 ok, 1 error or timeout, 2 a verdict reached --fail-on.
`;

const color = process.stdout.isTTY && !process.env.NO_COLOR;
const paint = (code, s) => (color ? `\x1b[${code}m${s}\x1b[0m` : s);
const VERDICT_STYLE = { malicious: "1;31", suspicious: "1;33", clean: "32", unknown: "2" };

async function main(argv) {
  const [command, ...rest] = argv;
  if (!command || command === "help" || command === "--help" || command === "-h") {
    process.stdout.write(HELP);
    return 0;
  }
  if (command === "--version" || command === "-V") {
    console.log(VERSION);
    return 0;
  }
  if (command === "mcp") {
    // stdout belongs to the protocol; everything else goes to stderr.
    const { runStdio } = await import("../src/mcp.js");
    await runStdio({ version: VERSION });
    return 0;
  }

  const { values, positionals } = parseArgs({
    args: rest,
    allowPositionals: true,
    options: {
      json: { type: "boolean", default: false },
      verbose: { type: "boolean", short: "v", default: false },
      "fail-on": { type: "string", default: "malicious" },
      timeout: { type: "string", default: "300" },
      summary: { type: "string" },
      output: { type: "string" },
      "no-wait": { type: "boolean", default: false },
      team: { type: "string" },
      description: { type: "string" },
    },
  });

  const failOn = values["fail-on"];
  if (!["malicious", "suspicious", "never"].includes(failOn)) {
    throw new VerdyxError(`--fail-on must be malicious, suspicious or never, not "${failOn}"`);
  }
  const timeoutSeconds = Number(values.timeout);
  if (!Number.isFinite(timeoutSeconds) || timeoutSeconds <= 0) {
    throw new VerdyxError(`--timeout must be a number of seconds, not "${values.timeout}"`);
  }

  const client = new Verdyx();

  if (command === "engines") {
    const engines = await client.listEngines();
    if (values.json) {
      console.log(JSON.stringify(engines, null, 2));
    } else {
      const width = Math.max(...engines.map((e) => String(e.name).length), 4);
      for (const e of engines) {
        console.log(`${String(e.name).padEnd(width)}  ${e.status ?? (e.isActive ? "online" : "offline")}`);
      }
    }
    return 0;
  }

  if (command !== "scan" && command !== "result") {
    throw new VerdyxError(`unknown command "${command}"; run "verdyx --help"`);
  }
  if (positionals.length === 0) {
    throw new VerdyxError(command === "scan" ? "give at least one file or URL to scan" : "give at least one scan id");
  }

  // Submit one at a time (kinder to rate limits), then wait for all together.
  let ids;
  /** What the user typed for each scan, shown instead of the server's file name. */
  const typed = new Map();
  if (command === "scan") {
    ids = [];
    for (const target of positionals) {
      const opts = { teamId: values.team, description: values.description };
      const sub = /^https?:\/\//i.test(target)
        ? await client.submitUrl(target, opts)
        : await client.submitFile(target, opts);
      if (!values.json) console.error(paint("2", `submitted ${target} → ${sub.id}`));
      ids.push(sub.id);
      typed.set(sub.id, target);
    }
    if (values["no-wait"]) {
      if (values.json) console.log(JSON.stringify(ids.map((id) => ({ id, reportUrl: client.reportUrl(id) })), null, 2));
      else for (const id of ids) console.log(`${id}  ${client.reportUrl(id)}`);
      return 0;
    }
  } else {
    ids = positionals;
  }

  const poll = Number(process.env.VERDYX_POLL_INTERVAL) || undefined;
  const settled = await Promise.allSettled(
    ids.map((id) => client.waitForResult(id, { timeoutSeconds, pollIntervalSeconds: poll })),
  );
  const results = [];
  const errors = [];
  settled.forEach((s, i) => {
    if (s.status === "fulfilled") results.push({ ...s.value, target: typed.get(ids[i]) ?? s.value.target });
    else errors.push({ id: ids[i], error: s.reason });
  });

  const report = JSON.stringify(
    {
      failOn,
      results: results.map(({ submission, consensus, ...r }) => r),
      errors: errors.map((e) => ({ id: e.id, error: String(e.error?.message ?? e.error) })),
    },
    null,
    2,
  );
  if (values.output) await writeFile(values.output, report + "\n");
  if (values.json) {
    console.log(report);
  } else {
    printTable(results, values.verbose);
    for (const e of errors) console.error(paint("31", `error  ${e.id}: ${e.error?.message ?? e.error}`));
  }
  if (values.summary) await appendFile(values.summary, markdown(results, errors, failOn));

  const failed = results.filter((r) => r.status === "failed");
  const hit = results.filter((r) => meetsThreshold(r.verdict, failOn));
  if (hit.length > 0) {
    if (!values.json) console.error(paint("1;31", `${hit.length} of ${results.length} reached --fail-on ${failOn}`));
    return 2;
  }
  return errors.length > 0 || failed.length > 0 ? 1 : 0;
}

function describeVotes(r) {
  if (r.status === "failed") return `scan failed${r.failureReason ? `: ${r.failureReason}` : ""}`;
  if (r.votes.total === 0) return "no engine voted";
  const flagged = r.votes.malicious + r.votes.suspicious;
  return `${flagged}/${r.votes.total} voting engines flagged it`;
}

function printTable(results, verbose) {
  const width = Math.max(...results.map((r) => (r.target ?? r.id).length), 6);
  for (const r of results) {
    const v = r.status === "failed" ? "failed" : r.verdict;
    const label = paint(VERDICT_STYLE[v] ?? "31", v.toUpperCase().padEnd(10));
    console.log(`${label} ${(r.target ?? r.id).padEnd(width)}  ${describeVotes(r)}  ${paint("2", r.reportUrl)}`);
    if (verbose) {
      for (const e of r.engines) {
        console.log(`           ${paint("2", "·")} ${e.name}: ${engineVote(e)}${e.reason ? paint("2", ` — ${e.reason}`) : ""}`);
      }
    }
  }
}

/** "malicious (90%)", "clean (64% malware chance)" or "no vote". */
function engineVote(e) {
  if (!e.verdict) return "no vote";
  // A model's malware chance reads better than its confidence in "clean".
  if (e.malwareChance != null) return `${e.verdict} (${e.malwareChance}% malware chance)`;
  return e.confidence != null ? `${e.verdict} (${e.confidence}%)` : e.verdict;
}

function cell(s) {
  return String(s ?? "").replace(/\|/g, "\\|").replace(/\r?\n/g, " ");
}

function markdown(results, errors, failOn) {
  const icon = { malicious: "🔴", suspicious: "🟠", clean: "🟢", unknown: "⚪" };
  const lines = ["### Verdyx scan", "", "| Verdict | Target | Engines | Report |", "|---|---|---|---|"];
  for (const r of results) {
    const v = r.status === "failed" ? "failed" : r.verdict;
    lines.push(`| ${icon[v] ?? "⚠️"} ${v} | \`${cell(r.target ?? r.id)}\` | ${cell(describeVotes(r))} | [open](${r.reportUrl}) |`);
  }
  for (const e of errors) lines.push(`| ⚠️ error | \`${cell(e.id)}\` | ${cell(e.error?.message ?? e.error)} | |`);
  lines.push("", `Fails the job on: **${failOn}**`, "", "");
  return lines.join("\n");
}

main(process.argv.slice(2)).then(
  (code) => process.exit(code),
  (e) => {
    const msg = e instanceof ScanTimeoutError || e instanceof VerdyxError ? e.message : (e?.stack ?? String(e));
    console.error(paint("31", `verdyx: ${msg}`));
    process.exit(1);
  },
);
