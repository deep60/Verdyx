// Turns the action's `paths` input into a list of files, one per line on stdout.
// Globs: * and ? match within one path segment, ** matches any number of
// segments, [abc] is a character class. Done here rather than in bash so the
// result is the same on every runner, whatever its bash version.
//
// Warnings go to stdout as workflow commands, prefixed so run.sh can tell
// them apart: lines starting "file\t" are files, anything else is printed.

import { readdirSync, statSync } from "node:fs";
import { join, sep } from "node:path";

const input = process.env.INPUT_PATHS ?? "";

function toRegex(glob) {
  let re = "";
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i];
    if (c === "*") {
      if (glob[i + 1] === "*") {
        // "**/" matches zero or more directories; a trailing "**" matches everything below.
        if (glob[i + 2] === "/") {
          re += "(?:.*/)?";
          i += 2;
        } else {
          re += ".*";
          i += 1;
        }
      } else {
        re += "[^/]*";
      }
    } else if (c === "?") {
      re += "[^/]";
    } else if (c === "[") {
      const end = glob.indexOf("]", i + 1);
      if (end === -1) re += "\\[";
      else {
        re += "[" + glob.slice(i + 1, end).replace(/\\/g, "\\\\").replace(/^!/, "^") + "]";
        i = end;
      }
    } else {
      re += c.replace(/[.+^${}()|\\]/g, "\\$&");
    }
  }
  return new RegExp(`^${re}$`);
}

function walk(dir, out) {
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const e of entries) {
    if (e.name === ".git" || e.name === "node_modules") continue;
    const p = dir === "." ? e.name : join(dir, e.name);
    if (e.isDirectory()) walk(p, out);
    else if (e.isFile()) out.push(p);
  }
}

const seen = new Set();
const emit = (f) => {
  if (!seen.has(f)) {
    seen.add(f);
    console.log(`file\t${f}`);
  }
};

for (const raw of input.split(/\r?\n/)) {
  const pattern = raw.trim().replace(/^\.\//, "");
  if (!pattern) continue;
  if (!/[*?[]/.test(pattern)) {
    let st = null;
    try {
      st = statSync(pattern);
    } catch {
      // Missing: let the CLI report it as an error.
    }
    if (st?.isDirectory()) {
      console.log(`::warning title=Verdyx::${pattern} is a directory; use a glob such as ${pattern.replace(/\/$/, "")}/** to scan its files`);
    } else {
      emit(pattern);
    }
    continue;
  }
  // Walk from the part before the first wildcard, to avoid scanning the whole tree.
  const parts = pattern.split("/");
  const firstWild = parts.findIndex((s) => /[*?[]/.test(s));
  const base = parts.slice(0, firstWild).join("/") || ".";
  const files = [];
  walk(base, files);
  const re = toRegex(pattern);
  const matched = files.map((f) => f.split(sep).join("/")).filter((f) => re.test(f)).sort();
  if (matched.length === 0) console.log(`::warning title=Verdyx::no files match ${pattern}`);
  matched.forEach(emit);
}
