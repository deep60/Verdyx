export interface YaraMatch {
  rule: string;
  stringId: string;
  offset: number;
  preview: string;
}

export interface YaraRuleResult {
  rule: string;
  matched: boolean;
  matches: YaraMatch[];
  error?: string;
}

interface HexAtom {
  value: number;
  mask: number;
}

interface YaraString {
  id: string;
  kind: "text" | "hex" | "regex";
  text?: Uint8Array;
  textWide?: Uint8Array;
  hex?: HexAtom[];
  regex?: RegExp;
  nocase: boolean;
}

interface YaraRule {
  name: string;
  strings: YaraString[];
  condition: string;
}

const MAX_MATCHES = 40;

function decodeString(body: string): Uint8Array {
  const out: number[] = [];
  for (let i = 0; i < body.length; i++) {
    const ch = body[i];
    if (ch !== "\\") {
      out.push(body.charCodeAt(i) & 0xff);
      continue;
    }
    const next = body[++i];
    if (next === "n") out.push(0x0a);
    else if (next === "r") out.push(0x0d);
    else if (next === "t") out.push(0x09);
    else if (next === "x") {
      const hex = body.slice(i + 1, i + 3);
      if (!/^[0-9a-fA-F]{2}$/.test(hex)) throw new Error(`bad hex escape \\x${hex}`);
      out.push(parseInt(hex, 16));
      i += 2;
    } else if (next) out.push(next.charCodeAt(0) & 0xff);
  }
  return Uint8Array.from(out);
}

function toWide(bytes: Uint8Array): Uint8Array {
  const wide = new Uint8Array(bytes.length * 2);
  for (let i = 0; i < bytes.length; i++) wide[i * 2] = bytes[i];
  return wide;
}

function parseHex(body: string): HexAtom[] {
  if (/\[[^\]]+\]/.test(body)) {
    throw new Error("hex jumps such as [4-6] are not supported in this playground");
  }
  const tokens = body.replace(/[{}]/g, " ").trim().split(/\s+/).filter(Boolean);
  const atoms: HexAtom[] = [];
  for (const token of tokens) {
    if (!/^[0-9a-fA-F?]{1,2}$/.test(token)) {
      throw new Error(`unsupported hex token "${token}"`);
    }
    if (token === "?" || token === "??") {
      atoms.push({ value: 0, mask: 0 });
      continue;
    }
    if (token.length === 1) {
      atoms.push({ value: parseInt(token, 16) << 4, mask: 0xf0 });
      continue;
    }
    const highWild = token[0] === "?";
    const lowWild = token[1] === "?";
    const high = highWild ? 0 : parseInt(token[0], 16);
    const low = lowWild ? 0 : parseInt(token[1], 16);
    const mask = (highWild ? 0 : 0xf0) | (lowWild ? 0 : 0x0f);
    atoms.push({ value: ((high << 4) | low) & mask, mask });
  }
  if (atoms.length === 0) throw new Error("hex string is empty");
  return atoms;
}

function parseRule(source: string): YaraRule {
  const nameMatch = /^\s*rule\s+([A-Za-z_][A-Za-z0-9_]*)/i.exec(source);
  if (!nameMatch) throw new Error("rule is missing a name");
  const stringsAt = source.search(/\bstrings\s*:/i);
  const conditionAt = source.search(/\bcondition\s*:/i);
  if (conditionAt < 0) throw new Error(`${nameMatch[1]} is missing a condition`);
  const condition = source.slice(conditionAt).replace(/^[^:]*:/, "").replace(/}\s*$/, "").trim();
  const strings: YaraString[] = [];
  if (stringsAt >= 0 && stringsAt < conditionAt) {
    const block = source.slice(stringsAt, conditionAt).replace(/^[^:]*:/, "");
    const textRe = /\$([A-Za-z0-9_]+)\s*=\s*"((?:\\.|[^"\\])*)"([^\n]*)/g;
    const hexRe = /\$([A-Za-z0-9_]+)\s*=\s*\{([^}]+)\}/g;
    const regexRe = /\$([A-Za-z0-9_]+)\s*=\s*\/((?:\\.|[^/\\])+)\/([A-Za-z]*)\b([^\n]*)/g;
    let match: RegExpExecArray | null;
    while ((match = textRe.exec(block))) {
      const mods = match[3].toLowerCase();
      const text = decodeString(match[2]);
      const wide = /\bwide\b/.test(mods);
      const ascii = /\bascii\b/.test(mods) || !wide;
      strings.push({
        id: match[1],
        kind: "text",
        text: ascii ? text : undefined,
        textWide: wide ? toWide(text) : undefined,
        nocase: /\bnocase\b/.test(mods),
      });
    }
    while ((match = hexRe.exec(block))) {
      strings.push({
        id: match[1],
        kind: "hex",
        hex: parseHex(match[2]),
        nocase: false,
      });
    }
    while ((match = regexRe.exec(block))) {
      const flagsRaw = `${match[3] || ""}${/\bnocase\b/i.test(match[4] || "") ? "i" : ""}`;
      const flags = flagsRaw.includes("i") ? "gi" : "g";
      strings.push({
        id: match[1],
        kind: "regex",
        regex: new RegExp(match[2], flags),
        nocase: flags.includes("i"),
      });
    }
  }
  return { name: nameMatch[1], strings, condition };
}

function splitRules(source: string): string[] {
  const parts: string[] = [];
  const re = /\brule\s+[A-Za-z_]/gi;
  const starts: number[] = [];
  let match: RegExpExecArray | null;
  while ((match = re.exec(source))) starts.push(match.index);
  if (starts.length === 0) throw new Error('No rule found. Start with `rule Name { strings: $a = "text" condition: $a }`');
  for (let i = 0; i < starts.length; i++) {
    parts.push(source.slice(starts[i], starts[i + 1] ?? source.length));
  }
  return parts;
}

function lowerByte(value: number): number {
  if (value >= 0x41 && value <= 0x5a) return value + 0x20;
  return value;
}

function findBytes(hay: Uint8Array, needle: Uint8Array, nocase: boolean): number[] {
  if (needle.length === 0 || needle.length > hay.length) return [];
  const hits: number[] = [];
  outer: for (let i = 0; i <= hay.length - needle.length; i++) {
    for (let j = 0; j < needle.length; j++) {
      const left = nocase ? lowerByte(hay[i + j]) : hay[i + j];
      const right = nocase ? lowerByte(needle[j]) : needle[j];
      if (left !== right) continue outer;
    }
    hits.push(i);
    if (hits.length >= MAX_MATCHES) break;
  }
  return hits;
}

function findHex(hay: Uint8Array, pattern: HexAtom[]): number[] {
  if (pattern.length === 0 || pattern.length > hay.length) return [];
  const hits: number[] = [];
  outer: for (let i = 0; i <= hay.length - pattern.length; i++) {
    for (let j = 0; j < pattern.length; j++) {
      const atom = pattern[j];
      if ((hay[i + j] & atom.mask) !== (atom.value & atom.mask)) continue outer;
    }
    hits.push(i);
    if (hits.length >= MAX_MATCHES) break;
  }
  return hits;
}

function findRegex(hay: Uint8Array, regex: RegExp): Array<{ offset: number; length: number }> {
  const latin1 = Array.from(hay.slice(0, 512 * 1024), (b) => String.fromCharCode(b)).join("");
  const hits: Array<{ offset: number; length: number }> = [];
  const re = new RegExp(regex.source, regex.flags.includes("g") ? regex.flags : `${regex.flags}g`);
  let m: RegExpExecArray | null;
  while ((m = re.exec(latin1))) {
    hits.push({ offset: m.index, length: Math.max(m[0].length, 1) });
    if (m[0].length === 0) re.lastIndex += 1;
    if (hits.length >= MAX_MATCHES) break;
  }
  return hits;
}

function previewAt(hay: Uint8Array, offset: number, length: number): string {
  const slice = hay.slice(offset, Math.min(hay.length, offset + Math.max(length, 8)));
  const hex = Array.from(slice.slice(0, 12), (b) => b.toString(16).padStart(2, "0")).join(" ");
  const text = Array.from(slice.slice(0, 16), (b) => (b >= 32 && b < 127 ? String.fromCharCode(b) : ".")).join("");
  return `${hex}  ${text}`;
}

function parseNumberLiteral(raw: string): number {
  const trimmed = raw.trim().toLowerCase();
  if (trimmed.startsWith("0x")) return parseInt(trimmed.slice(2), 16);
  if (trimmed.endsWith("kb")) return parseFloat(trimmed.slice(0, -2)) * 1024;
  if (trimmed.endsWith("mb")) return parseFloat(trimmed.slice(0, -2)) * 1024 * 1024;
  return Number(trimmed);
}

function preprocessBuiltins(condition: string, sample: Uint8Array): string {
  let out = condition;
  // Evaluate uint16(offset) == value and uint32(offset) == value
  out = out.replace(
    /\buint(16|32)\s*\(\s*(0x[0-9a-fA-F]+|\d+)\s*\)\s*(==|!=|<|>|<=|>=)\s*(0x[0-9a-fA-F]+|\d+)/gi,
    (_full, bitsStr, offStr, op, valStr) => {
      const bits = Number(bitsStr);
      const offset = parseNumberLiteral(offStr);
      const target = parseNumberLiteral(valStr);
      if (offset < 0 || offset + bits / 8 > sample.length) return "false";
      const actual =
        bits === 16
          ? sample[offset] | (sample[offset + 1] << 8)
          : (sample[offset] |
              (sample[offset + 1] << 8) |
              (sample[offset + 2] << 16) |
              (sample[offset + 3] << 24)) >>>
            0;
      const res =
        op === "=="
          ? actual === target
          : op === "!="
            ? actual !== target
            : op === "<"
              ? actual < target
              : op === ">"
                ? actual > target
                : op === "<="
                  ? actual <= target
                  : actual >= target;
      return res ? "true" : "false";
    }
  );
  // Evaluate filesize comparisons (e.g. filesize < 500KB)
  out = out.replace(
    /\bfilesize\s*(==|!=|<|>|<=|>=)\s*(0x[0-9a-fA-F]+|\d+(?:\.\d+)?\s*(?:kb|mb)?)/gi,
    (_full, op, valStr) => {
      const target = parseNumberLiteral(valStr);
      const sz = sample.length;
      const res =
        op === "=="
          ? sz === target
          : op === "!="
            ? sz !== target
            : op === "<"
              ? sz < target
              : op === ">"
                ? sz > target
                : op === "<="
                  ? sz <= target
                  : sz >= target;
      return res ? "true" : "false";
    }
  );
  return out;
}

type Token =
  | { type: "id"; value: string }
  | { type: "and" }
  | { type: "or" }
  | { type: "not" }
  | { type: "any" }
  | { type: "all" }
  | { type: "none" }
  | { type: "bool"; value: boolean }
  | { type: "(" }
  | { type: ")" };

function tokenize(condition: string): Token[] {
  const src = condition.replace(/\/\*[\s\S]*?\*\//g, " ").replace(/\/\/.*$/gm, " ");
  const tokens: Token[] = [];
  const re = /\$([A-Za-z0-9_]+)|#([A-Za-z0-9_]+)|\b(and|or|not|any of them|all of them|none of them|true|false)\b|[()]/gi;
  let match: RegExpExecArray | null;
  let cursor = 0;
  while ((match = re.exec(src))) {
    const gap = src.slice(cursor, match.index).trim();
    if (gap) throw new Error(`unsupported condition syntax "${gap.slice(0, 40)}"`);
    cursor = match.index + match[0].length;
    const word = match[0].toLowerCase();
    if (match[1] || match[2]) tokens.push({ type: "id", value: match[1] || match[2] });
    else if (word === "and") tokens.push({ type: "and" });
    else if (word === "or") tokens.push({ type: "or" });
    else if (word === "not") tokens.push({ type: "not" });
    else if (word === "any of them") tokens.push({ type: "any" });
    else if (word === "all of them") tokens.push({ type: "all" });
    else if (word === "none of them") tokens.push({ type: "none" });
    else if (word === "true") tokens.push({ type: "bool", value: true });
    else if (word === "false") tokens.push({ type: "bool", value: false });
    else if (match[0] === "(") tokens.push({ type: "(" });
    else if (match[0] === ")") tokens.push({ type: ")" });
  }
  const tail = src.slice(cursor).trim();
  if (tail) throw new Error(`unsupported condition syntax "${tail.slice(0, 40)}"`);
  return tokens;
}

function evalCondition(condition: string, present: Set<string>, defined: string[], sample: Uint8Array): boolean {
  const normalized = preprocessBuiltins(condition, sample);
  const tokens = tokenize(normalized);
  let index = 0;
  const peek = () => tokens[index];
  const eat = () => tokens[index++];

  const parseOr = (): boolean => {
    let left = parseAnd();
    while (peek()?.type === "or") {
      eat();
      const right = parseAnd();
      left = left || right;
    }
    return left;
  };
  const parseAnd = (): boolean => {
    let left = parseNot();
    while (peek()?.type === "and") {
      eat();
      const right = parseNot();
      left = left && right;
    }
    return left;
  };
  const parseNot = (): boolean => {
    if (peek()?.type === "not") {
      eat();
      return !parseNot();
    }
    return parsePrimary();
  };
  const parsePrimary = (): boolean => {
    const token = eat();
    if (!token) throw new Error("condition ended early");
    if (token.type === "bool") return token.value;
    if (token.type === "id") return present.has(token.value);
    if (token.type === "any") return defined.some((id) => present.has(id));
    if (token.type === "all") return defined.length > 0 && defined.every((id) => present.has(id));
    if (token.type === "none") return defined.every((id) => !present.has(id));
    if (token.type === "(") {
      const value = parseOr();
      if (eat()?.type !== ")") throw new Error("missing closing parenthesis");
      return value;
    }
    throw new Error("unsupported condition token");
  };

  const value = parseOr();
  if (index !== tokens.length) throw new Error("unexpected tokens after condition");
  return value;
}

export function runYaraSubset(ruleSource: string, sample: Uint8Array): YaraRuleResult[] {
  return splitRules(ruleSource).map((source) => {
    const fallbackName = /^\s*rule\s+([A-Za-z_][A-Za-z0-9_]*)/i.exec(source)?.[1] || "rule";
    let rule: YaraRule;
    try {
      rule = parseRule(source);
    } catch (error) {
      return {
        rule: fallbackName,
        matched: false,
        matches: [],
        error: error instanceof Error ? error.message : "rule failed",
      };
    }
    try {
      const matches: YaraMatch[] = [];
      const present = new Set<string>();
      for (const item of rule.strings) {
        let offsets: number[] = [];
        let length = 0;
        if (item.kind === "text") {
          if (item.text) offsets = offsets.concat(findBytes(sample, item.text, item.nocase));
          if (item.textWide) offsets = offsets.concat(findBytes(sample, item.textWide, item.nocase));
          length = item.text?.length || (item.textWide ? item.textWide.length / 2 : 0);
        } else if (item.kind === "hex" && item.hex) {
          offsets = findHex(sample, item.hex);
          length = item.hex.length;
        } else if (item.kind === "regex" && item.regex) {
          const rHits = findRegex(sample, item.regex);
          offsets = rHits.map((h) => h.offset);
          length = rHits[0]?.length ?? 12;
        }
        offsets.sort((a, b) => a - b);
        if (offsets.length > 0) present.add(item.id);
        for (const offset of offsets.slice(0, 12)) {
          matches.push({
            rule: rule.name,
            stringId: `$${item.id}`,
            offset,
            preview: previewAt(sample, offset, length),
          });
        }
      }
      const matched = evalCondition(
        rule.condition,
        present,
        rule.strings.map((item) => item.id),
        sample,
      );
      return {
        rule: rule.name,
        matched,
        matches: matched ? matches : [],
      };
    } catch (error) {
      return {
        rule: rule.name,
        matched: false,
        matches: [],
        error: error instanceof Error ? error.message : "rule failed",
      };
    }
  });
}
