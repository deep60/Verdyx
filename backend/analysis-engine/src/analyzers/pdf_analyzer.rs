//! PDF analysis: JavaScript, actions that run on open, launch actions,
//! embedded files, links and structural tricks.
//!
//! A PDF hides its dangerous parts from byte-level engines: JavaScript sits in
//! compressed streams, often inside compressed *object streams*, names can be
//! spelled with hex escapes (`/J#61vaScript`), and what runs on open is only
//! visible by following `/OpenAction` and `/AA` references. This analyzer
//! reads the file's real structure:
//!
//! - every `N G obj ... endobj`, plus the objects packed in `/ObjStm` streams;
//! - streams decoded through `FlateDecode`, `ASCIIHexDecode` and
//!   `ASCII85Decode` (chained filters too);
//! - names normalised, and hex-escaped action names reported as evasion;
//! - JavaScript collected from `/JS` (literal, hex or referenced streams) and
//!   from XFA forms, then scored the way analysts read it;
//! - automatic actions resolved from `/OpenAction` and `/AA`, including
//!   `/Next` chains;
//! - `/Launch` targets, embedded files (name and contents), links, UNC paths,
//!   and data before the header or after the last `%%EOF`.
//!
//! JavaScript is common in legitimate forms, so it isn't a finding on its own.
//! What is: script that runs by itself and is obfuscated, calls known exploit
//! APIs or sprays shellcode, actions that launch programs, and embedded
//! programs that get opened.
//!
//! Everything here reads hostile input: every read is size-capped and the
//! parse runs under `catch_unwind`, so a malformed file is "could not be
//! parsed", never a crash.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::Read;

use chrono::Utc;
use regex::bytes::Regex as BytesRegex;
use regex::Regex;
use serde::Serialize;
use uuid::Uuid;

use crate::models::analysis_result::{
    DetectionResult, EngineType, SeverityLevel, ThreatCategory, ThreatVerdict, STRONG_SIGNAL_KEY,
};

pub const ENGINE_NAME: &str = "PDF Analyzer";
const ENGINE_VERSION: &str = "1.0.0";

/// Objects read from one file (including those in object streams).
const MAX_OBJECTS: usize = 50_000;
/// Largest decoded stream.
const MAX_STREAM_BYTES: usize = 8 * 1024 * 1024;
/// Total decoded bytes across the file.
const MAX_TOTAL_DECODED: usize = 64 * 1024 * 1024;
/// Characters of each script kept in the report.
const SCRIPT_PREVIEW_CHARS: usize = 3_000;
const MAX_SCRIPTS: usize = 50;
const MAX_URIS: usize = 50;
/// How far into the file `%PDF-` may start (readers accept junk before it).
const HEADER_WINDOW: usize = 1024;

/// Names worth counting, as pdfid does.
const KEYWORDS: &[&str] = &[
    "JS",
    "JavaScript",
    "OpenAction",
    "AA",
    "Launch",
    "EmbeddedFile",
    "RichMedia",
    "XFA",
    "AcroForm",
    "URI",
    "SubmitForm",
    "GoToR",
    "GoToE",
    "ImportData",
    "Encrypt",
    "ObjStm",
    "JBIG2Decode",
];

/// Action keys whose hex-escaped spelling is a sign of evasion.
const EVASION_NAMES: &[&str] = &[
    "JS",
    "JavaScript",
    "OpenAction",
    "AA",
    "Launch",
    "EmbeddedFile",
    "URI",
    "SubmitForm",
    "RichMedia",
    "XFA",
];

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct Indicator {
    /// "autorun", "exploit", "shellcode", "obfuscation", "launch", "drop",
    /// "network", "evasion", "embedded".
    pub kind: &'static str,
    pub keyword: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Script {
    /// The object it came from, e.g. "12 0" or "XFA".
    pub object: String,
    /// Runs without the reader clicking anything.
    pub automatic: bool,
    pub bytes: usize,
    pub preview: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AutoAction {
    /// "OpenAction" or "AA".
    pub trigger: String,
    /// The action's `/S`: JavaScript, Launch, URI, SubmitForm, GoToR, ...
    pub action: String,
    pub target: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LaunchAction {
    pub object: String,
    pub target: Option<String>,
    pub parameters: Option<String>,
    pub automatic: bool,
    pub runs_command: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EmbeddedFile {
    pub name: Option<String>,
    pub bytes: usize,
    /// "Windows program", "script", "Office document with macros", "PDF", ...
    pub kind: Option<String>,
    pub executable: bool,
}

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Structure {
    pub version: Option<String>,
    /// Bytes before `%PDF-`.
    pub header_offset: usize,
    pub objects: usize,
    pub object_streams: usize,
    pub pages: usize,
    /// `%%EOF` markers beyond the first: incremental updates.
    pub incremental_updates: usize,
    /// Non-whitespace bytes after the last `%%EOF`.
    pub trailing_bytes: usize,
    pub encrypted: bool,
    /// Something that isn't a PDF hides before the header or after the end.
    pub polyglot: Option<String>,
}

/// Everything the analyzer found in one file.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PdfReport {
    pub structure: Structure,
    pub keywords: BTreeMap<String, usize>,
    pub hex_escaped_names: Vec<String>,
    pub auto_actions: Vec<AutoAction>,
    pub scripts: Vec<Script>,
    pub launch_actions: Vec<LaunchAction>,
    pub embedded_files: Vec<EmbeddedFile>,
    pub uris: Vec<String>,
    pub unc_paths: Vec<String>,
    pub indicators: Vec<Indicator>,
    pub errors: Vec<String>,
}

impl PdfReport {
    fn new() -> Self {
        Self {
            structure: Structure::default(),
            keywords: BTreeMap::new(),
            hex_escaped_names: Vec::new(),
            auto_actions: Vec::new(),
            scripts: Vec::new(),
            launch_actions: Vec::new(),
            embedded_files: Vec::new(),
            uris: Vec::new(),
            unc_paths: Vec::new(),
            indicators: Vec::new(),
            errors: Vec::new(),
        }
    }

    fn has(&self, kind: &str) -> bool {
        self.indicators.iter().any(|i| i.kind == kind)
    }

    fn indicate(
        &mut self,
        kind: &'static str,
        keyword: impl Into<String>,
        description: impl Into<String>,
    ) {
        let i = Indicator {
            kind,
            keyword: keyword.into(),
            description: description.into(),
        };
        if !self.indicators.contains(&i) {
            self.indicators.push(i);
        }
    }
}

/// Where `%PDF-` starts, if within the first kilobyte.
pub fn header_offset(data: &[u8]) -> Option<usize> {
    let window = &data[..data.len().min(HEADER_WINDOW + 5)];
    find(window, b"%PDF-")
}

/// Analyse `data` if it is a PDF. `None` for anything else.
pub fn analyze(data: &[u8]) -> Option<DetectionResult> {
    header_offset(data)?;
    let started = std::time::Instant::now();
    let report = std::panic::catch_unwind(|| inspect(data)).unwrap_or_else(|_| {
        let mut r = PdfReport::new();
        r.errors
            .push("PDF structure could not be parsed".to_string());
        r
    });
    Some(detection(&report, started.elapsed().as_millis() as u64))
}

// ── Parsing ──────────────────────────────────────────────────────────────

/// One object: its normalised dictionary text and decoded stream.
#[derive(Debug, Clone, Default)]
struct Object {
    /// The object's text before any stream, names normalised, as Latin-1.
    text: String,
    stream: Option<Vec<u8>>,
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

fn rfind(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).rposition(|w| w == needle)
}

fn latin1(b: &[u8]) -> String {
    b.iter().map(|&c| c as char).collect()
}

/// Undo `#hh` escapes in names. Returns the text and the escaped names seen.
fn normalize_names(text: &str) -> (String, Vec<String>) {
    let mut out = String::with_capacity(text.len());
    let mut escaped = Vec::new();
    let chars: Vec<char> = text.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c != '/' {
            out.push(c);
            i += 1;
            continue;
        }
        // A name runs until whitespace or a delimiter.
        out.push('/');
        i += 1;
        let mut name = String::new();
        let mut had_escape = false;
        while i < chars.len() {
            let c = chars[i];
            if c.is_whitespace() || "/<>[]()%{}".contains(c) {
                break;
            }
            if c == '#' && i + 2 < chars.len() + 1 {
                let hex: String = chars
                    .get(i + 1..i + 3)
                    .map(|s| s.iter().collect())
                    .unwrap_or_default();
                if let Ok(v) = u8::from_str_radix(&hex, 16) {
                    name.push(v as char);
                    had_escape = true;
                    i += 3;
                    continue;
                }
            }
            name.push(c);
            i += 1;
        }
        if had_escape {
            escaped.push(name.clone());
        }
        out.push_str(&name);
    }
    (out, escaped)
}

fn filters(dict: &str) -> Vec<String> {
    static RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r"/Filter\s*(\[[^\]]*\]|/[A-Za-z0-9]+)").unwrap());
    let Some(m) = re.captures(dict) else {
        return Vec::new();
    };
    m[1].split('/')
        .map(|s| s.trim_matches(|c: char| c.is_whitespace() || c == '[' || c == ']'))
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

fn inflate(data: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut z = flate2::read::ZlibDecoder::new(data).take(MAX_STREAM_BYTES as u64);
    // Truncated streams are common; keep what decoded.
    let _ = z.read_to_end(&mut out);
    if out.is_empty() {
        let mut d = flate2::read::DeflateDecoder::new(data).take(MAX_STREAM_BYTES as u64);
        let _ = d.read_to_end(&mut out);
    }
    (!out.is_empty()).then_some(out)
}

pub fn ascii_hex(data: &[u8]) -> Vec<u8> {
    let digits: Vec<u8> = data
        .iter()
        .take_while(|&&c| c != b'>')
        .filter(|c| c.is_ascii_hexdigit())
        .copied()
        .collect();
    digits
        .chunks(2)
        .map(|p| {
            let hi = (p[0] as char).to_digit(16).unwrap_or(0);
            let lo = p
                .get(1)
                .and_then(|&c| (c as char).to_digit(16))
                .unwrap_or(0);
            (hi * 16 + lo) as u8
        })
        .collect()
}

pub fn ascii85(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut group = [0u32; 5];
    let mut n = 0;
    let body = data.strip_prefix(b"<~").unwrap_or(data);
    for &c in body {
        if c == b'~' {
            break;
        }
        if c.is_ascii_whitespace() {
            continue;
        }
        if c == b'z' && n == 0 {
            out.extend_from_slice(&[0, 0, 0, 0]);
            continue;
        }
        if !(b'!'..=b'u').contains(&c) {
            continue;
        }
        group[n] = (c - b'!') as u32;
        n += 1;
        if n == 5 {
            let v = group.iter().fold(0u64, |acc, &d| acc * 85 + d as u64) as u32;
            out.extend_from_slice(&v.to_be_bytes());
            n = 0;
        }
        if out.len() > MAX_STREAM_BYTES {
            break;
        }
    }
    if n > 1 {
        for g in group.iter_mut().skip(n) {
            *g = 84;
        }
        let v = group.iter().fold(0u64, |acc, &d| acc * 85 + d as u64) as u32;
        out.extend_from_slice(&v.to_be_bytes()[..n - 1]);
    }
    out
}

/// Decode a stream through its filters. `None` if a filter isn't supported
/// (images and such don't matter here).
fn decode(dict: &str, raw: &[u8]) -> Option<Vec<u8>> {
    let mut data = raw.to_vec();
    for f in filters(dict) {
        data = match f.as_str() {
            "FlateDecode" | "Fl" => inflate(&data)?,
            "ASCIIHexDecode" | "AHx" => ascii_hex(&data),
            "ASCII85Decode" | "A85" => ascii85(&data),
            _ => return None,
        };
        data.truncate(MAX_STREAM_BYTES);
    }
    Some(data)
}

struct Parsed {
    objects: HashMap<String, Object>,
    /// Object ids in file order.
    order: Vec<String>,
}

fn parse(data: &[u8], report: &mut PdfReport) -> Parsed {
    static OBJ: std::sync::OnceLock<BytesRegex> = std::sync::OnceLock::new();
    let obj_re =
        OBJ.get_or_init(|| BytesRegex::new(r"(?-u)(\d{1,10})\s+(\d{1,5})\s+obj\b").unwrap());
    let mut objects: HashMap<String, Object> = HashMap::new();
    let mut order = Vec::new();
    let mut decoded_total = 0usize;
    let mut escaped: BTreeSet<String> = BTreeSet::new();
    let mut object_streams = Vec::new();

    // Each object ends at its `endobj`, or at the next object if that's
    // missing, so a file of unterminated objects still parses in one pass.
    let starts: Vec<_> = obj_re.captures_iter(data).take(MAX_OBJECTS).collect();
    for (i, m) in starts.iter().enumerate() {
        let whole = m.get(0).unwrap();
        let id = format!("{} {}", latin1(&m[1]), latin1(&m[2]));
        let start = whole.end();
        let bound = starts
            .get(i + 1)
            .map_or(data.len(), |n| n.get(0).unwrap().start())
            .max(start);
        let rest = &data[start..bound];
        let end = find(rest, b"endobj").unwrap_or(rest.len());
        let body = &rest[..end];

        let (dict_bytes, stream_raw) = match stream_start(body) {
            Some((dict_end, data_start)) => {
                let raw = &body[data_start..];
                let raw_end = rfind(raw, b"endstream").unwrap_or(raw.len());
                let raw = trim_eol(&raw[..raw_end]);
                (&body[..dict_end], Some(raw))
            }
            None => (body, None),
        };
        let (text, names) = normalize_names(&latin1(dict_bytes));
        escaped.extend(names);
        let stream = stream_raw.and_then(|raw| {
            if decoded_total > MAX_TOTAL_DECODED {
                return None;
            }
            let d = decode(&text, raw);
            decoded_total += d.as_ref().map_or(0, Vec::len);
            d
        });
        if text.contains("/ObjStm") {
            if let Some(s) = &stream {
                object_streams.push((text.clone(), s.clone()));
            }
        }
        if !objects.contains_key(&id) {
            order.push(id.clone());
        }
        // A later definition (an incremental update) replaces an earlier one.
        objects.insert(id, Object { text, stream });
    }

    report.structure.object_streams = object_streams.len();
    for (dict, content) in object_streams {
        for (id, text) in objstm_objects(&dict, &content) {
            if objects.len() >= MAX_OBJECTS {
                break;
            }
            let (text, names) = normalize_names(&text);
            escaped.extend(names);
            if let std::collections::hash_map::Entry::Vacant(e) = objects.entry(id.clone()) {
                order.push(id);
                e.insert(Object { text, stream: None });
            }
        }
    }
    report.hex_escaped_names = escaped.into_iter().collect();
    Parsed { objects, order }
}

/// Where a stream's data begins: after `stream` and its end of line, when the
/// keyword follows the dictionary.
fn stream_start(body: &[u8]) -> Option<(usize, usize)> {
    let pos = find(body, b"stream")?;
    // Not "endstream" and not inside the dictionary's text.
    if pos >= 3 && &body[pos - 3..pos] == b"end" {
        return None;
    }
    let mut data = pos + "stream".len();
    if body.get(data) == Some(&b'\r') {
        data += 1;
    }
    if body.get(data) == Some(&b'\n') {
        data += 1;
    }
    Some((pos, data.min(body.len())))
}

fn trim_eol(b: &[u8]) -> &[u8] {
    let mut end = b.len();
    while end > 0 && (b[end - 1] == b'\n' || b[end - 1] == b'\r') {
        end -= 1;
    }
    &b[..end]
}

/// The objects packed in an object stream: `/N` pairs of "id offset" then the
/// objects from `/First`.
fn objstm_objects(dict: &str, content: &[u8]) -> Vec<(String, String)> {
    let num = |key: &str| -> Option<usize> {
        let re = Regex::new(&format!(r"/{key}\s+(\d+)")).ok()?;
        re.captures(dict)?.get(1)?.as_str().parse().ok()
    };
    let (Some(n), Some(first)) = (num("N"), num("First")) else {
        return Vec::new();
    };
    if first > content.len() {
        return Vec::new();
    }
    let header = latin1(&content[..first]);
    let ints: Vec<usize> = header
        .split_whitespace()
        .filter_map(|t| t.parse().ok())
        .collect();
    let pairs: Vec<(usize, usize)> = ints
        .chunks(2)
        .filter(|p| p.len() == 2)
        .map(|p| (p[0], p[1]))
        .take(n)
        .collect();
    let mut out = Vec::new();
    for (i, (num, off)) in pairs.iter().enumerate() {
        let start = first + off;
        let end = pairs.get(i + 1).map_or(content.len(), |(_, o)| first + o);
        if start <= end && end <= content.len() {
            out.push((format!("{num} 0"), latin1(&content[start..end])));
        }
    }
    out
}

// ── Values ───────────────────────────────────────────────────────────────

/// The value text after `/key` in `text`: a dictionary, array, string,
/// reference or single token.
///
/// A name can be both a value and a key (`/S /URI /URI (...)`), so a match
/// whose value is not just another name wins over one that is.
fn value_of<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    let mut first_name: Option<&'a str> = None;
    let mut search = 0;
    while let Some(rel) = text[search..].find(&format!("/{key}")) {
        let at = search + rel + key.len() + 1;
        search = at;
        // Whole name only: "/JS" must not match "/JSONData".
        if text[at..]
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphanumeric())
        {
            continue;
        }
        let rest = text[at..].trim_start();
        let offset = text.len() - rest.len();
        let Some(len) = value_len(rest) else { continue };
        let value = &text[offset..offset + len];
        if value.starts_with('/') {
            first_name.get_or_insert(value);
            continue;
        }
        return Some(value);
    }
    first_name
}

fn value_len(s: &str) -> Option<usize> {
    let b = s.as_bytes();
    match *b.first()? {
        b'<' if b.get(1) == Some(&b'<') => balanced(s, "<<", ">>"),
        b'<' => s.find('>').map(|e| e + 1),
        b'[' => balanced(s, "[", "]"),
        b'(' => literal_len(s),
        b'/' => Some(
            1 + s[1..]
                .find(|c: char| c.is_whitespace() || "/<>[]()".contains(c))
                .unwrap_or(s.len() - 1),
        ),
        b'0'..=b'9' => {
            static REF: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
            let re = REF.get_or_init(|| Regex::new(r"^\d+\s+\d+\s+R\b").unwrap());
            Some(re.find(s).map_or_else(
                || {
                    s.find(|c: char| !c.is_ascii_digit() && c != '.')
                        .unwrap_or(s.len())
                },
                |m| m.end(),
            ))
        }
        _ => Some(
            s.find(|c: char| c.is_whitespace() || "/<>[]()".contains(c))
                .unwrap_or(s.len()),
        ),
    }
}

fn balanced(s: &str, open: &str, close: &str) -> Option<usize> {
    let mut depth = 0i32;
    let mut i = 0;
    let b = s.as_bytes();
    while i < b.len() {
        if b[i] == b'(' {
            // Strings may contain brackets.
            i += literal_len(&s[i..]).unwrap_or(1);
            continue;
        }
        if s[i..].starts_with(open) {
            depth += 1;
            i += open.len();
            continue;
        }
        if s[i..].starts_with(close) {
            depth -= 1;
            i += close.len();
            if depth == 0 {
                return Some(i);
            }
            continue;
        }
        i += 1;
    }
    None
}

fn literal_len(s: &str) -> Option<usize> {
    let b = s.as_bytes();
    let mut depth = 0;
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'\\' => i += 1,
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i + 1);
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

/// Decode a PDF literal string `( ... )` (without checking the outer parens).
pub fn literal_string(s: &str) -> Vec<u8> {
    let inner = s.strip_prefix('(').unwrap_or(s);
    let inner = inner.strip_suffix(')').unwrap_or(inner);
    let b: Vec<u8> = inner.chars().map(|c| c as u32 as u8).collect();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] != b'\\' {
            out.push(b[i]);
            i += 1;
            continue;
        }
        i += 1;
        let Some(&c) = b.get(i) else { break };
        match c {
            b'n' => out.push(b'\n'),
            b'r' => out.push(b'\r'),
            b't' => out.push(b'\t'),
            b'b' => out.push(8),
            b'f' => out.push(12),
            b'\r' => {
                if b.get(i + 1) == Some(&b'\n') {
                    i += 1;
                }
            }
            b'\n' => {}
            b'0'..=b'7' => {
                let mut v = 0u32;
                let mut k = 0;
                while k < 3 && b.get(i + k).is_some_and(|d| (b'0'..=b'7').contains(d)) {
                    v = v * 8 + (b[i + k] - b'0') as u32;
                    k += 1;
                }
                out.push(v as u8);
                i += k;
                continue;
            }
            other => out.push(other),
        }
        i += 1;
    }
    out
}

/// Text of a string value: UTF-16 with a BOM, else Latin-1.
fn text_of(bytes: &[u8]) -> String {
    if bytes.starts_with(&[0xFE, 0xFF]) {
        let units: Vec<u16> = bytes[2..]
            .chunks(2)
            .filter(|p| p.len() == 2)
            .map(|p| u16::from_be_bytes([p[0], p[1]]))
            .collect();
        return String::from_utf16_lossy(&units);
    }
    latin1(bytes)
}

fn ref_id(value: &str) -> Option<String> {
    static RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r"^(\d+)\s+(\d+)\s+R").unwrap());
    let c = re.captures(value.trim())?;
    Some(format!("{} {}", &c[1], &c[2]))
}

fn refs_in(value: &str) -> Vec<String> {
    static RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r"(\d+)\s+(\d+)\s+R\b").unwrap());
    re.captures_iter(value)
        .map(|c| format!("{} {}", &c[1], &c[2]))
        .collect()
}

/// A string-ish value: a literal, a hex string, or a referenced object's
/// stream or string.
fn resolve_text(value: &str, objects: &HashMap<String, Object>) -> Option<String> {
    let v = value.trim();
    if v.starts_with('(') {
        return Some(text_of(&literal_string(v)));
    }
    if v.starts_with('<') && !v.starts_with("<<") {
        return Some(text_of(&ascii_hex(&v.as_bytes()[1..])));
    }
    let id = ref_id(v)?;
    let obj = objects.get(&id)?;
    if let Some(s) = &obj.stream {
        return Some(text_of(s));
    }
    let t = obj.text.trim();
    (t.starts_with('(') || (t.starts_with('<') && !t.starts_with("<<")))
        .then(|| resolve_text(t, objects).unwrap_or_default())
}

/// A file name from `/F` or `/UF`, directly or in a file specification.
fn file_name(value: &str, objects: &HashMap<String, Object>) -> Option<String> {
    let v = value.trim();
    if v.starts_with("<<") {
        return value_of(v, "UF")
            .or_else(|| value_of(v, "F"))
            .and_then(|f| resolve_text(f, objects));
    }
    if let Some(id) = ref_id(v) {
        let obj = objects.get(&id)?;
        if obj.text.contains("/UF") || obj.text.contains("/F") {
            return value_of(&obj.text, "UF")
                .or_else(|| value_of(&obj.text, "F"))
                .and_then(|f| resolve_text(f, objects));
        }
    }
    resolve_text(v, objects)
}

fn action_type(text: &str) -> Option<String> {
    value_of(text, "S").map(|s| s.trim_start_matches('/').to_string())
}

// ── Inspection ───────────────────────────────────────────────────────────

/// Parse the file into a report.
pub fn inspect(data: &[u8]) -> PdfReport {
    let mut report = PdfReport::new();
    let offset = header_offset(data).unwrap_or(0);
    report.structure.header_offset = offset;
    report.structure.version = data
        .get(offset + 5..offset + 8)
        .map(latin1)
        .filter(|v| v.chars().all(|c| c.is_ascii_digit() || c == '.'));
    structure_checks(data, offset, &mut report);

    let parsed = parse(data, &mut report);
    report.structure.objects = parsed.objects.len();
    if parsed.objects.is_empty() {
        report.errors.push("no PDF objects found".to_string());
        return report;
    }
    for id in &parsed.order {
        let obj = &parsed.objects[id];
        for k in KEYWORDS {
            let n = count_name(&obj.text, k);
            if n > 0 {
                *report.keywords.entry((*k).to_string()).or_default() += n;
            }
        }
        if value_of(&obj.text, "Type").is_some_and(|t| t.trim() == "/Page") {
            report.structure.pages += 1;
        }
    }
    report.structure.encrypted = report.keywords.contains_key("Encrypt");

    for name in report.hex_escaped_names.clone() {
        if EVASION_NAMES.contains(&name.as_str()) {
            report.indicate(
                "evasion",
                format!("/{name}"),
                "an action name is spelled with hex escapes to hide it from scanners",
            );
        }
    }

    let automatic = automatic_actions(&parsed, &mut report);
    collect_scripts(&parsed, &automatic, &mut report);
    collect_launches(&parsed, &automatic, &mut report);
    collect_embedded(&parsed, &mut report);
    collect_links(&parsed, &mut report);
    score(&mut report);
    report
}

fn count_name(text: &str, name: &str) -> usize {
    let pat = format!("/{name}");
    text.match_indices(&pat)
        .filter(|(i, _)| {
            !text[i + pat.len()..]
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_alphanumeric())
        })
        .count()
}

fn structure_checks(data: &[u8], offset: usize, report: &mut PdfReport) {
    let eofs = data.windows(5).filter(|w| *w == b"%%EOF").count();
    report.structure.incremental_updates = eofs.saturating_sub(1);
    if let Some(last) = rfind(data, b"%%EOF") {
        let tail = &data[last + 5..];
        report.structure.trailing_bytes = tail.iter().filter(|c| !c.is_ascii_whitespace()).count();
        if let Some(kind) = foreign_kind(tail) {
            report.structure.polyglot = Some(format!("{kind} after the end of the PDF"));
        }
    }
    if offset > 0 {
        if let Some(kind) = foreign_kind(&data[..offset]) {
            report.structure.polyglot = Some(format!("{kind} before the PDF header"));
        }
    }
}

/// A known file type at the start of `b`, or anywhere in a short tail.
fn foreign_kind(b: &[u8]) -> Option<&'static str> {
    let b = {
        let start = b
            .iter()
            .position(|c| !c.is_ascii_whitespace())
            .unwrap_or(b.len());
        &b[start..]
    };
    file_kind(b)
        .filter(|(_, exe)| *exe)
        .map(|(k, _)| k)
        .or_else(|| (b.starts_with(b"PK\x03\x04")).then_some("a zip archive"))
}

/// What a file's contents are, and whether they run.
fn file_kind(b: &[u8]) -> Option<(&'static str, bool)> {
    if b.starts_with(b"MZ") {
        return Some(("a Windows program", true));
    }
    if b.starts_with(b"\x7fELF") {
        return Some(("a Linux program", true));
    }
    if b.starts_with(&[0xCF, 0xFA, 0xED, 0xFE]) || b.starts_with(&[0xCA, 0xFE, 0xBA, 0xBE]) {
        return Some(("a macOS program", true));
    }
    if b.starts_with(b"#!") {
        return Some(("a script", true));
    }
    if b.starts_with(b"%PDF-") {
        return Some(("a PDF", false));
    }
    if b.starts_with(&[0xD0, 0xCF, 0x11, 0xE0]) {
        return Some(("an Office document", false));
    }
    if b.starts_with(b"PK\x03\x04") {
        return Some(("a zip archive or Office document", false));
    }
    None
}

fn executable_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    const EXT: &[&str] = &[
        ".exe", ".scr", ".com", ".pif", ".dll", ".cpl", ".msi", ".bat", ".cmd", ".ps1", ".vbs",
        ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta", ".lnk", ".jar", ".sh", ".app", ".iso",
        ".img", ".docm", ".xlsm", ".pptm", ".xlam", ".dotm",
    ];
    EXT.iter().any(|e| lower.ends_with(e))
}

const COMMANDS: &[&str] = &[
    "cmd.exe",
    "cmd ",
    "/c ",
    "powershell",
    "pwsh",
    "mshta",
    "wscript",
    "cscript",
    "rundll32",
    "regsvr32",
    "certutil",
    "bitsadmin",
    "msiexec",
    "schtasks",
    "curl ",
    "wget ",
    "bash ",
    "/bin/sh",
];

fn runs_command(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    COMMANDS.iter().any(|c| lower.contains(c))
        || executable_name(lower.trim_matches(|c: char| c == '"' || c.is_whitespace()))
}

fn is_unc(s: &str) -> bool {
    let t = s.trim();
    t.starts_with("\\\\")
        || t.starts_with("//") && !t.starts_with("///")
        || t.to_ascii_lowercase().starts_with("file://")
            && !t.to_ascii_lowercase().starts_with("file:///")
}

/// Object ids (and inline texts) of actions that run without a click.
struct Automatic {
    ids: BTreeSet<String>,
    inline: Vec<(String, String)>,
}

fn automatic_actions(p: &Parsed, report: &mut PdfReport) -> Automatic {
    let mut ids = BTreeSet::new();
    let mut inline = Vec::new();
    let mut queue: Vec<(String, String)> = Vec::new();

    for id in &p.order {
        let obj = &p.objects[id];
        if let Some(v) = value_of(&obj.text, "OpenAction") {
            queue.push(("OpenAction".into(), v.to_string()));
        }
        if let Some(v) = value_of(&obj.text, "AA") {
            // The /AA dictionary may itself be a separate object. Only the
            // page-open triggers run unasked; field triggers (keystroke,
            // format, calculate) are how ordinary forms work.
            let aa = ref_id(v)
                .and_then(|r| p.objects.get(&r).map(|o| o.text.clone()))
                .unwrap_or_else(|| v.to_string());
            for key in ["O", "PO", "PV"] {
                if let Some(action) = value_of(&aa, key) {
                    queue.push(("AA".into(), action.to_string()));
                }
            }
        }
    }

    let mut seen = 0;
    while let Some((trigger, value)) = queue.pop() {
        seen += 1;
        if seen > 500 {
            break;
        }
        let mut candidates: Vec<(Option<String>, String)> = Vec::new();
        let v = value.trim();
        if v.starts_with("<<") {
            // An inline action; references inside it are its own values.
            candidates.push((None, v.to_string()));
        } else {
            // A reference, or an array of them (/Next can be either).
            for r in refs_in(v) {
                if let Some(o) = p.objects.get(&r) {
                    candidates.push((Some(r), o.text.clone()));
                }
            }
        }
        for (rid, text) in candidates {
            let Some(kind) = action_type(&text) else {
                // An OpenAction can be a destination array (go to a page).
                continue;
            };
            if let Some(r) = &rid {
                if !ids.insert(r.clone()) {
                    continue;
                }
            } else {
                inline.push((trigger.clone(), text.clone()));
            }
            let target = match kind.as_str() {
                "URI" => value_of(&text, "URI").and_then(|u| resolve_text(u, &p.objects)),
                "Launch" | "GoToR" | "GoToE" | "ImportData" | "SubmitForm" => value_of(&text, "F")
                    .and_then(|f| file_name(f, &p.objects))
                    .or_else(|| {
                        value_of(&text, "Win")
                            .and_then(|w| value_of(w, "F"))
                            .and_then(|f| resolve_text(f, &p.objects))
                    }),
                "JavaScript" => None,
                _ => None,
            };
            if kind != "GoTo" {
                report.auto_actions.push(AutoAction {
                    trigger: trigger.clone(),
                    action: kind.clone(),
                    target,
                });
            }
            if let Some(next) = value_of(&text, "Next") {
                queue.push((trigger.clone(), next.to_string()));
            }
        }
    }
    Automatic { ids, inline }
}

fn collect_scripts(p: &Parsed, auto: &Automatic, report: &mut PdfReport) {
    let push = |report: &mut PdfReport, object: String, automatic: bool, source: String| {
        if report.scripts.len() >= MAX_SCRIPTS || source.trim().is_empty() {
            return;
        }
        let preview: String = source.chars().take(SCRIPT_PREVIEW_CHARS).collect();
        report.scripts.push(Script {
            object,
            automatic,
            bytes: source.len(),
            preview,
        });
        score_script(report, &source, automatic);
    };

    for id in &p.order {
        let obj = &p.objects[id];
        if let Some(v) = value_of(&obj.text, "JS") {
            let source = resolve_text(v, &p.objects).unwrap_or_default();
            let automatic = auto.ids.contains(id);
            push(report, id.clone(), automatic, source);
        }
    }
    for (trigger, text) in &auto.inline {
        if let Some(v) = value_of(text, "JS") {
            let source = resolve_text(v, &p.objects).unwrap_or_default();
            push(report, trigger.clone(), true, source);
        }
    }
    // XFA forms carry script in their XML.
    static XFA_SCRIPT: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    let re = XFA_SCRIPT.get_or_init(|| Regex::new(r"(?is)<script[^>]*>(.*?)</script>").unwrap());
    for id in &p.order {
        let Some(s) = &p.objects[id].stream else {
            continue;
        };
        let text = latin1(&s[..s.len().min(MAX_STREAM_BYTES)]);
        if text.contains("<xdp:xdp") || text.contains("xfa") && text.contains("<script") {
            for c in re.captures_iter(&text).take(MAX_SCRIPTS) {
                // XFA scripts in initialize/docReady events run on open.
                push(
                    report,
                    format!("XFA ({id})"),
                    text.contains("initialize") || text.contains("docReady"),
                    c[1].to_string(),
                );
            }
        }
    }
}

/// Script patterns: (kind, regex, description).
fn script_patterns() -> &'static [(&'static str, Regex, &'static str)] {
    static P: std::sync::OnceLock<Vec<(&'static str, Regex, &'static str)>> =
        std::sync::OnceLock::new();
    P.get_or_init(|| {
        let p = |k: &'static str, re: &str, d: &'static str| (k, Regex::new(re).unwrap(), d);
        vec![
            p(
                "exploit",
                r#"util\.printf\s*\(\s*["']%\s*\d{3,}"#,
                "util.printf with a huge width (CVE-2008-2992)",
            ),
            p(
                "exploit",
                r"Collab\.getIcon\s*\(",
                "Collab.getIcon (CVE-2009-0927)",
            ),
            p(
                "exploit",
                r"Collab\.collectEmailInfo\s*\(",
                "Collab.collectEmailInfo (CVE-2007-5659)",
            ),
            p(
                "exploit",
                r"media\.newPlayer\s*\(",
                "media.newPlayer (CVE-2009-4324)",
            ),
            p(
                "exploit",
                r"spell\.customDictionaryOpen\s*\(",
                "spell.customDictionaryOpen (CVE-2009-1493)",
            ),
            p("exploit", r"\.printSeps\s*\(", "printSeps (CVE-2010-4091)"),
            p(
                "shellcode",
                r"(?i)%u0c0c%u0c0c|%u0a0a%u0a0a|%u9090%u9090|0x0c0c0c0c",
                "heap-spray pattern",
            ),
            p(
                "obfuscation",
                r"\beval\s*\(",
                "eval: runs code built at run time",
            ),
            p(
                "obfuscation",
                r"\bunescape\s*\(",
                "unescape: decodes hidden text or shellcode",
            ),
            p(
                "obfuscation",
                r"String\.fromCharCode\s*\(",
                "String.fromCharCode: builds text from numbers",
            ),
            p(
                "obfuscation",
                r"this\.info\.|getField\([^)]*\)\.value\s*\)",
                "reads hidden data from document fields",
            ),
            p(
                "drop",
                r"exportDataObject\s*\([^)]*nLaunch",
                "exportDataObject with nLaunch: saves and opens an embedded file",
            ),
            p(
                "network",
                r"app\.launchURL\s*\(",
                "app.launchURL: opens a web page",
            ),
            p(
                "network",
                r"\bsubmitForm\s*\(|SOAP\.request|Net\.HTTP",
                "sends data to a server",
            ),
        ]
    })
}

fn score_script(report: &mut PdfReport, source: &str, automatic: bool) {
    for (kind, re, desc) in script_patterns() {
        if let Some(m) = re.find(source) {
            report.indicate(kind, m.as_str().chars().take(60).collect::<String>(), *desc);
        }
    }
    // Long runs of %u escapes are shellcode.
    if source.matches("%u").count() >= 64 {
        report.indicate("shellcode", "%u…", "long %u-escaped sequence (shellcode)");
    }
    if automatic {
        report.indicate(
            "autorun",
            "JavaScript",
            "JavaScript runs when the document opens",
        );
    }
}

fn collect_launches(p: &Parsed, auto: &Automatic, report: &mut PdfReport) {
    let mut items: Vec<(String, String, bool)> = p
        .order
        .iter()
        .filter(|id| action_type(&p.objects[*id].text).as_deref() == Some("Launch"))
        .map(|id| {
            (
                id.clone(),
                p.objects[id].text.clone(),
                auto.ids.contains(id),
            )
        })
        .collect();
    for (trigger, text) in &auto.inline {
        if action_type(text).as_deref() == Some("Launch") {
            items.push((trigger.clone(), text.clone(), true));
        }
    }
    for (object, text, automatic) in items {
        let win = value_of(&text, "Win");
        let target = win
            .and_then(|w| value_of(w, "F"))
            .and_then(|f| resolve_text(f, &p.objects))
            .or_else(|| value_of(&text, "F").and_then(|f| file_name(f, &p.objects)));
        let parameters = win
            .and_then(|w| value_of(w, "P"))
            .and_then(|v| resolve_text(v, &p.objects));
        let joined = format!(
            "{} {}",
            target.clone().unwrap_or_default(),
            parameters.clone().unwrap_or_default()
        );
        let runs = runs_command(&joined);
        if target.as_deref().is_some_and(is_unc) {
            report.unc_paths.push(target.clone().unwrap_or_default());
        }
        report.indicate(
            "launch",
            target
                .clone()
                .unwrap_or_else(|| "Launch".to_string())
                .chars()
                .take(80)
                .collect::<String>(),
            if runs {
                "Launch action runs a program or command"
            } else {
                "Launch action opens a file or program"
            },
        );
        report.launch_actions.push(LaunchAction {
            object,
            target,
            parameters,
            automatic,
            runs_command: runs,
        });
    }
}

fn collect_embedded(p: &Parsed, report: &mut PdfReport) {
    // File specifications name the embedded streams they point to.
    let mut names: HashMap<String, String> = HashMap::new();
    for id in &p.order {
        let t = &p.objects[id].text;
        if let Some(ef) = value_of(t, "EF") {
            let name = value_of(t, "UF")
                .or_else(|| {
                    value_of(t, "F").filter(|v| !v.trim_start().starts_with(char::is_numeric))
                })
                .and_then(|v| resolve_text(v, &p.objects));
            for r in refs_in(ef) {
                if let Some(n) = &name {
                    names.insert(r, n.clone());
                }
            }
        }
    }
    for id in &p.order {
        let obj = &p.objects[id];
        if !value_of(&obj.text, "Type").is_some_and(|t| t.trim() == "/EmbeddedFile") {
            continue;
        }
        let data = obj.stream.as_deref().unwrap_or(&[]);
        let name = names.get(id).cloned();
        let kind = file_kind(data);
        let executable =
            kind.is_some_and(|(_, exe)| exe) || name.as_deref().is_some_and(executable_name);
        let label = kind.map(|(k, _)| k.to_string()).or_else(|| {
            name.as_deref()
                .filter(|n| executable_name(n))
                .map(|_| "a script or program".to_string())
        });
        if executable {
            report.indicate(
                "embedded",
                name.clone().unwrap_or_else(|| id.clone()),
                format!(
                    "embeds {}",
                    label.clone().unwrap_or_else(|| "a program".into())
                ),
            );
        }
        report.embedded_files.push(EmbeddedFile {
            name,
            bytes: data.len(),
            kind: label,
            executable,
        });
    }
}

fn collect_links(p: &Parsed, report: &mut PdfReport) {
    let mut uris = BTreeSet::new();
    for id in &p.order {
        let t = &p.objects[id].text;
        if let Some(v) = value_of(t, "URI") {
            if let Some(u) = resolve_text(v, &p.objects) {
                let u = u.trim().to_string();
                if !u.is_empty() {
                    uris.insert(u);
                }
            }
        }
        // Remote go-to and form targets can point at a share.
        if matches!(
            action_type(t).as_deref(),
            Some("GoToR") | Some("GoToE") | Some("SubmitForm") | Some("ImportData")
        ) {
            if let Some(f) = value_of(t, "F").and_then(|f| file_name(f, &p.objects)) {
                if is_unc(&f) {
                    report.unc_paths.push(f);
                }
            }
        }
    }
    for u in &uris {
        if is_unc(u) {
            report.unc_paths.push(u.clone());
        }
        let lower = u.to_ascii_lowercase();
        if lower.starts_with("javascript:") || lower.starts_with("data:") {
            report.indicate(
                "evasion",
                u.chars().take(60).collect::<String>(),
                "link runs script or carries data",
            );
        }
    }
    report.uris = uris.into_iter().take(MAX_URIS).collect();
    report.unc_paths.sort();
    report.unc_paths.dedup();
    if !report.unc_paths.is_empty() {
        let first = report.unc_paths[0].clone();
        report.indicate(
            "network",
            first,
            "points at a network share, which can leak Windows credentials",
        );
    }
}

/// Indicators that come from actions rather than script.
fn score(report: &mut PdfReport) {
    let autos = report.auto_actions.clone();
    for a in autos {
        match a.action.as_str() {
            "URI" | "SubmitForm" | "ImportData" | "GoToR" | "GoToE" => report.indicate(
                "autorun",
                format!("{} {}", a.action, a.target.unwrap_or_default())
                    .trim()
                    .to_string(),
                "opens a link, file or form target when the document opens",
            ),
            "Launch" => report.indicate(
                "autorun",
                "Launch",
                "launches something when the document opens",
            ),
            _ => {}
        }
    }
    if report.keywords.contains_key("RichMedia") {
        report.indicate(
            "embedded",
            "RichMedia",
            "embeds Flash or other rich media, an old exploit route",
        );
    }
    if let Some(p) = report.structure.polyglot.clone() {
        report.indicate("evasion", "polyglot", format!("contains {p}"));
    }
    report.indicators.sort();
}

// ── Verdict ──────────────────────────────────────────────────────────────

struct Assessment {
    verdict: ThreatVerdict,
    severity: SeverityLevel,
    confidence: f32,
    strong: bool,
    reasons: Vec<String>,
}

fn obfuscation_count(r: &PdfReport) -> usize {
    r.indicators
        .iter()
        .filter(|i| i.kind == "obfuscation")
        .count()
}

fn assess(r: &PdfReport) -> Assessment {
    let mut reasons = Vec::new();
    let auto_script = r.scripts.iter().any(|s| s.automatic);
    let obfuscated = obfuscation_count(r) >= 2
        || r.indicators
            .iter()
            .any(|i| i.kind == "obfuscation" && i.keyword.starts_with("eval"));
    let launch_runs = r.launch_actions.iter().any(|l| l.runs_command);
    let embedded_exe = r.embedded_files.iter().any(|e| e.executable);

    let mut malicious = false;
    if r.has("exploit") {
        malicious = true;
        reasons.push("JavaScript calls an API used by known Acrobat exploits".to_string());
    }
    if r.has("shellcode") {
        malicious = true;
        reasons.push("JavaScript carries shellcode or a heap spray".to_string());
    }
    if auto_script && obfuscated {
        malicious = true;
        reasons.push("obfuscated JavaScript runs when the document opens".to_string());
    }
    if launch_runs {
        malicious = true;
        reasons.push("a Launch action runs a program or command".to_string());
    }
    if r.has("drop") && embedded_exe {
        malicious = true;
        reasons.push("script saves an embedded program and opens it".to_string());
    }
    if r.launch_actions.iter().any(|l| l.automatic) && embedded_exe {
        malicious = true;
        reasons.push("launches an embedded program when the document opens".to_string());
    }
    if malicious {
        return Assessment {
            verdict: ThreatVerdict::Malicious,
            severity: SeverityLevel::High,
            confidence: 0.9,
            strong: true,
            reasons,
        };
    }

    if auto_script {
        reasons.push("JavaScript runs when the document opens".to_string());
    }
    if !r.launch_actions.is_empty() {
        reasons.push("contains a Launch action".to_string());
    }
    if embedded_exe {
        reasons.push("embeds a program or script".to_string());
    }
    if obfuscated {
        reasons.push("JavaScript is obfuscated".to_string());
    }
    if r.has("evasion") {
        let what: Vec<&str> = r
            .indicators
            .iter()
            .filter(|i| i.kind == "evasion")
            .map(|i| i.description.as_str())
            .collect();
        reasons.push(format!("hides its structure: {}", what.join("; ")));
    }
    if r.auto_actions.iter().any(|a| {
        matches!(
            a.action.as_str(),
            "URI" | "SubmitForm" | "ImportData" | "GoToR" | "GoToE"
        )
    }) {
        reasons.push("opens a link or remote target by itself".to_string());
    }
    if !r.unc_paths.is_empty() {
        reasons.push("points at a network share, which can leak Windows credentials".to_string());
    }
    if r.has("drop") {
        reasons.push("script can save and open an embedded file".to_string());
    }
    if r.keywords.contains_key("RichMedia") {
        reasons.push("embeds Flash or rich media".to_string());
    }
    if !reasons.is_empty() {
        return Assessment {
            verdict: ThreatVerdict::Suspicious,
            severity: SeverityLevel::Medium,
            confidence: 0.7,
            strong: false,
            reasons,
        };
    }

    if r.structure.objects == 0 {
        return Assessment {
            verdict: ThreatVerdict::Unknown,
            severity: SeverityLevel::Info,
            confidence: 0.0,
            strong: false,
            reasons: vec![format!("could not be inspected: {}", r.errors.join("; "))],
        };
    }

    let mut notes = Vec::new();
    if r.scripts.is_empty() {
        notes.push("no JavaScript, launch actions or embedded programs".to_string());
    } else {
        notes.push(format!(
            "{} script(s), none that runs on open, is obfuscated or calls exploit APIs",
            r.scripts.len()
        ));
    }
    if !r.uris.is_empty() {
        notes.push(format!("{} link(s)", r.uris.len()));
    }
    let mut confidence = 0.75;
    if r.structure.encrypted {
        notes.push("encrypted, so stream contents couldn't all be checked".to_string());
        confidence = 0.5;
    }
    Assessment {
        verdict: ThreatVerdict::Benign,
        severity: SeverityLevel::Info,
        confidence,
        strong: false,
        reasons: notes,
    }
}

fn detection(r: &PdfReport, processing_time_ms: u64) -> DetectionResult {
    let a = assess(r);
    let mut metadata = HashMap::new();
    let mut put = |k: &str, v: serde_json::Value| {
        metadata.insert(k.to_string(), v);
    };
    put("summary", serde_json::json!(a.reasons.join("; ")));
    put("pdfStructure", serde_json::json!(r.structure));
    put("pdfKeywords", serde_json::json!(r.keywords));
    put("hexEscapedNames", serde_json::json!(r.hex_escaped_names));
    put("autoActions", serde_json::json!(r.auto_actions));
    put("scripts", serde_json::json!(r.scripts));
    put("launchActions", serde_json::json!(r.launch_actions));
    put("embeddedFiles", serde_json::json!(r.embedded_files));
    put("uris", serde_json::json!(r.uris));
    put("uncPaths", serde_json::json!(r.unc_paths));
    put("indicators", serde_json::json!(r.indicators));
    let mut iocs: Vec<String> = r.uris.clone();
    iocs.extend(r.unc_paths.iter().cloned());
    iocs.extend(r.launch_actions.iter().filter_map(|l| l.target.clone()));
    iocs.sort();
    iocs.dedup();
    put("iocs", serde_json::json!(iocs));
    if !r.errors.is_empty() {
        put("parseErrors", serde_json::json!(r.errors));
    }
    put(STRONG_SIGNAL_KEY, serde_json::json!(a.strong));
    if a.verdict == ThreatVerdict::Unknown {
        put("status", serde_json::json!("unavailable"));
        put("reason", serde_json::json!(a.reasons.join("; ")));
    }

    DetectionResult {
        detection_id: Uuid::new_v4(),
        engine_name: ENGINE_NAME.to_string(),
        engine_version: ENGINE_VERSION.to_string(),
        engine_type: EngineType::Static,
        categories: match a.verdict {
            ThreatVerdict::Malicious | ThreatVerdict::Suspicious => vec![ThreatCategory::Malware],
            _ => vec![],
        },
        error_message: (a.verdict == ThreatVerdict::Unknown).then(|| a.reasons.join("; ")),
        verdict: a.verdict,
        confidence: a.confidence,
        severity: a.severity,
        metadata,
        detected_at: Utc::now(),
        processing_time_ms: processing_time_ms.max(1),
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use std::io::Write;

    /// A minimal PDF from object bodies ("<< ... >>" or "<< ... >>\nstream\n...\nendstream").
    pub fn pdf(objects: &[&[u8]]) -> Vec<u8> {
        let mut out = b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n".to_vec();
        for (i, body) in objects.iter().enumerate() {
            writeln!(out, "{} 0 obj", i + 1).unwrap();
            out.extend_from_slice(body);
            out.extend_from_slice(b"\nendobj\n");
        }
        out.extend_from_slice(b"trailer\n<< /Root 1 0 R >>\n%%EOF\n");
        out
    }

    pub fn deflate(data: &[u8]) -> Vec<u8> {
        let mut e = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    pub fn stream_obj(dict: &str, data: &[u8]) -> Vec<u8> {
        let mut o = format!("<< {dict} /Length {} >>\nstream\n", data.len()).into_bytes();
        o.extend_from_slice(data);
        o.extend_from_slice(b"\nendstream");
        o
    }

    const CATALOG: &[u8] = b"<< /Type /Catalog /Pages 2 0 R >>";
    const PAGES: &[u8] = b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>";
    const PAGE: &[u8] = b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>";

    fn verdict(data: &[u8]) -> ThreatVerdict {
        analyze(data).unwrap().verdict
    }

    #[test]
    fn non_pdfs_are_ignored() {
        assert!(analyze(b"MZ\x90\x00 not a pdf").is_none());
        assert!(analyze(b"").is_none());
        // Junk before the header is still a PDF.
        let mut junk = vec![b'x'; 100];
        junk.extend(pdf(&[CATALOG, PAGES, PAGE]));
        assert!(analyze(&junk).is_some());
    }

    #[test]
    fn a_plain_document_is_benign() {
        let d = analyze(&pdf(&[CATALOG, PAGES, PAGE])).unwrap();
        assert_eq!(d.verdict, ThreatVerdict::Benign);
        assert_eq!(d.metadata["pdfStructure"]["pages"], 1);
        assert_eq!(d.metadata["pdfStructure"]["version"], "1.7");
    }

    #[test]
    fn obfuscated_javascript_on_open_is_malicious() {
        let js = b"<< /Type /Action /S /JavaScript /JS (var s = unescape('%61%6c%65%72%74'); eval(s);) >>";
        let catalog = b"<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>";
        let d = analyze(&pdf(&[catalog, PAGES, PAGE, js])).unwrap();
        assert_eq!(
            d.verdict,
            ThreatVerdict::Malicious,
            "{:?}",
            d.metadata["summary"]
        );
        assert_eq!(d.metadata[STRONG_SIGNAL_KEY], true);
        assert_eq!(d.metadata["scripts"][0]["automatic"], true);
    }

    #[test]
    fn form_javascript_alone_is_benign() {
        // A calculate trigger (/C) runs on input, not on open.
        let field = b"<< /FT /Tx /T (total) /AA << /C << /S /JavaScript /JS (AFSimple_Calculate\\(\"SUM\", new Array \\(\"a\", \"b\"\\)\\);) >> >> >>";
        let d = analyze(&pdf(&[CATALOG, PAGES, PAGE, field])).unwrap();
        assert_eq!(
            d.verdict,
            ThreatVerdict::Benign,
            "{:?}",
            d.metadata["summary"]
        );
        assert_eq!(d.metadata["scripts"][0]["automatic"], false);
        // A page-open trigger (/O) does run on open.
        let page = b"<< /Type /Page /Parent 2 0 R /AA << /O << /S /JavaScript /JS (eval(unescape('%61'))) >> >> >>";
        assert_eq!(
            verdict(&pdf(&[CATALOG, PAGES, page])),
            ThreatVerdict::Malicious
        );
        let plain = b"<< /S /JavaScript /JS (this.print\\(\\);) >>";
        assert_eq!(
            verdict(&pdf(&[CATALOG, PAGES, PAGE, plain])),
            ThreatVerdict::Benign
        );
    }

    #[test]
    fn javascript_hidden_in_a_compressed_object_stream_is_found() {
        // Object 9 exists only inside object stream 5, compressed.
        let inner = b"<< /Type /Action /S /JavaScript /JS (eval(String.fromCharCode(97,108,101,114,116));) >>";
        let header = b"9 0 ";
        let mut content = header.to_vec();
        let first = content.len();
        content.extend_from_slice(inner);
        let objstm = stream_obj(
            &format!("/Type /ObjStm /N 1 /First {first} /Filter /FlateDecode"),
            &deflate(&content),
        );
        let catalog = b"<< /Type /Catalog /Pages 2 0 R /OpenAction 9 0 R >>";
        let d = analyze(&pdf(&[catalog, PAGES, PAGE, b"<< >>", &objstm])).unwrap();
        assert_eq!(
            d.verdict,
            ThreatVerdict::Malicious,
            "{:?}",
            d.metadata["summary"]
        );
        assert_eq!(d.metadata["pdfStructure"]["objectStreams"], 1);
    }

    #[test]
    fn javascript_in_a_referenced_stream_is_read() {
        let script = deflate(b"var x = 1; util.printf(\"%45000f\", num);");
        let js_stream = stream_obj("/Filter /FlateDecode", &script);
        let action = b"<< /S /JavaScript /JS 5 0 R >>";
        let d = analyze(&pdf(&[CATALOG, PAGES, PAGE, action, &js_stream])).unwrap();
        assert_eq!(d.verdict, ThreatVerdict::Malicious);
        assert!(d.metadata["summary"].as_str().unwrap().contains("exploit"));
        // A normal util.printf is fine.
        let ok = stream_obj("", b"util.printf(\"%.2f\", total);");
        assert_eq!(
            verdict(&pdf(&[CATALOG, PAGES, PAGE, action, &ok])),
            ThreatVerdict::Benign
        );
    }

    #[test]
    fn hex_escaped_names_are_undone_and_reported() {
        let js = b"<< /S /J#61vaScript /J#53 (app.alert\\(1\\)) >>";
        let catalog = b"<< /Type /Catalog /Pages 2 0 R /Open#41ction 4 0 R >>";
        let d = analyze(&pdf(&[catalog, PAGES, PAGE, js])).unwrap();
        assert_eq!(
            d.verdict,
            ThreatVerdict::Suspicious,
            "{:?}",
            d.metadata["summary"]
        );
        let names: Vec<String> =
            serde_json::from_value(d.metadata["hexEscapedNames"].clone()).unwrap();
        assert!(
            names.contains(&"JavaScript".to_string()) && names.contains(&"OpenAction".to_string())
        );
        assert_eq!(d.metadata["scripts"][0]["automatic"], true);
    }

    #[test]
    fn launch_actions_that_run_commands_are_malicious() {
        let launch = b"<< /S /Launch /Win << /F (cmd.exe) /P (/c powershell -enc AAAA) >> >>";
        let catalog = b"<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>";
        let d = analyze(&pdf(&[catalog, PAGES, PAGE, launch])).unwrap();
        assert_eq!(d.verdict, ThreatVerdict::Malicious);
        assert_eq!(d.metadata["launchActions"][0]["target"], "cmd.exe");
        assert_eq!(d.metadata["launchActions"][0]["automatic"], true);
        // Opening another PDF is only suspicious.
        let other = b"<< /S /Launch /F (manual.pdf) >>";
        assert_eq!(
            verdict(&pdf(&[CATALOG, PAGES, PAGE, other])),
            ThreatVerdict::Suspicious
        );
    }

    #[test]
    fn embedded_programs_that_get_opened_are_malicious() {
        let exe = stream_obj(
            "/Type /EmbeddedFile",
            b"MZ\x90\x00\x03\x00\x00\x00 this program cannot be run",
        );
        let spec = b"<< /Type /Filespec /F (invoice.exe) /EF << /F 5 0 R >> >>";
        let js = b"<< /S /JavaScript /JS (this.exportDataObject\\({ cName: \"invoice.exe\", nLaunch: 2 }\\);) >>";
        let catalog = b"<< /Type /Catalog /Pages 2 0 R /OpenAction 7 0 R >>";
        let d = analyze(&pdf(&[catalog, PAGES, PAGE, spec, &exe, b"<< >>", js])).unwrap();
        assert_eq!(
            d.verdict,
            ThreatVerdict::Malicious,
            "{:?}",
            d.metadata["summary"]
        );
        assert_eq!(d.metadata["embeddedFiles"][0]["name"], "invoice.exe");
        assert_eq!(d.metadata["embeddedFiles"][0]["executable"], true);
        // Embedded alone is suspicious.
        assert_eq!(
            verdict(&pdf(&[CATALOG, PAGES, PAGE, spec, &exe])),
            ThreatVerdict::Suspicious
        );
        // An embedded spreadsheet is fine.
        let csv = stream_obj("/Type /EmbeddedFile", b"a,b\n1,2\n");
        let spec = b"<< /Type /Filespec /F (data.csv) /EF << /F 5 0 R >> >>";
        assert_eq!(
            verdict(&pdf(&[CATALOG, PAGES, PAGE, spec, &csv])),
            ThreatVerdict::Benign
        );
    }

    #[test]
    fn links_are_listed_and_unc_paths_flagged() {
        let link =
            b"<< /Type /Annot /Subtype /Link /A << /S /URI /URI (https://example.com/login) >> >>";
        let d = analyze(&pdf(&[CATALOG, PAGES, PAGE, link])).unwrap();
        assert_eq!(d.verdict, ThreatVerdict::Benign);
        assert_eq!(d.metadata["uris"][0], "https://example.com/login");
        assert_eq!(d.metadata["iocs"][0], "https://example.com/login");

        let unc = b"<< /S /GoToR /F (\\\\\\\\203.0.113.5\\\\share\\\\x.pdf) /D [0 /Fit] >>";
        let d = analyze(&pdf(&[CATALOG, PAGES, PAGE, unc])).unwrap();
        assert_eq!(d.verdict, ThreatVerdict::Suspicious, "{:?}", d.metadata);
        assert!(d.metadata["uncPaths"][0]
            .as_str()
            .unwrap()
            .starts_with("\\\\203.0.113.5"));

        // A link that opens on its own.
        let catalog = b"<< /Type /Catalog /Pages 2 0 R /OpenAction << /S /URI /URI (http://198.51.100.7/a) >> >>";
        assert_eq!(
            verdict(&pdf(&[catalog, PAGES, PAGE])),
            ThreatVerdict::Suspicious
        );
    }

    #[test]
    fn heap_sprays_are_malicious() {
        let spray = format!(
            "<< /S /JavaScript /JS (var sc = unescape(\"{}\");) >>",
            "%u0c0c".repeat(80)
        );
        assert_eq!(
            verdict(&pdf(&[CATALOG, PAGES, PAGE, spray.as_bytes()])),
            ThreatVerdict::Malicious
        );
    }

    #[test]
    fn programs_hidden_after_the_end_are_reported() {
        let mut data = pdf(&[CATALOG, PAGES, PAGE]);
        data.extend_from_slice(b"MZ\x90\x00 hidden program");
        let d = analyze(&data).unwrap();
        assert_eq!(d.verdict, ThreatVerdict::Suspicious);
        assert!(d.metadata["pdfStructure"]["polyglot"]
            .as_str()
            .unwrap()
            .contains("Windows program"));
    }

    #[test]
    fn garbage_is_unknown_not_a_crash() {
        let d = analyze(b"%PDF-1.4\n\x00\x01\x02 not really").unwrap();
        assert_eq!(d.verdict, ThreatVerdict::Unknown);
        assert_eq!(d.metadata["status"], "unavailable");
        // Truncated everywhere: never panics.
        let full = pdf(&[CATALOG, PAGES, PAGE, b"<< /S /JavaScript /JS (eval(x)) >>"]);
        for cut in (0..full.len()).step_by(7) {
            let _ = analyze(&full[..cut]);
        }
    }

    #[test]
    fn many_unterminated_objects_parse_quickly() {
        let mut data = b"%PDF-1.4\n".to_vec();
        for i in 0..40_000 {
            data.extend_from_slice(format!("{i} 0 obj << /Type /X >>\n").as_bytes());
        }
        data.extend(vec![b'A'; 4 * 1024 * 1024]);
        let t = std::time::Instant::now();
        let d = analyze(&data).unwrap();
        assert!(t.elapsed().as_secs() < 10, "took {:?}", t.elapsed());
        assert_eq!(d.metadata["pdfStructure"]["objects"], 40_000);
    }

    #[test]
    fn encodings_decode() {
        assert_eq!(ascii_hex(b"48 65 6C6c6F>"), b"Hello");
        assert_eq!(ascii_hex(b"4>"), vec![0x40]);
        assert_eq!(ascii85(b"<~87cURD]i,\"Ebo80~>"), b"Hello World!");
        assert_eq!(ascii85(b"z~>"), vec![0, 0, 0, 0]);
        assert_eq!(literal_string("(a\\(b\\) \\101\\n\\\\)"), b"a(b) A\n\\");
        assert_eq!(text_of(&[0xFE, 0xFF, 0, b'h', 0, b'i']), "hi");
        let (n, esc) = normalize_names("/J#61vaScript /Plain /A#2fB");
        assert_eq!(n, "/JavaScript /Plain /A/B");
        assert_eq!(esc, vec!["JavaScript".to_string(), "A/B".to_string()]);
    }

    #[test]
    fn chained_filters_and_encryption() {
        let hexed: String = deflate(b"eval(unescape('%65'))")
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
            + ">";
        let s = stream_obj("/Filter [/ASCIIHexDecode /FlateDecode]", hexed.as_bytes());
        let action = b"<< /S /JavaScript /JS 5 0 R >>";
        let catalog = b"<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>";
        assert_eq!(
            verdict(&pdf(&[catalog, PAGES, PAGE, action, &s])),
            ThreatVerdict::Malicious
        );

        let enc = b"<< /Type /Catalog /Pages 2 0 R /Encrypt 4 0 R >>";
        let d = analyze(&pdf(&[enc, PAGES, PAGE, b"<< /Filter /Standard /V 2 >>"])).unwrap();
        assert_eq!(d.verdict, ThreatVerdict::Benign);
        assert_eq!(d.metadata["pdfStructure"]["encrypted"], true);
        assert!(d.confidence < 0.75);
    }
}
