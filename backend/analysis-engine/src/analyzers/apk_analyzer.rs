//! Android app (APK) analysis.
//!
//! An APK is a zip the archive unpacker deliberately leaves alone, and its
//! two most telling parts are unreadable to the byte-level engines: the
//! manifest is binary XML, and the code is DEX. This analyzer reads both:
//!
//! - **Manifest** (binary AXML): package, SDK levels, requested permissions,
//!   and every component with its intent filters, so it can see an
//!   accessibility service, a device-admin receiver, a notification
//!   listener, a boot receiver, and whether the app has a launcher icon at
//!   all. Attribute names are resolved through the resource map, so
//!   manifests with their names stripped (a common anti-analysis trick)
//!   still parse.
//! - **Code** (`classes*.dex`): Android APIs found in the DEX string table:
//!   SMS sending and reading, dynamic code loading, root (`su`), hiding the
//!   app icon, accessibility gestures, device-admin lock and wipe, package
//!   installation, Telegram bot exfiltration, mining pools.
//! - **Packaging:** commercial packers in `lib/`, payload APK/DEX/ELF files
//!   hidden in `assets/` or `res/raw/`, v1 and v2+ signatures, and debug
//!   signing certificates.
//!
//! Banking trojans, SMS-fraud apps and droppers are recognised by the
//! *combination* they need (for example accessibility plus overlay plus SMS),
//! not by any one permission: ordinary apps ask for the camera, contacts and
//! location every day.
//!
//! Reads are size-capped and parsing runs under `catch_unwind`.

use std::collections::BTreeSet;
use std::collections::HashMap;
use std::io::{Cursor, Read};

use chrono::Utc;
use regex::bytes::{Regex as BytesRegex, RegexSet};
use serde::Serialize;
use uuid::Uuid;

use crate::models::analysis_result::{
    DetectionResult, EngineType, SeverityLevel, ThreatCategory, ThreatVerdict, STRONG_SIGNAL_KEY,
};

pub const ENGINE_NAME: &str = "Android App Analyzer";
const ENGINE_VERSION: &str = "1.0.0";

const ZIP_MAGIC: &[u8] = b"PK\x03\x04";
/// Largest manifest read.
const MAX_MANIFEST_BYTES: u64 = 4 * 1024 * 1024;
/// Largest DEX file read; bigger ones are scanned up to this size.
const MAX_DEX_BYTES: u64 = 32 * 1024 * 1024;
/// DEX files scanned (multidex apps have several).
const MAX_DEX_FILES: usize = 12;
/// Zip entries inspected.
const MAX_ENTRIES: usize = 20_000;
/// Elements read from the manifest.
const MAX_ELEMENTS: usize = 20_000;

/// True when `data` is an APK: a zip with a root `AndroidManifest.xml` and
/// app code or resources.
pub fn is_apk(data: &[u8]) -> bool {
    if !data.starts_with(ZIP_MAGIC) {
        return false;
    }
    let Ok(archive) = zip::ZipArchive::new(Cursor::new(data)) else {
        return false;
    };
    archive.index_for_name("AndroidManifest.xml").is_some()
        && (archive.index_for_name("classes.dex").is_some()
            || archive.index_for_name("resources.arsc").is_some())
}

// ── Report ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize)]
pub struct Component {
    /// activity, activity-alias, service, receiver or provider.
    pub kind: String,
    pub name: String,
    /// Permission a caller needs, e.g. BIND_ACCESSIBILITY_SERVICE.
    pub permission: Option<String>,
    pub actions: Vec<String>,
    pub categories: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Manifest {
    pub package: Option<String>,
    pub version_name: Option<String>,
    pub min_sdk: Option<u32>,
    pub target_sdk: Option<u32>,
    pub permissions: Vec<String>,
    pub components: Vec<Component>,
    pub debuggable: bool,
    pub allow_backup: Option<bool>,
    pub cleartext_traffic: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct Indicator {
    pub kind: &'static str,
    pub evidence: String,
    pub description: &'static str,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Signing {
    /// JAR signature (META-INF/*.RSA, *.DSA, *.EC).
    pub v1: bool,
    /// APK Signature Scheme v2/v3 block.
    pub v2_plus: bool,
    /// Signed with Android's debug certificate.
    pub debug_certificate: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ApkReport {
    pub manifest: Option<Manifest>,
    pub dex_files: usize,
    pub apis: Vec<Indicator>,
    pub native_abis: Vec<String>,
    pub native_libraries: Vec<String>,
    pub packers: Vec<String>,
    pub embedded_payloads: Vec<String>,
    pub signing: Signing,
    pub iocs: Vec<String>,
    pub errors: Vec<String>,
}

// ── Entry point ──────────────────────────────────────────────────────────

/// Analyse `data` if it is an APK; `None` for anything else.
pub fn analyze(data: &[u8]) -> Option<DetectionResult> {
    if !is_apk(data) {
        return None;
    }
    let started = std::time::Instant::now();
    let report = std::panic::catch_unwind(|| inspect(data)).unwrap_or_else(|_| ApkReport {
        manifest: None,
        dex_files: 0,
        apis: vec![],
        native_abis: vec![],
        native_libraries: vec![],
        packers: vec![],
        embedded_payloads: vec![],
        signing: Signing::default(),
        iocs: vec![],
        errors: vec!["app structure could not be parsed".to_string()],
    });
    Some(detection(&report, started.elapsed().as_millis() as u64))
}

pub fn inspect(data: &[u8]) -> ApkReport {
    let mut report = ApkReport {
        manifest: None,
        dex_files: 0,
        apis: vec![],
        native_abis: vec![],
        native_libraries: vec![],
        packers: vec![],
        embedded_payloads: vec![],
        signing: Signing::default(),
        iocs: vec![],
        errors: vec![],
    };
    let Ok(mut archive) = zip::ZipArchive::new(Cursor::new(data)) else {
        report.errors.push("not a readable zip".to_string());
        return report;
    };

    let mut apis: BTreeSet<Indicator> = BTreeSet::new();
    let mut iocs: BTreeSet<String> = BTreeSet::new();
    let mut abis: BTreeSet<String> = BTreeSet::new();
    let mut packers: BTreeSet<String> = BTreeSet::new();

    for i in 0..archive.len().min(MAX_ENTRIES) {
        let Ok(mut entry) = archive.by_index(i) else {
            continue;
        };
        if !entry.is_file() {
            continue;
        }
        let name = entry.name().map(|n| n.to_string()).unwrap_or_default();
        let lower = name.to_ascii_lowercase();

        if name == "AndroidManifest.xml" {
            let mut buf = Vec::new();
            if (&mut entry)
                .take(MAX_MANIFEST_BYTES)
                .read_to_end(&mut buf)
                .is_ok()
            {
                match parse_axml(&buf) {
                    Some(m) => report.manifest = Some(m),
                    None => report
                        .errors
                        .push("AndroidManifest.xml is not valid binary XML".to_string()),
                }
            }
        } else if is_root_dex(&name) {
            report.dex_files += 1;
            if report.dex_files > MAX_DEX_FILES {
                continue;
            }
            let mut buf = Vec::new();
            if (&mut entry)
                .take(MAX_DEX_BYTES)
                .read_to_end(&mut buf)
                .is_ok()
                && buf.starts_with(b"dex\n")
            {
                scan_dex(&buf, &mut apis, &mut iocs);
            }
        } else if lower.starts_with("lib/") && lower.ends_with(".so") {
            let mut parts = name.split('/');
            parts.next();
            if let Some(abi) = parts.next() {
                abis.insert(abi.to_string());
            }
            let file = name.rsplit('/').next().unwrap_or(&name).to_string();
            if let Some(packer) = packer_for(&file) {
                packers.insert(packer.to_string());
            }
            if report.native_libraries.len() < 100 && !report.native_libraries.contains(&file) {
                report.native_libraries.push(file);
            }
        } else if lower.starts_with("meta-inf/")
            && [".rsa", ".dsa", ".ec"].iter().any(|e| lower.ends_with(e))
        {
            report.signing.v1 = true;
            let mut buf = Vec::new();
            if (&mut entry).take(256 * 1024).read_to_end(&mut buf).is_ok()
                && contains(&buf, b"Android Debug")
            {
                report.signing.debug_certificate = true;
            }
        } else if lower.starts_with("assets/") || lower.starts_with("res/raw/") {
            if let Some(packer) = packer_asset(&lower) {
                packers.insert(packer.to_string());
            }
            // What the file really is, from its first bytes.
            let mut head = [0u8; 4];
            let n = read_head(&mut entry, &mut head);
            let what = match &head[..n] {
                [b'd', b'e', b'x', b'\n'] => Some("DEX code"),
                [0x7F, b'E', b'L', b'F'] => Some("native program (ELF)"),
                [b'P', b'K', 3, 4]
                    if lower.ends_with(".apk")
                        || lower.ends_with(".jar")
                        || lower.ends_with(".zip") =>
                {
                    Some("packaged app or code")
                }
                _ if lower.ends_with(".apk") || lower.ends_with(".dex") => {
                    Some("encrypted or disguised app/code")
                }
                _ => None,
            };
            if let Some(what) = what {
                if report.embedded_payloads.len() < 50 {
                    report.embedded_payloads.push(format!("{name} ({what})"));
                }
            }
        }
    }

    // v2/v3 signatures live in a block before the central directory.
    if contains(data, b"APK Sig Block 42") {
        report.signing.v2_plus = true;
        if !report.signing.debug_certificate && contains(data, b"Android Debug") {
            report.signing.debug_certificate = true;
        }
    }

    report.apis = apis.into_iter().collect();
    report.iocs = iocs.into_iter().take(100).collect();
    report.native_abis = abis.into_iter().collect();
    report.packers = packers.into_iter().collect();
    report
}

fn is_root_dex(name: &str) -> bool {
    !name.contains('/') && name.starts_with("classes") && name.ends_with(".dex")
}

fn read_head(r: &mut impl Read, buf: &mut [u8]) -> usize {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..]) {
            Ok(0) | Err(_) => break,
            Ok(k) => n += k,
        }
    }
    n
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    BytesRegex::new(&regex::escape(&String::from_utf8_lossy(needle)))
        .map(|re| re.is_match(haystack))
        .unwrap_or(false)
}

/// Native libraries shipped by commercial Android packers/protectors.
fn packer_for(lib: &str) -> Option<&'static str> {
    let l = lib.to_ascii_lowercase();
    let table: &[(&str, &str)] = &[
        ("libjiagu", "Qihoo 360 Jiagu"),
        ("libsecexe", "Bangcle"),
        ("libsecmain", "Bangcle"),
        ("libdexhelper", "SecNeo"),
        ("libprotectclass", "Ijiami / APKProtect"),
        ("libexecmain", "Ijiami"),
        ("libmobisec", "Alibaba"),
        ("libshella", "Tencent Legu"),
        ("libshellx", "Tencent Legu"),
        ("libtup.so", "Tencent"),
        ("libbaiduprotect", "Baidu"),
        ("libnqshield", "NQ Shield"),
        ("libapkprotect", "APKProtect"),
        ("libjgdtc", "Ijiami"),
        ("libapssec", "Kiwisec"),
        ("libkwscmm", "Kiwisec"),
    ];
    table
        .iter()
        .find(|(p, _)| l.starts_with(p))
        .map(|(_, name)| *name)
}

fn packer_asset(path: &str) -> Option<&'static str> {
    if path.starts_with("assets/ijiami") {
        Some("Ijiami")
    } else if path.starts_with("assets/jiagu") || path.contains("libjiagu") {
        Some("Qihoo 360 Jiagu")
    } else if path.contains("secdata0.jar") {
        Some("Bangcle")
    } else {
        None
    }
}

// ── DEX ──────────────────────────────────────────────────────────────────

/// (kind, string in the DEX string table, description).
const DEX_APIS: &[(&str, &str, &str)] = &[
    ("sms_send", "sendTextMessage", "sends SMS messages"),
    ("sms_send", "sendMultipartTextMessage", "sends SMS messages"),
    ("sms_read", "getMessagesFromIntent", "reads incoming SMS"),
    ("sms_read", "content://sms", "reads the SMS inbox"),
    (
        "dynamic_code",
        "Ldalvik/system/DexClassLoader;",
        "loads code that isn't in the app",
    ),
    (
        "dynamic_code",
        "Ldalvik/system/InMemoryDexClassLoader;",
        "loads code from memory",
    ),
    ("root", "/system/xbin/su", "looks for or runs root (su)"),
    ("root", "/system/bin/su", "looks for or runs root (su)"),
    (
        "hide_icon",
        "setComponentEnabledSetting",
        "can hide its own launcher icon",
    ),
    (
        "accessibility_abuse",
        "performGlobalAction",
        "presses Back/Home/Recents through accessibility",
    ),
    (
        "accessibility_abuse",
        "dispatchGesture",
        "taps and swipes on the user's behalf",
    ),
    ("device_admin_abuse", "lockNow", "locks the device"),
    (
        "device_admin_abuse",
        "wipeData",
        "can factory-reset the device",
    ),
    (
        "install",
        "Landroid/content/pm/PackageInstaller;",
        "installs other apps",
    ),
    (
        "install",
        "application/vnd.android.package-archive",
        "opens APK files to install them",
    ),
    (
        "device_id",
        "getSubscriberId",
        "reads the SIM subscriber ID (IMSI)",
    ),
    (
        "device_id",
        "getSimSerialNumber",
        "reads the SIM serial number",
    ),
    ("device_id", "getLine1Number", "reads the phone number"),
    (
        "screen_capture",
        "Landroid/media/projection/MediaProjection;",
        "records the screen",
    ),
    (
        "exfiltration",
        "api.telegram.org/bot",
        "sends data to a Telegram bot",
    ),
    (
        "mining",
        "stratum+tcp://",
        "connects to a cryptocurrency mining pool",
    ),
    ("shell", "Ljava/lang/ProcessBuilder;", "runs shell commands"),
];

lazy_static::lazy_static! {
    static ref DEX_SET: RegexSet = RegexSet::new(
        DEX_APIS.iter().map(|(_, s, _)| regex::escape(s))
    ).unwrap();
    static ref URL_RE: BytesRegex =
        BytesRegex::new(r"(?i-u)\bhttps?://[A-Za-z0-9.\-]{4,100}(?::\d{2,5})?(?:/[\x21-\x7e]{0,120})?").unwrap();
    static ref IP_URL_RE: BytesRegex =
        BytesRegex::new(r"(?-u)\b(?:\d{1,3}\.){3}\d{1,3}:\d{2,5}\b").unwrap();
}

/// URL hosts too common in ordinary apps to be worth listing.
const COMMON_HOSTS: &[&str] = &[
    "schemas.android.com",
    "android.com",
    "google.com",
    "googleapis.com",
    "gstatic.com",
    "googlesyndication.com",
    "googleadservices.com",
    "doubleclick.net",
    "firebaseio.com",
    "facebook.com",
    "fb.com",
    "apache.org",
    "w3.org",
    "xml.org",
    "github.com",
    "example.com",
    "crashlytics.com",
    "app-measurement.com",
    "play.google.com",
];

fn scan_dex(dex: &[u8], apis: &mut BTreeSet<Indicator>, iocs: &mut BTreeSet<String>) {
    for i in DEX_SET.matches(dex).into_iter() {
        let (kind, api, desc) = DEX_APIS[i];
        apis.insert(Indicator {
            kind,
            evidence: api.to_string(),
            description: desc,
        });
    }
    for m in URL_RE.find_iter(dex).take(2_000) {
        if iocs.len() >= 100 {
            break;
        }
        let url = String::from_utf8_lossy(m.as_bytes()).to_string();
        let host = url
            .split("://")
            .nth(1)
            .and_then(|r| r.split(['/', ':']).next())
            .unwrap_or("")
            .to_ascii_lowercase();
        if host.len() < 4 || !host.contains('.') {
            continue;
        }
        if COMMON_HOSTS
            .iter()
            .any(|c| host == *c || host.ends_with(&format!(".{c}")))
        {
            continue;
        }
        iocs.insert(url);
    }
    for m in IP_URL_RE.find_iter(dex).take(200) {
        if iocs.len() >= 100 {
            break;
        }
        iocs.insert(String::from_utf8_lossy(m.as_bytes()).to_string());
    }
}

// ── Binary XML (AXML) ────────────────────────────────────────────────────

const RES_STRING_POOL: u16 = 0x0001;
const RES_XML_RESOURCE_MAP: u16 = 0x0180;
const RES_XML_START_ELEMENT: u16 = 0x0102;
const RES_XML_END_ELEMENT: u16 = 0x0103;
const NO_INDEX: u32 = 0xFFFF_FFFF;

/// android:* attribute resource ids, so stripped attribute names resolve.
fn android_attr(id: u32) -> Option<&'static str> {
    Some(match id {
        0x0101_0003 => "name",
        0x0101_0006 => "permission",
        0x0101_000f => "debuggable",
        0x0101_0010 => "exported",
        0x0101_020c => "minSdkVersion",
        0x0101_021c => "versionName",
        0x0101_0270 => "targetSdkVersion",
        0x0101_0280 => "allowBackup",
        0x0101_04ec => "usesCleartextTraffic",
        _ => return None,
    })
}

fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(at..at + 2)?.try_into().ok()?))
}

fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

fn parse_string_pool(chunk: &[u8]) -> Option<Vec<String>> {
    let header_size = u16_at(chunk, 2)? as usize;
    let count = u32_at(chunk, 8)? as usize;
    let flags = u32_at(chunk, 16)?;
    let strings_start = u32_at(chunk, 20)? as usize;
    let utf8 = flags & 0x100 != 0;
    if count > 500_000 {
        return None;
    }
    let mut out = Vec::with_capacity(count.min(10_000));
    for i in 0..count {
        let off = u32_at(chunk, header_size + i * 4)? as usize;
        let at = strings_start.checked_add(off)?;
        out.push(read_pool_string(chunk, at, utf8).unwrap_or_default());
    }
    Some(out)
}

fn read_pool_string(chunk: &[u8], mut at: usize, utf8: bool) -> Option<String> {
    if utf8 {
        // UTF-16 length, then UTF-8 length, each 1 or 2 bytes.
        let skip_len = |at: &mut usize| -> Option<usize> {
            let b = *chunk.get(*at)? as usize;
            *at += 1;
            if b & 0x80 != 0 {
                let b2 = *chunk.get(*at)? as usize;
                *at += 1;
                Some(((b & 0x7F) << 8) | b2)
            } else {
                Some(b)
            }
        };
        skip_len(&mut at)?;
        let len = skip_len(&mut at)?;
        Some(String::from_utf8_lossy(chunk.get(at..at + len)?).into_owned())
    } else {
        let mut len = u16_at(chunk, at)? as usize;
        at += 2;
        if len & 0x8000 != 0 {
            len = ((len & 0x7FFF) << 16) | u16_at(chunk, at)? as usize;
            at += 2;
        }
        let bytes = chunk.get(at..at + len * 2)?;
        let units: Vec<u16> = bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes(*c))
            .collect();
        Some(String::from_utf16_lossy(&units))
    }
}

#[derive(Debug, Clone)]
enum AttrValue {
    Str(String),
    Int(u32),
    Bool(bool),
}

impl AttrValue {
    fn as_str(&self) -> Option<&str> {
        match self {
            AttrValue::Str(s) => Some(s),
            _ => None,
        }
    }
    fn as_u32(&self) -> Option<u32> {
        match self {
            AttrValue::Int(i) => Some(*i),
            AttrValue::Str(s) => s.parse().ok(),
            AttrValue::Bool(_) => None,
        }
    }
    fn as_bool(&self) -> Option<bool> {
        match self {
            AttrValue::Bool(b) => Some(*b),
            AttrValue::Int(i) => Some(*i != 0),
            AttrValue::Str(s) => s.parse().ok(),
        }
    }
}

/// Parse a binary AndroidManifest.xml into what the scoring needs.
pub fn parse_axml(data: &[u8]) -> Option<Manifest> {
    // Chunk walk. The file header is 8 bytes; tolerate a damaged type field,
    // which some malware uses to break parsers.
    let mut strings: Vec<String> = Vec::new();
    let mut res_map: Vec<u32> = Vec::new();
    let mut manifest = Manifest::default();
    let mut stack: Vec<String> = Vec::new();
    let mut current: Option<Component> = None;
    let mut saw_element = false;
    let mut elements = 0;

    let mut pos = 8;
    while pos + 8 <= data.len() {
        let ty = u16_at(data, pos)?;
        let header_size = u16_at(data, pos + 2)? as usize;
        let size = u32_at(data, pos + 4)? as usize;
        if size < 8 || header_size < 8 || header_size > size {
            break;
        }
        let Some(chunk) = data.get(pos..pos + size) else {
            break;
        };
        match ty {
            RES_STRING_POOL => strings = parse_string_pool(chunk)?,
            RES_XML_RESOURCE_MAP => {
                res_map = (8..size)
                    .step_by(4)
                    .filter_map(|o| u32_at(chunk, o))
                    .collect();
            }
            RES_XML_START_ELEMENT => {
                elements += 1;
                if elements > MAX_ELEMENTS {
                    break;
                }
                saw_element = true;
                let ext = header_size;
                let name_idx = u32_at(chunk, ext + 4)?;
                let attr_start = u16_at(chunk, ext + 8)? as usize;
                let attr_size = (u16_at(chunk, ext + 10)? as usize).max(20);
                let attr_count = u16_at(chunk, ext + 12)? as usize;
                let tag = strings.get(name_idx as usize).cloned().unwrap_or_default();

                let mut attrs: HashMap<String, AttrValue> = HashMap::new();
                for a in 0..attr_count.min(256) {
                    let at = ext + attr_start + a * attr_size;
                    let Some(name_i) = u32_at(chunk, at + 4) else {
                        break;
                    };
                    let raw = u32_at(chunk, at + 8).unwrap_or(NO_INDEX);
                    let dtype = *chunk.get(at + 15).unwrap_or(&0);
                    let dval = u32_at(chunk, at + 16).unwrap_or(0);
                    // Prefer the resource id: it survives name stripping.
                    let attr_name = res_map
                        .get(name_i as usize)
                        .and_then(|id| android_attr(*id))
                        .map(str::to_string)
                        .or_else(|| strings.get(name_i as usize).cloned())
                        .unwrap_or_default();
                    let value = if raw != NO_INDEX {
                        AttrValue::Str(strings.get(raw as usize).cloned().unwrap_or_default())
                    } else {
                        match dtype {
                            0x03 => AttrValue::Str(
                                strings.get(dval as usize).cloned().unwrap_or_default(),
                            ),
                            0x12 => AttrValue::Bool(dval != 0),
                            _ => AttrValue::Int(dval),
                        }
                    };
                    attrs.insert(attr_name, value);
                }
                handle_start(&tag, &attrs, &stack, &mut manifest, &mut current);
                stack.push(tag);
            }
            RES_XML_END_ELEMENT => {
                if let Some(tag) = stack.pop() {
                    if is_component(&tag) {
                        if let Some(c) = current.take() {
                            manifest.components.push(c);
                        }
                    }
                }
            }
            _ => {}
        }
        pos += size;
    }
    if let Some(c) = current.take() {
        manifest.components.push(c);
    }
    saw_element.then_some(manifest)
}

fn is_component(tag: &str) -> bool {
    matches!(
        tag,
        "activity" | "activity-alias" | "service" | "receiver" | "provider"
    )
}

fn handle_start(
    tag: &str,
    attrs: &HashMap<String, AttrValue>,
    stack: &[String],
    m: &mut Manifest,
    current: &mut Option<Component>,
) {
    let s = |k: &str| attrs.get(k).and_then(|v| v.as_str()).map(str::to_string);
    match tag {
        "manifest" => {
            m.package = s("package");
            m.version_name = s("versionName");
        }
        "uses-sdk" => {
            m.min_sdk = attrs.get("minSdkVersion").and_then(|v| v.as_u32());
            m.target_sdk = attrs.get("targetSdkVersion").and_then(|v| v.as_u32());
        }
        "uses-permission" | "uses-permission-sdk-23" => {
            if let Some(p) = s("name") {
                if !m.permissions.contains(&p) {
                    m.permissions.push(p);
                }
            }
        }
        "application" => {
            m.debuggable = attrs
                .get("debuggable")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            m.allow_backup = attrs.get("allowBackup").and_then(|v| v.as_bool());
            m.cleartext_traffic = attrs.get("usesCleartextTraffic").and_then(|v| v.as_bool());
        }
        t if is_component(t) => {
            *current = Some(Component {
                kind: t.to_string(),
                name: s("name").unwrap_or_default(),
                permission: s("permission"),
                ..Default::default()
            });
        }
        "action" | "category" if stack.iter().any(|t| t == "intent-filter") => {
            if let (Some(c), Some(v)) = (current.as_mut(), s("name")) {
                let list = if tag == "action" {
                    &mut c.actions
                } else {
                    &mut c.categories
                };
                if !list.contains(&v) {
                    list.push(v);
                }
            }
        }
        _ => {}
    }
}

// ── Scoring ──────────────────────────────────────────────────────────────

/// Short name of a permission: `android.permission.SEND_SMS` → `SEND_SMS`.
fn short(p: &str) -> &str {
    p.rsplit('.').next().unwrap_or(p)
}

struct Capabilities {
    found: Vec<Indicator>,
    score: f32,
}

fn capabilities(r: &ApkReport) -> (Capabilities, HashMap<&'static str, bool>) {
    let empty = Manifest::default();
    let m = r.manifest.as_ref().unwrap_or(&empty);
    let perm = |name: &str| m.permissions.iter().any(|p| short(p) == name);
    let api = |kind: &str| r.apis.iter().any(|a| a.kind == kind);
    let service_with = |perm_name: &str| {
        m.components
            .iter()
            .filter(|c| c.permission.as_deref().map(short) == Some(perm_name))
            .map(|c| c.name.clone())
            .collect::<Vec<_>>()
    };
    let with_action = |action: &str| {
        m.components
            .iter()
            .filter(|c| c.actions.iter().any(|a| a == action))
            .map(|c| c.name.clone())
            .collect::<Vec<_>>()
    };

    let mut accessibility = service_with("BIND_ACCESSIBILITY_SERVICE");
    accessibility.extend(with_action(
        "android.accessibilityservice.AccessibilityService",
    ));
    let mut device_admin = service_with("BIND_DEVICE_ADMIN");
    device_admin.extend(with_action("android.app.action.DEVICE_ADMIN_ENABLED"));
    let notif = service_with("BIND_NOTIFICATION_LISTENER_SERVICE");
    let has_launcher = m.components.iter().any(|c| {
        c.kind.starts_with("activity")
            && c.actions.iter().any(|a| a == "android.intent.action.MAIN")
            && c.categories
                .iter()
                .any(|k| k == "android.intent.category.LAUNCHER")
    });
    let boot = perm("RECEIVE_BOOT_COMPLETED")
        || !with_action("android.intent.action.BOOT_COMPLETED").is_empty();

    let mut flags: HashMap<&'static str, bool> = HashMap::new();
    flags.insert("accessibility", !accessibility.is_empty());
    flags.insert("device_admin", !device_admin.is_empty());
    flags.insert("notification_listener", !notif.is_empty());
    flags.insert("overlay", perm("SYSTEM_ALERT_WINDOW"));
    flags.insert(
        "sms_read",
        perm("RECEIVE_SMS") || perm("READ_SMS") || api("sms_read"),
    );
    flags.insert("sms_send", perm("SEND_SMS") || api("sms_send"));
    flags.insert(
        "install",
        perm("REQUEST_INSTALL_PACKAGES") || perm("INSTALL_PACKAGES") || api("install"),
    );
    flags.insert("dynamic_code", api("dynamic_code"));
    flags.insert("embedded_payload", !r.embedded_payloads.is_empty());
    flags.insert("packer", !r.packers.is_empty());
    flags.insert("root", api("root"));
    flags.insert("hide_icon", api("hide_icon"));
    flags.insert("no_launcher", r.manifest.is_some() && !has_launcher);
    flags.insert("boot", boot);
    flags.insert("telegram", api("exfiltration"));
    flags.insert("mining", api("mining"));
    flags.insert("unsigned", !r.signing.v1 && !r.signing.v2_plus);
    flags.insert("debug_cert", r.signing.debug_certificate);

    let mut found = Vec::new();
    let mut score = 0.0_f32;
    let mut add = |on: bool, weight: f32, kind: &'static str, evidence: String, d: &'static str| {
        if on {
            score += weight;
            found.push(Indicator {
                kind,
                evidence,
                description: d,
            });
        }
    };
    add(
        !accessibility.is_empty(),
        3.0,
        "accessibility",
        accessibility.join(", "),
        "accessibility service: can read the screen and act for the user",
    );
    add(
        !device_admin.is_empty(),
        2.0,
        "device_admin",
        device_admin.join(", "),
        "device administrator: can lock or wipe the device and resist removal",
    );
    add(
        !notif.is_empty(),
        1.0,
        "notification_listener",
        notif.join(", "),
        "reads every notification, including one-time codes",
    );
    add(
        flags["overlay"],
        1.0,
        "overlay",
        "SYSTEM_ALERT_WINDOW".into(),
        "draws over other apps (fake login screens)",
    );
    add(
        flags["sms_read"],
        2.0,
        "sms_read",
        "RECEIVE_SMS / READ_SMS".into(),
        "reads SMS, including one-time codes",
    );
    add(
        flags["sms_send"],
        2.0,
        "sms_send",
        "SEND_SMS".into(),
        "sends SMS (premium-rate fraud, spreading)",
    );
    add(
        flags["install"],
        1.0,
        "install",
        "REQUEST_INSTALL_PACKAGES".into(),
        "installs other apps",
    );
    add(
        flags["dynamic_code"],
        1.0,
        "dynamic_code",
        "DexClassLoader".into(),
        "loads code that isn't part of the app",
    );
    add(
        flags["embedded_payload"],
        2.0,
        "embedded_payload",
        r.embedded_payloads.join(", "),
        "carries another app, DEX code or program inside it",
    );
    add(
        flags["packer"],
        2.0,
        "packer",
        r.packers.join(", "),
        "code is packed by a commercial protector, hiding it from analysis",
    );
    add(
        flags["root"],
        2.0,
        "root",
        "su".into(),
        "looks for or uses root",
    );
    add(
        flags["hide_icon"],
        1.0,
        "hide_icon",
        "setComponentEnabledSetting".into(),
        "can hide its launcher icon",
    );
    add(
        flags["no_launcher"],
        1.0,
        "no_launcher",
        "no MAIN/LAUNCHER activity".into(),
        "has no icon in the app drawer",
    );
    add(
        flags["telegram"],
        2.0,
        "telegram",
        "api.telegram.org/bot".into(),
        "sends data to a Telegram bot",
    );
    add(
        flags["mining"],
        3.0,
        "mining",
        "stratum+tcp://".into(),
        "mines cryptocurrency",
    );
    add(
        flags["unsigned"],
        2.0,
        "unsigned",
        "no v1 or v2+ signature".into(),
        "not signed, so Android won't install it as-is",
    );
    add(
        flags["debug_cert"],
        1.0,
        "debug_cert",
        "Android Debug".into(),
        "signed with the public debug certificate",
    );
    add(
        m.debuggable,
        0.5,
        "debuggable",
        "android:debuggable".into(),
        "built in debug mode",
    );
    let spy: Vec<&str> = [
        "READ_CONTACTS",
        "READ_CALL_LOG",
        "RECORD_AUDIO",
        "CAMERA",
        "ACCESS_FINE_LOCATION",
        "READ_PHONE_STATE",
    ]
    .into_iter()
    .filter(|p| perm(p))
    .collect();
    add(
        spy.len() >= 3,
        (spy.len() as f32 * 0.5).min(2.0),
        "personal_data",
        spy.join(", "),
        "access to contacts, calls, microphone, camera or location",
    );

    (Capabilities { found, score }, flags)
}

struct Assessment {
    verdict: ThreatVerdict,
    severity: SeverityLevel,
    confidence: f32,
    strong: bool,
    reasons: Vec<String>,
}

fn assess(r: &ApkReport, caps: &Capabilities, f: &HashMap<&'static str, bool>) -> Assessment {
    let on = |k: &str| f.get(k).copied().unwrap_or(false);
    let mut reasons = Vec::new();

    if on("accessibility")
        && (on("overlay") || on("notification_listener"))
        && (on("sms_read") || on("sms_send"))
    {
        reasons.push("banking-trojan pattern: accessibility control, screen overlays or notification access, and SMS".to_string());
    }
    if on("sms_send") && on("boot") && (on("hide_icon") || on("no_launcher")) {
        reasons.push(
            "SMS-fraud pattern: sends SMS, starts at boot and hides from the app drawer"
                .to_string(),
        );
    }
    if on("dynamic_code") && on("embedded_payload") && on("install") {
        reasons.push(
            "dropper pattern: carries a hidden payload, loads code and installs apps".to_string(),
        );
    }
    if on("telegram") && (on("sms_read") || on("notification_listener") || on("accessibility")) {
        reasons.push("spyware pattern: collects SMS, notifications or screen content and sends them to a Telegram bot".to_string());
    }
    if on("mining") {
        reasons.push("connects to a cryptocurrency mining pool".to_string());
    }
    if !reasons.is_empty() {
        return Assessment {
            verdict: ThreatVerdict::Malicious,
            severity: SeverityLevel::High,
            confidence: 0.85,
            strong: true,
            reasons,
        };
    }

    if r.manifest.is_none() {
        return Assessment {
            verdict: ThreatVerdict::Unknown,
            severity: SeverityLevel::Info,
            confidence: 0.0,
            strong: false,
            reasons: vec![format!(
                "manifest could not be read: {}",
                if r.errors.is_empty() {
                    "unknown error".to_string()
                } else {
                    r.errors.join("; ")
                }
            )],
        };
    }

    if caps.score >= 5.0 {
        let top: Vec<&str> = caps.found.iter().map(|i| i.description).take(4).collect();
        return Assessment {
            verdict: ThreatVerdict::Suspicious,
            severity: SeverityLevel::Medium,
            confidence: 0.65,
            strong: false,
            reasons: vec![format!(
                "risky combination (score {:.1}): {}",
                caps.score,
                top.join("; ")
            )],
        };
    }

    Assessment {
        verdict: ThreatVerdict::Benign,
        severity: SeverityLevel::Info,
        confidence: 0.7,
        strong: false,
        reasons: vec![if caps.found.is_empty() {
            "no risky permissions, components or APIs".to_string()
        } else {
            format!(
                "some sensitive abilities (score {:.1}), no malicious pattern",
                caps.score
            )
        }],
    }
}

fn detection(r: &ApkReport, processing_time_ms: u64) -> DetectionResult {
    let (caps, flags) = capabilities(r);
    let a = assess(r, &caps, &flags);
    let mut metadata = HashMap::new();
    let mut put = |k: &str, v: serde_json::Value| {
        metadata.insert(k.to_string(), v);
    };
    put("summary", serde_json::json!(a.reasons.join("; ")));
    put("riskScore", serde_json::json!(caps.score));
    put("indicators", serde_json::json!(caps.found));
    if let Some(m) = &r.manifest {
        put("package", serde_json::json!(m.package));
        put("versionName", serde_json::json!(m.version_name));
        put("minSdk", serde_json::json!(m.min_sdk));
        put("targetSdk", serde_json::json!(m.target_sdk));
        put("permissions", serde_json::json!(m.permissions));
        put("debuggable", serde_json::json!(m.debuggable));
        put("allowBackup", serde_json::json!(m.allow_backup));
        put("cleartextTraffic", serde_json::json!(m.cleartext_traffic));
        let count = |kind: &str| {
            m.components
                .iter()
                .filter(|c| c.kind.starts_with(kind))
                .count()
        };
        put(
            "componentCounts",
            serde_json::json!({
                "activities": count("activity"),
                "services": count("service"),
                "receivers": count("receiver"),
                "providers": count("provider"),
            }),
        );
        // Only components that matter for the verdict, to keep this small.
        let notable: Vec<&Component> = m
            .components
            .iter()
            .filter(|c| c.permission.is_some() || !c.actions.is_empty())
            .take(50)
            .collect();
        put("components", serde_json::json!(notable));
    }
    put("apis", serde_json::json!(r.apis));
    put("dexFiles", serde_json::json!(r.dex_files));
    put("nativeAbis", serde_json::json!(r.native_abis));
    put("nativeLibraries", serde_json::json!(r.native_libraries));
    put("packers", serde_json::json!(r.packers));
    put("embeddedPayloads", serde_json::json!(r.embedded_payloads));
    put("signing", serde_json::json!(r.signing));
    put("iocs", serde_json::json!(r.iocs));
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

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::io::Write;

    pub(crate) enum V {
        S(&'static str),
        I(u32),
        B(bool),
    }

    pub(crate) enum Node {
        Start(&'static str, Vec<(&'static str, V)>),
        End(&'static str),
    }
    use Node::{End, Start};

    fn android_id(name: &str) -> Option<u32> {
        Some(match name {
            "name" => 0x0101_0003,
            "permission" => 0x0101_0006,
            "debuggable" => 0x0101_000f,
            "minSdkVersion" => 0x0101_020c,
            "versionName" => 0x0101_021c,
            "targetSdkVersion" => 0x0101_0270,
            _ => return None,
        })
    }

    /// Encode a binary manifest the way aapt does: android attribute names
    /// first in the string pool, mapped to resource ids. With `strip`, those
    /// names are blanked, as obfuscators do.
    pub(crate) fn axml(nodes: &[Node], strip: bool) -> Vec<u8> {
        let mut attr_names: Vec<&str> = Vec::new();
        for n in nodes {
            if let Start(_, attrs) = n {
                for (k, _) in attrs {
                    if android_id(k).is_some() && !attr_names.contains(k) {
                        attr_names.push(k);
                    }
                }
            }
        }
        let mut pool: Vec<String> = attr_names
            .iter()
            .map(|n| if strip { String::new() } else { n.to_string() })
            .collect();
        let res_ids: Vec<u32> = attr_names.iter().map(|n| android_id(n).unwrap()).collect();
        let intern = |s: &str, pool: &mut Vec<String>| -> u32 {
            if let Some(i) = attr_names.iter().position(|n| *n == s) {
                return i as u32;
            }
            if let Some(i) = pool.iter().skip(attr_names.len()).position(|p| p == s) {
                return (i + attr_names.len()) as u32;
            }
            pool.push(s.to_string());
            (pool.len() - 1) as u32
        };
        let ns = intern("http://schemas.android.com/apk/res/android", &mut pool);

        let mut body = Vec::new();
        for n in nodes {
            match n {
                Start(tag, attrs) => {
                    let tag_i = intern(tag, &mut pool);
                    let mut chunk = Vec::new();
                    chunk.extend(0u32.to_le_bytes()); // line
                    chunk.extend(NO_INDEX.to_le_bytes()); // comment
                    chunk.extend(NO_INDEX.to_le_bytes()); // ns
                    chunk.extend(tag_i.to_le_bytes());
                    chunk.extend(20u16.to_le_bytes()); // attributeStart
                    chunk.extend(20u16.to_le_bytes()); // attributeSize
                    chunk.extend((attrs.len() as u16).to_le_bytes());
                    chunk.extend([0u8; 6]);
                    for (k, v) in attrs {
                        let k_i = intern(k, &mut pool);
                        let a_ns = if android_id(k).is_some() {
                            ns
                        } else {
                            NO_INDEX
                        };
                        chunk.extend(a_ns.to_le_bytes());
                        chunk.extend(k_i.to_le_bytes());
                        let (raw, ty, data) = match v {
                            V::S(s) => {
                                let i = intern(s, &mut pool);
                                (i, 0x03u8, i)
                            }
                            V::I(i) => (NO_INDEX, 0x10, *i),
                            V::B(b) => (NO_INDEX, 0x12, if *b { NO_INDEX } else { 0 }),
                        };
                        chunk.extend(raw.to_le_bytes());
                        chunk.extend(8u16.to_le_bytes());
                        chunk.push(0);
                        chunk.push(ty);
                        chunk.extend(data.to_le_bytes());
                    }
                    body.extend(RES_XML_START_ELEMENT.to_le_bytes());
                    body.extend(16u16.to_le_bytes());
                    body.extend(((chunk.len() + 8) as u32).to_le_bytes());
                    body.extend(chunk);
                }
                End(tag) => {
                    let tag_i = intern(tag, &mut pool);
                    body.extend(RES_XML_END_ELEMENT.to_le_bytes());
                    body.extend(16u16.to_le_bytes());
                    body.extend(24u32.to_le_bytes());
                    body.extend(0u32.to_le_bytes());
                    body.extend(NO_INDEX.to_le_bytes());
                    body.extend(NO_INDEX.to_le_bytes());
                    body.extend(tag_i.to_le_bytes());
                }
            }
        }

        // String pool, UTF-16.
        let mut data = Vec::new();
        let mut offsets = Vec::new();
        for s in &pool {
            offsets.push(data.len() as u32);
            let units: Vec<u16> = s.encode_utf16().collect();
            data.extend((units.len() as u16).to_le_bytes());
            for u in units {
                data.extend(u.to_le_bytes());
            }
            data.extend(0u16.to_le_bytes());
        }
        while data.len() % 4 != 0 {
            data.push(0);
        }
        let header = 28usize;
        let strings_start = header + offsets.len() * 4;
        let mut sp = Vec::new();
        sp.extend(RES_STRING_POOL.to_le_bytes());
        sp.extend((header as u16).to_le_bytes());
        sp.extend(((strings_start + data.len()) as u32).to_le_bytes());
        sp.extend((pool.len() as u32).to_le_bytes());
        sp.extend(0u32.to_le_bytes());
        sp.extend(0u32.to_le_bytes());
        sp.extend((strings_start as u32).to_le_bytes());
        sp.extend(0u32.to_le_bytes());
        for o in offsets {
            sp.extend(o.to_le_bytes());
        }
        sp.extend(data);

        let mut rm = Vec::new();
        rm.extend(RES_XML_RESOURCE_MAP.to_le_bytes());
        rm.extend(8u16.to_le_bytes());
        rm.extend(((8 + res_ids.len() * 4) as u32).to_le_bytes());
        for id in res_ids {
            rm.extend(id.to_le_bytes());
        }

        let total = 8 + sp.len() + rm.len() + body.len();
        let mut out = Vec::new();
        out.extend(0x0003u16.to_le_bytes());
        out.extend(8u16.to_le_bytes());
        out.extend((total as u32).to_le_bytes());
        out.extend(sp);
        out.extend(rm);
        out.extend(body);
        out
    }

    pub(crate) fn apk(manifest: &[u8], dex: &[u8], extra: &[(&str, &[u8])]) -> Vec<u8> {
        let mut w = zip::ZipWriter::new(Cursor::new(Vec::new()));
        let opts = zip::write::SimpleFileOptions::default();
        w.start_file("AndroidManifest.xml", opts).unwrap();
        w.write_all(manifest).unwrap();
        w.start_file("classes.dex", opts).unwrap();
        let mut d = b"dex\n035\0".to_vec();
        d.extend_from_slice(dex);
        w.write_all(&d).unwrap();
        for (name, data) in extra {
            w.start_file(*name, opts).unwrap();
            w.write_all(data).unwrap();
        }
        w.finish().unwrap().into_inner()
    }

    const SIGNED: (&str, &[u8]) = ("META-INF/CERT.RSA", b"0\x82 release certificate");

    fn launcher() -> Vec<Node> {
        vec![
            Start("activity", vec![("name", V::S(".Main"))]),
            Start("intent-filter", vec![]),
            Start("action", vec![("name", V::S("android.intent.action.MAIN"))]),
            End("action"),
            Start(
                "category",
                vec![("name", V::S("android.intent.category.LAUNCHER"))],
            ),
            End("category"),
            End("intent-filter"),
            End("activity"),
        ]
    }

    fn manifest(perms: &[&'static str], app: Vec<Node>) -> Vec<Node> {
        let mut n = vec![
            Start(
                "manifest",
                vec![
                    ("package", V::S("com.example.app")),
                    ("versionName", V::S("1.2")),
                ],
            ),
            Start(
                "uses-sdk",
                vec![("minSdkVersion", V::I(24)), ("targetSdkVersion", V::I(34))],
            ),
            End("uses-sdk"),
        ];
        for p in perms {
            n.push(Start("uses-permission", vec![("name", V::S(p))]));
            n.push(End("uses-permission"));
        }
        n.push(Start("application", vec![("debuggable", V::B(false))]));
        n.extend(app);
        n.push(End("application"));
        n.push(End("manifest"));
        n
    }

    pub(crate) fn banker() -> Vec<u8> {
        let mut app = launcher();
        app.extend([
            Start(
                "service",
                vec![
                    ("name", V::S(".Acc")),
                    (
                        "permission",
                        V::S("android.permission.BIND_ACCESSIBILITY_SERVICE"),
                    ),
                ],
            ),
            Start("intent-filter", vec![]),
            Start(
                "action",
                vec![(
                    "name",
                    V::S("android.accessibilityservice.AccessibilityService"),
                )],
            ),
            End("action"),
            End("intent-filter"),
            End("service"),
        ]);
        let m = axml(
            &manifest(
                &[
                    "android.permission.RECEIVE_SMS",
                    "android.permission.SYSTEM_ALERT_WINDOW",
                    "android.permission.INTERNET",
                ],
                app,
            ),
            false,
        );
        apk(
            &m,
            b"performGlobalAction\0http://203.0.113.7:8080/gate.php\0",
            &[SIGNED],
        )
    }

    #[test]
    fn parses_the_manifest() {
        let m = parse_axml(&axml(
            &manifest(&["android.permission.CAMERA"], launcher()),
            false,
        ))
        .unwrap();
        assert_eq!(m.package.as_deref(), Some("com.example.app"));
        assert_eq!(m.version_name.as_deref(), Some("1.2"));
        assert_eq!((m.min_sdk, m.target_sdk), (Some(24), Some(34)));
        assert_eq!(m.permissions, vec!["android.permission.CAMERA"]);
        assert_eq!(m.components.len(), 1);
        assert_eq!(m.components[0].actions, vec!["android.intent.action.MAIN"]);
        assert_eq!(
            m.components[0].categories,
            vec!["android.intent.category.LAUNCHER"]
        );
    }

    #[test]
    fn stripped_attribute_names_resolve_through_the_resource_map() {
        let m = parse_axml(&axml(
            &manifest(&["android.permission.SEND_SMS"], launcher()),
            true,
        ))
        .unwrap();
        assert_eq!(m.permissions, vec!["android.permission.SEND_SMS"]);
        assert_eq!(m.target_sdk, Some(34));
    }

    #[test]
    fn banking_trojan_pattern_is_malicious() {
        let data = banker();
        assert!(is_apk(&data));
        let det = analyze(&data).unwrap();
        assert_eq!(det.verdict, ThreatVerdict::Malicious, "{:?}", det.metadata);
        assert_eq!(det.metadata[STRONG_SIGNAL_KEY], serde_json::json!(true));
        assert!(det.metadata["summary"]
            .as_str()
            .unwrap()
            .contains("banking-trojan"));
        assert!(det.metadata["iocs"]
            .as_array()
            .unwrap()
            .iter()
            .any(|i| i.as_str().unwrap().contains("203.0.113.7")));
    }

    #[test]
    fn ordinary_app_is_benign() {
        let m = axml(
            &manifest(
                &[
                    "android.permission.INTERNET",
                    "android.permission.CAMERA",
                    "android.permission.ACCESS_FINE_LOCATION",
                ],
                launcher(),
            ),
            false,
        );
        let det = analyze(&apk(
            &m,
            b"https://www.google.com/maps\0Landroid/app/Activity;\0",
            &[SIGNED],
        ))
        .unwrap();
        assert_eq!(det.verdict, ThreatVerdict::Benign, "{:?}", det.metadata);
        assert!(det.metadata["iocs"].as_array().unwrap().is_empty());
    }

    #[test]
    fn sms_fraud_without_launcher_is_malicious() {
        let receiver = vec![
            Start("receiver", vec![("name", V::S(".Boot"))]),
            Start("intent-filter", vec![]),
            Start(
                "action",
                vec![("name", V::S("android.intent.action.BOOT_COMPLETED"))],
            ),
            End("action"),
            End("intent-filter"),
            End("receiver"),
        ];
        let m = axml(
            &manifest(
                &[
                    "android.permission.SEND_SMS",
                    "android.permission.RECEIVE_BOOT_COMPLETED",
                ],
                receiver,
            ),
            false,
        );
        let det = analyze(&apk(&m, b"sendTextMessage\0", &[SIGNED])).unwrap();
        assert_eq!(det.verdict, ThreatVerdict::Malicious, "{:?}", det.metadata);
    }

    #[test]
    fn dropper_with_hidden_payload_is_malicious() {
        let m = axml(
            &manifest(&["android.permission.REQUEST_INSTALL_PACKAGES"], launcher()),
            false,
        );
        let inner = apk(&axml(&manifest(&[], launcher()), false), b"", &[]);
        let det = analyze(&apk(
            &m,
            b"Ldalvik/system/DexClassLoader;\0",
            &[SIGNED, ("assets/update.bin.apk", &inner)],
        ))
        .unwrap();
        assert_eq!(det.verdict, ThreatVerdict::Malicious, "{:?}", det.metadata);
        assert_eq!(
            det.metadata["embeddedPayloads"].as_array().unwrap().len(),
            1
        );
    }

    #[test]
    fn packers_and_signing_are_reported() {
        let m = axml(&manifest(&[], launcher()), false);
        let report = inspect(&apk(
            &m,
            b"",
            &[
                ("lib/arm64-v8a/libjiagu_a64.so", b"\x7fELF"),
                ("META-INF/CERT.RSA", b"CN=Android Debug,O=Android"),
            ],
        ));
        assert_eq!(report.packers, vec!["Qihoo 360 Jiagu"]);
        assert_eq!(report.native_abis, vec!["arm64-v8a"]);
        assert!(report.signing.v1 && report.signing.debug_certificate);
    }

    #[test]
    fn jars_and_plain_zips_are_not_apks() {
        let mut w = zip::ZipWriter::new(Cursor::new(Vec::new()));
        w.start_file(
            "META-INF/MANIFEST.MF",
            zip::write::SimpleFileOptions::default(),
        )
        .unwrap();
        w.write_all(b"Manifest-Version: 1.0").unwrap();
        assert!(analyze(&w.finish().unwrap().into_inner()).is_none());
        assert!(analyze(b"MZ not an app").is_none());
    }

    #[test]
    fn broken_manifest_does_not_vote_or_panic() {
        let det = analyze(&apk(b"garbage that is not binary xml", b"", &[SIGNED])).unwrap();
        assert_eq!(det.verdict, ThreatVerdict::Unknown);
        assert!(det.non_vote().is_some());

        let good = banker();
        for cut in [40, 200, good.len() / 2, good.len() - 30] {
            let _ = analyze(&good[..cut]);
        }
        let m = axml(
            &manifest(&["android.permission.SEND_SMS"], launcher()),
            false,
        );
        for cut in [9, 30, m.len() / 2] {
            let _ = parse_axml(&m[..cut]);
        }
    }
}
