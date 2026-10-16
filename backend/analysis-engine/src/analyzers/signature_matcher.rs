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
}

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

        for sig in signatures {
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
            confidence: 0.85,
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

#[cfg(test)]
mod tests {
    use super::*;

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
