//! Real YARA engine backed by libyara (via the `yara` crate).
//!
//! Compiled only when the `yara-engine` cargo feature is enabled (which links
//! libyara). Rule files (`*.yar` / `*.yara`) are discovered recursively under
//! the configured rules directory, each compiled into its own ruleset so that
//! a single malformed file cannot disable detection for the rest.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{info, warn};
use yara::{Compiler, MetadataValue, Rule, Rules};

use crate::models::analysis_result::{
    DetectionResult, EngineType, SeverityLevel, ThreatCategory, ThreatVerdict,
};

#[derive(Error, Debug)]
pub enum YaraEngineError {
    #[error("YARA compilation failed: {0}")]
    CompilationError(String),
    #[error("YARA scan failed: {0}")]
    ScanError(String),
    #[error("Rule loading failed: {0}")]
    RuleLoadError(String),
    #[error("File I/O error: {0}")]
    IoError(#[from] std::io::Error),
}

/// A structured representation of a single matched rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraMatch {
    pub rule_name: String,
    pub namespace: String,
    pub tags: Vec<String>,
    pub meta: HashMap<String, String>,
    pub matched_strings: usize,
}

/// Lightweight description of a loaded rule file (for stats/introspection).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraRule {
    pub namespace: String,
    pub source_file: String,
}

#[derive(Debug, Clone)]
pub struct YaraEngineConfig {
    pub rules_directory: PathBuf,
    pub max_file_size: u64,
    pub timeout_seconds: i32,
}

impl Default for YaraEngineConfig {
    fn default() -> Self {
        Self {
            rules_directory: PathBuf::from("./rules"),
            max_file_size: 1024 * 1024 * 1024, // 1GB
            timeout_seconds: 30,
        }
    }
}

/// One compiled ruleset, originating from a single rule file.
struct CompiledRuleSet {
    namespace: String,
    source_file: String,
    rules: Rules,
}

pub struct YaraEngine {
    config: YaraEngineConfig,
    rulesets: Vec<CompiledRuleSet>,
}

impl YaraEngine {
    pub fn new(config: YaraEngineConfig) -> Result<Self, YaraEngineError> {
        let mut engine = Self {
            config,
            rulesets: Vec::new(),
        };
        engine.load_and_compile()?;
        Ok(engine)
    }

    /// Number of loaded compiled rule files
    pub fn rule_count(&self) -> usize {
        self.rulesets.len()
    }

    /// Discover and compile every rule file under the configured directory.
    /// Files that fail to compile are skipped with a warning rather than
    /// aborting the whole engine.
    fn load_and_compile(&mut self) -> Result<(), YaraEngineError> {
        let dir = &self.config.rules_directory;
        info!("Loading YARA rules from directory: {:?}", dir);

        if !dir.exists() {
            warn!(
                "YARA rules directory does not exist: {:?}; engine has 0 rules",
                dir
            );
            self.rulesets = Vec::new();
            return Ok(());
        }

        let rule_files = Self::discover_rule_files(dir)?;
        let mut rulesets = Vec::new();

        for path in rule_files {
            let namespace = path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("default")
                .to_string();

            match Self::compile_file(&path, &namespace) {
                Ok(rules) => rulesets.push(CompiledRuleSet {
                    namespace,
                    source_file: path.display().to_string(),
                    rules,
                }),
                Err(e) => {
                    warn!("Skipping YARA rule file {:?}: {}", path, e);
                    continue;
                }
            }
        }

        info!(
            "Compiled {} YARA rule file(s) from {:?}",
            rulesets.len(),
            dir
        );
        self.rulesets = rulesets;
        Ok(())
    }

    fn compile_file(path: &Path, namespace: &str) -> Result<Rules, YaraEngineError> {
        let compiler = Compiler::new()
            .map_err(|e| YaraEngineError::CompilationError(e.to_string()))?
            .add_rules_file_with_namespace(path, namespace)
            .map_err(|e| YaraEngineError::CompilationError(e.to_string()))?;
        compiler
            .compile_rules()
            .map_err(|e| YaraEngineError::CompilationError(e.to_string()))
    }

    fn discover_rule_files(dir: &Path) -> Result<Vec<PathBuf>, YaraEngineError> {
        let mut rule_files = Vec::new();

        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.is_file()
                && path
                    .extension()
                    .map_or(false, |ext| ext == "yara" || ext == "yar")
            {
                rule_files.push(path);
            } else if path.is_dir() {
                let mut sub_files = Self::discover_rule_files(&path)?;
                rule_files.append(&mut sub_files);
            }
        }

        Ok(rule_files)
    }

    /// Scan a byte buffer and summarize all rule matches into a single
    /// `DetectionResult`. Errors are returned as a non-fatal `Unknown`
    /// detection (with `error_message`) so a YARA failure does not abort the
    /// surrounding multi-engine analysis.
    pub async fn analyze_file_data(
        &self,
        data: &[u8],
        filename: &str,
    ) -> anyhow::Result<DetectionResult> {
        let start = std::time::Instant::now();

        if data.len() as u64 > self.config.max_file_size {
            return Ok(self.unknown_result(
                start.elapsed().as_millis() as u64,
                format!("File too large for YARA scan: {} bytes", data.len()),
            ));
        }

        if self.rulesets.is_empty() {
            return Ok(self.unknown_result(
                start.elapsed().as_millis() as u64,
                "No YARA rules loaded".to_string(),
            ));
        }

        // scan_mem takes &self and is CPU-bound; run it on the blocking pool to
        // avoid stalling the async runtime on large inputs.
        let matches = match self.scan(data) {
            Ok(m) => m,
            Err(e) => {
                warn!("YARA scan failed for {}: {}", filename, e);
                return Ok(self.unknown_result(
                    start.elapsed().as_millis() as u64,
                    format!("YARA scan error: {e}"),
                ));
            }
        };

        let processing_time_ms = start.elapsed().as_millis() as u64;
        Ok(self.build_detection(matches, processing_time_ms))
    }

    fn scan(&self, data: &[u8]) -> Result<Vec<YaraMatch>, YaraEngineError> {
        let mut matches = Vec::new();
        for set in &self.rulesets {
            let hits = set
                .rules
                .scan_mem(data, self.config.timeout_seconds)
                .map_err(|e| YaraEngineError::ScanError(e.to_string()))?;
            for rule in hits {
                matches.push(Self::rule_to_match(&rule));
            }
        }
        Ok(matches)
    }

    fn rule_to_match(rule: &Rule) -> YaraMatch {
        let mut meta = HashMap::new();
        for m in &rule.metadatas {
            let value = match &m.value {
                MetadataValue::Integer(i) => i.to_string(),
                MetadataValue::String(s) => s.to_string(),
                MetadataValue::Boolean(b) => b.to_string(),
            };
            meta.insert(m.identifier.to_string(), value);
        }

        YaraMatch {
            rule_name: rule.identifier.to_string(),
            namespace: rule.namespace.to_string(),
            tags: rule.tags.iter().map(|t| t.to_string()).collect(),
            meta,
            matched_strings: rule.strings.len(),
        }
    }

    fn build_detection(&self, matches: Vec<YaraMatch>, processing_time_ms: u64) -> DetectionResult {
        use uuid::Uuid;

        if matches.is_empty() {
            return DetectionResult {
                detection_id: Uuid::new_v4(),
                engine_name: "YARA".to_string(),
                engine_version: "libyara".to_string(),
                engine_type: EngineType::Yara,
                verdict: ThreatVerdict::Benign,
                confidence: 0.5,
                severity: SeverityLevel::Info,
                categories: vec![],
                metadata: HashMap::new(),
                detected_at: chrono::Utc::now(),
                processing_time_ms,
                error_message: None,
            };
        }

        let severity = Self::severity_from(&matches);
        let verdict = match severity {
            SeverityLevel::Critical | SeverityLevel::High => ThreatVerdict::Malicious,
            _ => ThreatVerdict::Suspicious,
        };
        let confidence = {
            let base = 0.6 + 0.1 * (matches.len() as f32);
            let bumped = if matches!(severity, SeverityLevel::Critical) {
                base + 0.2
            } else {
                base
            };
            bumped.clamp(0.0, 0.98)
        };
        let categories = Self::categories_from(&matches);

        let mut metadata = HashMap::new();
        metadata.insert("match_count".to_string(), serde_json::json!(matches.len()));
        metadata.insert(
            "matched_rules".to_string(),
            serde_json::json!(matches
                .iter()
                .map(|m| m.rule_name.clone())
                .collect::<Vec<_>>()),
        );
        metadata.insert(
            "matches".to_string(),
            serde_json::to_value(&matches).unwrap_or_default(),
        );

        DetectionResult {
            detection_id: Uuid::new_v4(),
            engine_name: "YARA".to_string(),
            engine_version: "libyara".to_string(),
            engine_type: EngineType::Yara,
            verdict,
            confidence,
            severity,
            categories,
            metadata,
            detected_at: chrono::Utc::now(),
            processing_time_ms,
            error_message: None,
        }
    }

    /// Derive a severity from rule tags and the conventional `severity` meta
    /// field, taking the most severe across all matches.
    fn severity_from(matches: &[YaraMatch]) -> SeverityLevel {
        let mut best = SeverityLevel::Low;
        for m in matches {
            let mut tokens: Vec<String> = m.tags.iter().map(|t| t.to_lowercase()).collect();
            if let Some(sev) = m.meta.get("severity") {
                tokens.push(sev.to_lowercase());
            }
            for token in tokens {
                let level = match token.as_str() {
                    "critical" => SeverityLevel::Critical,
                    "high" => SeverityLevel::High,
                    "medium" | "moderate" => SeverityLevel::Medium,
                    "low" => SeverityLevel::Low,
                    _ => continue,
                };
                if Self::severity_rank(&level) > Self::severity_rank(&best) {
                    best = level;
                }
            }
        }
        best
    }

    fn severity_rank(level: &SeverityLevel) -> u8 {
        match level {
            SeverityLevel::Info => 0,
            SeverityLevel::Low => 1,
            SeverityLevel::Medium => 2,
            SeverityLevel::High => 3,
            SeverityLevel::Critical => 4,
        }
    }

    /// Map rule tags / names to threat categories.
    fn categories_from(matches: &[YaraMatch]) -> Vec<ThreatCategory> {
        let mut categories = Vec::new();
        let push_unique = |c: ThreatCategory, v: &mut Vec<ThreatCategory>| {
            if !v.contains(&c) {
                v.push(c);
            }
        };

        for m in matches {
            let haystack = format!(
                "{} {}",
                m.rule_name.to_lowercase(),
                m.tags.join(" ").to_lowercase()
            );
            if haystack.contains("trojan") {
                push_unique(ThreatCategory::Trojan, &mut categories);
            }
            if haystack.contains("ransom") {
                push_unique(ThreatCategory::Ransomware, &mut categories);
            }
            if haystack.contains("worm") {
                push_unique(ThreatCategory::Worm, &mut categories);
            }
            if haystack.contains("rootkit") {
                push_unique(ThreatCategory::Rootkit, &mut categories);
            }
            if haystack.contains("backdoor") {
                push_unique(ThreatCategory::Backdoor, &mut categories);
            }
            if haystack.contains("spyware") || haystack.contains("keylog") {
                push_unique(ThreatCategory::Spyware, &mut categories);
            }
            if haystack.contains("adware") {
                push_unique(ThreatCategory::Adware, &mut categories);
            }
            if haystack.contains("exploit") {
                push_unique(ThreatCategory::Exploit, &mut categories);
            }
            if haystack.contains("phish") {
                push_unique(ThreatCategory::Phishing, &mut categories);
            }
        }

        if categories.is_empty() {
            categories.push(ThreatCategory::Malware);
        }
        categories
    }

    fn unknown_result(&self, processing_time_ms: u64, error: String) -> DetectionResult {
        DetectionResult {
            detection_id: uuid::Uuid::new_v4(),
            engine_name: "YARA".to_string(),
            engine_version: "libyara".to_string(),
            engine_type: EngineType::Yara,
            verdict: ThreatVerdict::Unknown,
            confidence: 0.0,
            severity: SeverityLevel::Info,
            categories: vec![],
            metadata: HashMap::new(),
            detected_at: chrono::Utc::now(),
            processing_time_ms,
            error_message: Some(error),
        }
    }

    /// Recompile all rules from disk (e.g. after rules are updated).
    pub fn reload_rules(&mut self) -> Result<(), YaraEngineError> {
        info!("Reloading YARA rules");
        self.load_and_compile()?;
        info!("Reloaded {} YARA rule file(s)", self.rulesets.len());
        Ok(())
    }

    pub fn loaded_rule_files(&self) -> Vec<YaraRule> {
        self.rulesets
            .iter()
            .map(|s| YaraRule {
                namespace: s.namespace.clone(),
                source_file: s.source_file.clone(),
            })
            .collect()
    }

    pub fn get_stats(&self) -> HashMap<String, String> {
        HashMap::from([
            (
                "rule_files_loaded".to_string(),
                self.rulesets.len().to_string(),
            ),
            (
                "rules_directory".to_string(),
                self.config.rules_directory.display().to_string(),
            ),
            (
                "timeout_seconds".to_string(),
                self.config.timeout_seconds.to_string(),
            ),
            (
                "max_file_size".to_string(),
                self.config.max_file_size.to_string(),
            ),
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn write_rule(dir: &Path, name: &str, body: &str) {
        std::fs::write(dir.join(name), body).unwrap();
    }

    #[tokio::test]
    async fn test_compile_and_match() {
        let temp = TempDir::new().unwrap();
        write_rule(
            temp.path(),
            "test.yara",
            r#"
rule DetectsEvil : trojan {
    meta:
        severity = "high"
        description = "matches the marker string"
    strings:
        $a = "EVIL_MARKER"
    condition:
        $a
}
"#,
        );

        let config = YaraEngineConfig {
            rules_directory: temp.path().to_path_buf(),
            ..Default::default()
        };
        let engine = YaraEngine::new(config).unwrap();
        assert_eq!(engine.loaded_rule_files().len(), 1);

        // Matching input -> malicious (severity high).
        let hit = engine
            .analyze_file_data(b"prefix EVIL_MARKER suffix", "sample.bin")
            .await
            .unwrap();
        assert_eq!(hit.verdict, ThreatVerdict::Malicious);
        assert!(hit.categories.contains(&ThreatCategory::Trojan));

        // Non-matching input -> benign.
        let clean = engine
            .analyze_file_data(b"nothing to see here", "clean.bin")
            .await
            .unwrap();
        assert_eq!(clean.verdict, ThreatVerdict::Benign);
    }

    #[tokio::test]
    async fn test_bad_rule_file_is_skipped() {
        let temp = TempDir::new().unwrap();
        write_rule(
            temp.path(),
            "broken.yara",
            "this is not a valid yara rule {",
        );
        write_rule(
            temp.path(),
            "good.yara",
            "rule Ok { strings: $a = \"hello\" condition: $a }",
        );

        let config = YaraEngineConfig {
            rules_directory: temp.path().to_path_buf(),
            ..Default::default()
        };
        let engine = YaraEngine::new(config).unwrap();
        // Only the valid file compiles; the broken one is skipped.
        assert_eq!(engine.loaded_rule_files().len(), 1);
    }
}
