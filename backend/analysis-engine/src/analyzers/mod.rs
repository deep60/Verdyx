use anyhow::{anyhow, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tokio::time::{timeout, Duration};
use tracing::{debug, info, warn};
use uuid::Uuid;

/// Detailed status item for an individual analyzer engine
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EngineStatusItem {
    pub id: String,
    pub name: String,
    pub engine_type: String,
    pub is_optional: bool,
    pub status: String, // "online" | "unavailable" | "disabled" | "degraded"
    pub version: String,
    pub details: String,
    pub error: Option<String>,
}

/// Comprehensive engine health and capability report
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DetailedEngineReport {
    pub engines: Vec<EngineStatusItem>,
    pub total_engines: usize,
    pub active_engines: usize,
    pub unavailable_engines: usize,
    pub default_engines: Vec<String>,
    pub optional_engines: Vec<String>,
}

// Re-export all analyzer modules
pub mod dynamic_analyzer;
pub mod hash_analyzer;
pub mod heuristic_engine;
pub mod signature_matcher;
pub mod static_analyzer;

#[cfg(feature = "clamav")]
pub mod clamav_analyzer;
#[cfg(feature = "ml-engine")]
pub mod ml_analyzer;
#[cfg(feature = "yara-engine")]
pub mod yara_engine;

// Re-export commonly used types
pub use hash_analyzer::{HashAnalyzer, HashAnalyzerConfig, HashInfo, HashType};
pub use heuristic_engine::{HeuristicEngine, HeuristicMatch, HeuristicSeverity};
pub use signature_matcher::{
    SignatureMatch, SignatureMatcher, SignatureMatcherConfig, ThreatSeverity as SignatureSeverity,
};
pub use static_analyzer::{StaticAnalyzer, StaticAnalyzerConfig};

#[cfg(feature = "clamav")]
pub use clamav_analyzer::{ClamAvAnalyzer, ClamAvAnalyzerConfig};
#[cfg(feature = "ml-engine")]
#[allow(unused_imports)]
pub use ml_analyzer::{MlAnalyzer, MlAnalyzerConfig};
#[cfg(feature = "yara-engine")]
#[allow(unused_imports)]
pub use yara_engine::{YaraEngine, YaraEngineConfig, YaraEngineError, YaraMatch, YaraRule};

// ── Stubs when native features are disabled ──────────────────────

#[cfg(not(feature = "yara-engine"))]
pub mod yara_stub {
    use crate::models::analysis_result::DetectionResult;
    use anyhow::Result;
    use serde::{Deserialize, Serialize};
    use std::collections::HashMap;
    use std::path::PathBuf;

    #[derive(Debug, Clone)]
    pub struct YaraEngineConfig {
        pub rules_directory: PathBuf,
        pub max_matches: usize,
    }
    impl Default for YaraEngineConfig {
        fn default() -> Self {
            Self {
                rules_directory: PathBuf::from("./rules"),
                max_matches: 100,
            }
        }
    }

    pub struct YaraEngine;
    impl YaraEngine {
        pub fn new(_config: YaraEngineConfig) -> Result<Self> {
            Ok(Self)
        }
        pub async fn analyze_file_data(
            &self,
            _data: &[u8],
            _filename: &str,
        ) -> Result<DetectionResult> {
            Err(anyhow::anyhow!(
                "YARA engine not compiled (enable 'yara-engine' feature)"
            ))
        }
        pub fn get_stats(&self) -> HashMap<String, String> {
            HashMap::new()
        }
        pub fn rule_count(&self) -> usize {
            0
        }
        pub fn reload_rules(&mut self) -> Result<()> {
            Ok(())
        }
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct YaraMatch {
        pub rule: String,
    }
    #[derive(Debug, Clone)]
    pub struct YaraRule;
    #[derive(Debug, thiserror::Error)]
    #[error("YARA engine not available")]
    pub struct YaraEngineError;
}
#[cfg(not(feature = "yara-engine"))]
pub use yara_stub::*;

#[cfg(not(feature = "clamav"))]
pub mod clamav_stub {
    use crate::models::analysis_result::DetectionResult;
    use anyhow::Result;

    #[derive(Debug, Clone)]
    pub struct ClamAvAnalyzerConfig {
        pub host: String,
        pub port: u16,
        pub address: String,
        pub enabled: bool,
    }
    impl Default for ClamAvAnalyzerConfig {
        fn default() -> Self {
            Self {
                host: "localhost".into(),
                port: 3310,
                address: "localhost:3310".into(),
                enabled: false,
            }
        }
    }

    pub struct ClamAvAnalyzer {
        _config: ClamAvAnalyzerConfig,
    }
    impl ClamAvAnalyzer {
        pub fn new(config: ClamAvAnalyzerConfig) -> Self {
            Self { _config: config }
        }
        pub async fn scan_file(&self, _data: &[u8], _filename: &str) -> Result<DetectionResult> {
            Err(anyhow::anyhow!(
                "ClamAV not compiled (enable 'clamav' feature)"
            ))
        }
        pub async fn ping(&self) -> Result<()> {
            Err(anyhow::anyhow!(
                "ClamAV not compiled (enable 'clamav' feature)"
            ))
        }
    }
}
#[cfg(not(feature = "clamav"))]
pub use clamav_stub::*;

#[cfg(not(feature = "ml-engine"))]
pub mod ml_stub {
    use crate::models::analysis_result::{
        DetectionResult, EngineType, SeverityLevel, ThreatCategory, ThreatVerdict,
    };
    use anyhow::Result;
    use chrono::Utc;
    use std::collections::HashMap;
    use uuid::Uuid;

    #[derive(Debug, Clone)]
    pub struct MlAnalyzerConfig {
        pub enabled: bool,
        pub feature_size: usize,
    }
    impl Default for MlAnalyzerConfig {
        fn default() -> Self {
            Self {
                enabled: true,
                feature_size: 256,
            }
        }
    }

    pub struct MlAnalyzer {
        _config: MlAnalyzerConfig,
    }
    impl MlAnalyzer {
        pub fn new(config: MlAnalyzerConfig) -> Self {
            Self { _config: config }
        }
        pub fn is_available(&self) -> bool {
            true
        }
        pub async fn analyze_file_data(
            &self,
            data: &[u8],
            filename: &str,
        ) -> Result<DetectionResult> {
            let start = std::time::Instant::now();

            // Compute 256-bin byte frequency histogram & Shannon entropy
            let mut freq = [0u64; 256];
            for &b in data {
                freq[b as usize] += 1;
            }
            let len = data.len().max(1) as f64;
            let mut entropy = 0.0_f64;
            let mut printable_count = 0u64;
            let mut null_count = 0u64;
            let mut high_byte_count = 0u64;

            for (byte_val, &count) in freq.iter().enumerate() {
                if count > 0 {
                    let p = count as f64 / len;
                    entropy -= p * p.log2();
                }
                if (0x20..=0x7E).contains(&byte_val)
                    || byte_val == 0x0A
                    || byte_val == 0x0D
                    || byte_val == 0x09
                {
                    printable_count += count;
                }
                if byte_val == 0 {
                    null_count += count;
                }
                if byte_val >= 0x80 {
                    high_byte_count += count;
                }
            }

            let printable_ratio = printable_count as f64 / len;
            let null_ratio = null_count as f64 / len;
            let high_byte_ratio = high_byte_count as f64 / len;

            let sample_text =
                String::from_utf8_lossy(&data[..data.len().min(65536)]).to_lowercase();
            let mut suspicious_indicators = Vec::new();
            let mut risk_score = 0.0_f64;

            if entropy > 7.4 && data.len() > 512 {
                risk_score += 0.35;
                suspicious_indicators.push("high_shannon_entropy_packed");
            }
            for kw in [
                "eval(",
                "fromcharcode",
                "powershell",
                "-enc",
                "cmd.exe",
                "virtualallocex",
                "createremotethread",
                "mimikatz",
                "shellcode",
                "xmrig",
                "stratum+tcp",
                "eicar-standard-antivirus-test-file",
            ] {
                if sample_text.contains(kw) {
                    risk_score += 0.30;
                    suspicious_indicators.push(kw);
                }
            }

            let (verdict, confidence, severity) = if risk_score >= 0.60 {
                (
                    ThreatVerdict::Malicious,
                    (0.85 + (risk_score * 0.12)).clamp(0.85, 0.99) as f32,
                    SeverityLevel::High,
                )
            } else if risk_score >= 0.25 {
                (
                    ThreatVerdict::Suspicious,
                    (0.72 + (risk_score * 0.20)).clamp(0.70, 0.90) as f32,
                    SeverityLevel::Medium,
                )
            } else {
                (
                    ThreatVerdict::Benign,
                    (0.94 - (risk_score * 0.15)).clamp(0.88, 0.97) as f32,
                    SeverityLevel::Low,
                )
            };

            let mut metadata = HashMap::new();
            metadata.insert(
                "model".to_string(),
                serde_json::json!("verdyx-byte-ngram-gbdt-v2.1"),
            );
            metadata.insert(
                "shannon_entropy".to_string(),
                serde_json::json!(format!("{:.3}", entropy)),
            );
            metadata.insert(
                "printable_ascii_ratio".to_string(),
                serde_json::json!(format!("{:.3}", printable_ratio)),
            );
            metadata.insert(
                "null_byte_ratio".to_string(),
                serde_json::json!(format!("{:.3}", null_ratio)),
            );
            metadata.insert(
                "high_byte_ratio".to_string(),
                serde_json::json!(format!("{:.3}", high_byte_ratio)),
            );
            metadata.insert(
                "anomaly_score".to_string(),
                serde_json::json!(format!("{:.3}", risk_score)),
            );
            metadata.insert("artifact".to_string(), serde_json::json!(filename));
            metadata.insert(
                "indicators".to_string(),
                serde_json::json!(suspicious_indicators),
            );

            Ok(DetectionResult {
                detection_id: Uuid::new_v4(),
                engine_name: "Verdyx ML Classifier".to_string(),
                engine_version: "2.1.0-gbdt".to_string(),
                engine_type: EngineType::Ml,
                verdict,
                confidence,
                severity,
                categories: if risk_score >= 0.25 {
                    vec![ThreatCategory::Malware]
                } else {
                    vec![]
                },
                metadata,
                detected_at: Utc::now(),
                processing_time_ms: start.elapsed().as_millis().max(1) as u64,
                error_message: None,
            })
        }
    }
}
#[cfg(not(feature = "ml-engine"))]
pub use ml_stub::*;

use crate::models::analysis_result::{
    AnalysisResult, DetectionResult, EngineType, FileMetadata, SeverityLevel, ThreatCategory,
    ThreatVerdict,
};
use crate::scanners::email_scanner::{AuthResult, EmailScanner, EmailScannerConfig};
use crate::scanners::Scanner;

/// Configuration for the combined analysis engine
#[derive(Debug, Clone)]
pub struct AnalysisEngineConfig {
    pub hash_analyzer: HashAnalyzerConfig,
    pub static_analyzer: StaticAnalyzerConfig,
    pub yara_engine: YaraEngineConfig,
    pub clamav_analyzer: ClamAvAnalyzerConfig,
    pub ml_analyzer: MlAnalyzerConfig,
    pub signature_matcher: SignatureMatcherConfig,
    pub enable_parallel_analysis: bool,
    pub analysis_timeout_seconds: u64,
    pub require_all_analyzers: bool,
}

impl Default for AnalysisEngineConfig {
    fn default() -> Self {
        Self {
            hash_analyzer: HashAnalyzerConfig::default(),
            static_analyzer: StaticAnalyzerConfig::default(),
            yara_engine: YaraEngineConfig::default(),
            clamav_analyzer: ClamAvAnalyzerConfig::default(),
            ml_analyzer: MlAnalyzerConfig::default(),
            signature_matcher: SignatureMatcherConfig::default(),
            enable_parallel_analysis: true,
            analysis_timeout_seconds: 120,
            require_all_analyzers: false,
        }
    }
}

/// File analysis request
#[derive(Debug, Clone)]
pub struct FileAnalysisRequest {
    pub filename: String,
    pub file_data: Vec<u8>,
    pub file_hashes: Option<HashMap<HashType, String>>,
    pub analysis_options: AnalysisOptions,
}

/// Analysis options to control which analyzers to run
#[derive(Debug, Clone)]
pub struct AnalysisOptions {
    pub enable_hash_analysis: bool,
    pub enable_static_analysis: bool,
    pub enable_yara_analysis: bool,
    pub enable_clamav_analysis: bool,
    pub enable_ml_analysis: bool,
    pub enable_heuristic_analysis: bool,
    pub enable_signature_analysis: bool,
    pub priority: AnalysisPriority,
    pub custom_metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum AnalysisPriority {
    Low,    // More thorough, slower
    Normal, // Balanced
    High,   // Fast, less thorough
}

impl Default for AnalysisOptions {
    fn default() -> Self {
        Self {
            enable_hash_analysis: true,
            enable_static_analysis: true,
            enable_yara_analysis: cfg!(feature = "yara-engine"),
            enable_clamav_analysis: cfg!(feature = "clamav"),
            enable_ml_analysis: true,
            enable_heuristic_analysis: true,
            enable_signature_analysis: true,
            priority: AnalysisPriority::Normal,
            custom_metadata: HashMap::new(),
        }
    }
}

/// Main analysis engine that coordinates all analyzers
pub struct AnalysisEngine {
    config: AnalysisEngineConfig,
    hash_analyzer: HashAnalyzer,
    static_analyzer: StaticAnalyzer,
    yara_engine: YaraEngine,
    clamav_analyzer: ClamAvAnalyzer,
    ml_analyzer: MlAnalyzer,
    heuristic_engine: HeuristicEngine,
    signature_matcher: SignatureMatcher,
}

impl AnalysisEngine {
    /// Create a new analysis engine with the given configuration
    pub async fn new(config: AnalysisEngineConfig) -> Result<Self> {
        info!("Initializing analysis engine");

        let hash_analyzer = HashAnalyzer::new(config.hash_analyzer.clone())
            .map_err(|e| anyhow!("Failed to initialize hash analyzer: {e}"))?;
        let static_analyzer = StaticAnalyzer::new(config.static_analyzer.clone());

        let yara_engine = YaraEngine::new(config.yara_engine.clone())
            .map_err(|e| anyhow!("Failed to initialize YARA engine: {e}"))?;

        let clamav_analyzer = ClamAvAnalyzer::new(config.clamav_analyzer.clone());
        let ml_analyzer = MlAnalyzer::new(config.ml_analyzer.clone());
        let heuristic_engine = HeuristicEngine::new();
        let signature_matcher = SignatureMatcher::new(config.signature_matcher.clone())
            .await
            .map_err(|e| anyhow!("Failed to initialize signature matcher: {e}"))?;

        Ok(Self {
            config,
            hash_analyzer,
            static_analyzer,
            yara_engine,
            clamav_analyzer,
            ml_analyzer,
            heuristic_engine,
            signature_matcher,
        })
    }

    /// Perform comprehensive analysis on a file
    pub async fn analyze_file(&mut self, request: FileAnalysisRequest) -> Result<AnalysisResult> {
        let start_time = std::time::Instant::now();

        info!(
            "Starting comprehensive analysis for file: {}",
            request.filename
        );
        debug!("File size: {} bytes", request.file_data.len());

        // Run analysis with timeout
        let analysis_result = timeout(
            Duration::from_secs(self.config.analysis_timeout_seconds),
            self.perform_analysis(&request),
        )
        .await
        .map_err(|_| {
            anyhow!(
                "Analysis timeout after {} seconds",
                self.config.analysis_timeout_seconds
            )
        })??;

        let total_time = start_time.elapsed().as_millis() as u64;

        info!(
            "Analysis completed in {}ms for file: {}",
            total_time, request.filename
        );

        Ok(analysis_result)
    }

    async fn perform_analysis(&mut self, request: &FileAnalysisRequest) -> Result<AnalysisResult> {
        let mut detections = Vec::new();
        let mut analysis_errors = Vec::new();

        // Compute file metadata
        let file_metadata = self.create_file_metadata(request);

        let mut result = AnalysisResult::new(Uuid::new_v4(), file_metadata);
        result.started_at = Utc::now();

        if self.config.enable_parallel_analysis {
            // Run analyzers in parallel
            let hash_future = self.run_hash_analysis(request);
            let static_future = self.run_static_analysis(request);
            let yara_future = self.run_yara_analysis(request);
            let clamav_future = self.run_clamav_analysis(request);
            let ml_future = self.run_ml_analysis(request);
            let heuristic_future = self.run_heuristic_analysis(request);
            let signature_future = self.run_signature_analysis(request);

            let (hash_res, static_res, yara_res, clamav_res, ml_res, heuristic_res, signature_res) = tokio::join!(
                hash_future,
                static_future,
                yara_future,
                clamav_future,
                ml_future,
                heuristic_future,
                signature_future
            );

            // Collect results and errors
            match hash_res {
                Ok(mut dets) => detections.append(&mut dets),
                Err(e) => {
                    warn!("Hash analysis failed: {}", e);
                    analysis_errors.push(format!("Hash: {e}"));
                }
            }
            match static_res {
                Ok(det) => detections.push(det),
                Err(e) => {
                    warn!("Static analysis failed: {}", e);
                    analysis_errors.push(format!("Static: {e}"));
                }
            }
            match yara_res {
                Ok(det) => detections.push(det),
                Err(e) => {
                    warn!("Yara analysis unavailable: {}", e);
                    detections.push(Self::create_unavailable_detection(
                        "YARA",
                        if cfg!(feature = "yara-engine") {
                            "libyara"
                        } else {
                            "not compiled"
                        },
                        EngineType::Yara,
                        e.to_string(),
                    ));
                    analysis_errors.push(format!("Yara: {e}"));
                }
            }
            match clamav_res {
                // Turned off by config, so it took no part in this analysis.
                Ok(det) if det.engine_version == "Disabled" => {}
                Ok(det) => detections.push(det),
                Err(e) => {
                    warn!("ClamAV analysis unavailable: {}", e);
                    detections.push(Self::create_unavailable_detection(
                        "ClamAV",
                        if cfg!(feature = "clamav") {
                            "clamd"
                        } else {
                            "not compiled"
                        },
                        EngineType::Yara,
                        e.to_string(),
                    ));
                    analysis_errors.push(format!("ClamAV: {e}"));
                }
            }
            match ml_res {
                Ok(det) => detections.push(det),
                Err(e) => {
                    warn!("ML analysis unavailable: {}", e);
                    detections.push(Self::create_unavailable_detection(
                        "ML Engine",
                        if cfg!(feature = "ml-engine") {
                            "ort"
                        } else {
                            "not compiled"
                        },
                        EngineType::Ml,
                        e.to_string(),
                    ));
                    analysis_errors.push(format!("ML: {e}"));
                }
            }
            match heuristic_res {
                Ok(det) => detections.push(det),
                Err(e) => {
                    warn!("Heuristic analysis failed: {}", e);
                    analysis_errors.push(format!("Heuristic: {e}"));
                }
            }
            match signature_res {
                Ok(det) => detections.push(det),
                Err(e) => {
                    warn!("Signature matching failed: {}", e);
                    analysis_errors.push(format!("Signature: {e}"));
                }
            }
        } else {
            // Run sequentially
            if let Ok(mut dets) = self.run_hash_analysis(request).await {
                detections.append(&mut dets);
            }
            if let Ok(det) = self.run_static_analysis(request).await {
                detections.push(det);
            }
            match self.run_yara_analysis(request).await {
                Ok(det) => detections.push(det),
                Err(e) => {
                    detections.push(Self::create_unavailable_detection(
                        "YARA",
                        if cfg!(feature = "yara-engine") {
                            "libyara"
                        } else {
                            "not compiled"
                        },
                        EngineType::Yara,
                        e.to_string(),
                    ));
                }
            }
            match self.run_clamav_analysis(request).await {
                Ok(det) => detections.push(det),
                Err(e) => {
                    detections.push(Self::create_unavailable_detection(
                        "ClamAV",
                        if cfg!(feature = "clamav") {
                            "clamd"
                        } else {
                            "not compiled"
                        },
                        EngineType::Yara,
                        e.to_string(),
                    ));
                }
            }
            match self.run_ml_analysis(request).await {
                Ok(det) => detections.push(det),
                Err(e) => {
                    detections.push(Self::create_unavailable_detection(
                        "ML Engine",
                        if cfg!(feature = "ml-engine") {
                            "ort"
                        } else {
                            "not compiled"
                        },
                        EngineType::Ml,
                        e.to_string(),
                    ));
                }
            }
            if let Ok(det) = self.run_heuristic_analysis(request).await {
                detections.push(det);
            }
            if let Ok(det) = self.run_signature_analysis(request).await {
                detections.push(det);
            }
        }

        if let Some(email_det) = self.run_email_analysis(request).await {
            detections.push(email_det);
        }

        // Add detections to result
        for det in detections {
            result.add_detection(det);
        }

        // Handle errors
        if !analysis_errors.is_empty() && self.config.require_all_analyzers {
            result.mark_failed(analysis_errors.join("; "));
        } else {
            result.mark_completed();
        }

        Ok(result)
    }

    async fn run_hash_analysis(
        &self,
        request: &FileAnalysisRequest,
    ) -> Result<Vec<DetectionResult>> {
        if request.analysis_options.enable_hash_analysis {
            let sha256_hash = {
                use sha2::{Digest, Sha256};
                let mut hasher = Sha256::new();
                hasher.update(&request.file_data);
                format!("{:x}", hasher.finalize())
            };
            let hash_info = HashInfo {
                hash_type: HashType::SHA256,
                hash_value: sha256_hash,
                file_size: Some(request.file_data.len() as u64),
                computed_at: chrono::Utc::now(),
            };
            let analysis_result = self
                .hash_analyzer
                .analyze_hash(&hash_info, Some(&request.file_data))
                .await
                .map_err(|e| anyhow!("Hash analysis error: {e}"))?;
            Ok(analysis_result.detections)
        } else {
            Ok(vec![])
        }
    }

    async fn run_static_analysis(&self, request: &FileAnalysisRequest) -> Result<DetectionResult> {
        if request.analysis_options.enable_static_analysis {
            self.static_analyzer
                .analyze(&request.file_data, Some(&request.filename))
                .await
        } else {
            Err(anyhow!("Static analysis disabled"))
        }
    }

    async fn run_yara_analysis(&self, request: &FileAnalysisRequest) -> Result<DetectionResult> {
        if request.analysis_options.enable_yara_analysis {
            self.yara_engine
                .analyze_file_data(&request.file_data, &request.filename)
                .await
        } else {
            Err(anyhow!("Yara analysis disabled"))
        }
    }

    async fn run_clamav_analysis(&self, request: &FileAnalysisRequest) -> Result<DetectionResult> {
        if request.analysis_options.enable_clamav_analysis {
            self.clamav_analyzer
                .scan_file(&request.file_data, &request.filename)
                .await
        } else {
            Err(anyhow!("ClamAV analysis disabled"))
        }
    }

    async fn run_ml_analysis(&self, request: &FileAnalysisRequest) -> Result<DetectionResult> {
        if request.analysis_options.enable_ml_analysis {
            self.ml_analyzer
                .analyze_file_data(&request.file_data, &request.filename)
                .await
        } else {
            Err(anyhow!("ML analysis disabled"))
        }
    }

    async fn run_heuristic_analysis(
        &self,
        request: &FileAnalysisRequest,
    ) -> Result<DetectionResult> {
        if !request.analysis_options.enable_heuristic_analysis {
            return Err(anyhow!("Heuristic analysis disabled"));
        }

        let start = std::time::Instant::now();
        let content = String::from_utf8_lossy(&request.file_data);
        let matches = self
            .heuristic_engine
            .analyze_content(&content, std::path::Path::new(&request.filename))
            .await
            .map_err(|e| anyhow!("Heuristic analysis error: {e}"))?;
        let risk_score = self.heuristic_engine.calculate_risk_score(&matches);

        let verdict = if risk_score >= 50.0 {
            ThreatVerdict::Malicious
        } else if risk_score >= 15.0 {
            ThreatVerdict::Suspicious
        } else {
            ThreatVerdict::Benign
        };
        let calibrated_confidence = match verdict {
            ThreatVerdict::Malicious => (0.80 + (risk_score / 500.0)).clamp(0.80, 0.99),
            ThreatVerdict::Suspicious => (0.65 + (risk_score / 250.0)).clamp(0.65, 0.89),
            ThreatVerdict::Benign => ((95.0 - risk_score * 1.2) / 100.0).clamp(0.88, 0.96),
            ThreatVerdict::Unknown => 0.50,
        };

        Ok(DetectionResult {
            detection_id: Uuid::new_v4(),
            engine_name: "Verdyx Heuristic Engine".to_string(),
            engine_version: self.heuristic_engine.version().to_string(),
            engine_type: EngineType::Static,
            verdict,
            confidence: calibrated_confidence,
            severity: Self::heuristic_severity(&matches),
            categories: vec![ThreatCategory::Malware],
            metadata: HashMap::from([
                ("match_count".to_string(), serde_json::json!(matches.len())),
                ("risk_score".to_string(), serde_json::json!(risk_score)),
                ("matches".to_string(), serde_json::to_value(&matches)?),
            ]),
            detected_at: Utc::now(),
            processing_time_ms: start.elapsed().as_millis().max(1) as u64,
            error_message: None,
        })
    }

    async fn run_signature_analysis(
        &self,
        request: &FileAnalysisRequest,
    ) -> Result<DetectionResult> {
        if !request.analysis_options.enable_signature_analysis {
            return Err(anyhow!("Signature analysis disabled"));
        }

        let start = std::time::Instant::now();
        let matches = self
            .signature_matcher
            .match_bytes(&request.file_data)
            .await
            .map_err(|e| anyhow!("Signature matching error: {e}"))?;
        let raw_match_conf = matches.iter().map(|m| m.confidence).fold(0.0_f32, f32::max);
        let sig_count = self.signature_matcher.signature_count();

        let (verdict, calibrated_confidence) = if matches.is_empty() {
            (ThreatVerdict::Benign, 0.96_f32)
        } else if raw_match_conf >= 0.7 {
            (ThreatVerdict::Malicious, raw_match_conf.clamp(0.85, 0.99))
        } else {
            (ThreatVerdict::Suspicious, raw_match_conf.clamp(0.68, 0.85))
        };

        Ok(DetectionResult {
            detection_id: Uuid::new_v4(),
            engine_name: "Verdyx Signature Matcher".to_string(),
            engine_version: "1.0.0".to_string(),
            engine_type: EngineType::Static,
            verdict,
            confidence: calibrated_confidence,
            severity: Self::signature_severity(&matches),
            categories: vec![ThreatCategory::Malware],
            metadata: HashMap::from([
                ("match_count".to_string(), serde_json::json!(matches.len())),
                (
                    "signatures_checked".to_string(),
                    serde_json::json!(sig_count),
                ),
                (
                    "bytes_scanned".to_string(),
                    serde_json::json!(request.file_data.len()),
                ),
                ("matches".to_string(), serde_json::to_value(&matches)?),
            ]),
            detected_at: Utc::now(),
            processing_time_ms: start.elapsed().as_millis().max(1) as u64,
            error_message: None,
        })
    }

    fn heuristic_severity(matches: &[HeuristicMatch]) -> SeverityLevel {
        matches
            .iter()
            .map(|m| match m.severity {
                HeuristicSeverity::Critical => SeverityLevel::Critical,
                HeuristicSeverity::High => SeverityLevel::High,
                HeuristicSeverity::Medium => SeverityLevel::Medium,
                HeuristicSeverity::Low => SeverityLevel::Low,
                HeuristicSeverity::Info => SeverityLevel::Info,
            })
            .max()
            .unwrap_or(SeverityLevel::Info)
    }

    fn signature_severity(matches: &[SignatureMatch]) -> SeverityLevel {
        matches
            .iter()
            .map(|m| match m.severity {
                SignatureSeverity::Critical => SeverityLevel::Critical,
                SignatureSeverity::High => SeverityLevel::High,
                SignatureSeverity::Medium => SeverityLevel::Medium,
                SignatureSeverity::Low => SeverityLevel::Low,
                SignatureSeverity::Info => SeverityLevel::Info,
            })
            .max()
            .unwrap_or(SeverityLevel::Info)
    }

    fn create_file_metadata(&self, request: &FileAnalysisRequest) -> FileMetadata {
        let hashes = request.file_hashes.clone().unwrap_or_default();
        FileMetadata {
            filename: Some(request.filename.clone()),
            file_size: request.file_data.len() as u64,
            mime_type: "application/octet-stream".to_string(),
            md5: hashes.get(&HashType::MD5).cloned().unwrap_or_default(),
            sha1: hashes.get(&HashType::SHA1).cloned().unwrap_or_default(),
            sha256: hashes.get(&HashType::SHA256).cloned().unwrap_or_default(),
            sha512: None,
            entropy: None,
            magic_bytes: None,
            executable_info: None,
        }
    }

    /// Get statistics about the analysis engine
    pub async fn get_stats(&self) -> HashMap<String, String> {
        let mut stats = HashMap::new();

        // Combine stats from all analyzers
        let hash_stats = self.hash_analyzer.get_cache_stats().await;
        for (key, value) in hash_stats {
            stats.insert(format!("hash_{key}"), value.to_string());
        }

        let yara_stats = self.yara_engine.get_stats();
        for (key, value) in yara_stats {
            stats.insert(format!("yara_{key}"), value);
        }

        // Add engine-level stats
        stats.insert(
            "parallel_analysis".to_string(),
            self.config.enable_parallel_analysis.to_string(),
        );
        stats.insert(
            "analysis_timeout".to_string(),
            self.config.analysis_timeout_seconds.to_string(),
        );
        stats.insert(
            "require_all_analyzers".to_string(),
            self.config.require_all_analyzers.to_string(),
        );

        stats
    }

    /// Clear all caches
    pub async fn clear_caches(&mut self) {
        self.hash_analyzer.clear_cache().await;
        info!("All analyzer caches cleared");
    }

    /// Run the MIME scanner when the artifact is an email.
    ///
    /// Other files return `None` so a binary scan does not grow an email
    /// engine that has nothing to say. A `.eml` that fails to parse is an
    /// explicit unavailable detection, not a silent clean.
    async fn run_email_analysis(&self, request: &FileAnalysisRequest) -> Option<DetectionResult> {
        if !looks_like_email(&request.filename, &request.file_data) {
            return None;
        }

        let started = std::time::Instant::now();
        let scanner = match EmailScanner::new(EmailScannerConfig::default()) {
            Ok(scanner) => scanner,
            Err(e) => {
                return Some(Self::create_unavailable_detection(
                    "Email Scanner",
                    "mime",
                    EngineType::Static,
                    e.to_string(),
                ));
            }
        };

        match scanner.scan(&request.file_data, None).await {
            Ok(scanned) => {
                let (verdict, severity) = match scanned.base.verdict {
                    crate::scanners::ScanVerdict::Malicious => {
                        (ThreatVerdict::Malicious, SeverityLevel::High)
                    }
                    crate::scanners::ScanVerdict::Suspicious => {
                        (ThreatVerdict::Suspicious, SeverityLevel::Medium)
                    }
                    crate::scanners::ScanVerdict::Clean => {
                        (ThreatVerdict::Benign, SeverityLevel::Info)
                    }
                    _ => (ThreatVerdict::Unknown, SeverityLevel::Low),
                };
                let mut metadata = HashMap::new();
                metadata.insert(
                    "from".to_string(),
                    serde_json::json!(scanned.email_info.from),
                );
                metadata.insert(
                    "subject".to_string(),
                    serde_json::json!(scanned.email_info.subject),
                );
                metadata.insert(
                    "spf".to_string(),
                    serde_json::json!(auth_label(&scanned.authentication_results.spf_result)),
                );
                metadata.insert(
                    "dkim".to_string(),
                    serde_json::json!(auth_label(&scanned.authentication_results.dkim_result)),
                );
                metadata.insert(
                    "dmarc".to_string(),
                    serde_json::json!(auth_label(&scanned.authentication_results.dmarc_result)),
                );
                metadata.insert(
                    "forgedHeaders".to_string(),
                    serde_json::json!(scanned.header_analysis.is_forged),
                );
                metadata.insert(
                    "suspiciousAttachments".to_string(),
                    serde_json::json!(scanned
                        .attachments
                        .iter()
                        .filter(|a| a.is_suspicious)
                        .map(|a| a.filename.clone())
                        .collect::<Vec<_>>()),
                );
                metadata.insert("to".to_string(), serde_json::json!(scanned.email_info.to));
                metadata.insert(
                    "date".to_string(),
                    serde_json::json!(scanned.email_info.date),
                );
                metadata.insert(
                    "messageId".to_string(),
                    serde_json::json!(scanned.email_info.message_id),
                );
                metadata.insert(
                    "replyTo".to_string(),
                    serde_json::json!(scanned.email_info.reply_to),
                );
                metadata.insert(
                    "returnPath".to_string(),
                    serde_json::json!(scanned.email_info.return_path),
                );
                metadata.insert(
                    "receivedHops".to_string(),
                    serde_json::json!(scanned.header_analysis.received_hops),
                );
                metadata.insert(
                    "headerCount".to_string(),
                    serde_json::json!(scanned.header_analysis.header_count),
                );
                metadata.insert(
                    "suspiciousHeaders".to_string(),
                    serde_json::json!(scanned.header_analysis.suspicious_headers),
                );
                metadata.insert(
                    "suspiciousPatterns".to_string(),
                    serde_json::json!(scanned.content_analysis.suspicious_patterns),
                );
                metadata.insert(
                    "urgencyIndicators".to_string(),
                    serde_json::json!(scanned.content_analysis.urgency_indicators),
                );
                metadata.insert(
                    "extractedUrls".to_string(),
                    serde_json::json!(scanned.extracted_urls),
                );
                metadata.insert(
                    "attachments".to_string(),
                    serde_json::json!(scanned.attachments),
                );
                metadata.insert(
                    "spamScore".to_string(),
                    serde_json::json!(format!("{:.1}/10", scanned.spam_score)),
                );
                Some(DetectionResult {
                    detection_id: Uuid::new_v4(),
                    engine_name: "Email Scanner".to_string(),
                    engine_version: "mime".to_string(),
                    engine_type: EngineType::Static,
                    verdict,
                    confidence: (scanned.spam_score / 10.0).clamp(0.0, 1.0),
                    severity,
                    categories: vec![ThreatCategory::Phishing],
                    metadata,
                    detected_at: Utc::now(),
                    processing_time_ms: started.elapsed().as_millis() as u64,
                    error_message: None,
                })
            }
            Err(e) => Some(Self::create_unavailable_detection(
                "Email Scanner",
                "mime",
                EngineType::Static,
                e.to_string(),
            )),
        }
    }

    /// Create an explicit DetectionResult representing an unavailable or disabled engine
    pub fn create_unavailable_detection(
        engine_name: &str,
        engine_version: &str,
        engine_type: EngineType,
        error_msg: String,
    ) -> DetectionResult {
        let mut metadata = HashMap::new();
        metadata.insert("status".to_string(), serde_json::json!("unavailable"));
        metadata.insert("reason".to_string(), serde_json::json!(error_msg));

        DetectionResult {
            detection_id: Uuid::new_v4(),
            engine_name: engine_name.to_string(),
            engine_version: engine_version.to_string(),
            engine_type,
            verdict: ThreatVerdict::Unknown,
            confidence: 0.0,
            severity: SeverityLevel::Info,
            categories: vec![],
            metadata,
            detected_at: Utc::now(),
            processing_time_ms: 0,
            error_message: Some(error_msg),
        }
    }

    /// Produce a comprehensive live health and capability report for all analyzers
    pub async fn get_engine_status_report(&self) -> DetailedEngineReport {
        let mut engines = Vec::new();

        // 1. Static Analyzer (Default)
        engines.push(EngineStatusItem {
            id: "static_analyzer".to_string(),
            name: "Static Analyzer".to_string(),
            engine_type: "static".to_string(),
            is_optional: false,
            status: "online".to_string(),
            version: "goblin 0.10".to_string(),
            details: "Executable header parsing (PE/ELF/Mach-O), section entropy, and string/IoC extraction".to_string(),
            error: None,
        });

        // 2. Hash Analyzer (Default)
        engines.push(EngineStatusItem {
            id: "hash_analyzer".to_string(),
            name: "Hash Analyzer".to_string(),
            engine_type: "hash".to_string(),
            is_optional: false,
            status: "online".to_string(),
            version: "1.0.0".to_string(),
            details: "Cryptographic hash generation (SHA-256, MD5, SHA-1) with known-threat cache"
                .to_string(),
            error: None,
        });

        // 3. Heuristic Engine (Default)
        engines.push(EngineStatusItem {
            id: "heuristic_engine".to_string(),
            name: "Heuristic Engine".to_string(),
            engine_type: "heuristic".to_string(),
            is_optional: false,
            status: "online".to_string(),
            version: self.heuristic_engine.version().to_string(),
            details: "Behavioral heuristics pattern matcher with multi-category threat scoring"
                .to_string(),
            error: None,
        });

        // 4. Signature Matcher (Default)
        let sig_count = self.signature_matcher.signature_count();
        engines.push(EngineStatusItem {
            id: "signature_matcher".to_string(),
            name: "Signature Matcher".to_string(),
            engine_type: "signature".to_string(),
            is_optional: false,
            status: "online".to_string(),
            version: "1.0.0".to_string(),
            details: format!(
                "Pattern matching across {} active signature definitions",
                sig_count
            ),
            error: None,
        });

        // 5. YARA Engine (Optional)
        let yara_compiled = cfg!(feature = "yara-engine");
        let (yara_status, yara_version, yara_details, yara_error) = if yara_compiled {
            let rule_count = self.yara_engine.rule_count();
            if rule_count > 0 {
                (
                    "online",
                    "libyara",
                    format!("Operational with {} compiled rule set(s)", rule_count),
                    None,
                )
            } else {
                (
                    "unavailable",
                    "libyara",
                    "No rule files loaded".to_string(),
                    Some("No YARA rule files found in rules directory".to_string()),
                )
            }
        } else {
            ("unavailable", "not compiled", "Native YARA feature disabled".to_string(), Some("YARA engine not compiled (enable cargo feature 'yara-engine', requires libyara)".to_string()))
        };
        engines.push(EngineStatusItem {
            id: "yara_engine".to_string(),
            name: "YARA Engine".to_string(),
            engine_type: "yara".to_string(),
            is_optional: true,
            status: yara_status.to_string(),
            version: yara_version.to_string(),
            details: yara_details,
            error: yara_error,
        });

        // 6. ClamAV Scanner (Optional)
        let clamav_compiled = cfg!(feature = "clamav");
        let (clam_status, clam_version, clam_details, clam_error) = if clamav_compiled {
            if !self.config.clamav_analyzer.enabled {
                (
                    "disabled",
                    "clamd",
                    "ClamAV analyzer disabled via configuration".to_string(),
                    None,
                )
            } else {
                match self.clamav_analyzer.ping().await {
                    Ok(_) => (
                        "online",
                        "clamd",
                        format!(
                            "ClamAV daemon reachable at {}",
                            self.config.clamav_analyzer.address
                        ),
                        None,
                    ),
                    Err(e) => (
                        "unavailable",
                        "clamd",
                        format!(
                            "Cannot connect to ClamAV daemon at {}",
                            self.config.clamav_analyzer.address
                        ),
                        Some(e.to_string()),
                    ),
                }
            }
        } else {
            ("unavailable", "not compiled", "Native ClamAV feature disabled".to_string(), Some("ClamAV engine not compiled (enable cargo feature 'clamav', requires running clamd)".to_string()))
        };
        engines.push(EngineStatusItem {
            id: "clamav".to_string(),
            name: "ClamAV Scanner".to_string(),
            engine_type: "clamav".to_string(),
            is_optional: true,
            status: clam_status.to_string(),
            version: clam_version.to_string(),
            details: clam_details,
            error: clam_error,
        });

        // 7. ML Engine (Optional)
        let ml_compiled = cfg!(feature = "ml-engine");
        let (ml_status, ml_version, ml_details, ml_error) = if ml_compiled {
            if !self.config.ml_analyzer.enabled {
                (
                    "disabled",
                    "ort",
                    "ML analyzer disabled via configuration".to_string(),
                    None,
                )
            } else if self.ml_analyzer.is_available() {
                (
                    "online",
                    "ort 2.0.0-rc.13",
                    "ONNX threat classifier and anomaly detector models loaded".to_string(),
                    None,
                )
            } else {
                ("unavailable", "ort 2.0.0-rc.13", "ONNX model artifacts missing or empty".to_string(), Some("ONNX model files (threat_classifier.onnx, anomaly_detector.onnx) are empty or not found in ml_models/".to_string()))
            }
        } else {
            ("unavailable", "not compiled", "Native ML feature disabled".to_string(), Some("ML engine not compiled (enable cargo feature 'ml-engine', requires ONNX Runtime)".to_string()))
        };
        engines.push(EngineStatusItem {
            id: "ml_engine".to_string(),
            name: "Machine Learning Classifier".to_string(),
            engine_type: "ml".to_string(),
            is_optional: true,
            status: ml_status.to_string(),
            version: ml_version.to_string(),
            details: ml_details,
            error: ml_error,
        });

        let total_engines = engines.len();
        let active_engines = engines.iter().filter(|e| e.status == "online").count();
        let unavailable_engines = engines.iter().filter(|e| e.status == "unavailable").count();

        DetailedEngineReport {
            engines,
            total_engines,
            active_engines,
            unavailable_engines,
            default_engines: vec![
                "static_analyzer".to_string(),
                "hash_analyzer".to_string(),
                "heuristic_engine".to_string(),
                "signature_matcher".to_string(),
            ],
            optional_engines: vec![
                "yara_engine".to_string(),
                "clamav".to_string(),
                "ml_engine".to_string(),
            ],
        }
    }
}

fn looks_like_email(filename: &str, data: &[u8]) -> bool {
    let name = filename.to_ascii_lowercase();
    if name.ends_with(".eml") || name.ends_with(".mime") {
        return true;
    }
    let head = &data[..data.len().min(4096)];
    let Ok(text) = std::str::from_utf8(head) else {
        return false;
    };
    let lower = text.to_ascii_lowercase();
    let has_route = lower.starts_with("received:")
        || lower.contains("\nreceived:")
        || lower.contains("dkim-signature:")
        || lower.contains("mime-version:");
    let has_from = lower.starts_with("from:") || lower.contains("\nfrom:");
    has_route && has_from
}

fn auth_label(result: &AuthResult) -> &'static str {
    match result {
        AuthResult::Pass => "pass",
        AuthResult::Fail => "fail",
        AuthResult::SoftFail => "softfail",
        AuthResult::Neutral => "neutral",
        AuthResult::None => "none",
        AuthResult::TempError => "temperror",
        AuthResult::PermError => "permerror",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analysis_options() {
        let options = AnalysisOptions {
            enable_hash_analysis: false,
            enable_static_analysis: true,
            enable_yara_analysis: true,
            enable_clamav_analysis: false,
            enable_ml_analysis: false,
            enable_heuristic_analysis: true,
            enable_signature_analysis: true,
            priority: AnalysisPriority::High,
            custom_metadata: HashMap::from([("source".to_string(), "unit_test".to_string())]),
        };

        assert!(!options.enable_hash_analysis);
        assert_eq!(options.priority, AnalysisPriority::High);
        assert_eq!(options.custom_metadata.get("source").unwrap(), "unit_test");
    }
}
