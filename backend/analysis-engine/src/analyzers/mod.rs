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
    pub status: String, // "online" | "advisory" | "unavailable" | "disabled" | "degraded"
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
pub mod apk_analyzer;
pub mod dynamic_analyzer;
pub mod hash_analyzer;
pub mod heuristic_engine;
pub mod office_analyzer;
pub mod pdf_analyzer;
pub mod pe_model_analyzer;
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
pub use pe_model_analyzer::{PeModelAnalyzer, PeModelConfig};
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
        pub fn rules_loaded(&self) -> usize {
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
        pub counts_toward_verdict: bool,
    }
    impl Default for MlAnalyzerConfig {
        fn default() -> Self {
            Self {
                enabled: true,
                feature_size: 256,
                counts_toward_verdict: false,
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
            // Not a trained model: fixed entropy and keyword rules, used only
            // in builds without the `ml-engine` feature.
            metadata.insert(
                "model".to_string(),
                serde_json::json!("byte-profile-rules (not machine learning)"),
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
                engine_name: "Byte Profile Rules".to_string(),
                engine_version: "fallback".to_string(),
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
    ThreatVerdict, STRONG_SIGNAL_KEY,
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
    pub pe_model: PeModelConfig,
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
            pe_model: PeModelConfig::default(),
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
    /// Unpack archives and scan the files inside.
    pub unpack_archives: bool,
    /// Deep Inspection: follow archives one level further, take more files
    /// from each and give them more time.
    pub deep: bool,
    pub priority: AnalysisPriority,
    pub custom_metadata: HashMap<String, String>,
}

/// The analysis type picked on the submit form (`metadata.analysisType`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AnalysisMode {
    /// Reputation lookups, ClamAV, YARA and signatures. No unpacking.
    Quick,
    /// Every engine. What an unspecified scan gets.
    #[default]
    Full,
    /// Every engine, with deeper archive unpacking.
    Deep,
    /// Deep, plus VirusTotal's sandbox report.
    Behavioral,
}

impl AnalysisMode {
    pub fn parse(raw: Option<&str>) -> Self {
        match raw.map(|s| s.trim().to_ascii_lowercase()).as_deref() {
            Some("quick") => Self::Quick,
            Some("deep") => Self::Deep,
            Some("behavioral") | Some("behavioural") => Self::Behavioral,
            _ => Self::Full,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Quick => "quick",
            Self::Full => "full",
            Self::Deep => "deep",
            Self::Behavioral => "behavioral",
        }
    }
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
            unpack_archives: true,
            deep: false,
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
    pe_model: PeModelAnalyzer,
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
        let pe_model = PeModelAnalyzer::new(config.pe_model.clone());
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
            pe_model,
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
        self.perform_analysis_at(request, 0).await
    }

    /// Analyse one file. `depth` is how many archives it was unpacked from.
    async fn perform_analysis_at(
        &mut self,
        request: &FileAnalysisRequest,
        depth: usize,
    ) -> Result<AnalysisResult> {
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
            let pe_model_future = self.run_pe_model_analysis(request);
            let heuristic_future = self.run_heuristic_analysis(request);
            let signature_future = self.run_signature_analysis(request);

            let (
                hash_res,
                static_res,
                yara_res,
                clamav_res,
                ml_res,
                pe_model_res,
                heuristic_res,
                signature_res,
            ) = tokio::join!(
                hash_future,
                static_future,
                yara_future,
                clamav_future,
                ml_future,
                pe_model_future,
                heuristic_future,
                signature_future
            );

            // None: not configured, or not a Windows program.
            if let Some(det) = pe_model_res {
                detections.push(det);
            }

            let opts = &request.analysis_options;
            // Collect results and errors
            match hash_res {
                Ok(mut dets) => detections.append(&mut dets),
                Err(e) => {
                    warn!("Hash analysis failed: {}", e);
                    analysis_errors.push(format!("Hash: {e}"));
                }
            }
            match static_res {
                // Switched off for this kind of target, so it took no part.
                Err(_) if !opts.enable_static_analysis => {}
                Ok(det) => detections.push(det),
                Err(e) => {
                    warn!("Static analysis failed: {}", e);
                    analysis_errors.push(format!("Static: {e}"));
                }
            }
            match yara_res {
                // Switched off for this kind of target, so it took no part.
                Err(_) if !opts.enable_yara_analysis => {}
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
                // Switched off for this kind of target, so it took no part.
                Err(_) if !opts.enable_clamav_analysis => {}
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
                        EngineType::Antivirus,
                        e.to_string(),
                    ));
                    analysis_errors.push(format!("ClamAV: {e}"));
                }
            }
            match ml_res {
                // Switched off for this kind of target, so it took no part.
                Err(_) if !opts.enable_ml_analysis => {}
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
                // Switched off for this kind of target, so it took no part.
                Err(_) if !opts.enable_heuristic_analysis => {}
                Ok(det) => detections.push(det),
                Err(e) => {
                    warn!("Heuristic analysis failed: {}", e);
                    analysis_errors.push(format!("Heuristic: {e}"));
                }
            }
            match signature_res {
                // Switched off for this kind of target, so it took no part.
                Err(_) if !opts.enable_signature_analysis => {}
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
                        EngineType::Antivirus,
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
            if let Some(det) = self.run_pe_model_analysis(request).await {
                detections.push(det);
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

        if let Some(office_det) = self.run_office_analysis(request).await {
            detections.push(office_det);
        }

        if let Some(apk_det) = self.run_apk_analysis(request).await {
            detections.push(apk_det);
        }

        if let Some(pdf_det) = self.run_pdf_analysis(request).await {
            detections.push(pdf_det);
        }

        let max_depth = match (
            request.analysis_options.unpack_archives,
            request.analysis_options.deep,
        ) {
            (false, _) => 0,
            (true, false) => MAX_ARCHIVE_DEPTH,
            (true, true) => DEEP_ARCHIVE_DEPTH,
        };
        if depth < max_depth {
            if let Some(det) = self.scan_archive_contents(request, depth).await {
                detections.push(det);
            }
        }

        // Add detections to result
        for mut det in detections {
            no_match_is_no_record(&mut det);
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

    /// Unpack an archive and run every engine on each file inside, so a
    /// zipped (or `infected`-password) sample is judged by what it contains,
    /// not by its compressed bytes. `None` if the file isn't an archive.
    async fn scan_archive_contents(
        &mut self,
        request: &FileAnalysisRequest,
        depth: usize,
    ) -> Option<DetectionResult> {
        use crate::scanners::unpack::{self, UnpackLimits};

        // Decompressing is bounded by UnpackLimits; the engine handles one
        // job at a time, so doing it inline costs no other request anything.
        let deep = request.analysis_options.deep;
        let limits = if deep {
            UnpackLimits::deep()
        } else {
            UnpackLimits::default()
        };
        let budget = if deep {
            DEEP_ARCHIVE_TIME_BUDGET
        } else {
            ARCHIVE_TIME_BUDGET
        };
        let mut unpacked = unpack::unpack(&request.file_data, limits)?;
        let members = std::mem::take(&mut unpacked.members);

        let started = std::time::Instant::now();
        let mut skipped = unpacked.skipped.clone();
        let mut scanned = Vec::new();
        for member in members {
            if started.elapsed() > budget {
                skipped.push(format!("{}: archive time limit reached", member.path));
                continue;
            }
            let inner = FileAnalysisRequest {
                filename: member.path.clone(),
                file_data: member.data,
                file_hashes: None,
                analysis_options: request.analysis_options.clone(),
            };
            match Box::pin(self.perform_analysis_at(&inner, depth + 1)).await {
                Ok(result) => scanned.push((member.path, result)),
                Err(e) => skipped.push(format!("{}: {e}", member.path)),
            }
        }
        info!(
            "Archive ({}) at depth {}: {} files scanned, {} skipped",
            unpacked.format.name(),
            depth,
            scanned.len(),
            skipped.len()
        );
        Some(archive_contents_detection(&unpacked, &scanned, &skipped))
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

    /// The EMBER2024-trained PE model. Shares the ML on/off switch.
    async fn run_pe_model_analysis(
        &self,
        request: &FileAnalysisRequest,
    ) -> Option<DetectionResult> {
        if !request.analysis_options.enable_ml_analysis {
            return None;
        }
        self.pe_model.analyze(&request.file_data).await
    }

    async fn run_heuristic_analysis(
        &self,
        request: &FileAnalysisRequest,
    ) -> Result<DetectionResult> {
        if !request.analysis_options.enable_heuristic_analysis {
            return Err(anyhow!("Heuristic analysis disabled"));
        }

        let start = std::time::Instant::now();
        let content = heuristic_text(&request.file_data);
        let matches = self
            .heuristic_engine
            .analyze_content(&content, std::path::Path::new(&request.filename))
            .await
            .map_err(|e| anyhow!("Heuristic analysis error: {e}"))?;
        let risk_score = self.heuristic_engine.calculate_risk_score(&matches);

        // Points from distinct rules: one strong rule (3) is suspicious, two
        // or more together are malicious. Thresholds match the static analyzer
        // and come from the detection benchmark.
        let verdict = if risk_score >= 5.0 {
            ThreatVerdict::Malicious
        } else if risk_score >= 2.0 {
            ThreatVerdict::Suspicious
        } else {
            ThreatVerdict::Benign
        };
        let calibrated_confidence = match verdict {
            ThreatVerdict::Malicious => 0.8,
            ThreatVerdict::Suspicious => 0.6,
            _ => 0.6,
        };
        let strong_signal = verdict == ThreatVerdict::Malicious;

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
                // Malicious here means several patterns scoring 50+, not one
                // stray string.
                (
                    STRONG_SIGNAL_KEY.to_string(),
                    serde_json::json!(strong_signal),
                ),
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
        let strong_signal = verdict == ThreatVerdict::Malicious;

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
                (
                    STRONG_SIGNAL_KEY.to_string(),
                    serde_json::json!(strong_signal),
                ),
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

    /// Office documents: VBA macros, Excel 4.0 macro sheets, remote
    /// templates, DDE and embedded objects. `None` for other files. Shares
    /// the static-analysis switch.
    async fn run_office_analysis(&self, request: &FileAnalysisRequest) -> Option<DetectionResult> {
        if !request.analysis_options.enable_static_analysis {
            return None;
        }
        let data = request.file_data.clone();
        // CPU-bound parsing of an untrusted file: keep it off the runtime's
        // worker threads.
        match tokio::task::spawn_blocking(move || office_analyzer::analyze(&data)).await {
            Ok(det) => det,
            Err(e) => Some(Self::create_unavailable_detection(
                office_analyzer::ENGINE_NAME,
                "1.0.0",
                EngineType::Static,
                format!("document analysis failed: {e}"),
            )),
        }
    }

    /// Android apps: manifest, DEX APIs, packers, payloads and signing.
    /// `None` for other files. Shares the static-analysis switch.
    async fn run_apk_analysis(&self, request: &FileAnalysisRequest) -> Option<DetectionResult> {
        if !request.analysis_options.enable_static_analysis {
            return None;
        }
        let data = request.file_data.clone();
        match tokio::task::spawn_blocking(move || apk_analyzer::analyze(&data)).await {
            Ok(det) => det,
            Err(e) => Some(Self::create_unavailable_detection(
                apk_analyzer::ENGINE_NAME,
                "1.0.0",
                EngineType::Static,
                format!("app analysis failed: {e}"),
            )),
        }
    }

    /// PDFs: JavaScript, actions that run on open, launch actions, embedded
    /// files and links. `None` for other files. Shares the static-analysis
    /// switch.
    async fn run_pdf_analysis(&self, request: &FileAnalysisRequest) -> Option<DetectionResult> {
        if !request.analysis_options.enable_static_analysis {
            return None;
        }
        let data = request.file_data.clone();
        match tokio::task::spawn_blocking(move || pdf_analyzer::analyze(&data)).await {
            Ok(det) => det,
            Err(e) => Some(Self::create_unavailable_detection(
                pdf_analyzer::ENGINE_NAME,
                "1.0.0",
                EngineType::Static,
                format!("PDF analysis failed: {e}"),
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

        // Office documents (Default; only reports on Office files)
        engines.push(EngineStatusItem {
            id: "office_analyzer".to_string(),
            name: office_analyzer::ENGINE_NAME.to_string(),
            engine_type: "static".to_string(),
            is_optional: false,
            status: "online".to_string(),
            version: "1.0.0".to_string(),
            details: "VBA macro extraction and scoring, Excel 4.0 macro sheets, remote templates, DDE and embedded objects in Word, Excel and PowerPoint files".to_string(),
            error: None,
        });

        // PDFs (Default; only reports on PDFs)
        engines.push(EngineStatusItem {
            id: "pdf_analyzer".to_string(),
            name: pdf_analyzer::ENGINE_NAME.to_string(),
            engine_type: "static".to_string(),
            is_optional: false,
            status: "online".to_string(),
            version: "1.0.0".to_string(),
            details: "JavaScript (including in compressed object streams and XFA forms), actions that run on open, launch actions, embedded files, links, network-share paths and hidden content in PDF files".to_string(),
            error: None,
        });

        // Android apps (Default; only reports on APKs)
        engines.push(EngineStatusItem {
            id: "apk_analyzer".to_string(),
            name: apk_analyzer::ENGINE_NAME.to_string(),
            engine_type: "static".to_string(),
            is_optional: false,
            status: "online".to_string(),
            version: "1.0.0".to_string(),
            details: "Binary manifest (permissions, accessibility and device-admin services, launcher), DEX API strings, packers, hidden payloads and signing for Android APKs".to_string(),
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
                    format!(
                        "Operational with {} rules from {} file(s)",
                        self.yara_engine.rules_loaded(),
                        rule_count
                    ),
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
                        // The daemon's address is internal; this text is public.
                        "ClamAV daemon connected; signatures checked on every file".to_string(),
                        None,
                    ),
                    Err(e) => {
                        tracing::warn!(
                            address = %self.config.clamav_analyzer.address,
                            error = %e,
                            "ClamAV daemon unreachable"
                        );
                        (
                            "unavailable",
                            "clamd",
                            "Cannot connect to the ClamAV daemon".to_string(),
                            Some("ClamAV daemon unreachable".to_string()),
                        )
                    }
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
                    // Advisory: running, but its prediction doesn't vote.
                    if self.config.ml_analyzer.counts_toward_verdict {
                        "online"
                    } else {
                        "advisory"
                    },
                    "ort 2.0.0-rc.13",
                    if self.config.ml_analyzer.counts_toward_verdict {
                        "ONNX threat classifier and anomaly detector models loaded".to_string()
                    } else {
                        "Advisory only: hand-set model weights, not trained on data; predictions are shown but do not vote".to_string()
                    },
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

        // 8. PE model (Optional; off until PE_MODEL_URL points at the ML service)
        let (pe_status, pe_version, pe_details, pe_error) = self.pe_model.status().await;
        engines.push(EngineStatusItem {
            id: "pe_model".to_string(),
            name: "Windows Program Model (EMBER2024)".to_string(),
            engine_type: "ml".to_string(),
            is_optional: true,
            status: pe_status,
            version: pe_version,
            details: pe_details,
            error: pe_error,
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
                "office_analyzer".to_string(),
                "apk_analyzer".to_string(),
                "pdf_analyzer".to_string(),
            ],
            optional_engines: vec![
                "yara_engine".to_string(),
                "clamav".to_string(),
                "ml_engine".to_string(),
                "pe_model".to_string(),
            ],
        }
    }
}

/// The text the heuristic rules read. Shortcuts (.lnk) and many PowerShell
/// scripts store their text as UTF-16, which a byte-wise read turns into
/// "p\0o\0w\0e\0r..."; their UTF-16 strings are decoded and appended.
pub(crate) fn heuristic_text(data: &[u8]) -> String {
    let mut text = String::from_utf8_lossy(data).into_owned();
    const LNK_MAGIC: [u8; 8] = [0x4C, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00];
    let utf16_bom = data.starts_with(&[0xFF, 0xFE]);
    if data.starts_with(&LNK_MAGIC) || utf16_bom {
        text.push('\n');
        text.push_str(&utf16_strings(data, if utf16_bom { 2 } else { 0 }));
    }
    text
}

/// Printable UTF-16LE runs of four or more characters, one per line.
fn utf16_strings(data: &[u8], skip: usize) -> String {
    let mut out = String::new();
    let mut run = String::new();
    for offset in [skip, skip + 1] {
        for pair in data.get(offset..).unwrap_or_default().as_chunks::<2>().0 {
            let unit = u16::from_le_bytes([pair[0], pair[1]]);
            match char::from_u32(unit as u32) {
                Some(c) if c == '\t' || (!c.is_control() && unit < 0xD800) => run.push(c),
                _ => {
                    if run.chars().count() >= 4 {
                        out.push_str(&run);
                        out.push('\n');
                    }
                    run.clear();
                }
            }
        }
        if run.chars().count() >= 4 {
            out.push_str(&run);
            out.push('\n');
        }
        run.clear();
    }
    out
}

/// Engines that only look for known-bad patterns.
const MATCH_ONLY_ENGINES: [&str; 3] = ["YARA", "ClamAV", "Verdyx Signature Matcher"];

/// A pattern engine that matched nothing has no opinion: it can only say a
/// file contains something known-bad, never that it's safe. Counting "no
/// match" as a clean vote let two such engines outvote the engines that did
/// flag a file; in the detection benchmark that hid most of the malware.
/// Engine name for the verdict on an archive's contents.
pub const ARCHIVE_CONTENTS: &str = "Archive contents";
/// Archives inside archives are unpacked this many levels deep.
const MAX_ARCHIVE_DEPTH: usize = 2;
/// Time spent analysing one archive's files before the rest are skipped, so
/// a large archive can't run past the overall analysis timeout.
const ARCHIVE_TIME_BUDGET: Duration = Duration::from_secs(60);
/// Deep Inspection's limits. The whole scan still has to finish within the
/// engine's analysis timeout (300 s by default).
const DEEP_ARCHIVE_DEPTH: usize = 3;
const DEEP_ARCHIVE_TIME_BUDGET: Duration = Duration::from_secs(150);

fn verdict_rank(v: &ThreatVerdict) -> u8 {
    match v {
        ThreatVerdict::Malicious => 3,
        ThreatVerdict::Suspicious => 2,
        ThreatVerdict::Benign => 1,
        ThreatVerdict::Unknown => 0,
    }
}

/// The voting engines that flagged a file (malicious or suspicious).
fn flagging_engines(r: &AnalysisResult) -> impl Iterator<Item = &DetectionResult> {
    r.detections
        .iter()
        .filter(|d| d.non_vote().is_none() && verdict_rank(&d.verdict) >= 2)
}

/// What an engine says it found, when it names it: ClamAV's signature, the
/// first matched YARA or signature rule, or a known malware family.
pub(crate) fn detection_signature(d: &DetectionResult) -> Option<String> {
    let text = |v: &serde_json::Value| {
        v.as_str()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(String::from)
    };
    if let Some(sig) = d.metadata.get("signature").and_then(text) {
        return Some(sig);
    }
    if let Some(first) = d
        .metadata
        .get("matches")
        .and_then(|m| m.as_array())
        .and_then(|m| m.first())
    {
        for key in ["rule_name", "rule", "name", "signature_name"] {
            if let Some(name) = first.get(key).and_then(text) {
                return Some(name);
            }
        }
    }
    d.metadata.get("malware_family").and_then(text)
}

/// One vote for an archive, from the consensus verdicts of the files inside:
/// the worst of them. A file inside judged Malicious decides the archive's
/// verdict ([`INNER_FILE_KEY`]): engines reading the compressed container
/// can't see that file, so their clean votes can't outweigh it.
pub(crate) fn archive_contents_detection(
    unpacked: &crate::scanners::unpack::Unpacked,
    scanned: &[(String, AnalysisResult)],
    skipped: &[String],
) -> DetectionResult {
    use crate::models::analysis_result::INNER_FILE_KEY;

    let worst = scanned
        .iter()
        .map(|(_, r)| &r.consensus_verdict)
        .max_by_key(|v| verdict_rank(v))
        .cloned()
        .unwrap_or(ThreatVerdict::Unknown);

    let flagged: Vec<String> = scanned
        .iter()
        .filter(|(_, r)| verdict_rank(&r.consensus_verdict) >= 2)
        .map(|(path, r)| {
            let engines: Vec<String> = flagging_engines(r)
                .map(|d| match detection_signature(d) {
                    Some(sig) => format!("{}: {sig}", d.engine_name),
                    None => d.engine_name.clone(),
                })
                .collect();
            format!("{path}: {:?} ({})", r.consensus_verdict, engines.join(", "))
        })
        .collect();

    let opened_with = unpacked
        .password
        .map(|p| format!(" Opened with the password \"{p}\"."))
        .unwrap_or_default();
    let summary = if scanned.is_empty() && unpacked.locked {
        format!(
            "Password-protected {}; none of the usual sample passwords ({}) opened it, so the files inside weren't scanned.",
            unpacked.format.name(),
            crate::scanners::unpack::COMMON_PASSWORDS.join(", ")
        )
    } else if scanned.is_empty() {
        format!(
            "Nothing inside this {} could be scanned.",
            unpacked.format.name()
        )
    } else if flagged.is_empty() {
        format!(
            "{} file(s) inside this {} were scanned by every engine; none was flagged.{opened_with}",
            scanned.len(),
            unpacked.format.name()
        )
    } else {
        format!(
            "{} of {} file(s) inside this {} were flagged: {}.{opened_with}",
            flagged.len(),
            scanned.len(),
            unpacked.format.name(),
            flagged.join("; ")
        )
    };

    let files: Vec<serde_json::Value> = scanned
        .iter()
        .map(|(path, r)| {
            serde_json::json!({
                "path": path,
                "size": r.file_metadata.file_size,
                "sha256": r.file_metadata.sha256,
                "verdict": format!("{:?}", r.consensus_verdict),
                "explanation": r.consensus_explanation,
                "engines": flagging_engines(r)
                    .map(|d| serde_json::json!({
                        "name": d.engine_name,
                        "verdict": format!("{:?}", d.verdict),
                        "signature": detection_signature(d),
                    }))
                    .collect::<Vec<_>>(),
            })
        })
        .collect();

    let mut metadata = HashMap::new();
    metadata.insert(
        "format".to_string(),
        serde_json::json!(unpacked.format.name()),
    );
    metadata.insert("files".to_string(), serde_json::json!(files));
    metadata.insert("skipped".to_string(), serde_json::json!(skipped));
    metadata.insert("summary".to_string(), serde_json::json!(summary));
    metadata.insert("reasons".to_string(), serde_json::json!(flagged));
    if let Some(p) = unpacked.password {
        metadata.insert("password_used".to_string(), serde_json::json!(p));
    }
    if worst == ThreatVerdict::Unknown {
        metadata.insert("reason".to_string(), serde_json::json!(summary));
    }
    if worst == ThreatVerdict::Malicious {
        metadata.insert(INNER_FILE_KEY.to_string(), serde_json::json!(true));
    }

    let confidence = scanned
        .iter()
        .filter(|(_, r)| r.consensus_verdict == worst)
        .map(|(_, r)| r.consensus_confidence)
        .fold(0.0_f32, f32::max);
    let severity = scanned
        .iter()
        .map(|(_, r)| r.consensus_severity.clone())
        .fold(SeverityLevel::Info, SeverityLevel::max);
    let categories = if verdict_rank(&worst) >= 2 {
        vec![ThreatCategory::Malware]
    } else {
        vec![]
    };

    DetectionResult {
        detection_id: Uuid::new_v4(),
        engine_name: ARCHIVE_CONTENTS.to_string(),
        engine_version: "1".to_string(),
        engine_type: EngineType::Static,
        verdict: worst,
        confidence,
        severity,
        categories,
        metadata,
        detected_at: Utc::now(),
        processing_time_ms: 0,
        error_message: None,
    }
}

pub(crate) fn no_match_is_no_record(d: &mut DetectionResult) {
    if d.verdict == ThreatVerdict::Benign && MATCH_ONLY_ENGINES.contains(&d.engine_name.as_str()) {
        d.verdict = ThreatVerdict::Unknown;
        d.confidence = 0.0;
        d.metadata
            .entry("reason".to_string())
            .or_insert_with(|| serde_json::json!("No known-bad pattern matched"));
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
            unpack_archives: true,
            deep: false,
            priority: AnalysisPriority::High,
            custom_metadata: HashMap::from([("source".to_string(), "unit_test".to_string())]),
        };

        assert!(!options.enable_hash_analysis);
        assert_eq!(options.priority, AnalysisPriority::High);
        assert_eq!(options.custom_metadata.get("source").unwrap(), "unit_test");
    }

    #[test]
    fn pattern_engines_that_match_nothing_do_not_vote_clean() {
        let mut yara = AnalysisEngine::create_unavailable_detection(
            "YARA",
            "libyara",
            EngineType::Yara,
            String::new(),
        );
        yara.error_message = None;
        yara.metadata.clear();
        yara.verdict = ThreatVerdict::Benign;
        no_match_is_no_record(&mut yara);
        assert_eq!(yara.verdict, ThreatVerdict::Unknown);
        assert_eq!(
            yara.non_vote().map(|(k, _)| k),
            Some(crate::models::analysis_result::NonVoteKind::NoRecord)
        );

        // An engine that inspects the whole file keeps its clean vote.
        let mut stat = yara.clone();
        stat.engine_name = "Verdyx Static Analyzer".to_string();
        stat.verdict = ThreatVerdict::Benign;
        no_match_is_no_record(&mut stat);
        assert_eq!(stat.verdict, ThreatVerdict::Benign);
    }
}

#[cfg(test)]
mod archive_tests {
    use super::*;
    use std::io::{Cursor, Write};

    const EICAR: &[u8] = br"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

    fn zip_of(files: &[(&str, &[u8])], password: Option<&str>) -> Vec<u8> {
        let mut buf = Vec::new();
        {
            let mut w = zip::ZipWriter::new(Cursor::new(&mut buf));
            for (name, body) in files {
                let mut opts = zip::write::SimpleFileOptions::default();
                if let Some(p) = password {
                    opts = opts.with_aes_encryption(zip::AesMode::Aes256, p);
                }
                w.start_file(*name, opts).unwrap();
                w.write_all(body).unwrap();
            }
            w.finish().unwrap();
        }
        buf
    }

    async fn engine() -> AnalysisEngine {
        let mut config = AnalysisEngineConfig::default();
        config.hash_analyzer.virustotal_api_key = None;
        config.hash_analyzer.malwarebazaar_api_key = None;
        config.hash_analyzer.hybrid_analysis_api_key = None;
        config.clamav_analyzer.enabled = false;
        config.yara_engine.rules_directory = "rules/yara".into();
        AnalysisEngine::new(config).await.unwrap()
    }

    async fn analyse(name: &str, data: Vec<u8>) -> AnalysisResult {
        engine()
            .await
            .analyze_file(FileAnalysisRequest {
                filename: name.to_string(),
                file_data: data,
                file_hashes: None,
                analysis_options: AnalysisOptions::default(),
            })
            .await
            .unwrap()
    }

    fn contents(r: &AnalysisResult) -> &DetectionResult {
        r.detections
            .iter()
            .find(|d| d.engine_name == ARCHIVE_CONTENTS)
            .expect("archive contents row")
    }

    #[tokio::test]
    async fn malware_in_an_infected_zip_makes_the_zip_malicious() {
        let bare = analyse("eicar.com", EICAR.to_vec()).await;
        assert_eq!(bare.consensus_verdict, ThreatVerdict::Malicious);

        let z = zip_of(
            &[("readme.txt", b"Invoice attached."), ("eicar.com", EICAR)],
            Some("infected"),
        );
        let r = analyse("invoice.zip", z).await;
        let row = contents(&r);
        assert_eq!(row.verdict, ThreatVerdict::Malicious);
        assert_eq!(row.metadata["password_used"], "infected");
        assert!(row.metadata["summary"]
            .as_str()
            .unwrap()
            .contains("eicar.com: Malicious"));
        assert_eq!(r.consensus_verdict, ThreatVerdict::Malicious);
        assert!(r.consensus_explanation.contains("a file inside it"));
    }

    #[tokio::test]
    async fn nested_archives_are_followed() {
        let inner = zip_of(&[("eicar.com", EICAR)], None);
        let outer = zip_of(&[("inner.zip", &inner)], None);
        let r = analyse("outer.zip", outer).await;
        assert_eq!(r.consensus_verdict, ThreatVerdict::Malicious);
    }

    #[tokio::test]
    async fn a_zip_of_clean_files_stays_clean() {
        let z = zip_of(
            &[
                ("notes.txt", b"Meeting at 10."),
                ("data.csv", b"a,b\n1,2\n"),
            ],
            None,
        );
        let r = analyse("notes.zip", z).await;
        let row = contents(&r);
        assert_eq!(row.verdict, ThreatVerdict::Benign);
        assert_ne!(r.consensus_verdict, ThreatVerdict::Malicious);
        assert!(row.metadata["summary"]
            .as_str()
            .unwrap()
            .contains("none was flagged"));
    }

    #[tokio::test]
    async fn a_locked_archive_says_so_and_does_not_vote() {
        let z = zip_of(&[("eicar.com", EICAR)], Some("not-a-common-one"));
        let r = analyse("locked.zip", z).await;
        let row = contents(&r);
        assert_eq!(row.verdict, ThreatVerdict::Unknown);
        let (_, reason) = row.non_vote().expect("doesn't vote");
        assert!(reason.contains("Password-protected"));
    }
}

#[cfg(test)]
mod office_tests {
    use super::office_analyzer::tests::{ooxml, vba_project, DROPPER};
    use super::*;

    async fn analyse(name: &str, data: Vec<u8>) -> AnalysisResult {
        let mut config = AnalysisEngineConfig::default();
        config.hash_analyzer.virustotal_api_key = None;
        config.hash_analyzer.malwarebazaar_api_key = None;
        config.hash_analyzer.hybrid_analysis_api_key = None;
        config.clamav_analyzer.enabled = false;
        config.yara_engine.rules_directory = "rules/yara".into();
        AnalysisEngine::new(config)
            .await
            .unwrap()
            .analyze_file(FileAnalysisRequest {
                filename: name.to_string(),
                file_data: data,
                file_hashes: None,
                analysis_options: AnalysisOptions::default(),
            })
            .await
            .unwrap()
    }

    fn office_row(r: &AnalysisResult) -> Option<&DetectionResult> {
        r.detections
            .iter()
            .find(|d| d.engine_name == office_analyzer::ENGINE_NAME)
    }

    #[tokio::test]
    async fn macro_dropper_docm_is_flagged_by_the_engine() {
        let bin = vba_project("", &[("ThisDocument", DROPPER)]);
        let r = analyse("invoice.docm", ooxml(&[("word/vbaProject.bin", &bin)])).await;
        assert_eq!(
            office_row(&r).expect("office row").verdict,
            ThreatVerdict::Malicious
        );
        // A strong signal can't be outvoted into a clean verdict.
        assert_ne!(r.consensus_verdict, ThreatVerdict::Benign);
        assert_ne!(r.consensus_verdict, ThreatVerdict::Unknown);
    }

    #[tokio::test]
    async fn non_office_files_get_no_office_row() {
        let r = analyse("notes.txt", b"just some text".to_vec()).await;
        assert!(office_row(&r).is_none());
    }
}

#[cfg(test)]
mod apk_tests {
    use super::apk_analyzer::tests::banker;
    use super::*;

    #[tokio::test]
    async fn banking_trojan_apk_is_flagged_by_the_engine() {
        let mut config = AnalysisEngineConfig::default();
        config.hash_analyzer.virustotal_api_key = None;
        config.hash_analyzer.malwarebazaar_api_key = None;
        config.hash_analyzer.hybrid_analysis_api_key = None;
        config.clamav_analyzer.enabled = false;
        config.yara_engine.rules_directory = "rules/yara".into();
        let r = AnalysisEngine::new(config)
            .await
            .unwrap()
            .analyze_file(FileAnalysisRequest {
                filename: "update.apk".to_string(),
                file_data: banker(),
                file_hashes: None,
                analysis_options: AnalysisOptions::default(),
            })
            .await
            .unwrap();
        let row = r
            .detections
            .iter()
            .find(|d| d.engine_name == apk_analyzer::ENGINE_NAME)
            .expect("apk row");
        assert_eq!(row.verdict, ThreatVerdict::Malicious);
        assert_ne!(r.consensus_verdict, ThreatVerdict::Benign);
        assert_ne!(r.consensus_verdict, ThreatVerdict::Unknown);
        // An APK isn't also treated as an Office file or an archive.
        assert!(!r
            .detections
            .iter()
            .any(|d| d.engine_name == office_analyzer::ENGINE_NAME
                || d.engine_name == ARCHIVE_CONTENTS));
    }
}

#[cfg(test)]
mod pdf_tests {
    use super::pdf_analyzer::tests::{pdf, stream_obj};
    use super::*;

    async fn analyse(name: &str, data: Vec<u8>) -> AnalysisResult {
        let mut config = AnalysisEngineConfig::default();
        config.hash_analyzer.virustotal_api_key = None;
        config.hash_analyzer.malwarebazaar_api_key = None;
        config.hash_analyzer.hybrid_analysis_api_key = None;
        config.clamav_analyzer.enabled = false;
        config.yara_engine.rules_directory = "rules/yara".into();
        AnalysisEngine::new(config)
            .await
            .unwrap()
            .analyze_file(FileAnalysisRequest {
                filename: name.to_string(),
                file_data: data,
                file_hashes: None,
                analysis_options: AnalysisOptions::default(),
            })
            .await
            .unwrap()
    }

    fn pdf_row(r: &AnalysisResult) -> Option<&DetectionResult> {
        r.detections
            .iter()
            .find(|d| d.engine_name == pdf_analyzer::ENGINE_NAME)
    }

    const CATALOG_OPEN: &[u8] = b"<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>";
    const PAGES: &[u8] = b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>";
    const PAGE: &[u8] = b"<< /Type /Page /Parent 2 0 R >>";

    #[tokio::test]
    async fn a_launching_pdf_is_flagged_by_the_engine() {
        let launch = b"<< /S /Launch /Win << /F (cmd.exe) /P (/c start calc) >> >>";
        let r = analyse("invoice.pdf", pdf(&[CATALOG_OPEN, PAGES, PAGE, launch])).await;
        assert_eq!(
            pdf_row(&r).expect("pdf row").verdict,
            ThreatVerdict::Malicious
        );
        // A strong signal can't be outvoted into a clean verdict.
        assert_ne!(r.consensus_verdict, ThreatVerdict::Benign);
        assert_ne!(r.consensus_verdict, ThreatVerdict::Unknown);
    }

    #[tokio::test]
    async fn a_plain_pdf_stays_clean() {
        let link = b"<< /Type /Annot /Subtype /Link /A << /S /URI /URI (https://example.com) >> >>";
        let text = stream_obj("", b"BT /F1 12 Tf (Quarterly report) Tj ET");
        let r = analyse(
            "report.pdf",
            pdf(&[
                b"<< /Type /Catalog /Pages 2 0 R >>",
                PAGES,
                PAGE,
                link,
                &text,
            ]),
        )
        .await;
        assert_eq!(pdf_row(&r).expect("pdf row").verdict, ThreatVerdict::Benign);
        assert_ne!(r.consensus_verdict, ThreatVerdict::Malicious);
    }

    #[tokio::test]
    async fn other_files_get_no_pdf_row() {
        let r = analyse("notes.txt", b"just some text".to_vec()).await;
        assert!(pdf_row(&r).is_none());
    }

    fn vote(
        name: &str,
        verdict: ThreatVerdict,
        meta: &[(&str, serde_json::Value)],
    ) -> DetectionResult {
        DetectionResult {
            detection_id: uuid::Uuid::new_v4(),
            engine_name: name.to_string(),
            engine_version: "1".to_string(),
            engine_type: EngineType::Static,
            verdict,
            confidence: 0.9,
            severity: SeverityLevel::Info,
            categories: vec![],
            metadata: meta
                .iter()
                .map(|(k, v)| (k.to_string(), v.clone()))
                .collect(),
            detected_at: chrono::Utc::now(),
            processing_time_ms: 1,
            error_message: None,
        }
    }

    #[test]
    fn archive_files_name_the_engine_and_signature_that_flagged_them() {
        use crate::scanners::unpack::{ArchiveFormat, Unpacked};
        let unpacked = Unpacked {
            format: ArchiveFormat::Zip,
            members: vec![],
            skipped: vec![],
            password: None,
            locked: false,
        };
        let eicar = AnalysisResult {
            consensus_verdict: ThreatVerdict::Malicious,
            detections: vec![
                vote(
                    "ClamAV",
                    ThreatVerdict::Malicious,
                    &[("signature", serde_json::json!("Eicar-Test-Signature"))],
                ),
                vote(
                    "YARA Engine",
                    ThreatVerdict::Suspicious,
                    &[("matches", serde_json::json!([{ "rule_name": "Test_Rule" }]))],
                ),
                vote("Static Analyzer", ThreatVerdict::Benign, &[]),
            ],
            ..Default::default()
        };
        let clean = AnalysisResult {
            consensus_verdict: ThreatVerdict::Benign,
            detections: vec![vote("Static Analyzer", ThreatVerdict::Benign, &[])],
            ..Default::default()
        };

        let scanned = vec![
            ("eicar.txt".to_string(), eicar),
            ("readme.txt".to_string(), clean),
        ];
        let d = archive_contents_detection(&unpacked, &scanned, &[]);

        let files = d.metadata["files"].as_array().unwrap();
        let engines = files[0]["engines"].as_array().unwrap();
        assert_eq!(engines.len(), 2, "only the engines that flagged it");
        assert_eq!(engines[0]["name"], "ClamAV");
        assert_eq!(engines[0]["signature"], "Eicar-Test-Signature");
        assert_eq!(engines[1]["signature"], "Test_Rule");
        assert!(files[1]["engines"].as_array().unwrap().is_empty());
        assert_eq!(
            d.metadata["reasons"][0],
            "eicar.txt: Malicious (ClamAV: Eicar-Test-Signature, YARA Engine: Test_Rule)"
        );
    }

    #[test]
    fn detection_signature_falls_back_to_the_malware_family() {
        let d = vote(
            "MalwareBazaar",
            ThreatVerdict::Malicious,
            &[("malware_family", serde_json::json!("AgentTesla"))],
        );
        assert_eq!(detection_signature(&d).as_deref(), Some("AgentTesla"));
        let none = vote(
            "Heuristic Engine",
            ThreatVerdict::Suspicious,
            &[("signature", serde_json::json!("  "))],
        );
        assert_eq!(detection_signature(&none), None);
    }
}
