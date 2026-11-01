//! ONNX-backed ML analyzer (compiled only with the `ml-engine` feature).
//!
//! This integrates with the shared `DetectionResult` pipeline like the other
//! analyzers. It loads two optional ONNX models — a threat classifier and an
//! anomaly detector — and runs them over a numeric feature vector extracted
//! from the file bytes.
//!
//! IMPORTANT: the models that ship in `ml_models/*.onnx` are currently empty
//! placeholders. When a model file is missing, empty, or fails to load, the
//! analyzer degrades gracefully: it returns a non-fatal `Unknown` detection
//! (with an `error_message`) instead of panicking or failing the whole scan.
//! Real inference begins automatically once valid models are dropped in.
//!
//! The feature-vector layout produced by [`extract_features`] is a contract
//! the trained model must match. The default layout is:
//!   [ size_norm, entropy_norm, printable_ratio, <256-bin byte histogram> ]
//! which is exactly [`DEFAULT_FEATURE_SIZE`] (= 259) floats. `feature_size`
//! defaults to that, so the natural layout survives intact; overriding it to a
//! smaller value truncates the tail of the histogram (and is warned about at
//! load time). Adjust both sides together if you train a model with a
//! different input.

use std::path::Path;
use std::sync::Mutex;

use tracing::{info, warn};
use uuid::Uuid;

use ort::session::Session;
use ort::value::Tensor;

use crate::models::analysis_result::{
    DetectionResult, EngineType, SeverityLevel, ThreatCategory, ThreatVerdict,
};

/// Number of scalar features emitted before the byte histogram
/// (`size_norm`, `entropy_norm`, `printable_ratio`).
pub const SCALAR_FEATURES: usize = 3;

/// Number of bins in the byte-frequency histogram (one per possible byte).
pub const HISTOGRAM_BINS: usize = 256;

/// Natural length of the feature vector produced by
/// [`MlAnalyzer::extract_features`]: the scalars plus the full histogram.
///
/// This is the default `feature_size`. A smaller `feature_size` silently drops
/// the tail of the histogram, so the default must not be lowered without
/// retraining the models against the shorter layout.
pub const DEFAULT_FEATURE_SIZE: usize = SCALAR_FEATURES + HISTOGRAM_BINS;

/// Configuration for the ML analyzer.
#[derive(Debug, Clone)]
pub struct MlAnalyzerConfig {
    pub enabled: bool,
    pub classifier_model_path: String,
    pub anomaly_model_path: String,
    /// Length of the feature vector fed to the models.
    pub feature_size: usize,
    /// Anomaly score above which a sample is considered anomalous.
    pub anomaly_threshold: f32,
    /// Class labels, index-aligned with the classifier's output vector.
    /// Index 0 is treated as the "benign" class.
    pub labels: Vec<String>,
}

impl Default for MlAnalyzerConfig {
    fn default() -> Self {
        Self {
            enabled: std::env::var("ENABLE_ML_ENGINE")
                .unwrap_or_else(|_| "true".to_string())
                .parse()
                .unwrap_or(true),
            classifier_model_path: std::env::var("ML_CLASSIFIER_MODEL")
                .unwrap_or_else(|_| "./ml_models/threat_classifier.onnx".to_string()),
            anomaly_model_path: std::env::var("ML_ANOMALY_MODEL")
                .unwrap_or_else(|_| "./ml_models/anomaly_detector.onnx".to_string()),
            feature_size: std::env::var("ML_FEATURE_SIZE")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(DEFAULT_FEATURE_SIZE),
            anomaly_threshold: std::env::var("ML_ANOMALY_THRESHOLD")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(0.5),
            labels: vec![
                "benign".to_string(),
                "malware".to_string(),
                "trojan".to_string(),
                "ransomware".to_string(),
                "adware".to_string(),
                "spyware".to_string(),
                "rootkit".to_string(),
                "backdoor".to_string(),
                "worm".to_string(),
                "virus".to_string(),
            ],
        }
    }
}

/// ML analyzer holding optionally-loaded ONNX sessions.
///
/// `Session::run` requires `&mut self`, so each session is wrapped in a Mutex
/// to allow inference through the analyzer's shared `&self` API.
pub struct MlAnalyzer {
    config: MlAnalyzerConfig,
    classifier: Option<Mutex<Session>>,
    anomaly: Option<Mutex<Session>>,
}

impl MlAnalyzer {
    /// Build the analyzer, loading whatever valid models are available.
    /// Never fails: missing/invalid models simply leave the engine unavailable.
    pub fn new(config: MlAnalyzerConfig) -> Self {
        if !config.enabled {
            info!("ML analyzer disabled via configuration");
            return Self {
                config,
                classifier: None,
                anomaly: None,
            };
        }

        if config.feature_size < DEFAULT_FEATURE_SIZE {
            warn!(
                "ML_FEATURE_SIZE={} is below the natural layout length of {}; the byte \
                 histogram will be truncated to its first {} bins. Models must be trained \
                 against this exact shortened layout.",
                config.feature_size,
                DEFAULT_FEATURE_SIZE,
                config.feature_size.saturating_sub(SCALAR_FEATURES),
            );
        }

        let classifier = Self::try_load_session("threat classifier", &config.classifier_model_path);
        let anomaly = Self::try_load_session("anomaly detector", &config.anomaly_model_path);

        if classifier.is_none() && anomaly.is_none() {
            warn!(
                "ML analyzer enabled but no usable models loaded (classifier: {}, anomaly: {}); \
                 the analyzer will report Unknown until valid ONNX models are provided",
                config.classifier_model_path, config.anomaly_model_path
            );
        }

        Self {
            config,
            classifier,
            anomaly,
        }
    }

    /// Attempt to load a single ONNX model. Returns `None` (with a warning) for
    /// any non-fatal problem: file missing, empty placeholder, or load error.
    fn try_load_session(label: &str, path: &str) -> Option<Mutex<Session>> {
        let p = Path::new(path);
        match std::fs::metadata(p) {
            Ok(meta) if meta.len() == 0 => {
                warn!("ML {label} model at {path} is empty (0 bytes); skipping");
                return None;
            }
            Ok(_) => {}
            Err(e) => {
                warn!("ML {label} model at {path} unavailable: {e}; skipping");
                return None;
            }
        }

        match Session::builder().and_then(|mut b| b.commit_from_file(p)) {
            Ok(session) => {
                info!("Loaded ML {label} model from {path}");
                Some(Mutex::new(session))
            }
            Err(e) => {
                warn!("Failed to load ML {label} model from {path}: {e}; skipping");
                None
            }
        }
    }

    /// Whether any model is loaded and ready for inference.
    pub fn is_available(&self) -> bool {
        self.classifier.is_some() || self.anomaly.is_some()
    }

    /// Analyze a file's bytes. Always returns `Ok`: inference failures and the
    /// "no models" case are surfaced as a non-fatal `Unknown` detection so the
    /// surrounding multi-engine analysis is never aborted.
    pub async fn analyze_file_data(
        &self,
        data: &[u8],
        _filename: &str,
    ) -> anyhow::Result<DetectionResult> {
        let start = std::time::Instant::now();

        if !self.config.enabled {
            return Ok(self.unknown(start, "ML analyzer disabled"));
        }
        if !self.is_available() {
            return Ok(self.unknown(start, "ML models not available"));
        }

        let features = self.extract_features(data);

        // Classification (optional).
        let classification = match &self.classifier {
            Some(session) => match Self::run_model(session, &features) {
                Ok(out) => Some(out),
                Err(e) => {
                    warn!("ML classifier inference failed: {e}");
                    return Ok(self.unknown(start, &format!("ML classifier error: {e}")));
                }
            },
            None => None,
        };

        // Anomaly detection (optional).
        let anomaly_score = match &self.anomaly {
            Some(session) => match Self::run_model(session, &features) {
                Ok(out) => out.first().copied(),
                Err(e) => {
                    warn!("ML anomaly inference failed: {e}");
                    None
                }
            },
            None => None,
        };

        Ok(self.build_detection(
            classification,
            anomaly_score,
            start.elapsed().as_millis() as u64,
        ))
    }

    /// Run a single-input/single-output model over the feature vector and
    /// return the output values as a flat `Vec<f32>`.
    fn run_model(session: &Mutex<Session>, features: &[f32]) -> anyhow::Result<Vec<f32>> {
        let shape = vec![1_i64, features.len() as i64];
        let tensor = Tensor::from_array((shape, features.to_vec()))?;

        let mut guard = session
            .lock()
            .map_err(|_| anyhow::anyhow!("ML session lock poisoned"))?;
        let outputs = guard.run(ort::inputs![tensor])?;

        if outputs.len() == 0 {
            return Err(anyhow::anyhow!("model produced no outputs"));
        }
        let (_, data) = outputs[0].try_extract_tensor::<f32>()?;
        Ok(data.to_vec())
    }

    /// Combine model outputs into a `DetectionResult`.
    fn build_detection(
        &self,
        classification: Option<Vec<f32>>,
        anomaly_score: Option<f32>,
        processing_time_ms: u64,
    ) -> DetectionResult {
        let mut metadata = std::collections::HashMap::new();

        // Interpret the classifier output: argmax over the probability vector.
        let (predicted_label, class_confidence) = match &classification {
            Some(scores) if !scores.is_empty() => {
                let (idx, conf) = scores
                    .iter()
                    .enumerate()
                    .max_by(|(_, a), (_, b)| a.total_cmp(b))
                    .map(|(i, v)| (i, *v))
                    .unwrap_or((0, 0.0));
                let label = self
                    .config
                    .labels
                    .get(idx)
                    .cloned()
                    .unwrap_or_else(|| format!("class_{idx}"));
                metadata.insert("predicted_class".to_string(), serde_json::json!(label));
                metadata.insert("class_confidence".to_string(), serde_json::json!(conf));
                (Some(label), conf.clamp(0.0, 1.0))
            }
            _ => (None, 0.0),
        };

        let is_anomaly = anomaly_score
            .map(|s| s > self.config.anomaly_threshold)
            .unwrap_or(false);
        if let Some(score) = anomaly_score {
            metadata.insert("anomaly_score".to_string(), serde_json::json!(score));
            metadata.insert("is_anomaly".to_string(), serde_json::json!(is_anomaly));
        }

        let classified_malicious = predicted_label
            .as_deref()
            .map(|l| l != "benign")
            .unwrap_or(false);
        let is_malicious = classified_malicious || is_anomaly;

        let confidence = if is_anomaly {
            ((class_confidence + anomaly_score.unwrap_or(0.0)) / 2.0).clamp(0.0, 1.0)
        } else {
            class_confidence
        };

        let verdict = if is_malicious {
            ThreatVerdict::Malicious
        } else if classification.is_some() {
            ThreatVerdict::Benign
        } else {
            // Only the anomaly model ran and it was within threshold.
            ThreatVerdict::Benign
        };

        let categories = match predicted_label.as_deref() {
            Some("ransomware") => vec![ThreatCategory::Ransomware],
            Some("trojan") => vec![ThreatCategory::Trojan],
            Some("worm") => vec![ThreatCategory::Worm],
            Some("rootkit") => vec![ThreatCategory::Rootkit],
            Some("backdoor") => vec![ThreatCategory::Backdoor],
            Some("spyware") => vec![ThreatCategory::Spyware],
            Some("adware") => vec![ThreatCategory::Adware],
            Some("virus") => vec![ThreatCategory::Virus],
            Some(l) if l != "benign" => vec![ThreatCategory::Malware],
            _ if is_anomaly => vec![ThreatCategory::Malware],
            _ => vec![],
        };

        let severity = match predicted_label.as_deref() {
            Some("ransomware") | Some("rootkit") | Some("backdoor") => SeverityLevel::High,
            Some("trojan") | Some("spyware") | Some("worm") | Some("virus") => {
                SeverityLevel::Medium
            }
            Some(l) if l != "benign" => SeverityLevel::Low,
            _ if is_anomaly => SeverityLevel::Medium,
            _ => SeverityLevel::Info,
        };

        DetectionResult {
            detection_id: Uuid::new_v4(),
            engine_name: "ML Engine".to_string(),
            engine_version: "onnx".to_string(),
            engine_type: EngineType::Ml,
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

    fn unknown(&self, start: std::time::Instant, reason: &str) -> DetectionResult {
        DetectionResult {
            detection_id: Uuid::new_v4(),
            engine_name: "ML Engine".to_string(),
            engine_version: "onnx".to_string(),
            engine_type: EngineType::Ml,
            verdict: ThreatVerdict::Unknown,
            confidence: 0.0,
            severity: SeverityLevel::Info,
            categories: vec![],
            metadata: std::collections::HashMap::new(),
            detected_at: chrono::Utc::now(),
            processing_time_ms: start.elapsed().as_millis() as u64,
            error_message: Some(reason.to_string()),
        }
    }

    /// Extract a fixed-length numeric feature vector from raw bytes.
    ///
    /// Layout: [size_norm, entropy_norm, printable_ratio, 256-bin histogram] —
    /// [`DEFAULT_FEATURE_SIZE`] floats — then padded or truncated to
    /// `feature_size`. At the default `feature_size` the layout is preserved
    /// exactly; a smaller configured size truncates the histogram tail (warned
    /// about at load time). This is a deterministic, model-agnostic baseline;
    /// retrain-time feature engineering must match it.
    fn extract_features(&self, data: &[u8]) -> Vec<f32> {
        let mut features = Vec::with_capacity(self.config.feature_size);

        let len = data.len() as f32;
        // Normalize size with a log scale capped at ~16MB.
        let size_norm = if len > 0.0 {
            (len.log2() / 24.0).clamp(0.0, 1.0)
        } else {
            0.0
        };

        let mut counts = [0u32; 256];
        let mut printable = 0u32;
        for &b in data {
            counts[b as usize] += 1;
            if b.is_ascii_graphic() || b == b' ' {
                printable += 1;
            }
        }

        let entropy = Self::shannon_entropy(&counts, data.len());
        let printable_ratio = if len > 0.0 {
            printable as f32 / len
        } else {
            0.0
        };

        features.push(size_norm);
        features.push(entropy / 8.0); // entropy is 0..8 bits
        features.push(printable_ratio);

        // Normalized byte-frequency histogram, one bin per byte value.
        if !data.is_empty() {
            for c in counts.iter() {
                features.push(*c as f32 / len);
            }
        } else {
            features.extend(std::iter::repeat(0.0).take(HISTOGRAM_BINS));
        }
        debug_assert_eq!(features.len(), DEFAULT_FEATURE_SIZE);

        features.resize(self.config.feature_size, 0.0);
        features
    }

    fn shannon_entropy(counts: &[u32; 256], total: usize) -> f32 {
        if total == 0 {
            return 0.0;
        }
        let total = total as f32;
        let mut entropy = 0.0f32;
        for &c in counts.iter() {
            if c > 0 {
                let p = c as f32 / total;
                entropy -= p * p.log2();
            }
        }
        entropy
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn disabled_config() -> MlAnalyzerConfig {
        MlAnalyzerConfig {
            enabled: false,
            ..Default::default()
        }
    }

    #[test]
    fn test_feature_vector_length_is_fixed() {
        let analyzer = MlAnalyzer::new(disabled_config());
        let feats = analyzer.extract_features(b"hello world");
        assert_eq!(feats.len(), analyzer.config.feature_size);

        // Empty input still yields a full-length vector.
        let empty = analyzer.extract_features(b"");
        assert_eq!(empty.len(), analyzer.config.feature_size);
    }

    /// Regression: the default `feature_size` used to be 256 while the layout
    /// emits 259 floats, so `resize` silently dropped histogram bins 253-255.
    /// The default must keep every bin.
    #[test]
    fn test_default_feature_size_preserves_full_histogram() {
        assert_eq!(DEFAULT_FEATURE_SIZE, SCALAR_FEATURES + HISTOGRAM_BINS);
        assert_eq!(
            MlAnalyzerConfig::default().feature_size,
            DEFAULT_FEATURE_SIZE
        );

        let analyzer = MlAnalyzer::new(disabled_config());

        // A sample containing only byte 0xFF must light up the *last* bin,
        // which truncation to 256 would have removed.
        let feats = analyzer.extract_features(&[0xFFu8; 4]);
        assert_eq!(feats.len(), DEFAULT_FEATURE_SIZE);
        assert_eq!(feats[SCALAR_FEATURES + 0xFF], 1.0);
        assert_eq!(feats[SCALAR_FEATURES + 0x00], 0.0);
    }

    /// An explicit undersized override still truncates, deliberately.
    #[test]
    fn test_explicit_smaller_feature_size_truncates() {
        let cfg = MlAnalyzerConfig {
            enabled: false,
            feature_size: 64,
            ..Default::default()
        };
        let analyzer = MlAnalyzer::new(cfg);
        assert_eq!(analyzer.extract_features(b"hello world").len(), 64);
    }

    #[tokio::test]
    async fn test_disabled_returns_unknown() {
        let analyzer = MlAnalyzer::new(disabled_config());
        assert!(!analyzer.is_available());
        let res = analyzer.analyze_file_data(b"data", "f.bin").await.unwrap();
        assert_eq!(res.verdict, ThreatVerdict::Unknown);
        assert!(res.error_message.is_some());
    }

    #[tokio::test]
    async fn test_missing_model_degrades_gracefully() {
        // Enabled, but model paths point at non-existent files.
        let cfg = MlAnalyzerConfig {
            enabled: true,
            classifier_model_path: "/nonexistent/classifier.onnx".to_string(),
            anomaly_model_path: "/nonexistent/anomaly.onnx".to_string(),
            ..Default::default()
        };
        let analyzer = MlAnalyzer::new(cfg);
        assert!(!analyzer.is_available());
        let res = analyzer.analyze_file_data(b"data", "f.bin").await.unwrap();
        assert_eq!(res.verdict, ThreatVerdict::Unknown);
    }

    /// End-to-end inference against a real ONNX model. Self-skips unless
    /// `ML_TEST_CLASSIFIER` points at a model whose single input is
    /// `[1, DEFAULT_FEATURE_SIZE]` f32 and single output is the class vector.
    /// The fixture used in local verification drives class index 1 ("malware").
    #[tokio::test]
    async fn test_real_model_inference() {
        let Ok(path) = std::env::var("ML_TEST_CLASSIFIER") else {
            return; // skipped when no model is provided (e.g. CI)
        };

        let cfg = MlAnalyzerConfig {
            enabled: true,
            classifier_model_path: path,
            anomaly_model_path: "/nonexistent/anomaly.onnx".to_string(),
            feature_size: DEFAULT_FEATURE_SIZE,
            ..Default::default()
        };
        let analyzer = MlAnalyzer::new(cfg);
        assert!(analyzer.is_available(), "classifier should have loaded");

        let res = analyzer
            .analyze_file_data(b"some non-empty sample bytes for inference", "f.bin")
            .await
            .unwrap();

        assert!(res.error_message.is_none(), "inference should succeed");
        assert_eq!(res.verdict, ThreatVerdict::Malicious);
        assert_eq!(
            res.metadata.get("predicted_class").and_then(|v| v.as_str()),
            Some("malware")
        );
    }
}
