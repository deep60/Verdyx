//! Windows-program (PE) model, served by the Verdyx ML service.
//!
//! The model is a LightGBM classifier trained on EMBER2024 with EMBER's own
//! feature extractor, which only exists in Python, so it runs in its own small
//! container (`ml/`) and this analyzer calls it over the internal network.
//!
//! What the service returns, and how it maps here:
//! - a calibrated probability: a score of 0.9 means about 90% of files scored
//!   like this were malicious on held-out, newer data. It becomes the
//!   detection's confidence, so it averages fairly with the other engines.
//! - a verdict from thresholds set at fixed false-positive rates
//!   (malicious at 0.1%, suspicious at 1%).
//! - a SHAP explanation: which imports, sections, strings and header fields
//!   pushed the score, carried in the detection's metadata.
//! - whether the model passed its quality gate. By default a model that did
//!   not is advisory: shown, but not voting.
//!
//! Non-PE files are not sent at all, and the engine is absent from results
//! when `PE_MODEL_URL` is unset, so nothing changes until a model is deployed.

use std::collections::HashMap;
use std::time::Duration;

use serde::Deserialize;
use serde_json::{json, Value};
use tracing::warn;
use uuid::Uuid;

use crate::models::analysis_result::{
    DetectionResult, EngineType, SeverityLevel, ThreatCategory, ThreatVerdict,
};

pub const ENGINE_NAME: &str = "Verdyx PE Model";

/// Whether the model's verdict counts in the consensus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VotePolicy {
    /// Vote only if the deployed model passed its quality gate.
    Auto,
    Always,
    Never,
}

impl VotePolicy {
    fn parse(value: &str) -> Self {
        match value.trim().to_ascii_lowercase().as_str() {
            "always" | "true" => Self::Always,
            "never" | "false" => Self::Never,
            _ => Self::Auto,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PeModelConfig {
    /// Base URL of the ML service, e.g. `http://ml-service:8090`. Unset = off.
    pub url: Option<String>,
    pub timeout: Duration,
    pub token: Option<String>,
    pub vote: VotePolicy,
    pub max_bytes: usize,
}

impl Default for PeModelConfig {
    fn default() -> Self {
        let env = |k: &str| std::env::var(k).ok().filter(|v| !v.trim().is_empty());
        Self {
            url: env("PE_MODEL_URL").map(|u| u.trim_end_matches('/').to_string()),
            timeout: Duration::from_secs(
                env("PE_MODEL_TIMEOUT_SECS")
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(20),
            ),
            token: env("ML_SERVICE_TOKEN"),
            vote: env("PE_MODEL_VOTE")
                .map(|v| VotePolicy::parse(&v))
                .unwrap_or(VotePolicy::Auto),
            max_bytes: env("PE_MODEL_MAX_BYTES")
                .and_then(|v| v.parse().ok())
                .unwrap_or(64 * 1024 * 1024),
        }
    }
}

#[derive(Debug, Deserialize)]
struct ScoreResponse {
    applicable: bool,
    #[serde(default)]
    verdict: Option<String>,
    #[serde(default)]
    probability: Option<f32>,
    #[serde(default)]
    raw_score: Option<f32>,
    #[serde(default)]
    thresholds: Option<Value>,
    #[serde(default)]
    explanation: Option<Value>,
    #[serde(default)]
    model_version: Option<String>,
    #[serde(default)]
    quality_gate_passed: Option<bool>,
}

pub struct PeModelAnalyzer {
    config: PeModelConfig,
    http: reqwest::Client,
}

/// Shown with a prediction that does not vote.
pub const ADVISORY_REASON: &str = "Advisory only: the deployed PE model did not pass its quality gate, so its prediction does not count toward the verdict";

fn looks_like_pe(data: &[u8]) -> bool {
    if data.len() < 0x40 || &data[..2] != b"MZ" {
        return false;
    }
    let off = u32::from_le_bytes([data[0x3c], data[0x3d], data[0x3e], data[0x3f]]) as usize;
    data.get(off..off + 4) == Some(b"PE\0\0")
}

impl PeModelAnalyzer {
    pub fn new(config: PeModelConfig) -> Self {
        let http = reqwest::Client::builder()
            .timeout(config.timeout)
            .user_agent("verdyx-analysis-engine")
            .build()
            .unwrap_or_default();
        Self { config, http }
    }

    pub fn is_configured(&self) -> bool {
        self.config.url.is_some()
    }

    /// Score a file. `None` means the engine has nothing to say about it:
    /// not configured, or not a Windows program.
    pub async fn analyze(&self, data: &[u8]) -> Option<DetectionResult> {
        let base = self.config.url.as_ref()?;
        if !looks_like_pe(data) {
            return None;
        }
        let started = std::time::Instant::now();
        if data.len() > self.config.max_bytes {
            return Some(unavailable(format!(
                "file is {} bytes, above the PE model's {} byte limit",
                data.len(),
                self.config.max_bytes
            )));
        }

        let mut req = self
            .http
            .post(format!("{base}/v1/pe/score"))
            .header("Content-Type", "application/octet-stream")
            .body(data.to_vec());
        if let Some(t) = &self.config.token {
            req = req.header("X-Verdyx-ML-Token", t);
        }
        let resp = match req.send().await {
            Ok(r) => r,
            Err(e) => {
                warn!("PE model service unreachable: {e}");
                return Some(unavailable(format!("PE model service unreachable: {e}")));
            }
        };
        let status = resp.status();
        let body: Value = match resp.json().await {
            Ok(v) => v,
            Err(e) => {
                return Some(unavailable(format!(
                    "PE model sent an unreadable reply: {e}"
                )))
            }
        };
        if !status.is_success() {
            let why = body
                .get("error")
                .and_then(Value::as_str)
                .unwrap_or("no reason given");
            return Some(unavailable(format!(
                "PE model service returned {status}: {why}"
            )));
        }
        let score: ScoreResponse = match serde_json::from_value(body) {
            Ok(s) => s,
            Err(e) => return Some(unavailable(format!("PE model reply did not match: {e}"))),
        };
        if !score.applicable {
            return None;
        }
        Some(self.to_detection(score, started.elapsed().as_millis() as u64))
    }

    fn to_detection(&self, s: ScoreResponse, elapsed_ms: u64) -> DetectionResult {
        let probability = s.probability.unwrap_or(0.0).clamp(0.0, 1.0);
        let (verdict, severity) = match s.verdict.as_deref() {
            Some("malicious") => (ThreatVerdict::Malicious, SeverityLevel::High),
            Some("suspicious") => (ThreatVerdict::Suspicious, SeverityLevel::Medium),
            Some("benign") => (ThreatVerdict::Benign, SeverityLevel::Info),
            _ => (ThreatVerdict::Unknown, SeverityLevel::Info),
        };
        // Confidence in the verdict given, from the calibrated probability.
        let confidence = match verdict {
            ThreatVerdict::Benign => 1.0 - probability,
            ThreatVerdict::Unknown => 0.0,
            _ => probability,
        };
        let gate_passed = s.quality_gate_passed.unwrap_or(false);
        let votes = match self.config.vote {
            VotePolicy::Always => true,
            VotePolicy::Never => false,
            VotePolicy::Auto => gate_passed,
        };

        let summary = s
            .explanation
            .as_ref()
            .and_then(|e| e.get("summary"))
            .and_then(Value::as_str)
            .map(str::to_string);
        let mut metadata = HashMap::from([
            ("probability".to_string(), json!(probability)),
            ("raw_score".to_string(), json!(s.raw_score)),
            ("model_verdict".to_string(), json!(s.verdict)),
            (
                "thresholds".to_string(),
                s.thresholds.unwrap_or(Value::Null),
            ),
            (
                "explanation".to_string(),
                s.explanation.unwrap_or(Value::Null),
            ),
            ("quality_gate_passed".to_string(), json!(gate_passed)),
            ("counts_toward_verdict".to_string(), json!(votes)),
        ]);
        if let Some(summary) = summary {
            metadata.insert("summary".to_string(), json!(summary));
        }

        let categories = match verdict {
            ThreatVerdict::Malicious | ThreatVerdict::Suspicious => vec![ThreatCategory::Malware],
            _ => vec![],
        };
        let version = s.model_version.unwrap_or_else(|| "unknown".to_string());

        if !votes {
            metadata.insert("advisory_confidence".to_string(), json!(confidence));
            return DetectionResult {
                detection_id: Uuid::new_v4(),
                engine_name: ENGINE_NAME.to_string(),
                engine_version: version,
                engine_type: EngineType::Ml,
                verdict: ThreatVerdict::Unknown,
                confidence: 0.0,
                severity: SeverityLevel::Info,
                categories: vec![],
                metadata,
                detected_at: chrono::Utc::now(),
                processing_time_ms: elapsed_ms,
                error_message: Some(ADVISORY_REASON.to_string()),
            };
        }

        DetectionResult {
            detection_id: Uuid::new_v4(),
            engine_name: ENGINE_NAME.to_string(),
            engine_version: version,
            engine_type: EngineType::Ml,
            verdict,
            confidence,
            severity,
            categories,
            metadata,
            detected_at: chrono::Utc::now(),
            processing_time_ms: elapsed_ms,
            error_message: None,
        }
    }

    /// For the engine status page: (status, version, details, error).
    pub async fn status(&self) -> (String, String, String, Option<String>) {
        let Some(base) = &self.config.url else {
            return (
                "disabled".into(),
                "none".into(),
                "PE model not configured (set PE_MODEL_URL)".into(),
                None,
            );
        };
        let health: Result<Value, String> = async {
            let r = self
                .http
                .get(format!("{base}/health"))
                .timeout(Duration::from_secs(3))
                .send()
                .await
                .map_err(|e| e.to_string())?;
            r.json::<Value>().await.map_err(|e| e.to_string())
        }
        .await;
        match health {
            Err(e) => (
                "unavailable".into(),
                "unknown".into(),
                format!("Cannot reach the ML service at {base}"),
                Some(e),
            ),
            Ok(h) => {
                let m = &h["pe_model"];
                if m["loaded"].as_bool() != Some(true) {
                    let why = m["reason"]
                        .as_str()
                        .unwrap_or("no model loaded")
                        .to_string();
                    return ("unavailable".into(), "none".into(), why.clone(), Some(why));
                }
                let version = m["model_version"].as_str().unwrap_or("unknown").to_string();
                let pct = |k: &str| {
                    m[k].as_f64()
                        .map(|v| format!("{:.2}%", v * 100.0))
                        .unwrap_or_else(|| "n/a".into())
                };
                let gate = m["quality_gate_passed"].as_bool() == Some(true);
                let details = format!(
                    "LightGBM on EMBER2024 features. On newer, held-out files: detects {} of malware at {} false positives. {}",
                    pct("test_detection_rate"),
                    pct("test_false_positive_rate"),
                    if gate {
                        "Passed its quality gate; votes in the consensus."
                    } else {
                        "Did not pass its quality gate; advisory only."
                    }
                );
                ("online".into(), version, details, None)
            }
        }
    }
}

fn unavailable(reason: String) -> DetectionResult {
    DetectionResult {
        detection_id: Uuid::new_v4(),
        engine_name: ENGINE_NAME.to_string(),
        engine_version: "unavailable".to_string(),
        engine_type: EngineType::Ml,
        verdict: ThreatVerdict::Unknown,
        confidence: 0.0,
        severity: SeverityLevel::Info,
        categories: vec![],
        metadata: HashMap::from([
            ("status".to_string(), json!("unavailable")),
            ("reason".to_string(), json!(reason.clone())),
        ]),
        detected_at: chrono::Utc::now(),
        processing_time_ms: 0,
        error_message: Some(reason),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        http::{HeaderMap, StatusCode},
        routing::{get, post},
        Json, Router,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    /// Enough of a PE for `looks_like_pe`: MZ, e_lfanew, PE signature.
    fn pe_bytes() -> Vec<u8> {
        let mut v = vec![0u8; 0x80];
        v[..2].copy_from_slice(b"MZ");
        v[0x3c] = 0x40;
        v[0x40..0x44].copy_from_slice(b"PE\0\0");
        v
    }

    async fn serve(router: Router) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        format!("http://{addr}")
    }

    fn analyzer(url: Option<String>, vote: VotePolicy) -> PeModelAnalyzer {
        PeModelAnalyzer::new(PeModelConfig {
            url,
            timeout: Duration::from_secs(5),
            token: Some("tok".into()),
            vote,
            max_bytes: 1024,
        })
    }

    fn reply(verdict: &str, probability: f32, gate: bool) -> Value {
        json!({
            "applicable": true, "verdict": verdict, "probability": probability,
            "raw_score": 0.97, "thresholds": {"malicious": 0.9, "suspicious": 0.5},
            "explanation": {"summary": "Main reasons: imported function: kernel32.dll:virtualallocex", "reasons": []},
            "model_version": "pe-20261105", "quality_gate_passed": gate
        })
    }

    fn scoring_service(body: Value, hits: Arc<AtomicUsize>) -> Router {
        Router::new().route(
            "/v1/pe/score",
            post(move |headers: HeaderMap| {
                let body = body.clone();
                let hits = hits.clone();
                async move {
                    hits.fetch_add(1, Ordering::SeqCst);
                    assert_eq!(headers["x-verdyx-ml-token"], "tok");
                    assert_eq!(headers["content-type"], "application/octet-stream");
                    Json(body)
                }
            }),
        )
    }

    #[test]
    fn recognises_pe_files() {
        assert!(looks_like_pe(&pe_bytes()));
        assert!(!looks_like_pe(b"MZ but far too short"));
        let mut not_pe = pe_bytes();
        not_pe[0x40] = b'X';
        assert!(!looks_like_pe(&not_pe));
    }

    #[tokio::test]
    async fn off_when_not_configured() {
        let a = analyzer(None, VotePolicy::Auto);
        assert!(!a.is_configured());
        assert!(a.analyze(&pe_bytes()).await.is_none());
        assert_eq!(a.status().await.0, "disabled");
    }

    #[tokio::test]
    async fn non_pe_files_are_never_sent() {
        let hits = Arc::new(AtomicUsize::new(0));
        let base = serve(scoring_service(
            reply("malicious", 0.99, true),
            hits.clone(),
        ))
        .await;
        let a = analyzer(Some(base), VotePolicy::Auto);
        assert!(a.analyze(b"%PDF-1.7 hello").await.is_none());
        assert_eq!(hits.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn a_gated_model_votes_with_its_calibrated_probability() {
        let hits = Arc::new(AtomicUsize::new(0));
        let base = serve(scoring_service(
            reply("malicious", 0.93, true),
            hits.clone(),
        ))
        .await;
        let det = analyzer(Some(base), VotePolicy::Auto)
            .analyze(&pe_bytes())
            .await
            .unwrap();
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        assert_eq!(det.verdict, ThreatVerdict::Malicious);
        assert!((det.confidence - 0.93).abs() < 1e-6);
        assert_eq!(det.severity, SeverityLevel::High);
        assert!(det.error_message.is_none());
        assert_eq!(det.engine_version, "pe-20261105");
        assert!(det.metadata["summary"]
            .as_str()
            .unwrap()
            .contains("virtualallocex"));
        assert_eq!(det.metadata["counts_toward_verdict"], json!(true));
    }

    #[tokio::test]
    async fn benign_confidence_is_one_minus_probability() {
        let hits = Arc::new(AtomicUsize::new(0));
        let base = serve(scoring_service(reply("benign", 0.02, true), hits)).await;
        let det = analyzer(Some(base), VotePolicy::Auto)
            .analyze(&pe_bytes())
            .await
            .unwrap();
        assert_eq!(det.verdict, ThreatVerdict::Benign);
        assert!((det.confidence - 0.98).abs() < 1e-6);
    }

    #[tokio::test]
    async fn an_ungated_model_is_advisory_unless_forced() {
        let hits = Arc::new(AtomicUsize::new(0));
        let base = serve(scoring_service(reply("malicious", 0.97, false), hits)).await;

        let det = analyzer(Some(base.clone()), VotePolicy::Auto)
            .analyze(&pe_bytes())
            .await
            .unwrap();
        assert_eq!(det.verdict, ThreatVerdict::Unknown);
        assert_eq!(det.error_message.as_deref(), Some(ADVISORY_REASON));
        assert_eq!(det.metadata["model_verdict"], json!("malicious"));

        let forced = analyzer(Some(base), VotePolicy::Always)
            .analyze(&pe_bytes())
            .await
            .unwrap();
        assert_eq!(forced.verdict, ThreatVerdict::Malicious);
    }

    #[tokio::test]
    async fn service_errors_become_unavailable_detections() {
        let router = Router::new().route(
            "/v1/pe/score",
            post(|| async {
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(json!({"error": "no model bundle in /models/pe"})),
                )
            }),
        );
        let base = serve(router).await;
        let det = analyzer(Some(base), VotePolicy::Auto)
            .analyze(&pe_bytes())
            .await
            .unwrap();
        assert_eq!(det.verdict, ThreatVerdict::Unknown);
        assert!(det
            .error_message
            .unwrap()
            .contains("no model bundle in /models/pe"));

        // Nothing listening at all.
        let dead = analyzer(Some("http://127.0.0.1:9".into()), VotePolicy::Auto)
            .analyze(&pe_bytes())
            .await
            .unwrap();
        assert!(dead.error_message.unwrap().contains("unreachable"));
    }

    #[tokio::test]
    async fn not_applicable_and_oversized_files() {
        let hits = Arc::new(AtomicUsize::new(0));
        let base = serve(scoring_service(
            json!({"applicable": false, "reason": "not a Windows PE file"}),
            hits.clone(),
        ))
        .await;
        let a = analyzer(Some(base), VotePolicy::Auto);
        assert!(a.analyze(&pe_bytes()).await.is_none());

        let mut big = pe_bytes();
        big.resize(4096, 0);
        let det = a.analyze(&big).await.unwrap();
        assert!(det.error_message.unwrap().contains("byte limit"));
        assert_eq!(hits.load(Ordering::SeqCst), 1, "oversized file is not sent");
    }

    #[tokio::test]
    async fn status_reads_the_service_health() {
        let router = Router::new().route(
            "/health",
            get(|| async {
                Json(json!({"status": "ok", "pe_model": {
                    "loaded": true, "model_version": "pe-1", "quality_gate_passed": true,
                    "test_detection_rate": 0.91, "test_false_positive_rate": 0.0012
                }}))
            }),
        );
        let base = serve(router).await;
        let (status, version, details, err) = analyzer(Some(base), VotePolicy::Auto).status().await;
        assert_eq!((status.as_str(), version.as_str()), ("online", "pe-1"));
        assert!(
            details.contains("91.00%") && details.contains("0.12%"),
            "{details}"
        );
        assert!(err.is_none());
    }
}
