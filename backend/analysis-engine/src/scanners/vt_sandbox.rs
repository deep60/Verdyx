//! Behavioral analysis through VirusTotal's sandboxes.
//!
//! Verdyx doesn't detonate files itself: the VM has no room for a sandbox.
//! A "Behavioral Analysis" scan asks VirusTotal for the behaviour its
//! sandboxes recorded for the file (processes, dropped files, network, MITRE
//! ATT&CK techniques). If VirusTotal has never seen the file, it is uploaded
//! so the sandboxes run it, and the report is added to the scan when it's
//! ready. Uploading shares the file with VirusTotal and its users; the form
//! says so before the user picks this mode.
//!
//! Uses `VIRUSTOTAL_API_KEY`, the key the hash and URL lookups already use.

use std::collections::HashMap;
use std::time::Duration;

use anyhow::{anyhow, Result};
use chrono::Utc;
use serde::Serialize;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::models::analysis_result::{
    DetectionResult, EngineType, SeverityLevel, ThreatCategory, ThreatVerdict, STRONG_SIGNAL_KEY,
};

/// Engine name shown in reports.
pub const SANDBOX: &str = "VirusTotal sandbox";
/// VirusTotal's limit for a direct upload. Larger files need an upload URL,
/// and memory on the VM is too tight to hold them twice anyway.
pub const MAX_UPLOAD_BYTES: usize = 32 * 1024 * 1024;
/// How often a pending report is checked, and how many times. Each check is
/// one request against the free key's 4 per minute.
pub const POLL_INTERVAL: Duration = Duration::from_secs(180);
pub const POLL_ATTEMPTS: u32 = 10;
/// Entries kept per list in the stored report.
const LIST_CAP: usize = 20;

const VT_API: &str = "https://www.virustotal.com/api/v3";

/// Sandbox verdicts that make a file malicious.
const MALICIOUS_VERDICTS: &[&str] = &[
    "MALWARE", "RANSOM", "TROJAN", "RAT", "BANKER", "SPREADER", "EXPLOIT", "EVADER", "PHISHING",
];
/// Sandbox verdicts for unwanted but not plainly malicious software.
const SUSPICIOUS_VERDICTS: &[&str] = &["GREYWARE", "ADWARE"];

#[derive(Clone)]
pub struct SandboxClient {
    http: reqwest::Client,
    key: String,
    api: String,
}

/// One MITRE ATT&CK technique the sandboxes saw.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Technique {
    pub id: String,
    pub description: String,
    /// "high", "medium", "low" or "info".
    pub severity: String,
}

/// What the sandboxes recorded, trimmed to what a report shows.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct Behaviour {
    pub verdicts: Vec<String>,
    pub techniques: Vec<Technique>,
    pub processes: Vec<String>,
    pub files_written: Vec<String>,
    pub dns: Vec<String>,
    pub ips: Vec<String>,
    pub tags: Vec<String>,
}

/// How the sandbox step of one scan ended.
#[derive(Debug, Clone, PartialEq)]
pub enum SandboxOutcome {
    /// A behaviour report exists.
    Report(Behaviour),
    /// Uploaded; the report is added when it's ready.
    Submitted,
    /// Polled for the whole window without a report.
    TimedOut,
    /// Not run, with the reason (no key, file too large).
    Skipped(String),
    /// The lookup or upload failed.
    Error(String),
}

impl SandboxClient {
    /// `None` when no VirusTotal key is set.
    pub fn from_env() -> Option<Self> {
        let key = std::env::var("VIRUSTOTAL_API_KEY")
            .ok()
            .map(|k| k.trim().to_string())
            .filter(|k| !k.is_empty())?;
        Self::with_endpoint(key, VT_API).ok()
    }

    pub fn with_endpoint(key: String, api: &str) -> Result<Self> {
        let http = reqwest::Client::builder()
            // An upload of up to 32 MB over the VM's link.
            .timeout(Duration::from_secs(120))
            .user_agent("verdyx-analysis-engine")
            .build()?;
        Ok(Self {
            http,
            key,
            api: api.trim_end_matches('/').to_string(),
        })
    }

    /// The merged behaviour report for a file, or `None` if no sandbox has
    /// run it yet.
    pub async fn behaviour(&self, sha256: &str) -> Result<Option<Behaviour>> {
        let resp = self
            .http
            .get(format!("{}/files/{sha256}/behaviour_summary", self.api))
            .header("x-apikey", &self.key)
            .send()
            .await?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !resp.status().is_success() {
            return Err(anyhow!(
                "VirusTotal returned HTTP {}",
                resp.status().as_u16()
            ));
        }
        let body: Value = resp.json().await?;
        Ok(parse_behaviour(&body))
    }

    /// Uploads a file so VirusTotal's sandboxes run it.
    pub async fn upload(&self, filename: &str, data: Vec<u8>) -> Result<()> {
        if data.len() > MAX_UPLOAD_BYTES {
            return Err(anyhow!("file is larger than 32 MB"));
        }
        let part = reqwest::multipart::Part::bytes(data).file_name(filename.to_string());
        let form = reqwest::multipart::Form::new().part("file", part);
        let resp = self
            .http
            .post(format!("{}/files", self.api))
            .header("x-apikey", &self.key)
            .multipart(form)
            .send()
            .await?;
        if !resp.status().is_success() {
            return Err(anyhow!(
                "VirusTotal upload returned HTTP {}",
                resp.status().as_u16()
            ));
        }
        Ok(())
    }
}

fn strings(v: &Value) -> Vec<String> {
    v.as_array()
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// "IMPACT_SEVERITY_HIGH", "HIGH" → "high".
fn severity(raw: &str) -> String {
    let raw = raw.to_ascii_uppercase();
    for level in ["HIGH", "MEDIUM", "LOW"] {
        if raw.ends_with(level) {
            return level.to_ascii_lowercase();
        }
    }
    "info".to_string()
}

fn capped(mut v: Vec<String>) -> Vec<String> {
    v.sort();
    v.dedup();
    v.truncate(LIST_CAP);
    v
}

/// Reads `behaviour_summary`. `None` when the report is empty.
pub fn parse_behaviour(body: &Value) -> Option<Behaviour> {
    let d = body.get("data")?;
    if !d.is_object() {
        return None;
    }

    let mut techniques: Vec<Technique> = Vec::new();
    // The documented list: [{id, signature_description, severity}].
    for t in d["mitre_attack_techniques"]
        .as_array()
        .into_iter()
        .flatten()
    {
        if let Some(id) = t["id"].as_str() {
            techniques.push(Technique {
                id: id.to_string(),
                description: t["signature_description"]
                    .as_str()
                    .unwrap_or("")
                    .to_string(),
                severity: severity(t["severity"].as_str().unwrap_or("")),
            });
        }
    }
    // The newer map: {"T1573": [{severity, description}]}.
    for (id, items) in d["attack_techniques"].as_object().into_iter().flatten() {
        for t in items.as_array().into_iter().flatten() {
            techniques.push(Technique {
                id: id.clone(),
                description: t["description"].as_str().unwrap_or("").to_string(),
                severity: severity(t["severity"].as_str().unwrap_or("")),
            });
        }
    }
    let rank = |s: &str| match s {
        "high" => 0,
        "medium" => 1,
        "low" => 2,
        _ => 3,
    };
    techniques.sort_by(|a, b| {
        rank(&a.severity)
            .cmp(&rank(&b.severity))
            .then(a.id.cmp(&b.id))
    });
    techniques.dedup_by(|a, b| a.id == b.id && a.description == b.description);
    techniques.truncate(LIST_CAP);

    let mut processes = strings(&d["processes_created"]);
    processes.extend(strings(&d["command_executions"]));

    let mut files_written = strings(&d["files_written"]);
    for f in d["files_dropped"].as_array().into_iter().flatten() {
        if let Some(p) = f["path"].as_str().or(f.as_str()) {
            files_written.push(p.to_string());
        }
    }

    let dns = d["dns_lookups"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|x| x["hostname"].as_str().map(str::to_string))
        .collect();

    let ips = d["ip_traffic"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|x| {
            let ip = x["destination_ip"].as_str()?;
            Some(match x["destination_port"].as_u64() {
                Some(port) => format!("{ip}:{port}"),
                None => ip.to_string(),
            })
        })
        .collect();

    let b = Behaviour {
        verdicts: capped(
            strings(&d["verdicts"])
                .into_iter()
                .map(|v| v.to_ascii_uppercase())
                .collect(),
        ),
        techniques,
        processes: capped(processes),
        files_written: capped(files_written),
        dns: capped(dns),
        ips: capped(ips),
        tags: capped(strings(&d["tags"])),
    };
    if b == Behaviour::default() {
        None
    } else {
        Some(b)
    }
}

fn reference(sha256: &str) -> String {
    format!("https://www.virustotal.com/gui/file/{sha256}/behavior")
}

fn detection(
    verdict: ThreatVerdict,
    confidence: f32,
    severity: SeverityLevel,
    metadata: HashMap<String, Value>,
    duration_ms: u64,
) -> DetectionResult {
    let categories = match verdict {
        ThreatVerdict::Malicious => vec![ThreatCategory::Malware],
        _ => vec![],
    };
    DetectionResult {
        detection_id: Uuid::new_v4(),
        engine_name: SANDBOX.to_string(),
        engine_version: "live".to_string(),
        engine_type: EngineType::Sandbox,
        verdict,
        confidence,
        severity,
        categories,
        metadata,
        detected_at: Utc::now(),
        processing_time_ms: duration_ms,
        error_message: None,
    }
}

/// A sandbox step that has no opinion (yet), with why.
fn no_record(status: &str, reason: &str, sha256: &str, duration_ms: u64) -> DetectionResult {
    detection(
        ThreatVerdict::Unknown,
        0.0,
        SeverityLevel::Info,
        HashMap::from([
            ("reason".to_string(), json!(reason)),
            ("sandbox_status".to_string(), json!(status)),
            ("reference".to_string(), json!(reference(sha256))),
        ]),
        duration_ms,
    )
}

/// The sandbox's vote. Its own verdicts decide; without one, high-severity
/// ATT&CK behaviour makes the file suspicious. A run that shows nothing bad
/// is no opinion: plenty of malware sleeps through a sandbox.
pub fn sandbox_detection(
    outcome: &SandboxOutcome,
    sha256: &str,
    duration_ms: u64,
) -> DetectionResult {
    let b = match outcome {
        SandboxOutcome::Report(b) => b,
        SandboxOutcome::Submitted => {
            return no_record(
                "pending",
                "Sent to VirusTotal's sandboxes. The behaviour report is added to this scan when it's ready, usually within 30 minutes.",
                sha256,
                duration_ms,
            )
        }
        SandboxOutcome::TimedOut => {
            return no_record(
                "timed_out",
                "No sandbox report arrived within 30 minutes. VirusTotal doesn't run every file type.",
                sha256,
                duration_ms,
            )
        }
        SandboxOutcome::Skipped(why) => return no_record("skipped", why, sha256, duration_ms),
        SandboxOutcome::Error(e) => {
            let mut d = no_record("error", "", sha256, duration_ms);
            d.metadata.remove("reason");
            d.error_message = Some(format!("{SANDBOX} failed: {e}"));
            return d;
        }
    };

    let bad: Vec<&String> = b
        .verdicts
        .iter()
        .filter(|v| MALICIOUS_VERDICTS.contains(&v.as_str()))
        .collect();
    let grey = b
        .verdicts
        .iter()
        .any(|v| SUSPICIOUS_VERDICTS.contains(&v.as_str()));
    let high: Vec<&Technique> = b
        .techniques
        .iter()
        .filter(|t| t.severity == "high")
        .collect();

    let (verdict, confidence, severity, reason) = if !bad.is_empty() {
        (
            ThreatVerdict::Malicious,
            0.85,
            SeverityLevel::High,
            format!(
                "The sandboxes classified it as {}",
                bad.iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        )
    } else if grey {
        (
            ThreatVerdict::Suspicious,
            0.5,
            SeverityLevel::Medium,
            "The sandboxes classified it as unwanted software (greyware or adware)".to_string(),
        )
    } else if !high.is_empty() {
        (
            ThreatVerdict::Suspicious,
            0.5,
            SeverityLevel::Medium,
            format!(
                "High-severity behaviour: {}",
                high.iter()
                    .take(3)
                    .map(|t| format!("{} ({})", t.description, t.id))
                    .collect::<Vec<_>>()
                    .join("; ")
            ),
        )
    } else {
        let mut d = no_record(
            "complete",
            "The sandboxes ran it and saw no malicious behaviour. That doesn't prove it's safe: some malware stays quiet in a sandbox.",
            sha256,
            duration_ms,
        );
        d.metadata.insert("behaviour".to_string(), json!(b));
        return d;
    };

    let mut meta = HashMap::from([
        ("reason".to_string(), json!(reason)),
        ("sandbox_status".to_string(), json!("complete")),
        ("reference".to_string(), json!(reference(sha256))),
        ("behaviour".to_string(), json!(b)),
    ]);
    if verdict == ThreatVerdict::Malicious {
        meta.insert(STRONG_SIGNAL_KEY.to_string(), json!(true));
    }
    detection(verdict, confidence, severity, meta, duration_ms)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn summary() -> Value {
        json!({"data": {
            "verdicts": ["malware", "RANSOM"],
            "mitre_attack_techniques": [
                {"id": "T1486", "signature_description": "Encrypts files", "severity": "IMPACT_SEVERITY_HIGH"},
                {"id": "T1082", "signature_description": "Reads system info", "severity": "IMPACT_SEVERITY_INFO"}
            ],
            "attack_techniques": {
                "T1573": [{"severity": "INFO", "description": "Uses HTTPS"}]
            },
            "processes_created": ["C:\\tasksche.exe", "C:\\tasksche.exe"],
            "command_executions": ["icacls . /grant Everyone:F"],
            "files_dropped": [{"path": "C:\\@WanaDecryptor@.exe", "sha256": "ab"}],
            "dns_lookups": [{"hostname": "iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com", "resolved_ips": []}],
            "ip_traffic": [{"destination_ip": "10.0.0.1", "destination_port": 445, "transport_layer_protocol": "TCP"}],
            "tags": ["DETECT_DEBUG_ENVIRONMENT"]
        }})
    }

    #[test]
    fn parses_a_summary() {
        let b = parse_behaviour(&summary()).unwrap();
        assert_eq!(b.verdicts, vec!["MALWARE", "RANSOM"]);
        assert_eq!(b.techniques[0].id, "T1486");
        assert_eq!(b.techniques[0].severity, "high");
        assert!(b
            .techniques
            .iter()
            .any(|t| t.id == "T1573" && t.severity == "info"));
        assert_eq!(b.processes.len(), 2, "duplicates removed, commands kept");
        assert_eq!(b.files_written, vec!["C:\\@WanaDecryptor@.exe"]);
        assert_eq!(b.ips, vec!["10.0.0.1:445"]);
        assert_eq!(b.dns.len(), 1);
    }

    #[test]
    fn an_empty_summary_is_no_report() {
        assert_eq!(parse_behaviour(&json!({"data": {}})), None);
        assert_eq!(
            parse_behaviour(&json!({"error": {"code": "NotFoundError"}})),
            None
        );
    }

    #[test]
    fn sandbox_malware_verdict_is_malicious() {
        let b = parse_behaviour(&summary()).unwrap();
        let d = sandbox_detection(&SandboxOutcome::Report(b), "abc", 5);
        assert_eq!(d.verdict, ThreatVerdict::Malicious);
        assert_eq!(d.engine_type, EngineType::Sandbox);
        assert!(d.non_vote().is_none());
        assert_eq!(d.metadata[STRONG_SIGNAL_KEY], json!(true));
        assert!(d.metadata["reference"]
            .as_str()
            .unwrap()
            .contains("abc/behavior"));
    }

    #[test]
    fn high_severity_behaviour_alone_is_suspicious() {
        let b = Behaviour {
            techniques: vec![Technique {
                id: "T1055".into(),
                description: "Injects into another process".into(),
                severity: "high".into(),
            }],
            ..Default::default()
        };
        let d = sandbox_detection(&SandboxOutcome::Report(b), "abc", 5);
        assert_eq!(d.verdict, ThreatVerdict::Suspicious);
        assert!(d.non_vote().is_none());
    }

    #[test]
    fn a_quiet_run_pending_upload_or_failure_does_not_vote() {
        let quiet = Behaviour {
            verdicts: vec!["CLEAN".into()],
            processes: vec!["a.exe".into()],
            ..Default::default()
        };
        for outcome in [
            SandboxOutcome::Report(quiet),
            SandboxOutcome::Submitted,
            SandboxOutcome::TimedOut,
            SandboxOutcome::Skipped("too large".into()),
            SandboxOutcome::Error("HTTP 429".into()),
        ] {
            let d = sandbox_detection(&outcome, "abc", 5);
            assert_eq!(d.verdict, ThreatVerdict::Unknown, "{outcome:?}");
            assert!(d.non_vote().is_some(), "{outcome:?}");
        }
        let pending = sandbox_detection(&SandboxOutcome::Submitted, "abc", 5);
        assert_eq!(pending.metadata["sandbox_status"], json!("pending"));
    }

    /// A local stand-in for VirusTotal: a known hash, an unknown one, and
    /// the upload.
    #[tokio::test]
    async fn client_reads_reports_and_uploads() {
        use axum::{routing::get, routing::post, Json, Router};

        let app = Router::new()
            .route(
                "/files/{sha}/behaviour_summary",
                get(
                    |axum::extract::Path(sha): axum::extract::Path<String>| async move {
                        if sha == "known" {
                            Ok(Json(summary()))
                        } else {
                            Err(axum::http::StatusCode::NOT_FOUND)
                        }
                    },
                ),
            )
            .route(
                "/files",
                post(|| async { Json(json!({"data": {"type": "analysis", "id": "x"}})) }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let client = SandboxClient::with_endpoint("k".into(), &base).unwrap();
        assert!(client.behaviour("known").await.unwrap().is_some());
        assert!(client.behaviour("unknown").await.unwrap().is_none());
        client.upload("a.exe", b"MZ".to_vec()).await.unwrap();
        assert!(client
            .upload("big.bin", vec![0; MAX_UPLOAD_BYTES + 1])
            .await
            .is_err());
    }
}
