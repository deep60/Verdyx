use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ThreatVerdict {
    Malicious,
    Benign,
    Suspicious,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ConfidenceLevel {
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ThreatLevel {
    Clean,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchDetails {
    pub rule_name: String,
    pub namespace: Option<String>,
    pub tags: Vec<String>,
    pub meta: HashMap<String, String>,
    pub strings: Vec<YaraString>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, PartialOrd, Ord, Eq)]
pub enum SeverityLevel {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl SeverityLevel {
    pub fn max(self, other: Self) -> Self {
        use SeverityLevel::*;
        match (self, other) {
            (Critical, _) | (_, Critical) => Critical,
            (High, _) | (_, High) => High,
            (Medium, _) | (_, Medium) => Medium,
            (Low, _) | (_, Low) => Low,
            _ => Info,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum EngineType {
    Static,
    Dynamic,
    Yara,
    Hash,
    Behavioral,
    Sandbox,
    Human,
    Ml,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ThreatCategory {
    Malware,
    Ransomware,
    Trojan,
    Virus,
    Worm,
    Adware,
    Spyware,
    Rootkit,
    Phishing,
    Exploit,
    Backdoor,
    Other(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionResult {
    pub detection_id: Uuid,
    pub engine_name: String,
    pub engine_version: String,
    pub engine_type: EngineType,
    pub verdict: ThreatVerdict,
    pub confidence: f32,
    pub severity: SeverityLevel,
    pub categories: Vec<ThreatCategory>,
    pub metadata: HashMap<String, serde_json::Value>,
    pub detected_at: DateTime<Utc>,
    pub processing_time_ms: u64,
    pub error_message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraMatch {
    pub rule_name: String,
    pub namespace: Option<String>,
    pub tags: Vec<String>,
    pub meta: HashMap<String, String>,
    pub strings: Vec<YaraString>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraString {
    pub identifier: String,
    pub instances: Vec<YaraStringInstance>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraStringInstance {
    pub offset: u64,
    pub length: u32,
    pub matched_data: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileMetadata {
    pub filename: Option<String>,
    pub file_size: u64,
    pub mime_type: String,
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
    pub sha512: Option<String>,
    pub entropy: Option<f64>,
    pub magic_bytes: Option<String>,
    pub executable_info: Option<ExecutableInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutableInfo {
    pub architecture: String,
    pub entry_point: Option<u64>,
    pub compile_time: Option<DateTime<Utc>>,
    pub imports: Vec<String>,
    pub exports: Vec<String>,
    pub signature_info: Option<SignatureInfo>,
    pub sections: Vec<SectionInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureInfo {
    pub is_valid: bool,
    pub signer: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionInfo {
    pub name: String,
    pub size: u64,
    pub entropy: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkIndicators {
    pub urls: Vec<String>,
    pub ips: Vec<String>,
    pub domains: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralAnalysis {
    pub process_operations: Vec<ProcessOperation>,
    pub file_operations: Vec<FileOperation>,
    pub registry_operations: Vec<RegistryOperation>,
    pub network_operations: Vec<NetworkOperation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessOperation {
    pub operation: String,
    pub process_id: u32,
    pub details: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileOperation {
    pub operation: String,
    pub path: String,
    pub details: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryOperation {
    pub operation: String,
    pub key: String,
    pub value: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkOperation {
    pub operation: String,
    pub destination: String,
    pub protocol: String,
    pub data_size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AnalysisStatus {
    Pending,
    InProgress,
    Completed,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnavailableEngineInfo {
    pub engine_name: String,
    pub engine_type: EngineType,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ConsensusVoteDistribution {
    pub malicious: usize,
    pub benign: usize,
    pub suspicious: usize,
    pub unknown: usize,
    pub total_participating: usize,
    pub total_engines: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerdictAuditRecord {
    pub verdict: ThreatVerdict,
    pub confidence: f32,
    pub reason: String,
    pub changed_by: String,
    pub changed_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisResult {
    pub analysis_id: Uuid,
    pub submission_id: Uuid,
    pub bounty_id: Option<Uuid>,
    pub file_metadata: FileMetadata,
    pub consensus_verdict: ThreatVerdict,
    pub consensus_confidence: f32,
    pub consensus_severity: SeverityLevel,
    pub detections: Vec<DetectionResult>,
    pub yara_matches: Vec<YaraMatch>,
    pub network_indicators: Option<NetworkIndicators>,
    pub behavioral_analysis: Option<BehavioralAnalysis>,
    pub tags: Vec<String>,
    pub notes: Option<String>,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub total_processing_time_ms: Option<u64>,
    pub status: AnalysisStatus,
    pub error_message: Option<String>,
    pub analysis_cost: Option<f64>,
    pub engine_reputations: HashMap<String, f32>,
    #[serde(default)]
    pub participating_engines: Vec<String>,
    #[serde(default)]
    pub unavailable_engines: Vec<UnavailableEngineInfo>,
    #[serde(default)]
    pub vote_distribution: ConsensusVoteDistribution,
    #[serde(default)]
    pub agreement_score: f32,
    #[serde(default)]
    pub consensus_explanation: String,
    #[serde(default)]
    pub verdict_history: Vec<VerdictAuditRecord>,
}

impl AnalysisResult {
    pub fn new(submission_id: Uuid, file_metadata: FileMetadata) -> Self {
        Self {
            analysis_id: Uuid::new_v4(),
            submission_id,
            bounty_id: None,
            file_metadata,
            consensus_verdict: ThreatVerdict::Unknown,
            consensus_confidence: 0.0,
            consensus_severity: SeverityLevel::Info,
            detections: Vec::new(),
            yara_matches: Vec::new(),
            network_indicators: None,
            behavioral_analysis: None,
            tags: Vec::new(),
            notes: None,
            started_at: Utc::now(),
            completed_at: None,
            total_processing_time_ms: None,
            status: AnalysisStatus::Pending,
            error_message: None,
            analysis_cost: None,
            engine_reputations: HashMap::new(),
            participating_engines: Vec::new(),
            unavailable_engines: Vec::new(),
            vote_distribution: ConsensusVoteDistribution::default(),
            agreement_score: 0.0,
            consensus_explanation: "Analysis initialized; awaiting engine detections.".to_string(),
            verdict_history: Vec::new(),
        }
    }

    pub fn add_detection(&mut self, detection: DetectionResult) {
        self.detections.push(detection);
        self.update_consensus();
    }

    pub fn update_consensus(&mut self) {
        if self.detections.is_empty() {
            self.consensus_verdict = ThreatVerdict::Unknown;
            self.consensus_confidence = 0.0;
            self.agreement_score = 0.0;
            self.consensus_explanation = "No detections recorded yet.".to_string();
            return;
        }

        let mut malicious_count = 0;
        let mut benign_count = 0;
        let mut suspicious_count = 0;
        let mut unknown_count = 0;
        let mut total_confidence = 0.0;
        let mut max_severity = SeverityLevel::Info;

        let mut participating = Vec::new();
        let mut unavailable = Vec::new();

        for detection in &self.detections {
            let is_unavailable = detection.error_message.is_some()
                || detection.metadata.get("status").and_then(|v| v.as_str()) == Some("unavailable")
                || matches!(detection.verdict, ThreatVerdict::Unknown);

            if is_unavailable {
                unknown_count += 1;
                let reason = detection
                    .error_message
                    .clone()
                    .unwrap_or_else(|| "Engine unavailable or did not produce a verdict".to_string());

                unavailable.push(UnavailableEngineInfo {
                    engine_name: detection.engine_name.clone(),
                    engine_type: detection.engine_type.clone(),
                    reason,
                });
            } else {
                participating.push(detection.engine_name.clone());
                total_confidence += detection.confidence;

                match detection.verdict {
                    ThreatVerdict::Malicious => malicious_count += 1,
                    ThreatVerdict::Benign => benign_count += 1,
                    ThreatVerdict::Suspicious => suspicious_count += 1,
                    ThreatVerdict::Unknown => {}
                }

                max_severity = max_severity.max(detection.severity.clone());
            }
        }

        let total_participating = malicious_count + benign_count + suspicious_count;
        let total_engines = self.detections.len();

        self.participating_engines = participating.clone();
        self.unavailable_engines = unavailable.clone();
        self.vote_distribution = ConsensusVoteDistribution {
            malicious: malicious_count,
            benign: benign_count,
            suspicious: suspicious_count,
            unknown: unknown_count,
            total_participating,
            total_engines,
        };
        self.consensus_severity = max_severity;

        if total_participating == 0 {
            self.consensus_verdict = ThreatVerdict::Unknown;
            self.consensus_confidence = 0.0;
            self.agreement_score = 0.0;
            self.consensus_explanation = format!(
                "Consensus verdict is Unknown. All {} engines were unavailable or reported errors.",
                total_engines
            );
        } else {
            // Confidence is calculated strictly across active participating engines
            self.consensus_confidence = (total_confidence / total_participating as f32).clamp(0.0, 1.0);

            // Verdict resolution
            if malicious_count > benign_count && malicious_count > suspicious_count {
                self.consensus_verdict = ThreatVerdict::Malicious;
            } else if benign_count > malicious_count && benign_count > suspicious_count {
                self.consensus_verdict = ThreatVerdict::Benign;
            } else if suspicious_count > 0 {
                self.consensus_verdict = ThreatVerdict::Suspicious;
            } else {
                self.consensus_verdict = ThreatVerdict::Unknown;
            }

            let max_votes = malicious_count.max(benign_count).max(suspicious_count);
            self.agreement_score = (max_votes as f32 / total_participating as f32) * 100.0;

            let unavailable_note = if !unavailable.is_empty() {
                let unavail_names: Vec<String> = unavailable.iter().map(|u| u.engine_name.clone()).collect();
                format!(
                    " {} engine(s) ({}) were unavailable and excluded from consensus.",
                    unavailable.len(),
                    unavail_names.join(", ")
                )
            } else {
                String::new()
            };

            self.consensus_explanation = format!(
                "Verdict: {:?} with {:.1}% agreement ({}/{} active engines: {}). Weighted confidence index: {:.2}.{}",
                self.consensus_verdict,
                self.agreement_score,
                max_votes,
                total_participating,
                participating.join(", "),
                self.consensus_confidence,
                unavailable_note
            );
        }

        // Record auditable history entry if verdict differs or history is empty
        let needs_audit = self.verdict_history.last().map_or(true, |last| {
            last.verdict != self.consensus_verdict || (last.confidence - self.consensus_confidence).abs() > 0.001
        });

        if needs_audit {
            self.verdict_history.push(VerdictAuditRecord {
                verdict: self.consensus_verdict.clone(),
                confidence: self.consensus_confidence,
                reason: self.consensus_explanation.clone(),
                changed_by: "engine_consensus_aggregator".to_string(),
                changed_at: Utc::now(),
            });
        }
    }

    pub fn mark_completed(&mut self) {
        self.completed_at = Some(Utc::now());
        self.status = AnalysisStatus::Completed;

        if let Some(completed) = self.completed_at {
            self.total_processing_time_ms =
                Some((completed - self.started_at).num_milliseconds() as u64);
        }
    }

    pub fn mark_failed(&mut self, error: String) {
        self.status = AnalysisStatus::Failed;
        self.error_message = Some(error);
        self.completed_at = Some(Utc::now());
    }

    pub fn is_high_confidence_malicious(&self) -> bool {
        matches!(self.consensus_verdict, ThreatVerdict::Malicious)
            && self.consensus_confidence >= 0.8
    }

    pub fn get_all_threat_categories(&self) -> Vec<ThreatCategory> {
        let mut categories = Vec::new();
        for detection in &self.detections {
            for category in &detection.categories {
                if !categories.contains(category) {
                    categories.push(category.clone());
                }
            }
        }
        categories
    }

    pub fn get_malicious_engines(&self) -> Vec<&String> {
        self.detections
            .iter()
            .filter(|d| matches!(d.verdict, ThreatVerdict::Malicious))
            .map(|d| &d.engine_name)
            .collect()
    }
}

impl Default for AnalysisResult {
    fn default() -> Self {
        Self::new(
            Uuid::new_v4(),
            FileMetadata {
                filename: None,
                file_size: 0,
                mime_type: "application/octet-stream".to_string(),
                md5: String::new(),
                sha1: String::new(),
                sha256: String::new(),
                sha512: None,
                entropy: None,
                magic_bytes: None,
                executable_info: None,
            },
        )
    }
}
