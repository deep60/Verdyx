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

/// Why an engine took no part in the vote.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum NonVoteKind {
    /// The engine failed, timed out or isn't running.
    #[default]
    Unavailable,
    /// The engine ran and had nothing to say, e.g. a reputation feed that has
    /// never seen this file. That is a result, not a failure.
    NoRecord,
    /// The engine ran, but by design its prediction doesn't vote (ML today).
    Advisory,
}

/// An engine that ran (or tried to) without casting a vote.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnavailableEngineInfo {
    pub engine_name: String,
    pub engine_type: EngineType,
    pub reason: String,
    #[serde(default)]
    pub kind: NonVoteKind,
}

/// Metadata key marking a detection that summarises other detections, such as
/// the hash analyzer's roll-up of its feeds. It never votes, so a feed match
/// isn't counted twice.
pub const AGGREGATE_KEY: &str = "aggregate";

/// Metadata key marking an exact match in a curated known-malware list
/// (MalwareBazaar, URLhaus, ThreatFox, EICAR). Such a match decides the
/// verdict: engines that found nothing can't outvote a confirmed sample.
pub const AUTHORITATIVE_KEY: &str = "authoritative";

fn meta_flag(detection: &DetectionResult, key: &str) -> bool {
    detection.metadata.get(key).and_then(|v| v.as_bool()) == Some(true)
}

impl DetectionResult {
    /// True for roll-up rows that must not vote or be shown as an engine.
    pub fn is_aggregate(&self) -> bool {
        meta_flag(self, AGGREGATE_KEY)
    }

    /// Why this detection doesn't vote, or `None` if it does.
    pub fn non_vote(&self) -> Option<(NonVoteKind, String)> {
        let meta_reason = || {
            self.metadata
                .get("reason")
                .and_then(|v| v.as_str())
                .map(str::to_string)
        };
        if self.metadata.contains_key("advisory_verdict") {
            let reason = self
                .error_message
                .clone()
                .or_else(meta_reason)
                .unwrap_or_else(|| "Advisory only; does not vote".to_string());
            return Some((NonVoteKind::Advisory, reason));
        }
        let failed = self.error_message.is_some()
            || self.metadata.get("status").and_then(|v| v.as_str()) == Some("unavailable");
        if failed {
            let reason = self
                .error_message
                .clone()
                .or_else(meta_reason)
                .unwrap_or_else(|| "Engine unavailable".to_string());
            return Some((NonVoteKind::Unavailable, reason));
        }
        if self.verdict == ThreatVerdict::Unknown {
            let reason =
                meta_reason().unwrap_or_else(|| "Ran; no match and no opinion".to_string());
            return Some((NonVoteKind::NoRecord, reason));
        }
        None
    }
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
        let mut flagged_by = Vec::new();
        let mut confirmed_by = Vec::new();

        for detection in self.detections.iter().filter(|d| !d.is_aggregate()) {
            if let Some((kind, reason)) = detection.non_vote() {
                unknown_count += 1;
                unavailable.push(UnavailableEngineInfo {
                    engine_name: detection.engine_name.clone(),
                    engine_type: detection.engine_type.clone(),
                    reason,
                    kind,
                });
                continue;
            }

            participating.push(detection.engine_name.clone());
            total_confidence += detection.confidence;
            match detection.verdict {
                ThreatVerdict::Malicious => {
                    malicious_count += 1;
                    flagged_by.push(detection.engine_name.clone());
                    if meta_flag(detection, AUTHORITATIVE_KEY) {
                        confirmed_by.push(detection.engine_name.clone());
                    }
                }
                ThreatVerdict::Suspicious => {
                    suspicious_count += 1;
                    flagged_by.push(detection.engine_name.clone());
                }
                ThreatVerdict::Benign => benign_count += 1,
                ThreatVerdict::Unknown => {}
            }
            max_severity = max_severity.max(detection.severity.clone());
        }

        let total_participating = malicious_count + benign_count + suspicious_count;
        let total_engines = total_participating + unknown_count;

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

        let not_voting_note = {
            let group = |k: NonVoteKind, label: &str| {
                let names: Vec<&str> = unavailable
                    .iter()
                    .filter(|u| u.kind == k)
                    .map(|u| u.engine_name.as_str())
                    .collect();
                (!names.is_empty()).then(|| format!("{label} ({})", names.join(", ")))
            };
            let parts: Vec<String> = [
                group(NonVoteKind::NoRecord, "no record"),
                group(NonVoteKind::Advisory, "advisory"),
                group(NonVoteKind::Unavailable, "unavailable"),
            ]
            .into_iter()
            .flatten()
            .collect();
            if parts.is_empty() {
                String::new()
            } else {
                format!(" Not voting: {}.", parts.join("; "))
            }
        };

        if total_participating == 0 {
            self.consensus_verdict = ThreatVerdict::Unknown;
            self.consensus_confidence = 0.0;
            self.agreement_score = 0.0;
            self.consensus_explanation = format!(
                "No verdict: none of the {total_engines} engines gave one.{not_voting_note}"
            );
        } else {
            self.consensus_confidence =
                (total_confidence / total_participating as f32).clamp(0.0, 1.0);

            let malicious_majority =
                malicious_count > benign_count && malicious_count > suspicious_count;
            self.consensus_verdict = if !confirmed_by.is_empty() || malicious_majority {
                ThreatVerdict::Malicious
            } else if benign_count > malicious_count && benign_count > suspicious_count {
                ThreatVerdict::Benign
            } else if malicious_count + suspicious_count > 0 {
                ThreatVerdict::Suspicious
            } else {
                ThreatVerdict::Unknown
            };

            let max_votes = malicious_count.max(benign_count).max(suspicious_count);
            self.agreement_score = (max_votes as f32 / total_participating as f32) * 100.0;

            let flagged = if flagged_by.is_empty() {
                format!("None of the {total_participating} voting engines flagged it.")
            } else {
                format!(
                    "{} of {total_participating} voting engines flagged it ({}).",
                    flagged_by.len(),
                    flagged_by.join(", ")
                )
            };
            self.consensus_explanation = if confirmed_by.is_empty() {
                format!("{flagged}{not_voting_note}")
            } else {
                format!(
                    "Known malicious: listed by {}. A match in a curated malware list decides the verdict. {flagged}{not_voting_note}",
                    confirmed_by.join(", ")
                )
            };
        }

        // Record auditable history entry if verdict differs or history is empty
        let needs_audit = self.verdict_history.last().is_none_or(|last| {
            last.verdict != self.consensus_verdict
                || (last.confidence - self.consensus_confidence).abs() > 0.001
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

#[cfg(test)]
mod consensus_tests {
    use super::*;

    fn det(
        name: &str,
        verdict: ThreatVerdict,
        meta: &[(&str, serde_json::Value)],
    ) -> DetectionResult {
        DetectionResult {
            detection_id: Uuid::new_v4(),
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
            detected_at: Utc::now(),
            processing_time_ms: 1,
            error_message: None,
        }
    }

    fn result_of(dets: Vec<DetectionResult>) -> AnalysisResult {
        let mut r = AnalysisResult::default();
        for d in dets {
            r.add_detection(d);
        }
        r
    }

    #[test]
    fn a_known_malware_listing_is_not_outvoted() {
        let r = result_of(vec![
            det(
                "MalwareBazaar",
                ThreatVerdict::Malicious,
                &[(AUTHORITATIVE_KEY, true.into())],
            ),
            det("YARA", ThreatVerdict::Benign, &[]),
            det("Signature", ThreatVerdict::Benign, &[]),
            det("Static", ThreatVerdict::Benign, &[]),
        ]);
        assert_eq!(r.consensus_verdict, ThreatVerdict::Malicious);
        assert!(r
            .consensus_explanation
            .starts_with("Known malicious: listed by MalwareBazaar"));
    }

    #[test]
    fn an_unconfirmed_malicious_vote_is_still_outvoted() {
        let r = result_of(vec![
            det("Static", ThreatVerdict::Malicious, &[]),
            det("YARA", ThreatVerdict::Benign, &[]),
            det("Signature", ThreatVerdict::Benign, &[]),
        ]);
        assert_eq!(r.consensus_verdict, ThreatVerdict::Benign);
        assert!(r
            .consensus_explanation
            .contains("1 of 3 voting engines flagged it (Static)"));
    }

    #[test]
    fn a_tie_between_malicious_and_clean_is_suspicious() {
        let r = result_of(vec![
            det("Static", ThreatVerdict::Malicious, &[]),
            det("YARA", ThreatVerdict::Benign, &[]),
        ]);
        assert_eq!(r.consensus_verdict, ThreatVerdict::Suspicious);
    }

    #[test]
    fn aggregates_never_vote_or_appear() {
        let r = result_of(vec![
            det("MalwareBazaar", ThreatVerdict::Malicious, &[]),
            det(
                "Hash Analyzer Consensus",
                ThreatVerdict::Malicious,
                &[(AGGREGATE_KEY, true.into())],
            ),
            det("YARA", ThreatVerdict::Benign, &[]),
        ]);
        assert_eq!(r.vote_distribution.malicious, 1);
        assert_eq!(r.vote_distribution.total_engines, 2);
        assert!(!r
            .participating_engines
            .contains(&"Hash Analyzer Consensus".to_string()));
    }

    #[test]
    fn non_votes_say_why() {
        let mut failed = det("ClamAV", ThreatVerdict::Unknown, &[]);
        failed.error_message = Some("connection refused".to_string());
        let mut ml = det(
            "ML Engine",
            ThreatVerdict::Unknown,
            &[("advisory_verdict", "benign".into())],
        );
        ml.error_message = Some("Advisory only".to_string());
        let r = result_of(vec![
            det(
                "MalwareBazaar",
                ThreatVerdict::Unknown,
                &[("reason", "Not in MalwareBazaar".into())],
            ),
            failed,
            ml,
            det("YARA", ThreatVerdict::Benign, &[]),
        ]);
        let kind = |name: &str| {
            r.unavailable_engines
                .iter()
                .find(|u| u.engine_name == name)
                .unwrap()
                .kind
        };
        assert_eq!(kind("MalwareBazaar"), NonVoteKind::NoRecord);
        assert_eq!(kind("ClamAV"), NonVoteKind::Unavailable);
        assert_eq!(kind("ML Engine"), NonVoteKind::Advisory);
        assert!(r.consensus_explanation.ends_with(
            "Not voting: no record (MalwareBazaar); advisory (ML Engine); unavailable (ClamAV)."
        ));
    }

    #[test]
    fn nothing_voting_is_no_verdict() {
        let r = result_of(vec![det("MalwareBazaar", ThreatVerdict::Unknown, &[])]);
        assert_eq!(r.consensus_verdict, ThreatVerdict::Unknown);
        assert!(r.consensus_explanation.starts_with("No verdict"));
    }
}
