pub mod archive_scanner;
pub mod email_scanner;
/// Scanner modules for different artifact types
///
/// This module provides specialized scanners for:
/// - Files (executables, documents, archives)
/// - URLs (phishing detection, malicious links)
/// - Emails (spam, phishing, malicious attachments)
/// - Archives (zip, tar, rar, etc.)
pub mod file_scanner;
pub mod url_policy;
pub mod url_scanner;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Base configuration for all scanners
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannerConfig {
    pub scanner_name: String,
    pub enabled: bool,
    pub max_file_size_mb: u64,
    pub timeout_seconds: u64,
    pub enable_deep_scan: bool,
    pub quarantine_suspicious: bool,
}

impl Default for ScannerConfig {
    fn default() -> Self {
        Self {
            scanner_name: "Generic Scanner".to_string(),
            enabled: true,
            max_file_size_mb: 100,
            timeout_seconds: 300,
            enable_deep_scan: true,
            quarantine_suspicious: true,
        }
    }
}

/// Generic scan result structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub scan_id: Uuid,
    pub artifact_type: ArtifactType,
    pub verdict: ScanVerdict,
    pub confidence_score: f32,
    pub threat_level: ThreatLevel,
    pub findings: Vec<Finding>,
    pub metadata: HashMap<String, String>,
    pub scan_duration_ms: u64,
    pub scanned_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ArtifactType {
    File,
    Url,
    Email,
    Archive,
    Script,
    Document,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ScanVerdict {
    Clean,
    Suspicious,
    Malicious,
    Unknown,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, PartialOrd)]
pub enum ThreatLevel {
    None,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub finding_id: Uuid,
    pub category: FindingCategory,
    pub title: String,
    pub description: String,
    pub severity: ThreatLevel,
    pub evidence: Vec<String>,
    pub recommendation: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum FindingCategory {
    Malware,
    Phishing,
    Suspicious,
    PotentiallyUnwanted,
    DataExfiltration,
    NetworkThreat,
    Exploit,
    Ransomware,
    Trojan,
    Other(String),
}

impl ScanResult {
    pub fn new(artifact_type: ArtifactType) -> Self {
        Self {
            scan_id: Uuid::new_v4(),
            artifact_type,
            verdict: ScanVerdict::Unknown,
            confidence_score: 0.0,
            threat_level: ThreatLevel::None,
            findings: Vec::new(),
            metadata: HashMap::new(),
            scan_duration_ms: 0,
            scanned_at: chrono::Utc::now(),
        }
    }

    pub fn add_finding(&mut self, finding: Finding) {
        // Update threat level if this finding is more severe
        if finding.severity > self.threat_level {
            self.threat_level = finding.severity.clone();
        }
        self.findings.push(finding);
        self.update_verdict();
    }

    fn update_verdict(&mut self) {
        if self.findings.is_empty() {
            self.verdict = ScanVerdict::Clean;
            self.confidence_score = 0.9;
            return;
        }

        let malicious_count = self
            .findings
            .iter()
            .filter(|f| {
                matches!(
                    f.category,
                    FindingCategory::Malware
                        | FindingCategory::Ransomware
                        | FindingCategory::Trojan
                )
            })
            .count();

        let suspicious_count = self
            .findings
            .iter()
            .filter(|f| {
                matches!(
                    f.category,
                    FindingCategory::Suspicious | FindingCategory::PotentiallyUnwanted
                )
            })
            .count();

        if malicious_count > 0 {
            self.verdict = ScanVerdict::Malicious;
            self.confidence_score =
                (malicious_count as f32 / (self.findings.len() as f32)).min(1.0);
        } else if suspicious_count > 0 {
            self.verdict = ScanVerdict::Suspicious;
            self.confidence_score =
                (suspicious_count as f32 / (self.findings.len() as f32)).min(1.0);
        } else {
            self.verdict = ScanVerdict::Clean;
            self.confidence_score = 0.8;
        }
    }

    pub fn is_malicious(&self) -> bool {
        matches!(self.verdict, ScanVerdict::Malicious)
    }

    pub fn is_suspicious(&self) -> bool {
        matches!(self.verdict, ScanVerdict::Suspicious)
    }

    pub fn is_clean(&self) -> bool {
        matches!(self.verdict, ScanVerdict::Clean)
    }
}

/// Trait that all scanners must implement
#[async_trait::async_trait]
pub trait Scanner {
    type Config;
    type Result;

    /// Initialize the scanner with configuration
    fn new(config: Self::Config) -> Result<Self>
    where
        Self: Sized;

    /// Perform a scan
    async fn scan(
        &self,
        data: &[u8],
        metadata: Option<HashMap<String, String>>,
    ) -> Result<Self::Result>;

    /// Get scanner statistics
    fn get_stats(&self) -> HashMap<String, String>;

    /// Check if scanner is healthy
    fn health_check(&self) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_result_creation() {
        let result = ScanResult::new(ArtifactType::File);
        assert_eq!(result.artifact_type, ArtifactType::File);
        assert_eq!(result.verdict, ScanVerdict::Unknown);
        assert_eq!(result.findings.len(), 0);
    }

    #[test]
    fn test_finding_addition() {
        let mut result = ScanResult::new(ArtifactType::File);

        let finding = Finding {
            finding_id: Uuid::new_v4(),
            category: FindingCategory::Malware,
            title: "Malicious executable detected".to_string(),
            description: "PE file contains malicious code".to_string(),
            severity: ThreatLevel::High,
            evidence: vec!["Signature match".to_string()],
            recommendation: Some("Quarantine immediately".to_string()),
        };

        result.add_finding(finding);

        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.verdict, ScanVerdict::Malicious);
        assert_eq!(result.threat_level, ThreatLevel::High);
    }

    #[test]
    fn test_verdict_update() {
        let mut result = ScanResult::new(ArtifactType::File);

        // Add suspicious finding
        result.add_finding(Finding {
            finding_id: Uuid::new_v4(),
            category: FindingCategory::Suspicious,
            title: "Suspicious behavior".to_string(),
            description: "Unusual patterns detected".to_string(),
            severity: ThreatLevel::Medium,
            evidence: vec![],
            recommendation: None,
        });

        assert_eq!(result.verdict, ScanVerdict::Suspicious);

        // Add malicious finding - should override
        result.add_finding(Finding {
            finding_id: Uuid::new_v4(),
            category: FindingCategory::Malware,
            title: "Malware detected".to_string(),
            description: "Known malware signature".to_string(),
            severity: ThreatLevel::High,
            evidence: vec![],
            recommendation: None,
        });

        assert_eq!(result.verdict, ScanVerdict::Malicious);
        assert_eq!(result.threat_level, ThreatLevel::High);
    }
}
