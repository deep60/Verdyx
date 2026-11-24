use anyhow::{anyhow, Result};
use std::time::{Duration, Instant};
use tokio::time::timeout;
use tracing::{error, info, warn};

use crate::models::analysis_result::{
    DetectionResult, EngineType, SeverityLevel, ThreatCategory, ThreatVerdict,
};

/// Configuration for ClamAV analyzer
#[derive(Debug, Clone)]
pub struct ClamAvAnalyzerConfig {
    /// ClamAV daemon TCP address in `host:port` form (e.g. `clamav:3310`).
    pub address: String,
    /// Connection/scan timeout in seconds
    pub timeout_seconds: u64,
    /// Enable ClamAV scanning
    pub enabled: bool,
}

impl Default for ClamAvAnalyzerConfig {
    fn default() -> Self {
        // CLAMAV_HOST is the full `host:port` address (matches docker-compose,
        // which sets `clamav:3310`). A bare host without a port falls back to
        // the clamd default port 3310.
        let address = std::env::var("CLAMAV_HOST")
            .ok()
            .map(|h| h.trim().to_string())
            .filter(|h| !h.is_empty())
            .map(|h| {
                if h.contains(':') {
                    h
                } else {
                    format!("{h}:3310")
                }
            })
            .unwrap_or_else(|| "localhost:3310".to_string());

        Self {
            address,
            timeout_seconds: std::env::var("CLAMAV_TIMEOUT_SECONDS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(30),
            enabled: std::env::var("ENABLE_CLAMAV")
                .unwrap_or_else(|_| "true".to_string())
                .parse()
                .unwrap_or(true),
        }
    }
}

/// ClamAV-based malware analyzer. Streams file bytes to a running `clamd`
/// daemon over TCP (INSTREAM) and interprets the verdict.
pub struct ClamAvAnalyzer {
    config: ClamAvAnalyzerConfig,
}

impl ClamAvAnalyzer {
    /// Create a new ClamAV analyzer
    pub fn new(config: ClamAvAnalyzerConfig) -> Self {
        info!(
            "Initializing ClamAV analyzer - address: {}, enabled: {}",
            config.address, config.enabled
        );
        Self { config }
    }

    /// Scan file data for malware using ClamAV
    pub async fn scan_file(&self, file_data: &[u8], filename: &str) -> Result<DetectionResult> {
        if !self.config.enabled {
            warn!("ClamAV analyzer is disabled");
            return Ok(self.create_disabled_result());
        }

        let start_time = Instant::now();
        info!(
            "Starting ClamAV scan for file: {} ({} bytes)",
            filename,
            file_data.len()
        );

        // Stream the buffer to clamd (INSTREAM) over TCP, bounded by a timeout.
        let scan = timeout(
            Duration::from_secs(self.config.timeout_seconds),
            clamav_client::tokio::scan_buffer_tcp(file_data, &self.config.address, None),
        )
        .await;

        let response = match scan {
            Ok(Ok(resp)) => resp,
            Ok(Err(e)) => {
                error!(
                    "ClamAV scan failed for {} via {}: {}",
                    filename, self.config.address, e
                );
                return Ok(self.create_error_result(filename, &format!("ClamAV scan error: {e}")));
            }
            Err(_) => {
                error!(
                    "ClamAV scan timed out for {} after {}s",
                    filename, self.config.timeout_seconds
                );
                return Ok(self.create_error_result(filename, "ClamAV scan timed out"));
            }
        };

        let processing_time = start_time.elapsed().as_millis() as u64;
        let detection = self.interpret_response(&response, filename, processing_time);

        info!(
            "ClamAV scan completed for {} - verdict: {:?}, time: {}ms",
            filename, detection.verdict, processing_time
        );

        Ok(detection)
    }

    /// Interpret a raw clamd INSTREAM response into a `DetectionResult`.
    ///
    /// clamd replies with either `stream: OK` (clean) or
    /// `stream: <Signature> FOUND` (malware detected).
    fn interpret_response(
        &self,
        response: &[u8],
        filename: &str,
        processing_time_ms: u64,
    ) -> DetectionResult {
        let is_clean = clamav_client::clean(response).unwrap_or(false);
        let text = String::from_utf8_lossy(response);

        if is_clean {
            info!("ClamAV: File {} is clean", filename);
            return DetectionResult {
                detection_id: uuid::Uuid::new_v4(),
                engine_name: "ClamAV".to_string(),
                engine_version: "clamd".to_string(),
                engine_type: EngineType::Antivirus,
                verdict: ThreatVerdict::Benign,
                confidence: 0.95,
                severity: SeverityLevel::Info,
                categories: vec![],
                metadata: std::collections::HashMap::new(),
                detected_at: chrono::Utc::now(),
                processing_time_ms,
                error_message: None,
            };
        }

        if text.contains("FOUND") {
            let virus_name =
                Self::parse_signature(&text).unwrap_or_else(|| "Unknown.Signature".to_string());
            warn!("ClamAV: Malware detected in {} - {}", filename, virus_name);

            let mut metadata = std::collections::HashMap::new();
            metadata.insert(
                "signature".to_string(),
                serde_json::Value::String(virus_name.clone()),
            );
            metadata.insert(
                "filename".to_string(),
                serde_json::Value::String(filename.to_string()),
            );

            return DetectionResult {
                detection_id: uuid::Uuid::new_v4(),
                engine_name: "ClamAV".to_string(),
                engine_version: "clamd".to_string(),
                engine_type: EngineType::Antivirus,
                verdict: ThreatVerdict::Malicious,
                confidence: 0.98,
                severity: self.determine_severity(&virus_name),
                categories: self.categorize_threat(&virus_name),
                metadata,
                detected_at: chrono::Utc::now(),
                processing_time_ms,
                error_message: None,
            };
        }

        // Neither OK nor FOUND: treat as an error/unknown response from clamd.
        self.create_error_result(
            filename,
            &format!("Unexpected ClamAV response: {}", text.trim()),
        )
    }

    /// Extract the signature name from a `stream: <Signature> FOUND` response.
    fn parse_signature(response: &str) -> Option<String> {
        let line = response.trim().trim_end_matches('\0').trim();
        let idx = line.find("FOUND")?;
        let before = line[..idx].trim_end();
        // Drop the leading `stream:` (or any `prefix:`) label if present.
        let name = before.rsplit(':').next().unwrap_or(before).trim();
        if name.is_empty() {
            None
        } else {
            Some(name.to_string())
        }
    }

    /// Categorize threat based on signature name
    fn categorize_threat(&self, signature: &str) -> Vec<ThreatCategory> {
        let sig_lower = signature.to_lowercase();
        let mut categories = vec![];

        if sig_lower.contains("trojan") {
            categories.push(ThreatCategory::Trojan);
        }
        if sig_lower.contains("ransomware") || sig_lower.contains("ransom") {
            categories.push(ThreatCategory::Ransomware);
        }
        if sig_lower.contains("worm") {
            categories.push(ThreatCategory::Worm);
        }
        if sig_lower.contains("rootkit") {
            categories.push(ThreatCategory::Rootkit);
        }
        if sig_lower.contains("backdoor") {
            categories.push(ThreatCategory::Backdoor);
        }
        if sig_lower.contains("spyware") || sig_lower.contains("keylog") {
            categories.push(ThreatCategory::Spyware);
        }
        if sig_lower.contains("adware") {
            categories.push(ThreatCategory::Adware);
        }
        if sig_lower.contains("exploit") {
            categories.push(ThreatCategory::Exploit);
        }

        // Default to generic malware if no specific category
        if categories.is_empty() {
            categories.push(ThreatCategory::Malware);
        }

        categories
    }

    /// Determine severity based on threat type
    fn determine_severity(&self, signature: &str) -> SeverityLevel {
        let sig_lower = signature.to_lowercase();

        if sig_lower.contains("ransomware") || sig_lower.contains("rootkit") {
            SeverityLevel::Critical
        } else if sig_lower.contains("trojan") || sig_lower.contains("backdoor") {
            SeverityLevel::High
        } else if sig_lower.contains("worm") || sig_lower.contains("exploit") {
            SeverityLevel::Medium
        } else {
            SeverityLevel::Low
        }
    }

    /// Create result for disabled state
    fn create_disabled_result(&self) -> DetectionResult {
        DetectionResult {
            detection_id: uuid::Uuid::new_v4(),
            engine_name: "ClamAV".to_string(),
            engine_version: "Disabled".to_string(),
            engine_type: EngineType::Antivirus,
            verdict: ThreatVerdict::Unknown,
            confidence: 0.0,
            severity: SeverityLevel::Info,
            categories: vec![],
            metadata: std::collections::HashMap::new(),
            detected_at: chrono::Utc::now(),
            processing_time_ms: 0,
            error_message: Some("ClamAV analyzer is disabled".to_string()),
        }
    }

    /// Create result for error state
    fn create_error_result(&self, filename: &str, error_msg: &str) -> DetectionResult {
        warn!("ClamAV error for {}: {}", filename, error_msg);

        DetectionResult {
            detection_id: uuid::Uuid::new_v4(),
            engine_name: "ClamAV".to_string(),
            engine_version: "Error".to_string(),
            engine_type: EngineType::Antivirus,
            verdict: ThreatVerdict::Unknown,
            confidence: 0.0,
            severity: SeverityLevel::Info,
            categories: vec![],
            metadata: std::collections::HashMap::new(),
            detected_at: chrono::Utc::now(),
            processing_time_ms: 0,
            error_message: Some(error_msg.to_string()),
        }
    }

    /// Ping the ClamAV daemon to check that it is reachable and alive.
    pub async fn ping(&self) -> Result<()> {
        let response = clamav_client::tokio::ping_tcp(&self.config.address)
            .await
            .map_err(|e| anyhow!("ClamAV ping failed at {}: {e}", self.config.address))?;

        if response.starts_with(b"PONG") {
            info!("ClamAV daemon is alive at {}", self.config.address);
            Ok(())
        } else {
            Err(anyhow!(
                "Unexpected ClamAV ping response: {}",
                String::from_utf8_lossy(&response)
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_signature() {
        assert_eq!(
            ClamAvAnalyzer::parse_signature("stream: Win.Test.EICAR_HDB-1 FOUND\0"),
            Some("Win.Test.EICAR_HDB-1".to_string())
        );
        assert_eq!(ClamAvAnalyzer::parse_signature("stream: OK\0"), None);
    }

    #[tokio::test]
    async fn test_eicar_detection() {
        // EICAR test file - standard malware test string
        let eicar = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

        let analyzer = ClamAvAnalyzer::new(ClamAvAnalyzerConfig {
            address: "localhost:3310".to_string(),
            timeout_seconds: 30,
            enabled: true,
        });

        // Only run if ClamAV is available
        if analyzer.ping().await.is_ok() {
            let result = analyzer.scan_file(eicar, "eicar.txt").await;
            assert!(result.is_ok());

            let detection = result.unwrap();
            assert_eq!(detection.verdict, ThreatVerdict::Malicious);
            assert!(detection.confidence > 0.9);
        }
    }
}
