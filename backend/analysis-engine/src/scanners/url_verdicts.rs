//! Turns a URL scan into engine votes for the consensus.
//!
//! A URL scan used to download the page and run the file engines on its HTML,
//! and look the page's hash up in MalwareBazaar, a database of malware files.
//! That said nothing about the URL. These are the engines that do:
//!
//! - **URLhaus**: abuse.ch's list of URLs and hosts serving malware.
//! - **ThreatFox**: abuse.ch's list of indicators (C2 domains, payload URLs).
//! - **URL checks**: Verdyx's own checks on the URL, redirects, TLS and page.
//!
//! A feed that doesn't list the URL has no opinion ("no record"), because
//! absence from a blocklist doesn't make a site safe.

use std::collections::HashMap;

use chrono::Utc;
use serde_json::{json, Value};
use uuid::Uuid;

use super::abuse_ch::ThreatIntelMatch;
use super::url_scanner::UrlScanResult;
use super::ThreatLevel;
use crate::models::analysis_result::{
    DetectionResult, EngineType, SeverityLevel, ThreatCategory, ThreatVerdict, AUTHORITATIVE_KEY,
};

pub const URLHAUS: &str = "URLhaus";
pub const THREATFOX: &str = "ThreatFox";
pub const URL_CHECKS: &str = "URL checks";

/// One detection per URL engine. Feeds are left out when no abuse.ch key is set.
pub fn url_detections(scan: &UrlScanResult, host_is_trusted: bool) -> Vec<DetectionResult> {
    let mut out = Vec::new();
    if let Some(intel) = &scan.threat_intel {
        for source in [URLHAUS, THREATFOX] {
            let matches: Vec<&ThreatIntelMatch> = intel
                .matches
                .iter()
                .filter(|m| m.source == source)
                .collect();
            let errors: Vec<&String> = intel
                .errors
                .iter()
                .filter(|e| e.starts_with(source))
                .collect();
            out.push(feed_detection(
                source,
                &matches,
                &errors,
                host_is_trusted,
                scan.base.scan_duration_ms,
            ));
        }
    }
    out.push(url_checks_detection(scan));
    out
}

fn detection(
    name: &str,
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
        engine_name: name.to_string(),
        engine_version: "live".to_string(),
        engine_type: if name == URL_CHECKS {
            EngineType::Static
        } else {
            EngineType::Hash
        },
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

/// How strongly one feed match counts. Exact, current listings decide the
/// verdict; weaker ones are a suspicious vote.
fn match_strength(m: &ThreatIntelMatch, host_is_trusted: bool) -> Option<(ThreatVerdict, bool)> {
    match (m.source.as_str(), m.match_type.as_str()) {
        // A shared host (code hosting, file sharing) serving malware somewhere
        // says nothing about this URL.
        (URLHAUS, "host") if host_is_trusted => None,
        (URLHAUS, "host") => Some((ThreatVerdict::Suspicious, false)),
        (URLHAUS, _) if m.status.as_deref() == Some("online") => {
            Some((ThreatVerdict::Malicious, true))
        }
        (URLHAUS, _) => Some((ThreatVerdict::Suspicious, false)),
        _ => match m.confidence.unwrap_or(0) {
            75.. => Some((ThreatVerdict::Malicious, true)),
            50..=74 => Some((ThreatVerdict::Malicious, false)),
            _ => Some((ThreatVerdict::Suspicious, false)),
        },
    }
}

fn feed_detection(
    source: &str,
    matches: &[&ThreatIntelMatch],
    errors: &[&String],
    host_is_trusted: bool,
    duration_ms: u64,
) -> DetectionResult {
    let counted: Vec<(&ThreatIntelMatch, ThreatVerdict, bool)> = matches
        .iter()
        .filter_map(|m| match_strength(m, host_is_trusted).map(|(v, a)| (*m, v, a)))
        .collect();

    if counted.is_empty() && !errors.is_empty() {
        let mut d = detection(
            source,
            ThreatVerdict::Unknown,
            0.0,
            SeverityLevel::Info,
            HashMap::new(),
            duration_ms,
        );
        d.error_message = Some(
            errors
                .iter()
                .map(|e| e.as_str())
                .collect::<Vec<_>>()
                .join("; "),
        );
        return d;
    }

    if counted.is_empty() {
        let reason = format!("Not listed on {source}");
        return detection(
            source,
            ThreatVerdict::Unknown,
            0.0,
            SeverityLevel::Info,
            HashMap::from([("reason".to_string(), json!(reason))]),
            duration_ms,
        );
    }

    let authoritative = counted.iter().any(|(_, _, a)| *a);
    let malicious = counted
        .iter()
        .any(|(_, v, _)| *v == ThreatVerdict::Malicious);
    let verdict = if malicious {
        ThreatVerdict::Malicious
    } else {
        ThreatVerdict::Suspicious
    };
    let listings: Vec<Value> = counted
        .iter()
        .map(|(m, _, _)| {
            json!({
                "matched": m.match_type,
                "indicator": m.indicator,
                "threat": m.threat,
                "malware": m.malware,
                "status": m.status,
                "feed_confidence": m.confidence,
                "tags": m.tags,
                "reference": m.reference,
            })
        })
        .collect();
    let mut metadata = HashMap::from([
        ("listings".to_string(), Value::Array(listings)),
        ("listing_count".to_string(), json!(counted.len())),
    ]);
    if authoritative {
        metadata.insert(AUTHORITATIVE_KEY.to_string(), Value::Bool(true));
    }
    if let Some(family) = counted.iter().find_map(|(m, _, _)| m.malware.clone()) {
        metadata.insert("malware_family".to_string(), json!(family));
    }
    let (confidence, severity) = match (verdict.clone(), authoritative) {
        (ThreatVerdict::Malicious, true) => (0.95, SeverityLevel::Critical),
        (ThreatVerdict::Malicious, false) => (0.7, SeverityLevel::High),
        _ => (0.5, SeverityLevel::Medium),
    };
    detection(source, verdict, confidence, severity, metadata, duration_ms)
}

/// Findings that came from the feeds, which vote as their own engines.
fn is_feed_finding(title: &str) -> bool {
    title.contains(URLHAUS) || title.contains(THREATFOX)
}

fn url_checks_detection(scan: &UrlScanResult) -> DetectionResult {
    let findings: Vec<_> = scan
        .base
        .findings
        .iter()
        .filter(|f| !is_feed_finding(&f.title))
        .collect();

    let worst = findings
        .iter()
        .map(|f| match f.severity {
            ThreatLevel::Critical => 3,
            ThreatLevel::High => 2,
            ThreatLevel::Medium => 1,
            _ => 0,
        })
        .max()
        .unwrap_or(0);
    let (verdict, confidence, severity) = match worst {
        3 => (ThreatVerdict::Malicious, 0.8, SeverityLevel::Critical),
        2 => (ThreatVerdict::Suspicious, 0.6, SeverityLevel::High),
        _ => (
            ThreatVerdict::Benign,
            0.6,
            if worst == 1 {
                SeverityLevel::Low
            } else {
                SeverityLevel::Info
            },
        ),
    };

    let mut metadata: HashMap<String, Value> = HashMap::new();
    metadata.insert(
        "findings".to_string(),
        Value::Array(
            findings
                .iter()
                .map(|f| {
                    json!({
                        "title": f.title,
                        "severity": format!("{:?}", f.severity).to_lowercase(),
                        "detail": f.description,
                    })
                })
                .collect(),
        ),
    );
    metadata.insert("domain".to_string(), json!(scan.url_info.parsed_url.domain));
    metadata.insert(
        "redirects".to_string(),
        json!(scan.redirect_chain.len().saturating_sub(1)),
    );
    if scan.redirect_chain.len() > 1 {
        metadata.insert("final_url".to_string(), json!(scan.redirect_chain.last()));
    }
    if let Some(ssl) = &scan.ssl_info {
        metadata.insert(
            "tls".to_string(),
            json!({
                "valid": ssl.has_ssl && ssl.is_valid,
                "issuer": ssl.issuer,
                "expires_in_days": ssl.expiry_days,
            }),
        );
    }
    if let Some(page) = &scan.content_analysis {
        metadata.insert("page_title".to_string(), json!(page.title));
        metadata.insert(
            "password_form".to_string(),
            json!(page.has_login_form && page.has_password_field),
        );
    }
    detection(
        URL_CHECKS,
        verdict,
        confidence,
        severity,
        metadata,
        scan.base.scan_duration_ms,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(
        source: &str,
        match_type: &str,
        status: Option<&str>,
        confidence: Option<u8>,
    ) -> ThreatIntelMatch {
        ThreatIntelMatch {
            source: source.to_string(),
            match_type: match_type.to_string(),
            indicator: "https://bad.example/x".to_string(),
            threat: Some("malware_download".to_string()),
            malware: Some("Emotet".to_string()),
            status: status.map(str::to_string),
            confidence,
            tags: vec![],
            reference: None,
        }
    }

    #[test]
    fn an_active_urlhaus_listing_is_authoritative() {
        let hit = m(URLHAUS, "url", Some("online"), None);
        let d = feed_detection(URLHAUS, &[&hit], &[], false, 5);
        assert_eq!(d.verdict, ThreatVerdict::Malicious);
        assert_eq!(d.metadata.get(AUTHORITATIVE_KEY), Some(&Value::Bool(true)));
        assert_eq!(d.metadata.get("malware_family"), Some(&json!("Emotet")));
    }

    #[test]
    fn weaker_listings_are_suspicious_and_not_authoritative() {
        let offline = m(URLHAUS, "url", Some("offline"), None);
        let d = feed_detection(URLHAUS, &[&offline], &[], false, 5);
        assert_eq!(d.verdict, ThreatVerdict::Suspicious);
        assert!(!d.metadata.contains_key(AUTHORITATIVE_KEY));

        let host = m(URLHAUS, "host", None, None);
        assert_eq!(
            feed_detection(URLHAUS, &[&host], &[], false, 5).verdict,
            ThreatVerdict::Suspicious
        );
        // On a trusted shared host the host listing doesn't count.
        assert_eq!(
            feed_detection(URLHAUS, &[&host], &[], true, 5).verdict,
            ThreatVerdict::Unknown
        );
    }

    #[test]
    fn threatfox_confidence_sets_the_strength() {
        let strong = m(THREATFOX, "domain", None, Some(100));
        let mid = m(THREATFOX, "domain", None, Some(60));
        let weak = m(THREATFOX, "domain", None, Some(25));
        let strong_d = feed_detection(THREATFOX, &[&strong], &[], false, 1);
        assert!(strong_d.metadata.contains_key(AUTHORITATIVE_KEY));
        let mid_d = feed_detection(THREATFOX, &[&mid], &[], false, 1);
        assert_eq!(mid_d.verdict, ThreatVerdict::Malicious);
        assert!(!mid_d.metadata.contains_key(AUTHORITATIVE_KEY));
        assert_eq!(
            feed_detection(THREATFOX, &[&weak], &[], false, 1).verdict,
            ThreatVerdict::Suspicious
        );
    }

    #[test]
    fn not_listed_is_no_record_and_an_outage_is_unavailable() {
        let d = feed_detection(URLHAUS, &[], &[], false, 1);
        assert_eq!(d.verdict, ThreatVerdict::Unknown);
        assert!(d.error_message.is_none());
        assert_eq!(
            d.metadata.get("reason"),
            Some(&json!("Not listed on URLhaus"))
        );

        let err = "URLhaus lookup failed: timeout".to_string();
        let d = feed_detection(URLHAUS, &[], &[&err], false, 1);
        assert_eq!(
            d.error_message.as_deref(),
            Some("URLhaus lookup failed: timeout")
        );
    }
}
