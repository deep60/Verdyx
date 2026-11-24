//! Turns a URL scan into engine votes for the consensus.
//!
//! A URL scan used to download the page and run the file engines on its HTML,
//! and look the page's hash up in MalwareBazaar, a database of malware files.
//! That said nothing about the URL. These are the engines that do:
//!
//! - **URLhaus**: abuse.ch's list of URLs and hosts serving malware.
//! - **ThreatFox**: abuse.ch's list of indicators (C2 domains, payload URLs).
//! - **VirusTotal**: the URL's last analysis by ~90 security vendors.
//! - **Google Safe Browsing**: Google's malware and phishing lists.
//! - **URL checks**: Verdyx's own checks on the URL, redirects, TLS, page
//!   and the domain's registration age.
//!
//! A feed that doesn't list the URL has no opinion ("no record"), because
//! absence from a blocklist doesn't make a site safe.

use std::collections::HashMap;

use chrono::Utc;
use serde_json::{json, Value};
use uuid::Uuid;

use super::abuse_ch::ThreatIntelMatch;
use super::url_reputation::{SafeBrowsing, VirusTotalUrl};
use super::url_scanner::UrlScanResult;
use super::{Finding, ThreatLevel};
use crate::models::analysis_result::{
    DetectionResult, EngineType, SeverityLevel, ThreatCategory, ThreatVerdict, AUTHORITATIVE_KEY,
};

pub const URLHAUS: &str = "URLhaus";
pub const THREATFOX: &str = "ThreatFox";
pub const URL_CHECKS: &str = "URL checks";
pub const VIRUSTOTAL: &str = "VirusTotal";
pub const SAFE_BROWSING: &str = "Google Safe Browsing";

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
    if let Some(rep) = &scan.reputation {
        let ms = scan.base.scan_duration_ms;
        if let Some(vt) = &rep.virustotal {
            out.push(virustotal_detection(vt, ms));
        }
        if let Some(gsb) = &rep.safe_browsing {
            out.push(safe_browsing_detection(gsb, ms));
        }
    }
    out.push(url_checks_detection(scan));
    out
}

/// An engine that answered but has nothing on this URL.
fn no_record(name: &str, reason: &str, duration_ms: u64) -> DetectionResult {
    detection(
        name,
        ThreatVerdict::Unknown,
        0.0,
        SeverityLevel::Info,
        HashMap::from([("reason".to_string(), json!(reason))]),
        duration_ms,
    )
}

/// An engine that couldn't answer (network, key, rate limit).
fn unavailable(name: &str, error: &str, duration_ms: u64) -> DetectionResult {
    let mut d = detection(
        name,
        ThreatVerdict::Unknown,
        0.0,
        SeverityLevel::Info,
        HashMap::new(),
        duration_ms,
    );
    d.error_message = Some(format!("{name} lookup failed: {error}"));
    d
}

/// VirusTotal's vendors vote together. One vendor alone is often a false
/// positive, so it only makes the URL suspicious; three or more decide it.
/// "Harmless" from vendors that actually rated the URL counts as a clean vote;
/// "undetected" alone is no opinion.
pub(crate) fn virustotal_detection(vt: &VirusTotalUrl, duration_ms: u64) -> DetectionResult {
    let (malicious, suspicious, harmless, undetected, flagged_by, date, reference) = match vt {
        VirusTotalUrl::NotSeen => {
            return no_record(
                VIRUSTOTAL,
                "VirusTotal has no record of this URL",
                duration_ms,
            )
        }
        VirusTotalUrl::Error(e) => return unavailable(VIRUSTOTAL, e, duration_ms),
        VirusTotalUrl::Analysed {
            malicious,
            suspicious,
            harmless,
            undetected,
            flagged_by,
            last_analysis_date,
            reference,
        } => (
            *malicious,
            *suspicious,
            *harmless,
            *undetected,
            flagged_by,
            last_analysis_date,
            reference,
        ),
    };
    let (verdict, confidence, severity, authoritative) = match (malicious, suspicious) {
        (3.., _) => (ThreatVerdict::Malicious, 0.9, SeverityLevel::Critical, true),
        (2, _) => (ThreatVerdict::Malicious, 0.7, SeverityLevel::High, false),
        (1, _) | (0, 2..) => (ThreatVerdict::Suspicious, 0.5, SeverityLevel::Medium, false),
        _ if harmless > 0 => (ThreatVerdict::Benign, 0.5, SeverityLevel::Info, false),
        _ => {
            return no_record(
                VIRUSTOTAL,
                "No VirusTotal vendor has rated this URL",
                duration_ms,
            )
        }
    };
    let mut metadata = HashMap::from([
        ("malicious".to_string(), json!(malicious)),
        ("suspicious".to_string(), json!(suspicious)),
        ("harmless".to_string(), json!(harmless)),
        ("undetected".to_string(), json!(undetected)),
        (
            "flagged_by".to_string(),
            Value::Array(
                flagged_by
                    .iter()
                    .map(|(vendor, label)| json!({"vendor": vendor, "result": label}))
                    .collect(),
            ),
        ),
        ("reference".to_string(), json!(reference)),
    ]);
    if let Some(ts) = date {
        if let Some(d) = chrono::DateTime::from_timestamp(*ts, 0) {
            metadata.insert("last_analysed".to_string(), json!(d.to_rfc3339()));
        }
    }
    if authoritative {
        metadata.insert(AUTHORITATIVE_KEY.to_string(), Value::Bool(true));
    }
    detection(
        VIRUSTOTAL,
        verdict,
        confidence,
        severity,
        metadata,
        duration_ms,
    )
}

/// A Safe Browsing listing is a curated, current decision, so it decides the
/// verdict. Not being listed is no opinion.
pub(crate) fn safe_browsing_detection(gsb: &SafeBrowsing, duration_ms: u64) -> DetectionResult {
    match gsb {
        SafeBrowsing::NotListed => no_record(
            SAFE_BROWSING,
            "Not on Google Safe Browsing's lists",
            duration_ms,
        ),
        SafeBrowsing::Error(e) => unavailable(SAFE_BROWSING, e, duration_ms),
        SafeBrowsing::Listed(types) => {
            let phishing = types.iter().any(|t| t == "SOCIAL_ENGINEERING");
            let mut d = detection(
                SAFE_BROWSING,
                ThreatVerdict::Malicious,
                0.95,
                SeverityLevel::Critical,
                HashMap::from([
                    ("threat_types".to_string(), json!(types)),
                    (AUTHORITATIVE_KEY.to_string(), Value::Bool(true)),
                ]),
                duration_ms,
            );
            if phishing {
                d.categories = vec![ThreatCategory::Phishing];
            }
            d
        }
    }
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

/// Several medium warning signs together make an address suspicious, even
/// though no single one does.
const SUSPICIOUS_POINTS: usize = 3;

/// Medium findings, one point each. Login words ("verify", "account", …)
/// count for at most two between them: ordinary bank and shop pages use
/// them, so words alone never reach [`SUSPICIOUS_POINTS`].
fn warning_points(findings: &[&Finding]) -> usize {
    let medium = findings
        .iter()
        .filter(|f| matches!(f.severity, ThreatLevel::Medium));
    let words = medium
        .clone()
        .filter(|f| f.title.ends_with("SuspiciousKeywords"))
        .count();
    let other = medium
        .filter(|f| !f.title.ends_with("SuspiciousKeywords"))
        .count();
    words.min(2) + other
}

/// The "URL checks" vote from its own findings (feed findings excluded).
pub(crate) fn checks_verdict(findings: &[&Finding]) -> (ThreatVerdict, f32, SeverityLevel) {
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
    match worst {
        3 => (ThreatVerdict::Malicious, 0.8, SeverityLevel::Critical),
        2 => (ThreatVerdict::Suspicious, 0.6, SeverityLevel::High),
        _ if warning_points(findings) >= SUSPICIOUS_POINTS => {
            (ThreatVerdict::Suspicious, 0.5, SeverityLevel::Medium)
        }
        _ => (
            ThreatVerdict::Benign,
            0.6,
            if worst == 1 {
                SeverityLevel::Low
            } else {
                SeverityLevel::Info
            },
        ),
    }
}

fn url_checks_detection(scan: &UrlScanResult) -> DetectionResult {
    let findings: Vec<_> = scan
        .base
        .findings
        .iter()
        .filter(|f| !is_feed_finding(&f.title))
        .collect();

    let (verdict, confidence, severity) = checks_verdict(&findings);

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
    if let Some(age) = scan.reputation.as_ref().and_then(|r| r.domain_age.as_ref()) {
        metadata.insert(
            "domain_age".to_string(),
            json!({
                "registered_domain": age.domain,
                "registered": age.registered.format("%Y-%m-%d").to_string(),
                "age_days": age.age_days,
            }),
        );
    }
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

    fn vt(malicious: u32, suspicious: u32, harmless: u32) -> VirusTotalUrl {
        VirusTotalUrl::Analysed {
            malicious,
            suspicious,
            harmless,
            undetected: 10,
            flagged_by: vec![],
            last_analysis_date: Some(1_764_000_000),
            reference: "https://www.virustotal.com/gui/url/x".to_string(),
        }
    }

    #[test]
    fn virustotal_votes_by_how_many_vendors_flag_it() {
        let d = virustotal_detection(&vt(5, 0, 60), 1);
        assert_eq!(d.verdict, ThreatVerdict::Malicious);
        assert!(d.metadata.contains_key(AUTHORITATIVE_KEY));

        let d = virustotal_detection(&vt(2, 0, 60), 1);
        assert_eq!(d.verdict, ThreatVerdict::Malicious);
        assert!(!d.metadata.contains_key(AUTHORITATIVE_KEY));

        assert_eq!(
            virustotal_detection(&vt(1, 0, 60), 1).verdict,
            ThreatVerdict::Suspicious
        );
        assert_eq!(
            virustotal_detection(&vt(0, 0, 60), 1).verdict,
            ThreatVerdict::Benign
        );
        // Nobody rated it: no opinion, not "clean".
        assert!(virustotal_detection(&vt(0, 0, 0), 1).non_vote().is_some());
        assert!(virustotal_detection(&VirusTotalUrl::NotSeen, 1)
            .non_vote()
            .is_some());
        let err = virustotal_detection(&VirusTotalUrl::Error("rate limit".into()), 1);
        assert_eq!(
            err.error_message.as_deref(),
            Some("VirusTotal lookup failed: rate limit")
        );
    }

    #[test]
    fn safe_browsing_listing_decides_and_absence_is_no_opinion() {
        let d =
            safe_browsing_detection(&SafeBrowsing::Listed(vec!["SOCIAL_ENGINEERING".into()]), 1);
        assert_eq!(d.verdict, ThreatVerdict::Malicious);
        assert_eq!(d.categories, vec![ThreatCategory::Phishing]);
        assert!(d.metadata.contains_key(AUTHORITATIVE_KEY));

        let d = safe_browsing_detection(&SafeBrowsing::NotListed, 1);
        assert_eq!(d.verdict, ThreatVerdict::Unknown);
        assert!(d.non_vote().is_some());
    }
}
