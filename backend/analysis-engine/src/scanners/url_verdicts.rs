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
    STRONG_SIGNAL_KEY,
};

pub const URLHAUS: &str = "URLhaus";
pub const THREATFOX: &str = "ThreatFox";
pub const URL_CHECKS: &str = "URL checks";
pub const VIRUSTOTAL: &str = "VirusTotal";
pub const SAFE_BROWSING: &str = "Google Safe Browsing";
/// Engine name for the verdict on the links in an email.
pub const EMAIL_LINKS: &str = "Email links";
/// Links in one email that are looked up.
pub const EMAIL_LINKS_CHECKED: usize = 5;

/// Which of an email's links to look up: hosts not on the trusted list come
/// first (a link to a well-known site is rarely the payload), one link per
/// host, at most `max`.
pub fn pick_email_links(
    links: &[String],
    is_trusted: impl Fn(&str) -> bool,
    max: usize,
) -> Vec<String> {
    let mut seen_hosts: Vec<String> = Vec::new();
    let mut unknown = Vec::new();
    let mut trusted = Vec::new();
    for link in links {
        let Some(host) = url::Url::parse(link)
            .ok()
            .and_then(|u| u.host_str().map(|h| h.to_ascii_lowercase()))
        else {
            continue;
        };
        if seen_hosts.contains(&host) {
            continue;
        }
        if is_trusted(&host) {
            trusted.push(link.clone());
        } else {
            unknown.push(link.clone());
        }
        seen_hosts.push(host);
    }
    unknown.into_iter().chain(trusted).take(max).collect()
}

/// One vote for an email from the URL engines' verdicts on its links: the
/// worst of them. A link that's on a blocklist is a strong signal (the email
/// is at least suspicious) but doesn't decide the verdict alone, since an
/// email can quote a bad link to warn about it. When nothing flags a link the
/// row has no opinion: a link missing from blocklists isn't proof it's safe.
pub fn email_links_detection(
    found: usize,
    checked: &[(String, Vec<DetectionResult>)],
    duration_ms: u64,
) -> DetectionResult {
    let rank = |v: &ThreatVerdict| match v {
        ThreatVerdict::Malicious => 2,
        ThreatVerdict::Suspicious => 1,
        _ => 0,
    };
    let mut worst = ThreatVerdict::Unknown;
    let mut listed = false;
    let mut confidence = 0.0_f32;
    let mut reasons = Vec::new();
    let mut links = Vec::new();
    for (url, votes) in checked {
        let flagged: Vec<&DetectionResult> = votes
            .iter()
            .filter(|d| d.non_vote().is_none() && rank(&d.verdict) > 0)
            .collect();
        let link_worst = flagged
            .iter()
            .map(|d| d.verdict.clone())
            .max_by_key(rank)
            .unwrap_or(ThreatVerdict::Unknown);
        if rank(&link_worst) > rank(&worst) {
            worst = link_worst.clone();
        }
        for d in &flagged {
            if d.verdict == worst {
                confidence = confidence.max(d.confidence);
            }
            if d.metadata.get(AUTHORITATIVE_KEY).and_then(Value::as_bool) == Some(true) {
                listed = true;
            }
        }
        let engines: Vec<&str> = flagged.iter().map(|d| d.engine_name.as_str()).collect();
        if !engines.is_empty() {
            reasons.push(format!("{url}: {:?} ({})", link_worst, engines.join(", ")));
        }
        links.push(json!({
            "url": url,
            "verdict": format!("{link_worst:?}"),
            "engines": engines,
        }));
    }

    let not_checked = found.saturating_sub(checked.len());
    let more = if not_checked > 0 {
        format!(" {not_checked} more link(s) weren't looked up.")
    } else {
        String::new()
    };
    let summary = if reasons.is_empty() {
        format!(
            "{} link(s) in this email were looked up in URLhaus, ThreatFox and Verdyx's URL checks; none was flagged.{more}",
            checked.len()
        )
    } else {
        format!(
            "{} of {} link(s) in this email were flagged: {}.{more}",
            reasons.len(),
            checked.len(),
            reasons.join("; ")
        )
    };

    let mut metadata = HashMap::new();
    metadata.insert("links".to_string(), json!(links));
    metadata.insert("linksFound".to_string(), json!(found));
    metadata.insert("summary".to_string(), json!(summary));
    metadata.insert("reasons".to_string(), json!(reasons));
    if worst == ThreatVerdict::Unknown {
        metadata.insert("reason".to_string(), json!(summary));
    }
    if listed && worst == ThreatVerdict::Malicious {
        metadata.insert(STRONG_SIGNAL_KEY.to_string(), json!(true));
    }
    let (severity, categories) = match worst {
        ThreatVerdict::Malicious => (SeverityLevel::High, vec![ThreatCategory::Phishing]),
        ThreatVerdict::Suspicious => (SeverityLevel::Medium, vec![ThreatCategory::Phishing]),
        _ => (SeverityLevel::Info, vec![]),
    };
    DetectionResult {
        detection_id: Uuid::new_v4(),
        engine_name: EMAIL_LINKS.to_string(),
        engine_version: "live".to_string(),
        engine_type: EngineType::ThreatIntel,
        verdict: worst,
        confidence,
        severity,
        categories,
        metadata,
        detected_at: Utc::now(),
        processing_time_ms: duration_ms,
        error_message: None,
    }
}

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
            let own_ms = if source == URLHAUS {
                intel.urlhaus_ms
            } else {
                intel.threatfox_ms
            };
            out.push(feed_detection(
                source,
                &matches,
                &errors,
                host_is_trusted,
                own_ms.unwrap_or(scan.base.scan_duration_ms),
            ));
        }
    }
    if let Some(rep) = &scan.reputation {
        // Each lookup reports its own time. Results stored before lookups
        // were timed fall back to the whole scan's.
        let whole = scan.base.scan_duration_ms;
        if let Some(vt) = &rep.virustotal {
            out.push(virustotal_detection(vt, rep.virustotal_ms.unwrap_or(whole)));
        }
        if let Some(gsb) = &rep.safe_browsing {
            out.push(safe_browsing_detection(
                gsb,
                rep.safe_browsing_ms.unwrap_or(whole),
            ));
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
            EngineType::ThreatIntel
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

    fn vote(name: &str, verdict: ThreatVerdict, listed: bool) -> DetectionResult {
        let mut metadata = HashMap::new();
        if listed {
            metadata.insert(AUTHORITATIVE_KEY.to_string(), json!(true));
        }
        if verdict == ThreatVerdict::Unknown {
            metadata.insert("reason".to_string(), json!("Not listed"));
        }
        detection(name, verdict, 0.9, SeverityLevel::High, metadata, 1)
    }

    #[test]
    fn unknown_hosts_are_looked_up_first_one_link_per_host() {
        let links: Vec<String> = [
            "https://www.google.com/a",
            "https://evil.example/login",
            "https://evil.example/other",
            "https://cdn.example.net/x.js",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let picked = pick_email_links(&links, |h| h.ends_with("google.com"), 5);
        assert_eq!(
            picked,
            [
                "https://evil.example/login",
                "https://cdn.example.net/x.js",
                "https://www.google.com/a"
            ]
        );
        assert_eq!(pick_email_links(&links, |_| false, 1).len(), 1);
    }

    #[test]
    fn a_listed_link_flags_the_email_without_deciding_it_alone() {
        let checked = vec![
            (
                "https://evil.example/login".to_string(),
                vec![
                    vote(URLHAUS, ThreatVerdict::Malicious, true),
                    vote(URL_CHECKS, ThreatVerdict::Suspicious, false),
                ],
            ),
            (
                "https://ok.example/".to_string(),
                vec![vote(URLHAUS, ThreatVerdict::Unknown, false)],
            ),
        ];
        let d = email_links_detection(7, &checked, 3);
        assert_eq!(d.engine_name, EMAIL_LINKS);
        assert_eq!(d.verdict, ThreatVerdict::Malicious);
        assert_eq!(d.metadata[STRONG_SIGNAL_KEY], true);
        assert!(!d.metadata.contains_key(AUTHORITATIVE_KEY));
        let summary = d.metadata["summary"].as_str().unwrap();
        assert!(summary.starts_with("1 of 2 link(s)"), "{summary}");
        assert!(summary.contains("evil.example/login: Malicious (URLhaus, URL checks)"));
        assert!(summary.ends_with("5 more link(s) weren't looked up."));
        assert_eq!(d.metadata["links"][1]["verdict"], "Unknown");
    }

    #[test]
    fn links_nobody_flags_are_no_opinion_not_clean() {
        let checked = vec![(
            "https://ok.example/".to_string(),
            vec![vote(URLHAUS, ThreatVerdict::Unknown, false)],
        )];
        let d = email_links_detection(1, &checked, 3);
        assert_eq!(d.verdict, ThreatVerdict::Unknown);
        assert!(d.non_vote().is_some());
        assert!(d.metadata["reason"]
            .as_str()
            .unwrap()
            .contains("none was flagged"));
    }

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

    #[test]
    fn feeds_are_labelled_threat_intel_and_own_checks_static() {
        let feed = detection(
            URLHAUS,
            ThreatVerdict::Unknown,
            0.0,
            SeverityLevel::Info,
            HashMap::new(),
            1,
        );
        assert_eq!(feed.engine_type, EngineType::ThreatIntel);
        let own = detection(
            URL_CHECKS,
            ThreatVerdict::Benign,
            0.6,
            SeverityLevel::Info,
            HashMap::new(),
            1,
        );
        assert_eq!(own.engine_type, EngineType::Static);
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
