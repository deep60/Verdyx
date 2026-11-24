//! Reputation lookups for a URL beyond abuse.ch:
//!
//! - **VirusTotal**: the last analysis of the URL by ~90 security vendors.
//!   Read-only lookup (`GET /urls/{id}`); the URL is never submitted for a new
//!   scan. Uses `VIRUSTOTAL_API_KEY`, the key file scans already use.
//! - **Google Safe Browsing**: Google's malware and phishing lists, the ones
//!   Chrome warns on. Uses `GOOGLE_SAFE_BROWSING_API_KEY`.
//! - **Domain age** from RDAP, the registries' public registration data. No
//!   key. A domain registered days ago is the strongest single phishing signal.
//!
//! Like the abuse.ch feeds, a lookup never fails a scan: an error is carried in
//! the outcome and that engine is reported as unavailable.

use std::time::Duration;

use base64::Engine as _;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tracing::warn;

const VT_API: &str = "https://www.virustotal.com/api/v3";
const GSB_API: &str = "https://safebrowsing.googleapis.com/v4/threatMatches:find";
const RDAP_API: &str = "https://rdap.org/domain";

/// What VirusTotal said about a URL.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum VirusTotalUrl {
    /// VirusTotal has never analysed this URL.
    NotSeen,
    Analysed {
        malicious: u32,
        suspicious: u32,
        harmless: u32,
        undetected: u32,
        /// Vendors that called it malicious or suspicious, with their label.
        flagged_by: Vec<(String, String)>,
        last_analysis_date: Option<i64>,
        reference: String,
    },
    Error(String),
}

/// What Google Safe Browsing said about a URL.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum SafeBrowsing {
    NotListed,
    /// Threat types, e.g. "SOCIAL_ENGINEERING", "MALWARE".
    Listed(Vec<String>),
    Error(String),
}

/// When the URL's domain was registered.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DomainAge {
    pub domain: String,
    pub registered: DateTime<Utc>,
    pub age_days: i64,
}

/// Everything these lookups said about one URL. A field is `None` when that
/// source is off (no key) or wasn't asked (private or trusted destination).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UrlReputationReport {
    pub virustotal: Option<VirusTotalUrl>,
    pub safe_browsing: Option<SafeBrowsing>,
    pub domain_age: Option<DomainAge>,
}

pub struct UrlReputationClient {
    http: reqwest::Client,
    vt_key: Option<String>,
    gsb_key: Option<String>,
    vt_api: String,
    gsb_api: String,
    rdap_api: String,
}

fn env_key(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|k| k.trim().to_string())
        .filter(|k| !k.is_empty())
}

impl UrlReputationClient {
    pub fn from_env() -> anyhow::Result<Self> {
        Self::with_endpoints(
            env_key("VIRUSTOTAL_API_KEY"),
            env_key("GOOGLE_SAFE_BROWSING_API_KEY"),
            VT_API,
            GSB_API,
            RDAP_API,
        )
    }

    pub fn with_endpoints(
        vt_key: Option<String>,
        gsb_key: Option<String>,
        vt_api: &str,
        gsb_api: &str,
        rdap_api: &str,
    ) -> anyhow::Result<Self> {
        // rdap.org answers with a redirect to the domain's registry.
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(8))
            .redirect(reqwest::redirect::Policy::limited(3))
            .user_agent("verdyx-analysis-engine")
            .build()?;
        Ok(Self {
            http,
            vt_key,
            gsb_key,
            vt_api: vt_api.trim_end_matches('/').to_string(),
            gsb_api: gsb_api.to_string(),
            rdap_api: rdap_api.trim_end_matches('/').to_string(),
        })
    }

    pub fn virustotal_enabled(&self) -> bool {
        self.vt_key.is_some()
    }

    pub fn safe_browsing_enabled(&self) -> bool {
        self.gsb_key.is_some()
    }

    /// Run every enabled lookup concurrently. `check_age` is false for hosts
    /// whose age says nothing (IP addresses, well-known sites).
    pub async fn check(&self, url: &url::Url, check_age: bool) -> UrlReputationReport {
        let vt = async {
            match &self.vt_key {
                Some(key) => Some(self.virustotal(url, key).await),
                None => None,
            }
        };
        let gsb = async {
            match &self.gsb_key {
                Some(key) => Some(self.safe_browsing(url, key).await),
                None => None,
            }
        };
        let age = async {
            match url.host_str() {
                Some(host) if check_age => self.domain_age(host).await,
                _ => None,
            }
        };
        let (virustotal, safe_browsing, domain_age) = tokio::join!(vt, gsb, age);
        UrlReputationReport {
            virustotal,
            safe_browsing,
            domain_age,
        }
    }

    async fn virustotal(&self, url: &url::Url, key: &str) -> VirusTotalUrl {
        let id = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(url.as_str());
        let res = self
            .http
            .get(format!("{}/urls/{id}", self.vt_api))
            .header("x-apikey", key)
            .send()
            .await;
        let res = match res {
            Ok(r) => r,
            Err(e) => return VirusTotalUrl::Error(format!("request failed: {e}")),
        };
        match res.status().as_u16() {
            200 => match res.json::<Value>().await {
                Ok(body) => parse_virustotal_url(&body, url.as_str()),
                Err(e) => VirusTotalUrl::Error(format!("unreadable response: {e}")),
            },
            404 => VirusTotalUrl::NotSeen,
            429 => VirusTotalUrl::Error("rate limit reached (free key: 4 lookups a minute)".into()),
            401 | 403 => VirusTotalUrl::Error("the API key was rejected".into()),
            s => VirusTotalUrl::Error(format!("HTTP {s}")),
        }
    }

    async fn safe_browsing(&self, url: &url::Url, key: &str) -> SafeBrowsing {
        let body = json!({
            "client": { "clientId": "verdyx", "clientVersion": env!("CARGO_PKG_VERSION") },
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE",
                                "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{ "url": url.as_str() }],
            }
        });
        let res = self
            .http
            .post(&self.gsb_api)
            .query(&[("key", key)])
            .json(&body)
            .send()
            .await;
        let res = match res {
            Ok(r) => r,
            Err(e) => return SafeBrowsing::Error(format!("request failed: {e}")),
        };
        match res.status().as_u16() {
            200 => match res.json::<Value>().await {
                Ok(body) => parse_safe_browsing(&body),
                Err(e) => SafeBrowsing::Error(format!("unreadable response: {e}")),
            },
            400 | 403 => SafeBrowsing::Error("the API key was rejected".into()),
            s => SafeBrowsing::Error(format!("HTTP {s}")),
        }
    }

    /// Registration date of the registrable domain. Tries the last two labels
    /// first ("example.com"), then three ("example.co.uk"), since a registry
    /// only knows registered names.
    async fn domain_age(&self, host: &str) -> Option<DomainAge> {
        for domain in registrable_candidates(host) {
            let res = self
                .http
                .get(format!("{}/{domain}", self.rdap_api))
                .header("Accept", "application/rdap+json")
                .send()
                .await;
            match res {
                Ok(r) if r.status().is_success() => {
                    let body: Value = r.json().await.ok()?;
                    let registered = registration_date(&body)?;
                    return Some(DomainAge {
                        age_days: (Utc::now() - registered).num_days().max(0),
                        domain,
                        registered,
                    });
                }
                Ok(r) if r.status().as_u16() == 404 => continue,
                Ok(r) => {
                    warn!("RDAP lookup for {domain}: HTTP {}", r.status());
                    return None;
                }
                Err(e) => {
                    warn!("RDAP lookup for {domain} failed: {e}");
                    return None;
                }
            }
        }
        None
    }
}

/// The VirusTotal web page for a URL (its ID there is the URL's SHA-256).
pub fn virustotal_reference(url: &str) -> String {
    format!(
        "https://www.virustotal.com/gui/url/{}",
        hex::encode(Sha256::digest(url.as_bytes()))
    )
}

pub fn parse_virustotal_url(body: &Value, url: &str) -> VirusTotalUrl {
    let attrs = &body["data"]["attributes"];
    let stats = &attrs["last_analysis_stats"];
    let count = |k: &str| stats[k].as_u64().unwrap_or(0) as u32;
    let mut flagged_by: Vec<(String, String)> = attrs["last_analysis_results"]
        .as_object()
        .map(|results| {
            results
                .iter()
                .filter(|(_, r)| matches!(r["category"].as_str(), Some("malicious" | "suspicious")))
                .map(|(vendor, r)| {
                    (
                        vendor.clone(),
                        r["result"].as_str().unwrap_or("flagged").to_string(),
                    )
                })
                .collect()
        })
        .unwrap_or_default();
    flagged_by.sort();
    VirusTotalUrl::Analysed {
        malicious: count("malicious"),
        suspicious: count("suspicious"),
        harmless: count("harmless"),
        undetected: count("undetected"),
        flagged_by,
        last_analysis_date: attrs["last_analysis_date"].as_i64(),
        reference: virustotal_reference(url),
    }
}

pub fn parse_safe_browsing(body: &Value) -> SafeBrowsing {
    let mut types: Vec<String> = body["matches"]
        .as_array()
        .map(|m| {
            m.iter()
                .filter_map(|x| x["threatType"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    types.sort();
    types.dedup();
    if types.is_empty() {
        SafeBrowsing::NotListed
    } else {
        SafeBrowsing::Listed(types)
    }
}

pub fn registration_date(body: &Value) -> Option<DateTime<Utc>> {
    body["events"].as_array()?.iter().find_map(|e| {
        if e["eventAction"].as_str()? == "registration" {
            DateTime::parse_from_rfc3339(e["eventDate"].as_str()?)
                .ok()
                .map(|d| d.with_timezone(&Utc))
        } else {
            None
        }
    })
}

/// "login.example.co.uk" → ["co.uk", "example.co.uk"]: the last two labels,
/// then the last three. IP addresses and single labels give nothing.
pub fn registrable_candidates(host: &str) -> Vec<String> {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host.parse::<std::net::IpAddr>().is_ok() || host.starts_with('[') {
        return vec![];
    }
    let labels: Vec<&str> = host.split('.').collect();
    let mut out = Vec::new();
    for n in [2, 3] {
        if labels.len() >= n {
            out.push(labels[labels.len() - n..].join("."));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn virustotal_url_report_is_read() {
        let body = json!({"data": {"attributes": {
            "last_analysis_date": 1764000000,
            "last_analysis_stats": {"malicious": 7, "suspicious": 1, "harmless": 60,
                                    "undetected": 25, "timeout": 0},
            "last_analysis_results": {
                "Fortinet": {"category": "malicious", "result": "phishing"},
                "Kaspersky": {"category": "suspicious", "result": "suspicious"},
                "Google": {"category": "harmless", "result": "clean"}
            }
        }}});
        let VirusTotalUrl::Analysed {
            malicious,
            flagged_by,
            reference,
            ..
        } = parse_virustotal_url(&body, "http://bad.example/")
        else {
            panic!("not analysed");
        };
        assert_eq!(malicious, 7);
        assert_eq!(
            flagged_by,
            vec![
                ("Fortinet".into(), "phishing".into()),
                ("Kaspersky".into(), "suspicious".into())
            ]
        );
        assert!(reference.starts_with("https://www.virustotal.com/gui/url/"));
        assert_eq!(
            reference.len(),
            "https://www.virustotal.com/gui/url/".len() + 64
        );
    }

    #[test]
    fn safe_browsing_matches_are_read() {
        assert_eq!(parse_safe_browsing(&json!({})), SafeBrowsing::NotListed);
        let body = json!({"matches": [
            {"threatType": "SOCIAL_ENGINEERING"}, {"threatType": "MALWARE"},
            {"threatType": "MALWARE"}
        ]});
        assert_eq!(
            parse_safe_browsing(&body),
            SafeBrowsing::Listed(vec!["MALWARE".into(), "SOCIAL_ENGINEERING".into()])
        );
    }

    #[test]
    fn rdap_registration_date_is_found() {
        let body = json!({"events": [
            {"eventAction": "expiration", "eventDate": "2027-01-01T00:00:00Z"},
            {"eventAction": "registration", "eventDate": "2026-11-20T08:15:00Z"}
        ]});
        assert_eq!(
            registration_date(&body).unwrap().to_rfc3339(),
            "2026-11-20T08:15:00+00:00"
        );
        assert!(registration_date(&json!({"events": []})).is_none());
    }

    #[test]
    fn registrable_domain_candidates() {
        assert_eq!(
            registrable_candidates("admin.kibisports.com"),
            vec!["kibisports.com", "admin.kibisports.com"]
        );
        assert_eq!(
            registrable_candidates("login.example.co.uk"),
            vec!["co.uk", "example.co.uk"]
        );
        assert!(registrable_candidates("10.0.0.1").is_empty());
        assert!(registrable_candidates("localhost").is_empty());
    }

    /// A local stand-in for all three services, to check the requests and
    /// the full path through `check`.
    #[tokio::test]
    async fn check_runs_every_enabled_lookup() {
        use axum::{routing::get, routing::post, Json, Router};

        let app = Router::new()
            .route(
                "/vt/urls/{id}",
                get(|| async {
                    Json(json!({"data": {"attributes": {
                        "last_analysis_stats": {"malicious": 4, "harmless": 50}}}}))
                }),
            )
            .route(
                "/gsb",
                post(|| async { Json(json!({"matches": [{"threatType": "SOCIAL_ENGINEERING"}]})) }),
            )
            .route(
                "/rdap/{domain}",
                get(
                    |axum::extract::Path(d): axum::extract::Path<String>| async move {
                        if d == "example.com" {
                            Json(json!({"events": [{"eventAction": "registration",
                            "eventDate": "2001-01-01T00:00:00Z"}]}))
                        } else {
                            Json(json!({}))
                        }
                    },
                ),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let client = UrlReputationClient::with_endpoints(
            Some("vt".into()),
            Some("gsb".into()),
            &format!("{base}/vt"),
            &format!("{base}/gsb"),
            &format!("{base}/rdap"),
        )
        .unwrap();
        let url = url::Url::parse("https://login.example.com/verify").unwrap();
        let report = client.check(&url, true).await;

        assert!(matches!(
            report.virustotal,
            Some(VirusTotalUrl::Analysed { malicious: 4, .. })
        ));
        assert_eq!(
            report.safe_browsing,
            Some(SafeBrowsing::Listed(vec!["SOCIAL_ENGINEERING".into()]))
        );
        let age = report.domain_age.unwrap();
        assert_eq!(age.domain, "example.com");
        assert!(age.age_days > 9000);

        let off = UrlReputationClient::with_endpoints(None, None, "x", "x", "x").unwrap();
        let none = off.check(&url, false).await;
        assert!(
            none.virustotal.is_none() && none.safe_browsing.is_none() && none.domain_age.is_none()
        );
    }
}
