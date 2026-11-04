//! abuse.ch threat intelligence lookups: URLhaus (malware URLs and the hosts
//! serving them) and ThreatFox (IOCs: C2 domains, payload URLs, ip:port).
//!
//! Both APIs need a free Auth-Key from https://auth.abuse.ch/, read from
//! `ABUSE_CH_API_KEY` (the same key MalwareBazaar uses). Without a key the
//! client is not built and URL scans simply skip these sources.
//!
//! Lookups never fail a scan: an unreachable feed is reported in
//! `ThreatIntelReport::errors` and the scan carries on with the other checks.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::Mutex;
use tracing::warn;

const URLHAUS_API: &str = "https://urlhaus-api.abuse.ch/v1";
const THREATFOX_API: &str = "https://threatfox-api.abuse.ch/api/v1/";
const CACHE_TTL: Duration = Duration::from_secs(30 * 60);
const CACHE_MAX_ENTRIES: usize = 10_000;

/// One positive answer from a feed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ThreatIntelMatch {
    /// "URLhaus" or "ThreatFox".
    pub source: String,
    /// What matched: "url", "host", "domain", "ip:port".
    pub match_type: String,
    pub indicator: String,
    /// e.g. "malware_download", "botnet_cc", "payload_delivery".
    pub threat: Option<String>,
    /// Malware family when the feed names one, e.g. "Cobalt Strike".
    pub malware: Option<String>,
    /// URLhaus: "online" / "offline" for a URL, or online URL count for a host.
    pub status: Option<String>,
    /// ThreatFox confidence level (0-100).
    pub confidence: Option<u8>,
    pub tags: Vec<String>,
    pub reference: Option<String>,
}

/// Everything the feeds said about one URL.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ThreatIntelReport {
    pub sources_checked: Vec<String>,
    pub matches: Vec<ThreatIntelMatch>,
    pub errors: Vec<String>,
}

pub struct AbuseChClient {
    http: reqwest::Client,
    api_key: String,
    urlhaus_api: String,
    threatfox_api: String,
    cache: Mutex<HashMap<String, (Instant, Vec<ThreatIntelMatch>)>>,
}

impl AbuseChClient {
    /// Built only when `ABUSE_CH_API_KEY` is set and non-empty.
    pub fn from_env() -> Option<Self> {
        let key = std::env::var("ABUSE_CH_API_KEY").ok()?;
        let key = key.trim();
        if key.is_empty() {
            return None;
        }
        Self::with_endpoints(key, URLHAUS_API, THREATFOX_API).ok()
    }

    pub fn with_endpoints(
        api_key: &str,
        urlhaus_api: &str,
        threatfox_api: &str,
    ) -> anyhow::Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .user_agent("verdyx-analysis-engine")
            .build()?;
        Ok(Self {
            http,
            api_key: api_key.to_string(),
            urlhaus_api: urlhaus_api.trim_end_matches('/').to_string(),
            threatfox_api: threatfox_api.to_string(),
            cache: Mutex::new(HashMap::new()),
        })
    }

    /// Look a URL up in URLhaus (exact URL and its host) and ThreatFox (the
    /// URL, its host, and `ip:port` for IP-based URLs). Lookups run
    /// concurrently.
    pub async fn check_url(&self, url: &url::Url) -> ThreatIntelReport {
        let full = url.as_str().to_string();
        let host = url.host_str().unwrap_or_default().to_string();
        let ip_port = match (url.host(), url.port_or_known_default()) {
            (Some(url::Host::Ipv4(_)) | Some(url::Host::Ipv6(_)), Some(port)) => {
                Some(format!("{host}:{port}"))
            }
            _ => None,
        };

        let mut threatfox_terms = vec![full.clone()];
        if !host.is_empty() {
            threatfox_terms.push(host.clone());
        }
        threatfox_terms.extend(ip_port);

        let urlhaus_url = self.cached("urlhaus-url", &full, self.urlhaus_url(&full));
        let urlhaus_host = async {
            if host.is_empty() {
                Ok(Vec::new())
            } else {
                self.cached("urlhaus-host", &host, self.urlhaus_host(&host))
                    .await
            }
        };
        let threatfox = futures::future::join_all(
            threatfox_terms
                .iter()
                .map(|term| self.cached("threatfox", term, self.threatfox_ioc(term))),
        );
        let (url_res, host_res, tf_res) = tokio::join!(urlhaus_url, urlhaus_host, threatfox);

        let mut report = ThreatIntelReport {
            sources_checked: vec!["URLhaus".to_string(), "ThreatFox".to_string()],
            ..Default::default()
        };
        let mut add = |source: &str, res: anyhow::Result<Vec<ThreatIntelMatch>>| match res {
            Ok(found) => {
                for m in found {
                    if !report.matches.contains(&m) {
                        report.matches.push(m);
                    }
                }
            }
            Err(e) => {
                warn!("{source} lookup failed: {e}");
                let msg = format!("{source} lookup failed: {e}");
                if !report.errors.contains(&msg) {
                    report.errors.push(msg);
                }
            }
        };
        add("URLhaus", url_res);
        add("URLhaus", host_res);
        for res in tf_res {
            add("ThreatFox", res);
        }
        report
    }

    async fn cached(
        &self,
        kind: &str,
        term: &str,
        lookup: impl std::future::Future<Output = anyhow::Result<Vec<ThreatIntelMatch>>>,
    ) -> anyhow::Result<Vec<ThreatIntelMatch>> {
        let key = format!("{kind}:{term}");
        if let Some((at, hit)) = self.cache.lock().await.get(&key) {
            if at.elapsed() < CACHE_TTL {
                return Ok(hit.clone());
            }
        }
        // Errors are not cached, so a feed outage doesn't stick.
        let found = lookup.await?;
        let mut cache = self.cache.lock().await;
        if cache.len() >= CACHE_MAX_ENTRIES {
            cache.retain(|_, (at, _)| at.elapsed() < CACHE_TTL);
            if cache.len() >= CACHE_MAX_ENTRIES {
                cache.clear();
            }
        }
        cache.insert(key, (Instant::now(), found.clone()));
        Ok(found)
    }

    async fn urlhaus_url(&self, url: &str) -> anyhow::Result<Vec<ThreatIntelMatch>> {
        let json = self
            .post_form(&format!("{}/url/", self.urlhaus_api), &[("url", url)])
            .await?;
        Ok(parse_urlhaus_url(&json))
    }

    async fn urlhaus_host(&self, host: &str) -> anyhow::Result<Vec<ThreatIntelMatch>> {
        let json = self
            .post_form(&format!("{}/host/", self.urlhaus_api), &[("host", host)])
            .await?;
        Ok(parse_urlhaus_host(&json))
    }

    async fn threatfox_ioc(&self, term: &str) -> anyhow::Result<Vec<ThreatIntelMatch>> {
        let body = serde_json::json!({
            "query": "search_ioc",
            "search_term": term,
            "exact_match": true,
        });
        let resp = self
            .http
            .post(&self.threatfox_api)
            .header("Auth-Key", &self.api_key)
            .json(&body)
            .send()
            .await?;
        let json = Self::json_or_error(resp).await?;
        Ok(parse_threatfox(&json, term))
    }

    async fn post_form(&self, url: &str, form: &[(&str, &str)]) -> anyhow::Result<Value> {
        let resp = self
            .http
            .post(url)
            .header("Auth-Key", &self.api_key)
            .form(form)
            .send()
            .await?;
        Self::json_or_error(resp).await
    }

    async fn json_or_error(resp: reqwest::Response) -> anyhow::Result<Value> {
        let status = resp.status();
        if !status.is_success() {
            anyhow::bail!("HTTP {status}");
        }
        let json: Value = resp.json().await?;
        // "no_results" / "no_result" are normal misses; anything else that
        // isn't "ok" (bad key, bad request) is an error worth surfacing.
        match json["query_status"].as_str() {
            Some("ok") | Some("no_results") | Some("no_result") => Ok(json),
            Some(other) => anyhow::bail!("query_status {other}"),
            None => anyhow::bail!("unexpected response"),
        }
    }
}

fn str_field(v: &Value, key: &str) -> Option<String> {
    v[key]
        .as_str()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

fn tags(v: &Value) -> Vec<String> {
    v["tags"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|t| t.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

fn parse_urlhaus_url(json: &Value) -> Vec<ThreatIntelMatch> {
    if json["query_status"] != "ok" {
        return Vec::new();
    }
    vec![ThreatIntelMatch {
        source: "URLhaus".to_string(),
        match_type: "url".to_string(),
        indicator: str_field(json, "url").unwrap_or_default(),
        threat: str_field(json, "threat"),
        malware: None,
        status: str_field(json, "url_status"),
        confidence: None,
        tags: tags(json),
        reference: str_field(json, "urlhaus_reference"),
    }]
}

/// A host match only counts while the host is still serving malware: big
/// shared hosts (code hosting, file sharing) accumulate old, removed URLs.
fn parse_urlhaus_host(json: &Value) -> Vec<ThreatIntelMatch> {
    if json["query_status"] != "ok" {
        return Vec::new();
    }
    let urls = json["urls"].as_array().cloned().unwrap_or_default();
    let online: Vec<&Value> = urls
        .iter()
        .filter(|u| u["url_status"] == "online")
        .collect();
    if online.is_empty() {
        return Vec::new();
    }
    let mut tag_list: Vec<String> = Vec::new();
    for u in &online {
        for t in tags(u) {
            if !tag_list.contains(&t) {
                tag_list.push(t);
            }
        }
    }
    vec![ThreatIntelMatch {
        source: "URLhaus".to_string(),
        match_type: "host".to_string(),
        indicator: str_field(json, "host").unwrap_or_default(),
        threat: online.first().and_then(|u| str_field(u, "threat")),
        malware: None,
        status: Some(format!("{} online malware URL(s)", online.len())),
        confidence: None,
        tags: tag_list,
        reference: str_field(json, "urlhaus_reference"),
    }]
}

fn parse_threatfox(json: &Value, term: &str) -> Vec<ThreatIntelMatch> {
    if json["query_status"] != "ok" {
        return Vec::new();
    }
    json["data"]
        .as_array()
        .map(|items| {
            items
                .iter()
                // Belt and braces on top of exact_match.
                .filter(|i| {
                    i["ioc"]
                        .as_str()
                        .is_some_and(|ioc| ioc.eq_ignore_ascii_case(term))
                })
                .map(|i| ThreatIntelMatch {
                    source: "ThreatFox".to_string(),
                    match_type: str_field(i, "ioc_type").unwrap_or_else(|| "ioc".to_string()),
                    indicator: str_field(i, "ioc").unwrap_or_default(),
                    threat: str_field(i, "threat_type"),
                    malware: str_field(i, "malware_printable"),
                    status: None,
                    confidence: i["confidence_level"].as_u64().map(|c| c.min(100) as u8),
                    tags: tags(i),
                    reference: i["id"]
                        .as_str()
                        .map(|id| format!("https://threatfox.abuse.ch/ioc/{id}/")),
                })
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{routing::post, Json, Router};
    use serde_json::json;

    #[test]
    fn urlhaus_url_hit_and_miss() {
        let hit = json!({
            "query_status": "ok",
            "url": "http://bad.example/payload.exe",
            "url_status": "online",
            "threat": "malware_download",
            "tags": ["exe", "AgentTesla"],
            "urlhaus_reference": "https://urlhaus.abuse.ch/url/1/"
        });
        let m = parse_urlhaus_url(&hit);
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].status.as_deref(), Some("online"));
        assert_eq!(m[0].tags, vec!["exe", "AgentTesla"]);

        assert!(parse_urlhaus_url(&json!({"query_status": "no_results"})).is_empty());
    }

    #[test]
    fn urlhaus_host_needs_an_online_url() {
        let offline_only = json!({
            "query_status": "ok",
            "host": "files.example",
            "urls": [{"url_status": "offline", "threat": "malware_download"}]
        });
        assert!(parse_urlhaus_host(&offline_only).is_empty());

        let online = json!({
            "query_status": "ok",
            "host": "files.example",
            "urls": [
                {"url_status": "offline"},
                {"url_status": "online", "threat": "malware_download", "tags": ["Mozi"]}
            ]
        });
        let m = parse_urlhaus_host(&online);
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].status.as_deref(), Some("1 online malware URL(s)"));
        assert_eq!(m[0].tags, vec!["Mozi"]);
    }

    #[test]
    fn threatfox_keeps_exact_matches_only() {
        let resp = json!({
            "query_status": "ok",
            "data": [
                {"id": "7", "ioc": "c2.example", "ioc_type": "domain", "threat_type": "botnet_cc",
                 "malware_printable": "Cobalt Strike", "confidence_level": 100, "tags": null},
                {"id": "8", "ioc": "other.c2.example", "ioc_type": "domain"}
            ]
        });
        let m = parse_threatfox(&resp, "c2.example");
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].malware.as_deref(), Some("Cobalt Strike"));
        assert_eq!(m[0].confidence, Some(100));
        assert_eq!(
            m[0].reference.as_deref(),
            Some("https://threatfox.abuse.ch/ioc/7/")
        );
    }

    async fn serve(router: Router) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn check_url_combines_feeds_and_sends_the_key() {
        let router = Router::new()
            .route(
                "/urlhaus/url/",
                post(|headers: axum::http::HeaderMap| async move {
                    assert_eq!(headers["auth-key"], "test-key");
                    Json(json!({
                        "query_status": "ok",
                        "url": "http://c2.example/x.exe",
                        "url_status": "online",
                        "threat": "malware_download"
                    }))
                }),
            )
            .route(
                "/urlhaus/host/",
                post(|| async { Json(json!({"query_status": "no_results"})) }),
            )
            .route(
                "/threatfox",
                post(|Json(body): Json<Value>| async move {
                    if body["search_term"] == "c2.example" {
                        Json(json!({"query_status": "ok", "data": [{
                            "id": "1", "ioc": "c2.example", "ioc_type": "domain",
                            "threat_type": "botnet_cc", "malware_printable": "Remcos",
                            "confidence_level": 75
                        }]}))
                    } else {
                        Json(json!({"query_status": "no_result"}))
                    }
                }),
            );
        let base = serve(router).await;
        let client = AbuseChClient::with_endpoints(
            "test-key",
            &format!("{base}/urlhaus"),
            &format!("{base}/threatfox"),
        )
        .unwrap();

        let url = url::Url::parse("http://c2.example/x.exe").unwrap();
        let report = client.check_url(&url).await;
        assert!(report.errors.is_empty(), "{:?}", report.errors);
        assert_eq!(report.matches.len(), 2);
        assert!(report
            .matches
            .iter()
            .any(|m| m.source == "URLhaus" && m.match_type == "url"));
        assert!(report
            .matches
            .iter()
            .any(|m| m.source == "ThreatFox" && m.malware.as_deref() == Some("Remcos")));
    }

    #[tokio::test]
    async fn feed_errors_are_reported_not_fatal() {
        let router = Router::new()
            .route(
                "/urlhaus/url/",
                post(|| async { Json(json!({"query_status": "unknown_auth_key"})) }),
            )
            .route(
                "/urlhaus/host/",
                post(|| async { Json(json!({"query_status": "unknown_auth_key"})) }),
            )
            .route(
                "/threatfox",
                post(|| async { (axum::http::StatusCode::SERVICE_UNAVAILABLE, "down") }),
            );
        let base = serve(router).await;
        let client = AbuseChClient::with_endpoints(
            "bad",
            &format!("{base}/urlhaus"),
            &format!("{base}/threatfox"),
        )
        .unwrap();

        let report = client
            .check_url(&url::Url::parse("https://example.org/").unwrap())
            .await;
        assert!(report.matches.is_empty());
        assert!(report.errors.iter().any(|e| e.contains("unknown_auth_key")));
        assert!(report.errors.iter().any(|e| e.contains("503")));
    }
}
