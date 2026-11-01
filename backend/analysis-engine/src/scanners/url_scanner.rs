/// URL scanner for detecting phishing, malware distribution, and malicious websites
///
/// Features:
/// - Domain reputation checking
/// - URL pattern analysis
/// - Phishing detection
/// - Malicious link detection
/// - Safe browsing integration
/// - Certificate validation (facts come from a real handshake, never placeholders)
/// - SSRF controls: only public http(s) destinations, re-checked on every redirect
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tracing::{info, warn};
use url::{Host, Url};
use uuid::Uuid;

use super::url_policy::{
    is_fetch_refusal, is_public_ip, parse_certificate, refusal, validate_url_policy,
    MAX_FETCH_BYTES,
};
use super::{
    ArtifactType, Finding, FindingCategory, ScanResult, Scanner, ScannerConfig, ThreatLevel,
};

/// Configuration for URL scanner
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UrlScannerConfig {
    pub base: ScannerConfig,
    pub check_reputation: bool,
    pub check_ssl: bool,
    pub check_phishing_patterns: bool,
    pub check_redirect_chain: bool,
    pub max_redirects: usize,
    pub timeout_seconds: u64,
    pub user_agent: String,
}

impl Default for UrlScannerConfig {
    fn default() -> Self {
        Self {
            base: ScannerConfig {
                scanner_name: "URL Scanner".to_string(),
                max_file_size_mb: 10,
                timeout_seconds: 30,
                ..Default::default()
            },
            check_reputation: true,
            check_ssl: true,
            check_phishing_patterns: true,
            check_redirect_chain: true,
            max_redirects: 5,
            timeout_seconds: 30,
            user_agent: "Mozilla/5.0 (Verdyx URL Scanner)".to_string(),
        }
    }
}

/// Detailed URL scan result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UrlScanResult {
    pub base: ScanResult,
    pub url_info: UrlInfo,
    pub domain_reputation: DomainReputation,
    pub phishing_indicators: Vec<PhishingIndicator>,
    pub redirect_chain: Vec<String>,
    pub ssl_info: Option<SslInfo>,
    pub content_analysis: Option<ContentAnalysis>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UrlInfo {
    pub original_url: String,
    pub parsed_url: ParsedUrl,
    pub is_shortened: bool,
    pub is_ip_based: bool,
    pub has_suspicious_tld: bool,
    pub url_length: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedUrl {
    pub scheme: String,
    pub domain: String,
    pub path: String,
    pub query: Option<String>,
    pub fragment: Option<String>,
    pub port: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainReputation {
    pub domain: String,
    pub age_days: Option<u64>,
    pub is_newly_registered: bool,
    pub is_on_blocklist: bool,
    pub reputation_score: f32,
    pub category: DomainCategory,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DomainCategory {
    Trusted,
    Unknown,
    Suspicious,
    Malicious,
    Phishing,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhishingIndicator {
    pub indicator_type: PhishingIndicatorType,
    pub description: String,
    pub severity: ThreatLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PhishingIndicatorType {
    SuspiciousKeywords,
    BrandImpersonation,
    UrlObfuscation,
    HomographAttack,
    ExcessiveSubdomains,
    SuspiciousTld,
    IpAddress,
    MismatchedDomain,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SslInfo {
    pub has_ssl: bool,
    pub is_valid: bool,
    pub issuer: Option<String>,
    pub expiry_days: Option<i64>,
    pub certificate_errors: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentAnalysis {
    pub title: Option<String>,
    pub has_login_form: bool,
    pub has_password_field: bool,
    pub external_links_count: usize,
    pub suspicious_scripts: Vec<String>,
}

/// URL scanner implementation
pub struct UrlScanner {
    config: UrlScannerConfig,
    blocklist_domains: Vec<String>,
    blocklist_keywords: Vec<String>,
    suspicious_tlds: Vec<String>,
    url_shortener_domains: Vec<String>,
    trusted_domains: Vec<String>,
    phishing_keywords: Vec<String>,
}

#[async_trait::async_trait]
impl Scanner for UrlScanner {
    type Config = UrlScannerConfig;
    type Result = UrlScanResult;

    fn new(config: Self::Config) -> Result<Self> {
        info!("Initializing URL scanner");

        Ok(Self {
            config,
            blocklist_domains: Self::load_blocklist_domains(),
            blocklist_keywords: Self::load_blocklist_keywords(),
            suspicious_tlds: Self::load_suspicious_tlds(),
            url_shortener_domains: Self::load_url_shortener_domains(),
            trusted_domains: Self::load_trusted_domains(),
            phishing_keywords: Self::load_phishing_keywords(),
        })
    }

    async fn scan(
        &self,
        data: &[u8],
        _metadata: Option<HashMap<String, String>>,
    ) -> Result<Self::Result> {
        let start_time = std::time::Instant::now();

        // Convert data to URL string
        let url_string =
            String::from_utf8(data.to_vec()).map_err(|_| anyhow!("Invalid UTF-8 in URL"))?;
        let url_string = url_string.trim();

        info!("Starting URL scan for: {}", url_string);

        let mut base_result = ScanResult::new(ArtifactType::Url);

        // Parse URL
        let parsed = Url::parse(url_string).map_err(|e| anyhow!("Invalid URL format: {e}"))?;

        // Gather URL information
        let url_info = self.analyze_url(&parsed);

        // Check domain reputation
        let domain_reputation = if self.config.check_reputation {
            self.check_domain_reputation(&url_info.parsed_url.domain)
        } else {
            DomainReputation {
                domain: url_info.parsed_url.domain.clone(),
                age_days: None,
                is_newly_registered: false,
                is_on_blocklist: false,
                reputation_score: 0.5,
                category: DomainCategory::Unknown,
            }
        };

        // Add findings based on domain reputation
        if domain_reputation.is_on_blocklist {
            base_result.add_finding(Finding {
                finding_id: Uuid::new_v4(),
                category: FindingCategory::Malware,
                title: "Domain on blocklist".to_string(),
                description: format!(
                    "Domain {} is on known malicious blocklist",
                    domain_reputation.domain
                ),
                severity: ThreatLevel::Critical,
                evidence: vec![format!("Blocklist match: {}", domain_reputation.domain)],
                recommendation: Some("Block access immediately".to_string()),
            });
        }

        if domain_reputation.is_newly_registered {
            base_result.add_finding(Finding {
                finding_id: Uuid::new_v4(),
                category: FindingCategory::Suspicious,
                title: "Newly registered domain".to_string(),
                description: "Domain registered within last 30 days".to_string(),
                severity: ThreatLevel::Medium,
                evidence: vec![format!("Domain age: {:?} days", domain_reputation.age_days)],
                recommendation: Some("Exercise caution".to_string()),
            });
        }

        // Check for phishing patterns
        let phishing_indicators = if self.config.check_phishing_patterns {
            self.check_phishing_patterns(&url_info, &parsed)
        } else {
            Vec::new()
        };

        // Add phishing findings
        for indicator in &phishing_indicators {
            let category = if matches!(
                indicator.indicator_type,
                PhishingIndicatorType::BrandImpersonation
            ) {
                FindingCategory::Phishing
            } else {
                FindingCategory::Suspicious
            };

            base_result.add_finding(Finding {
                finding_id: Uuid::new_v4(),
                category,
                title: format!("Phishing indicator: {:?}", indicator.indicator_type),
                description: indicator.description.clone(),
                severity: indicator.severity.clone(),
                evidence: vec![url_string.to_string()],
                recommendation: Some("Verify legitimacy before accessing".to_string()),
            });
        }

        // Refuse private, link-local, and metadata destinations before any
        // socket is opened. Hostnames that only fail once DNS is consulted are
        // rejected inside the fetch helpers, still before connect.
        let mut fetch_denials: Vec<String> = Vec::new();
        let start_blocked = if let Err(e) = validate_url_policy(&parsed) {
            fetch_denials.push(e.to_string());
            true
        } else {
            false
        };

        // Check redirect chain. Each hop is validated and DNS-pinned; a blocked
        // Location is recorded and not requested.
        let redirect_chain = if start_blocked || !self.config.check_redirect_chain {
            vec![url_string.to_string()]
        } else {
            let inspection = self.inspect_redirects(&parsed).await;
            if let Some(denied) = inspection.denied {
                push_denial(&mut fetch_denials, denied);
            }
            inspection.visited
        };

        if redirect_chain.len() > 1 {
            base_result.add_finding(Finding {
                finding_id: Uuid::new_v4(),
                category: FindingCategory::Suspicious,
                title: "Multiple redirects detected".to_string(),
                description: format!("URL redirects {} times", redirect_chain.len() - 1),
                severity: ThreatLevel::Low,
                evidence: redirect_chain.clone(),
                recommendation: Some(
                    "Review redirect chain for malicious destinations".to_string(),
                ),
            });
        }

        // Check TLS only by performing a handshake to a destination that already
        // passed the SSRF policy. Issuer and expiry stay empty unless a peer
        // certificate was actually parsed.
        let ssl_info = if self.config.check_ssl && parsed.scheme() == "https" {
            if start_blocked {
                Some(ssl_not_checked(
                    fetch_denials
                        .first()
                        .map(String::as_str)
                        .unwrap_or("destination blocked before TLS handshake"),
                ))
            } else {
                Some(self.check_ssl(&parsed).await)
            }
        } else {
            None
        };

        if let Some(ref ssl) = ssl_info {
            let refused = ssl.certificate_errors.iter().any(|e| is_fetch_refusal(e));
            if refused {
                if let Some(reason) = ssl.certificate_errors.iter().find(|e| is_fetch_refusal(e)) {
                    push_denial(&mut fetch_denials, reason.clone());
                }
            } else if !ssl.has_ssl || !ssl.is_valid {
                let detail = if ssl.certificate_errors.is_empty() {
                    "HTTPS endpoint did not present a trusted certificate".to_string()
                } else {
                    ssl.certificate_errors.join(", ")
                };
                base_result.add_finding(Finding {
                    finding_id: Uuid::new_v4(),
                    category: FindingCategory::Suspicious,
                    title: "TLS check failed".to_string(),
                    description: detail,
                    severity: ThreatLevel::High,
                    evidence: ssl.certificate_errors.clone(),
                    recommendation: Some("Do not enter sensitive information".to_string()),
                });
            }
        }

        // Fetch page content only when the submitted URL itself is allowed.
        // Redirects inside the fetch are validated the same way.
        let content_analysis = if start_blocked {
            None
        } else {
            match self.analyze_content(&parsed).await {
                Ok(content) => Some(content),
                Err(e) => {
                    let msg = e.to_string();
                    if is_fetch_refusal(&msg) {
                        push_denial(&mut fetch_denials, msg);
                    } else {
                        warn!("Content analysis skipped: {}", e);
                    }
                    None
                }
            }
        };

        for reason in &fetch_denials {
            base_result.add_finding(Finding {
                finding_id: Uuid::new_v4(),
                category: FindingCategory::NetworkThreat,
                title: "Outbound fetch blocked".to_string(),
                description: reason.clone(),
                severity: ThreatLevel::High,
                evidence: vec![url_string.to_string(), reason.clone()],
                recommendation: Some(
                    "The URL or a redirect target is not a public http(s) address and was not requested."
                        .to_string(),
                ),
            });
        }

        if let Some(ref content) = content_analysis {
            if content.has_login_form && content.has_password_field {
                base_result.add_finding(Finding {
                    finding_id: Uuid::new_v4(),
                    category: FindingCategory::Suspicious,
                    title: "Login form detected".to_string(),
                    description: "Page contains login form - verify legitimacy".to_string(),
                    severity: ThreatLevel::Medium,
                    evidence: vec!["Login form present".to_string()],
                    recommendation: Some("Verify domain matches expected service".to_string()),
                });
            }

            if !content.suspicious_scripts.is_empty() {
                base_result.add_finding(Finding {
                    finding_id: Uuid::new_v4(),
                    category: FindingCategory::Suspicious,
                    title: "Suspicious scripts detected".to_string(),
                    description: format!(
                        "{} suspicious scripts found",
                        content.suspicious_scripts.len()
                    ),
                    severity: ThreatLevel::Medium,
                    evidence: content.suspicious_scripts.clone(),
                    recommendation: Some("Review page source for malicious code".to_string()),
                });
            }
        }

        let scan_duration_ms = start_time.elapsed().as_millis() as u64;
        base_result.scan_duration_ms = scan_duration_ms;

        info!(
            "URL scan completed in {}ms - Verdict: {:?}",
            scan_duration_ms, base_result.verdict
        );

        Ok(UrlScanResult {
            base: base_result,
            url_info,
            domain_reputation,
            phishing_indicators,
            redirect_chain,
            ssl_info,
            content_analysis,
        })
    }

    fn get_stats(&self) -> HashMap<String, String> {
        let mut stats = HashMap::new();
        stats.insert(
            "scanner_name".to_string(),
            self.config.base.scanner_name.clone(),
        );
        stats.insert(
            "blocklist_domains".to_string(),
            self.blocklist_domains.len().to_string(),
        );
        stats.insert(
            "suspicious_tlds".to_string(),
            self.suspicious_tlds.len().to_string(),
        );
        stats.insert(
            "trusted_domains".to_string(),
            self.trusted_domains.len().to_string(),
        );
        stats
    }

    fn health_check(&self) -> bool {
        self.config.base.enabled
    }
}

impl UrlScanner {
    /// Analyze URL structure
    fn analyze_url(&self, parsed: &Url) -> UrlInfo {
        let domain = parsed.host_str().unwrap_or("").to_string();

        let is_shortened = self
            .url_shortener_domains
            .iter()
            .any(|d| domain.contains(d));
        let is_ip_based = domain.parse::<std::net::IpAddr>().is_ok();
        let has_suspicious_tld = self.suspicious_tlds.iter().any(|tld| domain.ends_with(tld));

        let parsed_url = ParsedUrl {
            scheme: parsed.scheme().to_string(),
            domain: domain.clone(),
            path: parsed.path().to_string(),
            query: parsed.query().map(|s| s.to_string()),
            fragment: parsed.fragment().map(|s| s.to_string()),
            port: parsed.port(),
        };

        UrlInfo {
            original_url: parsed.to_string(),
            parsed_url,
            is_shortened,
            is_ip_based,
            has_suspicious_tld,
            url_length: parsed.as_str().len(),
        }
    }

    /// Check domain reputation
    fn check_domain_reputation(&self, domain: &str) -> DomainReputation {
        let is_on_blocklist = self.blocklist_domains.iter().any(|d| domain.contains(d));
        let is_trusted = self.trusted_domains.iter().any(|d| domain.contains(d));

        let category = if is_on_blocklist {
            DomainCategory::Malicious
        } else if is_trusted {
            DomainCategory::Trusted
        } else {
            DomainCategory::Unknown
        };

        let reputation_score = if is_trusted {
            0.9
        } else if is_on_blocklist {
            0.1
        } else {
            0.5
        };

        DomainReputation {
            domain: domain.to_string(),
            age_days: None,             // Would query WHOIS in production
            is_newly_registered: false, // Would check WHOIS registration date
            is_on_blocklist,
            reputation_score,
            category,
        }
    }

    /// Check for phishing patterns
    fn check_phishing_patterns(&self, url_info: &UrlInfo, _parsed: &Url) -> Vec<PhishingIndicator> {
        let mut indicators = Vec::new();

        // Check for suspicious keywords
        let url_lower = url_info.original_url.to_lowercase();
        for keyword in &self.phishing_keywords {
            if url_lower.contains(keyword) {
                indicators.push(PhishingIndicator {
                    indicator_type: PhishingIndicatorType::SuspiciousKeywords,
                    description: format!("URL contains suspicious keyword: {keyword}"),
                    severity: ThreatLevel::Medium,
                });
            }
        }

        // Check for IP-based URLs
        if url_info.is_ip_based {
            indicators.push(PhishingIndicator {
                indicator_type: PhishingIndicatorType::IpAddress,
                description: "URL uses IP address instead of domain name".to_string(),
                severity: ThreatLevel::High,
            });
        }

        // Check for excessive subdomains
        let subdomain_count = url_info.parsed_url.domain.matches('.').count();
        if subdomain_count > 3 {
            indicators.push(PhishingIndicator {
                indicator_type: PhishingIndicatorType::ExcessiveSubdomains,
                description: format!("Excessive subdomains detected: {subdomain_count}"),
                severity: ThreatLevel::Medium,
            });
        }

        // Check for suspicious TLD
        if url_info.has_suspicious_tld {
            indicators.push(PhishingIndicator {
                indicator_type: PhishingIndicatorType::SuspiciousTld,
                description: "Domain uses suspicious top-level domain".to_string(),
                severity: ThreatLevel::Medium,
            });
        }

        // Check for URL obfuscation (excessive length, special characters)
        if url_info.url_length > 200 {
            indicators.push(PhishingIndicator {
                indicator_type: PhishingIndicatorType::UrlObfuscation,
                description: format!("Unusually long URL: {} characters", url_info.url_length),
                severity: ThreatLevel::Low,
            });
        }

        // Check for brand impersonation (simplified)
        let brands = [
            "paypal",
            "amazon",
            "google",
            "microsoft",
            "apple",
            "facebook",
        ];
        for brand in &brands {
            if url_lower.contains(brand)
                && !url_info
                    .parsed_url
                    .domain
                    .ends_with(&format!("{brand}.com"))
            {
                indicators.push(PhishingIndicator {
                    indicator_type: PhishingIndicatorType::BrandImpersonation,
                    description: format!("Possible {brand} brand impersonation"),
                    severity: ThreatLevel::High,
                });
            }
        }

        indicators
    }

    /// Walk redirects without ever requesting a destination that fails the
    /// SSRF policy. `visited` contains only URLs that were actually requested.
    async fn inspect_redirects(&self, start: &Url) -> RedirectInspection {
        let mut visited = Vec::new();
        let mut current = start.clone();
        let mut denied = None;

        for _ in 0..=self.config.max_redirects {
            if visited
                .iter()
                .any(|seen: &String| seen == &current.to_string())
            {
                break;
            }
            match self.send_once(&current).await {
                Ok(response) => {
                    visited.push(current.to_string());
                    match redirect_target(&current, &response) {
                        Ok(Some(next)) => current = next,
                        Ok(None) => break,
                        Err(e) => {
                            let msg = e.to_string();
                            if is_fetch_refusal(&msg) {
                                denied = Some(msg);
                            } else {
                                warn!("Stopping redirect walk: {e}");
                            }
                            break;
                        }
                    }
                }
                Err(e) => {
                    let msg = e.to_string();
                    if is_fetch_refusal(&msg) {
                        denied = Some(msg);
                    } else {
                        warn!("Redirect check could not fetch {}: {e}", current);
                    }
                    break;
                }
            }
        }

        if visited.is_empty() {
            visited.push(start.to_string());
        }
        RedirectInspection { visited, denied }
    }

    /// One request with redirects disabled, proxies disabled, and DNS pinned to
    /// an address that was checked immediately beforehand.
    async fn send_once(&self, url: &Url) -> Result<reqwest::Response> {
        let endpoint = self.resolve_endpoint(url).await?;
        let mut builder = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .timeout(Duration::from_secs(self.config.timeout_seconds))
            .connect_timeout(Duration::from_secs(
                self.config.timeout_seconds.clamp(1, 10),
            ))
            .user_agent(&self.config.user_agent);
        // Literal IPs are not resolved by reqwest. Hostnames must be pinned so
        // a second lookup cannot swap in a private address (DNS rebinding).
        if matches!(url.host(), Some(Host::Domain(_))) {
            builder = builder.resolve(&endpoint.host, SocketAddr::new(endpoint.ip, endpoint.port));
        }
        let client = builder.build()?;
        client
            .get(endpoint.url.clone())
            .send()
            .await
            .map_err(|e| anyhow!("request to {} failed: {e}", endpoint.url))
    }

    /// Policy check, then DNS. Returns only after every resolved address is public.
    async fn resolve_endpoint(&self, url: &Url) -> Result<ResolvedEndpoint> {
        validate_url_policy(url)?;
        let host = url
            .host_str()
            .ok_or_else(|| refusal(url, "missing host"))?
            .trim_end_matches('.')
            .to_string();
        let port = url
            .port_or_known_default()
            .ok_or_else(|| refusal(url, "missing port"))?;

        let ip = match url.host() {
            Some(Host::Ipv4(v4)) => IpAddr::V4(v4),
            Some(Host::Ipv6(v6)) => IpAddr::V6(v6),
            Some(Host::Domain(domain)) => self.resolve_domain(url, domain, port).await?,
            None => return Err(refusal(url, "missing host")),
        };
        if !is_public_ip(ip) {
            return Err(refusal(url, format!("{ip} is not a public address")));
        }
        Ok(ResolvedEndpoint {
            url: url.clone(),
            host,
            ip,
            port,
        })
    }

    async fn resolve_domain(&self, url: &Url, domain: &str, port: u16) -> Result<IpAddr> {
        let lookup = tokio::net::lookup_host((domain, port));
        let addrs = tokio::time::timeout(Duration::from_secs(self.config.timeout_seconds), lookup)
            .await
            .map_err(|_| anyhow!("DNS lookup timed out for {domain}"))?
            .map_err(|e| anyhow!("DNS lookup failed for {domain}: {e}"))?;
        let ips: Vec<IpAddr> = addrs.map(|addr| addr.ip()).collect();
        if ips.is_empty() {
            return Err(anyhow!("DNS lookup returned no addresses for {domain}"));
        }
        // Fail closed if any record is internal. A mixed answer is enough for
        // a rebinding or split-horizon trick to reach metadata or RFC1918.
        if let Some(bad) = ips.iter().find(|ip| !is_public_ip(**ip)) {
            return Err(refusal(
                url,
                format!("{domain} resolves to non-public address {bad}"),
            ));
        }
        Ok(ips[0])
    }

    /// Perform a real TLS handshake and report only facts taken from it.
    ///
    /// A blocked destination does not produce `is_valid: true` or a made-up
    /// issuer/expiry. Those fields are filled only after the peer certificate
    /// has been parsed.
    async fn check_ssl(&self, url: &Url) -> SslInfo {
        match self.inspect_tls(url).await {
            Ok(info) => info,
            Err(e) => ssl_not_checked(&e.to_string()),
        }
    }

    async fn inspect_tls(&self, url: &Url) -> Result<SslInfo> {
        if url.scheme() != "https" {
            return Err(anyhow!("TLS was not checked: URL is not https"));
        }
        let endpoint = self.resolve_endpoint(url).await?;
        let addr = SocketAddr::new(endpoint.ip, endpoint.port);
        let tcp = tokio::time::timeout(
            Duration::from_secs(self.config.timeout_seconds),
            tokio::net::TcpStream::connect(addr),
        )
        .await
        .map_err(|_| anyhow!("TLS connection to {} timed out", endpoint.url))??;

        let connector = native_tls::TlsConnector::builder()
            .build()
            .map_err(|e| anyhow!("failed to build TLS connector: {e}"))?;
        let connector = tokio_native_tls::TlsConnector::from(connector);
        // `connect` verifies the certificate against `endpoint.host` using the
        // system trust store. Do not disable that check.
        let tls = connector
            .connect(&endpoint.host, tcp)
            .await
            .map_err(|e| anyhow!("TLS handshake failed: {e}"))?;

        let peer = tls
            .get_ref()
            .peer_certificate()
            .map_err(|e| anyhow!("failed to read peer certificate: {e}"))?
            .ok_or_else(|| anyhow!("TLS handshake completed without a peer certificate"))?;
        let der = peer
            .to_der()
            .map_err(|e| anyhow!("peer certificate could not be encoded: {e}"))?;
        match parse_certificate(&der).and_then(certificate_facts) {
            Ok(info) => Ok(info),
            Err(e) => Ok(SslInfo {
                has_ssl: true,
                is_valid: true,
                issuer: None,
                expiry_days: None,
                certificate_errors: vec![format!("peer certificate could not be parsed: {e}")],
            }),
        }
    }

    /// Download a submitted page so the engines scan its content, not its URL.
    pub async fn fetch_page(&self, raw_url: &str) -> Result<Vec<u8>> {
        let url = Url::parse(raw_url).map_err(|e| anyhow!("invalid URL {raw_url}: {e}"))?;
        validate_url_policy(&url)?;
        Ok(self.fetch_html(&url).await?.into_bytes())
    }

    /// Redirects are followed manually so each hop is policy-checked and
    /// DNS-pinned. The body is capped.
    async fn fetch_html(&self, url: &Url) -> Result<String> {
        let mut current = url.clone();
        let mut seen = Vec::new();
        let mut final_response = None;

        for _ in 0..=self.config.max_redirects {
            if seen
                .iter()
                .any(|seen_url: &String| seen_url == &current.to_string())
            {
                return Err(anyhow!("redirect loop at {current}"));
            }
            seen.push(current.to_string());
            let response = self.send_once(&current).await?;
            match redirect_target(&current, &response)? {
                Some(next) => current = next,
                None => {
                    final_response = Some(response);
                    break;
                }
            }
        }

        let response = final_response.ok_or_else(|| anyhow!("too many redirects"))?;
        read_body_limited(response, MAX_FETCH_BYTES).await
    }

    /// Fetch and analyze page content.
    async fn analyze_content(&self, url: &Url) -> Result<ContentAnalysis> {
        let html = self.fetch_html(url).await?;
        let html_lower = html.to_lowercase();

        let has_login_form = html_lower.contains("<form")
            && (html_lower.contains("login") || html_lower.contains("signin"));
        let has_password_field =
            html_lower.contains(r#"type="password""#) || html_lower.contains("type='password'");

        let external_links_count = html.matches("href=").count();

        let mut suspicious_scripts = Vec::new();
        if html_lower.contains("eval(") {
            suspicious_scripts.push("eval() usage detected".to_string());
        }
        if html_lower.contains("document.write") {
            suspicious_scripts.push("document.write usage detected".to_string());
        }

        // Extract title (simplified)
        let title = if let Some(start) = html.find("<title>") {
            html[start..]
                .find("</title>")
                .map(|end| html[start + 7..start + end].to_string())
        } else {
            None
        };

        Ok(ContentAnalysis {
            title,
            has_login_form,
            has_password_field,
            external_links_count,
            suspicious_scripts,
        })
    }

    /// Load blocklist domains
    fn load_blocklist_domains() -> Vec<String> {
        vec![
            "malware.com".to_string(),
            "phishing.net".to_string(),
            "scam.site".to_string(),
        ]
    }

    /// Load blocklist keywords
    fn load_blocklist_keywords() -> Vec<String> {
        vec![
            "malware".to_string(),
            "phishing".to_string(),
            "scam".to_string(),
        ]
    }

    /// Load suspicious TLDs
    fn load_suspicious_tlds() -> Vec<String> {
        vec![
            ".tk".to_string(),
            ".ml".to_string(),
            ".ga".to_string(),
            ".cf".to_string(),
            ".gq".to_string(),
        ]
    }

    /// Load URL shortener domains
    fn load_url_shortener_domains() -> Vec<String> {
        vec![
            "bit.ly".to_string(),
            "tinyurl.com".to_string(),
            "goo.gl".to_string(),
            "t.co".to_string(),
        ]
    }

    /// Load trusted domains
    fn load_trusted_domains() -> Vec<String> {
        vec![
            "google.com".to_string(),
            "microsoft.com".to_string(),
            "amazon.com".to_string(),
            "github.com".to_string(),
        ]
    }

    /// Load phishing keywords
    fn load_phishing_keywords() -> Vec<String> {
        vec![
            "verify".to_string(),
            "account".to_string(),
            "suspended".to_string(),
            "confirm".to_string(),
            "update".to_string(),
            "secure".to_string(),
            "banking".to_string(),
        ]
    }
}

struct RedirectInspection {
    visited: Vec<String>,
    denied: Option<String>,
}

struct ResolvedEndpoint {
    url: Url,
    host: String,
    ip: IpAddr,
    port: u16,
}

fn push_denial(denials: &mut Vec<String>, reason: String) {
    if !denials.iter().any(|existing| existing == &reason) {
        denials.push(reason);
    }
}

fn ssl_not_checked(reason: &str) -> SslInfo {
    SslInfo {
        has_ssl: false,
        is_valid: false,
        issuer: None,
        expiry_days: None,
        certificate_errors: vec![reason.to_string()],
    }
}

fn certificate_facts(parsed: super::url_policy::ParsedCertificate) -> Result<SslInfo> {
    let now = chrono::Utc::now().timestamp();
    let mut errors = Vec::new();
    if now < parsed.not_before {
        errors.push("certificate is not yet valid".to_string());
    }
    if now > parsed.not_after {
        errors.push("certificate is expired".to_string());
    }
    Ok(SslInfo {
        has_ssl: true,
        is_valid: errors.is_empty(),
        issuer: Some(parsed.issuer),
        expiry_days: Some((parsed.not_after - now) / 86_400),
        certificate_errors: errors,
    })
}

fn redirect_target(current: &Url, response: &reqwest::Response) -> Result<Option<Url>> {
    if !matches!(response.status().as_u16(), 301 | 302 | 303 | 307 | 308) {
        return Ok(None);
    }
    let Some(location) = response.headers().get(reqwest::header::LOCATION) else {
        return Ok(None);
    };
    let location = location
        .to_str()
        .map_err(|_| anyhow!("redirect Location is not valid UTF-8"))?;
    let next = current
        .join(location)
        .map_err(|e| anyhow!("invalid redirect Location: {e}"))?;
    validate_url_policy(&next)?;
    Ok(Some(next))
}

async fn read_body_limited(mut response: reqwest::Response, max_bytes: usize) -> Result<String> {
    let mut body = Vec::new();
    while body.len() < max_bytes {
        match response.chunk().await? {
            Some(chunk) => {
                let room = max_bytes - body.len();
                if chunk.len() > room {
                    body.extend_from_slice(&chunk[..room]);
                    break;
                }
                body.extend_from_slice(&chunk);
            }
            None => break,
        }
    }
    Ok(String::from_utf8_lossy(&body).into_owned())
}

#[cfg(test)]
mod tests {
    use super::certificate_facts;
    use super::*;
    use crate::scanners::url_policy::{is_public_ip, parse_certificate, validate_url_policy};

    #[tokio::test]
    async fn test_url_scanner_creation() {
        let config = UrlScannerConfig::default();
        let scanner = UrlScanner::new(config);
        assert!(scanner.is_ok());
    }

    #[tokio::test]
    async fn test_scan_malicious_url() {
        let scanner = UrlScanner::new(UrlScannerConfig::default()).unwrap();
        let url = b"http://malware.com/bad.exe";

        let result = scanner.scan(url, None).await;
        assert!(result.is_ok());

        let scan_result = result.unwrap();
        assert_eq!(
            scan_result.domain_reputation.category,
            DomainCategory::Malicious
        );
    }

    #[tokio::test]
    async fn test_scan_ip_based_url() {
        let scanner = UrlScanner::new(UrlScannerConfig::default()).unwrap();
        let url = b"http://192.168.1.1/login";

        let result = scanner.scan(url, None).await;
        assert!(result.is_ok());

        let scan_result = result.unwrap();
        assert!(scan_result.url_info.is_ip_based);
        assert!(!scan_result.phishing_indicators.is_empty());
    }

    #[test]
    fn test_url_parsing() {
        let scanner = UrlScanner::new(UrlScannerConfig::default()).unwrap();
        let parsed = Url::parse("https://example.com:8080/path?query=value#fragment").unwrap();
        let url_info = scanner.analyze_url(&parsed);

        assert_eq!(url_info.parsed_url.scheme, "https");
        assert_eq!(url_info.parsed_url.domain, "example.com");
        assert_eq!(url_info.parsed_url.path, "/path");
        assert_eq!(url_info.parsed_url.port, Some(8080));
    }

    #[test]
    fn test_phishing_detection() {
        let scanner = UrlScanner::new(UrlScannerConfig::default()).unwrap();
        let parsed = Url::parse("http://paypal-verify.suspicious.tk/login").unwrap();
        let url_info = scanner.analyze_url(&parsed);
        let indicators = scanner.check_phishing_patterns(&url_info, &parsed);

        assert!(!indicators.is_empty());
        // Should detect suspicious TLD, keywords, and brand impersonation
        assert!(indicators
            .iter()
            .any(|i| matches!(i.indicator_type, PhishingIndicatorType::SuspiciousTld)));
    }

    #[test]
    fn rejects_private_link_local_and_metadata_destinations() {
        let blocked = [
            "http://127.0.0.1/",
            "http://10.1.2.3/",
            "http://192.168.1.1/login",
            "http://172.16.0.1/",
            "http://169.254.169.254/latest/meta-data/",
            "http://0.0.0.0/",
            "http://100.64.0.1/",
            "http://[::1]/",
            "http://[fe80::1]/",
            "http://[fd00::1]/",
            "http://[::ffff:127.0.0.1]/",
            "http://[::ffff:169.254.169.254]/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://instance-data.ec2.internal/",
            "file:///etc/passwd",
            "gopher://example.com/",
            "http://user:pass@example.com/",
            "http://localhost/",
            "http://printer.local/",
        ];
        for raw in blocked {
            let url = Url::parse(raw).unwrap();
            assert!(
                validate_url_policy(&url).is_err(),
                "{raw} should be refused"
            );
        }

        let allowed = Url::parse("https://example.com/path").unwrap();
        assert!(validate_url_policy(&allowed).is_ok());
    }

    #[test]
    fn redirect_to_metadata_is_rejected_before_fetch() {
        let current = Url::parse("https://example.com/start").unwrap();
        let metadata = current
            .join("http://169.254.169.254/latest/meta-data/")
            .unwrap();
        assert!(validate_url_policy(&metadata).is_err());

        let scheme_relative = current
            .join("//metadata.google.internal/computeMetadata/v1/")
            .unwrap();
        assert!(validate_url_policy(&scheme_relative).is_err());

        let relative = current.join("/still-here").unwrap();
        assert!(validate_url_policy(&relative).is_ok());
        assert_eq!(relative.host_str(), Some("example.com"));
    }

    #[test]
    fn decimal_ip_obfuscation_is_treated_as_the_address_it_encodes() {
        let url = Url::parse("http://2130706433/").unwrap();
        assert_eq!(url.host_str(), Some("127.0.0.1"));
        assert!(validate_url_policy(&url).is_err());
    }

    #[tokio::test]
    async fn private_scan_does_not_connect_or_invent_tls_facts() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let url = format!("https://127.0.0.1:{port}/latest/meta-data/");

        let scanner = UrlScanner::new(UrlScannerConfig {
            timeout_seconds: 2,
            ..UrlScannerConfig::default()
        })
        .unwrap();
        let result = scanner.scan(url.as_bytes(), None).await.unwrap();

        let accepted = tokio::time::timeout(Duration::from_millis(50), listener.accept()).await;
        assert!(accepted.is_err(), "scanner opened a connection to loopback");
        assert!(result
            .base
            .findings
            .iter()
            .any(|f| f.title == "Outbound fetch blocked"));

        let ssl = result.ssl_info.expect("https scan records an ssl result");
        assert!(!ssl.is_valid);
        assert!(ssl.issuer.is_none());
        assert!(ssl.expiry_days.is_none());
        assert!(ssl
            .certificate_errors
            .iter()
            .all(|e| !e.contains("Let's Encrypt") && !e.contains("90")));
    }

    #[test]
    fn certificate_facts_come_from_the_parsed_certificate() {
        fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
            let mut out = vec![tag];
            assert!(body.len() < 128);
            out.push(body.len() as u8);
            out.extend_from_slice(body);
            out
        }

        let cn_oid = [0x55, 0x04, 0x03];
        let issuer = tlv(
            0x30,
            &tlv(
                0x31,
                &tlv(0x30, &[tlv(0x06, &cn_oid), tlv(0x0c, b"Test CA")].concat()),
            ),
        );
        let validity = tlv(
            0x30,
            &[tlv(0x17, b"250101000000Z"), tlv(0x17, b"350101000000Z")].concat(),
        );
        let tbs = tlv(
            0x30,
            &[
                tlv(0x02, &[0x01]),
                tlv(0x30, &tlv(0x06, &cn_oid)),
                issuer,
                validity,
            ]
            .concat(),
        );
        let cert = tlv(0x30, &tbs);

        let info = certificate_facts(parse_certificate(&cert).unwrap()).unwrap();
        assert!(info.has_ssl);
        assert!(info.is_valid);
        assert_eq!(info.issuer.as_deref(), Some("CN=Test CA"));
        assert_ne!(info.expiry_days, Some(90));
        assert!(info.expiry_days.unwrap_or(0) > 90);
        assert!(info.certificate_errors.is_empty());
    }

    #[test]
    fn public_addresses_are_allowed() {
        assert!(is_public_ip("1.1.1.1".parse().unwrap()));
        assert!(is_public_ip("8.8.8.8".parse().unwrap()));
        assert!(!is_public_ip("169.254.169.254".parse().unwrap()));
        assert!(!is_public_ip("::ffff:10.0.0.1".parse().unwrap()));
    }
}
