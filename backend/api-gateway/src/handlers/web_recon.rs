//! Reconnaissance for bug-bounty work, from public sources:
//!
//! - **Subdomains** from certificate transparency logs (Cert Spotter, with
//!   crt.sh as a backup), and which of them resolve, via DNS-over-HTTPS.
//! - **Possible subdomain takeovers**: a CNAME that points at a service such
//!   as GitHub Pages, Heroku or S3 where nothing is claimed any more.
//! - **Archived URLs** from the Wayback Machine, sorted into URLs with
//!   parameters, interesting files and interesting paths.
//! - **JavaScript**: endpoints and exposed keys in the site's own scripts.
//!
//! Requests to the target and its subdomains are ordinary GETs a browser
//! would make, sent through the public-only resolver so they can't reach
//! Verdyx's own network. Results are cached for a few hours per domain, so
//! repeat scans don't hit the public sources again.

use std::collections::{BTreeSet, HashMap};
use std::net::IpAddr;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use axum::{extract::Query, http::StatusCode, response::Json};
use futures_util::{stream, StreamExt};
use regex::Regex;
use serde_json::{json, Value};

use super::web_intel::{normalize_target_url, WebIntelQuery};
use crate::services::webhook_delivery::{check_url, public_client_builder, safe_redirects};

const USER_AGENT: &str = "Mozilla/5.0 (compatible; Verdyx-Recon/3.0; +https://verdyx.dev)";

/// How long results are reused.
const CACHE_TTL: Duration = Duration::from_secs(6 * 3600);
/// Domains kept in each cache.
const CACHE_MAX: usize = 500;
/// Subdomains returned.
const MAX_SUBDOMAINS: usize = 1000;
/// Certificates kept per domain for picking the host's certificate.
const MAX_CERTS: usize = 3000;
/// Cert Spotter pages read (about 100 certificates each).
const CERTSPOTTER_PAGES: usize = 3;
/// Subdomains whose DNS is looked up.
const RESOLVE_LIMIT: usize = 150;
const RESOLVE_CONCURRENCY: usize = 16;
/// Subdomains whose page is fetched to confirm a takeover fingerprint.
const TAKEOVER_FETCH_LIMIT: usize = 20;
/// Archived URLs read from the Wayback Machine.
const WAYBACK_LIMIT: usize = 3000;
/// AlienVault OTX pages read (500 URLs each).
const OTX_PAGES: usize = 3;
/// Each list of archived URLs is cut to this many.
const WAYBACK_LIST_MAX: usize = 300;
/// First-party scripts read for endpoints and keys.
const MAX_SCRIPTS: usize = 8;
const MAX_SCRIPT_BYTES: usize = 2 * 1024 * 1024;
const MAX_PAGE_BYTES: usize = 1536 * 1024;
const MAX_ENDPOINTS: usize = 500;

// ─── Domains ──────────────────────────────────────────────────────────────

/// The registrable domain (`a.b.example.co.uk` → `example.co.uk`), using the
/// public suffix list, so `user.github.io` stays `user.github.io`.
pub(crate) fn registrable_domain(host: &str) -> String {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host.parse::<IpAddr>().is_ok() {
        return host;
    }
    psl::domain_str(&host).map(str::to_string).unwrap_or(host)
}

/// A certificate name cleaned to a subdomain of `root`, or `None`.
fn clean_name(raw: &str, root: &str) -> Option<String> {
    let name = raw
        .trim()
        .trim_start_matches("*.")
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if name.is_empty()
        || name
            .chars()
            .any(|c| !(c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == '_'))
    {
        return None;
    }
    name.ends_with(&format!(".{root}")).then_some(name)
}

/// True when a certificate name (possibly a wildcard) covers `host`.
pub(crate) fn name_covers(pattern: &str, host: &str) -> bool {
    let pattern = pattern.trim().trim_end_matches('.').to_ascii_lowercase();
    if pattern == host {
        return true;
    }
    match pattern.strip_prefix("*.") {
        Some(rest) => host
            .split_once('.')
            .is_some_and(|(_, parent)| parent == rest),
        None => false,
    }
}

// ─── Caches ───────────────────────────────────────────────────────────────

struct TtlCache<V: Clone> {
    entries: Mutex<HashMap<String, (Instant, V)>>,
}

impl<V: Clone> TtlCache<V> {
    fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
        }
    }

    fn get(&self, key: &str) -> Option<V> {
        let map = self.entries.lock().ok()?;
        map.get(key)
            .filter(|(at, _)| at.elapsed() < CACHE_TTL)
            .map(|(_, v)| v.clone())
    }

    fn put(&self, key: String, value: V) {
        let Ok(mut map) = self.entries.lock() else {
            return;
        };
        map.retain(|_, (at, _)| at.elapsed() < CACHE_TTL);
        if map.len() >= CACHE_MAX {
            if let Some(oldest) = map
                .iter()
                .min_by_key(|(_, (at, _))| *at)
                .map(|(k, _)| k.clone())
            {
                map.remove(&oldest);
            }
        }
        map.insert(key, (Instant::now(), value));
    }
}

static ENUMERATIONS: LazyLock<TtlCache<Enumeration>> = LazyLock::new(TtlCache::new);
static ARCHIVES: LazyLock<TtlCache<Value>> = LazyLock::new(TtlCache::new);

// ─── HTTP ─────────────────────────────────────────────────────────────────

/// For public APIs (Cert Spotter, crt.sh, Wayback, DNS-over-HTTPS).
fn api_client(timeout: Duration) -> reqwest::Client {
    public_client_builder(false)
        .redirect(safe_redirects(3))
        .timeout(timeout)
        .connect_timeout(Duration::from_secs(5))
        .user_agent(USER_AGENT)
        .build()
        .unwrap_or_default()
}

/// For the target and its subdomains.
fn target_client(timeout: Duration) -> reqwest::Client {
    public_client_builder(false)
        .redirect(safe_redirects(5))
        .timeout(timeout)
        .connect_timeout(Duration::from_secs(5))
        .user_agent(USER_AGENT)
        .build()
        .unwrap_or_default()
}

fn describe(e: &reqwest::Error) -> String {
    if e.is_timeout() {
        "timed out".to_string()
    } else if e.is_connect() {
        "couldn't connect".to_string()
    } else {
        "request failed".to_string()
    }
}

async fn get_json(client: &reqwest::Client, url: &str) -> Result<Value, String> {
    let resp = client
        .get(url)
        .header("Accept", "application/json")
        .send()
        .await
        .map_err(|e| describe(&e))?;
    let status = resp.status();
    if !status.is_success() {
        return Err(format!("HTTP {}", status.as_u16()));
    }
    resp.json::<Value>()
        .await
        .map_err(|_| "the response wasn't valid JSON".to_string())
}

/// GET a page, keeping at most `max` bytes. Returns the final URL, the
/// status and the text.
async fn fetch_limited(
    client: &reqwest::Client,
    url: &str,
    max: usize,
) -> Result<(String, u16, String), String> {
    check_url(url).map_err(str::to_string)?;
    let mut resp = client.get(url).send().await.map_err(|e| describe(&e))?;
    let final_url = resp.url().to_string();
    let status = resp.status().as_u16();
    let mut body = Vec::new();
    while let Some(chunk) = resp.chunk().await.map_err(|e| describe(&e))? {
        body.extend_from_slice(&chunk);
        if body.len() >= max {
            body.truncate(max);
            break;
        }
    }
    Ok((
        final_url,
        status,
        String::from_utf8_lossy(&body).into_owned(),
    ))
}

// ─── Subdomains from certificate transparency ─────────────────────────────

#[derive(Clone, Debug, Default, PartialEq)]
pub(crate) struct CertEntry {
    pub names: Vec<String>,
    pub issuer: Option<String>,
    pub not_before: Option<String>,
    pub not_after: Option<String>,
}

#[derive(Clone, Debug)]
pub(crate) struct Enumeration {
    pub source: &'static str,
    pub available: bool,
    pub error: Option<String>,
    pub subdomains: Vec<String>,
    pub total: usize,
    pub certs: Vec<CertEntry>,
}

const CERTSPOTTER: &str = "Certificate Transparency (Cert Spotter)";
const CRTSH: &str = "Certificate Transparency (crt.sh)";

fn strings(v: &Value) -> Vec<String> {
    v.as_array()
        .map(|a| {
            a.iter()
                .filter_map(|s| s.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// Cert Spotter issuances, and the id to continue from.
fn parse_certspotter(page: &Value) -> (Vec<CertEntry>, Option<String>) {
    let Some(arr) = page.as_array() else {
        return (Vec::new(), None);
    };
    let entries = arr
        .iter()
        .map(|e| CertEntry {
            names: strings(&e["dns_names"]),
            issuer: e["issuer"]["name"]
                .as_str()
                .or_else(|| e["issuer"]["friendly_name"].as_str())
                .map(str::to_string),
            not_before: e["not_before"].as_str().map(str::to_string),
            not_after: e["not_after"].as_str().map(str::to_string),
        })
        .collect();
    let last = arr
        .last()
        .and_then(|e| e["id"].as_str())
        .map(str::to_string);
    (entries, last)
}

fn parse_crtsh(rows: &Value) -> Vec<CertEntry> {
    rows.as_array()
        .map(|arr| {
            arr.iter()
                .map(|e| CertEntry {
                    names: e["name_value"]
                        .as_str()
                        .unwrap_or("")
                        .lines()
                        .map(str::to_string)
                        .collect(),
                    issuer: e["issuer_name"].as_str().map(str::to_string),
                    not_before: e["not_before"].as_str().map(str::to_string),
                    not_after: e["not_after"].as_str().map(str::to_string),
                })
                .collect()
        })
        .unwrap_or_default()
}

async fn certspotter(client: &reqwest::Client, root: &str) -> Result<Vec<CertEntry>, String> {
    let mut out = Vec::new();
    let mut after: Option<String> = None;
    for _ in 0..CERTSPOTTER_PAGES {
        let mut url = format!(
            "https://api.certspotter.com/v1/issuances?domain={}&include_subdomains=true&expand=dns_names&expand=issuer",
            urlencoding::encode(root)
        );
        if let Some(id) = &after {
            url.push_str(&format!("&after={}", urlencoding::encode(id)));
        }
        let page = match get_json(client, &url).await {
            Ok(page) => page,
            Err(e) if out.is_empty() => return Err(e),
            // Keep what earlier pages found.
            Err(_) => break,
        };
        let (entries, last) = parse_certspotter(&page);
        if entries.is_empty() {
            break;
        }
        out.extend(entries);
        match last {
            Some(id) => after = Some(id),
            None => break,
        }
    }
    Ok(out)
}

async fn crtsh(client: &reqwest::Client, root: &str) -> Result<Vec<CertEntry>, String> {
    // `%.` matches every name under the domain; crt.sh needs it encoded.
    let url = format!(
        "https://crt.sh/?q=%25.{}&output=json&deduplicate=Y",
        urlencoding::encode(root)
    );
    get_json(client, &url).await.map(|rows| parse_crtsh(&rows))
}

fn enumeration_from(source: &'static str, root: &str, mut certs: Vec<CertEntry>) -> Enumeration {
    let names: BTreeSet<String> = certs
        .iter()
        .flat_map(|c| c.names.iter())
        .filter_map(|n| clean_name(n, root))
        .collect();
    certs.truncate(MAX_CERTS);
    Enumeration {
        source,
        available: true,
        error: None,
        total: names.len(),
        subdomains: names.into_iter().take(MAX_SUBDOMAINS).collect(),
        certs,
    }
}

/// Subdomains of `root` from certificate transparency logs. Cert Spotter
/// answers in seconds; crt.sh is tried when it fails or finds nothing.
pub(crate) async fn enumerate_subdomains(root: &str) -> Enumeration {
    if let Some(hit) = ENUMERATIONS.get(root) {
        return hit;
    }
    let spotted = certspotter(&api_client(Duration::from_secs(10)), root).await;
    let result = match spotted {
        Ok(certs) if !certs.is_empty() => enumeration_from(CERTSPOTTER, root, certs),
        other => match crtsh(&api_client(Duration::from_secs(25)), root).await {
            Ok(certs) => enumeration_from(CRTSH, root, certs),
            Err(crt_err) => match other {
                // Cert Spotter answered: the domain just has no certificates.
                Ok(_) => enumeration_from(CERTSPOTTER, root, Vec::new()),
                Err(spot_err) => Enumeration {
                    source: CERTSPOTTER,
                    available: false,
                    error: Some(format!("Cert Spotter: {spot_err}; crt.sh: {crt_err}")),
                    subdomains: Vec::new(),
                    total: 0,
                    certs: Vec::new(),
                },
            },
        },
    };
    if result.available {
        ENUMERATIONS.put(root.to_string(), result.clone());
    }
    result
}

/// The newest certificate in the logs that covers `host`, preferring one
/// that hasn't expired.
pub(crate) fn certificate_for_host<'a>(
    certs: &'a [CertEntry],
    host: &str,
) -> Option<&'a CertEntry> {
    let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S").to_string();
    certs
        .iter()
        .filter(|c| c.names.iter().any(|n| name_covers(n, host)))
        .max_by_key(|c| {
            let unexpired = c.not_after.as_deref().is_some_and(|t| t > now.as_str());
            (unexpired, c.not_before.clone())
        })
}

// ─── DNS ──────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq)]
struct Resolution {
    /// `live`, `no-address`, `nxdomain` or `error`.
    status: &'static str,
    ips: Vec<String>,
    /// The last name in the CNAME chain.
    cname: Option<String>,
}

fn parse_doh(v: &Value) -> Resolution {
    let answers = v["Answer"].as_array().cloned().unwrap_or_default();
    let cname = answers
        .iter()
        .filter(|a| a["type"].as_u64() == Some(5))
        .filter_map(|a| a["data"].as_str())
        .map(|d| d.trim_end_matches('.').to_ascii_lowercase())
        .next_back();
    let ips: Vec<String> = answers
        .iter()
        .filter(|a| a["type"].as_u64() == Some(1))
        .filter_map(|a| a["data"].as_str().map(str::to_string))
        .collect();
    let status = match v["Status"].as_u64() {
        Some(0) if !ips.is_empty() => "live",
        Some(0) => "no-address",
        Some(3) => "nxdomain",
        _ => "error",
    };
    Resolution { status, ips, cname }
}

async fn resolve(client: &reqwest::Client, name: &str) -> Resolution {
    let url = format!(
        "https://cloudflare-dns.com/dns-query?name={}&type=A",
        urlencoding::encode(name)
    );
    match client
        .get(&url)
        .header("Accept", "application/dns-json")
        .send()
        .await
    {
        Ok(resp) => match resp.json::<Value>().await {
            Ok(v) => parse_doh(&v),
            Err(_) => Resolution {
                status: "error",
                ips: Vec::new(),
                cname: None,
            },
        },
        Err(_) => Resolution {
            status: "error",
            ips: Vec::new(),
            cname: None,
        },
    }
}

async fn resolve_all(names: Vec<String>) -> HashMap<String, Resolution> {
    let client = api_client(Duration::from_secs(4));
    stream::iter(names)
        .map(|name| {
            let client = client.clone();
            async move {
                let r = resolve(&client, &name).await;
                (name, r)
            }
        })
        .buffer_unordered(RESOLVE_CONCURRENCY)
        .collect()
        .await
}

// ─── Subdomain takeover ───────────────────────────────────────────────────

/// A service a CNAME can point at, and how an unclaimed one shows itself.
/// From the community list at github.com/EdOverflow/can-i-take-over-xyz.
struct Service {
    name: &'static str,
    suffixes: &'static [&'static str],
    /// Text on the page when nothing is claimed there.
    fingerprint: Option<&'static str>,
}

const SERVICES: &[Service] = &[
    Service {
        name: "GitHub Pages",
        suffixes: &[".github.io"],
        fingerprint: Some("There isn't a GitHub Pages site here"),
    },
    Service {
        name: "Heroku",
        suffixes: &[".herokuapp.com", ".herokudns.com", ".herokussl.com"],
        fingerprint: Some("no-such-app.html"),
    },
    Service {
        name: "Amazon S3",
        suffixes: &[".amazonaws.com"],
        fingerprint: Some("NoSuchBucket"),
    },
    Service {
        name: "AWS Elastic Beanstalk",
        suffixes: &[".elasticbeanstalk.com"],
        fingerprint: None,
    },
    Service {
        name: "Microsoft Azure",
        suffixes: &[
            ".azurewebsites.net",
            ".cloudapp.net",
            ".cloudapp.azure.com",
            ".trafficmanager.net",
            ".blob.core.windows.net",
            ".azure-api.net",
            ".azurefd.net",
            ".azurecontainer.io",
            ".azurehdinsight.net",
            ".azureedge.net",
        ],
        fingerprint: None,
    },
    Service {
        name: "Bitbucket",
        suffixes: &[".bitbucket.io"],
        fingerprint: Some("Repository not found"),
    },
    Service {
        name: "Ghost",
        suffixes: &[".ghost.io"],
        fingerprint: Some("Failed to resolve DNS path for this host"),
    },
    Service {
        name: "Surge.sh",
        suffixes: &[".surge.sh"],
        fingerprint: Some("project not found"),
    },
    Service {
        name: "Pantheon",
        suffixes: &[".pantheonsite.io"],
        fingerprint: Some("404 error unknown site!"),
    },
    Service {
        name: "Help Scout",
        suffixes: &[".helpscoutdocs.com"],
        fingerprint: Some("No settings were found for this company:"),
    },
    Service {
        name: "Shopify",
        suffixes: &[".myshopify.com"],
        fingerprint: Some("Sorry, this shop is currently unavailable."),
    },
    Service {
        name: "WordPress.com",
        suffixes: &[".wordpress.com"],
        fingerprint: Some("Do you want to register"),
    },
    Service {
        name: "Tumblr",
        suffixes: &["domains.tumblr.com"],
        fingerprint: Some("Whatever you were looking for doesn't currently exist at this address"),
    },
    Service {
        name: "ngrok",
        suffixes: &[".ngrok.io"],
        fingerprint: Some("ERR_NGROK_3200"),
    },
];

fn service_index(cname: &str) -> Option<usize> {
    SERVICES
        .iter()
        .position(|s| s.suffixes.iter().any(|suffix| cname.ends_with(suffix)))
}

fn service_for(cname: &str) -> Option<&'static Service> {
    service_index(cname).map(|i| &SERVICES[i])
}

/// What DNS alone says about a takeover, or `None`.
fn takeover_from_dns(subdomain: &str, r: &Resolution) -> Option<Value> {
    let cname = r.cname.as_deref()?;
    if r.status != "nxdomain" {
        return None;
    }
    Some(match service_for(cname) {
        Some(service) => json!({
            "subdomain": subdomain,
            "cname": cname,
            "service": service.name,
            "level": "likely",
            "evidence": format!("CNAME points to {cname} on {}, which doesn't exist. It may be claimable there.", service.name),
        }),
        None => json!({
            "subdomain": subdomain,
            "cname": cname,
            "service": null,
            "level": "check",
            "evidence": format!("CNAME points to {cname}, which doesn't resolve. If that domain is unregistered, it can be registered."),
        }),
    })
}

async fn takeover_from_page(
    client: &reqwest::Client,
    subdomain: &str,
    cname: &str,
    service: &'static Service,
) -> Option<Value> {
    let fingerprint = service.fingerprint?;
    for scheme in ["https", "http"] {
        let url = format!("{scheme}://{subdomain}/");
        if let Ok((_, _, body)) = fetch_limited(client, &url, 64 * 1024).await {
            if body.contains(fingerprint) {
                return Some(json!({
                    "subdomain": subdomain,
                    "cname": cname,
                    "service": service.name,
                    "level": "likely",
                    "evidence": format!("{} shows \"{fingerprint}\" at {url}, so nothing is claimed there.", service.name),
                }));
            }
            return None;
        }
    }
    None
}

async fn find_takeovers(resolved: &HashMap<String, Resolution>) -> (usize, Vec<Value>) {
    let mut found: Vec<Value> = Vec::new();
    // Services by index: a reference here trips a lifetime limit in the stream below.
    let mut to_fetch: Vec<(String, String, usize)> = Vec::new();
    let mut with_cname = 0usize;
    let mut names: Vec<&String> = resolved.keys().collect();
    names.sort();
    for name in names {
        let r = &resolved[name];
        let Some(cname) = r.cname.as_deref() else {
            continue;
        };
        with_cname += 1;
        if let Some(hit) = takeover_from_dns(name, r) {
            found.push(hit);
        } else if r.status == "live" {
            if let Some(index) = service_index(cname).filter(|i| SERVICES[*i].fingerprint.is_some())
            {
                to_fetch.push((name.clone(), cname.to_string(), index));
            }
        }
    }
    let client = target_client(Duration::from_secs(6));
    let fetched: Vec<Option<Value>> = stream::iter(to_fetch.into_iter().take(TAKEOVER_FETCH_LIMIT))
        .map(|(sub, cname, service)| {
            let client = client.clone();
            async move { takeover_from_page(&client, &sub, &cname, &SERVICES[service]).await }
        })
        .buffer_unordered(5)
        .collect()
        .await;
    found.extend(fetched.into_iter().flatten());
    found.sort_by(|a, b| {
        let rank = |v: &Value| if v["level"] == "likely" { 0 } else { 1 };
        rank(a)
            .cmp(&rank(b))
            .then_with(|| a["subdomain"].as_str().cmp(&b["subdomain"].as_str()))
    });
    (with_cname, found)
}

// ─── Wayback Machine ──────────────────────────────────────────────────────

const FILE_EXTENSIONS: &[&str] = &[
    "json", "xml", "txt", "log", "bak", "old", "backup", "swp", "sql", "db", "sqlite", "zip",
    "tar", "gz", "tgz", "rar", "7z", "env", "config", "conf", "cfg", "ini", "yml", "yaml", "toml",
    "pem", "key", "crt", "csv", "xls", "xlsx", "doc", "docx", "pdf", "php", "asp", "aspx", "jsp",
    "cgi", "pl", "sh", "map", "wsdl",
];

const PATH_KEYWORDS: &[&str] = &[
    "admin",
    "api",
    "graphql",
    "swagger",
    "openapi",
    "api-docs",
    "debug",
    "internal",
    "staging",
    "dev",
    "test",
    "backup",
    ".git",
    ".svn",
    ".env",
    "config",
    "console",
    "dashboard",
    "login",
    "signin",
    "oauth",
    "callback",
    "redirect",
    "return",
    "token",
    "reset",
    "upload",
    "download",
    "export",
    "import",
    "phpmyadmin",
    "wp-admin",
    "wp-json",
    "actuator",
    "server-status",
    "jenkins",
    "grafana",
    "kibana",
];

fn extension(path: &str) -> Option<String> {
    let last = path.rsplit('/').next()?;
    let (_, ext) = last.rsplit_once('.')?;
    (!ext.is_empty() && ext.len() <= 8).then(|| ext.to_ascii_lowercase())
}

fn has_keyword(path: &str) -> bool {
    path.to_ascii_lowercase().split('/').any(|segment| {
        PATH_KEYWORDS.iter().any(|kw| {
            segment == *kw
                || segment
                    .strip_prefix(kw)
                    .is_some_and(|rest| rest.starts_with(|c: char| !c.is_ascii_alphabetic()))
        })
    })
}

/// Sort archived URLs into the lists a hunter starts from.
fn categorize_urls(urls: Vec<String>) -> Value {
    let unique: BTreeSet<String> = urls.into_iter().collect();
    let total = unique.len();
    let mut with_params = Vec::new();
    let mut params = BTreeSet::new();
    let mut files = Vec::new();
    let mut scripts = Vec::new();
    let mut paths = Vec::new();
    for raw in &unique {
        let Ok(url) = url::Url::parse(raw) else {
            continue;
        };
        if url.query().is_some_and(|q| !q.is_empty()) {
            for (key, _) in url.query_pairs() {
                if !key.is_empty() && key.len() <= 64 {
                    params.insert(key.into_owned());
                }
            }
            if with_params.len() < WAYBACK_LIST_MAX {
                with_params.push(raw.clone());
            }
        }
        match extension(url.path()).as_deref() {
            Some("js") if scripts.len() < WAYBACK_LIST_MAX => scripts.push(raw.clone()),
            Some(ext) if FILE_EXTENSIONS.contains(&ext) && files.len() < WAYBACK_LIST_MAX => {
                files.push(raw.clone())
            }
            _ => {}
        }
        if has_keyword(url.path()) && paths.len() < WAYBACK_LIST_MAX {
            paths.push(raw.clone());
        }
    }
    json!({
        "total": total,
        "withParams": with_params,
        "paramNames": params.into_iter().take(WAYBACK_LIST_MAX).collect::<Vec<_>>(),
        "interestingFiles": files,
        "javascriptFiles": scripts,
        "interestingPaths": paths,
        "all": unique.into_iter().take(WAYBACK_LIMIT).collect::<Vec<_>>(),
    })
}

fn parse_cdx(rows: &Value) -> Vec<String> {
    rows.as_array()
        .map(|arr| {
            arr.iter()
                // The first row is the header.
                .skip(1)
                .filter_map(|row| row.get(0).and_then(|v| v.as_str()).map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

async fn wayback(host: &str) -> Result<(Vec<String>, bool), String> {
    let url = format!(
        "https://web.archive.org/cdx/search/cdx?url={}/*&output=json&fl=original&collapse=urlkey&limit={WAYBACK_LIMIT}",
        urlencoding::encode(host)
    );
    let rows = get_json(&api_client(Duration::from_secs(25)), &url).await?;
    let urls = parse_cdx(&rows);
    let full = urls.len() >= WAYBACK_LIMIT;
    Ok((urls, full))
}

fn parse_otx(page: &Value) -> (Vec<String>, bool) {
    let urls = page["url_list"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|u| u["url"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    (urls, page["has_next"].as_bool().unwrap_or(false))
}

/// URLs AlienVault OTX has seen for the host. Much faster than the Wayback
/// Machine, which is often busy for big sites.
async fn otx(host: &str) -> Result<Vec<String>, String> {
    let client = api_client(Duration::from_secs(10));
    let mut out = Vec::new();
    for page in 1..=OTX_PAGES {
        let url = format!(
            "https://otx.alienvault.com/api/v1/indicators/hostname/{}/url_list?limit=500&page={page}",
            urlencoding::encode(host)
        );
        match get_json(&client, &url).await {
            Ok(v) => {
                let (urls, more) = parse_otx(&v);
                out.extend(urls);
                if !more {
                    break;
                }
            }
            Err(e) if out.is_empty() => return Err(e),
            Err(_) => break,
        }
    }
    Ok(out)
}

async fn archived_urls(host: &str) -> Value {
    if let Some(hit) = ARCHIVES.get(host) {
        return hit;
    }
    let (wb, alien) = tokio::join!(wayback(host), otx(host));
    let mut urls = Vec::new();
    let mut sources = Vec::new();
    let mut errors = Vec::new();
    let mut truncated = false;
    match wb {
        Ok((found, full)) => {
            urls.extend(found);
            truncated = full;
            sources.push("Wayback Machine");
        }
        Err(e) => errors.push(format!("Wayback Machine: {e}")),
    }
    match alien {
        Ok(found) => {
            urls.extend(found);
            sources.push("AlienVault OTX");
        }
        Err(e) => errors.push(format!("AlienVault OTX: {e}")),
    }
    if sources.is_empty() {
        return json!({
            "available": false,
            "source": "Wayback Machine + AlienVault OTX",
            "error": errors.join("; "),
        });
    }
    let mut result = categorize_urls(urls);
    result["available"] = json!(true);
    result["source"] = json!(sources.join(" + "));
    result["partialErrors"] = json!(errors);
    result["truncated"] = json!(truncated);
    // Cache only complete answers, so a busy archive is tried again next time.
    if errors.is_empty() {
        ARCHIVES.put(host.to_string(), result.clone());
    }
    result
}

// ─── JavaScript ───────────────────────────────────────────────────────────

static SCRIPT_SRC: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?is)<script\b[^>]*\bsrc\s*=\s*["']?([^"'\s>]+)"#).expect("script regex")
});

static ENDPOINT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"["'`]((?:https?:)?//[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?:/[^"'`\s<>]*)?|/[A-Za-z0-9_\-][^"'`\s<>]{0,250})["'`]"#,
    )
    .expect("endpoint regex")
});

const STATIC_EXTENSIONS: &[&str] = &[
    "png", "jpg", "jpeg", "gif", "svg", "webp", "ico", "bmp", "css", "woff", "woff2", "ttf", "eot",
    "otf", "mp4", "webm", "mp3", "wav", "avif",
];

/// Keys that are secret when they show up in public JavaScript.
struct KeyPattern {
    kind: &'static str,
    pattern: &'static str,
    note: &'static str,
}

const KEY_PATTERNS: &[KeyPattern] = &[
    KeyPattern {
        kind: "AWS access key ID",
        pattern: r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b",
        note: "Look for the matching secret key nearby.",
    },
    KeyPattern {
        kind: "Google API key",
        pattern: r"\bAIza[0-9A-Za-z_\-]{35}\b",
        note: "Often meant to be public (Maps, Firebase). Check which APIs it can call and whether it's restricted.",
    },
    KeyPattern {
        kind: "GitHub token",
        pattern: r"\bgh[pousr]_[0-9A-Za-z]{36}\b",
        note: "Should never be in client code.",
    },
    KeyPattern {
        kind: "Slack token",
        pattern: r"\bxox[abprs]-[0-9A-Za-z\-]{10,}\b",
        note: "Should never be in client code.",
    },
    KeyPattern {
        kind: "Slack webhook",
        pattern: r"https://hooks\.slack\.com/services/T[0-9A-Za-z]+/B[0-9A-Za-z]+/[0-9A-Za-z]+",
        note: "Anyone can post to the channel with it.",
    },
    KeyPattern {
        kind: "Stripe live secret key",
        pattern: r"\b(?:sk|rk)_live_[0-9A-Za-z]{20,}\b",
        note: "Should never be in client code.",
    },
    KeyPattern {
        kind: "SendGrid API key",
        pattern: r"\bSG\.[0-9A-Za-z_\-]{22}\.[0-9A-Za-z_\-]{43}\b",
        note: "Should never be in client code.",
    },
    KeyPattern {
        kind: "Mailgun API key",
        pattern: r"\bkey-[0-9a-f]{32}\b",
        note: "Should never be in client code.",
    },
    KeyPattern {
        kind: "Private key",
        pattern: r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        note: "A private key block in public code.",
    },
    KeyPattern {
        kind: "Firebase database",
        pattern: r"https://[a-z0-9\-]+\.firebaseio\.com",
        note: "Check whether its rules allow public reads or writes.",
    },
];

static KEY_REGEXES: LazyLock<Vec<(&'static KeyPattern, Regex)>> = LazyLock::new(|| {
    KEY_PATTERNS
        .iter()
        .filter_map(|p| Regex::new(p.pattern).ok().map(|re| (p, re)))
        .collect()
});

/// Show enough of a key to recognise it, not enough to use it.
fn mask(value: &str) -> String {
    if value.starts_with("-----BEGIN") || value.starts_with("https://") {
        return value.to_string();
    }
    let chars: Vec<char> = value.chars().collect();
    if chars.len() <= 10 {
        return "****".to_string();
    }
    let head: String = chars[..4].iter().collect();
    let tail: String = chars[chars.len() - 4..].iter().collect();
    format!("{head}…{tail}")
}

fn is_endpoint(candidate: &str) -> bool {
    if candidate.len() < 2
        || candidate.contains('\\')
        || candidate.contains(['[', ']', '^', '|', '(', ')', '*'])
        // `$1` and the like are regex replacements, not paths.
        || candidate
            .as_bytes()
            .windows(2)
            .any(|w| w[0] == b'$' && w[1].is_ascii_digit())
    {
        return false;
    }
    let path = candidate.split(['?', '#']).next().unwrap_or(candidate);
    !extension(path).is_some_and(|ext| STATIC_EXTENSIONS.contains(&ext.as_str()))
}

fn endpoints_in(text: &str) -> Vec<String> {
    ENDPOINT
        .captures_iter(text)
        .filter_map(|c| c.get(1).map(|m| m.as_str().to_string()))
        .filter(|s| is_endpoint(s))
        .collect()
}

fn keys_in(text: &str, source: &str) -> Vec<Value> {
    let mut out = Vec::new();
    for (pattern, re) in KEY_REGEXES.iter() {
        for m in re.find_iter(text).take(5) {
            out.push(json!({
                "kind": pattern.kind,
                "masked": mask(m.as_str()),
                "source": source,
                "note": pattern.note,
            }));
        }
    }
    out
}

fn first_party_scripts(html: &str, page_url: &str, root: &str) -> Vec<String> {
    let Ok(base) = url::Url::parse(page_url) else {
        return Vec::new();
    };
    let mut out: Vec<String> = Vec::new();
    for cap in SCRIPT_SRC.captures_iter(html) {
        let Some(src) = cap.get(1).map(|m| m.as_str()) else {
            continue;
        };
        let Ok(url) = base.join(src) else {
            continue;
        };
        let host = url.host_str().unwrap_or("").to_ascii_lowercase();
        let first_party = host == root || host.ends_with(&format!(".{root}"));
        let s = url.to_string();
        if first_party && check_url(&s).is_ok() && !out.contains(&s) {
            out.push(s);
        }
        if out.len() >= MAX_SCRIPTS {
            break;
        }
    }
    out
}

async fn analyze_javascript(page_url: &str, root: &str) -> Value {
    let client = target_client(Duration::from_secs(10));
    let (final_url, html) = match fetch_limited(&client, page_url, MAX_PAGE_BYTES).await {
        Ok((final_url, _, html)) => (final_url, html),
        Err(e) => {
            return json!({
                "available": false,
                "error": format!("The page couldn't be fetched: {e}"),
            })
        }
    };
    let scripts = first_party_scripts(&html, &final_url, root);
    let fetched: Vec<(String, Result<String, String>)> = stream::iter(scripts)
        .map(|src| {
            let client = client.clone();
            async move {
                let body = fetch_limited(&client, &src, MAX_SCRIPT_BYTES)
                    .await
                    .and_then(|(_, status, body)| {
                        if (200..300).contains(&status) {
                            Ok(body)
                        } else {
                            Err(format!("HTTP {status}"))
                        }
                    });
                (src, body)
            }
        })
        .buffer_unordered(4)
        .collect()
        .await;

    let mut endpoints = BTreeSet::new();
    let mut keys = keys_in(&html, "inline");
    endpoints.extend(endpoints_in(&html));
    let mut scanned = Vec::new();
    for (src, body) in fetched {
        match body {
            Ok(text) => {
                endpoints.extend(endpoints_in(&text));
                keys.extend(keys_in(&text, &src));
                scanned.push(json!({ "url": src, "bytes": text.len(), "status": "read" }));
            }
            Err(e) => scanned.push(json!({ "url": src, "status": "failed", "error": e })),
        }
    }
    let mut seen = BTreeSet::new();
    keys.retain(|k| seen.insert((k["kind"].to_string(), k["masked"].to_string())));
    let total = endpoints.len();
    json!({
        "available": true,
        "pageUrl": final_url,
        "scripts": scanned,
        "endpointCount": total,
        "endpoints": endpoints.into_iter().take(MAX_ENDPOINTS).collect::<Vec<_>>(),
        "exposedKeys": keys,
    })
}

// ─── The report ───────────────────────────────────────────────────────────

/// The subdomain list for a report, with DNS facts where they were looked up.
fn subdomain_items(subdomains: &[String], resolved: &HashMap<String, Resolution>) -> Vec<Value> {
    subdomains
        .iter()
        .map(|name| match resolved.get(name) {
            Some(r) => json!({ "name": name, "status": r.status, "ips": r.ips, "cname": r.cname }),
            None => json!({ "name": name, "status": "unchecked", "ips": [], "cname": null }),
        })
        .collect()
}

/// `GET /api/v1/analysis/web-recon?url=...`
pub async fn inspect_url_web_recon(
    _claims: Option<crate::middleware::auth::Claims>,
    Query(query): Query<WebIntelQuery>,
) -> Result<Json<Value>, StatusCode> {
    Ok(Json(run_recon(&query.url).await?))
}

pub async fn run_recon(raw_url: &str) -> Result<Value, StatusCode> {
    let started = Instant::now();
    let (url, host, _origin) = normalize_target_url(raw_url)?;
    let root = registrable_domain(&host);

    let (enumeration, archive, javascript) = tokio::join!(
        enumerate_subdomains(&root),
        archived_urls(&host),
        analyze_javascript(url.as_str(), &root),
    );

    let to_check: Vec<String> = enumeration
        .subdomains
        .iter()
        .take(RESOLVE_LIMIT)
        .cloned()
        .collect();
    let resolved = resolve_all(to_check).await;
    let (with_cname, takeovers) = find_takeovers(&resolved).await;
    let live = resolved.values().filter(|r| r.status == "live").count();

    Ok(json!({
        "targetUrl": url.to_string(),
        "host": host,
        "rootDomain": root,
        "scannedAt": chrono::Utc::now().to_rfc3339(),
        "durationMs": started.elapsed().as_millis() as u64,
        "subdomains": {
            "available": enumeration.available,
            "source": enumeration.source,
            "error": enumeration.error,
            "total": enumeration.total,
            "truncated": enumeration.total > enumeration.subdomains.len(),
            "checked": resolved.len(),
            "live": live,
            "items": subdomain_items(&enumeration.subdomains, &resolved),
        },
        "takeovers": {
            "checked": resolved.len(),
            "withCname": with_cname,
            "candidates": takeovers,
        },
        "archivedUrls": archive,
        "javascript": javascript,
        "scope": "Only test what a program's scope allows. Read the target's security.txt and bug bounty policy first.",
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registrable_domain_uses_the_public_suffix_list() {
        assert_eq!(registrable_domain("a.b.example.co.uk"), "example.co.uk");
        assert_eq!(
            registrable_domain("wallet.apps.sandbox.nwb.youniqx.com"),
            "youniqx.com"
        );
        assert_eq!(registrable_domain("someone.github.io"), "someone.github.io");
        assert_eq!(registrable_domain("Example.COM."), "example.com");
        assert_eq!(registrable_domain("203.0.113.7"), "203.0.113.7");
    }

    #[test]
    fn only_real_subdomains_of_the_root_are_kept() {
        assert_eq!(
            clean_name("*.api.example.com", "example.com").as_deref(),
            Some("api.example.com")
        );
        assert_eq!(
            clean_name("WWW.Example.com.", "example.com").as_deref(),
            Some("www.example.com")
        );
        assert_eq!(clean_name("example.com", "example.com"), None);
        // The old check matched any name ending in the root's text.
        assert_eq!(clean_name("notexample.com", "example.com"), None);
        assert_eq!(clean_name("admin@example.com", "example.com"), None);
        assert_eq!(clean_name("bad name.example.com", "example.com"), None);
    }

    #[test]
    fn certspotter_pages_parse_with_the_id_to_continue_from() {
        let page = json!([
            {"id": "1", "dns_names": ["a.example.com", "*.example.com"], "issuer": {"name": "C=US, O=Let's Encrypt, CN=R11"}, "not_before": "2026-01-01T00:00:00Z", "not_after": "2026-04-01T00:00:00Z"},
            {"id": "2", "dns_names": ["b.example.com"], "issuer": {"friendly_name": "DigiCert"}, "not_before": "2026-02-01T00:00:00Z", "not_after": "2027-02-01T00:00:00Z"}
        ]);
        let (entries, last) = parse_certspotter(&page);
        assert_eq!(entries.len(), 2);
        assert_eq!(last.as_deref(), Some("2"));
        assert_eq!(entries[1].issuer.as_deref(), Some("DigiCert"));
        let e = enumeration_from(CERTSPOTTER, "example.com", entries);
        assert_eq!(e.subdomains, vec!["a.example.com", "b.example.com"]);
        assert_eq!(e.total, 2);
    }

    #[test]
    fn crtsh_rows_split_names_on_new_lines() {
        let rows = json!([{"name_value": "x.example.com\n*.y.example.com\nother.org", "issuer_name": "CA", "not_before": "2025-01-01T00:00:00", "not_after": "2025-06-01T00:00:00"}]);
        let e = enumeration_from(CRTSH, "example.com", parse_crtsh(&rows));
        assert_eq!(e.subdomains, vec!["x.example.com", "y.example.com"]);
    }

    #[test]
    fn the_host_certificate_is_the_newest_unexpired_one_covering_it() {
        let certs = vec![
            CertEntry {
                names: vec!["*.example.com".into()],
                issuer: Some("old".into()),
                not_before: Some("2020-01-01T00:00:00Z".into()),
                not_after: Some("2020-04-01T00:00:00Z".into()),
            },
            CertEntry {
                names: vec!["*.example.com".into()],
                issuer: Some("current".into()),
                not_before: Some("2026-01-01T00:00:00Z".into()),
                not_after: Some("2099-01-01T00:00:00Z".into()),
            },
            CertEntry {
                names: vec!["other.example.com".into()],
                issuer: Some("wrong host".into()),
                not_before: Some("2026-06-01T00:00:00Z".into()),
                not_after: Some("2099-01-01T00:00:00Z".into()),
            },
        ];
        let cert = certificate_for_host(&certs, "www.example.com").unwrap();
        assert_eq!(cert.issuer.as_deref(), Some("current"));
        // A wildcard covers one label only.
        assert!(certificate_for_host(&certs, "a.b.example.com").is_none());
    }

    #[test]
    fn doh_answers_give_status_addresses_and_the_last_cname() {
        let live = parse_doh(&json!({"Status": 0, "Answer": [
            {"type": 5, "data": "edge.example.net."},
            {"type": 5, "data": "Final.CDN.net."},
            {"type": 1, "data": "198.51.100.4"}
        ]}));
        assert_eq!(live.status, "live");
        assert_eq!(live.cname.as_deref(), Some("final.cdn.net"));
        assert_eq!(live.ips, vec!["198.51.100.4"]);

        let dangling = parse_doh(
            &json!({"Status": 3, "Answer": [{"type": 5, "data": "gone.herokuapp.com."}]}),
        );
        assert_eq!(dangling.status, "nxdomain");
        assert_eq!(parse_doh(&json!({"Status": 2})).status, "error");
        assert_eq!(parse_doh(&json!({"Status": 0})).status, "no-address");
    }

    #[test]
    fn a_dangling_cname_is_a_takeover_candidate() {
        let heroku = Resolution {
            status: "nxdomain",
            ips: vec![],
            cname: Some("gone.herokuapp.com".into()),
        };
        let hit = takeover_from_dns("shop.example.com", &heroku).unwrap();
        assert_eq!(hit["level"], "likely");
        assert_eq!(hit["service"], "Heroku");

        let unknown = Resolution {
            status: "nxdomain",
            ips: vec![],
            cname: Some("old-vendor.net".into()),
        };
        assert_eq!(
            takeover_from_dns("x.example.com", &unknown).unwrap()["level"],
            "check"
        );

        let fine = Resolution {
            status: "live",
            ips: vec!["198.51.100.4".into()],
            cname: Some("site.github.io".into()),
        };
        assert!(takeover_from_dns("docs.example.com", &fine).is_none());
        assert_eq!(service_for("site.github.io").unwrap().name, "GitHub Pages");
        assert!(service_for("cdn.example.net").is_none());
    }

    #[test]
    fn archived_urls_are_sorted_into_useful_lists() {
        let urls = vec![
            "https://example.com/search?q=1&page=2".to_string(),
            "https://example.com/static/app.js".to_string(),
            "https://example.com/backup/db.sql".to_string(),
            "https://example.com/api/v1/users".to_string(),
            "https://example.com/rapid/news".to_string(),
            "https://example.com/admin.php".to_string(),
            "https://example.com/search?q=1&page=2".to_string(),
        ];
        let v = categorize_urls(urls);
        assert_eq!(v["total"], 6);
        assert_eq!(v["paramNames"], json!(["page", "q"]));
        assert_eq!(
            v["javascriptFiles"],
            json!(["https://example.com/static/app.js"])
        );
        let files = v["interestingFiles"].as_array().unwrap();
        assert!(files
            .iter()
            .any(|f| f == "https://example.com/backup/db.sql"));
        assert!(files.iter().any(|f| f == "https://example.com/admin.php"));
        let paths = v["interestingPaths"].as_array().unwrap();
        assert!(paths
            .iter()
            .any(|p| p == "https://example.com/api/v1/users"));
        assert!(paths.iter().any(|p| p == "https://example.com/admin.php"));
        // "rapid" isn't "api".
        assert!(!paths.iter().any(|p| p == "https://example.com/rapid/news"));
    }

    #[test]
    fn otx_pages_give_urls_and_whether_there_are_more() {
        let page = json!({"url_list": [{"url": "https://example.com/a?x=1"}, {"url": "https://example.com/b"}], "has_next": true});
        let (urls, more) = parse_otx(&page);
        assert_eq!(
            urls,
            vec!["https://example.com/a?x=1", "https://example.com/b"]
        );
        assert!(more);
        assert_eq!(parse_otx(&json!({})), (Vec::<String>::new(), false));
    }

    #[test]
    fn cdx_rows_skip_the_header() {
        let rows = json!([
            ["original"],
            ["https://example.com/a"],
            ["https://example.com/b"]
        ]);
        assert_eq!(
            parse_cdx(&rows),
            vec!["https://example.com/a", "https://example.com/b"]
        );
    }

    #[test]
    fn javascript_endpoints_skip_assets_and_regexes() {
        let js = r#"fetch("/api/v2/orders?id=1"); const u = '/static/logo.png'; x = "https://api.example.com/graphql"; r = "/[a-z]+/"; p = `/users/${id}`; s = "/ajax$1"; q = "//cdn.example.com/lib"; "/""#;
        let found = endpoints_in(js);
        assert!(found.contains(&"/api/v2/orders?id=1".to_string()));
        assert!(found.contains(&"https://api.example.com/graphql".to_string()));
        assert!(found.contains(&"//cdn.example.com/lib".to_string()));
        assert!(found.contains(&"/users/${id}".to_string()));
        assert!(!found.iter().any(|f| f.ends_with(".png")));
        assert!(!found.iter().any(|f| f.contains('[')));
        assert!(!found.iter().any(|f| f == "/ajax$1"));
    }

    #[test]
    fn exposed_keys_are_found_and_masked() {
        let js = "var k='AKIAABCDEFGHIJKLMNOP'; var g=\"AIzaSyA1234567890abcdefghijklmnopqrstuv\";";
        let keys = keys_in(js, "https://example.com/app.js");
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0]["kind"], "AWS access key ID");
        assert_eq!(keys[0]["masked"], "AKIA…MNOP");
        assert!(!keys[0]["masked"].as_str().unwrap().contains("BCDEFGHIJKL"));
        assert_eq!(keys[1]["kind"], "Google API key");
        assert_eq!(mask("short"), "****");
    }

    #[test]
    fn only_first_party_scripts_are_read() {
        let html = r#"<script src="/app.js"></script><script src="https://cdn.other.com/x.js"></script>
            <script src="https://static.example.com/b.js"></script><script src="http://127.0.0.1/evil.js"></script>"#;
        let scripts = first_party_scripts(html, "https://www.example.com/", "example.com");
        assert_eq!(
            scripts,
            vec![
                "https://www.example.com/app.js",
                "https://static.example.com/b.js"
            ]
        );
    }

    #[test]
    fn unchecked_subdomains_say_so() {
        let mut resolved = HashMap::new();
        resolved.insert(
            "a.example.com".to_string(),
            Resolution {
                status: "live",
                ips: vec!["198.51.100.4".into()],
                cname: None,
            },
        );
        let items = subdomain_items(&["a.example.com".into(), "b.example.com".into()], &resolved);
        assert_eq!(items[0]["status"], "live");
        assert_eq!(items[1]["status"], "unchecked");
    }
}

/// Against the real services. `cargo test -p api-gateway --bins live_recon -- --ignored --nocapture`
#[cfg(test)]
mod live {
    #[tokio::test]
    #[ignore = "needs the network"]
    async fn live_recon_finds_subdomains() {
        let target = std::env::var("RECON_URL").unwrap_or_else(|_| {
            "https://wallet-backend-sandbox.apps.sandbox.nwb.youniqx.com/status-lists".to_string()
        });
        let report = super::run_recon(&target).await.unwrap();
        let subs = &report["subdomains"];
        println!(
            "source={} total={} checked={} live={} takeovers={} archived={:?} endpoints={:?} keys={} took={}ms",
            subs["source"],
            subs["total"],
            subs["checked"],
            subs["live"],
            report["takeovers"]["candidates"].as_array().map(|a| a.len()).unwrap_or(0),
            report["archivedUrls"]["total"],
            report["javascript"]["endpointCount"],
            report["javascript"]["exposedKeys"].as_array().map(|a| a.len()).unwrap_or(0),
            report["durationMs"],
        );
        assert_eq!(subs["available"], true);
        println!(
            "archive error={} js error={} first endpoints={:?}",
            report["archivedUrls"]["error"],
            report["javascript"]["error"],
            report["javascript"]["endpoints"]
                .as_array()
                .map(|a| a.iter().take(8).collect::<Vec<_>>())
        );
    }
}
