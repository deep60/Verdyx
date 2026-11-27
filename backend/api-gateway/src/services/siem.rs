//! SIEM destinations: Splunk (HTTP Event Collector) and Microsoft Sentinel
//! (Azure Monitor Logs Ingestion API).
//!
//! They are webhooks of another `kind`, so they share the outbox, the events,
//! the retries and the SSRF-safe client in `webhook_delivery`. What differs is
//! the request: Splunk wants the event wrapped for HEC with its token, and
//! Sentinel wants flat rows sent with an Entra ID access token.
//!
//! The credential each needs (the HEC token, the Entra app's client key) is
//! stored sealed with AES-256-GCM and never returned by the API.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use base64::Engine as _;
use chrono::{DateTime, Utc};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, NONCE_LEN};
use ring::rand::{SecureRandom, SystemRandom};
use serde_json::{json, Map, Value};

pub const KIND_WEBHOOK: &str = "webhook";
pub const KIND_SPLUNK: &str = "splunk";
pub const KIND_SENTINEL: &str = "sentinel";

pub const DEFAULT_SOURCETYPE: &str = "verdyx:event";
pub const DEFAULT_SOURCE: &str = "verdyx";
pub const DEFAULT_STREAM: &str = "Custom-VerdyxEvents_CL";
const LOGS_API_VERSION: &str = "2023-01-01";
const MAX_CREDENTIAL: usize = 512;

// ─── Credentials at rest ─────────────────────────────────────────────────

/// The key that seals stored credentials. Derived with HKDF from
/// `INTEGRATION_ENCRYPTION_KEY` when set, otherwise from the gateway's JWT
/// signing key, so no new setting is needed to start. Changing whichever is
/// used makes stored credentials unreadable: they then have to be entered
/// again.
pub struct CredentialKey(LessSafeKey);

impl CredentialKey {
    pub fn from_config(jwt_signing_key: &str) -> Self {
        let ikm = std::env::var("INTEGRATION_ENCRYPTION_KEY")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .unwrap_or_else(|| jwt_signing_key.to_string());
        Self::derive(ikm.as_bytes())
    }

    pub fn derive(ikm: &[u8]) -> Self {
        let salt = ring::hkdf::Salt::new(ring::hkdf::HKDF_SHA256, b"verdyx-integrations-v1");
        let prk = salt.extract(ikm);
        let okm = prk
            .expand(&[b"credential"], &AES_256_GCM)
            .expect("HKDF output length matches AES-256");
        let key: UnboundKey = okm.into();
        Self(LessSafeKey::new(key))
    }

    /// `v1:<base64(nonce || ciphertext || tag)>`
    pub fn seal(&self, plaintext: &str) -> String {
        let mut nonce = [0u8; NONCE_LEN];
        SystemRandom::new()
            .fill(&mut nonce)
            .expect("system randomness");
        let mut buf = plaintext.as_bytes().to_vec();
        self.0
            .seal_in_place_append_tag(Nonce::assume_unique_for_key(nonce), Aad::empty(), &mut buf)
            .expect("AES-GCM seal");
        let mut out = nonce.to_vec();
        out.extend_from_slice(&buf);
        format!(
            "v1:{}",
            base64::engine::general_purpose::STANDARD.encode(out)
        )
    }

    pub fn open(&self, sealed: &str) -> Option<String> {
        let raw = base64::engine::general_purpose::STANDARD
            .decode(sealed.strip_prefix("v1:")?)
            .ok()?;
        if raw.len() < NONCE_LEN {
            return None;
        }
        let (nonce, rest) = raw.split_at(NONCE_LEN);
        let mut buf = rest.to_vec();
        let plain = self
            .0
            .open_in_place(
                Nonce::try_assume_unique_for_key(nonce).ok()?,
                Aad::empty(),
                &mut buf,
            )
            .ok()?;
        String::from_utf8(plain.to_vec()).ok()
    }
}

// ─── Settings ─────────────────────────────────────────────────────────────

pub fn is_kind(kind: &str) -> bool {
    matches!(kind, KIND_WEBHOOK | KIND_SPLUNK | KIND_SENTINEL)
}

fn string_field<'a>(config: &'a Map<String, Value>, key: &str) -> Result<Option<&'a str>, String> {
    match config.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) if s.trim().is_empty() => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.trim())),
        Some(_) => Err(format!("{key} must be text")),
    }
}

fn token_ok(s: &str, max: usize, extra: &[char]) -> bool {
    !s.is_empty()
        && s.len() <= max
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || extra.contains(&c))
}

fn is_guid(s: &str) -> bool {
    uuid::Uuid::parse_str(s).is_ok() && s.len() == 36
}

/// The Azure cloud a Logs Ingestion endpoint belongs to: (sign-in host, token scope).
fn azure_cloud(host: &str) -> Option<(&'static str, &'static str)> {
    let host = host.to_ascii_lowercase();
    if host.ends_with(".ingest.monitor.azure.com") {
        Some((
            "login.microsoftonline.com",
            "https://monitor.azure.com//.default",
        ))
    } else if host.ends_with(".ingest.monitor.azure.us") {
        Some((
            "login.microsoftonline.us",
            "https://monitor.azure.us//.default",
        ))
    } else if host.ends_with(".ingest.monitor.azure.cn") {
        Some((
            "login.chinacloudapi.cn",
            "https://monitor.azure.cn//.default",
        ))
    } else {
        None
    }
}

/// Check a destination's URL and settings, returning the settings to store
/// (only known keys, defaults filled in). `has_credential` says whether a
/// credential is stored or being set.
pub fn validate(
    kind: &str,
    url: &str,
    config: &Value,
    has_credential: bool,
) -> Result<Value, String> {
    let parsed = super::webhook_delivery::check_url(url).map_err(str::to_string)?;
    let empty = Map::new();
    let cfg = match config {
        Value::Object(m) => m,
        Value::Null => &empty,
        _ => return Err("settings must be an object".into()),
    };
    match kind {
        KIND_WEBHOOK => Ok(json!({})),
        KIND_SPLUNK => {
            if parsed.scheme() != "https" {
                return Err(
                    "the Splunk HEC URL must use https:// so the token is never sent in the clear"
                        .into(),
                );
            }
            hec_url(url)?;
            if !has_credential {
                return Err("enter the HEC token".into());
            }
            let mut out = Map::new();
            if let Some(index) = string_field(cfg, "index")? {
                if !token_ok(index, 80, &[]) {
                    return Err("the index name can use letters, digits, _ and -".into());
                }
                out.insert("index".into(), json!(index));
            }
            let sourcetype = string_field(cfg, "sourcetype")?.unwrap_or(DEFAULT_SOURCETYPE);
            if !token_ok(sourcetype, 100, &[':', '.']) {
                return Err("the sourcetype can use letters, digits, _ - : and .".into());
            }
            out.insert("sourcetype".into(), json!(sourcetype));
            let source = string_field(cfg, "source")?.unwrap_or(DEFAULT_SOURCE);
            if !token_ok(source, 100, &[':', '.', '/']) {
                return Err("the source can use letters, digits, _ - : . and /".into());
            }
            out.insert("source".into(), json!(source));
            Ok(Value::Object(out))
        }
        KIND_SENTINEL => {
            if parsed.scheme() != "https" {
                return Err("the data collection endpoint must use https://".into());
            }
            let host = parsed.host_str().unwrap_or_default();
            if azure_cloud(host).is_none() {
                return Err("use the data collection endpoint's Logs Ingestion URL, ending in .ingest.monitor.azure.com".into());
            }
            if parsed.path() != "/" && !parsed.path().is_empty() {
                return Err(
                    "enter the endpoint without a path; the rule and stream go in their own fields"
                        .into(),
                );
            }
            if !has_credential {
                return Err("enter the app's client secret".into());
            }
            let tenant = string_field(cfg, "tenantId")?.ok_or("enter the Entra tenant ID")?;
            let client = string_field(cfg, "clientId")?.ok_or("enter the app's client ID")?;
            let dcr = string_field(cfg, "dcrImmutableId")?
                .ok_or("enter the data collection rule's immutable ID")?;
            let stream = string_field(cfg, "streamName")?.unwrap_or(DEFAULT_STREAM);
            if !is_guid(tenant) {
                return Err(
                    "the tenant ID is a GUID, like 00000000-0000-0000-0000-000000000000".into(),
                );
            }
            if !is_guid(client) {
                return Err(
                    "the client ID is a GUID, like 00000000-0000-0000-0000-000000000000".into(),
                );
            }
            let dcr_ok = dcr.len() == 36
                && dcr.starts_with("dcr-")
                && dcr[4..].chars().all(|c| c.is_ascii_hexdigit());
            if !dcr_ok {
                return Err(
                    "the immutable ID looks like dcr-0123456789abcdef0123456789abcdef".into(),
                );
            }
            let stream_ok = stream
                .strip_prefix("Custom-")
                .is_some_and(|rest| token_ok(rest, 100, &[]) && !rest.contains('-'));
            if !stream_ok {
                return Err(
                    "the stream name starts with Custom-, like Custom-VerdyxEvents_CL".into(),
                );
            }
            Ok(json!({
                "tenantId": tenant.to_ascii_lowercase(),
                "clientId": client.to_ascii_lowercase(),
                "dcrImmutableId": dcr.to_ascii_lowercase(),
                "streamName": stream,
            }))
        }
        _ => Err("unknown destination type".into()),
    }
}

/// The HEC event endpoint for what the user entered: a base URL gets
/// `/services/collector/event`; a `/services/collector` path gets `/event`.
pub fn hec_url(raw: &str) -> Result<url::Url, String> {
    let mut url = super::webhook_delivery::check_url(raw).map_err(str::to_string)?;
    let path = url.path().trim_end_matches('/').to_string();
    let path = if path.is_empty() {
        "/services/collector/event".to_string()
    } else if path.ends_with("/services/collector") {
        format!("{path}/event")
    } else if path.ends_with("/services/collector/event") {
        path
    } else {
        return Err(
            "the HEC URL is the Splunk server, like https://splunk.example.com:8088".into(),
        );
    };
    url.set_path(&path);
    url.set_query(None);
    Ok(url)
}

// ─── Request bodies ───────────────────────────────────────────────────────

/// A Splunk HEC event wrapping the webhook envelope.
pub fn splunk_event(config: &Value, created_at: DateTime<Utc>, envelope: &Value) -> Value {
    let mut ev = json!({
        "time": created_at.timestamp_millis() as f64 / 1000.0,
        "host": "verdyx.dev",
        "source": config.get("source").and_then(Value::as_str).unwrap_or(DEFAULT_SOURCE),
        "sourcetype": config.get("sourcetype").and_then(Value::as_str).unwrap_or(DEFAULT_SOURCETYPE),
        "event": envelope,
    });
    if let Some(index) = config.get("index").and_then(Value::as_str) {
        ev["index"] = json!(index);
    }
    ev
}

/// One Sentinel row: the fields people filter on as columns, and the whole
/// event in `Data`. Matches the table in docs/integrations/sentinel.md.
pub fn sentinel_record(envelope: &Value) -> Value {
    let data = &envelope["data"];
    let text = |k: &str| data.get(k).and_then(Value::as_str);
    json!({
        "TimeGenerated": envelope["createdAt"],
        "EventId": envelope["id"],
        "EventType": envelope["event"],
        "SubmissionId": text("submissionId"),
        "Target": text("target"),
        "Sha256": text("sha256"),
        "IsMalicious": data.get("isMalicious").and_then(Value::as_bool),
        "Confidence": data.get("confidence").and_then(Value::as_f64),
        "HuntName": text("huntName"),
        "Rules": data.get("rules").cloned().unwrap_or(Value::Null),
        "ReportUrl": text("reportUrl"),
        "Data": data,
    })
}

// ─── Sending ──────────────────────────────────────────────────────────────

/// Entra ID access tokens, kept until shortly before they expire.
fn token_cache() -> &'static Mutex<HashMap<String, (String, Instant)>> {
    static CACHE: OnceLock<Mutex<HashMap<String, (String, Instant)>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn cache_key(tenant: &str, client: &str, credential: &str) -> String {
    use ring::digest::{digest, SHA256};
    hex::encode(digest(
        &SHA256,
        format!("{tenant}|{client}|{credential}").as_bytes(),
    ))
}

/// Why a token request failed, for the delivery log, without the response
/// body (which can echo the request).
pub async fn entra_token(
    http: &reqwest::Client,
    login_base: &str,
    scope: &str,
    tenant: &str,
    client: &str,
    credential: &str,
) -> Result<String, String> {
    let key = cache_key(tenant, client, credential);
    if let Some((token, until)) = token_cache().lock().unwrap().get(&key).cloned() {
        if Instant::now() < until {
            return Ok(token);
        }
    }
    let url = format!(
        "{}/{tenant}/oauth2/v2.0/token",
        login_base.trim_end_matches('/')
    );
    let resp = http
        .post(url)
        .form(&[
            ("grant_type", "client_credentials"),
            ("client_id", client),
            ("client_secret", credential),
            ("scope", scope),
        ])
        .send()
        .await
        .map_err(|e| {
            format!(
                "Entra ID sign-in failed: {}",
                super::webhook_delivery::describe(&e)
            )
        })?;
    let status = resp.status();
    let body: Value = resp.json().await.unwrap_or(Value::Null);
    if !status.is_success() {
        let code = body
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("unknown_error");
        return Err(format!(
            "Entra ID refused the app (HTTP {}, {code})",
            status.as_u16()
        ));
    }
    let token = body
        .get("access_token")
        .and_then(Value::as_str)
        .ok_or("Entra ID sent no access token")?
        .to_string();
    let ttl = body
        .get("expires_in")
        .and_then(Value::as_u64)
        .unwrap_or(3600);
    let until = Instant::now() + Duration::from_secs(ttl.saturating_sub(300).max(60));
    token_cache()
        .lock()
        .unwrap()
        .insert(key, (token.clone(), until));
    Ok(token)
}

fn forget_token(tenant: &str, client: &str, credential: &str) {
    token_cache()
        .lock()
        .unwrap()
        .remove(&cache_key(tenant, client, credential));
}

/// What to send to a SIEM destination: the request to make, ready to send.
#[allow(clippy::too_many_arguments)]
pub async fn request(
    http: &reqwest::Client,
    kind: &str,
    url: &str,
    config: &Value,
    credential: Option<&str>,
    created_at: DateTime<Utc>,
    envelope: &Value,
    login_base_override: Option<&str>,
) -> Result<reqwest::RequestBuilder, String> {
    let credential = credential
        .filter(|c| !c.is_empty())
        .ok_or("no credential is stored for this destination (or it can no longer be read): enter it again")?;
    match kind {
        KIND_SPLUNK => Ok(http
            .post(hec_url(url)?)
            .header(
                reqwest::header::AUTHORIZATION,
                format!("Splunk {credential}"),
            )
            .json(&splunk_event(config, created_at, envelope))),
        KIND_SENTINEL => {
            let base = super::webhook_delivery::check_url(url).map_err(str::to_string)?;
            let (login, scope) = azure_cloud(base.host_str().unwrap_or_default())
                .ok_or("not an Azure Logs Ingestion endpoint")?;
            let field = |k: &str| config.get(k).and_then(Value::as_str).unwrap_or_default();
            let (tenant, client) = (field("tenantId"), field("clientId"));
            let login_base = login_base_override
                .map(str::to_string)
                .unwrap_or_else(|| format!("https://{login}"));
            let token = entra_token(http, &login_base, scope, tenant, client, credential).await?;
            let stream = config
                .get("streamName")
                .and_then(Value::as_str)
                .unwrap_or(DEFAULT_STREAM);
            let target = format!(
                "{}/dataCollectionRules/{}/streams/{}?api-version={LOGS_API_VERSION}",
                url.trim_end_matches('/'),
                field("dcrImmutableId"),
                stream
            );
            Ok(http
                .post(target)
                .bearer_auth(token)
                .json(&json!([sentinel_record(envelope)])))
        }
        _ => Err("unknown destination type".into()),
    }
}

/// After a Sentinel 401/403, sign in again next time rather than reuse a
/// token that was revoked or lacks the role.
pub fn after_refusal(kind: &str, config: &Value, credential: Option<&str>) {
    if kind == KIND_SENTINEL {
        let field = |k: &str| config.get(k).and_then(Value::as_str).unwrap_or_default();
        forget_token(
            field("tenantId"),
            field("clientId"),
            credential.unwrap_or_default(),
        );
    }
}

/// A short hint for common refusals, added to the delivery log.
pub fn hint(kind: &str, status: u16) -> Option<&'static str> {
    match (kind, status) {
        (KIND_SPLUNK, 401 | 403) => Some("Splunk refused the HEC token"),
        (KIND_SPLUNK, 400) => {
            Some("Splunk rejected the event; check the index is allowed for this token")
        }
        (KIND_SENTINEL, 403) => {
            Some("the app needs the Monitoring Metrics Publisher role on the data collection rule")
        }
        (KIND_SENTINEL, 404) => Some("the data collection rule or stream wasn't found"),
        (KIND_SENTINEL, 400) => {
            Some("the stream's columns don't match; see docs/integrations/sentinel.md")
        }
        _ => None,
    }
}

pub fn credential_ok(c: &str) -> bool {
    !c.is_empty() && c.len() <= MAX_CREDENTIAL && !c.chars().any(char::is_whitespace)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TENANT: &str = "72f988bf-86f1-41af-91ab-2d7cd011db47";
    const CLIENT: &str = "11111111-2222-3333-4444-555555555555";
    const DCR: &str = "dcr-0123456789abcdef0123456789abcdef";

    #[test]
    fn credentials_are_sealed_and_only_the_same_key_opens_them() {
        let k = CredentialKey::derive(b"one key");
        let sealed = k.seal("hec-token-1");
        assert!(sealed.starts_with("v1:"));
        assert!(!sealed.contains("hec-token-1"));
        assert_ne!(sealed, k.seal("hec-token-1"), "a fresh nonce every time");
        assert_eq!(k.open(&sealed).as_deref(), Some("hec-token-1"));
        assert_eq!(CredentialKey::derive(b"another key").open(&sealed), None);
        assert_eq!(k.open("v1:not-base64!"), None);
        assert_eq!(k.open("plain"), None);
    }

    #[test]
    fn hec_urls_are_completed() {
        let u = |s| hec_url(s).map(|u| u.to_string());
        assert_eq!(
            u("https://splunk.example.com:8088").unwrap(),
            "https://splunk.example.com:8088/services/collector/event"
        );
        assert_eq!(
            u("https://splunk.example.com/services/collector/").unwrap(),
            "https://splunk.example.com/services/collector/event"
        );
        assert_eq!(
            u("https://splunk.example.com/services/collector/event?x=1").unwrap(),
            "https://splunk.example.com/services/collector/event"
        );
        assert!(u("https://splunk.example.com/raw").is_err());
        assert!(
            u("https://10.0.0.5:8088").is_err(),
            "private addresses stay refused"
        );
    }

    #[test]
    fn splunk_settings() {
        let ok = validate(
            KIND_SPLUNK,
            "https://splunk.example.com:8088",
            &json!({"index": "security"}),
            true,
        )
        .unwrap();
        assert_eq!(
            ok,
            json!({"index": "security", "sourcetype": "verdyx:event", "source": "verdyx"})
        );
        assert!(validate(
            KIND_SPLUNK,
            "http://splunk.example.com:8088",
            &json!({}),
            true
        )
        .is_err());
        assert!(validate(
            KIND_SPLUNK,
            "https://splunk.example.com:8088",
            &json!({}),
            false
        )
        .is_err());
        assert!(validate(
            KIND_SPLUNK,
            "https://splunk.example.com:8088",
            &json!({"index": "a b"}),
            true
        )
        .is_err());
        assert!(validate(
            KIND_SPLUNK,
            "https://splunk.example.com:8088",
            &json!({"index": 3}),
            true
        )
        .is_err());
        // Unknown keys are dropped, not stored.
        let v = validate(
            KIND_SPLUNK,
            "https://splunk.example.com:8088",
            &json!({"evil": "x"}),
            true,
        )
        .unwrap();
        assert!(v.get("evil").is_none());
    }

    #[test]
    fn sentinel_settings() {
        let cfg = json!({"tenantId": TENANT, "clientId": CLIENT, "dcrImmutableId": DCR});
        let url = "https://verdyx-abcd.eastus-1.ingest.monitor.azure.com";
        let ok = validate(KIND_SENTINEL, url, &cfg, true).unwrap();
        assert_eq!(ok["streamName"], DEFAULT_STREAM);
        assert!(
            validate(KIND_SENTINEL, "https://example.com", &cfg, true).is_err(),
            "Azure endpoints only"
        );
        assert!(validate(
            KIND_SENTINEL,
            &format!("{url}/dataCollectionRules/x"),
            &cfg,
            true
        )
        .is_err());
        assert!(validate(KIND_SENTINEL, url, &cfg, false).is_err());
        let mut bad = cfg.clone();
        bad["dcrImmutableId"] = json!("dcr-123");
        assert!(validate(KIND_SENTINEL, url, &bad, true).is_err());
        let mut bad = cfg.clone();
        bad["streamName"] = json!("VerdyxEvents_CL");
        assert!(validate(KIND_SENTINEL, url, &bad, true).is_err());
        let mut bad = cfg;
        bad["tenantId"] = json!("contoso.onmicrosoft.com");
        assert!(validate(KIND_SENTINEL, url, &bad, true).is_err());
    }

    fn envelope() -> Value {
        json!({
            "id": "d1", "event": "analysis.completed", "createdAt": "2026-11-27T10:00:00Z",
            "data": {"submissionId": "s1", "target": "a.exe", "sha256": "ab", "isMalicious": true,
                     "confidence": 0.9, "reportUrl": "https://verdyx.dev/analysis/s1"}
        })
    }

    /// A local server that answers each request in turn with the given
    /// (status, body) and hands back what it received.
    async fn server(
        replies: Vec<(u16, &'static str)>,
    ) -> (u16, tokio::sync::mpsc::UnboundedReceiver<(String, String)>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            for (status, reply) in replies {
                let (mut sock, _) = listener.accept().await.unwrap();
                let mut got = Vec::new();
                let mut buf = vec![0u8; 65536];
                loop {
                    let n = sock.read(&mut buf).await.unwrap();
                    got.extend_from_slice(&buf[..n]);
                    let text = String::from_utf8_lossy(&got).to_string();
                    if let Some(end) = text.find("\r\n\r\n") {
                        let len = text[..end]
                            .lines()
                            .find_map(|l| {
                                l.to_ascii_lowercase()
                                    .strip_prefix("content-length:")
                                    .map(|v| v.trim().parse::<usize>().unwrap())
                            })
                            .unwrap_or(0);
                        if got.len() >= end + 4 + len {
                            let _ = tx.send((
                                text[..end].to_string(),
                                text[end + 4..end + 4 + len].to_string(),
                            ));
                            break;
                        }
                    }
                    if n == 0 {
                        break;
                    }
                }
                let msg = format!(
                    "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{reply}",
                    reply.len()
                );
                let _ = sock.write_all(msg.as_bytes()).await;
            }
        });
        (port, rx)
    }

    fn local_client(names: &[(&str, u16)]) -> reqwest::Client {
        let mut b = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none());
        for (name, port) in names {
            b = b.resolve(name, std::net::SocketAddr::from(([127, 0, 0, 1], *port)));
        }
        b.build().unwrap()
    }

    #[tokio::test]
    async fn splunk_gets_a_hec_event_with_the_token() {
        use crate::services::webhook_delivery::{send, Target};
        let (port, mut rx) = server(vec![(200, r#"{"text":"Success","code":0}"#)]).await;
        let http = local_client(&[("splunk.verdyx-test.example", port)]);
        let target = Target {
            url: format!("http://splunk.verdyx-test.example:{port}"),
            kind: KIND_SPLUNK.into(),
            config: json!({"index": "sec", "sourcetype": "verdyx:event", "source": "verdyx"}),
            credential: Some("hec-123".into()),
            ..Default::default()
        };
        let r = send(
            &http,
            &target,
            uuid::Uuid::new_v4(),
            "analysis.completed",
            Utc::now(),
            &json!({"submissionId": "s1"}),
            "https://verdyx.dev",
        )
        .await;
        assert!(r.ok, "{r:?}");
        let (head, body) = rx.recv().await.unwrap();
        assert!(
            head.starts_with("POST /services/collector/event "),
            "{head}"
        );
        assert!(head
            .to_ascii_lowercase()
            .contains("authorization: splunk hec-123"));
        assert!(!head.to_ascii_lowercase().contains("x-verdyx-signature"));
        let v: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["index"], "sec");
        assert_eq!(v["event"]["event"], "analysis.completed");
        assert_eq!(
            v["event"]["data"]["reportUrl"],
            "https://verdyx.dev/analysis/s1"
        );
    }

    #[tokio::test]
    async fn splunk_refusals_say_why() {
        use crate::services::webhook_delivery::{send, Target};
        let (port, _rx) = server(vec![(403, r#"{"text":"Invalid token","code":4}"#)]).await;
        let http = local_client(&[("splunk.verdyx-test.example", port)]);
        let target = Target {
            url: format!("http://splunk.verdyx-test.example:{port}"),
            kind: KIND_SPLUNK.into(),
            credential: Some("wrong".into()),
            ..Default::default()
        };
        let r = send(
            &http,
            &target,
            uuid::Uuid::new_v4(),
            "webhook.test",
            Utc::now(),
            &json!({}),
            "x",
        )
        .await;
        assert!(!r.ok);
        assert_eq!(
            r.error.as_deref(),
            Some("HTTP 403: Splunk refused the HEC token")
        );

        // Without a readable credential nothing is sent.
        let none = Target {
            credential: None,
            ..target
        };
        let r = send(
            &http,
            &none,
            uuid::Uuid::new_v4(),
            "webhook.test",
            Utc::now(),
            &json!({}),
            "x",
        )
        .await;
        assert!(r.error.unwrap().contains("enter it again"));
    }

    #[tokio::test]
    async fn sentinel_signs_in_then_sends_one_row() {
        use crate::services::webhook_delivery::{send, Target};
        let (login_port, mut login_rx) =
            server(vec![(200, r#"{"access_token":"tok-1","expires_in":3600}"#)]).await;
        let (dce_port, mut dce_rx) = server(vec![(204, ""), (204, "")]).await;
        let dce = "verdyx-x.eastus-1.ingest.monitor.azure.com";
        let http = local_client(&[("login.verdyx-test.example", login_port), (dce, dce_port)]);
        // A client id of its own, so other tests' cached tokens don't apply.
        let client = uuid::Uuid::new_v4().to_string();
        let target = Target {
            url: format!("http://{dce}:{dce_port}"),
            kind: KIND_SENTINEL.into(),
            config: json!({"tenantId": TENANT, "clientId": client, "dcrImmutableId": DCR, "streamName": "Custom-VerdyxEvents_CL"}),
            credential: Some("app-key".into()),
            sentinel_login: Some(format!("http://login.verdyx-test.example:{login_port}")),
            ..Default::default()
        };
        let r = send(
            &http,
            &target,
            uuid::Uuid::new_v4(),
            "analysis.completed",
            Utc::now(),
            &json!({"submissionId": "s1", "isMalicious": true}),
            "https://verdyx.dev",
        )
        .await;
        assert!(r.ok, "{r:?}");

        let (head, form) = login_rx.recv().await.unwrap();
        assert!(
            head.starts_with(&format!("POST /{TENANT}/oauth2/v2.0/token ")),
            "{head}"
        );
        assert!(form.contains("grant_type=client_credentials"));
        assert!(form.contains(&format!("client_id={client}")));
        assert!(form.contains("scope=https%3A%2F%2Fmonitor.azure.com%2F%2F.default"));

        let (head, body) = dce_rx.recv().await.unwrap();
        assert!(
            head.starts_with(&format!(
            "POST /dataCollectionRules/{DCR}/streams/Custom-VerdyxEvents_CL?api-version=2023-01-01 "
        )),
            "{head}"
        );
        assert!(head
            .to_ascii_lowercase()
            .contains("authorization: bearer tok-1"));
        let rows: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(rows.as_array().unwrap().len(), 1);
        assert_eq!(rows[0]["SubmissionId"], "s1");
        assert_eq!(rows[0]["IsMalicious"], true);

        // The token is reused: the second delivery doesn't sign in again
        // (the login server only answers once).
        let r = send(
            &http,
            &target,
            uuid::Uuid::new_v4(),
            "analysis.completed",
            Utc::now(),
            &json!({"submissionId": "s2"}),
            "https://verdyx.dev",
        )
        .await;
        assert!(r.ok, "{r:?}");
        assert!(dce_rx.recv().await.unwrap().1.contains("s2"));
    }

    #[tokio::test]
    async fn sentinel_sign_in_failures_are_reported_without_the_response() {
        use crate::services::webhook_delivery::{send, Target};
        let (login_port, _rx) = server(vec![(
            401,
            r#"{"error":"invalid_client","error_description":"AADSTS7000215: Invalid client secret provided."}"#,
        )])
        .await;
        let dce = "verdyx-y.eastus-1.ingest.monitor.azure.com";
        let http = local_client(&[("login.verdyx-test.example", login_port), (dce, 9)]);
        let target = Target {
            url: format!("http://{dce}:9"),
            kind: KIND_SENTINEL.into(),
            config: json!({"tenantId": TENANT, "clientId": uuid::Uuid::new_v4().to_string(), "dcrImmutableId": DCR}),
            credential: Some("bad".into()),
            sentinel_login: Some(format!("http://login.verdyx-test.example:{login_port}")),
            ..Default::default()
        };
        let r = send(
            &http,
            &target,
            uuid::Uuid::new_v4(),
            "webhook.test",
            Utc::now(),
            &json!({}),
            "x",
        )
        .await;
        assert!(!r.ok);
        assert_eq!(
            r.error.as_deref(),
            Some("Entra ID refused the app (HTTP 401, invalid_client)")
        );
    }

    #[test]
    fn bodies() {
        let at = DateTime::parse_from_rfc3339("2026-11-27T10:00:00.250Z")
            .unwrap()
            .with_timezone(&Utc);
        let s = splunk_event(
            &json!({"index": "sec", "sourcetype": "verdyx:event", "source": "verdyx"}),
            at,
            &envelope(),
        );
        assert_eq!(s["time"], json!(1795773600.25));
        assert_eq!(s["index"], "sec");
        assert_eq!(s["event"]["data"]["submissionId"], "s1");
        assert!(splunk_event(&json!({}), at, &envelope())
            .get("index")
            .is_none());

        let r = sentinel_record(&envelope());
        assert_eq!(r["TimeGenerated"], "2026-11-27T10:00:00Z");
        assert_eq!(r["EventType"], "analysis.completed");
        assert_eq!(r["IsMalicious"], true);
        assert_eq!(r["HuntName"], Value::Null);
        assert_eq!(r["Data"]["target"], "a.exe");
    }
}
