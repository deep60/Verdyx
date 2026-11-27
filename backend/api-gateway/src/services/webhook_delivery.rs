//! Webhook delivery: sends the events queued in `webhook_deliveries`.
//!
//! Services queue events with `shared::webhooks::ENQUEUE_SQL` (one pending row
//! per subscribed webhook). This worker:
//!
//! 1. claims due rows (`FOR UPDATE SKIP LOCKED`, so two gateways never send
//!    the same row), marking them `sending`;
//! 2. POSTs a JSON envelope `{id, event, createdAt, data}` with
//!    `X-Verdyx-Signature: t=<unix>,v1=<hex HMAC-SHA256 of "<t>.<body>">`,
//!    keyed with that webhook's own secret;
//! 3. records the outcome, retrying failures with backoff until the
//!    webhook's `retry_max_attempts`.
//!
//! Requests can't be pointed at the server's own network: the URL must be
//! http(s) without credentials, every address its host resolves to must be
//! public (checked when connecting, so DNS can't be swapped after a check),
//! redirects aren't followed, and no proxy is used.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use serde_json::{json, Value};
use sqlx::PgPool;
use uuid::Uuid;

use super::siem;
use crate::AppState;

/// Rows claimed per round.
const BATCH: i64 = 20;
/// How often to look for due rows when the last round wasn't full.
const IDLE: Duration = Duration::from_secs(2);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Longest wait between attempts.
const MAX_DELAY_SECS: i64 = 6 * 3600;
/// Response bodies are kept this short in the delivery log.
const MAX_LOGGED_BODY: usize = 1000;
/// Delivered or failed rows older than this are removed.
const KEEP_DAYS: i32 = 30;
const MAX_CUSTOM_HEADERS: usize = 10;

pub const USER_AGENT: &str = "Verdyx-Webhooks/1.0 (+https://verdyx.dev)";

// ─── Where requests may go ────────────────────────────────────────────────

/// True for an address on the public internet: not loopback, private,
/// link-local (cloud metadata), carrier-grade NAT, documentation, multicast
/// or reserved, including IPv4 addresses embedded in IPv6.
pub fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_public_v4(v4),
        IpAddr::V6(v6) => {
            if let Some(v4) = embedded_v4(v6) {
                return is_public_v4(v4);
            }
            let s = v6.segments();
            !(v6.is_unspecified()
                || v6.is_loopback()
                || v6.is_multicast()
                || (s[0] & 0xfe00) == 0xfc00 // unique local fc00::/7
                || (s[0] & 0xffc0) == 0xfe80 // link-local fe80::/10
                || (s[0] == 0x2001 && s[1] == 0x0db8) // documentation
                || (s[0] == 0x0100 && s[1] == 0 && s[2] == 0 && s[3] == 0)) // discard 100::/64
        }
    }
}

fn is_public_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !(a == 0
        || a == 10
        || a == 127
        || (a == 100 && (64..=127).contains(&b)) // carrier-grade NAT
        || (a == 169 && b == 254) // link-local, incl. cloud metadata
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 0 && c == 0)
        || (a == 192 && b == 0 && c == 2)
        || (a == 192 && b == 88 && c == 99)
        || (a == 192 && b == 168)
        || (a == 198 && (18..=19).contains(&b))
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113)
        || a >= 224) // multicast, reserved, broadcast
}

/// The IPv4 address inside an IPv4-mapped, IPv4-compatible, NAT64 or 6to4
/// IPv6 address.
fn embedded_v4(v6: Ipv6Addr) -> Option<Ipv4Addr> {
    let s = v6.segments();
    let tail = Ipv4Addr::new((s[6] >> 8) as u8, s[6] as u8, (s[7] >> 8) as u8, s[7] as u8);
    if s[..5] == [0, 0, 0, 0, 0]
        && (s[5] == 0xffff || s[5] == 0)
        && !(v6.is_loopback() || v6.is_unspecified())
    {
        return Some(tail);
    }
    if s[0] == 0x0064 && s[1] == 0xff9b && s[2..6] == [0, 0, 0, 0] {
        return Some(tail); // NAT64 64:ff9b::/96
    }
    if s[0] == 0x2002 {
        // 6to4: the IPv4 address is in segments 1 and 2.
        return Some(Ipv4Addr::new(
            (s[1] >> 8) as u8,
            s[1] as u8,
            (s[2] >> 8) as u8,
            s[2] as u8,
        ));
    }
    None
}

/// Why a webhook URL isn't allowed, or `Ok` with the parsed URL. Hosts are
/// checked again when connecting, since a name can resolve anywhere.
pub fn check_url(raw: &str) -> Result<url::Url, &'static str> {
    let url = url::Url::parse(raw.trim()).map_err(|_| "not a valid URL")?;
    if url.scheme() != "https" && url.scheme() != "http" {
        return Err("the URL must start with https:// or http://");
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("put credentials in a header, not in the URL");
    }
    match url.host() {
        None => Err("the URL has no host"),
        Some(url::Host::Ipv4(ip)) if !is_public(IpAddr::V4(ip)) => {
            Err("the URL points at a private or reserved address")
        }
        Some(url::Host::Ipv6(ip)) if !is_public(IpAddr::V6(ip)) => {
            Err("the URL points at a private or reserved address")
        }
        Some(url::Host::Domain(d)) => {
            let d = d.trim_end_matches('.').to_ascii_lowercase();
            if d == "localhost"
                || d.ends_with(".localhost")
                || d.ends_with(".local")
                || d.ends_with(".internal")
                || !d.contains('.')
            {
                Err("the URL points at a local or internal name")
            } else {
                Ok(url)
            }
        }
        Some(_) => Ok(url),
    }
}

/// Resolves names, keeping only public addresses.
struct PublicOnly {
    allow_private: bool,
}

impl Resolve for PublicOnly {
    fn resolve(&self, name: Name) -> Resolving {
        let allow_private = self.allow_private;
        let host = name.as_str().to_string();
        Box::pin(async move {
            let found: Vec<SocketAddr> =
                tokio::net::lookup_host((host.as_str(), 0)).await?.collect();
            let ok: Vec<SocketAddr> = found
                .into_iter()
                .filter(|a| allow_private || is_public(a.ip()))
                .collect();
            if ok.is_empty() {
                let e: Box<dyn std::error::Error + Send + Sync> =
                    format!("{host} doesn't resolve to a public address").into();
                return Err(e);
            }
            Ok(Box::new(ok.into_iter()) as Addrs)
        })
    }
}

/// The HTTP client for webhooks. `allow_private` is only for tests that send
/// to a local server.
pub fn client(allow_private: bool) -> reqwest::Client {
    client_with_timeout(allow_private, REQUEST_TIMEOUT)
}

/// The same client with a longer limit per request, for downloads.
pub fn client_with_timeout(allow_private: bool, timeout: Duration) -> reqwest::Client {
    reqwest::Client::builder()
        .dns_resolver(Arc::new(PublicOnly { allow_private }))
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .timeout(timeout)
        .connect_timeout(CONNECT_TIMEOUT)
        .user_agent(USER_AGENT)
        .build()
        .expect("webhook HTTP client")
}

// ─── What is sent ─────────────────────────────────────────────────────────

/// `t=<unix>,v1=<hex HMAC-SHA256(secret, "<t>.<body>")>`.
pub fn signature(secret: &str, timestamp: i64, body: &str) -> String {
    use ring::hmac;
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret.as_bytes());
    let mut ctx = hmac::Context::with_key(&key);
    ctx.update(timestamp.to_string().as_bytes());
    ctx.update(b".");
    ctx.update(body.as_bytes());
    format!("t={timestamp},v1={}", hex::encode(ctx.sign().as_ref()))
}

/// The JSON body. A submission id in the data also gets a link to its report.
pub fn envelope(
    id: Uuid,
    event: &str,
    created_at: DateTime<Utc>,
    data: &Value,
    web_url: &str,
) -> Value {
    let mut data = data.clone();
    if let Some(sid) = data
        .get("submissionId")
        .and_then(Value::as_str)
        .map(str::to_string)
    {
        if data.get("reportUrl").is_none() {
            data["reportUrl"] = json!(format!("{}/analysis/{sid}", web_url.trim_end_matches('/')));
        }
    }
    json!({ "id": id, "event": event, "createdAt": created_at, "data": data })
}

/// The webhook's own headers that may be sent: string values, valid names,
/// nothing that would change how the request is read or signed.
pub fn custom_headers(
    headers: Option<&Value>,
) -> Vec<(reqwest::header::HeaderName, reqwest::header::HeaderValue)> {
    const RESERVED: [&str; 7] = [
        "host",
        "content-length",
        "content-type",
        "transfer-encoding",
        "connection",
        "user-agent",
        "te",
    ];
    let Some(obj) = headers.and_then(Value::as_object) else {
        return Vec::new();
    };
    obj.iter()
        .filter_map(|(k, v)| {
            let lower = k.to_ascii_lowercase();
            if RESERVED.contains(&lower.as_str()) || lower.starts_with("x-verdyx-") {
                return None;
            }
            let value = v.as_str().filter(|s| s.len() <= 1024)?;
            Some((
                reqwest::header::HeaderName::from_bytes(k.as_bytes()).ok()?,
                reqwest::header::HeaderValue::from_str(value).ok()?,
            ))
        })
        .take(MAX_CUSTOM_HEADERS)
        .collect()
}

/// Seconds to wait before attempt `next` (2, 3, …).
pub fn delay_secs(interval: Option<i32>, exponential: Option<bool>, next: i32) -> i64 {
    let base = interval.unwrap_or(60).clamp(10, 3600) as i64;
    let factor = if exponential.unwrap_or(true) {
        2i64.saturating_pow((next - 2).clamp(0, 20) as u32)
    } else {
        1
    };
    (base.saturating_mul(factor)).min(MAX_DELAY_SECS)
}

pub fn max_attempts(configured: Option<i32>) -> i32 {
    configured.unwrap_or(3).clamp(1, 10)
}

// ─── Sending ──────────────────────────────────────────────────────────────

/// A webhook as the sender needs it.
#[derive(Debug, Clone, Default)]
pub struct Target {
    pub url: String,
    pub secret: Option<String>,
    pub headers: Option<Value>,
    /// `webhook` (or empty), `splunk` or `sentinel`.
    pub kind: String,
    /// Destination settings (see `siem::validate`).
    pub config: Value,
    /// The destination's credential, already unsealed.
    pub credential: Option<String>,
    /// Tests only: where to sign in to Entra ID instead of Microsoft.
    pub sentinel_login: Option<String>,
}

/// What happened to one attempt.
#[derive(Debug)]
pub struct Attempt {
    pub ok: bool,
    pub status_code: Option<i16>,
    pub response_body: Option<String>,
    pub error: Option<String>,
}

/// Send one delivery once.
pub async fn send(
    http: &reqwest::Client,
    target: &Target,
    delivery_id: Uuid,
    event: &str,
    created_at: DateTime<Utc>,
    data: &Value,
    web_url: &str,
) -> Attempt {
    let fail = |error: String| Attempt {
        ok: false,
        status_code: None,
        response_body: None,
        error: Some(error),
    };
    let url = match check_url(&target.url) {
        Ok(u) => u,
        Err(why) => return fail(why.to_string()),
    };
    let env = envelope(delivery_id, event, created_at, data, web_url);
    let kind = if target.kind.is_empty() {
        siem::KIND_WEBHOOK
    } else {
        target.kind.as_str()
    };
    if kind != siem::KIND_WEBHOOK {
        let req = match siem::request(
            http,
            kind,
            url.as_str(),
            &target.config,
            target.credential.as_deref(),
            created_at,
            &env,
            target.sentinel_login.as_deref(),
        )
        .await
        {
            Ok(r) => r,
            Err(why) => return fail(why),
        };
        let mut attempt = finish(req.send().await).await;
        if let Some(code) = attempt.status_code {
            if code == 401 || code == 403 {
                siem::after_refusal(kind, &target.config, target.credential.as_deref());
            }
            if let (false, Some(h)) = (attempt.ok, siem::hint(kind, code as u16)) {
                attempt.error = attempt.error.map(|e| format!("{e}: {h}"));
            }
        }
        return attempt;
    }
    let body = env.to_string();
    let ts = Utc::now().timestamp();
    let mut req = http
        .post(url)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .header("X-Verdyx-Event", event)
        .header("X-Verdyx-Delivery", delivery_id.to_string())
        .header("X-Verdyx-Timestamp", ts.to_string());
    if let Some(secret) = target.secret.as_deref().filter(|s| !s.is_empty()) {
        req = req.header("X-Verdyx-Signature", signature(secret, ts, &body));
    }
    for (k, v) in custom_headers(target.headers.as_ref()) {
        req = req.header(k, v);
    }
    finish(req.body(body).send().await).await
}

/// Read a response (or failure) into an [`Attempt`].
async fn finish(sent: Result<reqwest::Response, reqwest::Error>) -> Attempt {
    match sent {
        Ok(resp) => {
            let code = resp.status();
            let mut text = resp.text().await.unwrap_or_default();
            if text.len() > MAX_LOGGED_BODY {
                let cut = (0..=MAX_LOGGED_BODY)
                    .rev()
                    .find(|i| text.is_char_boundary(*i))
                    .unwrap_or(0);
                text.truncate(cut);
            }
            Attempt {
                ok: code.is_success(),
                status_code: Some(code.as_u16() as i16),
                response_body: Some(text),
                error: (!code.is_success()).then(|| {
                    if code.is_redirection() {
                        format!("HTTP {} (redirects aren't followed)", code.as_u16())
                    } else {
                        format!("HTTP {}", code.as_u16())
                    }
                }),
            }
        }
        Err(e) => Attempt {
            ok: false,
            status_code: None,
            response_body: None,
            error: Some(describe(&e)),
        },
    }
}

pub(crate) fn describe(e: &reqwest::Error) -> String {
    use std::error::Error;
    let mut msg = if e.is_timeout() {
        "timed out".to_string()
    } else if e.is_connect() {
        "could not connect".to_string()
    } else {
        "request failed".to_string()
    };
    // The innermost cause says why (e.g. "doesn't resolve to a public address").
    let mut src = e.source();
    let mut last = None;
    while let Some(s) = src {
        last = Some(s.to_string());
        src = s.source();
    }
    if let Some(l) = last {
        msg = format!("{msg}: {l}");
    }
    msg
}

// ─── The worker ───────────────────────────────────────────────────────────

type Claimed = (Uuid, Uuid, String, Value, i32, DateTime<Utc>);

/// Claim up to `limit` due deliveries.
pub async fn claim(db: &PgPool, limit: i64) -> Result<Vec<Claimed>, sqlx::Error> {
    sqlx::query_as(
        r#"UPDATE webhook_deliveries d SET status = 'sending'
           FROM (SELECT id FROM webhook_deliveries
                 WHERE status IN ('pending', 'retrying') AND next_attempt_at <= NOW()
                 ORDER BY next_attempt_at LIMIT $1 FOR UPDATE SKIP LOCKED) due
           WHERE d.id = due.id
           RETURNING d.id, d.webhook_id, d.event_type, d.payload, COALESCE(d.attempt_number, 1), d.triggered_at"#,
    )
    .bind(limit)
    .fetch_all(db)
    .await
}

/// The webhook settings a delivery needs.
#[derive(sqlx::FromRow)]
struct Hook {
    url: String,
    secret: Option<String>,
    headers: Option<Value>,
    kind: String,
    config: Value,
    credential: Option<String>,
    is_active: Option<bool>,
    retry_max_attempts: Option<i32>,
    retry_interval_seconds: Option<i32>,
    exponential_backoff: Option<bool>,
}

/// Send one claimed delivery and record what happened.
pub async fn process(
    db: &PgPool,
    http: &reqwest::Client,
    key: &siem::CredentialKey,
    web_url: &str,
    row: Claimed,
) -> Result<(), sqlx::Error> {
    let (id, webhook_id, event, data, attempt, created_at) = row;
    let hook: Option<Hook> = sqlx::query_as(
        "SELECT url, secret, headers, kind, config, credential, is_active, retry_max_attempts, \
         retry_interval_seconds, exponential_backoff FROM webhooks WHERE id = $1",
    )
    .bind(webhook_id)
    .fetch_optional(db)
    .await?;
    let Some(Hook {
        url,
        secret,
        headers,
        kind,
        config,
        credential,
        is_active,
        retry_max_attempts: max,
        retry_interval_seconds: interval,
        exponential_backoff: exponential,
    }) = hook
    else {
        return Ok(()); // deleted: its deliveries went with it
    };
    if is_active == Some(false) {
        sqlx::query(
            "UPDATE webhook_deliveries SET status = 'failed', error_message = 'the webhook is turned off', \
             completed_at = NOW() WHERE id = $1",
        )
        .bind(id)
        .execute(db)
        .await?;
        return Ok(());
    }
    let result = send(
        http,
        &Target {
            url,
            secret,
            headers,
            kind,
            config,
            credential: credential.as_deref().and_then(|c| key.open(c)),
            sentinel_login: None,
        },
        id,
        &event,
        created_at,
        &data,
        web_url,
    )
    .await;
    record(
        db,
        id,
        webhook_id,
        attempt,
        max_attempts(max),
        delay_secs(interval, exponential, attempt + 1),
        &result,
    )
    .await
}

/// Store the outcome of attempt `attempt` of `max`.
pub async fn record(
    db: &PgPool,
    id: Uuid,
    webhook_id: Uuid,
    attempt: i32,
    max: i32,
    retry_in_secs: i64,
    result: &Attempt,
) -> Result<(), sqlx::Error> {
    if result.ok {
        sqlx::query(
            "UPDATE webhook_deliveries SET status = 'success', status_code = $2, response_body = $3, \
             error_message = NULL, completed_at = NOW() WHERE id = $1",
        )
        .bind(id)
        .bind(result.status_code)
        .bind(&result.response_body)
        .execute(db)
        .await?;
        sqlx::query("UPDATE webhooks SET last_triggered_at = NOW() WHERE id = $1")
            .bind(webhook_id)
            .execute(db)
            .await?;
    } else if attempt < max {
        sqlx::query(
            "UPDATE webhook_deliveries SET status = 'retrying', status_code = $2, response_body = $3, \
             error_message = $4, attempt_number = $5, next_attempt_at = NOW() + make_interval(secs => $6) \
             WHERE id = $1",
        )
        .bind(id)
        .bind(result.status_code)
        .bind(&result.response_body)
        .bind(&result.error)
        .bind(attempt + 1)
        .bind(retry_in_secs as f64)
        .execute(db)
        .await?;
    } else {
        sqlx::query(
            "UPDATE webhook_deliveries SET status = 'failed', status_code = $2, response_body = $3, \
             error_message = $4, completed_at = NOW() WHERE id = $1",
        )
        .bind(id)
        .bind(result.status_code)
        .bind(&result.response_body)
        .bind(&result.error)
        .execute(db)
        .await?;
    }
    Ok(())
}

pub fn web_url() -> String {
    std::env::var("VERDYX_WEB_URL")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "https://verdyx.dev".to_string())
}

/// Start the delivery worker.
pub fn spawn(state: AppState) {
    if std::env::var("WEBHOOK_DELIVERY")
        .map(|v| v == "off")
        .unwrap_or(false)
    {
        tracing::info!("Webhook delivery is off (WEBHOOK_DELIVERY=off)");
        return;
    }
    tokio::spawn(async move {
        let db = state.db.pool().clone();
        let http = client(false);
        let web = web_url();
        let key = Arc::new(siem::CredentialKey::from_config(
            &state.config.security.jwt_secret,
        ));
        // Rows that were being sent when the gateway stopped are sent again.
        if let Err(e) = sqlx::query(
            "UPDATE webhook_deliveries SET status = 'retrying' WHERE status = 'sending'",
        )
        .execute(&db)
        .await
        {
            tracing::warn!("webhook deliveries not ready yet: {e}");
        }
        tracing::info!("Webhook delivery worker started");
        let mut last_prune = std::time::Instant::now() - Duration::from_secs(3600);
        loop {
            if last_prune.elapsed() >= Duration::from_secs(3600) {
                last_prune = std::time::Instant::now();
                if let Err(e) = sqlx::query(
                    "DELETE FROM webhook_deliveries WHERE status IN ('success', 'failed') \
                     AND triggered_at < NOW() - make_interval(days => $1)",
                )
                .bind(KEEP_DAYS)
                .execute(&db)
                .await
                {
                    tracing::warn!("could not prune old webhook deliveries: {e}");
                }
            }
            let rows = match claim(&db, BATCH).await {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!("webhook delivery: {e}");
                    tokio::time::sleep(IDLE * 5).await;
                    continue;
                }
            };
            let full = rows.len() as i64 == BATCH;
            let mut tasks = tokio::task::JoinSet::new();
            for row in rows {
                let (db, http, web, key) = (db.clone(), http.clone(), web.clone(), key.clone());
                tasks.spawn(async move {
                    let id = row.0;
                    if let Err(e) = process(&db, &http, &key, &web, row).await {
                        tracing::warn!("webhook delivery {id}: {e}");
                    }
                });
            }
            while tasks.join_next().await.is_some() {}
            if !full {
                tokio::time::sleep(IDLE).await;
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn private_and_reserved_addresses_are_refused() {
        for s in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "100.112.183.51",
            "0.0.0.0",
            "224.0.0.1",
            "255.255.255.255",
            "198.18.0.1",
            "::1",
            "::",
            "fc00::1",
            "fd12::1",
            "fe80::1",
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            "64:ff9b::a00:1",
            "2002:a00:1::",
            "2001:db8::1",
            "ff02::1",
        ] {
            assert!(!is_public(ip(s)), "{s} should be refused");
        }
        for s in [
            "8.8.8.8",
            "1.1.1.1",
            "172.15.0.1",
            "172.32.0.1",
            "100.63.0.1",
            "2606:4700::1111",
            "::ffff:8.8.8.8",
        ] {
            assert!(is_public(ip(s)), "{s} should be allowed");
        }
    }

    #[test]
    fn urls_are_checked() {
        assert!(check_url("https://hooks.example.com/verdyx").is_ok());
        assert!(check_url("http://hooks.example.com:8080/x").is_ok());
        for bad in [
            "ftp://example.com/x",
            "https://user:pass@example.com/",
            "http://127.0.0.1/",
            "http://[::1]/",
            "http://169.254.169.254/latest/meta-data",
            "http://0x7f000001/",
            "http://2130706433/",
            "http://localhost:8080/",
            "http://api.localhost/",
            "http://metadata.google.internal/",
            "http://printer.local/",
            "http://intranet/",
            "not a url",
        ] {
            assert!(check_url(bad).is_err(), "{bad} should be refused");
        }
    }

    #[test]
    fn signatures_are_stripe_style_and_verifiable() {
        let sig = signature("whsec_abc", 1_764_000_000, r#"{"a":1}"#);
        assert!(sig.starts_with("t=1764000000,v1="));
        let hex_part = sig.split("v1=").nth(1).unwrap();
        assert_eq!(hex_part.len(), 64);
        // Same input, same signature; any change, a different one.
        assert_eq!(sig, signature("whsec_abc", 1_764_000_000, r#"{"a":1}"#));
        assert_ne!(sig, signature("whsec_abc", 1_764_000_001, r#"{"a":1}"#));
        assert_ne!(sig, signature("whsec_abd", 1_764_000_000, r#"{"a":1}"#));
    }

    #[test]
    fn the_envelope_links_the_report() {
        let id = Uuid::nil();
        let at = Utc::now();
        let v = envelope(
            id,
            "analysis.completed",
            at,
            &json!({"submissionId": "abc"}),
            "https://verdyx.dev/",
        );
        assert_eq!(v["event"], "analysis.completed");
        assert_eq!(v["data"]["reportUrl"], "https://verdyx.dev/analysis/abc");
        let plain = envelope(
            id,
            "webhook.test",
            at,
            &json!({"x": 1}),
            "https://verdyx.dev",
        );
        assert!(plain["data"].get("reportUrl").is_none());
    }

    #[test]
    fn custom_headers_cannot_override_ours() {
        let h = custom_headers(Some(&json!({
            "Authorization": "Bearer abc",
            "X-Team": "soc",
            "Host": "evil",
            "Content-Type": "text/plain",
            "X-Verdyx-Signature": "forged",
            "X-Number": 5,
            "Bad Name": "x"
        })));
        let names: Vec<String> = h.iter().map(|(k, _)| k.as_str().to_string()).collect();
        assert_eq!(names, vec!["authorization", "x-team"]);
    }

    #[test]
    fn retries_back_off() {
        assert_eq!(delay_secs(None, None, 2), 60);
        assert_eq!(delay_secs(None, None, 3), 120);
        assert_eq!(delay_secs(None, None, 4), 240);
        assert_eq!(delay_secs(Some(30), Some(false), 5), 30);
        assert_eq!(delay_secs(Some(1), None, 2), 10, "at least 10 s");
        assert_eq!(delay_secs(Some(3600), None, 20), MAX_DELAY_SECS);
        assert_eq!(max_attempts(None), 3);
        assert_eq!(max_attempts(Some(0)), 1);
        assert_eq!(max_attempts(Some(99)), 10);
    }

    /// A tiny HTTP server that records one request and answers with `status`.
    async fn receiver(status: u16) -> (String, tokio::sync::oneshot::Receiver<(String, String)>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 65536];
            let mut got = Vec::new();
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
            let reply =
                format!("HTTP/1.1 {status} X\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
            let _ = sock.write_all(reply.as_bytes()).await;
        });
        // A public-looking name is required by check_url, so use one that
        // resolves locally only through the test client's allowance.
        (
            format!("http://localhost.verdyx-test.example:{}/hook", addr.port()),
            rx,
        )
    }

    #[tokio::test]
    async fn the_real_client_refuses_names_that_resolve_privately() {
        let target = Target {
            url: "http://localtest.me/".into(),
            secret: None,
            headers: None,
            ..Default::default()
        };
        let r = send(
            &client(false),
            &target,
            Uuid::new_v4(),
            "webhook.test",
            Utc::now(),
            &json!({}),
            "https://verdyx.dev",
        )
        .await;
        assert!(!r.ok);
        let e = r.error.unwrap();
        // localtest.me resolves to 127.0.0.1; offline, resolution fails instead.
        assert!(
            e.contains("public address")
                || e.contains("could not connect")
                || e.contains("request failed"),
            "{e}"
        );
    }

    #[tokio::test]
    async fn deliveries_are_signed_and_carry_the_envelope() {
        let (url, rx) = receiver(200).await;
        // Point the made-up name at the local receiver for this client only.
        let port: u16 = url
            .rsplit(':')
            .next()
            .unwrap()
            .split('/')
            .next()
            .unwrap()
            .parse()
            .unwrap();
        let http = reqwest::Client::builder()
            .resolve(
                "localhost.verdyx-test.example",
                SocketAddr::from(([127, 0, 0, 1], port)),
            )
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        let id = Uuid::new_v4();
        let target = Target {
            url,
            secret: Some("whsec_test".into()),
            headers: Some(json!({"Authorization": "Bearer t", "Host": "evil"})),
            ..Default::default()
        };
        let r = send(
            &http,
            &target,
            id,
            "livehunt.match",
            Utc::now(),
            &json!({"submissionId": "s1", "rules": ["A"]}),
            "https://verdyx.dev",
        )
        .await;
        assert!(r.ok, "{r:?}");
        assert_eq!(r.status_code, Some(200));
        let (head, body) = rx.await.unwrap();
        let head_l = head.to_ascii_lowercase();
        assert!(head_l.contains("x-verdyx-event: livehunt.match"));
        assert!(head_l.contains(&format!("x-verdyx-delivery: {id}")));
        assert!(head_l.contains("authorization: bearer t"));
        assert!(!head_l.contains("host: evil"));
        let sig_line = head
            .lines()
            .find(|l| l.to_ascii_lowercase().starts_with("x-verdyx-signature:"))
            .unwrap();
        let sig = sig_line.split_once(':').unwrap().1.trim();
        let ts: i64 = sig
            .trim_start_matches("t=")
            .split(',')
            .next()
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(
            sig,
            signature("whsec_test", ts, &body),
            "the signature covers the exact body"
        );
        let v: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["id"], json!(id));
        assert_eq!(v["data"]["reportUrl"], "https://verdyx.dev/analysis/s1");
    }

    #[tokio::test]
    async fn failures_and_redirects_are_reported() {
        let (url, _rx) = receiver(302).await;
        let port: u16 = url
            .rsplit(':')
            .next()
            .unwrap()
            .split('/')
            .next()
            .unwrap()
            .parse()
            .unwrap();
        let http = reqwest::Client::builder()
            .resolve(
                "localhost.verdyx-test.example",
                SocketAddr::from(([127, 0, 0, 1], port)),
            )
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        let target = Target {
            url,
            secret: None,
            headers: None,
            ..Default::default()
        };
        let r = send(
            &http,
            &target,
            Uuid::new_v4(),
            "webhook.test",
            Utc::now(),
            &json!({}),
            "x",
        )
        .await;
        assert!(!r.ok);
        assert_eq!(r.status_code, Some(302));
        assert_eq!(
            r.error.as_deref(),
            Some("HTTP 302 (redirects aren't followed)")
        );
    }

    /// Queue, claim, retry, fail and succeed against a real database. Runs
    /// only when API_GATEWAY_DATABASE_URL is set; cleans up after itself.
    #[tokio::test]
    async fn the_outbox_cycle_against_a_database() {
        let Ok(url) = std::env::var("API_GATEWAY_DATABASE_URL") else {
            eprintln!("skipping: API_GATEWAY_DATABASE_URL not set");
            return;
        };
        let db = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect(&url)
            .await
            .unwrap();
        sqlx::migrate!("./migrations").run(&db).await.unwrap();

        let (alice, bob) = (Uuid::new_v4(), Uuid::new_v4());
        let mk = |user: Uuid, events: Vec<&str>, active: bool| {
            let db = db.clone();
            let events: Vec<String> = events.into_iter().map(String::from).collect();
            async move {
                let id = Uuid::new_v4();
                sqlx::query(
                    "INSERT INTO webhooks (id, user_id, url, events, is_active, retry_max_attempts, retry_interval_seconds) \
                     VALUES ($1, $2, 'https://hooks.example.com/x', $3, $4, 2, 30)",
                )
                .bind(id)
                .bind(user)
                .bind(events)
                .bind(active)
                .execute(&db)
                .await
                .unwrap();
                id
            }
        };
        let a_scans = mk(alice, vec!["analysis.completed"], true).await;
        let a_all = mk(alice, vec!["*"], true).await;
        let a_hunts = mk(alice, vec!["livehunt.match"], true).await;
        let a_off = mk(alice, vec!["analysis.completed"], false).await;
        let b_scans = mk(bob, vec!["analysis.completed"], true).await;

        let n = sqlx::query(shared::webhooks::ENQUEUE_SQL)
            .bind(alice)
            .bind("analysis.completed")
            .bind(json!({"submissionId": "s1"}))
            .execute(&db)
            .await
            .unwrap()
            .rows_affected();
        assert_eq!(n, 2, "alice's subscribed, active hooks only");
        let queued: Vec<Uuid> = sqlx::query_scalar(
            "SELECT webhook_id FROM webhook_deliveries WHERE webhook_id = ANY($1) ORDER BY webhook_id",
        )
        .bind(vec![a_scans, a_all, a_hunts, a_off, b_scans])
        .fetch_all(&db)
        .await
        .unwrap();
        let mut want = vec![a_scans, a_all];
        want.sort();
        assert_eq!(queued, want);

        // Claim them; a second claim gets nothing.
        let mine = |rows: Vec<Claimed>| -> Vec<Claimed> {
            rows.into_iter().filter(|r| want.contains(&r.1)).collect()
        };
        let claimed = mine(claim(&db, 100).await.unwrap());
        assert_eq!(claimed.len(), 2);
        assert!(
            mine(claim(&db, 100).await.unwrap()).is_empty(),
            "sending rows aren't claimed twice"
        );

        let fail = Attempt {
            ok: false,
            status_code: Some(500),
            response_body: Some("boom".into()),
            error: Some("HTTP 500".into()),
        };
        let ok = Attempt {
            ok: true,
            status_code: Some(204),
            response_body: Some(String::new()),
            error: None,
        };
        let (first, second) = (claimed[0].0, claimed[1].0);

        // Attempt 1 of 2 fails: retried later, not claimable yet.
        record(&db, first, claimed[0].1, 1, 2, 30, &fail)
            .await
            .unwrap();
        let (status, attempt, later): (String, i32, bool) = sqlx::query_as(
            "SELECT status, attempt_number, next_attempt_at > NOW() + INTERVAL '20 seconds' FROM webhook_deliveries WHERE id = $1",
        )
        .bind(first)
        .fetch_one(&db)
        .await
        .unwrap();
        assert_eq!((status.as_str(), attempt, later), ("retrying", 2, true));
        assert!(mine(claim(&db, 100).await.unwrap()).is_empty());

        // Due now: claimed again; attempt 2 of 2 fails for good.
        sqlx::query("UPDATE webhook_deliveries SET next_attempt_at = NOW() WHERE id = $1")
            .bind(first)
            .execute(&db)
            .await
            .unwrap();
        let again = mine(claim(&db, 100).await.unwrap());
        assert_eq!(again.len(), 1);
        assert_eq!(again[0].4, 2, "the attempt number comes back");
        record(&db, first, claimed[0].1, 2, 2, 30, &fail)
            .await
            .unwrap();

        // The other succeeds.
        record(&db, second, claimed[1].1, 1, 2, 30, &ok)
            .await
            .unwrap();
        let rows: Vec<(Uuid, String, Option<i16>, bool)> = sqlx::query_as(
            "SELECT id, status, status_code, completed_at IS NOT NULL FROM webhook_deliveries WHERE id = ANY($1)",
        )
        .bind(vec![first, second])
        .fetch_all(&db)
        .await
        .unwrap();
        for (id, status, code, done) in rows {
            if id == first {
                assert_eq!((status.as_str(), code, done), ("failed", Some(500), true));
            } else {
                assert_eq!((status.as_str(), code, done), ("success", Some(204), true));
            }
        }
        let touched: bool =
            sqlx::query_scalar("SELECT last_triggered_at IS NOT NULL FROM webhooks WHERE id = $1")
                .bind(claimed[1].1)
                .fetch_one(&db)
                .await
                .unwrap();
        assert!(touched);

        sqlx::query("DELETE FROM webhooks WHERE user_id = ANY($1)")
            .bind(vec![alice, bob])
            .execute(&db)
            .await
            .unwrap();
    }
}
