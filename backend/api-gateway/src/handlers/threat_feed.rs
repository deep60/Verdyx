//! Threat feeds: Verdyx detections as STIX 2.1, served over TAXII 2.1.
//!
//! **STIX.** Every scan that ended malicious or suspicious becomes STIX
//! `indicator`s: one for the file's SHA-256 or the URL, and one for each
//! indicator an engine pulled out of it (URLs, domains, IP addresses,
//! hashes). Ids are UUID v5s of what they describe, so polling twice gives
//! the same objects. Each points back to its Verdyx report.
//!
//! - `GET /api/v1/submissions/{id}/stix`: one scan as a STIX bundle (anyone
//!   who can read the scan).
//!
//! **TAXII 2.1** (read-only), at the server root so TAXII clients find it:
//!
//! - `GET /taxii2/`: discovery
//! - `GET /taxii2/api/`: the API root
//! - `GET /taxii2/api/collections/`: "My scans" plus one per team
//! - `GET /taxii2/api/collections/{id}/`
//! - `GET /taxii2/api/collections/{id}/objects/?added_after&limit&next&match[type]`
//! - `GET /taxii2/api/collections/{id}/manifest/`
//!
//! Clients authenticate with an API key with the `read` scope: as
//! `X-API-Key`, a Bearer value, or the password of HTTP Basic auth (what
//! most TAXII clients offer). A team key sees only its team's collection.

use std::net::IpAddr;
use std::str::FromStr;

use axum::{
    extract::{Path, Query, State},
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use chrono::{DateTime, SecondsFormat, Utc};
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::middleware::auth::Claims;
use crate::AppState;

pub const TAXII_MEDIA_TYPE: &str = "application/taxii+json;version=2.1";
pub const STIX_MEDIA_TYPE: &str = "application/stix+json;version=2.1";
/// Namespace for Verdyx's deterministic STIX ids.
const NAMESPACE: Uuid = Uuid::from_u128(0x5f3c_6a1e_9b2d_4c07_8e41_d0a9_7b6c_2e18);
const PAGE_DEFAULT: i64 = 100;
const PAGE_MAX: i64 = 500;
/// Engine-extracted indicators kept per scan.
const MAX_IOCS_PER_SCAN: usize = 100;

fn site_url() -> String {
    std::env::var("PUBLIC_SITE_URL").unwrap_or_else(|_| "https://verdyx.dev".to_string())
}

fn stix_time(t: DateTime<Utc>) -> String {
    t.to_rfc3339_opts(SecondsFormat::Millis, true)
}

fn stix_id(kind: &str, name: &str) -> String {
    format!("{kind}--{}", Uuid::new_v5(&NAMESPACE, name.as_bytes()))
}

/// Verdyx as the STIX identity that creates every object.
pub fn identity() -> Value {
    json!({
        "type": "identity",
        "spec_version": "2.1",
        "id": stix_id("identity", "verdyx"),
        "created": "2026-01-01T00:00:00.000Z",
        "modified": "2026-01-01T00:00:00.000Z",
        "name": "Verdyx",
        "identity_class": "organization",
        "description": "Multi-engine malware and URL analysis",
    })
}

/// A value inside a STIX pattern string: backslashes and quotes escaped.
pub fn pattern_value(v: &str) -> String {
    v.replace('\\', "\\\\").replace('\'', "\\'")
}

/// The STIX pattern for an indicator value, and a short label, if it is a
/// kind STIX can express.
pub fn ioc_pattern(raw: &str) -> Option<(String, &'static str)> {
    let v = raw.trim();
    if v.is_empty() || v.len() > 2048 || v.chars().any(|c| c.is_control()) {
        return None;
    }
    let lower = v.to_ascii_lowercase();
    if lower.starts_with("http://") || lower.starts_with("https://") {
        return Some((format!("[url:value = '{}']", pattern_value(v)), "URL"));
    }
    if let Ok(ip) = IpAddr::from_str(v) {
        let kind = if ip.is_ipv4() {
            "ipv4-addr"
        } else {
            "ipv6-addr"
        };
        return Some((format!("[{kind}:value = '{ip}']"), "IP address"));
    }
    let hex = v.chars().all(|c| c.is_ascii_hexdigit());
    match (hex, v.len()) {
        (true, 64) => return Some((format!("[file:hashes.'SHA-256' = '{lower}']"), "SHA-256")),
        (true, 40) => return Some((format!("[file:hashes.'SHA-1' = '{lower}']"), "SHA-1")),
        (true, 32) => return Some((format!("[file:hashes.MD5 = '{lower}']"), "MD5")),
        _ => {}
    }
    if is_domain(&lower) {
        return Some((format!("[domain-name:value = '{lower}']"), "domain"));
    }
    None
}

fn is_domain(s: &str) -> bool {
    let labels: Vec<&str> = s.split('.').collect();
    labels.len() >= 2
        && s.len() <= 253
        && labels.iter().all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        })
        && labels
            .last()
            .is_some_and(|tld| tld.len() >= 2 && tld.chars().all(|c| c.is_ascii_alphabetic()))
}

/// One scan, as the feed sees it.
#[derive(Debug, Clone)]
pub struct FeedScan {
    pub id: Uuid,
    pub kind: String,
    pub filename: Option<String>,
    pub url: Option<String>,
    pub sha256: Option<String>,
    /// "malicious" or "suspicious".
    pub verdict: String,
    pub explanation: Option<String>,
    pub created_at: DateTime<Utc>,
    /// When it got its verdict: TAXII's "date added".
    pub updated_at: DateTime<Utc>,
    pub iocs: Vec<String>,
}

/// The STIX objects for one scan (no identity).
pub fn scan_objects(s: &FeedScan) -> Vec<Value> {
    let malicious = s.verdict == "malicious";
    let report = format!("{}/analysis/{}", site_url(), s.id);
    let subject = s
        .filename
        .clone()
        .or_else(|| s.url.clone())
        .unwrap_or_else(|| s.id.to_string());
    let mut primary: Option<(String, &'static str)> = None;
    if s.kind == "url" {
        primary = s.url.as_deref().and_then(ioc_pattern);
    } else if let Some(h) = &s.sha256 {
        primary = ioc_pattern(h);
    }
    let mut values: Vec<(String, &'static str, bool)> = Vec::new();
    if let Some((p, label)) = primary {
        values.push((p, label, true));
    }
    let mut seen = std::collections::BTreeSet::new();
    for ioc in s.iocs.iter().take(MAX_IOCS_PER_SCAN * 4) {
        if let Some((p, label)) = ioc_pattern(ioc) {
            if values.iter().any(|(v, _, _)| *v == p) || !seen.insert(p.clone()) {
                continue;
            }
            values.push((p, label, false));
            if values.len() > MAX_IOCS_PER_SCAN {
                break;
            }
        }
    }
    let creator = stix_id("identity", "verdyx");
    values
        .into_iter()
        .map(|(pattern, label, is_primary)| {
            let name = if is_primary {
                format!("{} {subject}", if malicious { "Malicious" } else { "Suspicious" })
            } else {
                format!("{label} seen in {subject}")
            };
            let mut description = format!("Verdyx verdict: {}.", s.verdict);
            if let Some(e) = &s.explanation {
                description.push(' ');
                description.push_str(e);
            }
            json!({
                "type": "indicator",
                "spec_version": "2.1",
                "id": stix_id("indicator", &format!("{}|{pattern}", s.id)),
                "created_by_ref": creator,
                "created": stix_time(s.created_at),
                "modified": stix_time(s.updated_at),
                "name": name,
                "description": description,
                "indicator_types": [if malicious { "malicious-activity" } else { "anomalous-activity" }],
                "pattern": pattern,
                "pattern_type": "stix",
                "pattern_version": "2.1",
                "valid_from": stix_time(s.updated_at),
                "confidence": if !is_primary { 60 } else if malicious { 85 } else { 50 },
                "labels": [s.kind.clone()],
                "external_references": [{
                    "source_name": "Verdyx",
                    "url": report,
                    "external_id": s.id.to_string(),
                }],
            })
        })
        .collect()
}

pub fn bundle(objects: Vec<Value>) -> Value {
    json!({ "type": "bundle", "id": format!("bundle--{}", Uuid::new_v4()), "objects": objects })
}

// ── Queries ──────────────────────────────────────────────────────────────

const SCAN_SQL: &str = r#"
    SELECT s.id, s.submission_type, s.original_filename, s.url, s.file_hash,
           CASE WHEN s.is_malicious THEN 'malicious' ELSE s.metadata ->> 'consensus_verdict' END,
           s.metadata ->> 'consensus_explanation', s.created_at, s.updated_at,
           COALESCE((SELECT array_agg(DISTINCT v) FROM analysis_results r,
                      jsonb_array_elements_text(CASE WHEN jsonb_typeof(r.metadata -> 'iocs') = 'array'
                                                     THEN r.metadata -> 'iocs' ELSE '[]'::jsonb END) v
                     WHERE r.submission_id = s.id), ARRAY[]::text[])
    FROM submissions s
"#;

type ScanRow = (
    Uuid,
    String,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    DateTime<Utc>,
    DateTime<Utc>,
    Vec<String>,
);

fn to_scan(r: ScanRow) -> FeedScan {
    FeedScan {
        id: r.0,
        kind: r.1,
        filename: r.2,
        url: r.3,
        sha256: r.4,
        verdict: r.5.unwrap_or_else(|| "suspicious".into()),
        explanation: r.6,
        created_at: r.7,
        updated_at: r.8,
        iocs: r.9,
    }
}

/// Which scans a collection holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    Person(Uuid),
    Team(Uuid),
}

pub fn personal_collection(user: Uuid) -> Uuid {
    Uuid::new_v5(&NAMESPACE, format!("collection:personal:{user}").as_bytes())
}

/// A page of feed scans, oldest first after `after`.
async fn feed_page(
    state: &AppState,
    scope: Scope,
    after: Option<(DateTime<Utc>, Uuid)>,
    // Include the cursor's own scan (the previous page stopped inside it).
    inclusive: bool,
    limit: i64,
) -> Result<Vec<FeedScan>, sqlx::Error> {
    let (filter, owner) = match scope {
        Scope::Person(u) => ("s.submitter_id = $1", u),
        Scope::Team(t) => ("s.organization_id = $1", t),
    };
    let (ts, id) = (after.map(|a| a.0), after.map(|a| a.1));
    let rows: Vec<ScanRow> = sqlx::query_as(&format!(
        "{SCAN_SQL} WHERE {filter}
           AND (s.is_malicious OR s.metadata ->> 'consensus_verdict' IN ('malicious', 'suspicious'))
           AND ($2::timestamptz IS NULL OR (s.updated_at, s.id) > ($2, $3::uuid)
                OR ($5 AND (s.updated_at, s.id) = ($2, $3::uuid)))
         ORDER BY s.updated_at, s.id LIMIT $4"
    ))
    .bind(owner)
    .bind(ts)
    .bind(id)
    .bind(limit)
    .bind(inclusive)
    .fetch_all(state.db.pool())
    .await?;
    Ok(rows.into_iter().map(to_scan).collect())
}

// ── HTTP ─────────────────────────────────────────────────────────────────

fn taxii(status: StatusCode, body: Value) -> Response {
    let mut r = (status, Json(body)).into_response();
    r.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(TAXII_MEDIA_TYPE),
    );
    r
}

/// TAXII's error message shape.
fn taxii_error(status: StatusCode, title: &str) -> Response {
    taxii(
        status,
        json!({ "title": title, "http_status": status.as_u16().to_string() }),
    )
}

fn db_error(e: sqlx::Error) -> Response {
    tracing::error!("threat feed query failed: {e}");
    taxii_error(StatusCode::INTERNAL_SERVER_ERROR, "something went wrong")
}

/// The API root's absolute URL: `PUBLIC_API_URL`, else the address the
/// request came to (TAXII clients want absolute URLs).
pub fn api_root_url(headers: &axum::http::HeaderMap) -> String {
    if let Ok(u) = std::env::var("PUBLIC_API_URL") {
        if !u.trim().is_empty() {
            return format!("{}/taxii2/api/", u.trim().trim_end_matches('/'));
        }
    }
    let host = headers
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .filter(|h| {
            h.chars()
                .all(|c| c.is_ascii_alphanumeric() || ".-:[]".contains(c))
        });
    let Some(host) = host else {
        return "/taxii2/api/".to_string();
    };
    let local =
        host.starts_with("localhost") || host.starts_with("127.") || host.starts_with("[::1]");
    let scheme = headers
        .get("x-forwarded-proto")
        .and_then(|h| h.to_str().ok())
        .filter(|p| *p == "http" || *p == "https")
        .unwrap_or(if local { "http" } else { "https" });
    format!("{scheme}://{host}/taxii2/api/")
}

/// `GET /taxii2/`
pub async fn discovery(headers: axum::http::HeaderMap) -> Response {
    let root = api_root_url(&headers);
    taxii(
        StatusCode::OK,
        json!({
            "title": "Verdyx threat feed",
            "description": "Malicious and suspicious files and URLs found by Verdyx, as STIX 2.1",
            "default": root,
            "api_roots": [root],
        }),
    )
}

/// `GET /taxii2/api/`
pub async fn api_root() -> Response {
    taxii(
        StatusCode::OK,
        json!({
            "title": "Verdyx",
            "versions": [TAXII_MEDIA_TYPE],
            "max_content_length": 10 * 1024 * 1024,
        }),
    )
}

fn collection_json(id: Uuid, title: &str, description: &str) -> Value {
    json!({
        "id": id,
        "title": title,
        "description": description,
        "can_read": true,
        "can_write": false,
        "media_types": [STIX_MEDIA_TYPE],
    })
}

/// The collections the caller may read.
async fn collections_for(
    state: &AppState,
    claims: &Claims,
) -> Result<Vec<(Uuid, Scope, Value)>, sqlx::Error> {
    if let Some(team) = claims.org_id {
        let name: Option<String> =
            sqlx::query_scalar("SELECT name FROM organizations WHERE id = $1")
                .bind(team)
                .fetch_optional(state.db.pool())
                .await?;
        return Ok(name
            .map(|n| {
                vec![(
                    team,
                    Scope::Team(team),
                    collection_json(team, &format!("Team: {n}"), "Scans saved to this team"),
                )]
            })
            .unwrap_or_default());
    }
    let me = personal_collection(claims.sub);
    let mut out = vec![(
        me,
        Scope::Person(claims.sub),
        collection_json(
            me,
            "My scans",
            "Scans you made, including those saved to teams",
        ),
    )];
    let teams: Vec<(Uuid, String)> = sqlx::query_as(
        "SELECT o.id, o.name FROM organizations o JOIN organization_members m ON m.organization_id = o.id
         WHERE m.user_id = $1 ORDER BY o.name",
    )
    .bind(claims.sub)
    .fetch_all(state.db.pool())
    .await?;
    for (id, name) in teams {
        out.push((
            id,
            Scope::Team(id),
            collection_json(id, &format!("Team: {name}"), "Scans saved to this team"),
        ));
    }
    Ok(out)
}

/// `GET /taxii2/api/collections/`
pub async fn collections(State(state): State<AppState>, claims: Claims) -> Response {
    match collections_for(&state, &claims).await {
        Ok(c) => taxii(
            StatusCode::OK,
            json!({ "collections": c.into_iter().map(|(_, _, v)| v).collect::<Vec<_>>() }),
        ),
        Err(e) => db_error(e),
    }
}

async fn find_collection(
    state: &AppState,
    claims: &Claims,
    id: Uuid,
) -> Result<(Scope, Value), Box<Response>> {
    let all = collections_for(state, claims)
        .await
        .map_err(|e| Box::new(db_error(e)))?;
    all.into_iter()
        .find(|(cid, _, _)| *cid == id)
        .map(|(_, s, v)| (s, v))
        .ok_or_else(|| Box::new(taxii_error(StatusCode::NOT_FOUND, "collection not found")))
}

/// `GET /taxii2/api/collections/{id}/`
pub async fn collection(
    State(state): State<AppState>,
    claims: Claims,
    Path(id): Path<Uuid>,
) -> Response {
    match find_collection(&state, &claims, id).await {
        Ok((_, v)) => taxii(StatusCode::OK, v),
        Err(r) => *r,
    }
}

#[derive(Debug, Deserialize, Default)]
pub struct ObjectsQuery {
    pub added_after: Option<String>,
    pub limit: Option<i64>,
    pub next: Option<String>,
    #[serde(rename = "match[type]")]
    pub match_type: Option<String>,
}

/// `next` is "<micros>_<scan id>_<skip>": the scan the previous page stopped
/// in, and how many of its objects were already sent.
pub fn encode_next(t: DateTime<Utc>, id: Uuid, skip: usize) -> String {
    format!("{}_{}_{skip}", t.timestamp_micros(), id.simple())
}

pub fn decode_next(s: &str) -> Option<(DateTime<Utc>, Uuid, usize)> {
    let mut parts = s.splitn(3, '_');
    let micros = parts.next()?.parse().ok()?;
    let id = Uuid::parse_str(parts.next()?).ok()?;
    let skip = parts.next()?.parse().ok()?;
    Some((DateTime::from_timestamp_micros(micros)?, id, skip))
}

/// One page of objects. `limit` counts objects, as TAXII requires, so a
/// scan's indicators can span pages.
struct Page {
    /// (object, its scan's date added)
    objects: Vec<(Value, DateTime<Utc>)>,
    more: bool,
    next: Option<String>,
}

fn wanted(q: &ObjectsQuery, kind: &str) -> bool {
    q.match_type
        .as_deref()
        .is_none_or(|types| types.split(',').any(|t| t.trim() == kind))
}

async fn page(state: &AppState, scope: Scope, q: &ObjectsQuery) -> Result<Page, Box<Response>> {
    let limit = q.limit.unwrap_or(PAGE_DEFAULT).clamp(1, PAGE_MAX) as usize;
    let bad = |m: &str| Box::new(taxii_error(StatusCode::BAD_REQUEST, m));
    let (after, inclusive, mut skip) = match (&q.next, &q.added_after) {
        (Some(n), _) => {
            // The cursor's scan is fetched again and its first `skip`
            // objects (already sent) are skipped.
            let (t, id, skip) = decode_next(n).ok_or_else(|| bad("next is not valid"))?;
            (Some((t, id)), true, skip)
        }
        (None, Some(a)) => (
            Some((
                DateTime::parse_from_rfc3339(a)
                    .map_err(|_| bad("added_after must be an RFC 3339 time"))?
                    .with_timezone(&Utc),
                // Strictly after the time: the largest id puts every scan
                // at that instant before the cursor.
                Uuid::max(),
            )),
            false,
            0,
        ),
        _ => (None, false, 0),
    };
    // Some scans yield no object (nothing STIX can express), so fetch spare.
    let fetch = (limit + 50) as i64;
    let scans = feed_page(state, scope, after, inclusive, fetch)
        .await
        .map_err(|e| Box::new(db_error(e)))?;
    let mut objects = Vec::new();
    if q.next.is_none() && wanted(q, "identity") && !scans.is_empty() {
        objects.push((identity(), scans[0].updated_at));
    }
    let mut next = None;
    let mut last_done: Option<(DateTime<Utc>, Uuid, usize)> = None;
    'scans: for s in &scans {
        let objs: Vec<Value> = if wanted(q, "indicator") {
            scan_objects(s)
        } else {
            Vec::new()
        };
        let total = objs.len();
        for (i, o) in objs.into_iter().enumerate().skip(skip) {
            if objects.len() == limit {
                next = Some(encode_next(s.updated_at, s.id, i));
                break 'scans;
            }
            objects.push((o, s.updated_at));
        }
        skip = 0;
        last_done = Some((s.updated_at, s.id, total));
    }
    // Every fetched scan was sent, but more scans may follow them.
    if next.is_none() && scans.len() == fetch as usize {
        next = last_done.map(|(t, id, n)| encode_next(t, id, n));
    }
    let more = next.is_some();
    Ok(Page {
        objects,
        more,
        next: if more { next } else { None },
    })
}

fn envelope(p: &Page, body_objects: Vec<Value>) -> Response {
    let mut body = json!({ "more": p.more, "objects": body_objects });
    if let Some(n) = &p.next {
        body["next"] = json!(n);
    }
    let mut r = taxii(StatusCode::OK, body);
    if let (Some(first), Some(last)) = (p.objects.first(), p.objects.last()) {
        for (name, t) in [
            ("x-taxii-date-added-first", first.1),
            ("x-taxii-date-added-last", last.1),
        ] {
            if let Ok(v) = HeaderValue::from_str(&stix_time(t)) {
                r.headers_mut().insert(name, v);
            }
        }
    }
    r
}

/// `GET /taxii2/api/collections/{id}/objects/`
pub async fn objects(
    State(state): State<AppState>,
    claims: Claims,
    Path(id): Path<Uuid>,
    Query(q): Query<ObjectsQuery>,
) -> Response {
    let scope = match find_collection(&state, &claims, id).await {
        Ok((s, _)) => s,
        Err(r) => return *r,
    };
    match page(&state, scope, &q).await {
        Ok(p) => {
            let objs = p.objects.iter().map(|(o, _)| o.clone()).collect();
            envelope(&p, objs)
        }
        Err(r) => *r,
    }
}

/// `GET /taxii2/api/collections/{id}/manifest/`
pub async fn manifest(
    State(state): State<AppState>,
    claims: Claims,
    Path(id): Path<Uuid>,
    Query(q): Query<ObjectsQuery>,
) -> Response {
    let scope = match find_collection(&state, &claims, id).await {
        Ok((s, _)) => s,
        Err(r) => return *r,
    };
    match page(&state, scope, &q).await {
        Ok(p) => {
            let entries = p
                .objects
                .iter()
                .map(|(o, added)| {
                    json!({
                        "id": o["id"],
                        "date_added": stix_time(*added),
                        "version": o["modified"],
                        "media_type": STIX_MEDIA_TYPE,
                    })
                })
                .collect();
            envelope(&p, entries)
        }
        Err(r) => *r,
    }
}

/// `GET /api/v1/submissions/{id}/stix`: one scan as a STIX bundle.
pub async fn submission_bundle(
    State(state): State<AppState>,
    claims: Option<Claims>,
    Path(id): Path<Uuid>,
) -> Result<Response, StatusCode> {
    crate::handlers::submission::load_visible_submission(&state, id, claims.as_ref()).await?;
    let row: Option<ScanRow> = sqlx::query_as(&format!("{SCAN_SQL} WHERE s.id = $1"))
        .bind(id)
        .fetch_optional(state.db.pool())
        .await
        .map_err(|e| {
            tracing::error!("STIX export failed: {e}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    let scan = row.map(to_scan).ok_or(StatusCode::NOT_FOUND)?;
    let objects = if matches!(scan.verdict.as_str(), "malicious" | "suspicious") {
        let mut o = vec![identity()];
        o.extend(scan_objects(&scan));
        o
    } else {
        // Nothing to indicate: a clean scan exports as an empty bundle.
        Vec::new()
    };
    let mut r = Json(bundle(objects)).into_response();
    r.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(STIX_MEDIA_TYPE),
    );
    if let Ok(v) = HeaderValue::from_str(&format!("attachment; filename=\"verdyx-{id}.stix.json\""))
    {
        r.headers_mut().insert(header::CONTENT_DISPOSITION, v);
    }
    Ok(r)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scan(kind: &str, verdict: &str, iocs: &[&str]) -> FeedScan {
        let t: DateTime<Utc> = "2026-11-17T10:00:00Z".parse().unwrap();
        FeedScan {
            id: Uuid::from_u128(7),
            kind: kind.into(),
            filename: Some("invoice.docm".into()),
            url: Some("https://evil.example/login".into()),
            sha256: Some("A".repeat(64)),
            verdict: verdict.into(),
            explanation: Some("macro downloads and runs code".into()),
            created_at: t,
            updated_at: t,
            iocs: iocs.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn indicator_values_become_stix_patterns() {
        assert_eq!(
            ioc_pattern("https://a.example/x?q=1").unwrap().0,
            "[url:value = 'https://a.example/x?q=1']"
        );
        assert_eq!(
            ioc_pattern("203.0.113.9").unwrap().0,
            "[ipv4-addr:value = '203.0.113.9']"
        );
        assert_eq!(
            ioc_pattern("2001:db8::1").unwrap().0,
            "[ipv6-addr:value = '2001:db8::1']"
        );
        assert_eq!(
            ioc_pattern("Evil.Example.COM").unwrap().0,
            "[domain-name:value = 'evil.example.com']"
        );
        assert_eq!(ioc_pattern(&"ab".repeat(32)).unwrap().1, "SHA-256");
        assert_eq!(
            ioc_pattern(&"ab".repeat(16)).unwrap().0,
            format!("[file:hashes.MD5 = '{}']", "ab".repeat(16))
        );
        for junk in [
            "",
            "hello",
            "C:\\Windows\\cmd.exe",
            "a.b",
            "1.2.3",
            "-bad.example",
            "\\\\host\\share",
            "x\ny.com",
        ] {
            assert!(ioc_pattern(junk).is_none(), "{junk:?}");
        }
        // Quotes can't break out of the pattern.
        assert_eq!(
            ioc_pattern("https://a.example/'] OR [x:y = 'z").unwrap().0,
            "[url:value = 'https://a.example/\\'] OR [x:y = \\'z']"
        );
    }

    #[test]
    fn a_malicious_file_scan_becomes_indicators() {
        let objs = scan_objects(&scan(
            "file",
            "malicious",
            &[
                "http://203.0.113.9/p.exe",
                "203.0.113.9",
                "junk",
                "203.0.113.9",
            ],
        ));
        assert_eq!(objs.len(), 3, "{objs:#?}");
        let main = &objs[0];
        assert_eq!(
            main["pattern"],
            format!("[file:hashes.'SHA-256' = '{}']", "a".repeat(64))
        );
        assert_eq!(main["indicator_types"], json!(["malicious-activity"]));
        assert_eq!(main["confidence"], 85);
        assert_eq!(main["name"], "Malicious invoice.docm");
        assert_eq!(main["spec_version"], "2.1");
        assert_eq!(main["created_by_ref"], identity()["id"]);
        assert!(main["external_references"][0]["url"]
            .as_str()
            .unwrap()
            .ends_with("/analysis/00000000-0000-0000-0000-000000000007"));
        assert_eq!(
            objs[1]["pattern"],
            "[url:value = 'http://203.0.113.9/p.exe']"
        );
        assert_eq!(objs[2]["pattern"], "[ipv4-addr:value = '203.0.113.9']");
    }

    #[test]
    fn ids_are_stable_and_suspicious_is_softer() {
        let a = scan_objects(&scan("url", "suspicious", &[]));
        let b = scan_objects(&scan("url", "suspicious", &[]));
        assert_eq!(a[0]["id"], b[0]["id"], "the same scan gives the same ids");
        assert_eq!(
            a[0]["pattern"],
            "[url:value = 'https://evil.example/login']"
        );
        assert_eq!(a[0]["indicator_types"], json!(["anomalous-activity"]));
        assert_eq!(a[0]["confidence"], 50);
        assert!(a[0]["id"].as_str().unwrap().starts_with("indicator--"));
        assert_eq!(identity()["id"], identity()["id"]);
    }

    #[test]
    fn cursors_round_trip() {
        let t: DateTime<Utc> = "2026-11-17T10:00:00.123456Z".parse().unwrap();
        let id = Uuid::new_v4();
        assert_eq!(decode_next(&encode_next(t, id, 3)), Some((t, id, 3)));
        assert_eq!(decode_next("nope"), None);
        assert_eq!(decode_next("12_notauuid"), None);
    }

    #[test]
    fn collections_ids_differ_per_person() {
        assert_ne!(
            personal_collection(Uuid::new_v4()),
            personal_collection(Uuid::new_v4())
        );
        let u = Uuid::new_v4();
        assert_eq!(personal_collection(u), personal_collection(u));
    }

    #[test]
    fn the_api_root_is_absolute() {
        use axum::http::HeaderMap;
        let mut h = HeaderMap::new();
        h.insert(header::HOST, HeaderValue::from_static("api.verdyx.dev"));
        assert_eq!(api_root_url(&h), "https://api.verdyx.dev/taxii2/api/");
        h.insert(header::HOST, HeaderValue::from_static("127.0.0.1:18082"));
        assert_eq!(api_root_url(&h), "http://127.0.0.1:18082/taxii2/api/");
        h.insert("x-forwarded-proto", HeaderValue::from_static("https"));
        assert_eq!(api_root_url(&h), "https://127.0.0.1:18082/taxii2/api/");
        // A host header that isn't a host name isn't echoed.
        h.insert(header::HOST, HeaderValue::from_static("evil.example/<x>"));
        assert_eq!(api_root_url(&h), "/taxii2/api/");
    }

    #[test]
    fn type_filters() {
        let q = ObjectsQuery {
            match_type: Some("indicator".into()),
            ..Default::default()
        };
        assert!(wanted(&q, "indicator") && !wanted(&q, "identity"));
        assert!(wanted(&ObjectsQuery::default(), "identity"));
    }
}
