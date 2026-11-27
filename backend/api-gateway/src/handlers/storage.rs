//! Cloud storage scanning for teams: connect an S3-compatible bucket, and
//! the files that arrive in it are scanned
//! ([`crate::services::storage_scan`]).
//!
//! Owners and admins manage connections at `/orgs/{id}/storage`. A
//! connection is tested (one listing request) before it's saved, and its
//! secret access key is stored sealed, like SIEM credentials. Read-only keys
//! are enough: Verdyx only lists and downloads.

// Query rows are read as plain tuples.
#![allow(clippy::type_complexity)]

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Json,
};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::handlers::organization::{can_manage, member_role};
use crate::middleware::auth::Claims;
use crate::services::s3::{self, Bucket, Keys};
use crate::services::{audit, siem::CredentialKey};
use crate::AppState;

// How many connections a team may have comes from its plan.
pub const INTERVALS: [i32; 5] = [15, 60, 180, 360, 1440];

type ApiError = (StatusCode, Json<Value>);
type ApiResult<T> = Result<T, ApiError>;

fn err(status: StatusCode, message: &str) -> ApiError {
    (
        status,
        Json(json!({ "error": message, "status": status.as_u16() })),
    )
}

fn db_err(e: sqlx::Error) -> ApiError {
    tracing::error!("storage query failed: {e}");
    err(StatusCode::INTERNAL_SERVER_ERROR, "something went wrong")
}

fn key(state: &AppState) -> CredentialKey {
    CredentialKey::from_config(&state.config.security.jwt_secret)
}

async fn require_manager(state: &AppState, org_id: Uuid, claims: &Claims) -> ApiResult<()> {
    let role = member_role(state.db.pool(), org_id, claims.sub)
        .await
        .map_err(db_err)?
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "team not found"))?;
    if can_manage(&role) {
        Ok(())
    } else {
        Err(err(
            StatusCode::FORBIDDEN,
            "only owners and admins can manage storage connections",
        ))
    }
}

// ─── Settings (pure, unit-tested) ─────────────────────────────────────

/// What a team sends to make or change a connection. On a change, missing
/// fields keep their value.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionInput {
    pub name: Option<String>,
    pub provider: Option<String>,
    pub endpoint: Option<String>,
    pub region: Option<String>,
    pub bucket: Option<String>,
    pub prefix: Option<String>,
    pub access_key_id: Option<String>,
    pub secret_access_key: Option<String>,
    pub analysis_type: Option<String>,
    pub interval_minutes: Option<i32>,
    pub max_object_mb: Option<i32>,
    pub enabled: Option<bool>,
    /// On a new connection: also scan the files already in the bucket.
    pub scan_existing: Option<bool>,
}

/// A connection's settings, checked.
#[derive(Debug, Clone, PartialEq)]
pub struct Settings {
    pub name: String,
    pub provider: String,
    pub endpoint: Option<url::Url>,
    pub region: String,
    pub bucket: String,
    pub prefix: String,
    pub access_key_id: String,
    pub analysis_type: String,
    pub interval_minutes: i32,
    pub max_object_mb: i32,
    pub enabled: bool,
}

impl Settings {
    pub fn bucket(&self) -> Bucket {
        Bucket {
            endpoint: self.endpoint.clone(),
            region: self.region.clone(),
            name: self.bucket.clone(),
        }
    }

    /// Whether going from `self` to `next` changes where Verdyx reads from,
    /// so the connection has to be tested again.
    pub fn moved(&self, next: &Settings) -> bool {
        self.endpoint != next.endpoint
            || self.region != next.region
            || self.bucket != next.bucket
            || self.prefix != next.prefix
            || self.access_key_id != next.access_key_id
    }
}

/// The checked settings from `input` laid over `current` (`None` for a new
/// connection), or what's wrong. The secret is checked by the caller.
pub fn settle(
    input: &ConnectionInput,
    current: Option<&Settings>,
    max_file_mb: i32,
) -> Result<Settings, String> {
    let text = |v: &Option<String>| v.as_deref().map(str::trim).map(str::to_string);
    let provider = match text(&input.provider)
        .or_else(|| current.map(|c| c.provider.clone()))
        .as_deref()
    {
        None | Some("") | Some("other") => "other".to_string(),
        Some(p @ ("aws" | "r2" | "gcs")) => p.to_string(),
        Some(_) => return Err("provider must be aws, r2, gcs or other".into()),
    };
    let name = text(&input.name)
        .or_else(|| current.map(|c| c.name.clone()))
        .unwrap_or_default();
    if name.is_empty() || name.chars().count() > 80 {
        return Err("give the connection a name of up to 80 characters".into());
    }
    let bucket = match text(&input.bucket).or_else(|| current.map(|c| c.bucket.clone())) {
        Some(b) => s3::clean_bucket(&b)?,
        None => return Err("enter the bucket's name".into()),
    };
    let endpoint_raw = match &input.endpoint {
        Some(e) => Some(e.trim().to_string()).filter(|e| !e.is_empty()),
        None => current.and_then(|c| c.endpoint.as_ref().map(|u| u.to_string())),
    };
    let endpoint = match (provider.as_str(), endpoint_raw) {
        ("aws", _) => None,
        ("gcs", None) => Some(s3::clean_endpoint("https://storage.googleapis.com")?),
        (_, Some(e)) => Some(s3::clean_endpoint(&e)?),
        ("r2", None) => {
            return Err(
                "enter your R2 endpoint: https://<account id>.r2.cloudflarestorage.com".into(),
            )
        }
        (_, None) => return Err("enter the storage service's endpoint".into()),
    };
    let region = match text(&input.region)
        .filter(|r| !r.is_empty())
        .or_else(|| current.map(|c| c.region.clone()))
    {
        Some(r) => s3::clean_region(&r)?,
        None if provider == "aws" => {
            return Err("enter the bucket's region, such as us-east-1".into())
        }
        None if provider == "other" => "us-east-1".to_string(),
        None => "auto".to_string(),
    };
    let prefix = match &input.prefix {
        Some(p) => s3::clean_prefix(p)?,
        None => current.map(|c| c.prefix.clone()).unwrap_or_default(),
    };
    let access_key_id = text(&input.access_key_id)
        .or_else(|| current.map(|c| c.access_key_id.clone()))
        .unwrap_or_default();
    if access_key_id.is_empty()
        || access_key_id.len() > 128
        || !access_key_id.chars().all(|c| c.is_ascii_graphic())
    {
        return Err("enter the access key ID".into());
    }
    let analysis_type = match text(&input.analysis_type)
        .or_else(|| current.map(|c| c.analysis_type.clone()))
        .as_deref()
    {
        None | Some("") => "full".to_string(),
        Some(t @ ("quick" | "full" | "deep")) => t.to_string(),
        Some(_) => return Err("analysisType must be quick, full or deep".into()),
    };
    let interval_minutes = input
        .interval_minutes
        .or_else(|| current.map(|c| c.interval_minutes))
        .unwrap_or(60);
    if !INTERVALS.contains(&interval_minutes) {
        return Err("intervalMinutes must be 15, 60, 180, 360 or 1440".into());
    }
    let max_object_mb = input
        .max_object_mb
        .or_else(|| current.map(|c| c.max_object_mb))
        .unwrap_or(32.min(max_file_mb));
    if !(1..=max_file_mb.min(100)).contains(&max_object_mb) {
        return Err(format!(
            "maxObjectMb must be between 1 and {}",
            max_file_mb.min(100)
        ));
    }
    let enabled = input
        .enabled
        .or_else(|| current.map(|c| c.enabled))
        .unwrap_or(true);
    Ok(Settings {
        name,
        provider,
        endpoint,
        region,
        bucket,
        prefix,
        access_key_id,
        analysis_type,
        interval_minutes,
        max_object_mb,
        enabled,
    })
}

/// A secret access key as sent, or why it isn't one.
pub fn clean_secret_key(raw: &str) -> Result<String, &'static str> {
    let k = raw.trim();
    if k.is_empty() || k.len() > 256 || !k.chars().all(|c| c.is_ascii_graphic()) {
        return Err("enter the secret access key");
    }
    Ok(k.to_string())
}

/// Lists one object, so a wrong key or bucket is found when it's saved.
async fn test_connection(settings: &Settings, keys: &Keys) -> ApiResult<()> {
    let http = crate::services::webhook_delivery::client(false);
    settings
        .bucket()
        .list(&http, keys, &settings.prefix, None, 1)
        .await
        .map(|_| ())
        .map_err(|e| {
            err(
                StatusCode::BAD_REQUEST,
                &format!("Verdyx couldn't list the bucket: {}", e.explain()),
            )
        })
}

// ─── Reading ──────────────────────────────────────────────────────────

const COLUMNS: &str = "id, name, provider, endpoint, region, bucket, prefix, access_key_id,
    analysis_type, interval_minutes, max_object_mb, enabled, scan_since, run_requested,
    running_since, last_run_at, last_error, last_scanned, created_at";

#[derive(Debug, sqlx::FromRow)]
struct Row {
    id: Uuid,
    name: String,
    provider: String,
    endpoint: Option<String>,
    region: String,
    bucket: String,
    prefix: String,
    access_key_id: String,
    analysis_type: String,
    interval_minutes: i32,
    max_object_mb: i32,
    enabled: bool,
    scan_since: DateTime<Utc>,
    run_requested: bool,
    running_since: Option<DateTime<Utc>>,
    last_run_at: Option<DateTime<Utc>>,
    last_error: Option<String>,
    last_scanned: i32,
    created_at: DateTime<Utc>,
}

fn settings_of(r: &Row) -> Settings {
    Settings {
        name: r.name.clone(),
        provider: r.provider.clone(),
        endpoint: r.endpoint.as_deref().and_then(|e| url::Url::parse(e).ok()),
        region: r.region.clone(),
        bucket: r.bucket.clone(),
        prefix: r.prefix.clone(),
        access_key_id: r.access_key_id.clone(),
        analysis_type: r.analysis_type.clone(),
        interval_minutes: r.interval_minutes,
        max_object_mb: r.max_object_mb,
        enabled: r.enabled,
    }
}

fn endpoint_text(u: &Option<url::Url>) -> Option<String> {
    u.as_ref()
        .map(|u| u.as_str().trim_end_matches('/').to_string())
}

/// Counts of what a connection has looked at: (files, flagged, waiting).
async fn stats(pool: &sqlx::PgPool, id: Uuid) -> Result<(i64, i64, i64), sqlx::Error> {
    sqlx::query_as(
        "SELECT COUNT(*),
                COUNT(*) FILTER (WHERE LOWER(s.metadata->>'consensus_verdict') IN ('malicious', 'suspicious')),
                COUNT(*) FILTER (WHERE o.status = 'queued' AND s.analysis_status IN ('pending', 'analyzing'))
         FROM storage_objects o
         LEFT JOIN submissions s ON s.id = o.submission_id
         WHERE o.connection_id = $1",
    )
    .bind(id)
    .fetch_one(pool)
    .await
}

async fn to_json(pool: &sqlx::PgPool, r: &Row) -> Result<Value, sqlx::Error> {
    let (files, flagged, waiting) = stats(pool, r.id).await?;
    let s = settings_of(r);
    Ok(json!({
        "id": r.id,
        "name": s.name,
        "provider": s.provider,
        "endpoint": endpoint_text(&s.endpoint),
        "region": s.region,
        "bucket": s.bucket,
        "prefix": s.prefix,
        "accessKeyId": s.access_key_id,
        "analysisType": s.analysis_type,
        "intervalMinutes": s.interval_minutes,
        "maxObjectMb": s.max_object_mb,
        "enabled": s.enabled,
        "scanSince": r.scan_since,
        "scanRequested": r.run_requested,
        "running": r.running_since.is_some(),
        "lastRunAt": r.last_run_at,
        "lastError": r.last_error,
        "lastScanned": r.last_scanned,
        "createdAt": r.created_at,
        "stats": { "files": files, "flagged": flagged, "waiting": waiting },
    }))
}

async fn find(pool: &sqlx::PgPool, org_id: Uuid, id: Uuid) -> ApiResult<Row> {
    sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM storage_connections WHERE id = $1 AND organization_id = $2"
    ))
    .bind(id)
    .bind(org_id)
    .fetch_optional(pool)
    .await
    .map_err(db_err)?
    .ok_or_else(|| err(StatusCode::NOT_FOUND, "storage connection not found"))
}

/// `GET /orgs/{id}/storage`
pub async fn list(
    State(state): State<AppState>,
    claims: Claims,
    Path(org_id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    require_manager(&state, org_id, &claims).await?;
    let pool = state.db.pool();
    let rows: Vec<Row> = sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM storage_connections WHERE organization_id = $1 ORDER BY created_at"
    ))
    .bind(org_id)
    .fetch_all(pool)
    .await
    .map_err(db_err)?;
    let mut out = Vec::with_capacity(rows.len());
    for r in &rows {
        out.push(to_json(pool, r).await.map_err(db_err)?);
    }
    let limit = crate::services::plans::team_plan(pool, org_id)
        .await
        .map_err(db_err)?
        .limits
        .storage_connections;
    Ok(Json(json!({
        "connections": out,
        "limit": limit,
        "maxObjectMb": state.config.services.max_file_size_mb.min(100),
    })))
}

/// `POST /orgs/{id}/storage`
pub async fn create(
    State(state): State<AppState>,
    claims: Claims,
    Path(org_id): Path<Uuid>,
    Json(input): Json<ConnectionInput>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    require_manager(&state, org_id, &claims).await?;
    let pool = state.db.pool();
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM storage_connections WHERE organization_id = $1")
            .bind(org_id)
            .fetch_one(pool)
            .await
            .map_err(db_err)?;
    let limit = crate::services::plans::team_plan(pool, org_id)
        .await
        .map_err(db_err)?
        .limits
        .storage_connections;
    if count >= limit {
        return Err(err(
            StatusCode::CONFLICT,
            &format!("this team's plan allows {limit} storage connections"),
        ));
    }
    let max_mb = state.config.services.max_file_size_mb as i32;
    let settings = settle(&input, None, max_mb).map_err(|m| err(StatusCode::BAD_REQUEST, &m))?;
    let secret = clean_secret_key(input.secret_access_key.as_deref().unwrap_or_default())
        .map_err(|m| err(StatusCode::BAD_REQUEST, m))?;
    let keys = Keys {
        access_key_id: settings.access_key_id.clone(),
        secret_access_key: secret.clone(),
    };
    test_connection(&settings, &keys).await?;

    let id = Uuid::new_v4();
    let scan_since: DateTime<Utc> = if input.scan_existing.unwrap_or(false) {
        DateTime::UNIX_EPOCH
    } else {
        Utc::now()
    };
    sqlx::query(
        "INSERT INTO storage_connections
            (id, organization_id, created_by, name, provider, endpoint, region, bucket, prefix,
             access_key_id, secret_access_key, analysis_type, interval_minutes, max_object_mb,
             scan_since, enabled, run_requested)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $16)",
    )
    .bind(id)
    .bind(org_id)
    .bind(claims.sub)
    .bind(&settings.name)
    .bind(&settings.provider)
    .bind(endpoint_text(&settings.endpoint))
    .bind(&settings.region)
    .bind(&settings.bucket)
    .bind(&settings.prefix)
    .bind(&settings.access_key_id)
    .bind(key(&state).seal(&secret))
    .bind(&settings.analysis_type)
    .bind(settings.interval_minutes)
    .bind(settings.max_object_mb)
    .bind(scan_since)
    .bind(settings.enabled)
    .execute(pool)
    .await
    .map_err(db_err)?;

    audit::Event::by(&claims, "team.storage_added")
        .team(org_id)
        .target("storage_connection", id)
        .detail("name", settings.name.clone())
        .detail("bucket", settings.bucket.clone())
        .detail("provider", settings.provider.clone())
        .record(pool)
        .await;
    let row = find(pool, org_id, id).await?;
    Ok((
        StatusCode::CREATED,
        Json(to_json(pool, &row).await.map_err(db_err)?),
    ))
}

/// `PATCH /orgs/{id}/storage/{connection_id}`
pub async fn update(
    State(state): State<AppState>,
    claims: Claims,
    Path((org_id, id)): Path<(Uuid, Uuid)>,
    Json(input): Json<ConnectionInput>,
) -> ApiResult<Json<Value>> {
    require_manager(&state, org_id, &claims).await?;
    let pool = state.db.pool();
    let row = find(pool, org_id, id).await?;
    let current = settings_of(&row);
    let max_mb = state.config.services.max_file_size_mb as i32;
    let next =
        settle(&input, Some(&current), max_mb).map_err(|m| err(StatusCode::BAD_REQUEST, &m))?;

    let new_secret = match input.secret_access_key.as_deref() {
        Some(s) if !s.trim().is_empty() => {
            Some(clean_secret_key(s).map_err(|m| err(StatusCode::BAD_REQUEST, m))?)
        }
        _ => None,
    };
    if next.access_key_id != current.access_key_id && new_secret.is_none() {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "enter the secret access key that goes with the new access key ID",
        ));
    }
    if current.moved(&next) || new_secret.is_some() {
        let secret = match &new_secret {
            Some(s) => s.clone(),
            None => {
                let sealed: String = sqlx::query_scalar(
                    "SELECT secret_access_key FROM storage_connections WHERE id = $1",
                )
                .bind(id)
                .fetch_one(pool)
                .await
                .map_err(db_err)?;
                key(&state).open(&sealed).ok_or_else(|| {
                    err(
                        StatusCode::CONFLICT,
                        "the stored secret access key can't be read any more; enter it again",
                    )
                })?
            }
        };
        let keys = Keys {
            access_key_id: next.access_key_id.clone(),
            secret_access_key: secret,
        };
        test_connection(&next, &keys).await?;
    }

    // A new place to read from starts its listing from the beginning.
    let reset_listing = current.moved(&next);
    sqlx::query(
        "UPDATE storage_connections SET
            name = $2, provider = $3, endpoint = $4, region = $5, bucket = $6, prefix = $7,
            access_key_id = $8, secret_access_key = COALESCE($9, secret_access_key),
            analysis_type = $10, interval_minutes = $11, max_object_mb = $12, enabled = $13,
            list_token = CASE WHEN $14 THEN NULL ELSE list_token END,
            last_error = CASE WHEN $14 OR $9 IS NOT NULL THEN NULL ELSE last_error END,
            updated_at = NOW()
         WHERE id = $1",
    )
    .bind(id)
    .bind(&next.name)
    .bind(&next.provider)
    .bind(endpoint_text(&next.endpoint))
    .bind(&next.region)
    .bind(&next.bucket)
    .bind(&next.prefix)
    .bind(&next.access_key_id)
    .bind(new_secret.as_deref().map(|s| key(&state).seal(s)))
    .bind(&next.analysis_type)
    .bind(next.interval_minutes)
    .bind(next.max_object_mb)
    .bind(next.enabled)
    .bind(reset_listing)
    .execute(pool)
    .await
    .map_err(db_err)?;

    let mut changed: Vec<&str> = Vec::new();
    if current.name != next.name {
        changed.push("name");
    }
    if current.moved(&next) {
        changed.push("location");
    }
    if new_secret.is_some() {
        changed.push("keys");
    }
    if current.analysis_type != next.analysis_type {
        changed.push("analysis");
    }
    if current.interval_minutes != next.interval_minutes {
        changed.push("schedule");
    }
    if current.max_object_mb != next.max_object_mb {
        changed.push("size limit");
    }
    if current.enabled != next.enabled {
        changed.push(if next.enabled {
            "turned on"
        } else {
            "turned off"
        });
    }
    audit::Event::by(&claims, "team.storage_changed")
        .team(org_id)
        .target("storage_connection", id)
        .detail("name", next.name.clone())
        .detail("changed", changed.join(", "))
        .record(pool)
        .await;
    let row = find(pool, org_id, id).await?;
    Ok(Json(to_json(pool, &row).await.map_err(db_err)?))
}

/// `DELETE /orgs/{id}/storage/{connection_id}`. The scans it made stay with
/// the team.
pub async fn remove(
    State(state): State<AppState>,
    claims: Claims,
    Path((org_id, id)): Path<(Uuid, Uuid)>,
) -> ApiResult<StatusCode> {
    require_manager(&state, org_id, &claims).await?;
    let pool = state.db.pool();
    let row = find(pool, org_id, id).await?;
    sqlx::query("DELETE FROM storage_connections WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await
        .map_err(db_err)?;
    audit::Event::by(&claims, "team.storage_removed")
        .team(org_id)
        .target("storage_connection", id)
        .detail("name", row.name.clone())
        .detail("bucket", row.bucket.clone())
        .record(pool)
        .await;
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /orgs/{id}/storage/{connection_id}/scan`: look for new files now.
pub async fn scan_now(
    State(state): State<AppState>,
    claims: Claims,
    Path((org_id, id)): Path<(Uuid, Uuid)>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    require_manager(&state, org_id, &claims).await?;
    let pool = state.db.pool();
    let row = find(pool, org_id, id).await?;
    if !row.enabled {
        return Err(err(
            StatusCode::CONFLICT,
            "turn the connection on before scanning",
        ));
    }
    sqlx::query("UPDATE storage_connections SET run_requested = TRUE WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await
        .map_err(db_err)?;
    audit::Event::by(&claims, "team.storage_scan_requested")
        .team(org_id)
        .target("storage_connection", id)
        .detail("name", row.name.clone())
        .record(pool)
        .await;
    Ok((StatusCode::ACCEPTED, Json(json!({ "scanRequested": true }))))
}

#[derive(Debug, Deserialize)]
pub struct ObjectsQuery {
    pub limit: Option<i64>,
    /// Only files a scan flagged.
    pub flagged: Option<bool>,
}

/// `GET /orgs/{id}/storage/{connection_id}/objects`: the files looked at,
/// newest first, with their scans' verdicts.
pub async fn objects(
    State(state): State<AppState>,
    claims: Claims,
    Path((org_id, id)): Path<(Uuid, Uuid)>,
    Query(q): Query<ObjectsQuery>,
) -> ApiResult<Json<Value>> {
    require_manager(&state, org_id, &claims).await?;
    let pool = state.db.pool();
    find(pool, org_id, id).await?;
    let limit = q.limit.unwrap_or(50).clamp(1, 200);
    let rows: Vec<(
        String,
        i64,
        Option<DateTime<Utc>>,
        String,
        Option<String>,
        DateTime<Utc>,
        Option<Uuid>,
        Option<String>,
        Option<String>,
    )> = sqlx::query_as(
        "SELECT o.key, o.size, o.last_modified, o.status, o.error, o.seen_at, o.submission_id,
                s.analysis_status, LOWER(s.metadata->>'consensus_verdict')
         FROM storage_objects o
         LEFT JOIN submissions s ON s.id = o.submission_id
         WHERE o.connection_id = $1
           AND (NOT $3 OR LOWER(s.metadata->>'consensus_verdict') IN ('malicious', 'suspicious'))
         ORDER BY o.seen_at DESC
         LIMIT $2",
    )
    .bind(id)
    .bind(limit)
    .bind(q.flagged.unwrap_or(false))
    .fetch_all(pool)
    .await
    .map_err(db_err)?;
    Ok(Json(json!({
        "objects": rows.into_iter().map(|r| json!({
            "key": r.0,
            "size": r.1,
            "lastModified": r.2,
            "status": r.3,
            "error": r.4,
            "seenAt": r.5,
            "submissionId": r.6,
            "analysisStatus": r.7,
            "verdict": r.8,
        })).collect::<Vec<_>>(),
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(provider: &str) -> ConnectionInput {
        ConnectionInput {
            name: Some("Uploads".into()),
            provider: Some(provider.into()),
            bucket: Some("acme-uploads".into()),
            access_key_id: Some("AKIAEXAMPLE".into()),
            ..Default::default()
        }
    }

    #[test]
    fn each_provider_gets_its_endpoint_and_region() {
        let aws = settle(
            &ConnectionInput {
                region: Some("eu-west-2".into()),
                endpoint: Some("https://ignored.example.com".into()),
                ..input("aws")
            },
            None,
            100,
        )
        .unwrap();
        assert_eq!(aws.endpoint, None);
        assert_eq!(aws.region, "eu-west-2");
        assert!(settle(&input("aws"), None, 100)
            .unwrap_err()
            .contains("region"));

        let gcs = settle(&input("gcs"), None, 100).unwrap();
        assert_eq!(
            gcs.endpoint.unwrap().as_str(),
            "https://storage.googleapis.com/"
        );
        assert_eq!(gcs.region, "auto");

        assert!(settle(&input("r2"), None, 100)
            .unwrap_err()
            .contains("r2.cloudflarestorage.com"));
        let r2 = settle(
            &ConnectionInput {
                endpoint: Some("abc.r2.cloudflarestorage.com".into()),
                ..input("r2")
            },
            None,
            100,
        )
        .unwrap();
        assert_eq!(r2.region, "auto");

        let other = settle(
            &ConnectionInput {
                endpoint: Some("https://s3.eu-central-003.backblazeb2.com".into()),
                ..input("other")
            },
            None,
            100,
        )
        .unwrap();
        assert_eq!(other.region, "us-east-1");
        assert!(settle(
            &ConnectionInput {
                endpoint: Some("https://10.0.0.5".into()),
                ..input("other")
            },
            None,
            100
        )
        .is_err());
    }

    #[test]
    fn defaults_and_limits() {
        let s = settle(&input("gcs"), None, 100).unwrap();
        assert_eq!(
            (
                s.analysis_type.as_str(),
                s.interval_minutes,
                s.max_object_mb,
                s.enabled
            ),
            ("full", 60, 32, true)
        );
        assert_eq!(settle(&input("gcs"), None, 20).unwrap().max_object_mb, 20);
        for bad in [
            ConnectionInput {
                interval_minutes: Some(5),
                ..input("gcs")
            },
            ConnectionInput {
                max_object_mb: Some(101),
                ..input("gcs")
            },
            ConnectionInput {
                analysis_type: Some("behavioral".into()),
                ..input("gcs")
            },
            ConnectionInput {
                name: Some(" ".into()),
                ..input("gcs")
            },
            ConnectionInput {
                provider: Some("azure".into()),
                ..input("gcs")
            },
        ] {
            assert!(settle(&bad, None, 100).is_err(), "{bad:?}");
        }
        assert!(clean_secret_key("  ").is_err());
        assert!(clean_secret_key("has space").is_err());
        assert_eq!(clean_secret_key(" abc/DEF+1 ").unwrap(), "abc/DEF+1");
    }

    #[test]
    fn a_change_keeps_what_isnt_sent_and_knows_when_to_retest() {
        let current = settle(&input("gcs"), None, 100).unwrap();
        let renamed = settle(
            &ConnectionInput {
                name: Some("Inbox".into()),
                enabled: Some(false),
                ..Default::default()
            },
            Some(&current),
            100,
        )
        .unwrap();
        assert_eq!(renamed.bucket, "acme-uploads");
        assert_eq!(renamed.endpoint, current.endpoint);
        assert!(!renamed.enabled);
        assert!(!current.moved(&renamed));

        let moved = settle(
            &ConnectionInput {
                prefix: Some("/incoming/".into()),
                ..Default::default()
            },
            Some(&current),
            100,
        )
        .unwrap();
        assert_eq!(moved.prefix, "incoming/");
        assert!(current.moved(&moved));
    }
}
