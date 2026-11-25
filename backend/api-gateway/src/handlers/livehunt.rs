//! Live hunts: saved YARA rules that run on every new upload in their scope.
//!
//! - `POST /livehunts {"name", "rule", "teamId"?}` saves a hunt over your own
//!   uploads, or a team's (you must be in it).
//! - `GET /livehunts`: your hunts, with how many matches you haven't seen.
//! - `GET /livehunts/{id}`: one hunt, with its rule and latest matches (only
//!   scans you can still see).
//! - `PATCH /livehunts/{id} {"name"?, "rule"?, "enabled"?}`: rename, edit the
//!   rule or turn it on or off.
//! - `POST /livehunts/{id}/seen`: mark its matches as seen.
//! - `DELETE /livehunts/{id}`: remove it and its matches.
//!
//! The analysis engine runs the rules (it has YARA). It turns a hunt off and
//! records the compiler's message in `lastError` if the rule doesn't compile.

#![allow(clippy::type_complexity)]

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::{json, Value};
use shared::live_hunts::{MAX_ENABLED_PER_USER, MAX_PER_USER};
use uuid::Uuid;

use crate::handlers::organization::member_role;
use crate::middleware::auth::Claims;
use crate::services::audit;
use crate::AppState;

const MAX_NAME_CHARS: usize = 100;

type ApiError = (StatusCode, Json<Value>);

fn err(status: StatusCode, message: &str) -> ApiError {
    (
        status,
        Json(json!({ "error": message, "status": status.as_u16() })),
    )
}

fn db_err(e: sqlx::Error) -> ApiError {
    tracing::error!("live hunt request failed: {e}");
    err(StatusCode::INTERNAL_SERVER_ERROR, "something went wrong")
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateRequest {
    pub name: String,
    pub rule: String,
    pub team_id: Option<Uuid>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateRequest {
    pub name: Option<String>,
    pub rule: Option<String>,
    pub enabled: Option<bool>,
}

/// A trimmed, non-empty name of at most [`MAX_NAME_CHARS`] characters.
pub(crate) fn clean_name(name: &str) -> Result<String, &'static str> {
    let n = name.trim();
    if n.is_empty() {
        return Err("give the hunt a name");
    }
    if n.chars().count() > MAX_NAME_CHARS {
        return Err("the name is longer than 100 characters");
    }
    if n.chars().any(char::is_control) {
        return Err("the name can't contain control characters");
    }
    Ok(n.to_string())
}

const COLUMNS: &str =
    "h.id, h.name, h.organization_id, o.name, h.enabled, h.matches, h.last_match_at, \
     h.last_error, h.created_at, h.updated_at, h.rule_text, \
     (SELECT COUNT(*) FROM live_hunt_matches m WHERE m.hunt_id = h.id AND NOT m.seen)";

type HuntRow = (
    Uuid,
    String,
    Option<Uuid>,
    Option<String>,
    bool,
    i32,
    Option<DateTime<Utc>>,
    Option<String>,
    DateTime<Utc>,
    DateTime<Utc>,
    String,
    i64,
);

fn hunt_json(r: &HuntRow, with_rule: bool) -> Value {
    let mut v = json!({
        "id": r.0, "name": r.1, "teamId": r.2, "teamName": r.3, "enabled": r.4,
        "matches": r.5, "lastMatchAt": r.6, "lastError": r.7,
        "createdAt": r.8, "updatedAt": r.9, "unseen": r.11,
        "ruleNames": shared::yara_rules::check(&r.10).map(|s| s.rule_names).unwrap_or_default(),
    });
    if with_rule {
        v["rule"] = json!(r.10);
    }
    v
}

async fn load(state: &AppState, claims: &Claims, id: Uuid) -> Result<HuntRow, ApiError> {
    sqlx::query_as::<_, HuntRow>(&format!(
        "SELECT {COLUMNS} FROM live_hunts h LEFT JOIN organizations o ON o.id = h.organization_id
         WHERE h.id = $1 AND h.user_id = $2"
    ))
    .bind(id)
    .bind(claims.sub)
    .fetch_optional(state.db.pool())
    .await
    .map_err(db_err)?
    .ok_or_else(|| err(StatusCode::NOT_FOUND, "hunt not found"))
}

async fn enabled_count(state: &AppState, user: Uuid) -> Result<i64, ApiError> {
    sqlx::query_scalar("SELECT COUNT(*) FROM live_hunts WHERE user_id = $1 AND enabled")
        .bind(user)
        .fetch_one(state.db.pool())
        .await
        .map_err(db_err)
}

fn too_many_enabled() -> ApiError {
    err(
        StatusCode::CONFLICT,
        "you already have 10 hunts turned on; turn one off first",
    )
}

/// `POST /livehunts`
pub async fn create(
    State(state): State<AppState>,
    claims: Claims,
    Json(req): Json<CreateRequest>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let name = clean_name(&req.name).map_err(|m| err(StatusCode::BAD_REQUEST, m))?;
    let summary =
        shared::yara_rules::check(&req.rule).map_err(|m| err(StatusCode::BAD_REQUEST, &m))?;
    if let Some(team) = req.team_id {
        member_role(state.db.pool(), team, claims.sub)
            .await
            .map_err(db_err)?
            .ok_or_else(|| err(StatusCode::NOT_FOUND, "team not found"))?;
    }
    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM live_hunts WHERE user_id = $1")
        .bind(claims.sub)
        .fetch_one(state.db.pool())
        .await
        .map_err(db_err)?;
    if total >= MAX_PER_USER {
        return Err(err(
            StatusCode::CONFLICT,
            "you have 25 hunts; delete one to add another",
        ));
    }
    if enabled_count(&state, claims.sub).await? >= MAX_ENABLED_PER_USER {
        return Err(too_many_enabled());
    }
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO live_hunts (id, user_id, organization_id, name, rule_text) VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(id)
    .bind(claims.sub)
    .bind(req.team_id)
    .bind(&name)
    .bind(&req.rule)
    .execute(state.db.pool())
    .await
    .map_err(db_err)?;
    let mut event = audit::Event::by(&claims, "livehunt.created")
        .target("livehunt", id)
        .detail("rules", json!(summary.rule_names));
    if let Some(t) = req.team_id {
        event = event.team(t);
    }
    event.record(state.db.pool()).await;
    let row = load(&state, &claims, id).await?;
    Ok((StatusCode::CREATED, Json(hunt_json(&row, true))))
}

/// `GET /livehunts`
pub async fn list(State(state): State<AppState>, claims: Claims) -> Result<Json<Value>, ApiError> {
    let rows: Vec<HuntRow> = sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM live_hunts h LEFT JOIN organizations o ON o.id = h.organization_id
         WHERE h.user_id = $1 ORDER BY h.created_at DESC"
    ))
    .bind(claims.sub)
    .fetch_all(state.db.pool())
    .await
    .map_err(db_err)?;
    Ok(Json(Value::Array(
        rows.iter().map(|r| hunt_json(r, false)).collect(),
    )))
}

/// `GET /livehunts/{id}`
pub async fn get(
    State(state): State<AppState>,
    claims: Claims,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, ApiError> {
    let hunt = load(&state, &claims, id).await?;
    // Only scans the person can still see: their own, or their teams'.
    let matches: Vec<(
        Uuid,
        Vec<String>,
        DateTime<Utc>,
        bool,
        Option<String>,
        Option<String>,
        Option<String>,
        String,
        Option<bool>,
    )> = sqlx::query_as(
        r#"SELECT s.id, m.rules, m.matched_at, m.seen, s.original_filename, s.url, s.file_hash,
                  s.submission_type, s.is_malicious
           FROM live_hunt_matches m JOIN submissions s ON s.id = m.submission_id
           WHERE m.hunt_id = $1
             AND (s.submitter_id = $2 OR s.organization_id IN
                  (SELECT organization_id FROM organization_members WHERE user_id = $2))
           ORDER BY m.matched_at DESC LIMIT 200"#,
    )
    .bind(id)
    .bind(claims.sub)
    .fetch_all(state.db.pool())
    .await
    .map_err(db_err)?;
    let mut v = hunt_json(&hunt, true);
    v["results"] = Value::Array(
        matches
            .into_iter()
            .map(|(sid, rules, at, seen, name, url, hash, kind, malicious)| {
                json!({ "submissionId": sid, "rules": rules, "matchedAt": at, "seen": seen,
                        "filename": name, "url": url, "sha256": hash, "type": kind,
                        "isMalicious": malicious })
            })
            .collect(),
    );
    Ok(Json(v))
}

/// `PATCH /livehunts/{id}`
pub async fn update(
    State(state): State<AppState>,
    claims: Claims,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateRequest>,
) -> Result<Json<Value>, ApiError> {
    let hunt = load(&state, &claims, id).await?;
    let name = match &req.name {
        Some(n) => Some(clean_name(n).map_err(|m| err(StatusCode::BAD_REQUEST, m))?),
        None => None,
    };
    if let Some(rule) = &req.rule {
        shared::yara_rules::check(rule).map_err(|m| err(StatusCode::BAD_REQUEST, &m))?;
    }
    // Turning on (or editing the rule of a hunt the engine turned off) counts
    // against the limit.
    let turning_on = req.enabled == Some(true) && !hunt.4;
    if turning_on && enabled_count(&state, claims.sub).await? >= MAX_ENABLED_PER_USER {
        return Err(too_many_enabled());
    }
    // A new rule gets a fresh start: the old compile error no longer applies.
    sqlx::query(
        r#"UPDATE live_hunts SET
             name = COALESCE($3, name),
             rule_text = COALESCE($4, rule_text),
             enabled = COALESCE($5, enabled),
             last_error = CASE WHEN $4::text IS NOT NULL THEN NULL ELSE last_error END,
             updated_at = NOW()
           WHERE id = $1 AND user_id = $2"#,
    )
    .bind(id)
    .bind(claims.sub)
    .bind(name)
    .bind(&req.rule)
    .bind(req.enabled)
    .execute(state.db.pool())
    .await
    .map_err(db_err)?;
    if req.rule.is_some() || req.enabled.is_some() {
        audit::Event::by(&claims, "livehunt.updated")
            .target("livehunt", id)
            .detail("enabled", json!(req.enabled))
            .detail("ruleChanged", json!(req.rule.is_some()))
            .record(state.db.pool())
            .await;
    }
    let row = load(&state, &claims, id).await?;
    Ok(Json(hunt_json(&row, true)))
}

/// `POST /livehunts/{id}/seen`
pub async fn mark_seen(
    State(state): State<AppState>,
    claims: Claims,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    load(&state, &claims, id).await?;
    sqlx::query("UPDATE live_hunt_matches SET seen = TRUE WHERE hunt_id = $1 AND NOT seen")
        .bind(id)
        .execute(state.db.pool())
        .await
        .map_err(db_err)?;
    Ok(StatusCode::NO_CONTENT)
}

/// `DELETE /livehunts/{id}`
pub async fn remove(
    State(state): State<AppState>,
    claims: Claims,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    load(&state, &claims, id).await?;
    sqlx::query("DELETE FROM live_hunts WHERE id = $1 AND user_id = $2")
        .bind(id)
        .bind(claims.sub)
        .execute(state.db.pool())
        .await
        .map_err(db_err)?;
    audit::Event::by(&claims, "livehunt.deleted")
        .target("livehunt", id)
        .record(state.db.pool())
        .await;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_trimmed_and_checked() {
        assert_eq!(clean_name("  Emotet loaders ").unwrap(), "Emotet loaders");
        assert!(clean_name("   ").is_err());
        assert!(clean_name(&"x".repeat(101)).is_err());
        assert!(
            clean_name(&"é".repeat(100)).is_ok(),
            "counts characters, not bytes"
        );
        assert!(clean_name("bad\nname").is_err());
    }

    #[test]
    fn hunts_render_with_rule_names_and_unseen_count() {
        let now = Utc::now();
        let row: HuntRow = (
            Uuid::nil(),
            "Loaders".into(),
            None,
            None,
            true,
            3,
            Some(now),
            None,
            now,
            now,
            "rule A { condition: true } rule B { condition: false }".into(),
            2,
        );
        let v = hunt_json(&row, false);
        assert_eq!(v["ruleNames"], json!(["A", "B"]));
        assert_eq!(v["unseen"], 2);
        assert_eq!(v["matches"], 3);
        assert!(v.get("rule").is_none());
        assert!(hunt_json(&row, true)["rule"].is_string());
    }
}
