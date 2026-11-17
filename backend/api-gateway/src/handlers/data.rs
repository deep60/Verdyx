//! Your data: retention choices, deleting a scan, and downloading everything.
//!
//! - `GET /users/me/retention`, `PUT /users/me/retention {"scanRetentionDays"}`
//! - `PUT /orgs/{id}/retention {"scanRetentionDays"}` (team owners and admins)
//! - `DELETE /submissions/{id}`: the person who made it, or an owner or admin
//!   of the team it's saved to. Scans with a bounty can't be deleted.
//! - `GET /users/me/export`: a JSON file of your account, scans and their
//!   results, keys, teams, webhooks and activity log. Sessions only.

use axum::{
    extract::{Path, State},
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Json, Response},
};
use chrono::Utc;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::handlers::organization::{can_manage, member_role};
use crate::middleware::auth::Claims;
use crate::services::{audit, retention};
use crate::AppState;

type ApiError = (StatusCode, Json<Value>);

fn err(status: StatusCode, message: &str) -> ApiError {
    (
        status,
        Json(json!({ "error": message, "status": status.as_u16() })),
    )
}

fn db_err(e: sqlx::Error) -> ApiError {
    tracing::error!("data request failed: {e}");
    err(StatusCode::INTERNAL_SERVER_ERROR, "something went wrong")
}

fn policy(scan_days: Option<i32>) -> Value {
    json!({
        "scanRetentionDays": scan_days,
        "sampleRetentionDays": retention::sample_days(),
        "guestScanRetentionDays": retention::guest_days(),
        "choices": retention::RETENTION_CHOICES,
    })
}

/// `GET /users/me/retention`
pub async fn get_my_retention(
    State(state): State<AppState>,
    claims: Claims,
) -> Result<Json<Value>, ApiError> {
    let days: Option<i32> =
        sqlx::query_scalar("SELECT scan_retention_days FROM users WHERE id = $1")
            .bind(claims.sub)
            .fetch_optional(state.db.pool())
            .await
            .map_err(db_err)?
            .flatten();
    Ok(Json(policy(days)))
}

fn requested_days(body: &Value) -> Result<Option<i32>, ApiError> {
    let v = body
        .get("scanRetentionDays")
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, "send scanRetentionDays"))?;
    retention::parse_choice(v).map_err(|m| err(StatusCode::BAD_REQUEST, m))
}

/// `PUT /users/me/retention`
pub async fn set_my_retention(
    State(state): State<AppState>,
    claims: Claims,
    Json(body): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    let days = requested_days(&body)?;
    let done = sqlx::query("UPDATE users SET scan_retention_days = $2 WHERE id = $1")
        .bind(claims.sub)
        .bind(days)
        .execute(state.db.pool())
        .await
        .map_err(db_err)?;
    if done.rows_affected() == 0 {
        return Err(err(StatusCode::NOT_FOUND, "account not found"));
    }
    audit::Event::by(&claims, "account.retention_changed")
        .detail("scanRetentionDays", json!(days))
        .record(state.db.pool())
        .await;
    Ok(Json(policy(days)))
}

/// `PUT /orgs/{id}/retention`
pub async fn set_team_retention(
    State(state): State<AppState>,
    claims: Claims,
    Path(org_id): Path<Uuid>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    match member_role(state.db.pool(), org_id, claims.sub)
        .await
        .map_err(db_err)?
    {
        Some(role) if can_manage(&role) => {}
        Some(_) => {
            return Err(err(
                StatusCode::FORBIDDEN,
                "only owners and admins can do this",
            ))
        }
        None => return Err(err(StatusCode::NOT_FOUND, "team not found")),
    }
    let days = requested_days(&body)?;
    sqlx::query(
        "UPDATE organizations SET scan_retention_days = $2, updated_at = NOW() WHERE id = $1",
    )
    .bind(org_id)
    .bind(days)
    .execute(state.db.pool())
    .await
    .map_err(db_err)?;
    audit::Event::by(&claims, "team.retention_changed")
        .team(org_id)
        .detail("scanRetentionDays", json!(days))
        .record(state.db.pool())
        .await;
    Ok(Json(policy(days)))
}

/// May the caller delete this scan? (`submitter`, `team`, `has_bounty`)
pub async fn may_delete(
    state: &AppState,
    claims: &Claims,
    submitter: Uuid,
    team: Option<Uuid>,
) -> Result<bool, sqlx::Error> {
    if let Some(key_team) = claims.org_id {
        // A team key may delete only its team's scans.
        return Ok(team == Some(key_team));
    }
    if claims.is_admin || claims.role == "admin" || (!submitter.is_nil() && submitter == claims.sub)
    {
        return Ok(true);
    }
    match team {
        Some(t) => Ok(member_role(state.db.pool(), t, claims.sub)
            .await?
            .is_some_and(|r| can_manage(&r))),
        None => Ok(false),
    }
}

/// `DELETE /submissions/{id}`
pub async fn delete_scan(
    State(state): State<AppState>,
    claims: Option<Claims>,
    Path(submission_id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    let claims = claims.ok_or_else(|| err(StatusCode::UNAUTHORIZED, "sign in first"))?;
    let row: Option<(Uuid, Option<Uuid>, bool)> = sqlx::query_as(
        r#"SELECT s.submitter_id, s.organization_id,
                  EXISTS (SELECT 1 FROM bounties b WHERE b.submission_id = s.id)
           FROM submissions s WHERE s.id = $1"#,
    )
    .bind(submission_id)
    .fetch_optional(state.db.pool())
    .await
    .map_err(db_err)?;
    // Not found and not yours look the same.
    let not_found = || err(StatusCode::NOT_FOUND, "scan not found");
    let (submitter, team, has_bounty) = row.ok_or_else(not_found)?;
    if !may_delete(&state, &claims, submitter, team)
        .await
        .map_err(db_err)?
    {
        return Err(not_found());
    }
    if has_bounty {
        return Err(err(
            StatusCode::CONFLICT,
            "this scan carries a bounty, so it can't be deleted",
        ));
    }
    retention::delete_scans(&state, &[submission_id])
        .await
        .map_err(db_err)?;
    let mut event = audit::Event::by(&claims, "scan.deleted").target("submission", submission_id);
    if let Some(t) = team {
        event = event.team(t);
    }
    event.record(state.db.pool()).await;
    Ok(StatusCode::NO_CONTENT)
}

/// Runs a query that returns one JSON value (`json_agg` / `row_to_json`).
async fn json_of(state: &AppState, sql: &str, user: Uuid) -> Result<Value, sqlx::Error> {
    let v: Option<Value> = sqlx::query_scalar(sql)
        .bind(user)
        .fetch_one(state.db.pool())
        .await?;
    Ok(v.unwrap_or(Value::Null))
}

/// `GET /users/me/export`
pub async fn export_my_data(
    State(state): State<AppState>,
    claims: Claims,
) -> Result<Response, ApiError> {
    let me = claims.sub;
    let account = json_of(
        &state,
        r#"SELECT row_to_json(t) FROM (
             SELECT id, username, email, wallet_address, is_verified, scan_retention_days, created_at
             FROM users WHERE id = $1) t"#,
        me,
    )
    .await
    .map_err(db_err)?;
    let scans = json_of(
        &state,
        r#"SELECT COALESCE(json_agg(t ORDER BY t.created_at DESC), '[]'::json) FROM (
             SELECT s.id, s.created_at, s.submission_type, s.original_filename, s.url, s.file_hash,
                    s.file_size, s.mime_type, s.analysis_status, s.is_malicious, s.organization_id,
                    s.file_purged_at, s.metadata ->> 'description' AS description,
                    (SELECT COALESCE(json_agg(json_build_object(
                         'engine', COALESCE(r.engine_name, r.engine_id::text), 'verdict', r.verdict,
                         'confidence', COALESCE(r.confidence, r.confidence_score::float8),
                         'severity', r.severity, 'categories', r.categories, 'at', r.created_at)
                       ORDER BY r.created_at), '[]'::json)
                     FROM analysis_results r WHERE r.submission_id = s.id) AS results
             FROM submissions s WHERE s.submitter_id = $1) t"#,
        me,
    )
    .await
    .map_err(db_err)?;
    let api_keys = json_of(
        &state,
        r#"SELECT COALESCE(json_agg(t ORDER BY t.created_at DESC), '[]'::json) FROM (
             SELECT k.id, k.name, k.key_prefix AS prefix, k.permissions AS scopes, k.organization_id,
                    k.is_active, k.created_at, k.last_used_at, k.expires_at
             FROM api_keys k WHERE k.user_id = $1) t"#,
        me,
    )
    .await
    .map_err(db_err)?;
    let teams = json_of(
        &state,
        r#"SELECT COALESCE(json_agg(t ORDER BY t.joined_at), '[]'::json) FROM (
             SELECT o.id, o.name, m.role, m.joined_at
             FROM organization_members m JOIN organizations o ON o.id = m.organization_id
             WHERE m.user_id = $1) t"#,
        me,
    )
    .await
    .map_err(db_err)?;
    let webhooks = json_of(
        &state,
        r#"SELECT COALESCE(json_agg(t ORDER BY t.created_at), '[]'::json) FROM (
             SELECT id, url, events, description, is_active, created_at, last_triggered_at
             FROM webhooks WHERE user_id = $1) t"#,
        me,
    )
    .await
    .map_err(db_err)?;
    let activity = json_of(
        &state,
        r#"SELECT COALESCE(json_agg(t ORDER BY t.id DESC), '[]'::json) FROM (
             SELECT id, occurred_at, action, actor_id, via, organization_id, subject_user_id,
                    target_type, target_id, ip, user_agent, details
             FROM audit_events WHERE actor_id = $1 OR subject_user_id = $1
             ORDER BY id DESC LIMIT 10000) t"#,
        me,
    )
    .await
    .map_err(db_err)?;

    audit::Event::by(&claims, "account.exported")
        .record(state.db.pool())
        .await;

    let body = json!({
        "format": "verdyx-export/1",
        "generatedAt": Utc::now(),
        "note": "Scans you saved to a team are included because you made them. Uploaded files aren't included; their hashes are. Secrets (API keys, webhook signing secrets) are never exported.",
        "account": account,
        "retention": policy(account.get("scan_retention_days").and_then(Value::as_i64).map(|d| d as i32)),
        "scans": scans,
        "apiKeys": api_keys,
        "teams": teams,
        "webhooks": webhooks,
        "activity": activity,
    });
    let mut resp = Json(body).into_response();
    let name = format!(
        "attachment; filename=\"verdyx-export-{}.json\"",
        Utc::now().format("%Y-%m-%d")
    );
    if let Ok(v) = HeaderValue::from_str(&name) {
        resp.headers_mut().insert(header::CONTENT_DISPOSITION, v);
    }
    Ok(resp)
}

/// Everything account deletion removes from the gateway besides scans:
/// personal keys, webhooks and their deliveries, sessions. Team keys the
/// person made are switched off by `organization::leave_all`.
pub async fn delete_personal_records(state: &AppState, user: Uuid) -> Result<(), sqlx::Error> {
    let mut tx = state.db.pool().begin().await?;
    sqlx::query("DELETE FROM api_keys WHERE user_id = $1 AND organization_id IS NULL")
        .bind(user)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM webhooks WHERE user_id = $1")
        .bind(user)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM user_sessions WHERE user_id = $1")
        .bind(user)
        .execute(&mut *tx)
        .await?;
    tx.commit().await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_policy_reports_every_rule() {
        let p = policy(Some(90));
        assert_eq!(p["scanRetentionDays"], 90);
        assert!(p["choices"].as_array().unwrap().contains(&json!(365)));
        assert!(p.get("sampleRetentionDays").is_some());
        assert!(p.get("guestScanRetentionDays").is_some());
        assert_eq!(policy(None)["scanRetentionDays"], Value::Null);
    }

    #[test]
    fn requests_must_name_the_setting() {
        assert!(requested_days(&json!({})).is_err());
        assert_eq!(
            requested_days(&json!({"scanRetentionDays": null})).unwrap(),
            None
        );
        assert_eq!(
            requested_days(&json!({"scanRetentionDays": 30})).unwrap(),
            Some(30)
        );
        assert!(requested_days(&json!({"scanRetentionDays": 31})).is_err());
    }
}
