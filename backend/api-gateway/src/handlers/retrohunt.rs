//! Retrohunt: run a YARA rule over past uploads.
//!
//! - `POST /retrohunts {"rule", "teamId"?}` queues a hunt over your own scans,
//!   or a team's scans if you're in the team. One hunt at a time per person,
//!   20 a day.
//! - `GET /retrohunts`: your hunts. `GET /retrohunts/{id}`: one, with its
//!   matches (only scans you can still see).
//! - `DELETE /retrohunts/{id}`: cancel a hunt that's waiting or running, or
//!   remove a finished one.
//!
//! The analysis engine does the scanning (it has YARA and the files). Files
//! are kept for 30 days, so a hunt covers that window.

#![allow(clippy::type_complexity)]

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::handlers::organization::member_role;
use crate::middleware::auth::Claims;
use crate::services::audit;
use crate::AppState;

pub const PER_DAY: i64 = 20;

type ApiError = (StatusCode, Json<Value>);

fn err(status: StatusCode, message: &str) -> ApiError {
    (
        status,
        Json(json!({ "error": message, "status": status.as_u16() })),
    )
}

fn db_err(e: sqlx::Error) -> ApiError {
    tracing::error!("retrohunt request failed: {e}");
    err(StatusCode::INTERNAL_SERVER_ERROR, "something went wrong")
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HuntRequest {
    pub rule: String,
    pub team_id: Option<Uuid>,
}

const JOB_COLUMNS: &str =
    "j.id, j.organization_id, o.name, j.status, j.files_total, j.files_scanned, \
     j.files_failed, j.matches, j.message, j.created_at, j.started_at, j.finished_at, j.rule_text";

type JobRow = (
    Uuid,
    Option<Uuid>,
    Option<String>,
    String,
    i32,
    i32,
    i32,
    i32,
    Option<String>,
    DateTime<Utc>,
    Option<DateTime<Utc>>,
    Option<DateTime<Utc>>,
    String,
);

fn job_json(r: &JobRow, with_rule: bool) -> Value {
    let mut v = json!({
        "id": r.0, "teamId": r.1, "teamName": r.2, "status": r.3,
        "filesTotal": r.4, "filesScanned": r.5, "filesFailed": r.6, "matches": r.7,
        "message": r.8, "createdAt": r.9, "startedAt": r.10, "finishedAt": r.11,
        "ruleNames": shared::yara_rules::check(&r.12).map(|s| s.rule_names).unwrap_or_default(),
    });
    if with_rule {
        v["rule"] = json!(r.12);
    }
    v
}

/// `POST /retrohunts`
pub async fn start(
    State(state): State<AppState>,
    claims: Claims,
    Json(req): Json<HuntRequest>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let summary =
        shared::yara_rules::check(&req.rule).map_err(|m| err(StatusCode::BAD_REQUEST, &m))?;
    if let Some(team) = req.team_id {
        member_role(state.db.pool(), team, claims.sub)
            .await
            .map_err(db_err)?
            .ok_or_else(|| err(StatusCode::NOT_FOUND, "team not found"))?;
    }
    let (open, today): (i64, i64) = sqlx::query_as(
        r#"SELECT COUNT(*) FILTER (WHERE status IN ('queued', 'running')),
                  COUNT(*) FILTER (WHERE created_at > NOW() - INTERVAL '1 day')
           FROM retrohunt_jobs WHERE user_id = $1"#,
    )
    .bind(claims.sub)
    .fetch_one(state.db.pool())
    .await
    .map_err(db_err)?;
    if open > 0 {
        return Err(err(
            StatusCode::CONFLICT,
            "you already have a hunt running; wait for it or cancel it",
        ));
    }
    if today >= PER_DAY {
        return Err(err(
            StatusCode::TOO_MANY_REQUESTS,
            "you've run 20 hunts in the last day; try again later",
        ));
    }
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO retrohunt_jobs (id, user_id, organization_id, rule_text) VALUES ($1, $2, $3, $4)",
    )
    .bind(id)
    .bind(claims.sub)
    .bind(req.team_id)
    .bind(&req.rule)
    .execute(state.db.pool())
    .await
    .map_err(db_err)?;
    if let Err(e) = state.redis.queue_retrohunt(id).await {
        tracing::error!("Failed to queue retrohunt {id}: {e}");
        let _ = sqlx::query(
            "UPDATE retrohunt_jobs SET status = 'failed', message = 'could not be queued', finished_at = NOW() WHERE id = $1",
        )
        .bind(id)
        .execute(state.db.pool())
        .await;
        return Err(err(
            StatusCode::SERVICE_UNAVAILABLE,
            "the hunt couldn't be queued; try again",
        ));
    }
    let mut event = audit::Event::by(&claims, "retrohunt.started")
        .target("retrohunt", id)
        .detail("rules", json!(summary.rule_names));
    if let Some(t) = req.team_id {
        event = event.team(t);
    }
    event.record(state.db.pool()).await;
    Ok((
        StatusCode::CREATED,
        Json(
            json!({ "id": id, "status": "queued", "ruleNames": summary.rule_names, "teamId": req.team_id }),
        ),
    ))
}

/// `GET /retrohunts`
pub async fn list(State(state): State<AppState>, claims: Claims) -> Result<Json<Value>, ApiError> {
    let rows: Vec<JobRow> = sqlx::query_as(&format!(
        "SELECT {JOB_COLUMNS} FROM retrohunt_jobs j LEFT JOIN organizations o ON o.id = j.organization_id
         WHERE j.user_id = $1 ORDER BY j.created_at DESC LIMIT 50"
    ))
    .bind(claims.sub)
    .fetch_all(state.db.pool())
    .await
    .map_err(db_err)?;
    Ok(Json(Value::Array(
        rows.iter().map(|r| job_json(r, false)).collect(),
    )))
}

async fn load(state: &AppState, claims: &Claims, id: Uuid) -> Result<JobRow, ApiError> {
    sqlx::query_as::<_, JobRow>(&format!(
        "SELECT {JOB_COLUMNS} FROM retrohunt_jobs j LEFT JOIN organizations o ON o.id = j.organization_id
         WHERE j.id = $1 AND j.user_id = $2"
    ))
    .bind(id)
    .bind(claims.sub)
    .fetch_optional(state.db.pool())
    .await
    .map_err(db_err)?
    .ok_or_else(|| err(StatusCode::NOT_FOUND, "hunt not found"))
}

/// `GET /retrohunts/{id}`
pub async fn get(
    State(state): State<AppState>,
    claims: Claims,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, ApiError> {
    let job = load(&state, &claims, id).await?;
    // Only scans the person can still see: their own, or their teams'.
    let matches: Vec<(Uuid, Vec<String>, Option<String>, Option<String>, Option<String>, String, DateTime<Utc>)> =
        sqlx::query_as(
            r#"SELECT s.id, m.rules, s.original_filename, s.url, s.file_hash, s.submission_type, s.created_at
               FROM retrohunt_matches m JOIN submissions s ON s.id = m.submission_id
               WHERE m.job_id = $1
                 AND (s.submitter_id = $2 OR s.organization_id IN
                      (SELECT organization_id FROM organization_members WHERE user_id = $2))
               ORDER BY s.created_at DESC LIMIT 1000"#,
        )
        .bind(id)
        .bind(claims.sub)
        .fetch_all(state.db.pool())
        .await
        .map_err(db_err)?;
    let mut v = job_json(&job, true);
    v["results"] = Value::Array(
        matches
            .into_iter()
            .map(|(sid, rules, name, url, hash, kind, created)| {
                json!({ "submissionId": sid, "rules": rules, "filename": name, "url": url,
                        "sha256": hash, "type": kind, "createdAt": created })
            })
            .collect(),
    );
    Ok(Json(v))
}

/// `DELETE /retrohunts/{id}`
pub async fn cancel_or_remove(
    State(state): State<AppState>,
    claims: Claims,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    let job = load(&state, &claims, id).await?;
    if matches!(job.3.as_str(), "queued" | "running") {
        // The engine checks for this between files.
        sqlx::query(
            "UPDATE retrohunt_jobs SET status = 'cancelled', finished_at = NOW() WHERE id = $1 AND status IN ('queued', 'running')",
        )
        .bind(id)
        .execute(state.db.pool())
        .await
        .map_err(db_err)?;
    } else {
        sqlx::query("DELETE FROM retrohunt_jobs WHERE id = $1")
            .bind(id)
            .execute(state.db.pool())
            .await
            .map_err(db_err)?;
    }
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jobs_render_with_rule_names() {
        let now = Utc::now();
        let row: JobRow = (
            Uuid::nil(),
            None,
            None,
            "completed".into(),
            10,
            10,
            0,
            2,
            None,
            now,
            Some(now),
            Some(now),
            "rule A { condition: true } rule B { condition: false }".into(),
        );
        let v = job_json(&row, false);
        assert_eq!(v["ruleNames"], json!(["A", "B"]));
        assert!(v.get("rule").is_none());
        assert_eq!(job_json(&row, true)["matches"], 2);
    }
}
