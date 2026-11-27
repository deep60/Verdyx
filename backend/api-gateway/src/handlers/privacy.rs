//! Privacy: whether files may leave Verdyx, and who can open a scan.
//!
//! - `GET /users/me/privacy`: your setting and your teams'.
//! - `PUT /users/me/privacy {"shareFilesWithVirusTotal"}`: for scans you
//!   save to your own account. Sessions only.
//! - `PUT /orgs/{id}/privacy {"shareFilesWithVirusTotal"}`: for scans saved
//!   to the team. Owners and admins.
//! - `PUT /submissions/{id}/sharing {"sharedByLink"}`: let anyone with the
//!   report's link open it, or stop that. Whoever may delete the scan.
//!
//! Files are private by default. Behavioral analysis only looks up
//! VirusTotal's existing report by hash; it uploads the file only when the
//! account (or team) the scan was saved to allows it. The choice is recorded
//! on each scan when it's created (`submissions.may_upload_file`), so a later
//! change never reaches back to earlier scans.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::handlers::organization::{can_manage, member_role};
use crate::middleware::auth::Claims;
use crate::services::audit;
use crate::AppState;

type ApiError = (StatusCode, Json<Value>);

fn err(status: StatusCode, message: &str) -> ApiError {
    (
        status,
        Json(json!({ "error": message, "status": status.as_u16() })),
    )
}

fn db_err(e: sqlx::Error) -> ApiError {
    tracing::error!("privacy request failed: {e}");
    err(StatusCode::INTERNAL_SERVER_ERROR, "something went wrong")
}

fn flag(body: &Value, key: &str) -> Result<bool, ApiError> {
    body.get(key).and_then(Value::as_bool).ok_or_else(|| {
        err(
            StatusCode::BAD_REQUEST,
            &format!("send {key}: true or false"),
        )
    })
}

/// May the file of a new scan be uploaded to VirusTotal? Signed-out scans
/// never; team scans by the team's setting; others by the account's. Any
/// doubt (a failed lookup) means no.
pub async fn may_upload_file(pool: &sqlx::PgPool, submitter: Uuid, team: Option<Uuid>) -> bool {
    if submitter.is_nil() {
        return false;
    }
    let found: Result<Option<bool>, sqlx::Error> = match team {
        Some(t) => {
            sqlx::query_scalar(
                "SELECT share_files_with_virustotal FROM organizations WHERE id = $1",
            )
            .bind(t)
            .fetch_optional(pool)
            .await
        }
        None => {
            sqlx::query_scalar("SELECT share_files_with_virustotal FROM users WHERE id = $1")
                .bind(submitter)
                .fetch_optional(pool)
                .await
        }
    };
    match found {
        Ok(v) => v.unwrap_or(false),
        Err(e) => {
            tracing::warn!("could not read the upload setting; not uploading: {e}");
            false
        }
    }
}

/// `GET /users/me/privacy`
pub async fn get_my_privacy(
    State(state): State<AppState>,
    claims: Claims,
) -> Result<Json<Value>, ApiError> {
    let mine: Option<bool> =
        sqlx::query_scalar("SELECT share_files_with_virustotal FROM users WHERE id = $1")
            .bind(claims.sub)
            .fetch_optional(state.db.pool())
            .await
            .map_err(db_err)?;
    let teams: Vec<(Uuid, String, String, bool)> = sqlx::query_as(
        r#"SELECT o.id, o.name, m.role, o.share_files_with_virustotal
           FROM organization_members m JOIN organizations o ON o.id = m.organization_id
           WHERE m.user_id = $1 ORDER BY o.name"#,
    )
    .bind(claims.sub)
    .fetch_all(state.db.pool())
    .await
    .map_err(db_err)?;
    Ok(Json(json!({
        "shareFilesWithVirusTotal": mine.unwrap_or(false),
        "teams": teams.into_iter().map(|(id, name, role, share)| json!({
            "id": id,
            "name": name,
            "canEdit": can_manage(&role),
            "shareFilesWithVirusTotal": share,
        })).collect::<Vec<_>>(),
    })))
}

/// `PUT /users/me/privacy`
pub async fn set_my_privacy(
    State(state): State<AppState>,
    claims: Claims,
    Json(body): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    if claims.org_id.is_some() {
        return Err(err(
            StatusCode::FORBIDDEN,
            "a team key can't change an account's settings",
        ));
    }
    let share = flag(&body, "shareFilesWithVirusTotal")?;
    let done = sqlx::query("UPDATE users SET share_files_with_virustotal = $2 WHERE id = $1")
        .bind(claims.sub)
        .bind(share)
        .execute(state.db.pool())
        .await
        .map_err(db_err)?;
    if done.rows_affected() == 0 {
        return Err(err(StatusCode::NOT_FOUND, "account not found"));
    }
    audit::Event::by(&claims, "account.file_sharing_changed")
        .detail("shareFilesWithVirusTotal", json!(share))
        .record(state.db.pool())
        .await;
    Ok(Json(json!({ "shareFilesWithVirusTotal": share })))
}

/// `PUT /orgs/{id}/privacy`
pub async fn set_team_privacy(
    State(state): State<AppState>,
    claims: Claims,
    Path(org_id): Path<Uuid>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    if claims.org_id.is_some() {
        return Err(err(
            StatusCode::FORBIDDEN,
            "a team key can't change the team's settings",
        ));
    }
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
    let share = flag(&body, "shareFilesWithVirusTotal")?;
    sqlx::query(
        "UPDATE organizations SET share_files_with_virustotal = $2, updated_at = NOW() WHERE id = $1",
    )
    .bind(org_id)
    .bind(share)
    .execute(state.db.pool())
    .await
    .map_err(db_err)?;
    audit::Event::by(&claims, "team.file_sharing_changed")
        .team(org_id)
        .detail("shareFilesWithVirusTotal", json!(share))
        .record(state.db.pool())
        .await;
    Ok(Json(json!({ "shareFilesWithVirusTotal": share })))
}

/// `PUT /submissions/{id}/sharing`
pub async fn set_scan_sharing(
    State(state): State<AppState>,
    claims: Option<Claims>,
    Path(submission_id): Path<Uuid>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    let claims = claims.ok_or_else(|| err(StatusCode::UNAUTHORIZED, "sign in first"))?;
    let shared = flag(&body, "sharedByLink")?;
    let row: Option<(Uuid, Option<Uuid>)> =
        sqlx::query_as("SELECT submitter_id, organization_id FROM submissions WHERE id = $1")
            .bind(submission_id)
            .fetch_optional(state.db.pool())
            .await
            .map_err(db_err)?;
    let Some((submitter, team)) = row else {
        return Err(err(StatusCode::NOT_FOUND, "scan not found"));
    };
    if submitter.is_nil() {
        return Err(err(
            StatusCode::CONFLICT,
            "a scan made while signed out is always open to anyone with its link",
        ));
    }
    let allowed = crate::handlers::data::may_delete(&state, &claims, submitter, team)
        .await
        .map_err(db_err)?;
    if !allowed {
        // Same answer as a scan that doesn't exist, so ids can't be probed.
        return Err(err(StatusCode::NOT_FOUND, "scan not found"));
    }
    sqlx::query("UPDATE submissions SET shared_by_link = $2 WHERE id = $1")
        .bind(submission_id)
        .bind(shared)
        .execute(state.db.pool())
        .await
        .map_err(db_err)?;
    let mut event = audit::Event::by(&claims, "scan.sharing_changed")
        .target("submission", submission_id)
        .detail("sharedByLink", json!(shared));
    if let Some(t) = team {
        event = event.team(t);
    }
    event.record(state.db.pool()).await;
    Ok(Json(
        json!({ "submissionId": submission_id, "sharedByLink": shared }),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Against a real database; runs only when API_GATEWAY_DATABASE_URL is
    /// set, and removes what it adds.
    #[tokio::test]
    async fn uploads_follow_the_account_or_the_team() {
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

        let (alice, team) = (Uuid::new_v4(), Uuid::new_v4());
        let name = format!("privacy-{}", &alice.to_string()[..8]);
        sqlx::query(
            "INSERT INTO users (id, username, email, password_hash, created_at, updated_at) \
             VALUES ($1, $2, $3, 'x', NOW(), NOW())",
        )
        .bind(alice)
        .bind(&name)
        .bind(format!("{name}@example.com"))
        .execute(&db)
        .await
        .unwrap();
        sqlx::query("INSERT INTO organizations (id, name, created_by) VALUES ($1, 'SOC', $2)")
            .bind(team)
            .bind(alice)
            .execute(&db)
            .await
            .unwrap();

        // Off by default, for the account and the team.
        assert!(!may_upload_file(&db, alice, None).await);
        assert!(!may_upload_file(&db, alice, Some(team)).await);
        // Signed-out scans never, and unknown accounts or teams never.
        assert!(!may_upload_file(&db, Uuid::nil(), None).await);
        assert!(!may_upload_file(&db, Uuid::new_v4(), None).await);
        assert!(!may_upload_file(&db, alice, Some(Uuid::new_v4())).await);

        // The account's setting covers its own scans only; the team decides
        // for scans saved to it.
        sqlx::query("UPDATE users SET share_files_with_virustotal = TRUE WHERE id = $1")
            .bind(alice)
            .execute(&db)
            .await
            .unwrap();
        assert!(may_upload_file(&db, alice, None).await);
        assert!(!may_upload_file(&db, alice, Some(team)).await);
        sqlx::query("UPDATE organizations SET share_files_with_virustotal = TRUE WHERE id = $1")
            .bind(team)
            .execute(&db)
            .await
            .unwrap();
        assert!(may_upload_file(&db, alice, Some(team)).await);

        // New scans start private and not uploadable.
        let (shared, upload): (bool, bool) = sqlx::query_as(
            "INSERT INTO submissions (id, submitter_id, submission_type, analysis_status, file_hash) \
             VALUES ($1, $2, 'file', 'pending', 'ab') RETURNING shared_by_link, may_upload_file",
        )
        .bind(Uuid::new_v4())
        .bind(alice)
        .fetch_one(&db)
        .await
        .unwrap();
        assert_eq!((shared, upload), (false, false));

        sqlx::query("DELETE FROM submissions WHERE submitter_id = $1")
            .bind(alice)
            .execute(&db)
            .await
            .unwrap();
        sqlx::query("DELETE FROM organizations WHERE id = $1")
            .bind(team)
            .execute(&db)
            .await
            .unwrap();
        sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(alice)
            .execute(&db)
            .await
            .unwrap();
    }
}
