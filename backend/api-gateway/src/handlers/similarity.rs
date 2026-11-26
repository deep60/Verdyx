//! Similarity search: `GET /submissions/{id}/similar`.
//!
//! Files close to a scanned file by fuzzy hash (TLSH, ssdeep) or with the same
//! imphash, among the uploads the caller may read: their own, their teams',
//! and scans posted with a bounty. See `shared::similarity`.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde_json::{json, Value};
use shared::similarity::{self, Candidate, Hashes, Match};
use std::collections::HashSet;
use uuid::Uuid;

use crate::middleware::auth::Claims;
use crate::AppState;

fn db_error(e: sqlx::Error) -> StatusCode {
    tracing::error!("similarity search failed: {e}");
    StatusCode::INTERNAL_SERVER_ERROR
}

/// `GET /submissions/{id}/similar`
pub async fn get_similar(
    State(state): State<AppState>,
    claims: Claims,
    Path(submission_id): Path<Uuid>,
) -> Result<Json<Value>, StatusCode> {
    let submission =
        crate::handlers::submission::load_visible_submission(&state, submission_id, Some(&claims))
            .await?;
    let pool = state.db.pool();

    let own: Option<(Option<String>, Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT tlsh, ssdeep, imphash FROM file_similarity WHERE submission_id = $1",
    )
    .bind(submission_id)
    .fetch_optional(pool)
    .await
    .map_err(db_error)?;

    let Some((tlsh, ssdeep, imphash)) = own else {
        // Why there's nothing to compare yet.
        let status = if submission.submission_type == "url" {
            "not_a_file"
        } else if matches!(submission.analysis_status.as_str(), "pending" | "analyzing") {
            "pending"
        } else {
            "unavailable"
        };
        return Ok(Json(json!({
            "submissionId": submission_id,
            "status": status,
            "hashes": null,
            "similar": [],
            "compared": 0,
        })));
    };
    let target = Hashes {
        tlsh,
        ssdeep,
        imphash,
    };

    let team_key = claims.org_id;
    let is_admin = claims.is_admin || claims.role == "admin";
    let mut candidates: Vec<Candidate> = sqlx::query_as(&similarity::recent_candidates_sql())
        .bind(claims.sub)
        .bind(team_key)
        .bind(is_admin)
        .bind(submission_id)
        .fetch_all(pool)
        .await
        .map_err(db_error)?;
    if let Some(imp) = &target.imphash {
        let same: Vec<Candidate> = sqlx::query_as(&similarity::imphash_candidates_sql())
            .bind(claims.sub)
            .bind(team_key)
            .bind(is_admin)
            .bind(submission_id)
            .bind(imp)
            .fetch_all(pool)
            .await
            .map_err(db_error)?;
        let seen: HashSet<Uuid> = candidates.iter().map(|c| c.submission_id).collect();
        candidates.extend(
            same.into_iter()
                .filter(|c| !seen.contains(&c.submission_id)),
        );
    }

    let compared = candidates.len();
    let sha = submission.file_hash.clone().unwrap_or_default();
    let target_for_task = target.clone();
    let found = tokio::task::spawn_blocking(move || rank(&target_for_task, &sha, candidates))
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let web = crate::services::webhook_delivery::web_url();
    let web = web.trim_end_matches('/');
    let similar: Vec<Value> = found
        .into_iter()
        .map(|(c, m)| {
            json!({
                "submissionId": c.submission_id,
                "sha256": c.file_hash,
                "filename": c.original_filename,
                "fileSize": c.file_size,
                "createdAt": c.created_at,
                "verdict": c.verdict,
                "reportUrl": format!("{web}/analysis/{}", c.submission_id),
                "match": m,
            })
        })
        .collect();

    Ok(Json(json!({
        "submissionId": submission_id,
        "status": "ready",
        "hashes": target,
        "similar": similar,
        "compared": compared,
    })))
}

/// The candidates similar enough to report, closest first, at most
/// [`similarity::MAX_RESULTS`].
fn rank(target: &Hashes, sha256: &str, candidates: Vec<Candidate>) -> Vec<(Candidate, Match)> {
    let mut found: Vec<(Candidate, Match)> = candidates
        .into_iter()
        .filter_map(|c| {
            let m = similarity::compare(
                target,
                sha256,
                &c.hashes(),
                c.file_hash.as_deref().unwrap_or(""),
            )?;
            Some((c, m))
        })
        .collect();
    found.sort_by_key(|(c, m)| (m.rank(), std::cmp::Reverse(c.created_at)));
    found.truncate(similarity::MAX_RESULTS);
    found
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn cand(id: u128, h: Hashes, sha: &str) -> Candidate {
        Candidate {
            submission_id: Uuid::from_u128(id),
            tlsh: h.tlsh,
            ssdeep: h.ssdeep,
            imphash: h.imphash,
            file_hash: Some(sha.into()),
            original_filename: None,
            file_size: None,
            created_at: Utc::now(),
            verdict: None,
        }
    }

    #[test]
    fn ranks_identical_then_imports_and_drops_unrelated() {
        let target = Hashes {
            imphash: Some("a".repeat(32)),
            ..Default::default()
        };
        let got = rank(
            &target,
            "sha-1",
            vec![
                cand(1, Hashes::default(), "other"),
                cand(
                    2,
                    Hashes {
                        imphash: Some("a".repeat(32)),
                        ..Default::default()
                    },
                    "sha-2",
                ),
                cand(3, Hashes::default(), "SHA-1"),
            ],
        );
        let ids: Vec<u128> = got.iter().map(|(c, _)| c.submission_id.as_u128()).collect();
        assert_eq!(ids, [3, 2]);
    }
}
