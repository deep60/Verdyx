//! Data retention: what is deleted, when, and how.
//!
//! A daily job ([`spawn`]) applies these rules, oldest first, in batches:
//!
//! | what | after | setting |
//! |---|---|---|
//! | a scan's stored sample file (the scan and results stay) | 30 days | `SAMPLE_RETENTION_DAYS` (0 = keep) |
//! | a scan made while signed out | 90 days | `GUEST_SCAN_RETENTION_DAYS` (0 = keep) |
//! | a team's scans | the team's choice: 30, 90, 180 or 365 days, or never | Teams → Settings |
//! | your own scans | your choice, as above | Profile → Data |
//!
//! Scans that carry a bounty are never deleted by retention: the bounty, its
//! votes and payouts depend on them.
//!
//! Files live on the gateway's upload volume, which the analysis engine shares.
//! [`delete_artifact`] removes them directly; anything that isn't a local file
//! under the upload folder is a storage key, queued for the engine to delete.

use std::path::{Component, Path, PathBuf};

use serde_json::json;
use uuid::Uuid;

use crate::services::audit::Event;
use crate::AppState;

pub const SAMPLE_DAYS_DEFAULT: i64 = 30;
pub const GUEST_DAYS_DEFAULT: i64 = 90;
/// Choices offered for personal and team scan retention.
pub const RETENTION_CHOICES: [i32; 4] = [30, 90, 180, 365];
const BATCH: i64 = 500;
const MAX_BATCHES: usize = 40;

/// `None` means keep forever.
fn days_from_env(name: &str, default: i64) -> Option<i64> {
    let days = std::env::var(name)
        .ok()
        .and_then(|v| v.trim().parse::<i64>().ok())
        .unwrap_or(default);
    (days > 0).then_some(days)
}

pub fn sample_days() -> Option<i64> {
    days_from_env("SAMPLE_RETENTION_DAYS", SAMPLE_DAYS_DEFAULT)
}

pub fn guest_days() -> Option<i64> {
    days_from_env("GUEST_SCAN_RETENTION_DAYS", GUEST_DAYS_DEFAULT)
}

/// A retention choice from a request: a number from [`RETENTION_CHOICES`],
/// or null to keep scans.
pub fn parse_choice(v: &serde_json::Value) -> Result<Option<i32>, &'static str> {
    match v {
        serde_json::Value::Null => Ok(None),
        serde_json::Value::Number(n) => n
            .as_i64()
            .and_then(|d| i32::try_from(d).ok())
            .filter(|d| RETENTION_CHOICES.contains(d))
            .map(Some)
            .ok_or("choose 30, 90, 180 or 365 days, or null to keep scans"),
        _ => Err("choose 30, 90, 180 or 365 days, or null to keep scans"),
    }
}

pub fn upload_root(state: &AppState) -> PathBuf {
    PathBuf::from(
        std::env::var("UPLOAD_DIR").unwrap_or_else(|_| state.config.services.upload_path.clone()),
    )
}

/// The local file a stored path points to, if it is inside the upload folder.
pub fn local_file(root: &Path, stored: &str) -> Option<PathBuf> {
    let path = Path::new(stored);
    if !path.is_absolute()
        || path
            .components()
            .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
    {
        return None;
    }
    path.starts_with(root).then(|| path.to_path_buf())
}

/// Delete a stored sample. Never fails the caller.
pub async fn delete_artifact(state: &AppState, stored: &str) {
    let root = upload_root(state);
    if let Some(file) = local_file(&root, stored) {
        match tokio::fs::remove_file(&file).await {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => tracing::error!("Failed to delete {}: {}", file.display(), e),
        }
        return;
    }
    if let Err(e) = state.redis.queue_artifact_deletion(stored).await {
        tracing::error!("Failed to queue deletion of {stored}: {e}");
    }
}

/// Delete scans, their results and votes, and their files. Returns how many.
pub async fn delete_scans(state: &AppState, ids: &[Uuid]) -> Result<u64, sqlx::Error> {
    if ids.is_empty() {
        return Ok(0);
    }
    let mut tx = state.db.pool().begin().await?;
    // Votes reference scans without a foreign key.
    sqlx::query("DELETE FROM submission_votes WHERE submission_id = ANY($1)")
        .bind(ids)
        .execute(&mut *tx)
        .await?;
    let paths: Vec<(Option<String>,)> =
        sqlx::query_as("DELETE FROM submissions WHERE id = ANY($1) RETURNING file_path")
            .bind(ids)
            .fetch_all(&mut *tx)
            .await?;
    tx.commit().await?;
    for path in paths.iter().filter_map(|(p,)| p.as_deref()) {
        delete_artifact(state, path).await;
    }
    Ok(paths.len() as u64)
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Summary {
    pub files_purged: u64,
    pub guest_scans: u64,
    pub team_scans: u64,
    pub personal_scans: u64,
}

/// Applies every rule once.
pub async fn run_once(state: &AppState) -> Result<Summary, sqlx::Error> {
    let pool = state.db.pool();
    let mut summary = Summary::default();

    // 1. Sample files. Scans still being analysed keep theirs.
    if let Some(days) = sample_days() {
        for _ in 0..MAX_BATCHES {
            let rows: Vec<(Uuid, String)> = sqlx::query_as(
                r#"SELECT id, file_path FROM submissions
                   WHERE file_path IS NOT NULL AND file_purged_at IS NULL
                     AND created_at < NOW() - make_interval(days => $1::INT)
                     AND COALESCE(analysis_status, '') NOT IN ('pending', 'analyzing', 'processing', 'queued')
                   ORDER BY created_at LIMIT $2"#,
            )
            .bind(days as i32)
            .bind(BATCH)
            .fetch_all(pool)
            .await?;
            if rows.is_empty() {
                break;
            }
            for (_, path) in &rows {
                delete_artifact(state, path).await;
            }
            let ids: Vec<Uuid> = rows.iter().map(|(id, _)| *id).collect();
            sqlx::query(
                "UPDATE submissions SET file_path = NULL, file_purged_at = NOW() WHERE id = ANY($1)",
            )
            .bind(&ids)
            .execute(pool)
            .await?;
            summary.files_purged += ids.len() as u64;
            if (rows.len() as i64) < BATCH {
                break;
            }
        }
    }

    const NO_BOUNTY: &str = "NOT EXISTS (SELECT 1 FROM bounties b WHERE b.submission_id = s.id)";

    // 2. Scans made while signed out.
    if let Some(days) = guest_days() {
        for _ in 0..MAX_BATCHES {
            let ids: Vec<Uuid> = sqlx::query_scalar(&format!(
                r#"SELECT s.id FROM submissions s
                   WHERE s.submitter_id = '00000000-0000-0000-0000-000000000000'
                     AND s.created_at < NOW() - make_interval(days => $1::INT) AND {NO_BOUNTY}
                   ORDER BY s.created_at LIMIT $2"#
            ))
            .bind(days as i32)
            .bind(BATCH)
            .fetch_all(pool)
            .await?;
            let n = delete_scans(state, &ids).await?;
            summary.guest_scans += n;
            if (ids.len() as i64) < BATCH {
                break;
            }
        }
    }

    // 3. Team scans past the team's retention, and 4. personal scans past the
    // person's. Each team or person gets one event saying how many went.
    for (owner_sql, team) in [
        (
            r#"SELECT s.id, o.id FROM submissions s JOIN organizations o ON o.id = s.organization_id
               WHERE o.scan_retention_days IS NOT NULL
                 AND s.created_at < NOW() - make_interval(days => o.scan_retention_days)"#,
            true,
        ),
        (
            r#"SELECT s.id, u.id FROM submissions s JOIN users u ON u.id = s.submitter_id
               WHERE s.organization_id IS NULL AND u.scan_retention_days IS NOT NULL
                 AND s.created_at < NOW() - make_interval(days => u.scan_retention_days)"#,
            false,
        ),
    ] {
        let mut per_owner: std::collections::HashMap<Uuid, u64> = Default::default();
        for _ in 0..MAX_BATCHES {
            let rows: Vec<(Uuid, Uuid)> = sqlx::query_as(&format!(
                "{owner_sql} AND {NO_BOUNTY} ORDER BY s.created_at LIMIT $1"
            ))
            .bind(BATCH)
            .fetch_all(pool)
            .await?;
            let ids: Vec<Uuid> = rows.iter().map(|(id, _)| *id).collect();
            delete_scans(state, &ids).await?;
            for (_, owner) in &rows {
                *per_owner.entry(*owner).or_default() += 1;
            }
            if (rows.len() as i64) < BATCH {
                break;
            }
        }
        for (owner, count) in per_owner {
            let event = Event::system("scan.expired").detail("count", json!(count));
            let event = if team {
                summary.team_scans += count;
                event.team(owner)
            } else {
                summary.personal_scans += count;
                event.subject(owner)
            };
            event.record(pool).await;
        }
    }

    Ok(summary)
}

/// Runs [`run_once`] a minute after start-up (`RETENTION_FIRST_RUN_SECS`),
/// then daily.
pub fn spawn(state: AppState) {
    let first = std::env::var("RETENTION_FIRST_RUN_SECS")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(60);
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(first)).await;
        let mut daily = tokio::time::interval(std::time::Duration::from_secs(24 * 3600));
        loop {
            daily.tick().await;
            match run_once(&state).await {
                Ok(s) if s != Summary::default() => tracing::info!(
                    files = s.files_purged,
                    guest = s.guest_scans,
                    team = s.team_scans,
                    personal = s.personal_scans,
                    "retention: deleted expired data"
                ),
                Ok(_) => {}
                Err(e) => tracing::error!("retention run failed: {e}"),
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_files_inside_the_upload_folder_are_deleted_locally() {
        let root = Path::new("/app/uploads");
        assert_eq!(
            local_file(root, "/app/uploads/abc"),
            Some(PathBuf::from("/app/uploads/abc"))
        );
        assert_eq!(local_file(root, "/app/uploads/../etc/passwd"), None);
        // `.` inside a path is ignored by the parser, so this is /app/uploads/x.
        assert!(local_file(root, "/app/uploads/./x").is_some());
        assert_eq!(local_file(root, "/etc/passwd"), None);
        assert_eq!(local_file(root, "/app/uploads-other/x"), None);
        assert_eq!(local_file(root, "submissions/abc"), None, "a storage key");
    }

    #[test]
    fn retention_choices_are_validated() {
        assert_eq!(parse_choice(&json!(null)).unwrap(), None);
        assert_eq!(parse_choice(&json!(90)).unwrap(), Some(90));
        for bad in [
            json!(7),
            json!(0),
            json!(-30),
            json!("90"),
            json!(90.5),
            json!(true),
        ] {
            assert!(parse_choice(&bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn zero_days_means_keep() {
        assert_eq!(days_from_env("VERDYX_TEST_UNSET_RETENTION", 30), Some(30));
        assert_eq!(days_from_env("VERDYX_TEST_UNSET_RETENTION", 0), None);
    }
}
