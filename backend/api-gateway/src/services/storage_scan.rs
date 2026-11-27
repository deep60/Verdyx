//! Scans the files that arrive in teams' connected buckets
//! ([`crate::handlers::storage`]).
//!
//! Every minute the worker takes the connections that are due (their
//! interval has passed, or someone pressed "Scan now"), lists their bucket
//! and makes a scan for each file it hasn't seen: a file is known by its key
//! and ETag, so a changed file is scanned again. Scans are saved to the team
//! in the name of whoever set the connection up, and go through the normal
//! analysis queue, webhooks and SIEM delivery.
//!
//! A run lists up to [`PAGES_PER_RUN`] pages and makes up to
//! [`SCANS_PER_RUN`] scans. A large bucket is covered over several runs, a
//! minute apart, continuing where the last stopped.
//!
//! Turn it off with `STORAGE_SCANNING=off`.

// Query rows are read as plain tuples.
#![allow(clippy::type_complexity)]

use std::collections::HashSet;
use std::time::Duration;

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::handlers::submission::{insert_and_queue, kind_of_upload, write_upload, ScanRow};
use crate::services::s3::{Bucket, Keys, Object, S3Error};
use crate::services::siem::CredentialKey;
use crate::utils::crypto::calculate_file_hash;
use crate::AppState;

/// Scans one run makes at most.
pub const SCANS_PER_RUN: usize = 25;
/// Listing pages (1,000 files each) one run reads at most.
pub const PAGES_PER_RUN: usize = 10;
/// Connections handled per tick.
const CONNECTIONS_PER_TICK: i64 = 3;
const TICK: Duration = Duration::from_secs(60);
/// A run that hasn't finished after this long is taken as dead.
const STALE_RUN_MINUTES: i32 = 30;
/// Downloads may take this long.
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(120);

/// A connection the worker is running.
#[derive(Debug, Clone)]
pub struct Due {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub created_by: Uuid,
    pub name: String,
    pub endpoint: Option<String>,
    pub region: String,
    pub bucket: String,
    pub prefix: String,
    pub access_key_id: String,
    pub sealed_key: String,
    pub analysis_type: String,
    pub max_object_mb: i32,
    pub scan_since: DateTime<Utc>,
    pub list_token: Option<String>,
}

/// What a run did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Outcome {
    pub scanned: usize,
    /// Where the next run continues; `None` starts a new pass.
    pub token: Option<String>,
    /// The pass isn't finished: run again at the next tick.
    pub more: bool,
    pub error: Option<String>,
}

/// The files in a page worth scanning: changed since `since`, not folder
/// markers, not empty, and not already seen (`seen` holds key and ETag).
pub fn worth_scanning<'a>(
    page: &'a [Object],
    since: DateTime<Utc>,
    seen: &HashSet<(String, String)>,
) -> Vec<&'a Object> {
    page.iter()
        .filter(|o| !o.key.ends_with('/') && o.size > 0)
        .filter(|o| o.last_modified.is_none_or(|t| t >= since))
        .filter(|o| !seen.contains(&(o.key.clone(), o.etag.clone())))
        .collect()
}

/// The scan's name: the file's key, cut to a length the reports can show.
pub fn scan_name(key: &str) -> String {
    const MAX: usize = 255;
    if key.chars().count() <= MAX {
        return key.to_string();
    }
    // Keep the end, where the file name is.
    let tail: String = key
        .chars()
        .rev()
        .take(MAX - 1)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    format!("…{tail}")
}

/// Takes the connections that are due, marking them as running.
pub async fn claim(db: &sqlx::PgPool, limit: i64) -> Result<Vec<Due>, sqlx::Error> {
    let rows: Vec<(
        Uuid,
        Uuid,
        Uuid,
        String,
        Option<String>,
        String,
        String,
        String,
        String,
        String,
        String,
        i32,
        DateTime<Utc>,
        Option<String>,
    )> = sqlx::query_as(
        "UPDATE storage_connections SET running_since = NOW()
         WHERE id IN (
             SELECT id FROM storage_connections
             WHERE enabled
               AND (running_since IS NULL
                    OR running_since < NOW() - make_interval(mins => $2))
               AND (run_requested OR last_run_at IS NULL
                    OR last_run_at < NOW() - make_interval(mins => interval_minutes))
             ORDER BY run_requested DESC, last_run_at NULLS FIRST
             LIMIT $1
             FOR UPDATE SKIP LOCKED)
         RETURNING id, organization_id, created_by, name, endpoint, region, bucket, prefix,
                   access_key_id, secret_access_key, analysis_type, max_object_mb, scan_since,
                   list_token",
    )
    .bind(limit)
    .bind(STALE_RUN_MINUTES)
    .fetch_all(db)
    .await?;
    Ok(rows
        .into_iter()
        .map(|r| Due {
            id: r.0,
            organization_id: r.1,
            created_by: r.2,
            name: r.3,
            endpoint: r.4,
            region: r.5,
            bucket: r.6,
            prefix: r.7,
            access_key_id: r.8,
            sealed_key: r.9,
            analysis_type: r.10,
            max_object_mb: r.11,
            scan_since: r.12,
            list_token: r.13,
        })
        .collect())
}

/// Records how a run went and frees the connection.
pub async fn finish(db: &sqlx::PgPool, id: Uuid, outcome: &Outcome) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE storage_connections SET
            running_since = NULL, run_requested = $2, last_run_at = NOW(),
            last_error = $3, last_scanned = $4, list_token = $5
         WHERE id = $1",
    )
    .bind(id)
    .bind(outcome.more)
    .bind(&outcome.error)
    .bind(outcome.scanned as i32)
    .bind(&outcome.token)
    .execute(db)
    .await?;
    Ok(())
}

/// Notes a file as looked at.
pub async fn record(
    db: &sqlx::PgPool,
    connection_id: Uuid,
    object: &Object,
    status: &str,
    error: Option<&str>,
    submission_id: Option<Uuid>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO storage_objects
            (connection_id, key, etag, size, last_modified, status, error, submission_id)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
         ON CONFLICT (connection_id, key, etag) DO UPDATE SET
            status = EXCLUDED.status, error = EXCLUDED.error,
            submission_id = EXCLUDED.submission_id, seen_at = NOW()",
    )
    .bind(connection_id)
    .bind(&object.key)
    .bind(&object.etag)
    .bind(object.size)
    .bind(object.last_modified)
    .bind(status)
    .bind(error)
    .bind(submission_id)
    .execute(db)
    .await?;
    Ok(())
}

/// Which of `keys` were already looked at. A download that failed is tried
/// again after a day.
async fn seen(
    db: &sqlx::PgPool,
    connection_id: Uuid,
    keys: &[String],
) -> Result<HashSet<(String, String)>, sqlx::Error> {
    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT key, etag FROM storage_objects
         WHERE connection_id = $1 AND key = ANY($2)
           AND (status <> 'failed' OR seen_at > NOW() - INTERVAL '1 day')",
    )
    .bind(connection_id)
    .bind(keys)
    .fetch_all(db)
    .await?;
    Ok(rows.into_iter().collect())
}

/// Saves a downloaded file as a team scan.
async fn make_scan(
    state: &AppState,
    due: &Due,
    object: &Object,
    data: Vec<u8>,
) -> Result<Uuid, String> {
    let id = Uuid::new_v4();
    let path = write_upload(state, id, &data)
        .await
        .map_err(|_| "couldn't store the file".to_string())?;
    let filename = scan_name(&object.key);
    let (submission_type, mime_type) = kind_of_upload(&object.key, &data, false);
    let metadata = serde_json::json!({
        "analysisType": due.analysis_type,
        "priority": false,
        "description": null,
        "source": {
            "kind": "storage",
            "connectionId": due.id,
            "connection": due.name,
            "bucket": due.bucket,
            "key": object.key,
        },
    });
    let pool = state.db.pool();
    let may_upload_file =
        crate::handlers::privacy::may_upload_file(pool, due.created_by, Some(due.organization_id))
            .await;
    insert_and_queue(
        state,
        ScanRow {
            id,
            submitter_id: due.created_by,
            filename: &filename,
            file_hash: &calculate_file_hash(&data),
            url: None,
            file_size: data.len() as i64,
            mime_type: &mime_type,
            file_path: Some(&path),
            submission_type: &submission_type,
            metadata: &metadata,
            created_at: Utc::now(),
            organization_id: Some(due.organization_id),
            may_upload_file,
            priority: false,
        },
    )
    .await
    .map_err(|e| {
        tracing::error!("storage scan: couldn't save a scan: {e}");
        "couldn't save the scan".to_string()
    })?;
    Ok(id)
}

/// One run over one connection.
pub async fn run(
    state: &AppState,
    http: &reqwest::Client,
    key: &CredentialKey,
    due: &Due,
) -> Outcome {
    let mut out = Outcome {
        token: due.list_token.clone(),
        ..Outcome::default()
    };
    let Some(secret) = key.open(&due.sealed_key) else {
        out.error =
            Some("the stored secret access key can't be read any more; enter it again".to_string());
        return out;
    };
    let endpoint = match due.endpoint.as_deref().map(url::Url::parse) {
        None => None,
        Some(Ok(u)) => Some(u),
        Some(Err(_)) => {
            out.error = Some("the endpoint isn't a valid address".to_string());
            return out;
        }
    };
    let bucket = Bucket {
        endpoint,
        region: due.region.clone(),
        name: due.bucket.clone(),
    };
    let keys = Keys {
        access_key_id: due.access_key_id.clone(),
        secret_access_key: secret,
    };
    let max_bytes = due.max_object_mb as u64 * 1024 * 1024;
    let db = state.db.pool();

    for _ in 0..PAGES_PER_RUN {
        let page = match bucket
            .list(http, &keys, &due.prefix, out.token.as_deref(), 1000)
            .await
        {
            Ok(p) => p,
            Err(e) => {
                out.error = Some(format!("couldn't list the bucket: {}", e.explain()));
                return out;
            }
        };
        let page_keys: Vec<String> = page.objects.iter().map(|o| o.key.clone()).collect();
        let already = match seen(db, due.id, &page_keys).await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!("storage scan: {e}");
                out.error = Some("something went wrong on Verdyx's side".to_string());
                return out;
            }
        };
        for object in worth_scanning(&page.objects, due.scan_since, &already) {
            if out.scanned >= SCANS_PER_RUN {
                // Continue from this page at the next tick.
                out.more = true;
                return out;
            }
            let noted = if object.size as u64 > max_bytes {
                record(db, due.id, object, "too_large", None, None).await
            } else {
                // A team out of monthly scans waits for next month (or a
                // bigger plan); the file is left unseen so it's scanned then.
                if let Err(q) =
                    crate::handlers::submission::team_quota_left(state, Some(due.organization_id))
                        .await
                {
                    out.error = Some(q.message());
                    return out;
                }
                match bucket.download(http, &keys, &object.key, max_bytes).await {
                    Ok(data) => match make_scan(state, due, object, data).await {
                        Ok(id) => {
                            out.scanned += 1;
                            record(db, due.id, object, "queued", None, Some(id)).await
                        }
                        Err(e) => {
                            out.error = Some(e);
                            return out;
                        }
                    },
                    Err(S3Error::TooLarge) => {
                        record(db, due.id, object, "too_large", None, None).await
                    }
                    Err(e) => {
                        let why = e.explain();
                        record(db, due.id, object, "failed", Some(&why), None).await
                    }
                }
            };
            if let Err(e) = noted {
                tracing::warn!("storage scan: couldn't note a file: {e}");
            }
        }
        match page.next {
            Some(next) => out.token = Some(next),
            None => {
                // The pass is done; the next run starts over for new files.
                out.token = None;
                return out;
            }
        }
    }
    // Read as many pages as one run may; carry on at the next tick.
    out.more = true;
    out
}

/// Start the worker.
pub fn spawn(state: AppState) {
    if std::env::var("STORAGE_SCANNING")
        .map(|v| v == "off")
        .unwrap_or(false)
    {
        tracing::info!("Storage scanning is off (STORAGE_SCANNING=off)");
        return;
    }
    tokio::spawn(async move {
        let http = crate::services::webhook_delivery::client_with_timeout(false, DOWNLOAD_TIMEOUT);
        let key = CredentialKey::from_config(&state.config.security.jwt_secret);
        tracing::info!("Storage scanning worker started");
        loop {
            tokio::time::sleep(TICK).await;
            let due = match claim(state.db.pool(), CONNECTIONS_PER_TICK).await {
                Ok(d) => d,
                Err(e) => {
                    tracing::warn!("storage scan: {e}");
                    continue;
                }
            };
            for d in due {
                let outcome = run(&state, &http, &key, &d).await;
                if outcome.scanned > 0 || outcome.error.is_some() {
                    tracing::info!(
                        connection = %d.id,
                        scanned = outcome.scanned,
                        error = outcome.error.as_deref().unwrap_or(""),
                        "storage scan run"
                    );
                }
                if let Err(e) = finish(state.db.pool(), d.id, &outcome).await {
                    tracing::warn!("storage scan: couldn't record a run: {e}");
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obj(key: &str, size: i64, etag: &str, at: Option<&str>) -> Object {
        Object {
            key: key.into(),
            size,
            etag: etag.into(),
            last_modified: at.map(|t| DateTime::parse_from_rfc3339(t).unwrap().with_timezone(&Utc)),
        }
    }

    #[test]
    fn only_new_unseen_files_are_scanned() {
        let since = DateTime::parse_from_rfc3339("2026-11-20T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let page = vec![
            obj("in/", 0, "d41d", Some("2026-11-21T00:00:00Z")),
            obj("in/old.exe", 10, "a", Some("2026-11-01T00:00:00Z")),
            obj("in/new.exe", 10, "b", Some("2026-11-21T00:00:00Z")),
            obj("in/empty.txt", 0, "c", Some("2026-11-21T00:00:00Z")),
            obj("in/seen.pdf", 10, "d", Some("2026-11-21T00:00:00Z")),
            obj("in/changed.pdf", 10, "e2", Some("2026-11-21T00:00:00Z")),
            obj("in/undated.bin", 10, "f", None),
        ];
        let seen: HashSet<(String, String)> = [
            ("in/seen.pdf".to_string(), "d".to_string()),
            ("in/changed.pdf".to_string(), "e1".to_string()),
        ]
        .into_iter()
        .collect();
        let keys: Vec<&str> = worth_scanning(&page, since, &seen)
            .into_iter()
            .map(|o| o.key.as_str())
            .collect();
        assert_eq!(keys, ["in/new.exe", "in/changed.pdf", "in/undated.bin"]);
    }

    #[test]
    fn long_keys_keep_their_file_name() {
        assert_eq!(scan_name("in/a.exe"), "in/a.exe");
        let long = format!("{}/invoice.exe", "d".repeat(300));
        let name = scan_name(&long);
        assert_eq!(name.chars().count(), 255);
        assert!(name.starts_with('…') && name.ends_with("/invoice.exe"));
    }

    /// Against a real database; runs only when API_GATEWAY_DATABASE_URL is
    /// set, and removes what it adds.
    #[tokio::test]
    async fn storage_runs_are_claimed_once_and_files_noted_once() {
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
        // Other connections in a shared test database mustn't be claimed.
        sqlx::query("UPDATE storage_connections SET enabled = FALSE")
            .execute(&db)
            .await
            .unwrap();

        let (team, owner, conn) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        sqlx::query("INSERT INTO organizations (id, name, created_by) VALUES ($1, 'Acme SOC', $2)")
            .bind(team)
            .bind(owner)
            .execute(&db)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO storage_connections
                (id, organization_id, created_by, name, provider, region, bucket,
                 access_key_id, secret_access_key, interval_minutes)
             VALUES ($1, $2, $3, 'Uploads', 'aws', 'us-east-1', 'acme', 'AKIA', 'sealed', 60)",
        )
        .bind(conn)
        .bind(team)
        .bind(owner)
        .execute(&db)
        .await
        .unwrap();

        // Never run: due. Claimed once, then not again while it runs.
        let first = claim(&db, 10).await.unwrap();
        assert_eq!(first.iter().filter(|d| d.id == conn).count(), 1);
        assert!(claim(&db, 10).await.unwrap().iter().all(|d| d.id != conn));

        // Finished with more to do: claimed again straight away.
        let more = Outcome {
            scanned: 25,
            token: Some("page-2".into()),
            more: true,
            error: None,
        };
        finish(&db, conn, &more).await.unwrap();
        let again = claim(&db, 10).await.unwrap();
        let d = again.iter().find(|d| d.id == conn).expect("claimed again");
        assert_eq!(d.list_token.as_deref(), Some("page-2"));

        // A finished pass waits for the interval.
        finish(&db, conn, &Outcome::default()).await.unwrap();
        assert!(claim(&db, 10).await.unwrap().iter().all(|d| d.id != conn));

        // A file is noted once per version; a failed download is noted, and
        // counts as seen for a day.
        let f = obj("in/a.exe", 10, "v1", None);
        record(&db, conn, &f, "failed", Some("timed out"), None)
            .await
            .unwrap();
        record(&db, conn, &f, "queued", None, Some(Uuid::new_v4()))
            .await
            .unwrap();
        let rows: Vec<(String,)> =
            sqlx::query_as("SELECT status FROM storage_objects WHERE connection_id = $1")
                .bind(conn)
                .fetch_all(&db)
                .await
                .unwrap();
        assert_eq!(rows, [("queued".to_string(),)]);
        let s = seen(&db, conn, &["in/a.exe".to_string(), "in/b.exe".to_string()])
            .await
            .unwrap();
        assert!(s.contains(&("in/a.exe".to_string(), "v1".to_string())));
        assert_eq!(s.len(), 1);

        // Deleting the team removes its connections and their notes.
        sqlx::query("DELETE FROM organizations WHERE id = $1")
            .bind(team)
            .execute(&db)
            .await
            .unwrap();
        let left: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM storage_objects WHERE connection_id = $1")
                .bind(conn)
                .fetch_one(&db)
                .await
                .unwrap();
        assert_eq!(left, 0);
    }
}
