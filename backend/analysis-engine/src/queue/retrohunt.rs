//! Retrohunt worker: runs a person's YARA rule over the stored files they
//! may see.
//!
//! The gateway queues a job id on `retrohunt_queue` and owns the
//! `retrohunt_jobs` / `retrohunt_matches` tables (in its database, which
//! this worker reaches through `GATEWAY_DATABASE_URL`). One job runs at a
//! time:
//!
//! 1. The rule is checked again (`shared::yara_rules`) and compiled with
//!    `include` refused, so it can't read files from the server.
//! 2. The files in scope are the person's own scans, or a team's (checked
//!    again here), newest first, at most [`MAX_FILES`].
//! 3. Each file is scanned with a per-file timeout. Only files inside
//!    `UPLOAD_DIR` are read.
//! 4. Progress is written every few files; a cancelled job stops at the next
//!    check, and a job stops after [`MAX_RUNTIME`].

use std::time::{Duration, Instant};

use anyhow::Result;
use sqlx::PgPool;
use tracing::{error, info, warn};
use uuid::Uuid;

pub const QUEUE: &str = "retrohunt_queue";
pub const MAX_FILES: i64 = 5_000;
pub const MAX_RUNTIME: Duration = Duration::from_secs(15 * 60);
/// Seconds YARA may spend on one file.
pub const FILE_TIMEOUT_SECS: i32 = 10;
const PROGRESS_EVERY: usize = 20;
const IDLE_POLL: Duration = Duration::from_secs(3);

/// A compiled rule set, or why it didn't compile.
pub trait Hunter: Send + Sync {
    /// Rule names that match the file at `path`.
    fn scan_file(&self, path: &std::path::Path) -> Result<Vec<String>, String>;
    /// Rule names that match these bytes, giving up after `timeout_secs`.
    fn scan_bytes(&self, data: &[u8], timeout_secs: i32) -> Result<Vec<String>, String>;
}

#[cfg(feature = "yara-engine")]
mod engine {
    use super::*;

    pub struct YaraHunter(yara::Rules);

    impl Hunter for YaraHunter {
        fn scan_file(&self, path: &std::path::Path) -> Result<Vec<String>, String> {
            self.0
                .scan_file(path, FILE_TIMEOUT_SECS)
                .map(|hits| hits.iter().map(|r| r.identifier.to_string()).collect())
                .map_err(|e| e.to_string())
        }

        fn scan_bytes(&self, data: &[u8], timeout_secs: i32) -> Result<Vec<String>, String> {
            self.0
                .scan_mem(data, timeout_secs)
                .map(|hits| hits.iter().map(|r| r.identifier.to_string()).collect())
                .map_err(|e| e.to_string())
        }
    }

    pub fn compile(rule: &str) -> Result<Box<dyn Hunter>, String> {
        let mut compiler = yara::Compiler::new().map_err(|e| e.to_string())?;
        // Refuse every include, whatever the checks above missed.
        compiler.set_include_callback(|_, _, _| None);
        let compiler = compiler
            .add_rules_str(rule)
            .map_err(|e| format!("the rule doesn't compile: {e}"))?;
        let rules = compiler
            .compile_rules()
            .map_err(|e| format!("the rule doesn't compile: {e}"))?;
        Ok(Box::new(YaraHunter(rules)))
    }
}

/// Compile a checked rule.
pub fn compile(rule: &str) -> Result<Box<dyn Hunter>, String> {
    shared::yara_rules::check(rule)?;
    #[cfg(feature = "yara-engine")]
    {
        engine::compile(rule)
    }
    #[cfg(not(feature = "yara-engine"))]
    {
        Err("YARA isn't available on this server".to_string())
    }
}

/// Runs jobs forever. Errors are logged; the loop never exits.
pub async fn run(redis_client: redis::Client, db: PgPool) {
    // A job that was running when the engine stopped can't resume.
    if let Err(e) = sqlx::query(
        "UPDATE retrohunt_jobs SET status = 'failed', message = 'interrupted by a restart; run it again', \
         finished_at = NOW() WHERE status = 'running'",
    )
    .execute(&db)
    .await
    {
        warn!("retrohunt tables not ready yet: {e}");
    }
    info!("Retrohunt worker started");
    loop {
        match next_job(&redis_client).await {
            Ok(Some(id)) => {
                if let Err(e) = run_job(&db, id).await {
                    error!("retrohunt {id} failed: {e}");
                    let _ = finish(
                        &db,
                        id,
                        "failed",
                        Some("something went wrong; run it again"),
                    )
                    .await;
                }
            }
            Ok(None) => tokio::time::sleep(IDLE_POLL).await,
            Err(e) => {
                warn!("retrohunt queue unavailable: {e}");
                tokio::time::sleep(IDLE_POLL * 5).await;
            }
        }
    }
}

async fn next_job(redis_client: &redis::Client) -> Result<Option<Uuid>> {
    use redis::AsyncCommands;
    let mut conn = redis_client.get_multiplexed_async_connection().await?;
    let raw: Option<String> = conn.rpop(QUEUE, None).await?;
    Ok(raw.and_then(|r| Uuid::parse_str(r.trim()).ok()))
}

async fn finish(db: &PgPool, id: Uuid, status: &str, message: Option<&str>) -> Result<()> {
    // Never overwrite a cancellation.
    sqlx::query(
        "UPDATE retrohunt_jobs SET status = $2, message = COALESCE($3, message), finished_at = NOW() \
         WHERE id = $1 AND status IN ('queued', 'running')",
    )
    .bind(id)
    .bind(status)
    .bind(message)
    .execute(db)
    .await?;
    Ok(())
}

async fn cancelled(db: &PgPool, id: Uuid) -> bool {
    sqlx::query_scalar::<_, String>("SELECT status FROM retrohunt_jobs WHERE id = $1")
        .bind(id)
        .fetch_optional(db)
        .await
        .ok()
        .flatten()
        .is_none_or(|s| s == "cancelled")
}

/// Run one job. Returns `Ok` when the job reached a final state itself.
pub async fn run_job(db: &PgPool, id: Uuid) -> Result<()> {
    let Some((user, team, rule, status)) =
        sqlx::query_as::<_, (Uuid, Option<Uuid>, String, String)>(
            "SELECT user_id, organization_id, rule_text, status FROM retrohunt_jobs WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(db)
        .await?
    else {
        return Ok(());
    };
    if status != "queued" {
        return Ok(());
    }
    sqlx::query("UPDATE retrohunt_jobs SET status = 'running', started_at = NOW() WHERE id = $1 AND status = 'queued'")
        .bind(id)
        .execute(db)
        .await?;

    let hunter = match tokio::task::spawn_blocking(move || compile(&rule)).await? {
        Ok(h) => std::sync::Arc::<dyn Hunter>::from(h),
        Err(why) => {
            let why: String = why.chars().take(500).collect();
            return finish(db, id, "failed", Some(&why)).await;
        }
    };

    // Scope, checked again in case the person left the team.
    let files: Vec<(Uuid, String)> = match team {
        Some(t) => {
            let member: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM organization_members WHERE organization_id = $1 AND user_id = $2)",
            )
            .bind(t)
            .bind(user)
            .fetch_one(db)
            .await?;
            if !member {
                return finish(db, id, "failed", Some("you're no longer in that team")).await;
            }
            sqlx::query_as(
                "SELECT id, file_path FROM submissions WHERE organization_id = $1 AND file_path IS NOT NULL \
                 ORDER BY created_at DESC LIMIT $2",
            )
            .bind(t)
            .bind(MAX_FILES)
            .fetch_all(db)
            .await?
        }
        None => {
            sqlx::query_as(
                "SELECT id, file_path FROM submissions WHERE submitter_id = $1 AND file_path IS NOT NULL \
                 ORDER BY created_at DESC LIMIT $2",
            )
            .bind(user)
            .bind(MAX_FILES)
            .fetch_all(db)
            .await?
        }
    };
    sqlx::query("UPDATE retrohunt_jobs SET files_total = $2 WHERE id = $1")
        .bind(id)
        .bind(files.len() as i32)
        .execute(db)
        .await?;

    let started = Instant::now();
    let (mut scanned, mut failed, mut matched) = (0i32, 0i32, 0i32);
    let mut note = None;
    for (i, (submission, stored)) in files.iter().enumerate() {
        if i % PROGRESS_EVERY == 0 {
            if cancelled(db, id).await {
                return Ok(());
            }
            sqlx::query(
                "UPDATE retrohunt_jobs SET files_scanned = $2, files_failed = $3, matches = $4 WHERE id = $1",
            )
            .bind(id)
            .bind(scanned)
            .bind(failed)
            .bind(matched)
            .execute(db)
            .await?;
        }
        if started.elapsed() > MAX_RUNTIME {
            note = Some(format!(
                "stopped after {} minutes; {} of {} files scanned",
                MAX_RUNTIME.as_secs() / 60,
                scanned + failed,
                files.len()
            ));
            break;
        }
        let Some(path) = crate::queue::consumer::local_upload(stored).filter(|p| p.is_file())
        else {
            failed += 1;
            continue;
        };
        let h = hunter.clone();
        let hits = tokio::task::spawn_blocking(move || h.scan_file(&path)).await?;
        match hits {
            Ok(rules) => {
                scanned += 1;
                if !rules.is_empty() {
                    matched += 1;
                    sqlx::query(
                        "INSERT INTO retrohunt_matches (job_id, submission_id, rules) VALUES ($1, $2, $3) \
                         ON CONFLICT DO NOTHING",
                    )
                    .bind(id)
                    .bind(submission)
                    .bind(&rules)
                    .execute(db)
                    .await?;
                }
            }
            Err(e) => {
                warn!("retrohunt {id}: {submission}: {e}");
                failed += 1;
            }
        }
    }
    sqlx::query(
        "UPDATE retrohunt_jobs SET files_scanned = $2, files_failed = $3, matches = $4 WHERE id = $1",
    )
    .bind(id)
    .bind(scanned)
    .bind(failed)
    .bind(matched)
    .execute(db)
    .await?;
    finish(db, id, "completed", note.as_deref()).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bad_rules_never_reach_the_compiler() {
        let e = compile("include \"/etc/passwd\"\nrule a { condition: true }")
            .err()
            .unwrap();
        assert!(e.contains("include"), "{e}");
        assert!(compile("import \"console\" rule a { condition: true }").is_err());
    }

    #[cfg(feature = "yara-engine")]
    #[test]
    fn rules_compile_and_scan_files() {
        let dir = std::env::temp_dir().join(format!("retrohunt-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let hit = dir.join("hit.bin");
        let miss = dir.join("miss.bin");
        std::fs::write(&hit, b"xx CreateRemoteThread xx").unwrap();
        std::fs::write(&miss, b"nothing to see").unwrap();
        let h = compile(
            r#"import "math"
               rule Inject { strings: $a = "CreateRemoteThread" nocase condition: $a }
               rule Small { condition: filesize < 10 }"#,
        )
        .unwrap();
        assert_eq!(h.scan_file(&hit).unwrap(), vec!["Inject".to_string()]);
        assert!(h.scan_file(&miss).unwrap().is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(feature = "yara-engine")]
    #[test]
    fn the_compiler_refuses_includes_even_without_the_checks() {
        let e = super::engine::compile("include \"/etc/hosts\"\nrule a { condition: true }")
            .err()
            .unwrap();
        assert!(e.starts_with("the rule doesn't compile"), "{e}");
    }

    #[cfg(feature = "yara-engine")]
    #[test]
    fn compile_errors_are_reported() {
        let e = compile("rule a { condition: $missing }").err().unwrap();
        assert!(e.starts_with("the rule doesn't compile"), "{e}");
    }
}
