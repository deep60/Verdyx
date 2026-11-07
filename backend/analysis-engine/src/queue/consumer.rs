use anyhow::{anyhow, Result};
use redis::AsyncCommands;
use sqlx::PgPool;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::analyzers::{AnalysisEngine, AnalysisOptions, FileAnalysisRequest};
use crate::models::analysis_result::without_nul;
use crate::scanners::url_scanner::UrlScanner;
use crate::scanners::url_verdicts::{url_detections, URL_CHECKS};
use crate::scanners::Scanner;
use crate::storage::S3Client;

/// Redis queue key for analysis tasks
const ANALYSIS_QUEUE_KEY: &str = "analysis_queue";
/// Jobs popped but not yet acknowledged. Recovered back onto the queue at startup.
const ANALYSIS_PROCESSING_KEY: &str = "analysis_queue:processing";
/// Messages that cannot be processed (bad payload or exhausted retries).
const ANALYSIS_DEAD_LETTER_KEY: &str = "analysis_queue:dead";
const ANALYSIS_ATTEMPTS_KEY: &str = "analysis_queue:attempts";
const MAX_ATTEMPTS: i32 = 3;

/// WebSocket event channel for real-time updates
const WS_CHANNEL_ANALYSIS_UPDATED: &str = "events:analysis_updated";
const WS_CHANNEL_ANALYSIS_COMPLETED: &str = "events:analysis_completed";

/// Submission record from database
#[derive(Debug, Clone, sqlx::FromRow)]
struct Submission {
    pub id: Uuid,
    pub submitter_id: Option<Uuid>,
    pub file_hash: Option<String>,
    pub url: Option<String>,
    pub original_filename: Option<String>,
    pub file_size: Option<i64>,
    pub mime_type: Option<String>,
    pub file_path: Option<String>,
    pub submission_type: String,
    pub analysis_status: String,
}

/// Start the analysis queue consumer worker
pub async fn start_analysis_worker(
    redis_client: redis::Client,
    db_pool: PgPool,
    s3_client: Arc<S3Client>,
    url_scanner: Arc<UrlScanner>,
    analysis_engine: Arc<Mutex<AnalysisEngine>>,
) -> Result<()> {
    info!("Starting analysis queue consumer worker");

    // Ensure submissions.confidence_score is DOUBLE PRECISION so 0..100 f64 scores never overflow DECIMAL(5,4)
    let _ = sqlx::query(
        "ALTER TABLE submissions ALTER COLUMN confidence_score TYPE DOUBLE PRECISION USING confidence_score::DOUBLE PRECISION",
    )
    .execute(&db_pool)
    .await;

    if let Err(e) = recover_processing(&redis_client).await {
        error!("Failed to recover in-flight analysis jobs: {}", e);
    }

    {
        let (redis_client, db_pool) = (redis_client.clone(), db_pool.clone());
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(STALE_SWEEP_INTERVAL);
            loop {
                ticker.tick().await;
                if let Err(e) = sweep_stale_submissions(&redis_client, &db_pool).await {
                    warn!("Stale scan sweep failed: {}", e);
                }
            }
        });
    }

    loop {
        // Reliable pop: the id stays on the processing list until ack.
        let popped = match pop_from_queue(&redis_client).await {
            Ok(Some(value)) => value,
            Ok(None) => {
                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                continue;
            }
            Err(e) => {
                error!("Failed to pop from queue: {}", e);
                tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                continue;
            }
        };

        let submission_id = match Uuid::parse_str(popped.trim()) {
            Ok(id) => id,
            Err(e) => {
                // Poison payload. Acknowledge it off the processing list so it
                // cannot block later jobs, and keep the raw value for diagnosis.
                error!("Discarding poison queue message: {e}");
                let _ = dead_letter(&redis_client, &popped, "invalid submission id").await;
                continue;
            }
        };

        let _ = drain_artifact_deletions(&redis_client, &s3_client).await;

        info!("Received submission for analysis: {}", submission_id);

        if let Err(e) = process_submission(
            submission_id,
            &redis_client,
            &db_pool,
            &s3_client,
            &url_scanner,
            &analysis_engine,
        )
        .await
        {
            error!("Failed to process submission {}: {}", submission_id, e);
            if let Err(retry_err) =
                nack(&redis_client, &db_pool, submission_id, &e.to_string()).await
            {
                error!(
                    "Failed to record retry for submission {}: {}",
                    submission_id, retry_err
                );
            }
        } else if let Err(ack_err) = ack(&redis_client, submission_id).await {
            error!(
                "Analysis for {} completed but was not acknowledged: {}",
                submission_id, ack_err
            );
        }
    }
}

/// How often unfinished scans are looked for.
const STALE_SWEEP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(600);
/// A scan untouched for this long, and not waiting in the queue, was lost.
const STALE_AFTER_MINUTES: i32 = 30;

/// Finds scans stuck in "pending" or "analyzing": their job was lost (a
/// failed enqueue, or a worker restart that dropped it). Each one is retried
/// through the normal retry path, and after `MAX_ATTEMPTS` it is marked failed
/// with the reason, so nothing stays "pending" forever.
async fn sweep_stale_submissions(redis_client: &redis::Client, db_pool: &PgPool) -> Result<()> {
    let stale: Vec<Uuid> = sqlx::query_scalar(
        r#"
        SELECT id FROM submissions
        WHERE analysis_status IN ('pending', 'analyzing', 'processing')
          AND updated_at < NOW() - make_interval(mins => $1)
        ORDER BY updated_at
        LIMIT 100
        "#,
    )
    .bind(STALE_AFTER_MINUTES)
    .fetch_all(db_pool)
    .await
    .map_err(|e| anyhow!("Failed to find stale submissions: {e}"))?;
    if stale.is_empty() {
        return Ok(());
    }

    let mut conn = redis_client
        .get_multiplexed_async_connection()
        .await
        .map_err(|e| anyhow!("Failed to connect to Redis: {e}"))?;
    for id in stale {
        let key = id.to_string();
        // Still waiting its turn or being worked on: not lost.
        let queued: Option<i64> = redis::cmd("LPOS")
            .arg(ANALYSIS_QUEUE_KEY)
            .arg(&key)
            .query_async(&mut conn)
            .await
            .unwrap_or(None);
        let in_flight: Option<i64> = redis::cmd("LPOS")
            .arg(ANALYSIS_PROCESSING_KEY)
            .arg(&key)
            .query_async(&mut conn)
            .await
            .unwrap_or(None);
        if queued.is_some() || in_flight.is_some() {
            continue;
        }
        warn!("Submission {id} was lost from the queue; retrying it");
        nack(
            redis_client,
            db_pool,
            id,
            &format!("analysis didn't finish within {STALE_AFTER_MINUTES} minutes"),
        )
        .await?;
    }
    Ok(())
}

/// Move jobs left on the processing list by a crashed worker back onto the queue.
async fn recover_processing(redis_client: &redis::Client) -> Result<()> {
    let mut conn = redis_client
        .get_multiplexed_async_connection()
        .await
        .map_err(|e| anyhow!("Failed to connect to Redis: {e}"))?;
    let mut recovered = 0u32;
    loop {
        let value: Option<String> = conn
            .rpoplpush(ANALYSIS_PROCESSING_KEY, ANALYSIS_QUEUE_KEY)
            .await
            .map_err(|e| anyhow!("Failed to recover processing list: {e}"))?;
        if value.is_none() {
            break;
        }
        recovered += 1;
    }
    if recovered > 0 {
        warn!("Requeued {recovered} analysis job(s) left in processing");
    }
    Ok(())
}

/// Blocking pop that also records the job as in-flight.
async fn pop_from_queue(redis_client: &redis::Client) -> Result<Option<String>> {
    let mut conn = redis_client
        .get_multiplexed_async_connection()
        .await
        .map_err(|e| anyhow!("Failed to connect to Redis: {e}"))?;

    let value: Option<String> = conn
        .brpoplpush(ANALYSIS_QUEUE_KEY, ANALYSIS_PROCESSING_KEY, 5.0)
        .await
        .map_err(|e| anyhow!("BRPOPLPUSH failed: {e}"))?;
    Ok(value)
}

async fn ack(redis_client: &redis::Client, submission_id: Uuid) -> Result<()> {
    let mut conn = redis_client
        .get_multiplexed_async_connection()
        .await
        .map_err(|e| anyhow!("Failed to connect to Redis: {e}"))?;
    let id = submission_id.to_string();
    let _: i32 = conn
        .lrem(ANALYSIS_PROCESSING_KEY, 1, &id)
        .await
        .map_err(|e| anyhow!("Failed to acknowledge job: {e}"))?;
    let _: i32 = conn.hdel(ANALYSIS_ATTEMPTS_KEY, &id).await.unwrap_or(0);
    Ok(())
}

/// Retry a failed job up to MAX_ATTEMPTS, then dead-letter it.
/// The processing-list copy is always removed so one failure cannot stall the queue.
async fn nack(
    redis_client: &redis::Client,
    db_pool: &PgPool,
    submission_id: Uuid,
    error: &str,
) -> Result<()> {
    let mut conn = redis_client
        .get_multiplexed_async_connection()
        .await
        .map_err(|e| anyhow!("Failed to connect to Redis: {e}"))?;
    let id = submission_id.to_string();
    let attempts: i32 = conn
        .hincr(ANALYSIS_ATTEMPTS_KEY, &id, 1)
        .await
        .map_err(|e| anyhow!("Failed to record attempt: {e}"))?;
    let _: i32 = conn
        .lrem(ANALYSIS_PROCESSING_KEY, 1, &id)
        .await
        .unwrap_or(0);

    let diagnostic = format!("attempt {attempts}/{MAX_ATTEMPTS}: {error}");
    if attempts >= MAX_ATTEMPTS {
        let _: i32 = conn.lpush(ANALYSIS_DEAD_LETTER_KEY, &id).await.unwrap_or(0);
        record_job_status(db_pool, submission_id, "failed", &diagnostic).await?;
        error!("Dead-lettered submission {id} after {attempts} attempts");
    } else {
        let _: i32 = conn.lpush(ANALYSIS_QUEUE_KEY, &id).await.unwrap_or(0);
        record_job_status(db_pool, submission_id, "analyzing", &diagnostic).await?;
        warn!("Requeued submission {id} ({diagnostic})");
    }
    Ok(())
}

/// Delete object keys queued by explicit account or submission removal.
/// A failed delete is dead-lettered so it cannot block the analysis queue.
async fn drain_artifact_deletions(
    redis_client: &redis::Client,
    s3_client: &S3Client,
) -> Result<()> {
    let mut conn = redis_client
        .get_multiplexed_async_connection()
        .await
        .map_err(|e| anyhow!("Failed to connect to Redis: {e}"))?;
    for _ in 0..20 {
        let key: Option<String> = conn
            .lpop("artifact_deletions", None)
            .await
            .map_err(|e| anyhow!("Failed to pop artifact deletion: {e}"))?;
        let Some(key) = key else { break };
        if let Err(e) = s3_client.delete_file(&key).await {
            warn!("Failed to delete artifact {key}: {e}");
            let _: i32 = conn
                .lpush("artifact_deletions:dead", format!("{e}: {key}"))
                .await
                .unwrap_or(0);
        }
    }
    Ok(())
}

async fn dead_letter(redis_client: &redis::Client, raw: &str, reason: &str) -> Result<()> {
    let mut conn = redis_client
        .get_multiplexed_async_connection()
        .await
        .map_err(|e| anyhow!("Failed to connect to Redis: {e}"))?;
    let _: i32 = conn
        .lrem(ANALYSIS_PROCESSING_KEY, 1, raw)
        .await
        .unwrap_or(0);
    let _: i32 = conn
        .lpush(ANALYSIS_DEAD_LETTER_KEY, format!("{reason}: {raw}"))
        .await
        .unwrap_or(0);
    Ok(())
}

/// Process a single submission
async fn process_submission(
    submission_id: Uuid,
    redis_client: &redis::Client,
    db_pool: &PgPool,
    s3_client: &S3Client,
    url_scanner: &UrlScanner,
    analysis_engine: &Arc<Mutex<AnalysisEngine>>,
) -> Result<()> {
    // Step 2: Fetch submission from database
    let submission = fetch_submission_from_db(db_pool, submission_id).await?;

    info!(
        "Processing submission: id={}, filename={:?}, file_path={:?}",
        submission.id, submission.original_filename, submission.file_path
    );

    // Update status to analyzing
    update_submission_status(db_pool, submission_id, "analyzing").await?;

    // Publish WebSocket event: analysis started
    publish_ws_event(
        redis_client,
        WS_CHANNEL_ANALYSIS_UPDATED,
        &serde_json::json!({
            "submission_id": submission_id.to_string(),
            "status": "analyzing"
        }),
    )
    .await?;

    // Step 3: Load artifact bytes (from disk/S3 for files, or the page for URL
    // submissions). A URL also gets the URL engines: URLhaus, ThreatFox and
    // Verdyx's own URL checks.
    let mut url_votes = Vec::new();
    // Why a URL's page couldn't be loaded, when it couldn't.
    let mut page_error: Option<String> = None;
    let file_data = match submission.file_path.as_deref() {
        Some(fp) if !fp.is_empty() => Some(load_artifact(s3_client, fp).await?),
        _ if submission.submission_type == "url" => {
            let target_url = submission
                .url
                .as_deref()
                .or(submission.original_filename.as_deref())
                .ok_or_else(|| anyhow!("URL submission has no url"))?;
            // The URL engines (URLhaus, ThreatFox, phishing patterns, blocked
            // destinations) don't need the page, so an unreachable page
            // doesn't stop them. Phishing pages are often down or blocked.
            url_votes = url_engine_votes(url_scanner, target_url).await;
            match url_scanner.fetch_page(target_url).await {
                Ok(page) => Some(page),
                Err(e) => {
                    warn!("Could not fetch {target_url}: {e}");
                    page_error = Some(e.to_string());
                    None
                }
            }
        }
        _ => return Err(anyhow!("Submission has no file_path")),
    };

    // Step 4: Run ClamAV + other analyzers on the bytes, when there are any.
    let mut analysis_result = match file_data {
        Some(file_data) => {
            info!(
                "Loaded artifact for analysis: submission_id={}, size={} bytes",
                submission_id,
                file_data.len()
            );
            let filename = submission
                .original_filename
                .clone()
                .or_else(|| submission.url.clone())
                .unwrap_or_else(|| "unknown".to_string());

            let analysis_request = FileAnalysisRequest {
                filename,
                file_data,
                file_hashes: None,
                analysis_options: analysis_options_for(&submission.submission_type),
            };

            let mut engine = analysis_engine.lock().await;
            let result = engine
                .analyze_file(analysis_request)
                .await
                .map_err(|e| anyhow!("Analysis failed: {e}"))?;
            drop(engine); // Release lock
            result
        }
        None => {
            let mut result = crate::models::analysis_result::AnalysisResult {
                submission_id,
                ..Default::default()
            };
            result.mark_completed();
            result
        }
    };

    for vote in url_votes {
        analysis_result.add_detection(vote);
    }
    if let Some(err) = page_error {
        note_unreachable_page(&mut analysis_result, &err);
    }

    info!(
        "Analysis completed for submission {}: status={:?}, detections={}",
        submission_id,
        analysis_result.status,
        analysis_result.detections.len()
    );

    // Step 5: Store results in database
    let (is_malicious, confidence_score) = calculate_verdict(&analysis_result);

    store_analysis_results(
        db_pool,
        submission_id,
        is_malicious,
        confidence_score,
        &analysis_result,
    )
    .await?;

    // Update submission status to completed and clear any retry diagnostic.
    record_job_status(db_pool, submission_id, "completed", "").await?;

    // Publish WebSocket event: analysis completed
    publish_ws_event(
        redis_client,
        WS_CHANNEL_ANALYSIS_COMPLETED,
        &serde_json::json!({
            "submission_id": submission_id.to_string(),
            "status": "completed",
            "is_malicious": is_malicious,
            "confidence_score": confidence_score,
            "detections_count": analysis_result.detections.len()
        }),
    )
    .await?;

    info!(
        "Submission {} processed successfully: is_malicious={}, confidence={}",
        submission_id, is_malicious, confidence_score
    );

    Ok(())
}

/// Engine name for the page itself, shown when it couldn't be loaded.
pub const PAGE_CONTENT: &str = "Page content";

/// Records that a URL's page couldn't be loaded.
///
/// Only the address was checked, so "URL checks found nothing" is not a clean
/// bill of health: that vote becomes "no record" and, unless something else
/// flagged the URL, the result is "no verdict" rather than clean. Findings
/// (phishing patterns, a blocked destination, a feed listing) still count.
fn note_unreachable_page(result: &mut crate::models::analysis_result::AnalysisResult, error: &str) {
    use crate::models::analysis_result::{EngineType, ThreatVerdict};

    for d in result.detections.iter_mut() {
        if d.engine_name == URL_CHECKS && d.verdict == ThreatVerdict::Benign {
            d.verdict = ThreatVerdict::Unknown;
            d.metadata.insert(
                "reason".to_string(),
                serde_json::json!(
                    "The page couldn't be loaded, so only the address was checked. \
                     Nothing was found there, but that doesn't make the site safe."
                ),
            );
        }
    }
    result.add_detection(AnalysisEngine::create_unavailable_detection(
        PAGE_CONTENT,
        "live",
        EngineType::Static,
        format!("The page couldn't be loaded: {error}"),
    ));
}

/// Load the bytes the gateway stored. An absolute path that exists on disk
/// is read directly. Otherwise `file_path` is a storage key for S3 or the
/// local upload directory.
async fn load_artifact(s3_client: &S3Client, file_path: &str) -> Result<Vec<u8>> {
    let path = std::path::Path::new(file_path);
    if path.is_file() {
        return tokio::fs::read(path)
            .await
            .map_err(|e| anyhow!("Failed to read artifact {file_path}: {e}"));
    }
    s3_client
        .download_file(file_path)
        .await
        .map_err(|e| anyhow!("Failed to download artifact {file_path}: {e}"))
}

/// Fetch submission record from database
async fn fetch_submission_from_db(db_pool: &PgPool, submission_id: Uuid) -> Result<Submission> {
    let submission = sqlx::query_as::<_, Submission>(
        r#"
        SELECT id, submitter_id, file_hash, url, original_filename, file_size,
               mime_type, file_path, submission_type, analysis_status
        FROM submissions
        WHERE id = $1
        "#,
    )
    .bind(submission_id)
    .fetch_one(db_pool)
    .await
    .map_err(|e| anyhow!("Failed to fetch submission from database: {e}"))?;

    Ok(submission)
}

/// Update submission status in database
async fn update_submission_status(
    db_pool: &PgPool,
    submission_id: Uuid,
    status: &str,
) -> Result<()> {
    sqlx::query(
        r#"
        UPDATE submissions
        SET analysis_status = $1, updated_at = NOW()
        WHERE id = $2
        "#,
    )
    .bind(status)
    .bind(submission_id)
    .execute(db_pool)
    .await
    .map_err(|e| anyhow!("Failed to update submission status: {e}"))?;

    info!("Updated submission {} status to: {}", submission_id, status);
    Ok(())
}

/// Persist status plus a diagnostic the API can return in `metadata.last_error`.
async fn record_job_status(
    db_pool: &PgPool,
    submission_id: Uuid,
    status: &str,
    diagnostic: &str,
) -> Result<()> {
    sqlx::query(
        r#"
        UPDATE submissions
        SET analysis_status = $1,
            metadata = COALESCE(metadata, '{}'::jsonb) || jsonb_build_object('last_error', $2::text),
            updated_at = NOW()
        WHERE id = $3
        "#,
    )
    .bind(status)
    .bind(diagnostic)
    .bind(submission_id)
    .execute(db_pool)
    .await
    .map_err(|e| anyhow!("Failed to record job status: {e}"))?;
    Ok(())
}

/// Engine metadata plus how the engine took part in the vote, so the report
/// can say "not listed on URLhaus" instead of a blank.
fn detection_metadata(
    detection: &crate::models::analysis_result::DetectionResult,
) -> serde_json::Value {
    let mut meta = serde_json::to_value(&detection.metadata)
        .ok()
        .and_then(|v| v.as_object().cloned())
        .unwrap_or_default();
    meta.insert(
        "engine_type".to_string(),
        serde_json::json!(format!("{:?}", detection.engine_type).to_lowercase()),
    );
    match detection.non_vote() {
        None => {
            meta.insert("vote".to_string(), serde_json::json!("counted"));
        }
        Some((kind, reason)) => {
            meta.insert("vote".to_string(), serde_json::json!(kind));
            meta.insert("reason".to_string(), serde_json::json!(reason));
        }
    }
    serde_json::Value::Object(meta)
}

/// Runs the URL engines. If the URL scan itself fails, "URL checks" is
/// reported as unavailable rather than silently dropped.
async fn url_engine_votes(
    url_scanner: &UrlScanner,
    target_url: &str,
) -> Vec<crate::models::analysis_result::DetectionResult> {
    match url_scanner.scan(target_url.as_bytes(), None).await {
        Ok(scan) => {
            let trusted = url_scanner.is_trusted_domain(&scan.url_info.parsed_url.domain);
            url_detections(&scan, trusted)
        }
        Err(e) => {
            warn!("URL checks failed for {}: {}", target_url, e);
            vec![AnalysisEngine::create_unavailable_detection(
                URL_CHECKS,
                "live",
                crate::models::analysis_result::EngineType::Static,
                e.to_string(),
            )]
        }
    }
}

/// Which file engines read a URL's page.
///
/// - Static and heuristic analysis read program files. Given a web page they
///   flag ordinary minified JavaScript, so a github.com scan drew a
///   "malicious" vote.
/// - Hash reputation looks the page's hash up in malware-file databases. A
///   page is regenerated on every load, so its hash is never there.
/// - The ML model scores executables, so its output on HTML means nothing.
///
/// YARA and the signature matcher still read the HTML, where they can find
/// phishing kits and web shells.
fn analysis_options_for(submission_type: &str) -> AnalysisOptions {
    let is_page = submission_type == "url";
    AnalysisOptions {
        enable_static_analysis: !is_page,
        enable_heuristic_analysis: !is_page,
        enable_hash_analysis: !is_page,
        enable_ml_analysis: !is_page,
        ..AnalysisOptions::default()
    }
}

/// Calculate final verdict from analysis result
fn calculate_verdict(
    analysis_result: &crate::models::analysis_result::AnalysisResult,
) -> (bool, f64) {
    use crate::models::analysis_result::ThreatVerdict;

    let is_malicious = analysis_result.consensus_verdict == ThreatVerdict::Malicious;
    let confidence = analysis_result.agreement_score as f64;
    (is_malicious, confidence)
}

/// Inserts one engine's row into `analysis_results`.
async fn insert_detection_row(
    db_pool: &PgPool,
    submission_id: Uuid,
    detection: &crate::models::analysis_result::DetectionResult,
    metadata: serde_json::Value,
) -> Result<(), sqlx::Error> {
    let conf_f64 = detection.confidence as f64;
    sqlx::query(
        r#"
        INSERT INTO analysis_results (
            id, submission_id, engine_name, engine_version,
            verdict, confidence, confidence_score, severity, categories,
            metadata, analysis_status, detected_at, processing_time_ms
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 'completed', $11, $12)
        "#,
    )
    .bind(detection.detection_id)
    .bind(submission_id)
    .bind(detection.engine_name.replace('\0', ""))
    .bind(detection.engine_version.replace('\0', ""))
    .bind(format!("{:?}", detection.verdict).to_lowercase())
    .bind(conf_f64)
    .bind(conf_f64)
    .bind(format!("{:?}", detection.severity))
    .bind(serde_json::to_value(&detection.categories).unwrap_or_default())
    .bind(metadata)
    .bind(detection.detected_at)
    .bind(detection.processing_time_ms as i64)
    .execute(db_pool)
    .await
    .map(|_| ())
}

/// Store analysis results in database
async fn store_analysis_results(
    db_pool: &PgPool,
    submission_id: Uuid,
    is_malicious: bool,
    confidence_score: f64,
    analysis_result: &crate::models::analysis_result::AnalysisResult,
) -> Result<()> {
    let consensus_meta = without_nul(serde_json::json!({
        "consensus_verdict": format!("{:?}", analysis_result.consensus_verdict).to_lowercase(),
        "consensus_explanation": analysis_result.consensus_explanation,
        "agreement_score": analysis_result.agreement_score,
        "participating_engines": analysis_result.participating_engines,
        "unavailable_engines": analysis_result.unavailable_engines,
        "vote_distribution": analysis_result.vote_distribution,
        "verdict_history": analysis_result.verdict_history,
    }));

    // Update submission with final results and explainability metadata
    sqlx::query(
        r#"
        UPDATE submissions
        SET
            is_malicious = $1,
            confidence_score = $2,
            metadata = COALESCE(metadata, '{}'::jsonb) || $3::jsonb,
            updated_at = NOW()
        WHERE id = $4
        "#,
    )
    .bind(is_malicious)
    .bind(confidence_score)
    .bind(consensus_meta)
    .bind(submission_id)
    .execute(db_pool)
    .await
    .map_err(|e| anyhow!("Failed to store analysis results: {e}"))?;

    // Replace any detections from a previous attempt so a retry cannot
    // insert a second set of result rows for the same submission.
    let _ = sqlx::query("DELETE FROM analysis_results WHERE submission_id = $1")
        .bind(submission_id)
        .execute(db_pool)
        .await;

    // Store individual detection results in analysis_results table. Every
    // engine counted in the verdict must get a row, or the report shows a
    // verdict built from engines it doesn't list.
    for detection in analysis_result
        .detections
        .iter()
        .filter(|d| !d.is_aggregate())
    {
        let detection_meta = without_nul(detection_metadata(detection));
        if let Err(e) =
            insert_detection_row(db_pool, submission_id, detection, detection_meta).await
        {
            error!(
                "Failed to store {} result for submission {}: {}; storing it without evidence",
                detection.engine_name, submission_id, e
            );
            // Keep the engine and its vote visible even if its evidence can't
            // be stored.
            let mut fallback = detection_metadata(detection)
                .as_object()
                .map(|m| {
                    m.iter()
                        .filter(|(k, _)| matches!(k.as_str(), "engine_type" | "vote" | "reason"))
                        .map(|(k, v)| (k.clone(), v.clone()))
                        .collect::<serde_json::Map<_, _>>()
                })
                .unwrap_or_default();
            fallback.insert(
                "evidence_unavailable".to_string(),
                serde_json::json!("The engine's details could not be saved."),
            );
            let fallback = without_nul(serde_json::Value::Object(fallback));
            if let Err(e) = insert_detection_row(db_pool, submission_id, detection, fallback).await
            {
                error!(
                    "Failed to store {} result for submission {} even without evidence: {}",
                    detection.engine_name, submission_id, e
                );
            }
        }
    }

    info!(
        "Stored analysis results for submission {}: malicious={}, confidence={}",
        submission_id, is_malicious, confidence_score
    );

    Ok(())
}

/// Publish WebSocket event to Redis Pub/Sub
async fn publish_ws_event(
    redis_client: &redis::Client,
    channel: &str,
    payload: &serde_json::Value,
) -> Result<()> {
    let mut conn = redis_client
        .get_multiplexed_async_connection()
        .await
        .map_err(|e| anyhow!("Failed to connect to Redis: {e}"))?;

    let message = serde_json::to_string(payload)
        .map_err(|e| anyhow!("Failed to serialize WebSocket event: {e}"))?;

    conn.publish::<_, _, ()>(channel, message)
        .await
        .map_err(|e| anyhow!("Failed to publish WebSocket event: {e}"))?;

    info!("Published WebSocket event to channel: {}", channel);
    Ok(())
}

#[cfg(test)]
mod analysis_options_tests {
    use super::{analysis_options_for, detection_metadata};
    use crate::models::analysis_result::{
        DetectionResult, EngineType, SeverityLevel, ThreatVerdict,
    };

    #[test]
    fn stored_metadata_says_how_the_engine_voted() {
        let mut d = DetectionResult {
            detection_id: uuid::Uuid::new_v4(),
            engine_name: "URLhaus".to_string(),
            engine_version: "live".to_string(),
            engine_type: EngineType::Hash,
            verdict: ThreatVerdict::Unknown,
            confidence: 0.0,
            severity: SeverityLevel::Info,
            categories: vec![],
            metadata: [(
                "reason".to_string(),
                serde_json::json!("Not listed on URLhaus"),
            )]
            .into(),
            detected_at: chrono::Utc::now(),
            processing_time_ms: 1,
            error_message: None,
        };
        let meta = detection_metadata(&d);
        assert_eq!(meta["vote"], "no_record");
        assert_eq!(meta["reason"], "Not listed on URLhaus");
        assert_eq!(meta["engine_type"], "hash");

        d.verdict = ThreatVerdict::Benign;
        d.metadata.clear();
        assert_eq!(detection_metadata(&d)["vote"], "counted");
    }

    #[test]
    fn web_pages_skip_analyzers_built_for_program_files() {
        let options = analysis_options_for("url");
        assert!(!options.enable_static_analysis);
        assert!(!options.enable_heuristic_analysis);
        assert!(options.enable_signature_analysis);
        // A page's hash is never in a malware-file database, and the ML
        // model scores executables.
        assert!(!options.enable_hash_analysis);
        assert!(!options.enable_ml_analysis);
    }

    #[test]
    fn files_run_every_analyzer() {
        let options = analysis_options_for("file");
        assert!(options.enable_static_analysis);
        assert!(options.enable_heuristic_analysis);
    }
}

#[cfg(test)]
mod unreachable_page_tests {
    use super::{note_unreachable_page, PAGE_CONTENT};
    use crate::models::analysis_result::{
        AnalysisResult, DetectionResult, EngineType, SeverityLevel, ThreatVerdict,
    };
    use crate::scanners::url_verdicts::{URLHAUS, URL_CHECKS};

    fn det(name: &str, verdict: ThreatVerdict, reason: Option<&str>) -> DetectionResult {
        DetectionResult {
            detection_id: uuid::Uuid::new_v4(),
            engine_name: name.to_string(),
            engine_version: "live".to_string(),
            engine_type: EngineType::Static,
            verdict,
            confidence: 0.6,
            severity: SeverityLevel::Info,
            categories: vec![],
            metadata: reason
                .map(|r| [("reason".to_string(), serde_json::json!(r))].into())
                .unwrap_or_default(),
            detected_at: chrono::Utc::now(),
            processing_time_ms: 1,
            error_message: None,
        }
    }

    #[test]
    fn an_unreachable_page_with_no_findings_has_no_verdict_not_clean() {
        let mut r = AnalysisResult::default();
        r.add_detection(det(
            URLHAUS,
            ThreatVerdict::Unknown,
            Some("Not listed on URLhaus"),
        ));
        r.add_detection(det(URL_CHECKS, ThreatVerdict::Benign, None));
        note_unreachable_page(&mut r, "connection timed out");
        assert_eq!(r.consensus_verdict, ThreatVerdict::Unknown);
        assert!(r
            .unavailable_engines
            .iter()
            .any(|u| u.engine_name == PAGE_CONTENT && u.reason.contains("connection timed out")));
    }

    #[test]
    fn findings_on_the_address_still_count_when_the_page_is_down() {
        // A phishing-looking address on a host that can't be reached.
        let mut r = AnalysisResult::default();
        r.add_detection(det(URL_CHECKS, ThreatVerdict::Suspicious, None));
        note_unreachable_page(&mut r, "blocked destination");
        assert_eq!(r.consensus_verdict, ThreatVerdict::Suspicious);
    }
}
