use anyhow::{anyhow, Result};
use redis::AsyncCommands;
use sqlx::PgPool;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::analyzers::{AnalysisEngine, AnalysisOptions, FileAnalysisRequest};
use crate::scanners::url_scanner::UrlScanner;
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

    // Step 3: Load artifact bytes (from disk/S3 for files, or the page for URL submissions)
    let file_data = match submission.file_path.as_deref() {
        Some(fp) if !fp.is_empty() => load_artifact(s3_client, fp).await?,
        _ if submission.submission_type == "url" => {
            let target_url = submission
                .url
                .as_deref()
                .or(submission.original_filename.as_deref())
                .ok_or_else(|| anyhow!("URL submission has no url"))?;
            // A failed fetch must fail the job: scanning only the URL's text
            // would report every unreachable page as clean.
            url_scanner
                .fetch_page(target_url)
                .await
                .map_err(|e| anyhow!("Could not fetch {target_url}: {e}"))?
        }
        _ => return Err(anyhow!("Submission has no file_path")),
    };

    info!(
        "Loaded artifact for analysis: submission_id={}, size={} bytes",
        submission_id,
        file_data.len()
    );

    // Step 4: Run ClamAV + other analyzers
    let filename = submission
        .original_filename
        .clone()
        .or_else(|| submission.url.clone())
        .unwrap_or_else(|| "unknown".to_string());

    let analysis_request = FileAnalysisRequest {
        filename: filename.clone(),
        file_data,
        file_hashes: None,
        analysis_options: analysis_options_for(&submission.submission_type),
    };

    let mut engine = analysis_engine.lock().await;
    let analysis_result = engine
        .analyze_file(analysis_request)
        .await
        .map_err(|e| anyhow!("Analysis failed: {e}"))?;

    drop(engine); // Release lock

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

/// The static and heuristic analyzers read program files. Given a web page they
/// flag ordinary minified JavaScript, so a github.com scan drew a "malicious" vote.
fn analysis_options_for(submission_type: &str) -> AnalysisOptions {
    let is_page = submission_type == "url";
    AnalysisOptions {
        enable_static_analysis: !is_page,
        enable_heuristic_analysis: !is_page,
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

/// Store analysis results in database
async fn store_analysis_results(
    db_pool: &PgPool,
    submission_id: Uuid,
    is_malicious: bool,
    confidence_score: f64,
    analysis_result: &crate::models::analysis_result::AnalysisResult,
) -> Result<()> {
    let consensus_meta = serde_json::json!({
        "consensus_explanation": analysis_result.consensus_explanation,
        "agreement_score": analysis_result.agreement_score,
        "participating_engines": analysis_result.participating_engines,
        "unavailable_engines": analysis_result.unavailable_engines,
        "vote_distribution": analysis_result.vote_distribution,
        "verdict_history": analysis_result.verdict_history,
    });

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

    // Store individual detection results in analysis_results table
    for detection in &analysis_result.detections {
        let detection_meta = serde_json::to_value(&detection.metadata).unwrap_or_default();
        let verdict_lower = format!("{:?}", detection.verdict).to_lowercase();
        let conf_f64 = detection.confidence as f64;
        if let Err(e) = sqlx::query(
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
        .bind(&detection.engine_name)
        .bind(&detection.engine_version)
        .bind(&verdict_lower)
        .bind(conf_f64)
        .bind(conf_f64)
        .bind(format!("{:?}", detection.severity))
        .bind(serde_json::to_value(&detection.categories).unwrap_or_default())
        .bind(detection_meta)
        .bind(detection.detected_at)
        .bind(detection.processing_time_ms as i64)
        .execute(db_pool)
        .await
        {
            warn!(
                "Failed to store detection result for submission {}: {}",
                submission_id, e
            );
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
    use super::analysis_options_for;

    #[test]
    fn web_pages_skip_analyzers_built_for_program_files() {
        let options = analysis_options_for("url");
        assert!(!options.enable_static_analysis);
        assert!(!options.enable_heuristic_analysis);
        assert!(options.enable_signature_analysis);
        assert!(options.enable_ml_analysis);
    }

    #[test]
    fn files_run_every_analyzer() {
        let options = analysis_options_for("file");
        assert!(options.enable_static_analysis);
        assert!(options.enable_heuristic_analysis);
    }
}
