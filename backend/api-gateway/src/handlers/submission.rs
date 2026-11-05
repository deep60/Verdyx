use axum::{
    extract::{DefaultBodyLimit, Multipart, Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::Json,
    routing::{delete, get, post, put},
    Router,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::fs;
use tokio::io::AsyncWriteExt;
use uuid::Uuid;

use crate::utils::{crypto::calculate_file_hash, validation::FileValidator};

// Request/Response DTOs
#[derive(Deserialize, Clone, Serialize)]
pub struct CreateSubmissionRequest {
    pub bounty_id: Uuid,
    pub engine_name: String,
    pub engine_version: String,
    pub verdict: String, // "malicious", "benign", "suspicious"
    pub confidence: f32, // 0.0-1.0
    pub threat_types: Vec<String>,
    pub risk_score: u8, // 0-100
    pub analysis_summary: String,
    pub technical_details: serde_json::Value,
    pub stake_amount: u64,
    pub signatures: Vec<String>, // YARA rules, hashes, etc.
}

/// Request DTO for the user-facing file submission form.
/// This maps to the `submissions` table (not `bounty_submissions`).
#[derive(Deserialize, Clone, Serialize)]
pub struct CreateFileSubmissionRequest {
    pub filename: Option<String>,
    #[serde(rename = "originalFilename")]
    pub original_filename: Option<String>,
    #[serde(rename = "submissionType")]
    pub submission_type: String, // "file" | "url"
    pub description: Option<String>,
    #[serde(rename = "fileHash")]
    pub file_hash: Option<String>,
    #[serde(rename = "fileSize")]
    pub file_size: Option<i64>,
    #[serde(rename = "analysisType")]
    pub analysis_type: Option<String>, // "full", "quick", "deep", "behavioral"
    #[serde(rename = "bountyAmount")]
    pub bounty_amount: Option<String>, // ETH amount as string
    pub priority: Option<bool>,
}

#[derive(Serialize)]
pub struct FileSubmissionResponse {
    pub id: Uuid,
    pub submitter_id: Uuid,
    pub original_filename: Option<String>,
    pub file_hash: Option<String>,
    pub file_size: Option<i64>,
    pub submission_type: String,
    pub analysis_status: String,
    pub description: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// One row of `GET /api/v1/submissions`.
///
/// Serialized camelCase and returned as a FLAT ARRAY because that is what the
/// client already expects: `marketplace.tsx` declares
/// `useQuery<ApiSubmission[]>({ queryKey: ["/api/submissions"] })` and the
/// default fetcher in `queryClient.ts` does no unwrapping, so an envelope
/// object would arrive where an array is required.
///
/// `analysisType`, `bountyAmount` and `priority` live inside the row's
/// `metadata` JSON (that is how `create_file_submission` writes them), so they
/// are lifted back out here rather than exposing the raw blob.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FileSubmissionListItem {
    pub id: Uuid,
    pub submitter_id: Uuid,
    pub user_id: Uuid,
    pub original_filename: Option<String>,
    pub filename: Option<String>,
    pub file_name: Option<String>,
    pub file_hash: Option<String>,
    pub url: Option<String>,
    pub file_size: Option<i64>,
    pub mime_type: Option<String>,
    pub submission_type: String,
    pub analysis_status: String,
    /// Duplicate of `analysis_status`. `ApiSubmission` reads `status` in some
    /// places and `analysisStatus` in others; emitting both keeps every
    /// existing call site working without touching the client.
    pub status: String,
    pub is_malicious: Option<bool>,
    pub description: Option<String>,
    pub analysis_type: Option<String>,
    pub bounty_amount: Option<String>,
    pub priority: Option<bool>,
    /// Bounty opened for this upload, when one exists. Commit-reveal and
    /// disputes are keyed by this id, not by the submission id.
    pub bounty_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
}

#[derive(Deserialize)]
pub struct UpdateSubmissionRequest {
    pub analysis_summary: Option<String>,
    pub technical_details: Option<serde_json::Value>,
    pub additional_signatures: Option<Vec<String>>,
}

#[derive(Deserialize, Serialize)]
pub struct SubmissionFilters {
    pub bounty_id: Option<Uuid>,
    pub engine_id: Option<String>,
    pub verdict: Option<String>,
    pub min_confidence: Option<f32>,
    pub max_confidence: Option<f32>,
    pub status: Option<String>,
    pub date_from: Option<DateTime<Utc>>,
    pub date_to: Option<DateTime<Utc>>,
    pub page: Option<u32>,
    pub limit: Option<u32>,
    /// `bounties` lists every scan carrying a bounty; otherwise only the caller's own.
    pub scope: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct SubmissionResponse {
    pub id: Uuid,
    pub bounty_id: Uuid,
    pub engine_id: String,
    pub engine_name: String,
    pub engine_version: String,
    pub verdict: String,
    pub confidence: f32,
    pub threat_types: Vec<String>,
    pub risk_score: u8,
    pub analysis_summary: String,
    pub stake_amount: u64,
    pub submitted_at: DateTime<Utc>,
    pub updated_at: Option<DateTime<Utc>>,
    pub status: SubmissionStatus,
    pub is_winner: Option<bool>,
    pub reward_earned: Option<u64>,
    pub reputation_change: Option<i32>,
}

#[derive(Serialize, Deserialize)]
pub struct DetailedSubmissionResponse {
    pub submission: SubmissionResponse,
    pub technical_details: serde_json::Value,
    pub signatures: Vec<String>,
    pub analysis_metrics: AnalysisMetrics,
    pub file_info: Option<FileInfo>,
}

#[derive(Serialize)]
pub struct SubmissionListResponse {
    pub submissions: Vec<SubmissionResponse>,
    pub total_count: u32,
    pub page: u32,
    pub limit: u32,
    pub filters_applied: SubmissionFilters,
}

#[derive(Serialize)]
pub struct FileUploadResponse {
    pub file_id: Uuid,
    pub file_hash: String,
    pub file_size: u64,
    pub file_type: String,
    pub upload_timestamp: DateTime<Utc>,
    pub analysis_status: String,
}

#[derive(Serialize)]
pub struct BulkSubmissionResponse {
    pub successful: Vec<SubmissionResponse>,
    pub failed: Vec<SubmissionError>,
    pub total_processed: u32,
}

#[derive(Serialize)]
pub struct SubmissionError {
    pub index: u32,
    pub error: String,
    pub request_data: serde_json::Value,
}

#[derive(Serialize, Deserialize)]
pub struct AnalysisMetrics {
    pub processing_time_ms: u64,
    pub signatures_matched: u32,
    pub false_positive_rate: Option<f32>,
    pub detection_accuracy: Option<f32>,
    pub resource_usage: ResourceUsage,
}

#[derive(Serialize, Deserialize)]
pub struct ResourceUsage {
    pub cpu_time_ms: u64,
    pub memory_usage_mb: u64,
    pub disk_io_mb: u64,
}

#[derive(Serialize, Deserialize)]
pub struct FileInfo {
    pub hash: String,
    pub size: u64,
    pub file_type: String,
    pub mime_type: String,
    pub upload_timestamp: DateTime<Utc>,
    pub scan_count: u32,
    pub last_analysis: Option<DateTime<Utc>>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum SubmissionStatus {
    Pending,
    Processing,
    Completed,
    Failed,
    Disputed,
    Verified,
}

// Application state
use crate::AppState;

// Handler Implementation
pub async fn upload_file(
    State(state): State<AppState>,
    headers: HeaderMap,
    claims: crate::middleware::auth::Claims,
    mut multipart: Multipart,
) -> Result<Json<FileUploadResponse>, StatusCode> {
    // Check content length
    if let Some(content_length) = headers.get("content-length") {
        if let Ok(size) = content_length.to_str().unwrap_or("0").parse::<u64>() {
            if size > state.config.max_file_size_bytes() as u64 {
                return Err(StatusCode::PAYLOAD_TOO_LARGE);
            }
        }
    }

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|_| StatusCode::BAD_REQUEST)?
    {
        let name = field.name().unwrap_or("").to_string();

        if name == "file" {
            let filename = field.file_name().map(|s| s.to_string());
            let _content_type = field.content_type().map(|s| s.to_string());
            let data = field.bytes().await.map_err(|_| StatusCode::BAD_REQUEST)?;

            // validate file type
            if let Some(ref fname) = filename {
                let allowed_types = &[
                    "exe", "dll", "pdf", "doc", "docx", "zip", "rar", "7z", "tar", "gz", "bin",
                    "apk", "ipa", "msi", "dmg",
                ];
                if FileValidator::validate_file_type(fname, allowed_types).is_err() {
                    return Err(StatusCode::UNSUPPORTED_MEDIA_TYPE);
                }
            }

            // Calculate file hash
            let file_hash = calculate_file_hash(&data);
            let file_id = Uuid::new_v4();

            // save file to disk
            let file_path = format!("{}/{}", state.config.services.upload_path, file_hash);
            // Ensure directory exists
            if let Some(parent) = std::path::Path::new(&file_path).parent() {
                fs::create_dir_all(parent)
                    .await
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            }

            let mut file = fs::File::create(&file_path)
                .await
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            file.write_all(&data)
                .await
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

            // Store file metadata in the database
            // The file_metadata table stores upload artifacts independently of analysis results.
            let upload_timestamp = Utc::now();
            let file_type_str = detect_file_type(&data);

            if let Err(e) = sqlx::query(
                r#"
                INSERT INTO file_metadata (id, file_hash, original_filename, file_size, mime_type, file_path, uploaded_at)
                VALUES ($1, $2, $3, $4, $5, $6, $7)
                ON CONFLICT (file_hash) DO UPDATE SET file_path = $6, uploaded_at = $7
                "#
            )
            .bind(file_id)
            .bind(&file_hash)
            .bind(&filename)
            .bind(data.len() as i64)
            .bind(&file_type_str)
            .bind(&file_path)
            .bind(upload_timestamp)
            .execute(state.db.pool())
            .await
            {
                tracing::warn!("Failed to store file metadata: {} — proceeding without persistence", e);
            }

            // The worker reads submission ids from the list `analysis_queue`
            // and loads `submissions.file_path`. A bare file id is not a job.
            let submission_id = Uuid::new_v4();
            let now = Utc::now();
            sqlx::query(
                r#"
                INSERT INTO submissions (
                    id, submitter_id, original_filename, file_hash, file_size,
                    mime_type, file_path, submission_type, analysis_status,
                    created_at, updated_at
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, 'file', 'pending', $8, $8)
                "#,
            )
            .bind(submission_id)
            .bind(claims.sub)
            .bind(&filename)
            .bind(&file_hash)
            .bind(data.len() as i64)
            .bind(&file_type_str)
            .bind(&file_path)
            .bind(now)
            .execute(state.db.pool())
            .await
            .map_err(|e| {
                tracing::error!("Failed to insert submission for upload: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

            if let Err(e) = state.redis.queue_for_analysis(submission_id, 1).await {
                tracing::error!("Failed to enqueue submission {}: {}", submission_id, e);
                return Err(StatusCode::INTERNAL_SERVER_ERROR);
            }
            tracing::info!(submission_id = %submission_id, file_path = %file_path, "Queued submission for analysis");

            return Ok(Json(FileUploadResponse {
                file_id,
                file_hash,
                file_size: data.len() as u64,
                file_type: detect_file_type(&data),
                upload_timestamp,
                analysis_status: "queued".to_string(),
            }));
        }
    }

    Err(StatusCode::BAD_REQUEST)
}

pub async fn create_submission(
    State(state): State<AppState>,
    claims: crate::middleware::auth::Claims,
    Json(request): Json<CreateSubmissionRequest>,
) -> Result<Json<SubmissionResponse>, StatusCode> {
    // Resolve the submitter's on-chain wallet address from their user record.
    // Falls back to the zero address only if the account has no wallet linked
    // (staking/payout for such submissions will fail on-chain, as expected).
    let engine_address = match state.db.get_user_by_id(claims.sub).await {
        Ok(Some(user)) => user
            .wallet_address
            .unwrap_or_else(|| "0x0000000000000000000000000000000000000000".to_string()),
        Ok(None) => "0x0000000000000000000000000000000000000000".to_string(),
        Err(e) => {
            tracing::error!("Failed to look up submitter wallet: {}", e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    // Construct BountySubmission
    let submission_id = Uuid::new_v4();
    let submission = crate::models::bounty::BountySubmission {
        id: submission_id,
        bounty_id: request.bounty_id,
        engine_id: claims.sub, // Authenticated user as the engine submitter
        engine_name: request.engine_name.clone(),
        engine_address,
        verdict: request.verdict.clone(),
        confidence: request.confidence as f64,
        details: request.technical_details.clone(),
        stake_amount: request.stake_amount.to_string(),
        submitted_at: Utc::now(),
        is_verified: false,
    };

    // Ideally we'd use a transaction here
    state
        .db
        .create_extended_submission(&submission)
        .await
        .map_err(|e| {
            tracing::error!("Failed to create submission: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    // Mirror the staked verdict into consensus-service. This is the vote that
    // carries a stake, so it is the one consensus most needs; like the analyst
    // vote path it is non-fatal, because the submission is already committed
    // and must not be lost to a downstream outage.
    forward_submission_to_consensus(&state, &submission).await;

    // Return response
    Ok(Json(SubmissionResponse {
        id: submission.id,
        bounty_id: submission.bounty_id,
        engine_id: submission.engine_id.to_string(),
        engine_name: submission.engine_name,
        engine_version: request.engine_version,
        verdict: submission.verdict,
        confidence: submission.confidence as f32,
        threat_types: request.threat_types,
        risk_score: request.risk_score,
        analysis_summary: request.analysis_summary,
        stake_amount: request.stake_amount,
        submitted_at: submission.submitted_at,
        updated_at: None,
        status: SubmissionStatus::Processing, // Map from internal status
        is_winner: None,
        reward_earned: None,
        reputation_change: None,
    }))
}

/// Mirror a staked engine/analyst verdict into consensus-service.
///
/// Failures are logged, never propagated: the submission row is already
/// committed, and losing it because consensus-service is briefly unreachable
/// would be worse than a bounty that scores late.
async fn forward_submission_to_consensus(
    state: &AppState,
    submission: &crate::models::bounty::BountySubmission,
) {
    use crate::services::consensus_client::{forward_vote, resolve_verdict, ForwardedVote};

    // A staked verdict is already absolute; run it through the same resolver
    // so anything outside the known vocabulary is rejected rather than
    // forwarded as a verdict consensus cannot interpret.
    let Some(resolved) = resolve_verdict(&submission.verdict, None) else {
        tracing::warn!(
            "Submission {} has verdict '{}', which is not an absolute verdict; not forwarded",
            submission.id,
            submission.verdict
        );
        return;
    };

    let sample_hash: Option<String> = match sqlx::query_scalar(
        r#"
        SELECT s.file_hash
        FROM bounties b
        JOIN submissions s ON s.id = b.submission_id
        WHERE b.id = $1
        "#,
    )
    .bind(submission.bounty_id)
    .fetch_optional(state.db.pool())
    .await
    {
        Ok(h) => h.flatten(),
        Err(e) => {
            tracing::error!(
                "Could not resolve sample hash for bounty {}: {}",
                submission.bounty_id,
                e
            );
            None
        }
    };

    let reputation_score: i32 =
        match sqlx::query_scalar("SELECT reputation_score FROM users WHERE id = $1")
            .bind(submission.engine_id)
            .fetch_optional(state.db.pool())
            .await
        {
            Ok(r) => r.flatten().unwrap_or(0),
            Err(e) => {
                tracing::warn!(
                    "Could not read reputation for {}: {}; forwarding with 0",
                    submission.engine_id,
                    e
                );
                0
            }
        };

    let recorded = forward_vote(&ForwardedVote {
        bounty_id: submission.bounty_id,
        voter_id: submission.engine_id,
        verdict: resolved,
        confidence: submission.confidence,
        reputation_score,
        sample_hash,
    })
    .await;

    if !recorded {
        tracing::error!(
            "Staked verdict on submission {} did not reach consensus-service; bounty {} may score without it",
            submission.id,
            submission.bounty_id
        );
    }
}

pub async fn get_submissions(
    State(state): State<AppState>,
    Query(filters): Query<SubmissionFilters>,
) -> Result<Json<SubmissionListResponse>, StatusCode> {
    let page = filters.page.unwrap_or(1).max(1);
    let limit = filters.limit.unwrap_or(20).clamp(1, 100);

    let (submissions, total) = state
        .db
        .get_submissions_with_filters(&filters, page, limit)
        .await
        .map_err(|e| {
            tracing::error!("Failed to fetch submissions: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    // Map internal submissions to response DTOs
    let response_items: Vec<SubmissionResponse> = submissions
        .into_iter()
        .map(|s| {
            SubmissionResponse {
                id: s.id,
                bounty_id: s.bounty_id,
                engine_id: s.engine_id.to_string(),
                engine_name: s.engine_name,
                engine_version: "1.0".to_string(),
                verdict: s.verdict,
                confidence: s.confidence as f32,
                threat_types: vec![],
                risk_score: 0,
                analysis_summary: "".to_string(),
                stake_amount: s.stake_amount.parse().unwrap_or(0),
                submitted_at: s.submitted_at,
                updated_at: None,
                status: SubmissionStatus::Completed, // Default status as BountySubmission doesn't have it
                is_winner: None,
                reward_earned: None,
                reputation_change: None,
            }
        })
        .collect();

    Ok(Json(SubmissionListResponse {
        submissions: response_items,
        total_count: total,
        page,
        limit,
        filters_applied: filters,
    }))
}

pub async fn get_submission_details(
    State(state): State<AppState>,
    Path(submission_id): Path<Uuid>,
) -> Result<Json<DetailedSubmissionResponse>, StatusCode> {
    // Try cache first
    if let Ok(Some(cached)) = state
        .redis
        .get_cached_detailed_submission(submission_id)
        .await
    {
        return Ok(Json(cached));
    }

    match state.db.get_extended_submission_by_id(submission_id).await {
        Ok(Some(extended_sub)) => {
            let analysis_metrics = AnalysisMetrics {
                processing_time_ms: extended_sub
                    .processing_metrics
                    .as_ref()
                    .map(|m| m.processing_time_ms)
                    .unwrap_or(0),
                signatures_matched: extended_sub.signatures.len() as u32,
                false_positive_rate: None, // Requires historical accuracy tracking across bounties
                detection_accuracy: None,  // Requires ground-truth labeling pipeline
                resource_usage: ResourceUsage {
                    cpu_time_ms: extended_sub
                        .processing_metrics
                        .as_ref()
                        .map(|m| m.processing_time_ms)
                        .unwrap_or(0),
                    memory_usage_mb: 0, // Not yet captured in ProcessingMetrics
                    disk_io_mb: 0,      // Not yet captured in ProcessingMetrics
                },
            };

            // Get file info if available
            let file_info = if let Ok(Some(_bounty)) = state
                .db
                .get_bounty_by_id(extended_sub.submission.bounty_id)
                .await
            {
                // file_hash is not in Bounty struct, assuming it's in metadata or we skip this check
                // For now, let's skip file info retrieval if hash is missing
                None
            } else {
                None
            };

            let submission_response = SubmissionResponse {
                id: extended_sub.submission.id,
                bounty_id: extended_sub.submission.bounty_id,
                engine_id: extended_sub.submission.engine_id.to_string(),
                engine_name: extended_sub.engine_name,
                engine_version: extended_sub.engine_version,
                verdict: extended_sub.submission.verdict.to_string(),
                confidence: extended_sub.submission.confidence as f32,
                threat_types: extended_sub.threat_types,
                risk_score: extended_sub.risk_score,
                analysis_summary: extended_sub.analysis_summary,
                stake_amount: extended_sub.submission.stake_amount.parse().unwrap_or(0),
                submitted_at: extended_sub.submission.submitted_at,
                updated_at: None,
                status: extended_sub.status,
                is_winner: None, // Not in BountySubmission
                reward_earned: None,
                reputation_change: None,
            };

            let response = DetailedSubmissionResponse {
                submission: submission_response,
                technical_details: extended_sub.submission.details,
                signatures: extended_sub.signatures,
                analysis_metrics,
                file_info,
            };

            // Cache the response
            let _ = state
                .redis
                .cache_detailed_submission(submission_id, &response)
                .await;

            Ok(Json(response))
        }
        Ok(None) => Err(StatusCode::NOT_FOUND),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

pub async fn update_submission(
    State(state): State<AppState>,
    claims: crate::middleware::auth::Claims,
    Path(submission_id): Path<Uuid>,
    Json(request): Json<UpdateSubmissionRequest>,
) -> Result<Json<SubmissionResponse>, StatusCode> {
    // Verify the caller owns this submission
    let existing = state
        .db
        .get_extended_submission_by_id(submission_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;
    if existing.submission.engine_id != claims.sub {
        tracing::warn!(
            "User {} denied update on submission {} (owner: {})",
            claims.sub,
            submission_id,
            existing.submission.engine_id
        );
        return Err(StatusCode::FORBIDDEN);
    }

    match state.db.update_submission(submission_id, &request).await {
        Ok(updated_submission) => {
            // Invalidate cache
            let _ = state.redis.invalidate_submission_cache(submission_id).await;

            let response = SubmissionResponse {
                id: updated_submission.submission.id,
                bounty_id: updated_submission.submission.bounty_id,
                engine_id: updated_submission.submission.engine_id.to_string(),
                engine_name: updated_submission.engine_name,
                engine_version: updated_submission.engine_version,
                verdict: updated_submission.submission.verdict.to_string(),
                confidence: updated_submission.submission.confidence as f32,
                threat_types: updated_submission.threat_types,
                risk_score: updated_submission.risk_score,
                analysis_summary: updated_submission.analysis_summary,
                stake_amount: updated_submission
                    .submission
                    .stake_amount
                    .parse()
                    .unwrap_or(0),
                submitted_at: updated_submission.submission.submitted_at,
                updated_at: Some(Utc::now()),
                status: updated_submission.status,
                is_winner: None,
                reward_earned: None,
                reputation_change: None,
            };

            Ok(Json(response))
        }
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

pub async fn delete_submission(
    State(state): State<AppState>,
    claims: crate::middleware::auth::Claims,
    Path(submission_id): Path<Uuid>,
) -> Result<StatusCode, StatusCode> {
    // Verify the caller owns this submission
    let sub = state
        .db
        .get_extended_submission_by_id(submission_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;

    if sub.submission.engine_id != claims.sub {
        tracing::warn!(
            "User {} denied deletion of submission {} (owner: {})",
            claims.sub,
            submission_id,
            sub.submission.engine_id
        );
        return Err(StatusCode::FORBIDDEN);
    }

    // Finalized submissions cannot be deleted
    let status_str = format!("{:?}", sub.status);
    if status_str == "Verified" || status_str == "Completed" {
        tracing::warn!("Cannot delete finalized submission {}", submission_id);
        return Err(StatusCode::CONFLICT);
    }

    match state.db.delete_submission(submission_id).await {
        Ok(_) => {
            // Invalidate cache
            let _ = state.redis.invalidate_submission_cache(submission_id).await;
            Ok(StatusCode::NO_CONTENT)
        }
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

pub async fn bulk_create_submissions(
    State(state): State<AppState>,
    claims: crate::middleware::auth::Claims,
    Json(requests): Json<Vec<CreateSubmissionRequest>>,
) -> Result<Json<BulkSubmissionResponse>, StatusCode> {
    let mut successful = Vec::new();
    let mut failed = Vec::new();
    let total_processed = requests.len() as u32;

    for (index, request) in requests.into_iter().enumerate() {
        match process_single_submission(&state, claims.clone(), request.clone()).await {
            Ok(response) => successful.push(response),
            Err(error) => failed.push(SubmissionError {
                index: index as u32,
                error: format!("{error:?}"),
                request_data: serde_json::to_value(request).unwrap_or_default(),
            }),
        }
    }

    Ok(Json(BulkSubmissionResponse {
        successful,
        failed,
        total_processed,
    }))
}

pub async fn get_file_info(
    State(state): State<AppState>,
    Path(file_hash): Path<String>,
) -> Result<Json<FileInfo>, StatusCode> {
    // Try cache first
    if let Ok(Some(cached)) = state.redis.get_cached_file_info(&file_hash).await {
        return Ok(Json(cached));
    }

    match state.db.get_file_info(&file_hash).await {
        Ok(Some(file_info)) => {
            // Cache the result
            let _ = state.redis.cache_file_info(&file_hash, &file_info).await;
            Ok(Json(file_info))
        }
        Ok(None) => Err(StatusCode::NOT_FOUND),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

// Helper functions
async fn trigger_automatic_analysis(state: &AppState, _file_hash: &str) {
    // Queue file for automatic analysis by available engines
    // Generating a random analysis ID for now since RedisService expects Uuid
    let analysis_id = Uuid::new_v4();
    let _ = state.redis.queue_for_analysis(analysis_id, 1).await;
}

fn detect_file_type(data: &[u8]) -> String {
    // Simple file type detection based on magic bytes
    if data.len() < 4 {
        return "unknown".to_string();
    }

    match &data[0..4] {
        [0x4D, 0x5A, _, _] => "executable".to_string(), // PE
        [0x7F, 0x45, 0x4C, 0x46] => "elf".to_string(),  // ELF
        [0x50, 0x4B, 0x03, 0x04] => "zip".to_string(),  // ZIP/JAR
        [0x25, 0x50, 0x44, 0x46] => "pdf".to_string(),  // PDF
        _ => "unknown".to_string(),
    }
}

async fn process_single_submission(
    state: &AppState,
    claims: crate::middleware::auth::Claims,
    request: CreateSubmissionRequest,
) -> Result<SubmissionResponse, StatusCode> {
    // This is a simplified version of create_submission for bulk processing
    let json_request = Json(request);
    match create_submission(State(state.clone()), claims, json_request).await {
        Ok(Json(response)) => Ok(response),
        Err(status) => Err(status),
    }
}

/// User-facing file submission handler.
///
/// POST /api/v1/submissions/file
///
/// Multipart field `file` is required. Optional fields: `analysisType`,
/// `bountyAmount`, `priority`, `description`. The bytes are written to disk,
/// `submissions.file_path` is set to that path, and the submission id is
/// pushed onto the Redis list `analysis_queue` that the worker reads.
pub async fn create_file_submission(
    State(state): State<AppState>,
    claims: Option<crate::middleware::auth::Claims>,
    mut multipart: Multipart,
) -> Result<Json<FileSubmissionResponse>, StatusCode> {
    let submitter_id = claims.map(|c| c.sub).unwrap_or_else(Uuid::nil);
    let mut filename: Option<String> = None;
    let mut file_bytes: Option<Vec<u8>> = None;
    let mut target_url: Option<String> = None;
    let mut submission_type_override: Option<String> = None;
    let mut analysis_type: Option<String> = None;
    let mut bounty_amount: Option<String> = None;
    let mut priority = false;
    let mut description: Option<String> = None;

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|_| StatusCode::BAD_REQUEST)?
    {
        let name = field.name().unwrap_or("").to_string();
        if name == "file" {
            filename = field.file_name().map(|s| s.to_string()).or(filename);
            file_bytes = Some(
                field
                    .bytes()
                    .await
                    .map_err(|_| StatusCode::BAD_REQUEST)?
                    .to_vec(),
            );
        } else {
            let text = field.text().await.map_err(|_| StatusCode::BAD_REQUEST)?;
            match name.as_str() {
                "analysisType" | "analysis_type" => analysis_type = Some(text),
                "bountyAmount" | "bounty_amount" => bounty_amount = Some(text),
                "priority" => priority = text == "true" || text == "1",
                "description" => description = Some(text),
                "url" => target_url = Some(text),
                "submissionType" | "submission_type" => submission_type_override = Some(text),
                "filename" if filename.is_none() => filename = Some(text),
                _ => {}
            }
        }
    }

    let submission_id = Uuid::new_v4();
    let now = Utc::now();

    let (submission_type, final_filename, file_hash, file_size, mime_type, file_path, url_col) =
        if let Some(data) = file_bytes.filter(|b| !b.is_empty()) {
            let fname = filename.unwrap_or_else(|| "upload.bin".to_string());
            let hash = calculate_file_hash(&data);
            let upload_root = std::env::var("UPLOAD_DIR")
                .unwrap_or_else(|_| state.config.services.upload_path.clone());
            let fpath = format!("{upload_root}/{submission_id}");
            if let Some(parent) = std::path::Path::new(&fpath).parent() {
                fs::create_dir_all(parent)
                    .await
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            }
            let mut file = fs::File::create(&fpath)
                .await
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            file.write_all(&data)
                .await
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            let mtype = if fname.to_ascii_lowercase().ends_with(".eml")
                || fname.to_ascii_lowercase().ends_with(".mime")
                || submission_type_override.as_deref() == Some("email")
            {
                "message/rfc822".to_string()
            } else {
                detect_file_type(&data)
            };
            let stype = match submission_type_override.as_deref() {
                Some("email") => "email".to_string(),
                _ if mtype == "message/rfc822" => "email".to_string(),
                _ => "file".to_string(),
            };
            (
                stype,
                fname,
                hash,
                data.len() as i64,
                mtype,
                Some(fpath),
                None,
            )
        } else if let Some(u) = target_url.filter(|s| !s.trim().is_empty()) {
            let clean_url = u.trim().to_string();
            let hash = calculate_file_hash(clean_url.as_bytes());
            let fname = filename.unwrap_or_else(|| clean_url.clone());
            let stype = submission_type_override.unwrap_or_else(|| "url".to_string());
            (
                stype,
                fname,
                hash,
                clean_url.len() as i64,
                "text/uri-list".to_string(),
                None,
                Some(clean_url),
            )
        } else {
            return Err(StatusCode::BAD_REQUEST);
        };

    let metadata = serde_json::json!({
        "analysisType": analysis_type,
        "bountyAmount": bounty_amount,
        "priority": priority,
        "description": description,
    });

    sqlx::query_as::<_, (Uuid,)>(
        r#"
        INSERT INTO submissions (
            id, submitter_id, original_filename, file_hash, url, file_size,
            mime_type, file_path, submission_type, analysis_status,
            metadata, created_at, updated_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'pending', $10, $11, $11)
        RETURNING id
        "#,
    )
    .bind(submission_id)
    .bind(submitter_id)
    .bind(&final_filename)
    .bind(&file_hash)
    .bind(&url_col)
    .bind(file_size)
    .bind(&mime_type)
    .bind(&file_path)
    .bind(&submission_type)
    .bind(&metadata)
    .bind(now)
    .fetch_one(state.db.pool())
    .await
    .map(|row: (Uuid,)| {
        let actual_id = row.0;
        let redis = state.redis.clone();
        let prio = if priority { 2 } else { 1 };
        tokio::spawn(async move {
            if let Err(e) = redis.queue_for_analysis(actual_id, prio).await {
                tracing::error!("Failed to enqueue submission {}: {}", actual_id, e);
            }
        });
        Json(FileSubmissionResponse {
            id: actual_id,
            submitter_id,
            original_filename: Some(final_filename),
            file_hash: Some(file_hash),
            file_size: Some(file_size),
            submission_type,
            analysis_status: "pending".to_string(),
            description,
            created_at: now,
        })
    })
    .map_err(|e| {
        tracing::error!("Failed to insert submission: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })
}

// Router setup
pub fn create_submission_router() -> Router<AppState> {
    Router::new()
        .route("/upload", post(upload_file))
        .route("/submissions", post(create_submission))
        .route("/submissions/file", post(create_file_submission))
        .route("/submissions", get(get_submissions))
        .route("/submissions/bulk", post(bulk_create_submissions))
        .route("/submissions/{id}", get(get_submission_details))
        .route("/submissions/{id}", put(update_submission))
        .route("/submissions/{id}", delete(delete_submission))
        .route("/files/{hash}", get(get_file_info))
        .layer(DefaultBodyLimit::max(100 * 1024 * 1024)) // 100MB max file size
}

// Aliases / stubs for v1 routes

/// `GET /api/v1/submissions` — lists file/URL submissions (scoped to user if authenticated, or recent public submissions for guests).
pub async fn list_submissions(
    State(state): State<AppState>,
    claims: Option<crate::middleware::auth::Claims>,
    Query(filters): Query<SubmissionFilters>,
) -> Result<Json<Vec<FileSubmissionListItem>>, StatusCode> {
    // Scans can name private files and URLs, so nobody browses them anonymously.
    let claims = claims.ok_or(StatusCode::UNAUTHORIZED)?;
    let limit = filters.limit.unwrap_or(50).clamp(1, 200) as i64;
    let offset = (filters.page.unwrap_or(1).max(1) as i64 - 1) * limit;

    let rows = if filters.scope.as_deref() == Some("bounties") {
        // Scans carrying a bounty are posted for analysts to work on.
        state.db.list_bounty_file_submissions(limit, offset).await
    } else {
        state
            .db
            .list_file_submissions_for_user(claims.sub, limit, offset)
            .await
    }
    .map_err(|e| {
        tracing::error!("Failed to list submissions for {}: {}", claims.sub, e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(Json(rows))
}

/// GET /api/v1/submissions/:id
pub async fn get_submission(
    State(state): State<AppState>,
    claims: Option<crate::middleware::auth::Claims>,
    Path(submission_id): Path<Uuid>,
) -> Result<Json<FileSubmissionListItem>, StatusCode> {
    load_visible_submission(&state, submission_id, claims.as_ref())
        .await
        .map(Json)
}

/// Who may read a scan and its results.
///
/// - A signed-out upload has no owner, so its unguessable link is the only key.
/// - A scan with a bounty is posted for analysts, so any signed-in user may.
/// - Otherwise only the person who submitted it, or an admin.
pub(crate) fn can_view(
    submission: &FileSubmissionListItem,
    claims: Option<&crate::middleware::auth::Claims>,
) -> bool {
    if submission.submitter_id.is_nil() {
        return true;
    }
    let Some(claims) = claims else {
        return false;
    };
    submission.bounty_id.is_some()
        || claims.sub == submission.submitter_id
        || claims.is_admin
        || claims.role == "admin"
}

/// Loads a scan the caller may read. A scan they may not read answers 404,
/// the same as one that doesn't exist, so ids can't be probed.
pub(crate) async fn load_visible_submission(
    state: &AppState,
    submission_id: Uuid,
    claims: Option<&crate::middleware::auth::Claims>,
) -> Result<FileSubmissionListItem, StatusCode> {
    let submission = state
        .db
        .get_file_submission_any(submission_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to load submission {}: {}", submission_id, e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .ok_or(StatusCode::NOT_FOUND)?;
    if can_view(&submission, claims) {
        Ok(submission)
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

/// Vote on a submission
pub async fn vote_on_submission(
    State(state): State<AppState>,
    claims: crate::middleware::auth::Claims,
    Path(submission_id): Path<Uuid>,
    Json(payload): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let voter_id = claims.sub;

    let verdict = payload
        .get("verdict")
        .and_then(|v| v.as_str())
        .ok_or(StatusCode::BAD_REQUEST)?;
    let confidence = payload
        .get("confidence")
        .and_then(|c| c.as_f64())
        .unwrap_or(1.0);

    // Validate verdict value
    let valid_verdicts = ["malicious", "benign", "suspicious", "agree", "disagree"];
    if !valid_verdicts.contains(&verdict) {
        return Err(StatusCode::BAD_REQUEST);
    }

    // Prevent the submission owner from voting on their own submission
    if let Ok(Some(sub)) = state.db.get_extended_submission_by_id(submission_id).await {
        if sub.submission.engine_id == voter_id {
            tracing::warn!(
                "User {} cannot vote on their own submission {}",
                voter_id,
                submission_id
            );
            return Err(StatusCode::FORBIDDEN);
        }
    }

    // Prevent duplicate votes
    let existing_vote: Option<(Uuid,)> = sqlx::query_as(
        "SELECT id FROM submission_votes WHERE submission_id = $1 AND voter_id = $2 LIMIT 1",
    )
    .bind(submission_id)
    .bind(voter_id)
    .fetch_optional(state.db.pool())
    .await
    .map_err(|e| {
        tracing::error!("Failed to check existing votes: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    if existing_vote.is_some() {
        tracing::warn!(
            "User {} already voted on submission {}",
            voter_id,
            submission_id
        );
        return Err(StatusCode::CONFLICT);
    }

    let vote_id = Uuid::new_v4();

    // Record the vote with voter identity
    sqlx::query(
        "INSERT INTO submission_votes (id, submission_id, voter_id, verdict, confidence, created_at) VALUES ($1, $2, $3, $4, $5, $6)"
    )
    .bind(vote_id)
    .bind(submission_id)
    .bind(voter_id)
    .bind(verdict)
    .bind(confidence)
    .bind(Utc::now())
    .execute(state.db.pool())
    .await
    .map_err(|e| {
        tracing::error!("Failed to record vote: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // Mirror the vote into consensus-service. The gateway's submission_votes
    // table is the voter's receipt; consensus-service keeps the store the
    // aggregator actually reads. Without this forward the vote never reaches
    // consensus and no bounty can ever be scored, paid out, or re-graded.
    //
    // Failure here is logged and reported, never fatal: the vote is already
    // committed above and must not be lost because a downstream service is
    // unreachable.
    let consensus_recorded =
        match forward_vote_to_consensus(&state, submission_id, voter_id, verdict, confidence).await
        {
            Ok(recorded) => recorded,
            Err(e) => {
                tracing::error!(
                    "Could not prepare consensus forward for vote {}: {}",
                    vote_id,
                    e
                );
                false
            }
        };

    Ok(Json(serde_json::json!({
        "success": true,
        "vote_id": vote_id,
        "submission_id": submission_id,
        "voter_id": voter_id,
        "verdict": verdict,
        "confidence": confidence,
        "consensus_recorded": consensus_recorded,
    })))
}

/// Resolve a vote to its bounty and sample, then mirror it into
/// consensus-service.
///
/// Returns whether consensus-service accepted the vote. `Err` covers only the
/// lookup failing; a rejected or unreachable consensus-service is reported as
/// `Ok(false)` so the caller can carry on.
async fn forward_vote_to_consensus(
    state: &AppState,
    submission_id: Uuid,
    voter_id: Uuid,
    verdict: &str,
    confidence: f64,
) -> Result<bool, sqlx::Error> {
    use crate::services::consensus_client::{forward_vote, resolve_verdict, ForwardedVote};

    // One hop resolves everything the consensus vote needs: which bounty the
    // submission belongs to, what the submission itself claimed (to interpret
    // agree/disagree), and the hash of the sample under analysis.
    let row: Option<(Uuid, Option<String>, Option<String>)> = sqlx::query_as(
        r#"
        SELECT bs.bounty_id, bs.verdict, s.file_hash
        FROM bounty_submissions bs
        JOIN bounties b   ON b.id = bs.bounty_id
        JOIN submissions s ON s.id = b.submission_id
        WHERE bs.id = $1
        "#,
    )
    .bind(submission_id)
    .fetch_optional(state.db.pool())
    .await?;

    let Some((bounty_id, submission_verdict, sample_hash)) = row else {
        tracing::warn!(
            "Vote on submission {} has no resolvable bounty; not forwarded",
            submission_id
        );
        return Ok(false);
    };

    let Some(resolved) = resolve_verdict(verdict, submission_verdict.as_deref()) else {
        // e.g. "disagree" with a suspicious submission -- the voter has told us
        // what they reject, not what they believe. Recorded locally, but there
        // is no honest absolute verdict to forward.
        tracing::info!(
            "Vote '{}' on submission {} has no absolute verdict; not forwarded",
            verdict,
            submission_id
        );
        return Ok(false);
    };

    let reputation_score: i32 =
        sqlx::query_scalar("SELECT reputation_score FROM users WHERE id = $1")
            .bind(voter_id)
            .fetch_optional(state.db.pool())
            .await?
            .flatten()
            .unwrap_or(0);

    Ok(forward_vote(&ForwardedVote {
        bounty_id,
        voter_id,
        verdict: resolved,
        confidence,
        reputation_score,
        sample_hash,
    })
    .await)
}

/// Verify a submission
pub async fn verify_submission(
    State(state): State<AppState>,
    claims: crate::middleware::auth::Claims,
    Path(submission_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    // Only admins/moderators can verify submissions
    if claims.role != "admin" && claims.role != "moderator" {
        tracing::warn!(
            "User {} (role: {}) denied verify on submission {}",
            claims.sub,
            claims.role,
            submission_id
        );
        return Err(StatusCode::FORBIDDEN);
    }

    // Update the submission status to Verified
    let result = sqlx::query(
        "UPDATE extended_submissions SET status = 'Verified', updated_at = NOW() WHERE submission_id = $1"
    )
    .bind(submission_id)
    .execute(state.db.pool())
    .await
    .map_err(|e| {
        tracing::error!("Failed to verify submission: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    if result.rows_affected() == 0 {
        return Err(StatusCode::NOT_FOUND);
    }

    // Invalidate cache
    let _ = state.redis.invalidate_submission_cache(submission_id).await;

    tracing::info!(admin = %claims.sub, submission = %submission_id, "Submission verified by admin");

    Ok(Json(serde_json::json!({
        "success": true,
        "submission_id": submission_id,
        "verified_by": claims.sub,
        "status": "Verified",
        "message": "Submission has been verified"
    })))
}

/// Get current user's submissions
pub async fn get_my_submissions(
    State(state): State<AppState>,
    claims: crate::middleware::auth::Claims,
) -> Result<Json<SubmissionListResponse>, StatusCode> {
    // Query submissions owned by the authenticated user
    let user_id = claims.sub;
    let filters = SubmissionFilters {
        bounty_id: None,
        engine_id: Some(user_id.to_string()),
        verdict: None,
        min_confidence: None,
        max_confidence: None,
        status: None,
        date_from: None,
        date_to: None,
        page: Some(1),
        limit: Some(20),
        scope: None,
    };

    let (submissions, total) = state
        .db
        .get_submissions_with_filters(&filters, 1, 20)
        .await
        .map_err(|e| {
            tracing::error!("Failed to fetch user submissions: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let response_items: Vec<SubmissionResponse> = submissions
        .into_iter()
        .map(|s| SubmissionResponse {
            id: s.id,
            bounty_id: s.bounty_id,
            engine_id: s.engine_id.to_string(),
            engine_name: s.engine_name,
            engine_version: "1.0".to_string(),
            verdict: s.verdict,
            confidence: s.confidence as f32,
            threat_types: vec![],
            risk_score: 0,
            analysis_summary: "".to_string(),
            stake_amount: s.stake_amount.parse().unwrap_or(0),
            submitted_at: s.submitted_at,
            updated_at: None,
            status: SubmissionStatus::Completed,
            is_winner: None,
            reward_earned: None,
            reputation_change: None,
        })
        .collect();

    Ok(Json(SubmissionListResponse {
        submissions: response_items,
        total_count: total,
        page: 1,
        limit: 20,
        filters_applied: filters,
    }))
}

// ─── Extra endpoints consumed by the frontend ────────────────────

/// Start analysis for a submission.
///
/// POST /api/v1/submissions/:submission_id/start-analysis
///
/// Transitions the submission status to "Processing" and queues it
/// for engine analysis.
pub async fn start_analysis(
    State(state): State<AppState>,
    claims: Option<crate::middleware::auth::Claims>,
    Path(submission_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let found = state
        .db
        .get_file_submission_any(submission_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    if let Some(sub) = &found {
        if !can_view(sub, claims.as_ref()) {
            return Err(StatusCode::NOT_FOUND);
        }
    }
    if found.is_some() {
        sqlx::query(
            "UPDATE submissions SET analysis_status = 'analyzing', updated_at = NOW() WHERE id = $1",
        )
        .bind(submission_id)
        .execute(state.db.pool())
        .await
        .map_err(|e| {
            tracing::error!("Failed to start analysis for {}: {}", submission_id, e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    } else {
        let result = sqlx::query(
            "UPDATE extended_submissions SET status = 'Processing', updated_at = NOW() WHERE submission_id = $1",
        )
        .bind(submission_id)
        .execute(state.db.pool())
        .await
        .map_err(|e| {
            tracing::error!("Failed to start analysis for {}: {}", submission_id, e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

        if result.rows_affected() == 0 {
            return Err(StatusCode::NOT_FOUND);
        }
    }

    // Queue for processing
    let _ = state.redis.queue_for_analysis(submission_id, 1).await;

    Ok(Json(serde_json::json!({
        "success": true,
        "submission_id": submission_id,
        "status": "Processing",
        "message": "Analysis started"
    })))
}

/// Get analyses for a specific submission / bounty.
///
/// GET /api/v1/submissions/:submission_id/analyses
///
/// Returns analysis results associated with the submission's bounty.
pub async fn get_submission_analyses(
    State(state): State<AppState>,
    claims: Option<crate::middleware::auth::Claims>,
    Path(submission_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    load_visible_submission(&state, submission_id, claims.as_ref()).await?;

    // Every value comes from what the engine recorded. An engine that gave no
    // verdict has no confidence, and nothing is filled in.
    let rows: Vec<serde_json::Value> = sqlx::query_scalar(
        r#"SELECT row_to_json(t) FROM (
             SELECT
               id,
               submission_id,
               submission_id AS "submissionId",
               CASE WHEN LOWER(verdict) = 'benign' THEN 'clean' ELSE LOWER(verdict) END AS verdict,
               CASE
                 WHEN LOWER(verdict) IN ('unknown', 'unavailable') THEN NULL
                 WHEN COALESCE(confidence, confidence_score) IS NULL THEN NULL
                 WHEN COALESCE(confidence, confidence_score) <= 1.0
                   THEN ROUND((COALESCE(confidence, confidence_score) * 100.0)::numeric, 0)::float8
                 ELSE ROUND(COALESCE(confidence, confidence_score)::numeric, 0)::float8
               END AS confidence,
               COALESCE(metadata ->> 'vote',
                 CASE WHEN LOWER(verdict) IN ('unknown', 'unavailable') THEN 'no_verdict' ELSE 'counted' END
               ) AS vote,
               metadata ->> 'reason' AS reason,
               LOWER(COALESCE(analysis_status, 'completed')) AS status,
               COALESCE(analysis_status, 'completed') AS analysis_status,
               processing_time_ms AS "processingTimeMs",
               severity,
               COALESCE(metadata, '{}'::jsonb) - 'vote' - 'reason' - 'engine_type' AS metadata,
               created_at,
               created_at AS "createdAt",
               COALESCE(completed_at, detected_at, created_at) AS completed_at,
               COALESCE(completed_at, detected_at, created_at) AS "completedAt",
               json_build_object(
                 'name', engine_name,
                 'type', COALESCE(metadata ->> 'engine_type', 'scanner'),
                 'version', engine_version
               ) AS engine
             FROM analysis_results
             WHERE submission_id = $1
               AND engine_name <> 'Hash Analyzer Consensus'
               AND COALESCE((metadata ->> 'aggregate')::boolean, false) = false
             ORDER BY engine_name
           ) t"#,
    )
    .bind(submission_id)
    .fetch_all(state.db.pool())
    .await
    .map_err(|e| {
        tracing::error!("Failed to load analyses for {}: {}", submission_id, e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(Json(serde_json::json!(rows)))
}

/// Get consensus result for a submission.
///
/// GET /api/v1/submissions/:submission_id/consensus
///
/// Returns the aggregated verdict across all analyses.
pub async fn get_submission_consensus(
    State(state): State<AppState>,
    claims: Option<crate::middleware::auth::Claims>,
    Path(submission_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    load_visible_submission(&state, submission_id, claims.as_ref()).await?;

    let votes: Vec<String> = sqlx::query_scalar(
        "SELECT LOWER(verdict) FROM analysis_results
         WHERE submission_id = $1
           AND engine_name <> 'Hash Analyzer Consensus'
           AND COALESCE((metadata ->> 'aggregate')::boolean, false) = false",
    )
    .bind(submission_id)
    .fetch_all(state.db.pool())
    .await
    .map_err(|e| {
        tracing::error!("Failed to load votes for {}: {}", submission_id, e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    if votes.is_empty() {
        return Err(StatusCode::NOT_FOUND);
    }

    let meta: serde_json::Value = sqlx::query_scalar::<_, Option<serde_json::Value>>(
        "SELECT metadata FROM submissions WHERE id = $1",
    )
    .bind(submission_id)
    .fetch_optional(state.db.pool())
    .await
    .unwrap_or_default()
    .flatten()
    .unwrap_or(serde_json::Value::Null);

    Ok(Json(consensus_body(submission_id, &votes, &meta)))
}

/// The consensus as the analysis engine decided it. Scans stored before the
/// engine recorded its verdict fall back to a count of the stored votes.
fn consensus_body(
    submission_id: Uuid,
    votes: &[String],
    meta: &serde_json::Value,
) -> serde_json::Value {
    let count = |names: &[&str]| votes.iter().filter(|v| names.contains(&v.as_str())).count();
    let malicious = count(&["malicious"]);
    let suspicious = count(&["suspicious"]);
    let clean = count(&["benign", "clean"]);
    let voting = malicious + suspicious + clean;

    let final_verdict = match meta.get("consensus_verdict").and_then(|v| v.as_str()) {
        Some("benign") => "clean".to_string(),
        Some(v) => v.to_string(),
        None if voting == 0 => "unknown".to_string(),
        None if malicious > suspicious && malicious > clean => "malicious".to_string(),
        None if clean > malicious && clean > suspicious => "clean".to_string(),
        None => "suspicious".to_string(),
    };

    let not_voting: Vec<serde_json::Value> = meta
        .get("unavailable_engines")
        .and_then(|v| v.as_array())
        .map(|list| {
            list.iter()
                .filter(|u| {
                    u.get("engine_name").and_then(|n| n.as_str()) != Some("Hash Analyzer Consensus")
                })
                .map(|u| {
                    serde_json::json!({
                        "engineName": u.get("engine_name"),
                        "engineType": u.get("engine_type"),
                        "reason": u.get("reason"),
                        "kind": u.get("kind").and_then(|k| k.as_str()).unwrap_or("unavailable"),
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    let explanation = meta
        .get("consensus_explanation")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .unwrap_or_else(|| {
            format!(
                "{} of {voting} voting engines flagged it.",
                malicious + suspicious
            )
        });

    let max_votes = malicious.max(suspicious).max(clean);
    let agreement = if voting == 0 {
        0.0
    } else {
        max_votes as f64 / voting as f64
    };

    serde_json::json!({
        "submissionId": submission_id,
        "finalVerdict": final_verdict,
        "explanation": explanation,
        "maliciousVotes": malicious,
        "suspiciousVotes": suspicious,
        "cleanVotes": clean,
        "totalVotes": voting,
        "flaggedVotes": malicious + suspicious,
        "engineCount": votes.len(),
        "agreementScore": agreement,
        "unavailableEngines": not_voting,
        "verdictHistory": meta.get("verdict_history").cloned().unwrap_or_else(|| serde_json::json!([])),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::middleware::auth::Claims;

    fn sub(owner: Uuid, bounty: Option<Uuid>) -> FileSubmissionListItem {
        FileSubmissionListItem {
            id: Uuid::new_v4(),
            submitter_id: owner,
            user_id: owner,
            original_filename: None,
            filename: None,
            file_name: None,
            file_hash: None,
            url: Some("https://example.com".to_string()),
            file_size: None,
            mime_type: None,
            submission_type: "url".to_string(),
            analysis_status: "completed".to_string(),
            status: "completed".to_string(),
            is_malicious: None,
            description: None,
            analysis_type: None,
            bounty_amount: None,
            priority: None,
            bounty_id: bounty,
            created_at: Utc::now(),
        }
    }

    fn claims(user: Uuid, role: &str) -> Claims {
        serde_json::from_value(serde_json::json!({
            "sub": user, "email": "a@example.com", "role": role, "exp": 0
        }))
        .unwrap()
    }

    #[test]
    fn only_the_owner_or_an_admin_can_read_a_private_scan() {
        let (owner, other) = (Uuid::new_v4(), Uuid::new_v4());
        let s = sub(owner, None);
        assert!(!can_view(&s, None), "signed out");
        assert!(!can_view(&s, Some(&claims(other, "user"))), "someone else");
        assert!(can_view(&s, Some(&claims(owner, "user"))));
        assert!(can_view(&s, Some(&claims(other, "admin"))));
    }

    #[test]
    fn ownerless_and_bounty_scans_are_shared_as_documented() {
        assert!(can_view(&sub(Uuid::nil(), None), None));
        let bounty = sub(Uuid::new_v4(), Some(Uuid::new_v4()));
        assert!(!can_view(&bounty, None));
        assert!(can_view(&bounty, Some(&claims(Uuid::new_v4(), "user"))));
    }

    #[test]
    fn consensus_uses_the_engine_verdict_and_names_non_voters() {
        let votes: Vec<String> = ["malicious", "benign", "benign", "unknown"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let meta = serde_json::json!({
            "consensus_verdict": "malicious",
            "consensus_explanation": "Known malicious: listed by URLhaus.",
            "unavailable_engines": [
                {"engine_name": "ThreatFox", "engine_type": "Hash", "reason": "Not listed on ThreatFox", "kind": "no_record"},
                {"engine_name": "Hash Analyzer Consensus", "engine_type": "Hash", "reason": "x"}
            ]
        });
        let body = consensus_body(Uuid::nil(), &votes, &meta);
        assert_eq!(body["finalVerdict"], "malicious");
        assert_eq!(body["flaggedVotes"], 1);
        assert_eq!(body["totalVotes"], 3);
        assert_eq!(body["engineCount"], 4);
        let non_voters = body["unavailableEngines"].as_array().unwrap();
        assert_eq!(non_voters.len(), 1);
        assert_eq!(non_voters[0]["engineName"], "ThreatFox");
        assert_eq!(non_voters[0]["kind"], "no_record");
        assert!(body.get("confidenceScore").is_none());
    }

    #[test]
    fn old_scans_fall_back_to_counting_without_favouring_malicious() {
        let votes: Vec<String> = ["malicious", "benign"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let body = consensus_body(Uuid::nil(), &votes, &serde_json::Value::Null);
        assert_eq!(body["finalVerdict"], "suspicious");
        let none: Vec<String> = vec!["unknown".to_string()];
        assert_eq!(
            consensus_body(Uuid::nil(), &none, &serde_json::Value::Null)["finalVerdict"],
            "unknown"
        );
    }
}
