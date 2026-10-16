use anyhow::{Context, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::models::{
    analysis::AnalysisResult,
    bounty::{Bounty, CreateBountyRequest},
    user::User,
};

#[derive(Clone)]
pub struct DatabaseService {
    pool: PgPool,
}

impl DatabaseService {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Get database connection pool reference
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Get database connection pool for use as executor
    pub fn executor(&self) -> &PgPool {
        &self.pool
    }

    // ═══════════════════════════════════════════════
    // User operations
    // ═══════════════════════════════════════════════

    pub async fn create_user(
        &self,
        wallet_address: &str,
        username: &str,
        email: &str,
        password_hash: &str,
    ) -> Result<User> {
        let user = sqlx::query_as::<_, User>(
            r#"
            INSERT INTO users (id, wallet_address, username, email, password_hash, reputation_score, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING *
            "#
        )
        .bind(Uuid::new_v4())
        .bind(wallet_address)
        .bind(username)
        .bind(email)
        .bind(password_hash)
        .bind(0i32)
        .bind(Utc::now())
        .bind(Utc::now())
        .fetch_one(&self.pool)
        .await
        .context("Failed to create user")?;

        Ok(user)
    }

    pub async fn get_user_by_wallet(&self, wallet_address: &str) -> Result<Option<User>> {
        let user = sqlx::query_as::<_, User>(
            r#"
            SELECT * FROM users
            WHERE wallet_address = $1
            "#,
        )
        .bind(wallet_address)
        .fetch_optional(&self.pool)
        .await
        .context("Failed to fetch user by wallet address")?;

        Ok(user)
    }

    pub async fn get_user_by_id(&self, user_id: Uuid) -> Result<Option<User>> {
        let user = sqlx::query_as::<_, User>(
            r#"
            SELECT * FROM users
            WHERE id = $1
            "#,
        )
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await
        .context("Failed to fetch user by ID")?;

        Ok(user)
    }

    pub async fn update_user_reputation(&self, user_id: Uuid, reputation_delta: i32) -> Result<()> {
        sqlx::query(
            r#"
            UPDATE users
            SET reputation_score = reputation_score + $1, updated_at = $2
            WHERE id = $3
            "#,
        )
        .bind(reputation_delta)
        .bind(Utc::now())
        .bind(user_id)
        .execute(&self.pool)
        .await
        .context("Failed to update user reputation")?;

        Ok(())
    }

    // ═══════════════════════════════════════════════
    // Bounty operations — matches `bounties` table
    // ═══════════════════════════════════════════════

    pub async fn create_bounty(
        &self,
        request: CreateBountyRequest,
        creator_id: Uuid,
    ) -> Result<Bounty> {
        let now = Utc::now();
        let bounty_id = Uuid::new_v4();
        let deadline = request
            .deadline_hours
            .map(|h| now + chrono::Duration::hours(h as i64));
        let min_stake = request.min_stake_amount.unwrap_or_else(|| "0".to_string());
        let consensus = request.consensus_threshold.unwrap_or(0.60);
        let priority = request.priority_level.unwrap_or(1);
        let requires_verification = request.requires_verification.unwrap_or(false);

        let bounty = sqlx::query_as::<_, Bounty>(
            r#"
            INSERT INTO bounties (
                id, creator_id, submission_id, title, description,
                reward_amount, min_stake_amount, max_participants,
                deadline, bounty_status, requires_verification,
                priority_level, consensus_threshold,
                created_at, updated_at
            )
            VALUES (
                $1, $2, $3, $4, $5,
                $6, $7, $8,
                $9, 'active', $10,
                $11, $12,
                $13, $14
            )
            RETURNING *
            "#,
        )
        .bind(bounty_id)
        .bind(creator_id)
        .bind(request.submission_id)
        .bind(&request.title)
        .bind(&request.description)
        .bind(&request.reward_amount)
        .bind(&min_stake)
        .bind(request.max_participants)
        .bind(deadline)
        .bind(requires_verification)
        .bind(priority)
        .bind(consensus)
        .bind(now)
        .bind(now)
        .fetch_one(&self.pool)
        .await
        .context("Failed to create bounty")?;

        Ok(bounty)
    }

    /// Store the on-chain bounty ID (incremental counter from BountyManager) and tx hash
    pub async fn update_bounty_on_chain_id(
        &self,
        bounty_id: Uuid,
        tx_hash: &str,
        on_chain_id: i64,
    ) -> Result<()> {
        sqlx::query(
            "UPDATE bounties SET blockchain_tx_hash = $1, on_chain_id = $2, updated_at = $3 WHERE id = $4"
        )
        .bind(tx_hash)
        .bind(on_chain_id)
        .bind(Utc::now())
        .bind(bounty_id)
        .execute(&self.pool)
        .await
        .context("Failed to update bounty on_chain_id")?;

        Ok(())
    }

    /// Look up the on-chain bounty ID for a given DB bounty UUID.
    pub async fn get_bounty_on_chain_id(&self, bounty_id: Uuid) -> Result<Option<i64>> {
        let row: Option<(Option<i64>,)> =
            sqlx::query_as("SELECT on_chain_id FROM bounties WHERE id = $1")
                .bind(bounty_id)
                .fetch_optional(&self.pool)
                .await
                .context("Failed to fetch bounty on_chain_id")?;

        Ok(row.and_then(|r| r.0))
    }

    pub async fn get_bounty_by_id(&self, bounty_id: Uuid) -> Result<Option<Bounty>> {
        let bounty = sqlx::query_as::<_, Bounty>(
            r#"
            SELECT * FROM bounties
            WHERE id = $1
            "#,
        )
        .bind(bounty_id)
        .fetch_optional(&self.pool)
        .await
        .context("Failed to fetch bounty by ID")?;

        Ok(bounty)
    }

    pub async fn get_submission_file_hash(&self, submission_id: Uuid) -> Result<Option<String>> {
        let row: Option<(Option<String>,)> =
            sqlx::query_as("SELECT file_hash FROM submissions WHERE id = $1")
                .bind(submission_id)
                .fetch_optional(&self.pool)
                .await
                .context("Failed to fetch submission file hash")?;

        Ok(row.and_then(|(hash,)| hash))
    }

    pub async fn get_active_bounties(&self, limit: i64, offset: i64) -> Result<Vec<Bounty>> {
        let bounties = sqlx::query_as::<_, Bounty>(
            r#"
            SELECT * FROM bounties
            WHERE bounty_status = 'active' AND (deadline IS NULL OR deadline > $1)
            ORDER BY created_at DESC
            LIMIT $2 OFFSET $3
            "#,
        )
        .bind(Utc::now())
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await
        .context("Failed to fetch active bounties")?;

        Ok(bounties)
    }

    pub async fn get_bounties_by_creator(&self, creator_id: Uuid) -> Result<Vec<Bounty>> {
        let bounties = sqlx::query_as::<_, Bounty>(
            r#"
            SELECT * FROM bounties
            WHERE creator_id = $1
            ORDER BY created_at DESC
            "#,
        )
        .bind(creator_id)
        .fetch_all(&self.pool)
        .await
        .context("Failed to fetch bounties by creator")?;

        Ok(bounties)
    }

    pub async fn update_bounty_status(&self, bounty_id: Uuid, status: &str) -> Result<()> {
        sqlx::query(
            r#"
            UPDATE bounties
            SET bounty_status = $1, updated_at = $2
            WHERE id = $3
            "#,
        )
        .bind(status)
        .bind(Utc::now())
        .bind(bounty_id)
        .execute(&self.pool)
        .await
        .context("Failed to update bounty status")?;

        Ok(())
    }

    // ═══════════════════════════════════════════════
    // Analysis operations — matches `analysis_results` table
    // ═══════════════════════════════════════════════

    pub async fn create_analysis_result(
        &self,
        engine_id: Uuid,
        submission_id: Uuid,
        bounty_id: Option<Uuid>,
        verdict: &str,
        confidence_score: f64,
        detailed_report: serde_json::Value,
    ) -> Result<AnalysisResult> {
        let analysis = sqlx::query_as::<_, AnalysisResult>(
            r#"
            INSERT INTO analysis_results (
                id, engine_id, submission_id, bounty_id,
                verdict, confidence_score, detailed_report,
                analysis_status, created_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, 'completed', $8)
            RETURNING *
            "#,
        )
        .bind(Uuid::new_v4())
        .bind(engine_id)
        .bind(submission_id)
        .bind(bounty_id)
        .bind(verdict)
        .bind(confidence_score)
        .bind(detailed_report)
        .bind(Utc::now())
        .fetch_one(&self.pool)
        .await
        .context("Failed to create analysis result")?;

        Ok(analysis)
    }

    pub async fn get_analysis_results_by_bounty(
        &self,
        bounty_id: Uuid,
    ) -> Result<Vec<AnalysisResult>> {
        let results = sqlx::query_as::<_, AnalysisResult>(
            r#"
            SELECT * FROM analysis_results
            WHERE bounty_id = $1
            ORDER BY created_at DESC
            "#,
        )
        .bind(bounty_id)
        .fetch_all(&self.pool)
        .await
        .context("Failed to fetch analysis results by bounty")?;

        Ok(results)
    }

    pub async fn get_analysis_results_by_engine(
        &self,
        engine_id: Uuid,
    ) -> Result<Vec<AnalysisResult>> {
        let results = sqlx::query_as::<_, AnalysisResult>(
            r#"
            SELECT * FROM analysis_results
            WHERE engine_id = $1
            ORDER BY created_at DESC
            "#,
        )
        .bind(engine_id)
        .fetch_all(&self.pool)
        .await
        .context("Failed to fetch analysis results by engine")?;

        Ok(results)
    }

    // ═══════════════════════════════════════════════
    // Consensus and reputation operations
    // ═══════════════════════════════════════════════

    pub async fn calculate_consensus_for_bounty(
        &self,
        bounty_id: Uuid,
    ) -> Result<Option<ConsensusResult>> {
        let consensus = sqlx::query_as::<_, ConsensusResult>(
            r#"
            SELECT
                COUNT(*) as total_analyses,
                AVG(confidence_score::float) as avg_confidence,
                COUNT(CASE WHEN verdict = 'malicious' THEN 1 END) as malicious_count,
                COUNT(CASE WHEN verdict = 'benign' THEN 1 END) as benign_count,
                COUNT(CASE WHEN verdict = 'suspicious' THEN 1 END) as suspicious_count
            FROM analysis_results
            WHERE bounty_id = $1 AND analysis_status = 'completed'
            "#,
        )
        .bind(bounty_id)
        .fetch_optional(&self.pool)
        .await
        .context("Failed to calculate consensus")?;

        Ok(consensus)
    }

    pub async fn get_user_analysis_stats(
        &self,
        user_id: Uuid,
    ) -> Result<Option<UserAnalysisStats>> {
        let stats = sqlx::query_as::<_, UserAnalysisStats>(
            r#"
            SELECT
                COUNT(*) as total_analyses,
                AVG(confidence_score::float) as avg_confidence,
                COUNT(CASE WHEN verdict = 'malicious' THEN 1 END) as malicious_detections,
                COUNT(CASE WHEN verdict = 'benign' THEN 1 END) as benign_detections
            FROM analysis_results
            WHERE analyzer_id = $1 AND analysis_status = 'completed'
            "#,
        )
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await
        .context("Failed to fetch user analysis stats")?;

        Ok(stats)
    }

    // ═══════════════════════════════════════════════
    // Transaction management
    // ═══════════════════════════════════════════════

    pub async fn begin_transaction(&self) -> Result<sqlx::Transaction<'_, sqlx::Postgres>> {
        self.pool
            .begin()
            .await
            .context("Failed to begin transaction")
    }

    // Health check
    pub async fn health_check(&self) -> Result<()> {
        sqlx::query("SELECT 1")
            .execute(&self.pool)
            .await
            .context("Database health check failed")?;

        Ok(())
    }

    // === Submission-related methods ===

    /// Get analysis result by ID
    pub async fn get_analysis_result(&self, _analysis_id: Uuid) -> Result<AnalysisResult> {
        anyhow::bail!("get_analysis_result not yet implemented")
    }

    /// Store file metadata
    pub async fn store_file_metadata(
        &self,
        _file_id: Uuid,
        _metadata: &crate::models::analysis::FileMetadata,
    ) -> Result<()> {
        anyhow::bail!("store_file_metadata not yet implemented")
    }

    /// Get file info by hash
    pub async fn get_file_info(
        &self,
        _file_hash: &str,
    ) -> Result<Option<crate::handlers::submission::FileInfo>> {
        Ok(None)
    }

    /// Create a bounty submission and its extended data
    pub async fn create_extended_submission(
        &self,
        submission: &crate::models::bounty::BountySubmission,
    ) -> Result<()> {
        let mut tx = self
            .pool
            .begin()
            .await
            .context("Failed to begin transaction")?;

        sqlx::query(
            r#"
            INSERT INTO bounty_submissions (
                id, bounty_id, engine_id, engine_name, engine_address,
                verdict, confidence, stake_amount, details, submitted_at, is_verified
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            "#,
        )
        .bind(submission.id)
        .bind(submission.bounty_id)
        .bind(submission.engine_id)
        .bind(&submission.engine_name)
        .bind(&submission.engine_address)
        .bind(&submission.verdict)
        .bind(submission.confidence)
        .bind(&submission.stake_amount)
        .bind(&submission.details)
        .bind(submission.submitted_at)
        .bind(submission.is_verified)
        .execute(&mut *tx)
        .await
        .context("Failed to insert bounty_submission")?;

        sqlx::query(
            r#"
            INSERT INTO extended_submissions (submission_id, status, created_at, updated_at)
            VALUES ($1, 'Pending', NOW(), NOW())
            "#,
        )
        .bind(submission.id)
        .execute(&mut *tx)
        .await
        .context("Failed to insert extended_submission")?;

        tx.commit()
            .await
            .context("Failed to commit submission transaction")?;
        Ok(())
    }

    /// One submission, only if this user uploaded it. Missing and not-owned
    /// both return None so callers can respond 404 without confirming the id exists.
    pub async fn get_file_submission_for_user(
        &self,
        submission_id: Uuid,
        submitter_id: Uuid,
    ) -> Result<Option<crate::handlers::submission::FileSubmissionListItem>> {
        let row = sqlx::query(
            r#"
            SELECT
                id, submitter_id, original_filename, file_hash, url,
                file_size, mime_type, submission_type,
                COALESCE(analysis_status, 'pending') AS analysis_status,
                is_malicious, created_at,
                metadata ->> 'description'  AS description,
                metadata ->> 'analysisType' AS analysis_type,
                metadata ->> 'bountyAmount' AS bounty_amount,
                (metadata ->> 'priority')::boolean AS priority,
                file_path
            FROM submissions
            WHERE id = $1 AND submitter_id = $2
            "#,
        )
        .bind(submission_id)
        .bind(submitter_id)
        .fetch_optional(&self.pool)
        .await
        .context("Failed to load owned submission")?;

        Ok(row.map(|r| {
            let analysis_status: String = r.get("analysis_status");
            crate::handlers::submission::FileSubmissionListItem {
                id: r.get("id"),
                submitter_id: r.get("submitter_id"),
                original_filename: r.get("original_filename"),
                file_hash: r.get("file_hash"),
                url: r.get("url"),
                file_size: r.get("file_size"),
                mime_type: r.get("mime_type"),
                submission_type: r.get("submission_type"),
                status: analysis_status.clone(),
                analysis_status,
                is_malicious: r.get("is_malicious"),
                description: r.get("description"),
                analysis_type: r.get("analysis_type"),
                bounty_amount: r.get("bounty_amount"),
                priority: r.get("priority"),
                created_at: r.get("created_at"),
            }
        }))
    }

    /// File paths for a user's uploads, used to delete objects when the account
    /// or those submissions are explicitly removed.
    pub async fn file_paths_for_user(&self, submitter_id: Uuid) -> Result<Vec<String>> {
        let rows: Vec<(Option<String>,)> =
            sqlx::query_as("SELECT file_path FROM submissions WHERE submitter_id = $1")
                .bind(submitter_id)
                .fetch_all(&self.pool)
                .await
                .context("Failed to list artifact paths")?;
        Ok(rows.into_iter().filter_map(|(p,)| p).collect())
    }

    pub async fn delete_file_submissions_for_user(&self, submitter_id: Uuid) -> Result<u64> {
        let result = sqlx::query("DELETE FROM submissions WHERE submitter_id = $1")
            .bind(submitter_id)
            .execute(&self.pool)
            .await
            .context("Failed to delete user submissions")?;
        Ok(result.rows_affected())
    }

    /// List one user's own file/URL submissions, newest first.
    ///
    /// Reads `submissions` (what a user uploaded), NOT `bounty_submissions`
    /// (an analyst's verdict on a bounty) — see `list_submissions` in the
    /// handler for why that distinction matters.
    ///
    /// `analysis_type` / `bounty_amount` / `priority` / `description` are
    /// stored inside `metadata` by `create_file_submission`, so they are
    /// extracted here with `->>` rather than being real columns.
    pub async fn list_file_submissions_for_user(
        &self,
        submitter_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<crate::handlers::submission::FileSubmissionListItem>> {
        let rows = sqlx::query(
            r#"
            SELECT
                id, submitter_id, original_filename, file_hash, url,
                file_size, mime_type, submission_type,
                COALESCE(analysis_status, 'pending') AS analysis_status,
                is_malicious, created_at,
                metadata ->> 'description'  AS description,
                metadata ->> 'analysisType' AS analysis_type,
                metadata ->> 'bountyAmount' AS bounty_amount,
                (metadata ->> 'priority')::boolean AS priority
            FROM submissions
            WHERE submitter_id = $1
            ORDER BY created_at DESC
            LIMIT $2 OFFSET $3
            "#,
        )
        .bind(submitter_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await
        .context("Failed to list file submissions for user")?;

        Ok(rows
            .into_iter()
            .map(|r| {
                let analysis_status: String = r.get("analysis_status");
                crate::handlers::submission::FileSubmissionListItem {
                    id: r.get("id"),
                    submitter_id: r.get("submitter_id"),
                    original_filename: r.get("original_filename"),
                    file_hash: r.get("file_hash"),
                    url: r.get("url"),
                    file_size: r.get("file_size"),
                    mime_type: r.get("mime_type"),
                    submission_type: r.get("submission_type"),
                    status: analysis_status.clone(),
                    analysis_status,
                    is_malicious: r.get("is_malicious"),
                    description: r.get("description"),
                    analysis_type: r.get("analysis_type"),
                    bounty_amount: r.get("bounty_amount"),
                    priority: r.get("priority"),
                    created_at: r.get("created_at"),
                }
            })
            .collect())
    }

    /// Get submissions with filters (paginated)
    pub async fn get_submissions_with_filters(
        &self,
        filters: &crate::handlers::submission::SubmissionFilters,
        page: u32,
        limit: u32,
    ) -> Result<(Vec<crate::models::bounty::BountySubmission>, u32)> {
        let offset = (page.saturating_sub(1)) * limit;

        // Build dynamic WHERE clause
        let mut conditions: Vec<String> = Vec::new();
        if filters.bounty_id.is_some() {
            conditions.push("bs.bounty_id = $1".to_string());
        }
        if filters.verdict.is_some() {
            conditions.push(format!("bs.verdict = ${}", conditions.len() + 1));
        }

        let where_clause = if conditions.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", conditions.join(" AND "))
        };

        // Count query
        let count_sql = format!("SELECT COUNT(*) as cnt FROM bounty_submissions bs {where_clause}");
        let total: (i64,) = {
            let mut q = sqlx::query_as(&count_sql);
            if let Some(ref bounty_id) = filters.bounty_id {
                q = q.bind(bounty_id);
            }
            if let Some(ref verdict) = filters.verdict {
                q = q.bind(verdict);
            }
            q.fetch_one(&self.pool)
                .await
                .context("Failed to count submissions")?
        };

        // Data query
        let data_sql = format!(
            "SELECT bs.* FROM bounty_submissions bs {where_clause} ORDER BY bs.submitted_at DESC LIMIT {limit} OFFSET {offset}"
        );
        let submissions: Vec<crate::models::bounty::BountySubmission> = {
            let mut q = sqlx::query_as(&data_sql);
            if let Some(ref bounty_id) = filters.bounty_id {
                q = q.bind(bounty_id);
            }
            if let Some(ref verdict) = filters.verdict {
                q = q.bind(verdict);
            }
            q.fetch_all(&self.pool)
                .await
                .context("Failed to fetch submissions")?
        };

        Ok((submissions, total.0 as u32))
    }

    /// Get extended submission by ID (joins bounty_submissions + extended_submissions)
    pub async fn get_extended_submission_by_id(
        &self,
        submission_id: Uuid,
    ) -> Result<Option<crate::models::bounty::ExtendedSubmission>> {
        use crate::handlers::submission::SubmissionStatus;

        let row = sqlx::query(
            r#"
            SELECT
                bs.id, bs.bounty_id, bs.engine_id, bs.engine_name, bs.engine_address,
                bs.verdict, bs.confidence, bs.stake_amount, bs.details, bs.submitted_at, bs.is_verified,
                es.engine_version, es.threat_types, es.risk_score, es.analysis_summary,
                es.signatures, es.status, es.processing_metrics
            FROM bounty_submissions bs
            JOIN extended_submissions es ON es.submission_id = bs.id
            WHERE bs.id = $1
            "#,
        )
        .bind(submission_id)
        .fetch_optional(&self.pool)
        .await
        .context("Failed to fetch extended submission")?;

        match row {
            Some(r) => {
                let submission = crate::models::bounty::BountySubmission {
                    id: r.get("id"),
                    bounty_id: r.get("bounty_id"),
                    engine_id: r.get("engine_id"),
                    engine_name: r.get("engine_name"),
                    engine_address: r.get("engine_address"),
                    verdict: r.get("verdict"),
                    confidence: r.get("confidence"),
                    stake_amount: r.get("stake_amount"),
                    details: r.get("details"),
                    submitted_at: r.get("submitted_at"),
                    is_verified: r.get("is_verified"),
                };

                let status_str: String = r.get("status");
                let status = match status_str.as_str() {
                    "Processing" => SubmissionStatus::Processing,
                    "Completed" => SubmissionStatus::Completed,
                    "Failed" => SubmissionStatus::Failed,
                    "Disputed" => SubmissionStatus::Disputed,
                    "Verified" => SubmissionStatus::Verified,
                    _ => SubmissionStatus::Pending,
                };

                let metrics_json: Option<serde_json::Value> = r.get("processing_metrics");
                let processing_metrics = metrics_json.and_then(|v| {
                    serde_json::from_value::<crate::models::bounty::ProcessingMetrics>(v).ok()
                });

                Ok(Some(crate::models::bounty::ExtendedSubmission {
                    engine_name: submission.engine_name.clone(),
                    engine_version: r.get("engine_version"),
                    threat_types: r.get("threat_types"),
                    risk_score: {
                        let v: i16 = r.get("risk_score");
                        v as u8
                    },
                    analysis_summary: r.get("analysis_summary"),
                    signatures: r.get("signatures"),
                    status,
                    processing_metrics,
                    submission,
                }))
            }
            None => Ok(None),
        }
    }

    /// Update submission extended fields
    pub async fn update_submission(
        &self,
        submission_id: Uuid,
        updates: &crate::handlers::submission::UpdateSubmissionRequest,
    ) -> Result<crate::models::bounty::ExtendedSubmission> {
        // Update extended_submissions fields if provided
        if let Some(ref summary) = updates.analysis_summary {
            sqlx::query(
                "UPDATE extended_submissions SET analysis_summary = $1, updated_at = NOW() WHERE submission_id = $2"
            )
            .bind(summary)
            .bind(submission_id)
            .execute(&self.pool)
            .await
            .context("Failed to update analysis_summary")?;
        }

        if let Some(ref details) = updates.technical_details {
            sqlx::query("UPDATE bounty_submissions SET details = $1 WHERE id = $2")
                .bind(details)
                .bind(submission_id)
                .execute(&self.pool)
                .await
                .context("Failed to update technical_details")?;
        }

        if let Some(ref sigs) = updates.additional_signatures {
            sqlx::query(
                "UPDATE extended_submissions SET signatures = signatures || $1, updated_at = NOW() WHERE submission_id = $2"
            )
            .bind(sigs)
            .bind(submission_id)
            .execute(&self.pool)
            .await
            .context("Failed to update signatures")?;
        }

        // Re-fetch the full extended submission
        self.get_extended_submission_by_id(submission_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Submission {submission_id} not found after update"))
    }

    /// Delete a submission (cascade removes extended_submissions row)
    pub async fn delete_submission(&self, submission_id: Uuid) -> Result<()> {
        let result = sqlx::query("DELETE FROM bounty_submissions WHERE id = $1")
            .bind(submission_id)
            .execute(&self.pool)
            .await
            .context("Failed to delete submission")?;

        if result.rows_affected() == 0 {
            anyhow::bail!("Submission {submission_id} not found");
        }

        Ok(())
    }
}

// Helper structs for complex queries
#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct ConsensusResult {
    pub total_analyses: Option<i64>,
    pub avg_confidence: Option<f64>,
    pub malicious_count: Option<i64>,
    pub benign_count: Option<i64>,
    pub suspicious_count: Option<i64>,
}

impl ConsensusResult {
    pub fn get_consensus_verdict(&self) -> Option<String> {
        let malicious = self.malicious_count.unwrap_or(0);
        let benign = self.benign_count.unwrap_or(0);
        let suspicious = self.suspicious_count.unwrap_or(0);
        let total = self.total_analyses.unwrap_or(0);

        if total == 0 {
            return None;
        }

        if malicious > benign && malicious > suspicious {
            Some("malicious".to_string())
        } else if benign > malicious && benign > suspicious {
            Some("benign".to_string())
        } else {
            Some("suspicious".to_string())
        }
    }

    pub fn get_consensus_confidence(&self) -> f32 {
        self.avg_confidence.unwrap_or(0.0) as f32
    }
}

#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct UserAnalysisStats {
    pub total_analyses: Option<i64>,
    pub avg_confidence: Option<f64>,
    pub malicious_detections: Option<i64>,
    pub benign_detections: Option<i64>,
}

// Database connection helper
pub async fn create_connection_pool(database_url: &str) -> Result<PgPool> {
    PgPool::connect(database_url)
        .await
        .context("Failed to create database connection pool")
}

// Migration helper
pub async fn run_migrations(pool: &PgPool) -> Result<()> {
    sqlx::migrate!("./migrations")
        .run(pool)
        .await
        .context("Failed to run database migrations")?;

    Ok(())
}
