/// Database operations for analysis results persistence
///
/// This module handles all PostgreSQL database operations including:
/// - Connection pool management
/// - Analysis result CRUD operations
/// - Query optimization
/// - Transaction management

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use sqlx::postgres::{PgPool, PgPoolOptions};
use sqlx::Row;
use std::time::Duration;
use thiserror::Error;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use crate::models::analysis_result::{AnalysisResult, AnalysisStatus, ThreatVerdict};

/// Database error types
#[derive(Debug, Error)]
pub enum DatabaseError {
    #[error("Connection error: {0}")]
    ConnectionError(String),

    #[error("Query error: {0}")]
    QueryError(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Database error: {0}")]
    Other(#[from] anyhow::Error),
}

impl From<sqlx::Error> for DatabaseError {
    fn from(err: sqlx::Error) -> Self {
        match err {
            sqlx::Error::RowNotFound => DatabaseError::NotFound("Record not found".to_string()),
            sqlx::Error::PoolTimedOut => {
                DatabaseError::ConnectionError("Connection pool timeout".to_string())
            }
            _ => DatabaseError::QueryError(err.to_string()),
        }
    }
}

/// Database configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub database: String,
    pub max_connections: u32,
    pub min_connections: u32,
    pub connect_timeout_seconds: u64,
    pub idle_timeout_seconds: u64,
    pub max_lifetime_seconds: u64,
    pub ssl_mode: SslMode,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SslMode {
    Disable,
    Prefer,
    Require,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            host: "localhost".to_string(),
            port: 5432,
            username: "postgres".to_string(),
            password: "postgres".to_string(),
            database: "verdyx".to_string(),
            max_connections: 20,
            min_connections: 2,
            connect_timeout_seconds: 10,
            idle_timeout_seconds: 600,
            max_lifetime_seconds: 1800,
            ssl_mode: SslMode::Prefer,
        }
    }
}

impl DatabaseConfig {
    /// Build database URL from configuration
    pub fn database_url(&self) -> String {
        format!(
            "postgresql://{}:{}@{}:{}/{}",
            self.username, self.password, self.host, self.port, self.database
        )
    }
}

/// Database client for analysis engine
pub struct Database {
    pool: PgPool,
    config: DatabaseConfig,
}

impl Database {
    /// Create a new database client
    pub async fn new(config: DatabaseConfig) -> Result<Self> {
        info!("Connecting to database at {}:{}", config.host, config.port);

        let database_url = config.database_url();

        let pool = PgPoolOptions::new()
            .max_connections(config.max_connections)
            .min_connections(config.min_connections)
            .acquire_timeout(Duration::from_secs(config.connect_timeout_seconds))
            .idle_timeout(Duration::from_secs(config.idle_timeout_seconds))
            .max_lifetime(Duration::from_secs(config.max_lifetime_seconds))
            .connect(&database_url)
            .await
            .context("Failed to connect to database")?;

        info!("Database connection pool established");

        // Run migrations
        Self::run_migrations(&pool).await?;

        Ok(Self { pool, config })
    }

    /// Run database migrations
    async fn run_migrations(pool: &PgPool) -> Result<()> {
        info!("Running database migrations");

        // Create analyses table if not exists
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS analyses (
                id UUID PRIMARY KEY,
                submission_id UUID NOT NULL,
                bounty_id UUID,
                status VARCHAR(50) NOT NULL,
                verdict VARCHAR(50) NOT NULL,
                confidence FLOAT NOT NULL,
                severity VARCHAR(50) NOT NULL,
                file_metadata JSONB NOT NULL,
                detections JSONB NOT NULL,
                yara_matches JSONB,
                network_indicators JSONB,
                behavioral_analysis JSONB,
                tags TEXT[],
                notes TEXT,
                started_at TIMESTAMP WITH TIME ZONE NOT NULL,
                completed_at TIMESTAMP WITH TIME ZONE,
                processing_time_ms BIGINT,
                error_message TEXT,
                analysis_cost FLOAT,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
            )
            "#,
        )
        .execute(pool)
        .await
        .context("Failed to create analyses table")?;

        // Create index on submission_id for faster lookups
        sqlx::query(
            r#"
            CREATE INDEX IF NOT EXISTS idx_analyses_submission_id
            ON analyses(submission_id)
            "#,
        )
        .execute(pool)
        .await
        .context("Failed to create index")?;

        // Create index on status for filtering
        sqlx::query(
            r#"
            CREATE INDEX IF NOT EXISTS idx_analyses_status
            ON analyses(status)
            "#,
        )
        .execute(pool)
        .await
        .context("Failed to create index")?;

        // Create index on verdict
        sqlx::query(
            r#"
            CREATE INDEX IF NOT EXISTS idx_analyses_verdict
            ON analyses(verdict)
            "#,
        )
        .execute(pool)
        .await
        .context("Failed to create index")?;

        // Create index on created_at for time-based queries
        sqlx::query(
            r#"
            CREATE INDEX IF NOT EXISTS idx_analyses_created_at
            ON analyses(created_at DESC)
            "#,
        )
        .execute(pool)
        .await
        .context("Failed to create index")?;

        // Create artifacts table for storing file metadata
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS artifacts (
                id UUID PRIMARY KEY,
                analysis_id UUID NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
                filename VARCHAR(500),
                file_size BIGINT NOT NULL,
                mime_type VARCHAR(100),
                md5 VARCHAR(32),
                sha1 VARCHAR(40),
                sha256 VARCHAR(64) NOT NULL,
                sha512 VARCHAR(128),
                s3_key VARCHAR(500),
                uploaded_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
            )
            "#,
        )
        .execute(pool)
        .await
        .context("Failed to create artifacts table")?;

        // Create index on sha256 for deduplication
        sqlx::query(
            r#"
            CREATE INDEX IF NOT EXISTS idx_artifacts_sha256
            ON artifacts(sha256)
            "#,
        )
        .execute(pool)
        .await
        .context("Failed to create index")?;

        info!("Database migrations completed successfully");
        Ok(())
    }

    /// Save analysis result to database
    pub async fn save_analysis_result(&self, result: &AnalysisResult) -> Result<()> {
        debug!("Saving analysis result: {}", result.analysis_id);

        let verdict = format!("{:?}", result.consensus_verdict);
        let status = format!("{:?}", result.status);
        let severity = format!("{:?}", result.consensus_severity);

        // Postgres rejects NUL in jsonb; strings pulled from binaries carry it.
        use crate::models::analysis_result::without_nul;
        let file_metadata = without_nul(
            serde_json::to_value(&result.file_metadata)
                .context("Failed to serialize file metadata")?,
        );

        let detections = without_nul(
            serde_json::to_value(&result.detections).context("Failed to serialize detections")?,
        );

        let yara_matches = without_nul(
            serde_json::to_value(&result.yara_matches)
                .context("Failed to serialize yara matches")?,
        );

        let network_indicators = without_nul(
            serde_json::to_value(&result.network_indicators)
                .context("Failed to serialize network indicators")?,
        );

        let behavioral_analysis = without_nul(
            serde_json::to_value(&result.behavioral_analysis)
                .context("Failed to serialize behavioral analysis")?,
        );

        sqlx::query(
            r#"
            INSERT INTO analyses (
                id, submission_id, bounty_id, status, verdict, confidence, severity,
                file_metadata, detections, yara_matches, network_indicators,
                behavioral_analysis, tags, notes, started_at, completed_at,
                processing_time_ms, error_message, analysis_cost
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19)
            ON CONFLICT (id) DO UPDATE SET
                status = EXCLUDED.status,
                verdict = EXCLUDED.verdict,
                confidence = EXCLUDED.confidence,
                severity = EXCLUDED.severity,
                detections = EXCLUDED.detections,
                yara_matches = EXCLUDED.yara_matches,
                network_indicators = EXCLUDED.network_indicators,
                behavioral_analysis = EXCLUDED.behavioral_analysis,
                tags = EXCLUDED.tags,
                notes = EXCLUDED.notes,
                completed_at = EXCLUDED.completed_at,
                processing_time_ms = EXCLUDED.processing_time_ms,
                error_message = EXCLUDED.error_message,
                analysis_cost = EXCLUDED.analysis_cost,
                updated_at = NOW()
            "#,
        )
        .bind(result.analysis_id)
        .bind(result.submission_id)
        .bind(result.bounty_id)
        .bind(status)
        .bind(verdict)
        .bind(result.consensus_confidence)
        .bind(severity)
        .bind(file_metadata)
        .bind(detections)
        .bind(yara_matches)
        .bind(network_indicators)
        .bind(behavioral_analysis)
        .bind(&result.tags)
        .bind(&result.notes)
        .bind(result.started_at)
        .bind(result.completed_at)
        .bind(result.total_processing_time_ms.map(|t| t as i64))
        .bind(&result.error_message)
        .bind(result.analysis_cost)
        .execute(&self.pool)
        .await
        .context("Failed to insert analysis result")?;

        debug!("Analysis result saved successfully");
        Ok(())
    }

    /// Get analysis result by ID
    pub async fn get_analysis_result(&self, analysis_id: &Uuid) -> Result<Option<AnalysisResult>> {
        debug!("Fetching analysis result: {}", analysis_id);

        let row = sqlx::query(
            r#"
            SELECT
                id, submission_id, bounty_id, status, verdict, confidence, severity,
                file_metadata, detections, yara_matches, network_indicators,
                behavioral_analysis, tags, notes, started_at, completed_at,
                processing_time_ms, error_message, analysis_cost
            FROM analyses
            WHERE id = $1
            "#,
        )
        .bind(analysis_id)
        .fetch_optional(&self.pool)
        .await?;

        if let Some(row) = row {
            let file_metadata: serde_json::Value = row.try_get("file_metadata")?;
            let file_metadata = serde_json::from_value(file_metadata)
                .context("Failed to deserialize file metadata")?;

            let detections: serde_json::Value = row.try_get("detections")?;
            let detections =
                serde_json::from_value(detections).context("Failed to deserialize detections")?;

            let yara_matches: Option<serde_json::Value> = row.try_get("yara_matches")?;
            let yara_matches = yara_matches
                .map(|v| serde_json::from_value(v).ok())
                .flatten()
                .unwrap_or_default();

            let network_indicators: Option<serde_json::Value> =
                row.try_get("network_indicators")?;
            let network_indicators = network_indicators
                .and_then(|v| serde_json::from_value(v).ok());

            let behavioral_analysis: Option<serde_json::Value> =
                row.try_get("behavioral_analysis")?;
            let behavioral_analysis = behavioral_analysis
                .and_then(|v| serde_json::from_value(v).ok());

            let verdict_str: String = row.try_get("verdict")?;
            let consensus_verdict = match verdict_str.as_str() {
                "Malicious" => ThreatVerdict::Malicious,
                "Benign" => ThreatVerdict::Benign,
                "Suspicious" => ThreatVerdict::Suspicious,
                _ => ThreatVerdict::Unknown,
            };

            let status_str: String = row.try_get("status")?;
            let status = match status_str.as_str() {
                "Pending" => AnalysisStatus::Pending,
                "InProgress" => AnalysisStatus::InProgress,
                "Completed" => AnalysisStatus::Completed,
                "Failed" => AnalysisStatus::Failed,
                _ => AnalysisStatus::Pending,
            };

            let processing_time: Option<i64> = row.try_get("processing_time_ms")?;

            Ok(Some(AnalysisResult {
                analysis_id: row.try_get("id")?,
                submission_id: row.try_get("submission_id")?,
                bounty_id: row.try_get("bounty_id")?,
                file_metadata,
                consensus_verdict,
                consensus_confidence: row.try_get("confidence")?,
                consensus_severity: serde_json::from_str(&row.try_get::<String, _>("severity")?)
                    .unwrap_or_default(),
                detections,
                yara_matches,
                network_indicators,
                behavioral_analysis,
                tags: row.try_get("tags")?,
                notes: row.try_get("notes")?,
                started_at: row.try_get("started_at")?,
                completed_at: row.try_get("completed_at")?,
                total_processing_time_ms: processing_time.map(|t| t as u64),
                status,
                error_message: row.try_get("error_message")?,
                analysis_cost: row.try_get("analysis_cost")?,
                engine_reputations: std::collections::HashMap::new(),
            }))
        } else {
            Ok(None)
        }
    }

    /// Get analyses by submission ID
    pub async fn get_analyses_by_submission(
        &self,
        submission_id: &Uuid,
    ) -> Result<Vec<AnalysisResult>> {
        debug!("Fetching analyses for submission: {}", submission_id);

        let rows = sqlx::query(
            r#"
            SELECT id FROM analyses
            WHERE submission_id = $1
            ORDER BY created_at DESC
            "#,
        )
        .bind(submission_id)
        .fetch_all(&self.pool)
        .await?;

        let mut results = Vec::new();
        for row in rows {
            let id: Uuid = row.try_get("id")?;
            if let Some(result) = self.get_analysis_result(&id).await? {
                results.push(result);
            }
        }

        Ok(results)
    }

    /// Get recent analyses with pagination
    pub async fn get_recent_analyses(
        &self,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<AnalysisResult>> {
        debug!("Fetching recent analyses (limit: {}, offset: {})", limit, offset);

        let rows = sqlx::query(
            r#"
            SELECT id FROM analyses
            ORDER BY created_at DESC
            LIMIT $1 OFFSET $2
            "#,
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;

        let mut results = Vec::new();
        for row in rows {
            let id: Uuid = row.try_get("id")?;
            if let Some(result) = self.get_analysis_result(&id).await? {
                results.push(result);
            }
        }

        Ok(results)
    }

    /// Get analyses by verdict
    pub async fn get_analyses_by_verdict(
        &self,
        verdict: ThreatVerdict,
    ) -> Result<Vec<AnalysisResult>> {
        let verdict_str = format!("{:?}", verdict);
        debug!("Fetching analyses with verdict: {}", verdict_str);

        let rows = sqlx::query(
            r#"
            SELECT id FROM analyses
            WHERE verdict = $1
            ORDER BY created_at DESC
            LIMIT 100
            "#,
        )
        .bind(verdict_str)
        .fetch_all(&self.pool)
        .await?;

        let mut results = Vec::new();
        for row in rows {
            let id: Uuid = row.try_get("id")?;
            if let Some(result) = self.get_analysis_result(&id).await? {
                results.push(result);
            }
        }

        Ok(results)
    }

    /// Delete analysis result
    pub async fn delete_analysis(&self, analysis_id: &Uuid) -> Result<bool> {
        debug!("Deleting analysis: {}", analysis_id);

        let result = sqlx::query(
            r#"
            DELETE FROM analyses
            WHERE id = $1
            "#,
        )
        .bind(analysis_id)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Count total analyses
    pub async fn count_analyses(&self) -> Result<i64> {
        let row = sqlx::query("SELECT COUNT(*) as count FROM analyses")
            .fetch_one(&self.pool)
            .await?;

        let count: i64 = row.try_get("count")?;
        Ok(count)
    }

    /// Count analyses by status
    pub async fn count_by_status(&self, status: AnalysisStatus) -> Result<i64> {
        let status_str = format!("{:?}", status);

        let row = sqlx::query(
            r#"
            SELECT COUNT(*) as count FROM analyses
            WHERE status = $1
            "#,
        )
        .bind(status_str)
        .fetch_one(&self.pool)
        .await?;

        let count: i64 = row.try_get("count")?;
        Ok(count)
    }

    /// Get database statistics
    pub async fn get_stats(&self) -> DatabaseStats {
        let active_connections = self.pool.size() as usize;
        let idle_connections = self.pool.num_idle();

        let total_records = self.count_analyses().await.unwrap_or(0) as u64;

        DatabaseStats {
            active_connections,
            idle_connections,
            total_records,
        }
    }

    /// Health check
    pub async fn health_check(&self) -> bool {
        sqlx::query("SELECT 1")
            .fetch_one(&self.pool)
            .await
            .is_ok()
    }

    /// Close database connection
    pub async fn close(&self) {
        self.pool.close().await;
        info!("Database connection closed");
    }
}

/// Database statistics
#[derive(Debug, Clone)]
pub struct DatabaseStats {
    pub active_connections: usize,
    pub idle_connections: usize,
    pub total_records: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_database_config_url() {
        let config = DatabaseConfig::default();
        let url = config.database_url();
        assert!(url.contains("postgresql://"));
        assert!(url.contains("localhost:5432"));
    }

    #[test]
    fn test_database_config_custom() {
        let config = DatabaseConfig {
            host: "db.example.com".to_string(),
            port: 5433,
            username: "user".to_string(),
            password: "pass".to_string(),
            database: "testdb".to_string(),
            ..Default::default()
        };

        let url = config.database_url();
        assert!(url.contains("db.example.com:5433"));
        assert!(url.contains("testdb"));
    }
}
