use chrono::{DateTime, Utc};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

pub type ReputationResult<T> = Result<T, ReputationError>;

#[derive(Debug, Error)]
pub enum ReputationError {
    #[error("Validation error: {0}")]
    ValidationError(String),

    #[error("Database error: {0}")]
    DatabaseError(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Calculation error: {0}")]
    CalculationError(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct UserReputation {
    pub user_id: Uuid,
    pub current_score: i32,
    pub highest_score: i32,
    pub lowest_score: i32,
    pub total_submissions: i32,
    pub correct_submissions: i32,
    pub incorrect_submissions: i32,
    pub accuracy_rate: Decimal,
    pub current_streak: i32,
    pub best_streak: i32,
    pub total_earned: Decimal,
    pub rank: Option<i32>,
    pub percentile: Option<Decimal>,
    pub last_updated: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineReputation {
    pub engine_id: String,
    pub user_id: Uuid,
    pub reputation_score: i32,
    pub total_analyses: i64,
    pub correct_analyses: i64,
    pub accuracy_rate: f64,
    pub avg_confidence: f64,
    pub specializations: Vec<String>,
    pub total_earnings: f64,
    pub total_losses: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct ReputationHistory {
    pub id: Uuid,
    pub user_id: Uuid,
    pub score_before: i32,
    pub score_after: i32,
    pub score_change: i32,
    pub reason: String,
    pub bounty_id: Option<Uuid>,
    pub submission_id: Option<Uuid>,
    pub details: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Badge {
    pub id: Uuid,
    pub name: String,
    pub description: String,
    pub icon: String,
    pub rarity: BadgeRarity,
    pub criteria: BadgeCriteria,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BadgeRarity {
    Common,
    Uncommon,
    Rare,
    Epic,
    Legendary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BadgeCriteria {
    pub min_score: Option<i32>,
    pub min_accuracy: Option<f64>,
    pub min_submissions: Option<i32>,
    pub min_streak: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct UserBadge {
    pub user_id: Uuid,
    pub badge_id: Uuid,
    pub awarded_at: DateTime<Utc>,
    pub progress: Option<Decimal>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ReputationUpdateRequest {
    pub user_id: Uuid,
    pub submission_id: Uuid,
    pub bounty_id: Uuid,
    pub was_correct: bool,
    pub confidence_score: Decimal,
    pub in_consensus: bool,
    pub was_early: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LeaderboardEntry {
    pub rank: i32,
    pub user_id: Uuid,
    pub username: String,
    pub score: i32,
    pub accuracy_rate: Decimal,
    pub total_submissions: i32,
    pub badges_count: i32,
    pub current_streak: i32,
    pub total_earned: Decimal,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ReputationStats {
    pub total_users: i64,
    pub avg_score: Decimal,
    pub median_score: Decimal,
    pub avg_accuracy: Decimal,
    pub score_distribution: Vec<ScoreDistribution>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ScoreDistribution {
    pub range_start: i32,
    pub range_end: i32,
    pub count: i64,
    pub percentage: Decimal,
}
