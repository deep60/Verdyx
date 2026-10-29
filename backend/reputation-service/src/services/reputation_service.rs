use anyhow::Result;
use redis::aio::ConnectionManager;
use rust_decimal::Decimal;
use sqlx::PgPool;
use uuid::Uuid;

use crate::config::Config;
use crate::models::*;
use crate::scoring::ReputationScorer;

pub struct ReputationService {
    config: Config,
    db_pool: PgPool,
    redis_conn: ConnectionManager,
    scorer: ReputationScorer,
}

impl ReputationService {
    pub async fn new(
        config: Config,
        db_pool: PgPool,
        redis_conn: ConnectionManager,
    ) -> Result<Self> {
        let scorer = ReputationScorer::new(config.reputation.clone());

        Ok(Self {
            config,
            db_pool,
            redis_conn,
            scorer,
        })
    }

    /// Fetch a user's reputation, creating a baseline row on first access.
    pub async fn get_or_create(&self, user_id: Uuid) -> ReputationResult<UserReputation> {
        if let Some(rep) = self.get(user_id).await? {
            return Ok(rep);
        }

        let base = self.config.reputation.base_score;
        sqlx::query(
            r#"
            INSERT INTO user_reputation
                (user_id, current_score, highest_score, lowest_score)
            VALUES ($1, $2, $2, $2)
            ON CONFLICT (user_id) DO NOTHING
            "#,
        )
        .bind(user_id)
        .bind(base)
        .execute(&self.db_pool)
        .await
        .map_err(|e| ReputationError::DatabaseError(e.to_string()))?;

        self.get(user_id)
            .await?
            .ok_or_else(|| ReputationError::NotFound(format!("user {user_id}")))
    }

    pub async fn get(&self, user_id: Uuid) -> ReputationResult<Option<UserReputation>> {
        sqlx::query_as::<_, UserReputation>(
            r#"
            SELECT user_id, current_score, highest_score, lowest_score,
                   total_submissions, correct_submissions, incorrect_submissions,
                   accuracy_rate, current_streak, best_streak, total_earned,
                   rank, percentile, last_updated, created_at
            FROM user_reputation
            WHERE user_id = $1
            "#,
        )
        .bind(user_id)
        .fetch_optional(&self.db_pool)
        .await
        .map_err(|e| ReputationError::DatabaseError(e.to_string()))
    }

    /// Apply a submission outcome to a user's reputation and log history.
    pub async fn apply_update(
        &self,
        update: &ReputationUpdateRequest,
    ) -> ReputationResult<UserReputation> {
        let current = self.get_or_create(update.user_id).await?;

        let change = self.scorer.calculate_score_change(&current, update);
        let score_before = current.current_score;
        let mut score_after = score_before + change;

        // Clamp to configured bounds.
        score_after = score_after
            .max(self.config.reputation.min_score)
            .min(self.config.reputation.max_score);

        let new_correct = current.correct_submissions + if update.was_correct { 1 } else { 0 };
        let new_incorrect = current.incorrect_submissions + if update.was_correct { 0 } else { 1 };
        let new_total = current.total_submissions + 1;
        let new_streak = if update.was_correct {
            current.current_streak + 1
        } else {
            0
        };
        let best_streak = current.best_streak.max(new_streak);
        let highest = current.highest_score.max(score_after);
        let lowest = current.lowest_score.min(score_after);
        let accuracy = ReputationScorer::calculate_accuracy(new_correct, new_total);

        let mut tx = self
            .db_pool
            .begin()
            .await
            .map_err(|e| ReputationError::DatabaseError(e.to_string()))?;

        sqlx::query(
            r#"
            UPDATE user_reputation
            SET current_score = $2,
                highest_score = $3,
                lowest_score = $4,
                total_submissions = $5,
                correct_submissions = $6,
                incorrect_submissions = $7,
                accuracy_rate = $8,
                current_streak = $9,
                best_streak = $10,
                last_updated = NOW()
            WHERE user_id = $1
            "#,
        )
        .bind(update.user_id)
        .bind(score_after)
        .bind(highest)
        .bind(lowest)
        .bind(new_total)
        .bind(new_correct)
        .bind(new_incorrect)
        .bind(accuracy)
        .bind(new_streak)
        .bind(best_streak)
        .execute(&mut *tx)
        .await
        .map_err(|e| ReputationError::DatabaseError(e.to_string()))?;

        let reason = if update.was_correct {
            "correct_analysis"
        } else {
            "incorrect_analysis"
        };

        sqlx::query(
            r#"
            INSERT INTO reputation_history
                (user_id, score_before, score_after, score_change, reason, bounty_id, submission_id, details)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            "#,
        )
        .bind(update.user_id)
        .bind(score_before)
        .bind(score_after)
        .bind(score_after - score_before)
        .bind(reason)
        .bind(update.bounty_id)
        .bind(update.submission_id)
        .bind(serde_json::json!({
            "in_consensus": update.in_consensus,
            "was_early": update.was_early,
            "confidence": update.confidence_score.to_string(),
        }))
        .execute(&mut *tx)
        .await
        .map_err(|e| ReputationError::DatabaseError(e.to_string()))?;

        tx.commit()
            .await
            .map_err(|e| ReputationError::DatabaseError(e.to_string()))?;

        // Award any newly-earned badges (best effort).
        let _ = self.evaluate_badges(update.user_id).await;
        // Invalidate cached leaderboard.
        let mut conn = self.redis_conn.clone();
        let _: Result<(), _> = redis::cmd("DEL")
            .arg("reputation:leaderboard")
            .query_async(&mut conn)
            .await;

        self.get(update.user_id)
            .await?
            .ok_or_else(|| ReputationError::NotFound(format!("user {}", update.user_id)))
    }

    pub async fn get_history(
        &self,
        user_id: Uuid,
        limit: i64,
    ) -> ReputationResult<Vec<ReputationHistory>> {
        sqlx::query_as::<_, ReputationHistory>(
            r#"
            SELECT id, user_id, score_before, score_after, score_change, reason,
                   bounty_id, submission_id, details, created_at
            FROM reputation_history
            WHERE user_id = $1
            ORDER BY created_at DESC
            LIMIT $2
            "#,
        )
        .bind(user_id)
        .bind(limit)
        .fetch_all(&self.db_pool)
        .await
        .map_err(|e| ReputationError::DatabaseError(e.to_string()))
    }

    pub async fn get_leaderboard(&self, limit: i64) -> ReputationResult<Vec<LeaderboardEntry>> {
        let rows = sqlx::query_as::<_, LeaderboardRow>(
            r#"
            SELECT user_id, current_score, accuracy_rate, total_submissions,
                   current_streak, total_earned,
                   ROW_NUMBER() OVER (ORDER BY current_score DESC)::int AS rank,
                   (SELECT COUNT(*) FROM user_badges b WHERE b.user_id = r.user_id)::int AS badges_count
            FROM user_reputation r
            ORDER BY current_score DESC
            LIMIT $1
            "#,
        )
        .bind(limit)
        .fetch_all(&self.db_pool)
        .await
        .map_err(|e| ReputationError::DatabaseError(e.to_string()))?;

        Ok(rows
            .into_iter()
            .map(|r| LeaderboardEntry {
                rank: r.rank,
                user_id: r.user_id,
                username: r.user_id.to_string(),
                score: r.current_score,
                accuracy_rate: r.accuracy_rate,
                total_submissions: r.total_submissions,
                badges_count: r.badges_count,
                current_streak: r.current_streak,
                total_earned: r.total_earned,
            })
            .collect())
    }

    pub async fn get_badges(&self, user_id: Uuid) -> ReputationResult<Vec<serde_json::Value>> {
        let rows = sqlx::query_as::<_, BadgeRow>(
            r#"
            SELECT b.id, b.name, b.description, b.icon, b.rarity, ub.awarded_at
            FROM user_badges ub
            JOIN badges b ON b.id = ub.badge_id
            WHERE ub.user_id = $1
            ORDER BY ub.awarded_at DESC
            "#,
        )
        .bind(user_id)
        .fetch_all(&self.db_pool)
        .await
        .map_err(|e| ReputationError::DatabaseError(e.to_string()))?;

        Ok(rows
            .into_iter()
            .map(|b| {
                serde_json::json!({
                    "id": b.id,
                    "name": b.name,
                    "description": b.description,
                    "icon": b.icon,
                    "rarity": b.rarity,
                    "awarded_at": b.awarded_at,
                })
            })
            .collect())
    }

    /// Award any badges whose criteria the user now satisfies.
    pub async fn evaluate_badges(&self, user_id: Uuid) -> ReputationResult<u64> {
        let result = sqlx::query(
            r#"
            INSERT INTO user_badges (user_id, badge_id, progress)
            SELECT r.user_id, b.id, 100.0
            FROM user_reputation r
            CROSS JOIN badges b
            WHERE r.user_id = $1
              AND (b.min_score IS NULL OR r.current_score >= b.min_score)
              AND (b.min_accuracy IS NULL OR r.accuracy_rate >= b.min_accuracy)
              AND (b.min_submissions IS NULL OR r.total_submissions >= b.min_submissions)
              AND (b.min_streak IS NULL OR r.best_streak >= b.min_streak)
            ON CONFLICT (user_id, badge_id) DO NOTHING
            "#,
        )
        .bind(user_id)
        .execute(&self.db_pool)
        .await
        .map_err(|e| ReputationError::DatabaseError(e.to_string()))?;

        Ok(result.rows_affected())
    }

    /// Recompute ranks/percentiles for every user. Run by the worker.
    pub async fn recompute_ranks(&self) -> ReputationResult<u64> {
        let result = sqlx::query(
            r#"
            WITH ranked AS (
                SELECT user_id,
                       ROW_NUMBER() OVER (ORDER BY current_score DESC) AS rnk,
                       COUNT(*) OVER () AS total
                FROM user_reputation
            )
            UPDATE user_reputation u
            SET rank = ranked.rnk::int,
                percentile = ROUND(((ranked.total - ranked.rnk + 1)::numeric / ranked.total) * 100, 2)
            FROM ranked
            WHERE u.user_id = ranked.user_id
            "#,
        )
        .execute(&self.db_pool)
        .await
        .map_err(|e| ReputationError::DatabaseError(e.to_string()))?;

        Ok(result.rows_affected())
    }

    /// Apply inactivity decay to all users not updated within `idle_days`.
    pub async fn apply_decay_all(&self, idle_days: f64) -> ReputationResult<u64> {
        let users = sqlx::query_as::<_, (Uuid, i32)>(
            r#"
            SELECT user_id, current_score
            FROM user_reputation
            WHERE last_updated < NOW() - ($1 || ' days')::interval
            "#,
        )
        .bind(idle_days.to_string())
        .fetch_all(&self.db_pool)
        .await
        .map_err(|e| ReputationError::DatabaseError(e.to_string()))?;

        let mut updated = 0u64;
        for (user_id, score) in users {
            let new_score = self.scorer.apply_decay(score, idle_days);
            if new_score != score {
                sqlx::query(
                    "UPDATE user_reputation SET current_score = $2, last_updated = NOW() WHERE user_id = $1",
                )
                .bind(user_id)
                .bind(new_score)
                .execute(&self.db_pool)
                .await
                .map_err(|e| ReputationError::DatabaseError(e.to_string()))?;
                updated += 1;
            }
        }
        Ok(updated)
    }

    pub async fn reset(&self, user_id: Uuid) -> ReputationResult<()> {
        let base = self.config.reputation.base_score;
        sqlx::query(
            r#"
            UPDATE user_reputation
            SET current_score = $2, highest_score = $2, lowest_score = $2,
                total_submissions = 0, correct_submissions = 0, incorrect_submissions = 0,
                accuracy_rate = 0, current_streak = 0, best_streak = 0, last_updated = NOW()
            WHERE user_id = $1
            "#,
        )
        .bind(user_id)
        .bind(base)
        .execute(&self.db_pool)
        .await
        .map_err(|e| ReputationError::DatabaseError(e.to_string()))?;
        Ok(())
    }

    pub async fn cache_leaderboard(&self) -> ReputationResult<()> {
        let board = self.get_leaderboard(100).await?;
        let json = serde_json::to_string(&board)
            .map_err(|e| ReputationError::CalculationError(e.to_string()))?;
        let mut conn = self.redis_conn.clone();
        let _: Result<(), _> = redis::cmd("SET")
            .arg("reputation:leaderboard")
            .arg(json)
            .arg("EX")
            .arg(300)
            .query_async(&mut conn)
            .await;
        Ok(())
    }
}

#[derive(sqlx::FromRow)]
struct LeaderboardRow {
    user_id: Uuid,
    current_score: i32,
    accuracy_rate: Decimal,
    total_submissions: i32,
    current_streak: i32,
    total_earned: Decimal,
    rank: i32,
    badges_count: i32,
}

#[derive(sqlx::FromRow)]
struct BadgeRow {
    id: Uuid,
    name: String,
    description: String,
    icon: String,
    rarity: String,
    awarded_at: chrono::DateTime<chrono::Utc>,
}
