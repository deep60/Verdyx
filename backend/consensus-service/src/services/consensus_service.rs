use anyhow::Result;
use chrono::{DateTime, Utc};
use redis::aio::ConnectionManager;
use rust_decimal::prelude::ToPrimitive;
use rust_decimal::Decimal;
use sqlx::PgPool;
use uuid::Uuid;

use crate::aggregation::ConsensusAggregator;
use crate::config::Config;
use crate::models::*;

/// Core consensus service: owns DB access, the aggregator, and the cache.
pub struct ConsensusService {
    config: Config,
    db_pool: PgPool,
    redis_conn: ConnectionManager,
    aggregator: ConsensusAggregator,
}

impl ConsensusService {
    pub async fn new(
        config: Config,
        db_pool: PgPool,
        redis_conn: ConnectionManager,
    ) -> Result<Self> {
        let aggregator = ConsensusAggregator::new(config.consensus.clone());

        Ok(Self {
            config,
            db_pool,
            redis_conn,
            aggregator,
        })
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Load all votes recorded for a bounty.
    pub async fn load_votes(&self, bounty_id: Uuid) -> ConsensusResult<Vec<SubmissionVote>> {
        let rows = sqlx::query_as::<_, VoteRow>(
            r#"
            SELECT id, bounty_id, engine_id, verdict, confidence, reputation_score,
                   submitted_at, sample_hash
            FROM consensus_submissions
            WHERE bounty_id = $1
            ORDER BY submitted_at ASC
            "#,
        )
        .bind(bounty_id)
        .fetch_all(&self.db_pool)
        .await
        .map_err(|e| ConsensusError::DatabaseError(e.to_string()))?;

        Ok(rows
            .into_iter()
            .map(|r| SubmissionVote {
                submission_id: r.id,
                user_id: r.id, // engine submissions are keyed by engine; reuse id as placeholder
                engine_id: r.engine_id,
                verdict: parse_verdict(&r.verdict),
                confidence: r.confidence,
                reputation_score: r.reputation_score,
                submitted_at: r.submitted_at,
                sample_hash: r.sample_hash,
            })
            .collect())
    }

    /// Record (or update) a single engine's vote for a bounty.
    /// `sample_hash` identifies the artifact voted on. It is what makes delayed
    /// re-grading possible, so callers should always supply it; a vote without
    /// one still counts toward consensus but leaves the bounty ungradable.
    pub async fn record_vote(
        &self,
        bounty_id: Uuid,
        engine_id: &str,
        verdict: &Verdict,
        confidence: Decimal,
        reputation_score: i32,
        sample_hash: Option<&str>,
    ) -> ConsensusResult<()> {
        // When commit-reveal is on, this path must be shut. Leaving it open
        // would let anyone skip the commitment entirely, vote in the clear
        // after watching the tally, and defeat the whole mechanism -- while
        // the system still reported itself as using commit-reveal.
        if self.config.commit_reveal.enabled {
            return Err(ConsensusError::ValidationError(
                "commit-reveal voting is enabled; use the commit and reveal endpoints"
                    .to_string(),
            ));
        }

        sqlx::query(
            r#"
            INSERT INTO consensus_submissions
                (bounty_id, engine_id, verdict, confidence, reputation_score, sample_hash)
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (bounty_id, engine_id)
            DO UPDATE SET verdict = EXCLUDED.verdict,
                          confidence = EXCLUDED.confidence,
                          reputation_score = EXCLUDED.reputation_score,
                          sample_hash = COALESCE(EXCLUDED.sample_hash,
                                                 consensus_submissions.sample_hash),
                          submitted_at = NOW()
            "#,
        )
        .bind(bounty_id)
        .bind(engine_id)
        .bind(verdict.to_string())
        .bind(confidence)
        .bind(reputation_score)
        .bind(sample_hash)
        .execute(&self.db_pool)
        .await
        .map_err(|e| ConsensusError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    /// Compute consensus for a bounty and persist the result.
    pub async fn calculate_and_store(
        &self,
        bounty_id: Uuid,
        finalize: bool,
    ) -> ConsensusResult<ConsensusResponse> {
        let votes = self.load_votes(bounty_id).await?;

        if votes.len() < self.config.consensus.min_submissions {
            return Err(ConsensusError::InsufficientSubmissions {
                required: self.config.consensus.min_submissions,
                actual: votes.len(),
            });
        }

        let (verdict, confidence, distribution) = self.aggregator.calculate_consensus(&votes);
        let agreement = self.aggregator.calculate_agreement_score(&distribution);
        let can_dispute = self.aggregator.can_be_disputed(agreement);

        let engines: Vec<String> = votes.iter().map(|v| v.engine_id.clone()).collect();
        let distribution_json = serde_json::to_value(&distribution)
            .map_err(|e| ConsensusError::ConsensusFailed(e.to_string()))?;

        let counts = count_verdicts(&votes);

        // Promote the sample hash from the votes onto the result so the
        // regrader can re-scan this bounty later. Voters should all be looking
        // at the same artifact; if they disagree, the majority wins.
        let sample_hash = majority_sample_hash(&votes);

        sqlx::query(
            r#"
            INSERT INTO consensus_results
                (bounty_id, final_verdict, confidence, total_submissions,
                 malicious_count, benign_count, suspicious_count, unknown_count,
                 weighted_voting, agreement_score, is_disputed, is_finalized,
                 finalized_at, participating_engines, verdict_distribution,
                 sample_hash, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, NOW())
            ON CONFLICT (bounty_id) DO UPDATE SET
                final_verdict = EXCLUDED.final_verdict,
                confidence = EXCLUDED.confidence,
                total_submissions = EXCLUDED.total_submissions,
                malicious_count = EXCLUDED.malicious_count,
                benign_count = EXCLUDED.benign_count,
                suspicious_count = EXCLUDED.suspicious_count,
                unknown_count = EXCLUDED.unknown_count,
                agreement_score = EXCLUDED.agreement_score,
                is_disputed = EXCLUDED.is_disputed,
                is_finalized = EXCLUDED.is_finalized,
                finalized_at = EXCLUDED.finalized_at,
                participating_engines = EXCLUDED.participating_engines,
                verdict_distribution = EXCLUDED.verdict_distribution,
                sample_hash = COALESCE(EXCLUDED.sample_hash, consensus_results.sample_hash),
                updated_at = NOW()
            "#,
        )
        .bind(bounty_id)
        .bind(verdict.to_string())
        .bind(confidence)
        .bind(votes.len() as i32)
        .bind(counts.malicious)
        .bind(counts.benign)
        .bind(counts.suspicious)
        .bind(counts.unknown)
        .bind(self.config.consensus.weighted_voting)
        .bind(agreement)
        .bind(can_dispute)
        .bind(finalize)
        .bind(if finalize { Some(Utc::now()) } else { None })
        .bind(&engines)
        .bind(&distribution_json)
        .bind(sample_hash.as_deref())
        .execute(&self.db_pool)
        .await
        .map_err(|e| ConsensusError::DatabaseError(e.to_string()))?;

        // Best-effort cache invalidation of the cached response.
        let mut conn = self.redis_conn.clone();
        let _: Result<(), _> = redis::cmd("DEL")
            .arg(format!("consensus:{bounty_id}"))
            .query_async(&mut conn)
            .await;

        Ok(ConsensusResponse {
            bounty_id,
            final_verdict: verdict,
            confidence_score: confidence,
            agreement_score: agreement,
            verdict_distribution: distribution,
            total_submissions: votes.len(),
            is_finalized: finalize,
            can_be_disputed: can_dispute,
        })
    }

    /// Read a previously stored consensus result for a bounty.
    pub async fn get_stored(&self, bounty_id: Uuid) -> ConsensusResult<Option<ConsensusResponse>> {
        let row = sqlx::query_as::<_, ResultRow>(
            r#"
            SELECT bounty_id, final_verdict, confidence, total_submissions,
                   agreement_score, is_finalized, verdict_distribution
            FROM consensus_results
            WHERE bounty_id = $1
            "#,
        )
        .bind(bounty_id)
        .fetch_optional(&self.db_pool)
        .await
        .map_err(|e| ConsensusError::DatabaseError(e.to_string()))?;

        let Some(row) = row else {
            return Ok(None);
        };

        let distribution: VerdictDistribution =
            serde_json::from_value(row.verdict_distribution).unwrap_or_default();
        let agreement = row.agreement_score;
        let can_dispute = self.aggregator.can_be_disputed(agreement);

        Ok(Some(ConsensusResponse {
            bounty_id: row.bounty_id,
            final_verdict: parse_verdict(&row.final_verdict),
            confidence_score: row.confidence,
            agreement_score: agreement,
            verdict_distribution: distribution,
            total_submissions: row.total_submissions.to_usize().unwrap_or(0),
            is_finalized: row.is_finalized,
            can_be_disputed: can_dispute,
        }))
    }

    /// Bounties that have enough votes but no finalized result yet,
    /// past the auto-finalize window. Used by the background worker.
    pub async fn find_finalizable_bounties(&self) -> ConsensusResult<Vec<Uuid>> {
        let window_hours = self.config.consensus.auto_finalize_hours as i64;
        let min = self.config.consensus.min_submissions as i64;

        let rows = sqlx::query_scalar::<_, Uuid>(
            r#"
            SELECT s.bounty_id
            FROM consensus_submissions s
            LEFT JOIN consensus_results r ON r.bounty_id = s.bounty_id
            WHERE (r.is_finalized IS NULL OR r.is_finalized = false)
            GROUP BY s.bounty_id
            HAVING COUNT(*) >= $1
               AND MIN(s.submitted_at) <= NOW() - ($2 || ' hours')::interval
            "#,
        )
        .bind(min)
        .bind(window_hours.to_string())
        .fetch_all(&self.db_pool)
        .await
        .map_err(|e| ConsensusError::DatabaseError(e.to_string()))?;

        Ok(rows)
    }

    // -- Commit-reveal voting ---------------------------------------------

    /// Which phase a bounty is in, and when that phase ends.
    ///
    /// The clock is anchored on the bounty's first commit rather than on a
    /// stored deadline: consensus-service does not own the bounty record, and
    /// the first commit is the moment voting demonstrably opened.
    pub async fn voting_phase(&self, bounty_id: Uuid) -> ConsensusResult<PhaseStatus> {
        let cfg = &self.config.commit_reveal;

        let row: (Option<DateTime<Utc>>, i64, i64) = sqlx::query_as(
            r#"
            SELECT MIN(committed_at),
                   COUNT(*)::bigint,
                   COUNT(*) FILTER (WHERE revealed_at IS NOT NULL)::bigint
            FROM consensus_vote_commits
            WHERE bounty_id = $1
            "#,
        )
        .bind(bounty_id)
        .fetch_one(&self.db_pool)
        .await
        .map_err(|e| ConsensusError::DatabaseError(e.to_string()))?;

        let (first_commit, total, revealed) = row;

        // No commits yet: the clock has not started, so commits are open.
        let Some(opened_at) = first_commit else {
            return Ok(PhaseStatus {
                bounty_id,
                phase: VotingPhase::Commit,
                total_commits: 0,
                revealed: 0,
                phase_ends_at: None,
            });
        };

        let commit_ends = opened_at + chrono::Duration::hours(cfg.commit_window_hours as i64);
        let reveal_ends = commit_ends + chrono::Duration::hours(cfg.reveal_window_hours as i64);
        let now = Utc::now();

        let (phase, ends_at) = if now < commit_ends {
            (VotingPhase::Commit, Some(commit_ends))
        } else if now < reveal_ends {
            (VotingPhase::Reveal, Some(reveal_ends))
        } else {
            (VotingPhase::Closed, None)
        };

        Ok(PhaseStatus {
            bounty_id,
            phase,
            total_commits: total,
            revealed,
            phase_ends_at: ends_at,
        })
    }

    /// Record a commitment. Nothing about the vote is disclosed.
    ///
    /// Re-committing while the window is open is allowed and simply replaces
    /// the previous commitment: no information has leaked, so a voter changing
    /// their mind in private is harmless. Once the window shuts, or once the
    /// vote has been revealed, the commitment is frozen.
    pub async fn commit_vote(
        &self,
        bounty_id: Uuid,
        engine_id: &str,
        commitment: &str,
    ) -> ConsensusResult<()> {
        if !crate::commitment::is_well_formed(commitment) {
            return Err(ConsensusError::ValidationError(
                "commitment must be 64 hex characters (sha256)".to_string(),
            ));
        }

        let status = self.voting_phase(bounty_id).await?;
        if status.phase != VotingPhase::Commit {
            return Err(ConsensusError::ValidationError(format!(
                "the commit window for this bounty has closed (phase: {})",
                status.phase.to_string()
            )));
        }

        let commitment = commitment.trim().to_ascii_lowercase();

        // The WHERE clause is the freeze: an already-revealed commitment can
        // never be rewritten, so a voter cannot reveal, see the tally move,
        // and then substitute a different commitment.
        sqlx::query(
            r#"
            INSERT INTO consensus_vote_commits (bounty_id, engine_id, commitment)
            VALUES ($1, $2, $3)
            ON CONFLICT (bounty_id, engine_id) DO UPDATE
                SET commitment = EXCLUDED.commitment,
                    committed_at = NOW()
                WHERE consensus_vote_commits.revealed_at IS NULL
            "#,
        )
        .bind(bounty_id)
        .bind(engine_id.trim())
        .bind(&commitment)
        .execute(&self.db_pool)
        .await
        .map_err(|e| ConsensusError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    /// Reveal a committed vote, verifying it against the stored commitment.
    ///
    /// On success the vote becomes an ordinary row in `consensus_submissions`
    /// -- from the aggregator's point of view nothing about commit-reveal is
    /// visible, it simply sees votes appear during the reveal window.
    pub async fn reveal_vote(
        &self,
        bounty_id: Uuid,
        req: &RevealVoteRequest,
    ) -> ConsensusResult<()> {
        let cfg = &self.config.commit_reveal;

        if req.salt.len() < cfg.min_salt_len {
            return Err(ConsensusError::ValidationError(format!(
                "salt must be at least {} characters",
                cfg.min_salt_len
            )));
        }

        let status = self.voting_phase(bounty_id).await?;
        match status.phase {
            VotingPhase::Reveal => {}
            VotingPhase::Commit => {
                // Revealing early would republish the vote to anyone watching
                // and reintroduce exactly the herding the scheme prevents.
                return Err(ConsensusError::ValidationError(
                    "the commit window is still open; reveals are not accepted yet".to_string(),
                ));
            }
            VotingPhase::Closed => {
                return Err(ConsensusError::ValidationError(
                    "the reveal window for this bounty has closed".to_string(),
                ));
            }
        }

        let engine_id = req.engine_id.trim();

        let stored: Option<(String, Option<DateTime<Utc>>)> = sqlx::query_as(
            "SELECT commitment, revealed_at FROM consensus_vote_commits \
             WHERE bounty_id = $1 AND engine_id = $2",
        )
        .bind(bounty_id)
        .bind(engine_id)
        .fetch_optional(&self.db_pool)
        .await
        .map_err(|e| ConsensusError::DatabaseError(e.to_string()))?;

        let Some((commitment, revealed_at)) = stored else {
            return Err(ConsensusError::NotFound(
                "no commitment found for this voter on this bounty".to_string(),
            ));
        };

        if revealed_at.is_some() {
            return Err(ConsensusError::ValidationError(
                "this vote has already been revealed".to_string(),
            ));
        }

        if !crate::commitment::verify(
            &commitment,
            bounty_id,
            engine_id,
            &req.verdict,
            req.confidence,
            &req.salt,
        ) {
            return Err(ConsensusError::ValidationError(
                "revealed vote does not match the commitment".to_string(),
            ));
        }

        // Record the vote and mark the commitment spent atomically: a failure
        // between the two would either lose the vote or let it be revealed
        // twice.
        let mut tx = self
            .db_pool
            .begin()
            .await
            .map_err(|e| ConsensusError::DatabaseError(e.to_string()))?;

        sqlx::query(
            r#"
            INSERT INTO consensus_submissions
                (bounty_id, engine_id, verdict, confidence, reputation_score, sample_hash)
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (bounty_id, engine_id)
            DO UPDATE SET verdict = EXCLUDED.verdict,
                          confidence = EXCLUDED.confidence,
                          reputation_score = EXCLUDED.reputation_score,
                          sample_hash = COALESCE(EXCLUDED.sample_hash,
                                                 consensus_submissions.sample_hash),
                          submitted_at = NOW()
            "#,
        )
        .bind(bounty_id)
        .bind(engine_id)
        .bind(req.verdict.to_string())
        .bind(req.confidence)
        .bind(req.reputation_score)
        .bind(req.sample_hash.as_deref())
        .execute(&mut *tx)
        .await
        .map_err(|e| ConsensusError::DatabaseError(e.to_string()))?;

        sqlx::query(
            "UPDATE consensus_vote_commits SET revealed_at = NOW() \
             WHERE bounty_id = $1 AND engine_id = $2 AND revealed_at IS NULL",
        )
        .bind(bounty_id)
        .bind(engine_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| ConsensusError::DatabaseError(e.to_string()))?;

        tx.commit()
            .await
            .map_err(|e| ConsensusError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    // -- Delayed grading --------------------------------------------------

    /// Finalized results that are past the grading delay and not yet graded.
    ///
    /// Only rows with a `sample_hash` are returned: without one the worker has
    /// nothing to re-scan. Older results can still be graded through
    /// [`Self::record_grade`] by a retro-scan job or an admin.
    pub async fn find_gradable_bounties(&self) -> ConsensusResult<Vec<GradableBounty>> {
        let delay_hours = self.config.grading.delay_hours as i64;

        let rows = sqlx::query_as::<_, GradableBounty>(
            r#"
            SELECT r.bounty_id, r.final_verdict, r.sample_hash, r.finalized_at
            FROM consensus_results r
            LEFT JOIN verdict_grades g ON g.bounty_id = r.bounty_id
            WHERE r.is_finalized = true
              AND g.bounty_id IS NULL
              AND r.sample_hash IS NOT NULL
              AND r.finalized_at IS NOT NULL
              AND r.finalized_at <= NOW() - ($1 || ' hours')::interval
            ORDER BY r.finalized_at ASC
            LIMIT $2
            "#,
        )
        .bind(delay_hours.to_string())
        .bind(self.config.grading.batch_size)
        .fetch_all(&self.db_pool)
        .await
        .map_err(|e| ConsensusError::DatabaseError(e.to_string()))?;

        Ok(rows)
    }

    /// Record the grade for a bounty.
    ///
    /// `original_verdict` is read from the stored consensus result rather than
    /// taken from the caller, so a grade can never be recorded against a
    /// verdict the system never actually reached. Returns the stored grade.
    ///
    /// Idempotent: re-grading an already-graded bounty overwrites the row (a
    /// later, better-informed source should win over an earlier one).
    pub async fn record_grade(
        &self,
        bounty_id: Uuid,
        graded_verdict: &Verdict,
        source: GradeSource,
        sample_hash: Option<&str>,
        notes: Option<&str>,
    ) -> ConsensusResult<VerdictGrade> {
        let original: Option<String> = sqlx::query_scalar(
            "SELECT final_verdict FROM consensus_results WHERE bounty_id = $1 AND is_finalized = true",
        )
        .bind(bounty_id)
        .fetch_optional(&self.db_pool)
        .await
        .map_err(|e| ConsensusError::DatabaseError(e.to_string()))?;

        let Some(original_verdict) = original else {
            return Err(ConsensusError::NotFound(format!(
                "no finalized consensus for bounty {bounty_id}"
            )));
        };

        let graded = graded_verdict.to_string();
        let changed = original_verdict != graded;

        let grade = sqlx::query_as::<_, VerdictGrade>(
            r#"
            INSERT INTO verdict_grades
                (bounty_id, original_verdict, graded_verdict, verdict_changed,
                 grade_source, sample_hash, notes)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            ON CONFLICT (bounty_id) DO UPDATE SET
                graded_verdict  = EXCLUDED.graded_verdict,
                verdict_changed = EXCLUDED.verdict_changed,
                grade_source    = EXCLUDED.grade_source,
                sample_hash     = COALESCE(EXCLUDED.sample_hash, verdict_grades.sample_hash),
                notes           = EXCLUDED.notes,
                graded_at       = NOW()
            RETURNING bounty_id, original_verdict, graded_verdict, verdict_changed,
                      grade_source, sample_hash, notes, graded_at
            "#,
        )
        .bind(bounty_id)
        .bind(&original_verdict)
        .bind(&graded)
        .bind(changed)
        .bind(source.to_string())
        .bind(sample_hash)
        .bind(notes)
        .fetch_one(&self.db_pool)
        .await
        .map_err(|e| ConsensusError::DatabaseError(e.to_string()))?;

        Ok(grade)
    }

    /// Read a bounty's grade, if it has been graded.
    pub async fn get_grade(&self, bounty_id: Uuid) -> ConsensusResult<Option<VerdictGrade>> {
        sqlx::query_as::<_, VerdictGrade>(
            r#"
            SELECT bounty_id, original_verdict, graded_verdict, verdict_changed,
                   grade_source, sample_hash, notes, graded_at
            FROM verdict_grades
            WHERE bounty_id = $1
            "#,
        )
        .bind(bounty_id)
        .fetch_optional(&self.db_pool)
        .await
        .map_err(|e| ConsensusError::DatabaseError(e.to_string()))
    }

    /// How often the crowd was wrong. This is the number the whole grading
    /// loop exists to produce.
    pub async fn grading_stats(&self) -> ConsensusResult<GradingStats> {
        let row: (i64, i64) = sqlx::query_as(
            r#"
            SELECT COUNT(*)::bigint,
                   COUNT(*) FILTER (WHERE verdict_changed)::bigint
            FROM verdict_grades
            "#,
        )
        .fetch_one(&self.db_pool)
        .await
        .map_err(|e| ConsensusError::DatabaseError(e.to_string()))?;

        let (total, overturned) = row;
        Ok(GradingStats {
            total_graded: total,
            overturned,
            accuracy_rate: if total == 0 {
                None
            } else {
                Some(((total - overturned) as f64 / total as f64 * 100.0 * 100.0).round() / 100.0)
            },
        })
    }

    // -- Disputes ---------------------------------------------------------

    pub async fn create_dispute(
        &self,
        req: &CreateDisputeRequest,
        initiator_id: Uuid,
    ) -> ConsensusResult<Uuid> {
        let id = sqlx::query_scalar::<_, Uuid>(
            r#"
            INSERT INTO consensus_disputes
                (bounty_id, submission_id, initiator_id, disputed_verdict,
                 claimed_verdict, reason, evidence, status)
            VALUES ($1, $2, $3, $4, $5, $6, $7, 'open')
            RETURNING id
            "#,
        )
        .bind(req.bounty_id)
        .bind(req.submission_id)
        .bind(initiator_id)
        .bind(req.disputed_verdict.to_string())
        .bind(req.claimed_verdict.to_string())
        .bind(&req.reason)
        .bind(&req.evidence)
        .fetch_one(&self.db_pool)
        .await
        .map_err(|e| ConsensusError::DatabaseError(e.to_string()))?;

        // Flag the bounty's consensus as disputed.
        let _ = sqlx::query("UPDATE consensus_results SET is_disputed = true WHERE bounty_id = $1")
            .bind(req.bounty_id)
            .execute(&self.db_pool)
            .await;

        Ok(id)
    }

    pub async fn get_dispute(&self, dispute_id: Uuid) -> ConsensusResult<Option<Dispute>> {
        sqlx::query_as::<_, Dispute>(
            r#"
            SELECT id, bounty_id, submission_id, initiator_id, disputed_verdict,
                   claimed_verdict, reason, evidence, status, resolution,
                   resolved_by, resolved_at, created_at
            FROM consensus_disputes
            WHERE id = $1
            "#,
        )
        .bind(dispute_id)
        .fetch_optional(&self.db_pool)
        .await
        .map_err(|e| ConsensusError::DatabaseError(e.to_string()))
    }

    pub async fn get_bounty_disputes(&self, bounty_id: Uuid) -> ConsensusResult<Vec<Dispute>> {
        sqlx::query_as::<_, Dispute>(
            r#"
            SELECT id, bounty_id, submission_id, initiator_id, disputed_verdict,
                   claimed_verdict, reason, evidence, status, resolution,
                   resolved_by, resolved_at, created_at
            FROM consensus_disputes
            WHERE bounty_id = $1
            ORDER BY created_at DESC
            "#,
        )
        .bind(bounty_id)
        .fetch_all(&self.db_pool)
        .await
        .map_err(|e| ConsensusError::DatabaseError(e.to_string()))
    }

    pub async fn resolve_dispute(
        &self,
        dispute_id: Uuid,
        req: &ResolveDisputeRequest,
        resolver_id: Uuid,
    ) -> ConsensusResult<()> {
        let dispute = self
            .get_dispute(dispute_id)
            .await?
            .ok_or_else(|| ConsensusError::NotFound(format!("dispute {dispute_id}")))?;

        sqlx::query(
            r#"
            UPDATE consensus_disputes
            SET status = 'resolved', resolution = $2, resolved_by = $3, resolved_at = NOW()
            WHERE id = $1
            "#,
        )
        .bind(dispute_id)
        .bind(&req.resolution)
        .bind(resolver_id)
        .execute(&self.db_pool)
        .await
        .map_err(|e| ConsensusError::DatabaseError(e.to_string()))?;

        // Apply the resolved verdict to the consensus result and re-finalize.
        sqlx::query(
            r#"
            UPDATE consensus_results
            SET final_verdict = $2, is_disputed = false, is_finalized = true, finalized_at = NOW()
            WHERE bounty_id = $1
            "#,
        )
        .bind(dispute.bounty_id)
        .bind(req.final_verdict.to_string())
        .execute(&self.db_pool)
        .await
        .map_err(|e| ConsensusError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    /// Open disputes that have been waiting long enough to auto-escalate.
    pub async fn find_open_disputes(&self) -> ConsensusResult<Vec<Uuid>> {
        sqlx::query_scalar::<_, Uuid>(
            "SELECT id FROM consensus_disputes WHERE status = 'open' ORDER BY created_at ASC",
        )
        .fetch_all(&self.db_pool)
        .await
        .map_err(|e| ConsensusError::DatabaseError(e.to_string()))
    }

    pub async fn mark_dispute_under_review(&self, dispute_id: Uuid) -> ConsensusResult<()> {
        sqlx::query(
            "UPDATE consensus_disputes SET status = 'under_review' WHERE id = $1 AND status = 'open'",
        )
        .bind(dispute_id)
        .execute(&self.db_pool)
        .await
        .map_err(|e| ConsensusError::DatabaseError(e.to_string()))?;
        Ok(())
    }
}

fn parse_verdict(s: &str) -> Verdict {
    match s.to_lowercase().as_str() {
        "malicious" => Verdict::Malicious,
        "benign" => Verdict::Benign,
        "suspicious" => Verdict::Suspicious,
        _ => Verdict::Unknown,
    }
}

struct VerdictCounts {
    malicious: i32,
    benign: i32,
    suspicious: i32,
    unknown: i32,
}

fn count_verdicts(votes: &[SubmissionVote]) -> VerdictCounts {
    let mut c = VerdictCounts {
        malicious: 0,
        benign: 0,
        suspicious: 0,
        unknown: 0,
    };
    for v in votes {
        match v.verdict {
            Verdict::Malicious => c.malicious += 1,
            Verdict::Benign => c.benign += 1,
            Verdict::Suspicious => c.suspicious += 1,
            Verdict::Unknown => c.unknown += 1,
        }
    }
    c
}

/// The sample hash most voters agreed they were looking at.
///
/// Votes should all carry the same hash; a mismatch means someone voted on the
/// wrong artifact, so the majority is used rather than an arbitrary first row.
/// Returns `None` when no vote carried a hash, which leaves the bounty
/// ungradable rather than inventing a sample to re-scan.
fn majority_sample_hash(votes: &[SubmissionVote]) -> Option<String> {
    let mut counts: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    for v in votes {
        if let Some(h) = v.sample_hash.as_deref() {
            if !h.is_empty() {
                *counts.entry(h).or_insert(0) += 1;
            }
        }
    }
    counts
        .into_iter()
        // Tie-break on the hash itself so the result is deterministic across
        // runs; HashMap iteration order is not.
        .max_by(|(ha, ca), (hb, cb)| ca.cmp(cb).then_with(|| hb.cmp(ha)))
        .map(|(h, _)| h.to_string())
}

#[derive(sqlx::FromRow)]
struct VoteRow {
    id: Uuid,
    #[allow(dead_code)]
    bounty_id: Uuid,
    engine_id: String,
    verdict: String,
    confidence: Decimal,
    reputation_score: i32,
    submitted_at: chrono::DateTime<Utc>,
    sample_hash: Option<String>,
}

#[derive(sqlx::FromRow)]
struct ResultRow {
    bounty_id: Uuid,
    final_verdict: String,
    confidence: Decimal,
    total_submissions: i32,
    agreement_score: Decimal,
    is_finalized: bool,
    verdict_distribution: serde_json::Value,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vote(engine: &str, hash: Option<&str>) -> SubmissionVote {
        SubmissionVote {
            submission_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            engine_id: engine.to_string(),
            verdict: Verdict::Malicious,
            confidence: Decimal::new(90, 2),
            reputation_score: 5000,
            submitted_at: Utc::now(),
            sample_hash: hash.map(|h| h.to_string()),
        }
    }

    #[test]
    fn picks_the_hash_all_voters_agree_on() {
        let votes = vec![
            vote("a", Some("abc")),
            vote("b", Some("abc")),
            vote("c", Some("abc")),
        ];
        assert_eq!(majority_sample_hash(&votes), Some("abc".to_string()));
    }

    /// A voter who looked at the wrong artifact must not decide what gets
    /// re-scanned.
    #[test]
    fn majority_wins_when_voters_disagree() {
        let votes = vec![
            vote("a", Some("abc")),
            vote("b", Some("abc")),
            vote("c", Some("wrong")),
        ];
        assert_eq!(majority_sample_hash(&votes), Some("abc".to_string()));
    }

    #[test]
    fn ignores_votes_without_a_hash() {
        let votes = vec![vote("a", None), vote("b", Some("abc")), vote("c", None)];
        assert_eq!(majority_sample_hash(&votes), Some("abc".to_string()));
    }

    /// No hash anywhere means the bounty is ungradable. Returning None keeps it
    /// out of the regrader queue instead of inventing a sample to re-scan.
    #[test]
    fn returns_none_when_no_vote_carries_a_hash() {
        let votes = vec![vote("a", None), vote("b", None)];
        assert_eq!(majority_sample_hash(&votes), None);
        assert_eq!(majority_sample_hash(&[]), None);
    }

    /// Empty strings are not hashes.
    #[test]
    fn treats_empty_hash_as_absent() {
        let votes = vec![vote("a", Some("")), vote("b", Some(""))];
        assert_eq!(majority_sample_hash(&votes), None);
    }

    /// A tie must resolve the same way every run -- HashMap iteration order
    /// alone would make the re-scan target nondeterministic.
    #[test]
    fn tie_break_is_deterministic() {
        let votes = vec![vote("a", Some("aaa")), vote("b", Some("bbb"))];
        let first = majority_sample_hash(&votes);
        for _ in 0..50 {
            assert_eq!(majority_sample_hash(&votes), first);
        }
        assert!(first.is_some());
    }
}
