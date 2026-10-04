use chrono::{DateTime, Utc};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

pub type ConsensusResult<T> = Result<T, ConsensusError>;

#[derive(Debug, Error)]
pub enum ConsensusError {
    #[error("Validation error: {0}")]
    ValidationError(String),

    #[error("Database error: {0}")]
    DatabaseError(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Insufficient submissions: need {required}, got {actual}")]
    InsufficientSubmissions { required: usize, actual: usize },

    #[error("Consensus failed: {0}")]
    ConsensusFailed(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    Malicious,
    Benign,
    Suspicious,
    Unknown,
}

#[allow(clippy::to_string_trait_impl)]
impl ToString for Verdict {
    fn to_string(&self) -> String {
        match self {
            Verdict::Malicious => "malicious".to_string(),
            Verdict::Benign => "benign".to_string(),
            Verdict::Suspicious => "suspicious".to_string(),
            Verdict::Unknown => "unknown".to_string(),
        }
    }
}

/// Which phase of commit-reveal voting a bounty is in.
///
/// The clock starts at the bounty's first commit, so a bounty nobody has voted
/// on yet is always open for commits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VotingPhase {
    /// Accepting commitments. Nothing about anyone's vote is visible.
    Commit,
    /// Commits are closed; accepting plaintext reveals.
    Reveal,
    /// Both windows have passed. Unrevealed commits can no longer be revealed.
    Closed,
}

#[allow(clippy::to_string_trait_impl)]
impl ToString for VotingPhase {
    fn to_string(&self) -> String {
        match self {
            VotingPhase::Commit => "commit".to_string(),
            VotingPhase::Reveal => "reveal".to_string(),
            VotingPhase::Closed => "closed".to_string(),
        }
    }
}

/// Body for committing to a vote without disclosing it.
///
/// The voter computes the commitment locally; the service never sees the
/// verdict until the reveal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitVoteRequest {
    pub engine_id: String,
    /// Lowercase hex sha256 of the canonical preimage.
    pub commitment: String,
}

/// Body for revealing a previously committed vote.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevealVoteRequest {
    pub engine_id: String,
    pub verdict: Verdict,
    pub confidence: Decimal,
    /// The secret used when committing. Without it the commitment cannot be
    /// reproduced, so this is what proves the vote is the one committed to.
    pub salt: String,
    #[serde(default)]
    pub reputation_score: i32,
    #[serde(default)]
    pub sample_hash: Option<String>,
}

/// A stored commitment.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct VoteCommit {
    pub bounty_id: Uuid,
    pub engine_id: String,
    pub commitment: String,
    pub committed_at: DateTime<Utc>,
    pub revealed_at: Option<DateTime<Utc>>,
}

/// Where a bounty stands in the commit-reveal cycle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhaseStatus {
    pub bounty_id: Uuid,
    pub phase: VotingPhase,
    pub total_commits: i64,
    pub revealed: i64,
    /// When the current phase ends. `None` before the first commit, since the
    /// clock has not started.
    pub phase_ends_at: Option<DateTime<Utc>>,
}

/// Body for casting a vote on a bounty.
///
/// `sample_hash` is what makes delayed re-grading possible: it records which
/// artifact the verdict was about, so the sample can be scanned again later.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordVoteRequest {
    pub engine_id: String,
    pub verdict: Verdict,
    pub confidence: Decimal,
    #[serde(default)]
    pub reputation_score: i32,
    #[serde(default)]
    pub sample_hash: Option<String>,
}

/// Where a grade came from. Stored as a lowercase string in `grade_source`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum GradeSource {
    /// The regrader worker re-scanned the sample with today's engines.
    Rescan,
    /// A retro-scan with a newly added rule matched an old sample.
    Retroscan,
    /// A dispute was upheld.
    Dispute,
    /// A human overrode the verdict.
    Admin,
}

#[allow(clippy::to_string_trait_impl)]
impl ToString for GradeSource {
    fn to_string(&self) -> String {
        match self {
            GradeSource::Rescan => "rescan".to_string(),
            GradeSource::Retroscan => "retroscan".to_string(),
            GradeSource::Dispute => "dispute".to_string(),
            GradeSource::Admin => "admin".to_string(),
        }
    }
}

/// A finalized verdict, re-checked after the grading delay.
///
/// `verdict_changed == true` means the crowd was wrong: held-back payouts
/// should settle to the other side and reputation should be corrected.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct VerdictGrade {
    pub bounty_id: Uuid,
    pub original_verdict: String,
    pub graded_verdict: String,
    pub verdict_changed: bool,
    pub grade_source: String,
    pub sample_hash: Option<String>,
    pub notes: Option<String>,
    pub graded_at: DateTime<Utc>,
}

/// A finalized bounty that is due for re-grading.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct GradableBounty {
    pub bounty_id: Uuid,
    pub final_verdict: String,
    pub sample_hash: Option<String>,
    pub finalized_at: Option<DateTime<Utc>>,
}

/// Aggregate answer to "how often was the crowd wrong?".
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GradingStats {
    pub total_graded: i64,
    pub overturned: i64,
    /// Percentage of graded bounties the crowd got right. `None` until at
    /// least one bounty has been graded.
    pub accuracy_rate: Option<f64>,
}

/// Body for submitting a grade from outside the worker (retro-scan, admin).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitGradeRequest {
    pub graded_verdict: Verdict,
    pub grade_source: GradeSource,
    #[serde(default)]
    pub sample_hash: Option<String>,
    #[serde(default)]
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct BountyConsensus {
    pub id: Uuid,
    pub bounty_id: Uuid,
    pub final_verdict: String,
    pub confidence_score: Decimal,
    pub total_submissions: i32,
    pub agreement_score: Decimal,
    pub participating_engines: Vec<String>,
    pub weighted_votes: serde_json::Value,
    pub verdict_distribution: serde_json::Value,
    pub is_disputed: bool,
    pub finalized_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmissionVote {
    pub submission_id: Uuid,
    pub user_id: Uuid,
    pub engine_id: String,
    pub verdict: Verdict,
    pub confidence: Decimal,
    pub reputation_score: i32,
    pub submitted_at: DateTime<Utc>,
    /// Hash of the sample this vote is about. Carried so the regrader can
    /// re-scan the right artifact after the grading delay.
    pub sample_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VerdictDistribution {
    pub malicious: VoteStats,
    pub benign: VoteStats,
    pub suspicious: VoteStats,
    pub unknown: VoteStats,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoteStats {
    pub count: usize,
    pub weighted_count: Decimal,
    pub percentage: Decimal,
    pub avg_confidence: Decimal,
    pub voters: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Dispute {
    pub id: Uuid,
    pub bounty_id: Uuid,
    pub submission_id: Option<Uuid>,
    pub initiator_id: Uuid,
    pub disputed_verdict: String,
    pub claimed_verdict: String,
    pub reason: String,
    pub evidence: Option<serde_json::Value>,
    pub status: String,
    pub resolution: Option<String>,
    pub resolved_by: Option<Uuid>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DisputeStatus {
    Open,
    UnderReview,
    Resolved,
    Rejected,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ConsensusCalculationRequest {
    pub bounty_id: Uuid,
    pub force_recalculate: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ConsensusResponse {
    pub bounty_id: Uuid,
    pub final_verdict: Verdict,
    pub confidence_score: Decimal,
    pub agreement_score: Decimal,
    pub verdict_distribution: VerdictDistribution,
    pub total_submissions: usize,
    pub is_finalized: bool,
    pub can_be_disputed: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateDisputeRequest {
    pub bounty_id: Uuid,
    pub submission_id: Option<Uuid>,
    pub disputed_verdict: Verdict,
    pub claimed_verdict: Verdict,
    pub reason: String,
    pub evidence: Option<serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ResolveDisputeRequest {
    pub resolution: String,
    pub final_verdict: Verdict,
    pub compensation: Option<Decimal>,
}

impl Default for VoteStats {
    fn default() -> Self {
        Self {
            count: 0,
            weighted_count: Decimal::new(0, 0),
            percentage: Decimal::new(0, 0),
            avg_confidence: Decimal::new(0, 0),
            voters: Vec::new(),
        }
    }
}

#[cfg(test)]
mod contract_tests {
    use super::*;

    /// Cross-service contract: this is the exact JSON api-gateway's
    /// `consensus_client` puts on the wire when an analyst or engine votes.
    /// Both sides of it were written here, so nothing but a test proves they
    /// agree -- a renamed field or a Decimal that will not accept a JSON
    /// number would fail silently at runtime as a 4xx nobody reads.
    #[test]
    fn accepts_the_payload_api_gateway_sends() {
        let wire = r#"{
            "engine_id": "9f8b7c6d-5e4f-4a3b-8c1d-2e3f4a5b6c7d",
            "verdict": "malicious",
            "confidence": 0.9,
            "reputation_score": 100,
            "sample_hash": "abc123"
        }"#;

        let req: RecordVoteRequest =
            serde_json::from_str(wire).expect("gateway payload must deserialize");

        assert_eq!(req.engine_id, "9f8b7c6d-5e4f-4a3b-8c1d-2e3f4a5b6c7d");
        assert_eq!(req.verdict, Verdict::Malicious);
        assert_eq!(req.reputation_score, 100);
        assert_eq!(req.sample_hash.as_deref(), Some("abc123"));
        // Confidence must survive as a real number, not a truncated integer.
        assert_eq!(req.confidence.to_string(), "0.9");
    }

    /// The gateway omits `sample_hash` entirely (skip_serializing_if) rather
    /// than sending null when no hash is known.
    #[test]
    fn accepts_a_payload_with_no_sample_hash() {
        let wire = r#"{
            "engine_id": "engine-a",
            "verdict": "benign",
            "confidence": 0.42,
            "reputation_score": 0
        }"#;

        let req: RecordVoteRequest =
            serde_json::from_str(wire).expect("payload without sample_hash must deserialize");
        assert_eq!(req.verdict, Verdict::Benign);
        assert!(req.sample_hash.is_none());
    }

    /// Every verdict the gateway can resolve to must be understood here.
    #[test]
    fn understands_every_verdict_the_gateway_can_send() {
        for (s, expected) in [
            ("malicious", Verdict::Malicious),
            ("benign", Verdict::Benign),
            ("suspicious", Verdict::Suspicious),
        ] {
            let wire = format!(
                r#"{{"engine_id":"e","verdict":"{s}","confidence":0.5,"reputation_score":0}}"#
            );
            let req: RecordVoteRequest = serde_json::from_str(&wire)
                .unwrap_or_else(|e| panic!("verdict {s:?} must deserialize: {e}"));
            assert_eq!(req.verdict, expected);
        }
    }
}
