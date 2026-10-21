use crate::models::{SubmissionVote, Verdict};
use rust_decimal::Decimal;

pub fn validate_submission(vote: &SubmissionVote) -> bool {
    !vote.engine_id.trim().is_empty()
        && vote.verdict != Verdict::Unknown
        && vote.confidence >= Decimal::ZERO
        && vote.confidence <= Decimal::ONE
        && vote.reputation_score >= 0
}
