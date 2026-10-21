// Consensus rule validation
pub fn validate_consensus_rules(submission_count: usize, min_required: usize) -> bool {
    min_required > 0 && submission_count >= min_required
}
