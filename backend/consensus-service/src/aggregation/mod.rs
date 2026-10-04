use crate::config::ConsensusConfig;
use crate::models::{SubmissionVote, Verdict, VerdictDistribution, VoteStats};
use rust_decimal::Decimal;
use std::collections::HashMap;

pub struct ConsensusAggregator {
    config: ConsensusConfig,
}

impl ConsensusAggregator {
    pub fn new(config: ConsensusConfig) -> Self {
        Self { config }
    }

    /// Calculate weighted consensus from submissions
    pub fn calculate_consensus(
        &self,
        votes: &[SubmissionVote],
    ) -> (Verdict, Decimal, VerdictDistribution) {
        if votes.is_empty() {
            return (
                Verdict::Unknown,
                Decimal::new(0, 0),
                VerdictDistribution::default(),
            );
        }

        let distribution = if self.config.weighted_voting {
            self.calculate_weighted_votes(votes)
        } else {
            self.calculate_simple_majority(votes)
        };

        let (final_verdict, confidence) = self.determine_final_verdict(&distribution);

        (final_verdict, confidence, distribution)
    }

    /// Weighted voting algorithm
    fn calculate_weighted_votes(&self, votes: &[SubmissionVote]) -> VerdictDistribution {
        let mut verdict_map: HashMap<String, Vec<WeightedVote>> = HashMap::new();

        for vote in votes {
            let weight = self.calculate_vote_weight(vote);

            verdict_map
                .entry(vote.verdict.to_string())
                .or_default()
                .push(WeightedVote {
                    engine_id: vote.engine_id.clone(),
                    weight,
                    confidence: vote.confidence,
                });
        }

        self.build_distribution(verdict_map, votes.len())
    }

    /// Simple majority voting (one vote per submission)
    fn calculate_simple_majority(&self, votes: &[SubmissionVote]) -> VerdictDistribution {
        let mut verdict_counts: HashMap<String, usize> = HashMap::new();

        for vote in votes {
            *verdict_counts.entry(vote.verdict.to_string()).or_insert(0) += 1;
        }

        let mut distribution = VerdictDistribution::default();
        let total = votes.len() as f64;

        for (verdict_str, count) in verdict_counts {
            let percentage =
                Decimal::try_from((count as f64 / total) * 100.0).unwrap_or(Decimal::new(0, 0));

            let voters: Vec<String> = votes
                .iter()
                .filter(|v| v.verdict.to_string() == verdict_str)
                .map(|v| v.engine_id.clone())
                .collect();

            let avg_confidence = votes
                .iter()
                .filter(|v| v.verdict.to_string() == verdict_str)
                .map(|v| v.confidence)
                .sum::<Decimal>()
                / Decimal::from(count);

            let stats = VoteStats {
                count,
                weighted_count: Decimal::from(count),
                percentage,
                avg_confidence,
                voters,
            };

            match verdict_str.as_str() {
                "malicious" => distribution.malicious = stats,
                "benign" => distribution.benign = stats,
                "suspicious" => distribution.suspicious = stats,
                "unknown" => distribution.unknown = stats,
                _ => {}
            }
        }

        distribution
    }

    /// Calculate vote weight based on multiple factors
    fn calculate_vote_weight(&self, vote: &SubmissionVote) -> Decimal {
        // Normalize reputation score (0-10000 range to 0-1)
        let reputation_factor = Decimal::from(vote.reputation_score) / Decimal::from(10000);

        // Confidence factor (already 0-1)
        let confidence_factor = vote.confidence;

        // Time factor (early submissions weighted slightly higher)
        let time_factor = Decimal::new(10, 1); // 1.0 for now, can be time-based

        // Weighted combination
        let reputation_weight =
            Decimal::try_from(self.config.reputation_weight).unwrap_or(Decimal::new(5, 1));
        let confidence_weight =
            Decimal::try_from(self.config.confidence_weight).unwrap_or(Decimal::new(3, 1));
        let time_weight = Decimal::try_from(self.config.time_weight).unwrap_or(Decimal::new(2, 1));

        let total_weight = reputation_factor * reputation_weight
            + confidence_factor * confidence_weight
            + time_factor * time_weight;

        total_weight / (reputation_weight + confidence_weight + time_weight)
    }

    /// Build verdict distribution from weighted votes
    fn build_distribution(
        &self,
        verdict_map: HashMap<String, Vec<WeightedVote>>,
        _total_votes: usize,
    ) -> VerdictDistribution {
        let mut distribution = VerdictDistribution::default();

        let total_weight: Decimal = verdict_map
            .values()
            .flat_map(|votes| votes.iter().map(|v| v.weight))
            .sum();

        for (verdict_str, weighted_votes) in verdict_map {
            let count = weighted_votes.len();
            let weighted_count: Decimal = weighted_votes.iter().map(|v| v.weight).sum();
            let percentage = if total_weight > Decimal::new(0, 0) {
                (weighted_count / total_weight) * Decimal::from(100)
            } else {
                Decimal::new(0, 0)
            };

            let avg_confidence =
                weighted_votes.iter().map(|v| v.confidence).sum::<Decimal>() / Decimal::from(count);

            let voters: Vec<String> = weighted_votes.iter().map(|v| v.engine_id.clone()).collect();

            let stats = VoteStats {
                count,
                weighted_count,
                percentage,
                avg_confidence,
                voters,
            };

            match verdict_str.as_str() {
                "malicious" => distribution.malicious = stats,
                "benign" => distribution.benign = stats,
                "suspicious" => distribution.suspicious = stats,
                "unknown" => distribution.unknown = stats,
                _ => {}
            }
        }

        distribution
    }

    /// Determine final verdict and confidence
    fn determine_final_verdict(&self, distribution: &VerdictDistribution) -> (Verdict, Decimal) {
        let threshold = Decimal::try_from(self.config.consensus_threshold * 100.0)
            .unwrap_or(Decimal::new(66, 0));

        // Check if any verdict meets threshold
        if distribution.malicious.percentage >= threshold {
            return (Verdict::Malicious, distribution.malicious.avg_confidence);
        }
        if distribution.benign.percentage >= threshold {
            return (Verdict::Benign, distribution.benign.avg_confidence);
        }
        if distribution.suspicious.percentage >= threshold {
            return (Verdict::Suspicious, distribution.suspicious.avg_confidence);
        }

        // No clear consensus, return highest weighted verdict
        let max_verdict = [
            (&distribution.malicious, Verdict::Malicious),
            (&distribution.benign, Verdict::Benign),
            (&distribution.suspicious, Verdict::Suspicious),
            (&distribution.unknown, Verdict::Unknown),
        ]
        .iter()
        .max_by(|a, b| a.0.weighted_count.cmp(&b.0.weighted_count))
        .map(|(stats, verdict)| (verdict.clone(), stats.avg_confidence))
        .unwrap_or((Verdict::Unknown, Decimal::new(0, 0)));

        max_verdict
    }

    /// Calculate agreement score (how unified the votes are)
    pub fn calculate_agreement_score(&self, distribution: &VerdictDistribution) -> Decimal {
        // Agreement is highest percentage - measures consensus strength
        [
            distribution.malicious.percentage,
            distribution.benign.percentage,
            distribution.suspicious.percentage,
            distribution.unknown.percentage,
        ]
        .iter()
        .max()
        .copied()
        .unwrap_or(Decimal::new(0, 0))
    }

    /// Check if result can be disputed (low agreement)
    pub fn can_be_disputed(&self, agreement_score: Decimal) -> bool {
        let dispute_threshold =
            Decimal::try_from(self.config.dispute_threshold * 100.0).unwrap_or(Decimal::new(40, 0));

        agreement_score < dispute_threshold
    }
}

struct WeightedVote {
    engine_id: String,
    weight: Decimal,
    confidence: Decimal,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use uuid::Uuid;

    fn test_config() -> ConsensusConfig {
        ConsensusConfig {
            min_submissions: 3,
            max_submissions: 100,
            consensus_threshold: 0.66,
            weighted_voting: true,
            reputation_weight: 0.5,
            confidence_weight: 0.3,
            time_weight: 0.2,
            dispute_threshold: 0.4,
            auto_finalize_hours: 24,
        }
    }

    #[test]
    fn test_weighted_consensus() {
        let aggregator = ConsensusAggregator::new(test_config());

        let votes = vec![
            SubmissionVote {
                submission_id: Uuid::new_v4(),
                user_id: Uuid::new_v4(),
                engine_id: "engine1".to_string(),
                verdict: Verdict::Malicious,
                confidence: Decimal::new(90, 2),
                reputation_score: 8000,
                submitted_at: Utc::now(),
                sample_hash: None,
            },
            SubmissionVote {
                submission_id: Uuid::new_v4(),
                user_id: Uuid::new_v4(),
                engine_id: "engine2".to_string(),
                verdict: Verdict::Malicious,
                confidence: Decimal::new(85, 2),
                reputation_score: 7500,
                submitted_at: Utc::now(),
                sample_hash: None,
            },
            SubmissionVote {
                submission_id: Uuid::new_v4(),
                user_id: Uuid::new_v4(),
                engine_id: "engine3".to_string(),
                verdict: Verdict::Benign,
                confidence: Decimal::new(60, 2),
                reputation_score: 3000,
                submitted_at: Utc::now(),
                sample_hash: None,
            },
        ];

        let (verdict, _confidence, distribution) = aggregator.calculate_consensus(&votes);

        assert_eq!(verdict, Verdict::Malicious);
        assert!(distribution.malicious.count == 2);
        assert!(distribution.benign.count == 1);
    }

    #[test]
    fn test_simple_majority() {
        let mut config = test_config();
        config.weighted_voting = false;
        let aggregator = ConsensusAggregator::new(config);

        let votes = vec![
            SubmissionVote {
                submission_id: Uuid::new_v4(),
                user_id: Uuid::new_v4(),
                engine_id: "engine1".to_string(),
                verdict: Verdict::Malicious,
                confidence: Decimal::new(90, 2),
                reputation_score: 1000,
                submitted_at: Utc::now(),
                sample_hash: None,
            },
            SubmissionVote {
                submission_id: Uuid::new_v4(),
                user_id: Uuid::new_v4(),
                engine_id: "engine2".to_string(),
                verdict: Verdict::Malicious,
                confidence: Decimal::new(85, 2),
                reputation_score: 1000,
                submitted_at: Utc::now(),
                sample_hash: None,
            },
        ];

        let (verdict, _, _) = aggregator.calculate_consensus(&votes);
        assert_eq!(verdict, Verdict::Malicious);
    }
}
