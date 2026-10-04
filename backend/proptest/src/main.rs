//! Property-based tests for Verdyx consensus and reward logic
//!
//! Standalone tests that don't depend on the full shared crate.

use proptest::prelude::*;
use proptest::collection::vec as prop_vec;

/// Consensus verdict types matching the smart contract
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Verdict {
    Benign,
    Malicious,
    Suspicious,
}

/// Analysis submission for consensus
#[derive(Debug, Clone)]
pub struct Analysis {
    pub analyst: String,
    pub verdict: Verdict,
    pub confidence: u8, // 0-100
    pub stake: u128,
}

/// Consensus result
#[derive(Debug, Clone, PartialEq)]
pub struct ConsensusResult {
    pub verdict: Verdict,
    pub confidence_score: u64, // basis points (0-10000)
    pub total_analyses: usize,
    pub consensus_count: usize,
}

/// Calculate consensus from analyses (ported from BountyManager.sol)
pub fn calculate_consensus(
    analyses: &[Analysis],
    consensus_threshold: u128, // percentage (e.g., 66 for 66%)
) -> ConsensusResult {
    if analyses.is_empty() {
        return ConsensusResult {
            verdict: Verdict::Suspicious,
            confidence_score: 0,
            total_analyses: 0,
            consensus_count: 0,
        };
    }
    
    let mut malicious_weight = 0u128;
    let mut benign_weight = 0u128;
    let mut total_weight = 0u128;
    
    for analysis in analyses {
        // Use saturating arithmetic to prevent overflow
        let weight = analysis.stake.saturating_mul(analysis.confidence as u128) / 100;
        
        match analysis.verdict {
            Verdict::Malicious => {
                malicious_weight = malicious_weight.saturating_add(weight);
                total_weight = total_weight.saturating_add(weight);
            }
            Verdict::Benign => {
                benign_weight = benign_weight.saturating_add(weight);
                total_weight = total_weight.saturating_add(weight);
            }
            Verdict::Suspicious => {} // Suspicious is NOT counted in total weight
        }
    }
    
    let (verdict, _consensus_weight) = if total_weight == 0 {
        (Verdict::Suspicious, 0)
    } else {
        let malicious_pct = (malicious_weight * 100) / total_weight;
        let benign_pct = (benign_weight * 100) / total_weight;
        
        if malicious_pct >= consensus_threshold {
            (Verdict::Malicious, malicious_weight)
        } else if benign_pct >= consensus_threshold {
            (Verdict::Benign, benign_weight)
        } else {
            (Verdict::Suspicious, 0)
        }
    };
    
    let consensus_count = analyses.iter()
        .filter(|a| a.verdict == verdict)
        .count();
    
    let confidence_score = if analyses.is_empty() {
        0
    } else {
        ((consensus_count * 10000) / analyses.len()) as u64
    };
    
    ConsensusResult {
        verdict,
        confidence_score,
        total_analyses: analyses.len(),
        consensus_count,
    }
}

/// Reward distribution (ported from ThreatToken.sol)
pub fn calculate_base_reward(
    staked_amount: u128,
    reputation: u128,
    base_reward_rate: u64,
    bonus_multiplier: u64,
    is_first_correct: bool,
) -> u128 {
    let base_reward = (staked_amount * base_reward_rate as u128) / 100;
    let reputation_bonus = reputation / 1000;
    let bonus_reward = (base_reward * reputation_bonus) / 100;
    
    let mut final_reward = base_reward + bonus_reward;
    
    if is_first_correct {
        final_reward = (final_reward * bonus_multiplier as u128) / 100;
    }
    
    final_reward
}

/// Slashing calculation
pub fn calculate_slash(stake_amount: u128, slash_percentage: u64) -> u128 {
    (stake_amount * slash_percentage as u128) / 100
}

// Strategy for generating valid analyses
fn analysis_strategy() -> impl Strategy<Value = Analysis> {
    (
        "[a-zA-Z0-9]{1,50}",
        prop::sample::select(vec![Verdict::Benign, Verdict::Malicious, Verdict::Suspicious]),
        1u8..=100,
        1u128..=1_000_000_000_000_000_000u128,
    ).prop_map(|(analyst, verdict, confidence, stake)| Analysis {
        analyst,
        verdict,
        confidence,
        stake,
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]
    
    #[test]
    fn consensus_empty_returns_suspicious(_ in any::<()>()) {
        let result = calculate_consensus(&[], 66);
        prop_assert_eq!(result.verdict, Verdict::Suspicious);
        prop_assert_eq!(result.confidence_score, 0);
        prop_assert_eq!(result.total_analyses, 0);
    }
    
    #[test]
    fn consensus_single_analysis(
        confidence in 66u8..=100,
        stake in 1u128..=1_000_000_000_000_000_000u128,
    ) {
        let analyses = vec![
            Analysis {
                analyst: "analyst1".to_string(),
                verdict: Verdict::Malicious,
                confidence,
                stake,
            }
        ];
        
        let result = calculate_consensus(&analyses, 66);
        prop_assert_eq!(result.verdict, Verdict::Malicious);
        prop_assert_eq!(result.total_analyses, 1);
        prop_assert_eq!(result.consensus_count, 1);
    }
    
    #[test]
    fn consensus_below_threshold(
        params in (
            // First analysis: Malicious
            ("[a-zA-Z0-9]{1,50}", 1u8..=65, 1u128..=1_000_000_000_000_000_000u128),
            // Second analysis: Benign
            ("[a-zA-Z0-9]{1,50}", 1u8..=65, 1u128..=1_000_000_000_000_000_000u128),
        ).prop_filter("max percentage < 95%", |(m, b)| {
            let (_, conf1, stake1) = m;
            let (_, conf2, stake2) = b;
            let w1 = (stake1 * *conf1 as u128) / 100;
            let w2 = (stake2 * *conf2 as u128) / 100;
            if w1 > 0 && w2 > 0 {
                let total = w1 + w2;
                let max_pct = (std::cmp::max(w1, w2) * 100) / total;
                max_pct < 95
            } else {
                false
            }
        }),
    ) {
        let (malicious_params, benign_params) = params;
        let (analyst1, conf1, stake1) = malicious_params;
        let (analyst2, conf2, stake2) = benign_params;
        
        let analyses = vec![
            Analysis {
                analyst: analyst1,
                verdict: Verdict::Malicious,
                confidence: conf1,
                stake: stake1,
            },
            Analysis {
                analyst: analyst2,
                verdict: Verdict::Benign,
                confidence: conf2,
                stake: stake2,
            }
        ];
        
        // Test with 95% threshold - should return Suspicious for these filtered cases
        let result = calculate_consensus(&analyses, 95);
        prop_assert_eq!(result.verdict, Verdict::Suspicious);
    }
    
    #[test]
    fn consensus_confidence_score_range(
        analyses in prop_vec(analysis_strategy(), 1..=50),
    ) {
        let result = calculate_consensus(&analyses, 66);
        prop_assert!(result.confidence_score <= 10000);
    }
    
    #[test]
    fn consensus_count_bounded(
        analyses in prop_vec(analysis_strategy(), 1..=50),
    ) {
        let result = calculate_consensus(&analyses, 66);
        prop_assert!(result.consensus_count <= result.total_analyses);
    }
    
    #[test]
    fn consensus_weighted_correctly(
        stake1 in 1u128..=1000,
        conf1 in 1u8..=100,
        stake2 in 1u128..=1000,
        conf2 in 1u8..=100,
    ) {
        let analyses = vec![
            Analysis {
                analyst: "a1".to_string(),
                verdict: Verdict::Malicious,
                confidence: conf1,
                stake: stake1,
            },
            Analysis {
                analyst: "a2".to_string(),
                verdict: Verdict::Benign,
                confidence: conf2,
                stake: stake2,
            }
        ];
        
        let weight1 = (stake1 as u128 * conf1 as u128) / 100;
        let weight2 = (stake2 as u128 * conf2 as u128) / 100;
        
        // Use 50% threshold for simple majority (weight1 > weight2 means >50%)
        let result = calculate_consensus(&analyses, 50);
        
        if weight1 > weight2 {
            prop_assert_eq!(result.verdict, Verdict::Malicious);
        } else if weight2 > weight1 {
            prop_assert_eq!(result.verdict, Verdict::Benign);
        } else {
            prop_assert!(matches!(result.verdict, Verdict::Malicious | Verdict::Benign | Verdict::Suspicious));
        }
    }
    
    #[test]
    fn reward_increases_with_stake(
        stake1 in 100u128..=10000,
        stake2 in 100u128..=10000,
        reputation in 0u128..=10000,
    ) {
        let reward1 = calculate_base_reward(stake1, reputation, 5, 150, false);
        let reward2 = calculate_base_reward(stake2, reputation, 5, 150, false);
        
        if stake1 > stake2 {
            prop_assert!(reward1 >= reward2);
        }
    }
    
    #[test]
    fn reward_increases_with_reputation(
        stake in 100u128..=10000,
        rep1 in 0u128..=10000,
        rep2 in 0u128..=10000,
    ) {
        let reward1 = calculate_base_reward(stake, rep1, 5, 150, false);
        let reward2 = calculate_base_reward(stake, rep2, 5, 150, false);
        
        if rep1 > rep2 {
            prop_assert!(reward1 >= reward2);
        }
    }
    
    #[test]
    fn first_correct_bonus(
        stake in 100u128..=10000,
        reputation in 0u128..=10000,
    ) {
        let normal = calculate_base_reward(stake, reputation, 5, 150, false);
        let bonus = calculate_base_reward(stake, reputation, 5, 150, true);
        
        let expected_bonus = (normal * 150) / 100;
        prop_assert_eq!(bonus, expected_bonus);
    }
    
    #[test]
    fn slash_percentage_correct(
        stake in 100u128..=1_000_000_000_000_000_000u128,
        slash_pct in 1u64..=100,
    ) {
        let slash = calculate_slash(stake, slash_pct);
        let expected = (stake * slash_pct as u128) / 100;
        prop_assert_eq!(slash, expected);
        prop_assert!(slash <= stake);
    }
    
    #[test]
    fn reward_pool_accounting(
        analyses in prop_vec(analysis_strategy(), 3..=10),
        consensus_threshold in 51u128..=90,
        reward_pool in 1000u128..=1_000_000_000_000_000_000u128,
        platform_fee_pct in 0u64..=20,
    ) {
        let result = calculate_consensus(&analyses, consensus_threshold);
        
        if result.verdict != Verdict::Suspicious && result.consensus_count > 0 {
            let platform_fee = (reward_pool * platform_fee_pct as u128) / 100;
            let distributable = reward_pool - platform_fee;
            let per_winner = distributable / result.consensus_count as u128;
            let total_distributed = per_winner * result.consensus_count as u128;
            
            prop_assert!(total_distributed + platform_fee <= reward_pool);
            prop_assert_eq!(per_winner, distributable / result.consensus_count as u128);
        }
    }
    
    #[test]
    fn consensus_deterministic(
        analyses in prop_vec(analysis_strategy(), 1..=20),
    ) {
        let result1 = calculate_consensus(&analyses, 66);
        let result2 = calculate_consensus(&analyses, 66);
        prop_assert_eq!(result1, result2);
    }
    
    #[test]
    fn consensus_strengthens_with_more_same_verdict(
        base_analyses in prop_vec(analysis_strategy().prop_filter("must be malicious", |a| a.verdict == Verdict::Malicious), 1..=5),
        additional_count in 1usize..=5,
    ) {
        let mut analyses = base_analyses.clone();
        for i in 0..additional_count {
            analyses.push(Analysis {
                analyst: format!("extra_{}", i),
                verdict: Verdict::Malicious,
                confidence: 80,
                stake: 1000,
            });
        }
        
        let result_base = calculate_consensus(&base_analyses, 66);
        let result_extended = calculate_consensus(&analyses, 66);
        
        if result_base.verdict == Verdict::Malicious {
            prop_assert_eq!(result_extended.verdict, Verdict::Malicious);
        }
    }
}

#[cfg(test)]
mod regression_tests {
    use super::*;
    
    #[test]
    fn test_zero_confidence_analysis() {
        let analyses = vec![
            Analysis {
                analyst: "a1".to_string(),
                verdict: Verdict::Malicious,
                confidence: 0,
                stake: 10000,
            },
            Analysis {
                analyst: "a2".to_string(),
                verdict: Verdict::Benign,
                confidence: 100,
                stake: 1000,
            },
        ];
        
        let result = calculate_consensus(&analyses, 51);
        assert_eq!(result.verdict, Verdict::Benign);
    }
    
    #[test]
    fn test_large_numbers_no_overflow() {
        let analyses = vec![
            Analysis {
                analyst: "a1".to_string(),
                verdict: Verdict::Malicious,
                confidence: 100,
                stake: u128::MAX / 2,
            },
        ];
        
        let result = calculate_consensus(&analyses, 51);
        assert_eq!(result.verdict, Verdict::Malicious);
    }
    
    #[test]
    fn test_suspicious_verdict_not_counted() {
        let analyses = vec![
            Analysis {
                analyst: "a1".to_string(),
                verdict: Verdict::Suspicious,
                confidence: 100,
                stake: 10000,
            },
            Analysis {
                analyst: "a2".to_string(),
                verdict: Verdict::Benign,
                confidence: 50,
                stake: 100,
            },
        ];
        
        let result = calculate_consensus(&analyses, 51);
        assert_eq!(result.verdict, Verdict::Benign);
    }
    
    #[test]
    fn test_reward_calculation_edge_cases() {
        let r1 = calculate_base_reward(1000, 0, 5, 150, false);
        assert_eq!(r1, 50);
        
        let r2 = calculate_base_reward(1000, 1_000_000, 5, 150, false);
        assert_eq!(r2, 550);
    }
}