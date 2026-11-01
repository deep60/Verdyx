// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title ReputationLib
 * @dev Library for reputation score calculations and analytics
 * @notice Provides pure functions for reputation-related computations
 */
library ReputationLib {
    // ============ CONSTANTS ============

    uint256 internal constant PERCENTAGE_BASE = 100;
    uint256 internal constant BASIS_POINTS_BASE = 10000;
    uint256 internal constant MAX_REPUTATION = 1000;
    uint256 internal constant MIN_REPUTATION = 0;

    // ============ STRUCTS ============

    /**
     * @dev Weighted score components
     */
    struct ScoreComponents {
        uint256 accuracy;
        uint256 participation;
        uint256 consistency;
    }

    /**
     * @dev Reputation calculation parameters
     */
    struct ReputationParams {
        uint256 accuracyWeight; // Percentage (0-100)
        uint256 participationWeight; // Percentage (0-100)
        uint256 consistencyWeight; // Percentage (0-100)
    }

    // ============ REPUTATION CALCULATION ============

    /**
     * @dev Calculate weighted reputation score
     * @param components Score components
     * @param params Weighting parameters
     * @return Calculated reputation score
     */
    function calculateWeightedReputation(
        ScoreComponents memory components,
        ReputationParams memory params
    ) internal pure returns (uint256) {
        require(
            params.accuracyWeight +
                params.participationWeight +
                params.consistencyWeight ==
                100,
            "Weights must sum to 100"
        );

        uint256 weightedScore = (components.accuracy * params.accuracyWeight +
            components.participation * params.participationWeight +
            components.consistency * params.consistencyWeight) /
            PERCENTAGE_BASE;

        return capReputation(weightedScore);
    }

    /**
     * @dev Calculate accuracy score from correct/total predictions
     * @param correct Number of correct predictions
     * @param total Total number of predictions
     * @return Accuracy score (0-100)
     */
    function calculateAccuracyScore(
        uint256 correct,
        uint256 total
    ) internal pure returns (uint256) {
        if (total == 0) return 0;
        return (correct * PERCENTAGE_BASE) / total;
    }

    /**
     * @dev Calculate participation score based on activity
     * @param submissions Number of submissions
     * @param maxSubmissions Maximum expected submissions for 100% score
     * @return Participation score (0-100)
     */
    function calculateParticipationScore(
        uint256 submissions,
        uint256 maxSubmissions
    ) internal pure returns (uint256) {
        if (maxSubmissions == 0) return 0;
        if (submissions >= maxSubmissions) return PERCENTAGE_BASE;
        return (submissions * PERCENTAGE_BASE) / maxSubmissions;
    }

    /**
     * @dev Calculate consistency score based on consecutive correct predictions
     * @param consecutiveCorrect Number of consecutive correct predictions
     * @param maxConsecutive Maximum expected for 100% score
     * @return Consistency score (0-100)
     */
    function calculateConsistencyScore(
        uint256 consecutiveCorrect,
        uint256 maxConsecutive
    ) internal pure returns (uint256) {
        if (maxConsecutive == 0) return 0;
        if (consecutiveCorrect >= maxConsecutive) return PERCENTAGE_BASE;
        return (consecutiveCorrect * PERCENTAGE_BASE) / maxConsecutive;
    }

    // ============ REPUTATION ADJUSTMENTS ============

    /**
     * @dev Calculate reputation gain for correct analysis
     * @param currentReputation Current reputation score
     * @param baseGain Base gain amount
     * @param confidenceBonus Bonus based on confidence
     * @param stakeBonus Bonus based on stake amount
     * @return Total reputation gain
     */
    function calculateReputationGain(
        uint256 currentReputation,
        uint256 baseGain,
        uint256 confidenceBonus,
        uint256 stakeBonus
    ) internal pure returns (uint256) {
        uint256 totalGain = baseGain + confidenceBonus + stakeBonus;

        // Apply diminishing returns for high reputation
        if (currentReputation > 800) {
            totalGain = (totalGain * 50) / 100; // 50% reduction
        } else if (currentReputation > 600) {
            totalGain = (totalGain * 75) / 100; // 25% reduction
        }

        return totalGain;
    }

    /**
     * @dev Calculate reputation loss for incorrect analysis
     * @param currentReputation Current reputation score
     * @param baseLoss Base loss amount
     * @param confidencePenalty Penalty based on confidence
     * @param stakePenalty Penalty based on stake amount
     * @return Total reputation loss
     */
    function calculateReputationLoss(
        uint256 currentReputation,
        uint256 baseLoss,
        uint256 confidencePenalty,
        uint256 stakePenalty
    ) internal pure returns (uint256) {
        uint256 totalLoss = baseLoss + confidencePenalty + stakePenalty;

        // Apply protection for low reputation
        if (currentReputation < 200) {
            totalLoss = (totalLoss * 50) / 100; // 50% reduction
        } else if (currentReputation < 400) {
            totalLoss = (totalLoss * 75) / 100; // 25% reduction
        }

        return totalLoss;
    }

    /**
     * @dev Apply reputation decay for inactivity
     * @param currentReputation Current reputation score
     * @param decayRate Decay rate percentage
     * @return New reputation after decay
     */
    function applyDecay(
        uint256 currentReputation,
        uint256 decayRate
    ) internal pure returns (uint256) {
        require(decayRate <= 100, "Invalid decay rate");

        uint256 decayAmount = (currentReputation * decayRate) / PERCENTAGE_BASE;

        if (currentReputation > decayAmount) {
            return currentReputation - decayAmount;
        }
        return MIN_REPUTATION;
    }

    // ============ TIER CALCULATIONS ============

    /**
     * @dev Determine reputation tier
     * @param reputation Current reputation score
     * @return tier Tier level (0-4)
     */
    function getReputationTier(
        uint256 reputation
    ) internal pure returns (uint256 tier) {
        if (reputation >= 800) return 4; // Expert
        if (reputation >= 600) return 3; // Advanced
        if (reputation >= 400) return 2; // Intermediate
        if (reputation >= 200) return 1; // Beginner
        return 0; // Novice
    }

    /**
     * @dev Get tier multiplier for rewards/stakes
     * @param tier Reputation tier (0-4)
     * @return multiplier Multiplier in basis points
     */
    function getTierMultiplier(
        uint256 tier
    ) internal pure returns (uint256 multiplier) {
        if (tier == 4) return 15000; // 150% for Expert
        if (tier == 3) return 12500; // 125% for Advanced
        if (tier == 2) return 11000; // 110% for Intermediate
        if (tier == 1) return 10500; // 105% for Beginner
        return 10000; // 100% for Novice
    }

    /**
     * @dev Calculate minimum stake based on reputation tier
     * @param baseStake Base stake requirement
     * @param tier Reputation tier
     * @return Required stake amount
     */
    function calculateRequiredStake(
        uint256 baseStake,
        uint256 tier
    ) internal pure returns (uint256) {
        // Higher tier = lower stake requirement
        if (tier == 4) return (baseStake * 70) / 100; // 30% reduction
        if (tier == 3) return (baseStake * 80) / 100; // 20% reduction
        if (tier == 2) return (baseStake * 90) / 100; // 10% reduction
        if (tier == 1) return baseStake; // No reduction
        return (baseStake * 110) / 100; // 10% increase for novice
    }

    // ============ ANALYTICS ============

    /**
     * @dev Calculate false positive rate
     * @param falsePositives Number of false positives
     * @param totalSubmissions Total number of submissions
     * @return Rate as percentage (0-100)
     */
    function calculateFalsePositiveRate(
        uint256 falsePositives,
        uint256 totalSubmissions
    ) internal pure returns (uint256) {
        if (totalSubmissions == 0) return 0;
        return (falsePositives * PERCENTAGE_BASE) / totalSubmissions;
    }

    /**
     * @dev Calculate false negative rate
     * @param falseNegatives Number of false negatives
     * @param totalSubmissions Total number of submissions
     * @return Rate as percentage (0-100)
     */
    function calculateFalseNegativeRate(
        uint256 falseNegatives,
        uint256 totalSubmissions
    ) internal pure returns (uint256) {
        if (totalSubmissions == 0) return 0;
        return (falseNegatives * PERCENTAGE_BASE) / totalSubmissions;
    }

    /**
     * @dev Calculate F1 score (harmonic mean of precision and recall)
     * @param truePositives True positives
     * @param falsePositives False positives
     * @param falseNegatives False negatives
     * @return F1 score (0-100)
     */
    function calculateF1Score(
        uint256 truePositives,
        uint256 falsePositives,
        uint256 falseNegatives
    ) internal pure returns (uint256) {
        if (truePositives == 0) return 0;

        uint256 precision = (truePositives * BASIS_POINTS_BASE) /
            (truePositives + falsePositives);
        uint256 recall = (truePositives * BASIS_POINTS_BASE) /
            (truePositives + falseNegatives);

        if (precision + recall == 0) return 0;

        uint256 f1 = (2 * precision * recall) / (precision + recall);
        return (f1 * PERCENTAGE_BASE) / BASIS_POINTS_BASE;
    }

    /**
     * @dev Calculate streak bonus
     * @param consecutiveCorrect Number of consecutive correct predictions
     * @return Bonus multiplier in basis points
     */
    function calculateStreakBonus(
        uint256 consecutiveCorrect
    ) internal pure returns (uint256) {
        if (consecutiveCorrect >= 20) return 12000; // 120%
        if (consecutiveCorrect >= 15) return 11500; // 115%
        if (consecutiveCorrect >= 10) return 11000; // 110%
        if (consecutiveCorrect >= 5) return 10500; // 105%
        return 10000; // 100% (no bonus)
    }

    // ============ UTILITY FUNCTIONS ============

    /**
     * @dev Cap reputation within valid range
     * @param reputation Reputation score to cap
     * @return Capped reputation score
     */
    function capReputation(uint256 reputation) internal pure returns (uint256) {
        if (reputation > MAX_REPUTATION) return MAX_REPUTATION;
        if (reputation < MIN_REPUTATION) return MIN_REPUTATION;
        return reputation;
    }

    /**
     * @dev Safe addition with reputation cap
     * @param current Current reputation
     * @param addition Amount to add
     * @return New reputation score
     */
    function safeAddReputation(
        uint256 current,
        uint256 addition
    ) internal pure returns (uint256) {
        uint256 newReputation = current + addition;
        return capReputation(newReputation);
    }

    /**
     * @dev Safe subtraction with reputation floor
     * @param current Current reputation
     * @param subtraction Amount to subtract
     * @return New reputation score
     */
    function safeSubReputation(
        uint256 current,
        uint256 subtraction
    ) internal pure returns (uint256) {
        if (current <= subtraction) return MIN_REPUTATION;
        return current - subtraction;
    }

    /**
     * @dev Calculate average reputation from array
     * @param reputations Array of reputation scores
     * @return Average reputation
     */
    function calculateAverageReputation(
        uint256[] memory reputations
    ) internal pure returns (uint256) {
        if (reputations.length == 0) return 0;

        uint256 sum = 0;
        for (uint256 i = 0; i < reputations.length; i++) {
            sum += reputations[i];
        }

        return sum / reputations.length;
    }

    /**
     * @dev Check if reputation meets minimum requirement
     * @param reputation Reputation to check
     * @param minimum Minimum required reputation
     * @return bool True if meets requirement
     */
    function meetsMinimumReputation(
        uint256 reputation,
        uint256 minimum
    ) internal pure returns (bool) {
        return reputation >= minimum;
    }
}
