// Fixed ReputationSystem.sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "../Interfaces/IReputationSystem.sol";

/**
 * @title ReputationSystem
 * @dev Manages reputation scores for security analysts and engines in the Verdyx platform
 * @notice This contract tracks accuracy, participation, and calculates weighted reputation scores
 */
contract ReputationSystem is IReputationSystem, AccessControl {
    bytes32 public constant BOUNTY_MANAGER_ROLE =
        keccak256("BOUNTY_MANAGER_ROLE");
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");

    // Constants for reputation calculations
    uint256 public constant INITIAL_REPUTATION = 100;
    uint256 public constant MAX_REPUTATION = 1000;
    uint256 public constant MIN_REPUTATION = 0;
    uint256 public constant ACCURACY_WEIGHT = 70; // 70% weight for accuracy
    uint256 public constant PARTICIPATION_WEIGHT = 20; // 20% weight for participation
    uint256 public constant CONSISTENCY_WEIGHT = 10; // 10% weight for consistency
    uint256 public constant DECAY_RATE = 5; // 5% decay per month for inactive users
    uint256 public constant MIN_SUBMISSIONS_FOR_RATING = 10;

    // Structs
    struct EngineProfile {
        bool isRegistered;
        uint8 engineType;
        uint256 reputation;
        uint256 totalSubmissions;
        uint256 correctPredictions;
        uint256 lastActiveTimestamp;
        uint256 registrationTimestamp;
        bool isActive;
        // Additional fields
        uint256 falsePositives;
        uint256 falseNegatives;
        uint256 totalStakeAmount;
        uint256 totalRewards;
        uint256 consecutiveCorrect;
        uint256 maxConsecutiveCorrect;
    }

    // ReputationRecord is defined in IReputationSystem interface

    struct SubmissionRecord {
        address engine;
        uint256 bountyId;
        bool prediction; // true for malicious, false for benign
        bool actualResult;
        uint256 stakeAmount;
        uint256 timestamp;
        bool isResolved;
        uint256 confidenceScore; // 0-100
    }

    struct ReputationTier {
        uint256 minReputation;
        uint256 maxStakeMultiplier;
        uint256 rewardBonus; // percentage bonus
        string tierName;
    }

    // EngineInfo is defined in IReputationSystem interface

    enum EngineCategory {
        Human,
        AutomatedEngine,
        HybridSystem
    }

    // State variables
    mapping(address => EngineProfile) public engines;
    mapping(uint256 => SubmissionRecord) public submissions;
    mapping(address => uint256[]) public engineSubmissions;
    mapping(uint256 => ReputationTier) public reputationTiers;
    mapping(address => ReputationRecord[]) private reputationHistory;
    mapping(address => uint256) public engineIndex;

    address[] public activeEngines;
    uint256 public nextSubmissionId;
    uint256 public totalActiveEngines;
    uint256 public decayTimestamp;

    // Events are defined in IReputationSystem interface

    event SubmissionRecorded(
        uint256 indexed submissionId,
        address indexed engineAddress,
        uint256 indexed bountyId,
        bool prediction,
        uint256 stakeAmount
    );

    event SubmissionResolved(
        uint256 indexed submissionId,
        bool isCorrect,
        uint256 reputationChange
    );

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(ADMIN_ROLE, msg.sender);

        // Initialize reputation tiers
        _initializeReputationTiers();

        decayTimestamp = block.timestamp;
        nextSubmissionId = 1;
    }

    /**
     * @notice Check if an engine is eligible to participate in bounties
     */
    function isEligibleEngine(
        address engineAddress
    ) external view override returns (bool) {
        EngineProfile storage profile = engines[engineAddress];
        return profile.isActive && profile.reputation >= getMinimumReputation();
    }

    /**
     * @notice Get minimum reputation required to participate
     */
    function getMinimumReputation() public view override returns (uint256) {
        return MIN_REPUTATION;
    }

    /**
     * @notice Get reputation decay parameters
     */
    function getDecayParameters()
        external
        view
        override
        returns (uint256 decayRate, uint256 decayPeriod)
    {
        return (DECAY_RATE, 30 days);
    }

    /**
     * @notice Get reputation multipliers for different engine types
     */
    function getEngineMultiplier(
        uint8 engineType
    ) external pure override returns (uint256) {
        if (engineType == 0) return 100; // Human
        if (engineType == 1) return 80; // Automated
        return 90; // Hybrid
    }

    function getEngineInfo(
        address engineAddress
    ) external view returns (EngineInfo memory) {
        EngineProfile storage profile = engines[engineAddress];
        return
            EngineInfo({
                isRegistered: profile.isRegistered,
                engineType: profile.engineType,
                reputation: profile.reputation,
                totalAnalyses: profile.totalSubmissions,
                correctAnalyses: profile.correctPredictions,
                lastActivityTimestamp: profile.lastActiveTimestamp,
                registrationTimestamp: profile.registrationTimestamp,
                isActive: profile.isActive
            });
    }

    function registerEngine(
        address engineAddress,
        uint8 engineType
    ) external override onlyRole(BOUNTY_MANAGER_ROLE) returns (bool success) {
        require(engineAddress != address(0), "Invalid engine address");
        require(!engines[engineAddress].isActive, "Engine already registered");
        require(engineType <= 2, "Invalid engine type");

        engines[engineAddress] = EngineProfile({
            isRegistered: true,
            engineType: engineType,
            reputation: INITIAL_REPUTATION,
            totalSubmissions: 0,
            correctPredictions: 0,
            lastActiveTimestamp: block.timestamp,
            registrationTimestamp: block.timestamp,
            isActive: true,
            falsePositives: 0,
            falseNegatives: 0,
            totalStakeAmount: 0,
            totalRewards: 0,
            consecutiveCorrect: 0,
            maxConsecutiveCorrect: 0
        });

        activeEngines.push(engineAddress);
        engineIndex[engineAddress] = activeEngines.length - 1;
        totalActiveEngines += 1;

        emit EngineRegistered(engineAddress, engineType, INITIAL_REPUTATION);
        return true;
    }

    function deactivateEngine(
        address engineAddress
    ) external override onlyRole(BOUNTY_MANAGER_ROLE) returns (bool success) {
        require(engines[engineAddress].isActive, "Engine not active");
        uint256 index = engineIndex[engineAddress];
        address last = activeEngines[activeEngines.length - 1];
        activeEngines[index] = last;
        engineIndex[last] = index;
        activeEngines.pop();
        delete engineIndex[engineAddress];
        engines[engineAddress].isActive = false;
        totalActiveEngines -= 1;
        return true;
    }

    function reactivateEngine(
        address engineAddress
    ) external override onlyRole(BOUNTY_MANAGER_ROLE) returns (bool success) {
        require(!engines[engineAddress].isActive, "Engine already active");
        engines[engineAddress].isActive = true;
        activeEngines.push(engineAddress);
        engineIndex[engineAddress] = activeEngines.length - 1;
        totalActiveEngines += 1;
        return true;
    }

    function penalizeEngine(
        address engineAddress,
        uint256 penaltyAmount,
        string calldata reason
    ) external override onlyRole(BOUNTY_MANAGER_ROLE) returns (bool success) {
        EngineProfile storage profile = engines[engineAddress];
        require(profile.isActive, "Engine not active");

        uint256 oldReputation = profile.reputation;
        if (profile.reputation > penaltyAmount) {
            profile.reputation -= penaltyAmount;
        } else {
            profile.reputation = MIN_REPUTATION;
        }

        reputationHistory[engineAddress].push(
            ReputationRecord({
                timestamp: block.timestamp,
                oldReputation: oldReputation,
                newReputation: profile.reputation,
                changeType: 1, // 1 = penalty
                bountyId: 0 // not tied to specific bounty
            })
        );

        emit EnginePenalized(engineAddress, penaltyAmount, reason);
        emit ReputationUpdated(
            engineAddress,
            oldReputation,
            profile.reputation,
            reason
        );
        return true;
    }

    function recordSubmission(
        address engine,
        uint256 bountyId,
        bool prediction,
        uint256 stakeAmount,
        uint256 confidenceScore
    ) external onlyRole(BOUNTY_MANAGER_ROLE) returns (uint256) {
        require(engines[engine].isActive, "Engine not active");
        require(confidenceScore <= 100, "Invalid confidence score");

        uint256 submissionId = nextSubmissionId++;

        submissions[submissionId] = SubmissionRecord({
            engine: engine,
            bountyId: bountyId,
            prediction: prediction,
            actualResult: false,
            stakeAmount: stakeAmount,
            timestamp: block.timestamp,
            isResolved: false,
            confidenceScore: confidenceScore
        });

        engineSubmissions[engine].push(submissionId);
        engines[engine].totalSubmissions += 1;
        engines[engine].totalStakeAmount += stakeAmount;
        engines[engine].lastActiveTimestamp = block.timestamp;

        emit SubmissionRecorded(
            submissionId,
            engine,
            bountyId,
            prediction,
            stakeAmount
        );
        return submissionId;
    }

    function resolveSubmission(
        uint256 submissionId,
        bool actualResult
    ) external onlyRole(BOUNTY_MANAGER_ROLE) {
        SubmissionRecord storage submission = submissions[submissionId];
        require(!submission.isResolved, "Submission already resolved");
        require(submission.engine != address(0), "Invalid submission");

        submission.actualResult = actualResult;
        submission.isResolved = true;

        bool isCorrect = submission.prediction == actualResult;
        uint256 reputationChange = _updateEngineReputation(
            submission.engine,
            submissionId,
            isCorrect
        );

        emit SubmissionResolved(submissionId, isCorrect, reputationChange);
    }

    function updateReputation(
        address engine,
        bool success
    ) external onlyRole(BOUNTY_MANAGER_ROLE) {
        // Wrapper for compatibility if needed, but prefer resolveSubmission
        EngineProfile storage profile = engines[engine];
        uint256 oldReputation = profile.reputation;
        uint256 change = success ? 10 : 5; // Example, adjust as needed
        if (success) {
            profile.reputation = (profile.reputation + change > MAX_REPUTATION)
                ? MAX_REPUTATION
                : profile.reputation + change;
        } else {
            profile.reputation = (profile.reputation > change)
                ? profile.reputation - change
                : MIN_REPUTATION;
        }
        emit ReputationUpdated(
            engine,
            oldReputation,
            profile.reputation,
            success ? "Success" : "Failure"
        );
    }

    /**
     * @notice Update engine reputation based on analysis accuracy (interface implementation)
     * @param engineAddress Address of the engine
     * @param bountyId ID of the bounty being analyzed
     * @param wasCorrect Whether the engine's analysis was correct
     * @param stakeAmount Amount staked by the engine
     * @return newReputation Updated reputation score
     */
    function updateReputationForAnalysis(
        address engineAddress,
        uint256 bountyId,
        bool wasCorrect,
        uint256 stakeAmount
    )
        external
        override
        onlyRole(BOUNTY_MANAGER_ROLE)
        returns (uint256 newReputation)
    {
        EngineProfile storage profile = engines[engineAddress];
        require(profile.isActive, "Engine not active");

        uint256 oldReputation = profile.reputation;

        // Calculate reputation change based on correctness and stake
        uint256 change;
        if (wasCorrect) {
            // Base gain + stake-based bonus
            change = 5 + (stakeAmount / 1000);
            if (change > 20) change = 20; // Cap gain
            profile.reputation = (profile.reputation + change > MAX_REPUTATION)
                ? MAX_REPUTATION
                : profile.reputation + change;
            profile.correctPredictions += 1;
        } else {
            // Base loss + stake-based penalty
            change = 10 + (stakeAmount / 500);
            if (change > 30) change = 30; // Cap loss
            profile.reputation = (profile.reputation > change)
                ? profile.reputation - change
                : MIN_REPUTATION;
        }

        profile.totalSubmissions += 1;
        profile.lastActiveTimestamp = block.timestamp;

        reputationHistory[engineAddress].push(
            ReputationRecord({
                timestamp: block.timestamp,
                oldReputation: oldReputation,
                newReputation: profile.reputation,
                changeType: wasCorrect ? uint8(0) : uint8(2), // 0 = reward, 2 = incorrect
                bountyId: bountyId
            })
        );

        emit ReputationUpdated(
            engineAddress,
            oldReputation,
            profile.reputation,
            wasCorrect ? "Correct analysis" : "Incorrect analysis"
        );
        return profile.reputation;
    }

    /**
     * @notice Apply reputation decay for a specific inactive engine (interface implementation)
     * @param engineAddress Address of the engine
     * @return newReputation Updated reputation after decay
     */
    function applyReputationDecay(
        address engineAddress
    ) external override onlyRole(ADMIN_ROLE) returns (uint256 newReputation) {
        EngineProfile storage profile = engines[engineAddress];
        require(profile.isRegistered, "Engine not registered");
        require(
            block.timestamp >= profile.lastActiveTimestamp + 30 days,
            "Decay not due yet"
        );

        uint256 oldReputation = profile.reputation;
        uint256 decayAmount = (profile.reputation * DECAY_RATE) / 100;

        if (profile.reputation > decayAmount) {
            profile.reputation -= decayAmount;
        } else {
            profile.reputation = MIN_REPUTATION;
        }

        reputationHistory[engineAddress].push(
            ReputationRecord({
                timestamp: block.timestamp,
                oldReputation: oldReputation,
                newReputation: profile.reputation,
                changeType: 3, // 3 = decay
                bountyId: 0
            })
        );

        emit ReputationDecayed(engineAddress, decayAmount);
        emit ReputationUpdated(
            engineAddress,
            oldReputation,
            profile.reputation,
            "Reputation decay"
        );

        return profile.reputation;
    }

    function _updateEngineReputation(
        address engine,
        uint256 submissionId,
        bool isCorrect
    ) internal returns (uint256 reputationChange) {
        EngineProfile storage profile = engines[engine];
        SubmissionRecord storage submission = submissions[submissionId];

        uint256 oldReputation = profile.reputation;

        // Calculate components
        uint256 accuracyScore = _getAccuracyScore(engine);
        uint256 participationScore = _getParticipationScore(engine);
        uint256 consistencyScore = _getConsistencyScore(engine);

        // Weighted reputation base
        uint256 weightedBase = (accuracyScore * ACCURACY_WEIGHT +
            participationScore * PARTICIPATION_WEIGHT +
            consistencyScore * CONSISTENCY_WEIGHT) / 100;

        // Adjust for this submission
        reputationChange = isCorrect
            ? _calculateReputationGain(engine, submissionId)
            : _calculateReputationLoss(engine, submissionId);

        if (isCorrect) {
            profile.correctPredictions += 1;
            profile.consecutiveCorrect += 1;

            if (profile.consecutiveCorrect > profile.maxConsecutiveCorrect) {
                profile.maxConsecutiveCorrect = profile.consecutiveCorrect;
            }

            profile.reputation = (weightedBase + reputationChange >
                MAX_REPUTATION)
                ? MAX_REPUTATION
                : weightedBase + reputationChange;
        } else {
            profile.consecutiveCorrect = 0;

            if (submission.prediction && !submission.actualResult) {
                profile.falsePositives += 1;
            } else if (!submission.prediction && submission.actualResult) {
                profile.falseNegatives += 1;
            }

            profile.reputation = (weightedBase > reputationChange)
                ? weightedBase - reputationChange
                : MIN_REPUTATION;
        }

        reputationHistory[engine].push(
            ReputationRecord({
                timestamp: block.timestamp,
                oldReputation: oldReputation,
                newReputation: profile.reputation,
                changeType: isCorrect ? uint8(0) : uint8(2), // 0 = reward, 2 = incorrect prediction
                bountyId: submission.bountyId
            })
        );

        emit ReputationUpdated(
            engine,
            oldReputation,
            profile.reputation,
            isCorrect ? "Correct prediction" : "Incorrect prediction"
        );
    }

    // Helper functions for weighted scores (added)
    function _getAccuracyScore(address engine) internal view returns (uint256) {
        EngineProfile storage profile = engines[engine];
        if (profile.totalSubmissions < MIN_SUBMISSIONS_FOR_RATING) return 50; // Default
        return (profile.correctPredictions * 100) / profile.totalSubmissions;
    }

    function _getParticipationScore(
        address engine
    ) internal view returns (uint256) {
        EngineProfile storage profile = engines[engine];
        // Example: Scale based on submissions, cap at 100
        return profile.totalSubmissions > 100 ? 100 : profile.totalSubmissions;
    }

    function _getConsistencyScore(
        address engine
    ) internal view returns (uint256) {
        EngineProfile storage profile = engines[engine];
        // Example: Based on consecutive correct, cap at 100
        return
            profile.maxConsecutiveCorrect > 100
                ? 100
                : profile.maxConsecutiveCorrect;
    }

    function _calculateReputationGain(
        address engine,
        uint256 submissionId
    ) internal view returns (uint256) {
        EngineProfile memory profile = engines[engine];
        SubmissionRecord memory submission = submissions[submissionId];

        // Base gain
        uint256 baseGain = 5;

        // Confidence bonus (higher confidence = higher reward if correct)
        uint256 confidenceBonus = submission.confidenceScore / 20; // 0-5 bonus

        // Consistency bonus
        uint256 consistencyBonus = profile.consecutiveCorrect / 5; // Bonus for streaks

        // Stake-based bonus (higher stake = higher reward)
        uint256 stakeBonus = submission.stakeAmount / 1000; // Adjust divisor as needed
        if (stakeBonus > 10) stakeBonus = 10; // Cap at 10

        return baseGain + confidenceBonus + consistencyBonus + stakeBonus;
    }

    function _calculateReputationLoss(
        address /* engine */,
        uint256 submissionId
    ) internal view returns (uint256) {
        SubmissionRecord memory submission = submissions[submissionId];

        // Base loss
        uint256 baseLoss = 10;

        // Confidence penalty (higher confidence = higher penalty if wrong)
        uint256 confidencePenalty = submission.confidenceScore / 10; // 0-10 penalty

        // Stake-based penalty
        uint256 stakePenalty = submission.stakeAmount / 500; // Adjust divisor as needed
        if (stakePenalty > 15) stakePenalty = 15; // Cap at 15

        return baseLoss + confidencePenalty + stakePenalty;
    }

    function getReputation(
        address engine
    ) external view override returns (uint256) {
        return engines[engine].reputation;
    }

    function getAccuracyRate(
        address engine
    ) external view override returns (uint256) {
        EngineProfile memory profile = engines[engine];
        if (profile.totalSubmissions == 0) return 0;

        return (profile.correctPredictions * 100) / profile.totalSubmissions;
    }

    function getEngineProfile(
        address engine
    ) external view returns (EngineProfile memory) {
        return engines[engine];
    }

    function getAnalystTier(address engine) external view returns (uint256) {
        uint256 reputation = engines[engine].reputation;
        for (uint256 i = 4; i > 0; i--) {
            if (reputation >= reputationTiers[i].minReputation) return i;
        }
        return 0;
    }

    /**
     * @notice Apply reputation decay for all inactive engines (batch operation)
     * @dev This is a convenience function to apply decay to all engines at once
     */
    function applyReputationDecayAll() external onlyRole(ADMIN_ROLE) {
        require(
            block.timestamp >= decayTimestamp + 30 days,
            "Decay not due yet"
        );

        for (uint256 i = 0; i < activeEngines.length; i++) {
            address engine = activeEngines[i];
            EngineProfile storage profile = engines[engine];

            if (block.timestamp >= profile.lastActiveTimestamp + 30 days) {
                uint256 oldReputation = profile.reputation;
                uint256 decayAmount = (profile.reputation * DECAY_RATE) / 100;
                if (profile.reputation > decayAmount) {
                    profile.reputation -= decayAmount;
                } else {
                    profile.reputation = MIN_REPUTATION;
                }

                reputationHistory[engine].push(
                    ReputationRecord({
                        timestamp: block.timestamp,
                        oldReputation: oldReputation,
                        newReputation: profile.reputation,
                        changeType: 3, // 3 = decay
                        bountyId: 0 // not tied to specific bounty
                    })
                );

                emit ReputationDecayed(engine, decayAmount);
            }
        }

        decayTimestamp = block.timestamp;
    }

    function _initializeReputationTiers() internal {
        reputationTiers[0] = ReputationTier(0, 100, 0, "Novice");
        reputationTiers[1] = ReputationTier(200, 150, 5, "Beginner");
        reputationTiers[2] = ReputationTier(400, 200, 10, "Intermediate");
        reputationTiers[3] = ReputationTier(600, 300, 20, "Advanced");
        reputationTiers[4] = ReputationTier(800, 500, 35, "Expert");
    }

    function getReputationTier(
        uint256 tier
    ) external view returns (ReputationTier memory) {
        return reputationTiers[tier];
    }

    function getTopAnalysts(
        uint256 limit
    ) external view returns (address[] memory) {
        require(limit > 0 && limit <= activeEngines.length, "Invalid limit");

        // NOTE: For efficiency, this could be improved with a better data structure, but kept as-is for now
        address[] memory sortedEngines = new address[](limit);

        for (uint256 i = 0; i < limit && i < activeEngines.length; i++) {
            address maxEngine = activeEngines[0];
            uint256 maxReputation = 0;

            for (uint256 j = 0; j < activeEngines.length; j++) {
                bool alreadySelected = false;
                for (uint256 k = 0; k < i; k++) {
                    if (sortedEngines[k] == activeEngines[j]) {
                        alreadySelected = true;
                        break;
                    }
                }

                if (
                    !alreadySelected &&
                    engines[activeEngines[j]].reputation > maxReputation
                ) {
                    maxEngine = activeEngines[j];
                    maxReputation = engines[activeEngines[j]].reputation;
                }
            }

            sortedEngines[i] = maxEngine;
        }

        return sortedEngines;
    }

    function getTotalAnalysts() external view returns (uint256) {
        return totalActiveEngines;
    }

    function isEligibleForTier(
        address engine,
        uint256 requiredTier
    ) external view returns (bool) {
        uint256 currentTier = this.getAnalystTier(engine);
        return currentTier >= requiredTier;
    }

    function getReputationHistory(
        address engineAddress,
        uint256 limit
    ) external view override returns (ReputationRecord[] memory records) {
        require(limit > 0, "Invalid limit");
        uint256 histLen = reputationHistory[engineAddress].length;
        uint256 recLen = histLen < limit ? histLen : limit;
        records = new ReputationRecord[](recLen);
        uint256 start = histLen - recLen;
        for (uint256 i = 0; i < recLen; i++) {
            records[i] = reputationHistory[engineAddress][start + i];
        }
        return records;
    }

    function getTopEngines(
        uint256 limit
    )
        external
        view
        override
        returns (address[] memory enginesList, uint256[] memory reputations)
    {
        require(limit > 0 && limit <= activeEngines.length, "Invalid limit");

        enginesList = new address[](limit);
        reputations = new uint256[](limit);

        // NOTE: Same efficiency note as getTopAnalysts
        for (uint256 i = 0; i < limit && i < activeEngines.length; i++) {
            address maxEngine = activeEngines[0];
            uint256 maxReputation = 0;

            for (uint256 j = 0; j < activeEngines.length; j++) {
                bool alreadySelected = false;
                for (uint256 k = 0; k < i; k++) {
                    if (enginesList[k] == activeEngines[j]) {
                        alreadySelected = true;
                        break;
                    }
                }

                if (
                    !alreadySelected &&
                    engines[activeEngines[j]].reputation > maxReputation
                ) {
                    maxEngine = activeEngines[j];
                    maxReputation = engines[activeEngines[j]].reputation;
                }
            }

            enginesList[i] = maxEngine;
            reputations[i] = maxReputation;
        }
        return (enginesList, reputations);
    }

    function calculateRequiredStake(
        address engineAddress,
        uint256 baseStake
    ) external view override returns (uint256 requiredStake) {
        EngineProfile storage profile = engines[engineAddress];
        uint256 multiplier = this.getEngineMultiplier(profile.engineType);
        return (baseStake * multiplier) / 100;
    }

    function rewardEngine(
        address engineAddress,
        uint256 rewardAmount,
        uint256 bountyId
    ) external onlyRole(BOUNTY_MANAGER_ROLE) {
        EngineProfile storage profile = engines[engineAddress];
        profile.totalRewards += rewardAmount;
        emit EngineRewarded(engineAddress, rewardAmount, bountyId);
    }
}
