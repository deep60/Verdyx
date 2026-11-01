// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title IReputationSystem
 * @dev Interface for the Verdyx reputation system
 * @notice Manages reputation scores for security analysts and automated engines
 */

interface IReputationSystem {
    // ============ Events ============

    /**
     * @notice Emitted when an engine is registered
     * @param engineAddress The address of the registered engine
     * @param engineType Type of engine (0: Human, 1: Automated)
     * @param initialReputation Initial reputation score
     */
    event EngineRegistered(
        address indexed engineAddress,
        uint8 engineType,
        uint256 initialReputation
    );

    /**
     * @notice Emitted when reputation is updated
     * @param engineAddress The engine whose reputation changed
     * @param oldReputation Previous reputation score
     * @param newReputation New reputation score
     * @param reason Reason for reputation change
     */
    event ReputationUpdated(
        address indexed engineAddress,
        uint256 oldReputation,
        uint256 newReputation,
        string reason
    );

    /**
     * @notice Emitted when an engine is penalized
     * @param engineAddress The penalized engine
     * @param penaltyAmount Amount of reputation lost
     * @param reason Reason for penalty
     */
    event EnginePenalized(
        address indexed engineAddress,
        uint256 penaltyAmount,
        string reason
    );

    /**
     * @notice Emitted when an engine is rewarded
     * @param engineAddress The rewarded engine
     * @param rewardAmount Amount of reputation gained
     * @param bountyId Associated bounty ID
     */
    event EngineRewarded(
        address indexed engineAddress,
        uint256 rewardAmount,
        uint256 indexed bountyId
    );

    /**
     * @notice Emitted when reputation decay is applied
     * @param engineAddress The engine affected by decay
     * @param decayAmount Amount of reputation decayed
     */
    event ReputationDecayed(address indexed engineAddress, uint256 decayAmount);

    // ============ Structs ============

    /**
     * @notice Engine information structure
     * @param isRegistered Whether the engine is registered
     * @param engineType Type of engine (0: Human, 1: Automated)
     * @param reputation Current reputation score
     * @param totalAnalyses Total number of analyses performed
     * @param correctAnalyses Number of correct analyses
     * @param lastActivityTimestamp Timestamp of last activity
     * @param registrationTimestamp When the engine was registered
     * @param isActive Whether the engine is currently active
     */
    struct EngineInfo {
        bool isRegistered;
        uint8 engineType;
        uint256 reputation;
        uint256 totalAnalyses;
        uint256 correctAnalyses;
        uint256 lastActivityTimestamp;
        uint256 registrationTimestamp;
        bool isActive;
    }

    /**
     * @notice Reputation change record
     * @param timestamp When the change occurred
     * @param oldReputation Previous reputation
     * @param newReputation New reputation
     * @param changeType Type of change (0: Reward, 1: Penalty, 2: Decay)
     * @param bountyId Associated bounty (0 if not applicable)
     */
    struct ReputationRecord {
        uint256 timestamp;
        uint256 oldReputation;
        uint256 newReputation;
        uint8 changeType;
        uint256 bountyId;
    }

    // ============ Engine Management ============

    /**
     * @notice Register a new engine in the reputation system
     * @param engineAddress Address of the engine to register
     * @param engineType Type of engine (0: Human, 1: Automated)
     * @return success Whether registration was successful
     */
    function registerEngine(
        address engineAddress,
        uint8 engineType
    ) external returns (bool success);

    /**
     * @notice Deactivate an engine
     * @param engineAddress Address of the engine to deactivate
     * @return success Whether deactivation was successful
     */
    function deactivateEngine(
        address engineAddress
    ) external returns (bool success);

    /**
     * @notice Reactivate a previously deactivated engine
     * @param engineAddress Address of the engine to reactivate
     * @return success Whether reactivation was successful
     */
    function reactivateEngine(
        address engineAddress
    ) external returns (bool success);

    // ============ Reputation Updates ============

    /**
     * @notice Update engine reputation based on analysis accuracy
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
    ) external returns (uint256 newReputation);

    /**
     * @notice Apply penalty to an engine for malicious behavior
     * @param engineAddress Address of the engine to penalize
     * @param penaltyAmount Amount of reputation to deduct
     * @param reason Reason for the penalty
     * @return success Whether penalty was applied successfully
     */
    function penalizeEngine(
        address engineAddress,
        uint256 penaltyAmount,
        string calldata reason
    ) external returns (bool success);

    /**
     * @notice Apply reputation decay for inactive engines
     * @param engineAddress Address of the engine
     * @return newReputation Updated reputation after decay
     */
    function applyReputationDecay(
        address engineAddress
    ) external returns (uint256 newReputation);

    // ============ View Functions ============

    /**
     * @notice Get current reputation score of an engine
     * @param engineAddress Address of the engine
     * @return reputation Current reputation score
     */
    function getReputation(
        address engineAddress
    ) external view returns (uint256 reputation);

    /**
     * @notice Get detailed information about an engine
     * @param engineAddress Address of the engine
     * @return engineInfo Complete engine information
     */
    // function getEngineInfo(address engineAddress)
    //     external
    //     view
    //     override
    //     returns (EngineInfo memory)
    // {
    //     AnalystProfile storage profile = analysts[engineAddress];
    //     return EngineInfo({
    //         isRegistered: profile.isActive,
    //         engineType: uint8(profile.category),
    //         reputation: profile.reputation,
    //         totalAnalyses: profile.totalSubmissions,
    //         correctAnalyses: profile.correctPredictions,
    //         lastActivityTimestamp: profile.lastActiveTimestamp,
    //         registrationTimestamp: profile.registrationTimestamp,
    //         isActive: profile.isActive
    //     });
    // }

    /**
     * @notice Get accuracy rate of an engine
     * @param engineAddress Address of the engine
     * @return accuracyRate Accuracy as a percentage (0-10000, where 10000 = 100%)
     */
    function getAccuracyRate(
        address engineAddress
    ) external view returns (uint256 accuracyRate);

    /**
     * @notice Check if an engine is eligible to participate in bounties
     * @param engineAddress Address of the engine
     * @return eligible Whether the engine meets minimum reputation requirements
     */
    function isEligibleEngine(
        address engineAddress
    ) external view returns (bool eligible);

    /**
     * @notice Get reputation history for an engine
     * @param engineAddress Address of the engine
     * @param limit Maximum number of records to return
     * @return records Array of reputation change records
     */
    function getReputationHistory(
        address engineAddress,
        uint256 limit
    ) external view returns (ReputationRecord[] memory records);

    /**
     * @notice Get list of top engines by reputation
     * @param limit Maximum number of engines to return
     * @return engines Array of engine addresses sorted by reputation
     * @return reputations Corresponding reputation scores
     */
    function getTopEngines(
        uint256 limit
    )
        external
        view
        returns (address[] memory engines, uint256[] memory reputations);

    /**
     * @notice Calculate required stake amount based on reputation
     * @param engineAddress Address of the engine
     * @param baseStake Base stake amount for the bounty
     * @return requiredStake Adjusted stake amount based on reputation
     */
    function calculateRequiredStake(
        address engineAddress,
        uint256 baseStake
    ) external view returns (uint256 requiredStake);

    // ============ Configuration ============

    /**
     * @notice Get minimum reputation required to participate
     * @return minReputation Minimum reputation threshold
     */
    function getMinimumReputation()
        external
        view
        returns (uint256 minReputation);

    /**
     * @notice Get reputation decay parameters
     * @return decayRate Rate of decay per time period
     * @return decayPeriod Time period for decay application
     */
    function getDecayParameters()
        external
        view
        returns (uint256 decayRate, uint256 decayPeriod);

    /**
     * @notice Get reputation multipliers for different engine types
     * @param engineType Type of engine (0: Human, 1: Automated)
     * @return multiplier Reputation multiplier for rewards/penalties
     */
    function getEngineMultiplier(
        uint8 engineType
    ) external view returns (uint256 multiplier);
}
