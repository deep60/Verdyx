// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title IBountyManager
 * @dev Interface for the Verdyx Bounty Manager contract
 * @notice Defines the core functionality for managing threat analysis bounties
 */
interface IBountyManager {
    // ============ ENUMS ============

    /**
     * @dev Enumeration of possible bounty states
     */
    enum BountyStatus {
        Active, // Bounty is open for submissions
        InReview, // Analysis period has ended, consensus being calculated
        Completed, // Bounty resolved with consensus
        Cancelled, // Bounty cancelled by creator
        Disputed // Bounty under dispute resolution
    }

    /**
     * @dev Enumeration of threat verdicts
     */
    enum ThreatVerdict {
        Pending, // No verdict yet
        Benign, // File/URL is safe
        Malicious, // File/URL is a threat
        Suspicious // File/URL requires further investigation
    }

    // ============ STRUCTS ============

    /**
     * @dev Structure representing a bounty
     */
    struct Bounty {
        uint256 id; // Unique bounty identifier
        address creator; // Address that created the bounty
        string artifactHash; // Hash of the artifact being analyzed
        string artifactType; // Type: "file", "url", "hash", etc.
        uint256 rewardAmount; // Total reward amount in tokens
        uint256 deadline; // Timestamp when analysis period ends
        string description; // Description of the bounty
        BountyStatus status; // Current status of the bounty
        ThreatVerdict consensusVerdict; // Final consensus verdict
        uint256 totalStaked; // Total tokens staked
        uint256 analysisCount; // Number of analyses submitted
        uint256 createdAt; // Timestamp when bounty was created
    }

    /**
     * @dev Structure representing an analysis submission
     */
    struct Analysis {
        uint256 bountyId; // ID of the associated bounty
        address analyst; // Address of the analyzing engine
        ThreatVerdict verdict; // Engine's verdict
        uint256 confidence; // Engine's confidence (0-100)
        uint256 stakeAmount; // Amount staked by engine
        string analysisHash; // IPFS hash or analysis details
        uint256 submittedAt; // Timestamp of submission
        bool rewarded; // Whether engine has been rewarded
    }

    // ============ EVENTS ============

    /**
     * @dev Emitted when a new bounty is created
     */
    event BountyCreated(
        uint256 indexed bountyId,
        address indexed creator,
        string targetHash,
        uint256 reward,
        uint256 deadline
    );

    /**
     * @dev Emitted when an analysis is submitted
     */
    event AnalysisSubmitted(
        uint256 indexed bountyId,
        address indexed engine,
        ThreatVerdict verdict,
        uint256 stake,
        uint256 confidence
    );

    /**
     * @dev Emitted when a bounty reaches consensus
     */
    event ConsensusReached(
        uint256 indexed bountyId,
        ThreatVerdict consensus,
        uint256 confidenceScore,
        uint256 totalAnalyses
    );

    /**
     * @dev Emitted when rewards are distributed
     */
    event RewardsDistributed(
        uint256 indexed bountyId,
        address[] winners,
        uint256[] rewards,
        uint256[] stakes
    );

    /**
     * @dev Emitted when a bounty is cancelled
     */
    event BountyCancelled(
        uint256 indexed bountyId,
        address indexed creator,
        string reason
    );

    /**
     * @dev Emitted when minimum stake is updated
     */
    event MinimumStakeUpdated(uint256 oldStake, uint256 newStake);

    // ============ BOUNTY MANAGEMENT FUNCTIONS ============

    /**
     * @dev Creates a new threat analysis bounty
     * @param artifactHash Hash or identifier of the artifact to analyze
     * @param artifactType Type of artifact ("file", "url", "domain", etc.)
     * @param rewardAmount Reward amount in tokens
     * @param deadline Timestamp when analysis period ends
     * @param description Description of the bounty
     * @return bountyId The ID of the created bounty
     */
    function createBounty(
        string calldata artifactHash,
        string calldata artifactType,
        uint256 rewardAmount,
        uint256 deadline,
        string calldata description
    ) external returns (uint256 bountyId);

    /**
     * @dev Submits an analysis for a bounty
     * @param bountyId ID of the bounty to analyze
     * @param verdict The engine's verdict on the threat
     * @param confidence Confidence level (0-100)
     * @param stakeAmount Amount of tokens to stake
     * @param analysisHash IPFS hash or analysis details
     */
    function submitAnalysis(
        uint256 bountyId,
        ThreatVerdict verdict,
        uint256 confidence,
        uint256 stakeAmount,
        string calldata analysisHash
    ) external;

    /**
     * @dev Resolves a bounty by calculating consensus and distributing rewards
     * @param bountyId ID of the bounty to resolve
     */
    function resolveBounty(uint256 bountyId) external;

    /**
     * @dev Cancels a bounty (only by creator before deadline)
     * @param bountyId ID of the bounty to cancel
     * @param reason Reason for cancellation
     */
    function cancelBounty(uint256 bountyId, string calldata reason) external;

    // ============ STAKING AND REWARDS ============

    /**
     * @dev Allows engines to withdraw their stakes from completed bounties
     * @param bountyId ID of the bounty to withdraw from
     */
    function withdrawStake(uint256 bountyId) external;

    /**
     * @dev Claims rewards for accurate analyses
     * @param bountyIds Array of bounty IDs to claim rewards from
     */
    function claimRewards(uint256[] calldata bountyIds) external;

    /**
     * @dev Emergency function to withdraw unclaimed rewards after timeout
     * @param bountyId ID of the bounty
     */
    function emergencyWithdraw(uint256 bountyId) external;

    // ============ VIEW FUNCTIONS ============

    /**
     * @dev Gets bounty information
     * @param bountyId ID of the bounty
     * @return id Bounty ID
     * @return creator Creator address
     * @return targetHash Hash of target
     * @return targetType Type of target
     * @return reward Reward amount
     * @return minimumStake Minimum stake required
     * @return deadline Analysis deadline
     * @return createdAt Creation timestamp
     * @return status Bounty status
     * @return consensus Consensus verdict
     * @return confidenceScore Confidence score
     * @return totalAnalyses Total number of analyses
     */
    function getBounty(
        uint256 bountyId
    )
        external
        view
        returns (
            uint256 id,
            address creator,
            string memory targetHash,
            string memory targetType,
            uint256 reward,
            uint256 minimumStake,
            uint256 deadline,
            uint256 createdAt,
            BountyStatus status,
            ThreatVerdict consensus,
            uint256 confidenceScore,
            uint256 totalAnalyses
        );

    /**
     * @dev Gets analysis information
     * @param bountyId ID of the bounty
     * @param engine Address of the analyzing engine
     * @return verdict Analysis verdict
     * @return stake Stake amount
     * @return confidence Confidence level
     * @return analysisData Analysis data hash
     * @return submittedAt Submission timestamp
     * @return isRewarded Whether rewarded
     */
    function getAnalysis(
        uint256 bountyId,
        address engine
    )
        external
        view
        returns (
            ThreatVerdict verdict,
            uint256 stake,
            uint256 confidence,
            string memory analysisData,
            uint256 submittedAt,
            bool isRewarded
        );

    /**
     * @dev Gets all analyses for a bounty
     * @param bountyId ID of the bounty
     * @return engines Array of engine addresses
     * @return verdicts Array of verdicts
     * @return stakes Array of stakes
     * @return confidences Array of confidence scores
     */
    function getBountyAnalyses(
        uint256 bountyId
    )
        external
        view
        returns (
            address[] memory engines,
            ThreatVerdict[] memory verdicts,
            uint256[] memory stakes,
            uint256[] memory confidences
        );

    /**
     * @dev Gets active bounties count
     * @return Number of active bounties
     */
    function getActiveBountiesCount() external view returns (uint256);

    /**
     * @dev Gets bounties created by a specific address
     * @param creator Address of the bounty creator
     * @return Array of bounty IDs
     */
    function getBountiesByCreator(
        address creator
    ) external view returns (uint256[] memory);

    /**
     * @dev Gets bounties analyzed by a specific engine
     * @param engine Address of the analyzing engine
     * @return Array of bounty IDs
     */
    function getBountiesByEngine(
        address engine
    ) external view returns (uint256[] memory);

    /**
     * @dev Checks if an engine has analyzed a specific bounty
     * @param bountyId ID of the bounty
     * @param engine Address of the engine
     * @return Whether the engine has submitted an analysis
     */
    function hasEngineAnalyzed(
        uint256 bountyId,
        address engine
    ) external view returns (bool);

    /**
     * @dev Gets the current minimum stake requirement
     * @return Minimum stake in wei
     */
    function getMinimumStake() external view returns (uint256);

    /**
     * @dev Gets total rewards available for claiming by an engine
     * @param engine Address of the engine
     * @return Total claimable rewards in wei
     */
    function getPendingRewards(address engine) external view returns (uint256);

    // ============ ADMIN FUNCTIONS ============

    /**
     * @dev Updates the minimum stake requirement (admin only)
     * @param newMinimumStake New minimum stake amount
     */
    function setMinimumStake(uint256 newMinimumStake) external;

    /**
     * @dev Pauses the contract (admin only)
     */
    function pause() external;

    /**
     * @dev Unpauses the contract (admin only)
     */
    function unpause() external;

    /**
     * @dev Updates the reputation system contract address (admin only)
     * @param newReputationSystem Address of the new reputation system
     */
    function setReputationSystem(address newReputationSystem) external;
}
