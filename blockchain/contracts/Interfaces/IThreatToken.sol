// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/**
 * @title IThreatToken
 * @dev Interface for the ThreatToken ERC20 token with staking and reward functionality
 * @notice Extends standard ERC20 with threat analysis staking mechanisms
 */
interface IThreatToken is IERC20 {
    // ============ STRUCTS ============

    /**
     * @dev Stake information for an analysis engine
     */
    struct Stake {
        uint256 amount; // Amount of tokens staked
        uint256 lockTime; // Timestamp when stake can be withdrawn
        bool active; // Whether stake is currently active
        address engine; // Address of the staking engine
        bytes32 analysisId; // Unique identifier for the analysis
    }

    /**
     * @dev Reward pool for a specific analysis
     */
    struct RewardPoolInfo {
        uint256 totalPool; // Total reward pool size
        uint256 distributed; // Amount already distributed
        bool finalized; // Whether rewards have been finalized
    }

    // ============ EVENTS ============

    /**
     * @dev Emitted when tokens are staked for analysis
     */
    event Staked(
        address indexed engine,
        uint256 amount,
        bytes32 indexed analysisId,
        uint256 stakeIndex
    );

    /**
     * @dev Emitted when staked tokens are withdrawn
     */
    event Unstaked(
        address indexed engine,
        uint256 amount,
        bytes32 indexed analysisId,
        uint256 stakeIndex
    );

    /**
     * @dev Emitted when stakes are slashed for incorrect analysis
     */
    event Slashed(
        address indexed engine,
        uint256 amount,
        bytes32 indexed analysisId,
        uint256 stakeIndex
    );

    /**
     * @dev Emitted when rewards are distributed
     */
    event RewardDistributed(
        address indexed engine,
        uint256 amount,
        bytes32 indexed analysisId
    );

    /**
     * @dev Emitted when an engine is authorized or deauthorized
     */
    event EngineAuthorized(address indexed engine, bool authorized);

    /**
     * @dev Emitted when reputation is updated
     */
    event ReputationUpdated(address indexed engine, uint256 newReputation);

    /**
     * @dev Emitted when new tokens are minted
     */
    event TokensMinted(address indexed to, uint256 amount);

    // ============ STAKING FUNCTIONS ============

    /**
     * @dev Stake tokens for analysis participation
     * @param amount Amount of tokens to stake
     * @param analysisId Unique identifier for the analysis
     */
    function stakeForAnalysis(uint256 amount, bytes32 analysisId) external;

    /**
     * @dev Unstake tokens after lock period
     * @param stakeIndex Index of the stake to unstake
     */
    function unstake(uint256 stakeIndex) external;

    /**
     * @dev Slash tokens from incorrect analysis (only bounty manager)
     * @param engine Address of the engine to slash
     * @param stakeIndex Index of the stake to slash
     */
    function slashStake(address engine, uint256 stakeIndex) external;

    /**
     * @dev Distribute rewards for correct analysis (only bounty manager)
     * @param analysisId Unique identifier for the analysis
     * @param correctEngines Array of engines that provided correct analysis
     * @param isFirstCorrect Array indicating which engines were first to be correct
     */
    function distributeRewards(
        bytes32 analysisId,
        address[] calldata correctEngines,
        bool[] calldata isFirstCorrect
    ) external;

    // ============ ADMIN FUNCTIONS ============

    /**
     * @dev Mint new tokens (up to max supply)
     * @param to Address to mint tokens to
     * @param amount Amount of tokens to mint
     */
    function mint(address to, uint256 amount) external;

    /**
     * @dev Pause all token transfers
     */
    function pause() external;

    /**
     * @dev Unpause all token transfers
     */
    function unpause() external;

    /**
     * @dev Authorize or deauthorize an analysis engine
     * @param engine Address of the engine
     * @param authorized Whether the engine is authorized
     */
    function setEngineAuthorization(address engine, bool authorized) external;

    /**
     * @dev Emergency function to recover stuck tokens
     * @param token Address of token to recover
     * @param amount Amount to recover
     */
    function emergencyRecover(address token, uint256 amount) external;

    // ============ VIEW FUNCTIONS ============

    /**
     * @dev Get engine's stake information
     * @param engine Address of the engine
     * @return Array of stake information
     */
    function getEngineStakes(
        address engine
    ) external view returns (Stake[] memory);

    /**
     * @dev Get reward information for an analysis
     * @param analysisId Analysis identifier
     * @param engine Engine address
     * @return Reward amount for the engine
     */
    function getAnalysisReward(
        bytes32 analysisId,
        address engine
    ) external view returns (uint256);

    /**
     * @dev Get total staked amount for an engine
     * @param engine Address of the engine
     * @return Total staked amount
     */
    function totalStaked(address engine) external view returns (uint256);

    /**
     * @dev Get engine reputation
     * @param engine Address of the engine
     * @return Reputation score
     */
    function engineReputation(address engine) external view returns (uint256);

    /**
     * @dev Check if an engine is authorized
     * @param engine Address of the engine
     * @return Whether the engine is authorized
     */
    function authorizedEngines(address engine) external view returns (bool);

    /**
     * @dev Get global active stakes total
     * @return Total amount of active stakes
     */
    function globalActiveStakes() external view returns (uint256);

    // ============ CONSTANTS ============

    /**
     * @dev Get maximum token supply
     * @return Maximum supply
     */
    function MAX_SUPPLY() external view returns (uint256);

    /**
     * @dev Get initial token supply
     * @return Initial supply
     */
    function INITIAL_SUPPLY() external view returns (uint256);

    /**
     * @dev Get minimum stake amount
     * @return Minimum stake amount
     */
    function MIN_STAKE_AMOUNT() external view returns (uint256);

    /**
     * @dev Get stake lock period
     * @return Lock period in seconds
     */
    function STAKE_LOCK_PERIOD() external view returns (uint256);

    /**
     * @dev Get slash percentage
     * @return Slash percentage
     */
    function SLASH_PERCENTAGE() external view returns (uint256);

    /**
     * @dev Get base reward rate
     * @return Base reward rate
     */
    function BASE_REWARD_RATE() external view returns (uint256);

    /**
     * @dev Get bonus multiplier
     * @return Bonus multiplier
     */
    function BONUS_MULTIPLIER() external view returns (uint256);
}
