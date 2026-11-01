// SPDX-License-Identifier: MIT
// Fixed ThreatToken.sol
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Burnable.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Pausable.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/**
 * @title ThreatToken
 * @dev ERC20 token for Verdyx threat intelligence marketplace
 *
 * Features:
 * - Standard ERC20 functionality
 * - Burnable tokens for deflationary mechanics
 * - Pausable for emergency stops
 * - Role-based access control
 * - Staking mechanism for analysis engines
 * - Reward distribution for accurate threat detection
 * - Anti-manipulation safeguards
 */

contract ThreatToken is
    ERC20,
    ERC20Burnable,
    ERC20Pausable,
    AccessControl,
    ReentrancyGuard
{
    using SafeERC20 for IERC20;

    // Roles
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    bytes32 public constant BOUNTY_MANAGER_ROLE =
        keccak256("BOUNTY_MANAGER_ROLE");
    bytes32 public constant REPUTATION_MANAGER_ROLE =
        keccak256("REPUTATION_MANAGER_ROLE");

    // Token Economics
    uint256 public constant MAX_SUPPLY = 1_000_000_000 * 10 ** 18; // 1 billion tokens
    uint256 public constant INITIAL_SUPPLY = 100_000_000 * 10 ** 18; // 100 million tokens

    // Staking Configuration
    uint256 public constant MIN_STAKE_AMOUNT = 100 * 10 ** 18; // Minimum 100 tokens to stake
    uint256 public constant STAKE_LOCK_PERIOD = 24 hours; // 24 hours lock period
    uint256 public constant SLASH_PERCENTAGE = 10; // 10% slashing for incorrect analysis

    // Reward Configuration
    uint256 public constant BASE_REWARD_RATE = 5; // 5% base reward for correct analysis
    uint256 public constant BONUS_MULTIPLIER = 150; // 150% multiplier for first correct analysis

    // Structs
    struct Stake {
        uint256 amount;
        uint256 lockTime;
        bool active;
        address engine;
        bytes32 analysisId;
    }

    struct RewardPool {
        uint256 totalPool;
        uint256 distributed;
        mapping(address => uint256) engineRewards;
        bool finalized;
    }

    // State Variables
    mapping(address => Stake[]) public engineStakes;
    mapping(bytes32 => RewardPool) public analysisRewards;
    mapping(address => uint256) public totalStaked;
    mapping(address => uint256) public engineReputation;
    mapping(address => bool) public authorizedEngines;
    uint256 public globalActiveStakes; // Added for emergency recover tracking

    // Events
    event Staked(
        address indexed engine,
        uint256 amount,
        bytes32 indexed analysisId,
        uint256 stakeIndex
    );
    event Unstaked(
        address indexed engine,
        uint256 amount,
        bytes32 indexed analysisId,
        uint256 stakeIndex
    );
    event Slashed(
        address indexed engine,
        uint256 amount,
        bytes32 indexed analysisId,
        uint256 stakeIndex
    );
    event RewardDistributed(
        address indexed engine,
        uint256 amount,
        bytes32 indexed analysisId
    );
    event EngineAuthorized(address indexed engine, bool authorized);
    event ReputationUpdated(address indexed engine, uint256 newReputation);
    event TokensMinted(address indexed to, uint256 amount); // Added for mint transparency

    constructor(address admin) ERC20("ThreatToken", "THREAT") {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(PAUSER_ROLE, admin);
        _grantRole(MINTER_ROLE, admin);
        _grantRole(BOUNTY_MANAGER_ROLE, admin);
        _grantRole(REPUTATION_MANAGER_ROLE, admin);

        // Mint initial supply to admin
        _mint(admin, INITIAL_SUPPLY);
    }

    /**
     * @dev Mint new tokens (up to max supply)
     * @param to Address to mint tokens to
     * @param amount Amount of tokens to mint
     */
    function mint(address to, uint256 amount) external onlyRole(MINTER_ROLE) {
        require(totalSupply() + amount <= MAX_SUPPLY, "Exceeds max supply");
        _mint(to, amount);
        emit TokensMinted(to, amount);
    }

    /**
     * @dev Pause all token transfers
     */
    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }

    /**
     * @dev Unpause all token transfers
     */
    function unpause() external onlyRole(PAUSER_ROLE) {
        _unpause();
    }

    /**
     * @dev Authorize or deauthorize an analysis engine
     * @param engine Address of the engine
     * @param authorized Whether the engine is authorized
     */
    function setEngineAuthorization(
        address engine,
        bool authorized
    ) external onlyRole(REPUTATION_MANAGER_ROLE) {
        authorizedEngines[engine] = authorized;
        emit EngineAuthorized(engine, authorized);
    }

    /**
     * @dev Stake tokens for analysis participation
     * @param amount Amount of tokens to stake
     * @param analysisId Unique identifier for the analysis
     */
    function stakeForAnalysis(
        uint256 amount,
        bytes32 analysisId
    ) external nonReentrant whenNotPaused {
        require(authorizedEngines[msg.sender], "Engine not authorized");
        require(amount >= MIN_STAKE_AMOUNT, "Amount below minimum stake");
        require(balanceOf(msg.sender) >= amount, "Insufficient balance");

        // Transfer tokens to contract
        _transfer(msg.sender, address(this), amount);

        // Create stake record
        Stake memory newStake = Stake({
            amount: amount,
            lockTime: block.timestamp + STAKE_LOCK_PERIOD,
            active: true,
            engine: msg.sender,
            analysisId: analysisId
        });

        engineStakes[msg.sender].push(newStake);
        totalStaked[msg.sender] += amount;
        globalActiveStakes += amount; // Added

        uint256 stakeIndex = engineStakes[msg.sender].length - 1;
        emit Staked(msg.sender, amount, analysisId, stakeIndex);
    }

    /**
     * @dev Unstake tokens after lock period (if analysis allows)
     * @param stakeIndex Index of the stake to unstake
     */
    function unstake(uint256 stakeIndex) external nonReentrant whenNotPaused {
        require(
            stakeIndex < engineStakes[msg.sender].length,
            "Invalid stake index"
        );

        Stake storage stake = engineStakes[msg.sender][stakeIndex];
        require(stake.active, "Stake not active");
        require(stake.engine == msg.sender, "Not stake owner");
        require(block.timestamp >= stake.lockTime, "Stake still locked");
        require(
            analysisRewards[stake.analysisId].finalized,
            "Analysis not finalized"
        );

        uint256 amount = stake.amount;
        stake.active = false;
        totalStaked[msg.sender] -= amount;
        globalActiveStakes -= amount; // Added

        // Return tokens to engine
        _transfer(address(this), msg.sender, amount);

        emit Unstaked(msg.sender, amount, stake.analysisId, stakeIndex);
    }

    /**
     * @dev Slash tokens from incorrect analysis
     * @param engine Address of the engine to slash
     * @param stakeIndex Index of the stake to slash
     */
    function slashStake(
        address engine,
        uint256 stakeIndex
    ) external onlyRole(BOUNTY_MANAGER_ROLE) nonReentrant {
        require(
            stakeIndex < engineStakes[engine].length,
            "Invalid stake index"
        );

        Stake storage stake = engineStakes[engine][stakeIndex];
        require(stake.active, "Stake not active");

        uint256 slashAmount = (stake.amount * SLASH_PERCENTAGE) / 100;
        uint256 remainingAmount = stake.amount - slashAmount;

        stake.amount = remainingAmount;
        totalStaked[engine] -= slashAmount;
        globalActiveStakes -= slashAmount; // Added

        // Burn slashed tokens (deflationary mechanism)
        _burn(address(this), slashAmount);

        // Update reputation
        if (engineReputation[engine] > slashAmount) {
            engineReputation[engine] -= slashAmount;
        } else {
            engineReputation[engine] = 0;
        }

        emit Slashed(engine, slashAmount, stake.analysisId, stakeIndex);
        emit ReputationUpdated(engine, engineReputation[engine]);
    }

    /**
     * @dev Distribute rewards for correct analysis
     * @param analysisId Unique identifier for the analysis
     * @param correctEngines Array of engines that provided correct analysis
     * @param isFirstCorrect Array indicating which engines were first to be correct
     */
    function distributeRewards(
        bytes32 analysisId,
        address[] calldata correctEngines,
        bool[] calldata isFirstCorrect
    ) external onlyRole(BOUNTY_MANAGER_ROLE) nonReentrant {
        require(
            correctEngines.length == isFirstCorrect.length,
            "Array length mismatch"
        );
        require(
            !analysisRewards[analysisId].finalized,
            "Rewards already distributed"
        );

        RewardPool storage rewardPool = analysisRewards[analysisId];
        uint256 totalRewardsToMint = 0;

        // First pass: Calculate total to mint
        for (uint256 i = 0; i < correctEngines.length; i++) {
            address engine = correctEngines[i];
            uint256 baseReward = _calculateBaseReward(engine, analysisId);
            uint256 finalReward = baseReward;

            if (isFirstCorrect[i]) {
                finalReward = (baseReward * BONUS_MULTIPLIER) / 100;
            }

            rewardPool.engineRewards[engine] = finalReward;
            totalRewardsToMint += finalReward;
        }

        // Check total mint against max supply
        require(
            totalSupply() + totalRewardsToMint <= MAX_SUPPLY,
            "Exceeds max supply"
        );

        // Second pass: Mint and distribute
        for (uint256 i = 0; i < correctEngines.length; i++) {
            address engine = correctEngines[i];
            uint256 finalReward = rewardPool.engineRewards[engine];

            // Update reputation
            engineReputation[engine] += finalReward;

            // Mint and transfer rewards
            _mint(engine, finalReward);
            emit RewardDistributed(engine, finalReward, analysisId);
            emit ReputationUpdated(engine, engineReputation[engine]);
        }

        rewardPool.totalPool = totalRewardsToMint;
        rewardPool.distributed = totalRewardsToMint;
        rewardPool.finalized = true;
    }

    /**
     * @dev Calculate base reward for an engine based on stake and reputation
     * @param engine Address of the engine
     * @param analysisId Analysis identifier
     * @return Base reward amount
     */
    function _calculateBaseReward(
        address engine,
        bytes32 analysisId
    ) internal view returns (uint256) {
        uint256 stakedAmount = _getStakedAmountForAnalysis(engine, analysisId);
        uint256 reputationBonus = engineReputation[engine] / 1000; // 0.1% bonus per 1000 reputation

        uint256 baseReward = (stakedAmount * BASE_REWARD_RATE) / 100;
        uint256 bonusReward = (baseReward * reputationBonus) / 100;

        return baseReward + bonusReward;
    }

    /**
     * @dev Get staked amount for a specific analysis
     * @param engine Address of the engine
     * @param analysisId Analysis identifier
     * @return Total staked amount
     */
    function _getStakedAmountForAnalysis(
        address engine,
        bytes32 analysisId
    ) internal view returns (uint256) {
        uint256 totalAmount = 0;
        Stake[] storage stakes = engineStakes[engine];

        for (uint256 i = 0; i < stakes.length; i++) {
            if (stakes[i].analysisId == analysisId && stakes[i].active) {
                totalAmount += stakes[i].amount;
            }
        }

        return totalAmount;
    }

    /**
     * @dev Get engine's stake information
     * @param engine Address of the engine
     * @return Array of active stake amounts and their analysis IDs
     */
    function getEngineStakes(
        address engine
    ) external view returns (Stake[] memory) {
        return engineStakes[engine];
    }

    /**
     * @dev Get reward information for an analysis
     * @param analysisId Analysis identifier
     * @param engine Engine address
     * @return Reward amount for the engine
     */
    function getAnalysisReward(
        bytes32 analysisId,
        address engine
    ) external view returns (uint256) {
        return analysisRewards[analysisId].engineRewards[engine];
    }

    /**
     * @dev Emergency function to recover stuck tokens
     * @param token Address of token to recover
     * @param amount Amount to recover
     */
    function emergencyRecover(
        address token,
        uint256 amount
    ) external onlyRole(DEFAULT_ADMIN_ROLE) nonReentrant {
        if (token == address(this)) {
            // Only recover excess tokens not part of active stakes
            uint256 contractBalance = balanceOf(address(this));
            require(
                amount <= contractBalance - globalActiveStakes,
                "Cannot recover staked tokens"
            );
        }

        if (token == address(0)) {
            // Recipient is constrained to the admin by onlyRole; use call (not
            // transfer) to avoid the 2300-gas stipend and check the result.
            // slither-disable-next-line arbitrary-send-eth
            (bool success, ) = payable(msg.sender).call{value: amount}("");
            require(success, "ETH recovery failed");
        } else {
            // safeTransfer reverts on tokens that return false instead of reverting.
            IERC20(token).safeTransfer(msg.sender, amount);
        }
    }

    // Override functions for pausable functionality (OpenZeppelin v5)
    function _update(
        address from,
        address to,
        uint256 amount
    ) internal override(ERC20, ERC20Pausable) {
        super._update(from, to, amount);
    }
}
