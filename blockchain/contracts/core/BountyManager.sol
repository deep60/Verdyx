// Fixed BountyManager.sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "../Interfaces/IBountyManager.sol";
import "../Interfaces/IReputationSystem.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/**
 * @title BountyManager
 * @dev Manages bounties for threat intelligence analysis in the Verdyx platform
 * @author Verdyx Team
 * @notice Uses a pull-payment (withdraw) pattern for all outbound token movement so
 *         that resolution never loops over external token transfers. This prevents
 *         gas-limit griefing/DoS where a single failing or gas-heavy recipient could
 *         block resolution and permanently lock staked funds.
 */

contract BountyManager is ReentrancyGuard {
    using SafeERC20 for IERC20;
    // Enums
    enum BountyStatus {
        Active, // Bounty is open for submissions
        InReview, // Analysis period has ended, consensus being calculated
        Completed, // Bounty resolved with consensus
        Cancelled, // Bounty cancelled by creator
        Disputed // Bounty under dispute resolution
    }

    enum ThreatVerdict {
        Pending, // No verdict yet
        Benign, // File/URL is safe
        Malicious, // File/URL is a threat
        Suspicious // File/URL requires further investigation
    }

    // Structs
    struct Bounty {
        uint256 id;
        address creator;
        string artifactHash;
        string artifactType;
        uint256 rewardAmount;
        uint256 deadline;
        string description;
        BountyStatus status;
        ThreatVerdict consensusVerdict;
        uint256 totalStaked;
        uint256 analysisCount;
        uint256 createdAt;
    }

    struct Analysis {
        uint256 bountyId;
        address analyst;
        ThreatVerdict verdict;
        uint256 confidence;
        uint256 stakeAmount;
        string analysisHash;
        uint256 submittedAt;
        bool rewarded;
    }

    // state variables
    IERC20 public immutable threatToken;
    IReputationSystem public immutable reputationSystem;

    uint256 public bountyCounter;
    uint256 public constant MIN_STAKE_AMOUNT = 10 * 10 ** 18; // 10 token minimum stake
    uint256 public constant ANALYSIS_TIMEOUT = 24 hours; // 24 hours to complete analysis
    uint256 public constant CONSENSUS_THRESHOLD = 66; // 66% consensus required
    uint256 public constant PLATFORM_FEE_PERCENT = 5; // 5% platfrom fee
    uint256 public constant MIN_ANALYSES_TO_RESOLVE = 5; // Synced threshold
    uint256 public constant MAX_ANALYSTS_PER_BOUNTY = 50; // Bounds resolution loops (gas-DoS guard)

    address public owner;
    // Pending owner for the two-step ownership handover. Set by transferOwnership()
    // and cleared once acceptOwnership() is called by the new owner. The two-step
    // flow prevents transferring ownership to an address that cannot act (e.g. a
    // mistyped multisig), which for this fund-custody contract would be unrecoverable.
    address public pendingOwner;
    address public feeCollector;
    bool public paused;

    // Mappings
    mapping(uint256 => Bounty) public bounties;
    mapping(uint256 => mapping(address => Analysis)) public analyses;
    mapping(uint256 => address[]) public bountyAnalysts;
    mapping(address => uint256[]) public userBounties;
    mapping(uint256 => mapping(address => uint256)) public analystSubmissionIds; // Reserved slot; currently unused (reputation handled at resolution)

    // Pull-payment ledger: funds owed to an account, claimed via withdraw()
    mapping(address => uint256) public pendingWithdrawals;

    // Total threatToken the contract owes to users: bounty rewards + analyst
    // stakes still in escrow plus everything credited but not yet withdrawn.
    // emergencyWithdraw() is bounded by this so owner action can never touch
    // escrowed user funds — only surplus (e.g. accidentally-sent tokens).
    uint256 public totalEscrowed;

    // Events
    event BountyCreated(
        uint256 indexed bountyId,
        address indexed creator,
        string artifactHash,
        uint256 reward,
        uint256 deadline
    );

    event AnalysisSubmitted(
        uint256 indexed bountyId,
        address indexed engine,
        ThreatVerdict verdict,
        uint256 stake,
        uint256 confidence
    );

    event ConsensusReached(
        uint256 indexed bountyId,
        ThreatVerdict consensus,
        uint256 confidenceScore,
        uint256 totalAnalyses
    );

    event RewardsDistributed(
        uint256 indexed bountyId,
        address[] winners,
        uint256[] rewards,
        uint256[] stakes
    );

    event PaymentCredited(address indexed account, uint256 amount);

    event Withdrawal(address indexed account, uint256 amount);

    event OwnershipTransferStarted(
        address indexed previousOwner,
        address indexed newOwner
    );

    event OwnershipTransferred(
        address indexed previousOwner,
        address indexed newOwner
    );

    // Modifiers
    modifier onlyOwner() {
        require(msg.sender == owner, "Not authorized");
        _;
    }

    modifier notPaused() {
        require(!paused, "Contract is paused");
        _;
    }

    modifier validBounty(uint256 bountyId) {
        require(bountyId > 0 && bountyId <= bountyCounter, "Invalid bounty ID");
        _;
    }

    modifier bountyActive(uint256 bountyId) {
        require(
            bounties[bountyId].status == BountyStatus.Active,
            "Bounty not active"
        );
        require(
            block.timestamp <= bounties[bountyId].deadline,
            "Bounty expired"
        );
        _;
    }

    constructor(
        address _threatToken,
        address _reputationSystem,
        address _feeCollector
    ) {
        require(_threatToken != address(0), "Invalid token address");
        require(
            _reputationSystem != address(0),
            "Invalid reputation system address"
        );
        require(_feeCollector != address(0), "Invalid fee collector address");

        threatToken = IERC20(_threatToken);
        reputationSystem = IReputationSystem(_reputationSystem);
        feeCollector = _feeCollector;
        owner = msg.sender;
    }

    /**
     * @dev Create a new bounty for threat analysis
     * @param artifactHash IPFS hash of the artifact to be analyzed
     * @param artifactType Type of artifact (file, URL, etc.)
     * @param rewardAmount Amount of tokens offered as reward
     * @param deadline Deadline for analysis submission
     * @param description Description of the bounty
     */

    function createBounty(
        string memory artifactHash,
        string memory artifactType,
        uint256 rewardAmount,
        uint256 deadline,
        string memory description
    ) external notPaused returns (uint256) {
        require(bytes(artifactHash).length > 0, "Invalid artifact hash");
        require(rewardAmount > 0, "Reward must be positive");
        require(deadline > block.timestamp + 1 hours, "Deadline too soon");
        require(bytes(description).length > 0, "Description required");

        // Transfer reward tokens to contract
        threatToken.safeTransferFrom(msg.sender, address(this), rewardAmount);
        totalEscrowed += rewardAmount;

        bountyCounter++;

        bounties[bountyCounter] = Bounty({
            id: bountyCounter,
            creator: msg.sender,
            artifactHash: artifactHash,
            artifactType: artifactType,
            rewardAmount: rewardAmount,
            deadline: deadline,
            description: description,
            status: BountyStatus.Active,
            consensusVerdict: ThreatVerdict.Pending,
            totalStaked: 0,
            analysisCount: 0,
            createdAt: block.timestamp
        });

        userBounties[msg.sender].push(bountyCounter);

        emit BountyCreated(
            bountyCounter,
            msg.sender,
            artifactHash,
            rewardAmount,
            deadline
        );

        return bountyCounter;
    }

    /**
     * @dev Submit analysis for a bounty
     * @param bountyId ID of the bounty
     * @param verdict Analysis verdict (Malicious/Benign)
     * @param confidence Confidence level (0-100)
     * @param stakeAmount Amount of tokens to stake
     * @param analysisHash IPFS hash of detailed analysis
     */

    function submitAnalysis(
        uint256 bountyId,
        ThreatVerdict verdict,
        uint256 confidence,
        uint256 stakeAmount,
        string memory analysisHash
    )
        external
        nonReentrant
        validBounty(bountyId)
        bountyActive(bountyId)
        notPaused
    {
        require(verdict != ThreatVerdict.Pending, "Invalid verdict");
        require(confidence > 0 && confidence <= 100, "Invalid confidence");
        require(stakeAmount >= MIN_STAKE_AMOUNT, "Insufficient stake");
        require(bytes(analysisHash).length > 0, "Analysis hash required");
        require(
            analyses[bountyId][msg.sender].analyst == address(0),
            "Already submitted"
        );
        require(
            bountyAnalysts[bountyId].length < MAX_ANALYSTS_PER_BOUNTY,
            "Analyst cap reached"
        );

        // Check reputation requirements
        require(
            reputationSystem.getReputation(msg.sender) >=
                reputationSystem.getMinimumReputation(),
            "Insufficient reputation"
        );

        // Effects: record the analysis before any external interaction
        analyses[bountyId][msg.sender] = Analysis({
            bountyId: bountyId,
            analyst: msg.sender,
            verdict: verdict,
            confidence: confidence,
            stakeAmount: stakeAmount,
            analysisHash: analysisHash,
            submittedAt: block.timestamp,
            rewarded: false
        });

        bountyAnalysts[bountyId].push(msg.sender);
        bounties[bountyId].totalStaked += stakeAmount;
        bounties[bountyId].analysisCount++;

        // Interaction: pull the stake into escrow
        threatToken.safeTransferFrom(msg.sender, address(this), stakeAmount);
        totalEscrowed += stakeAmount;

        // NOTE: Reputation is intentionally NOT recorded at submission time.
        // Accuracy can only be judged once consensus is known, so all reputation
        // updates happen in _resolveBountyInternal() via
        // reputationSystem.updateReputationForAnalysis(). recordSubmission() is also
        // deliberately absent from the IReputationSystem interface this contract binds
        // to, so wiring it here is neither possible nor desirable.

        emit AnalysisSubmitted(
            bountyId,
            msg.sender,
            verdict,
            stakeAmount,
            confidence
        );

        // NOTE: Resolution is intentionally decoupled from submission. It is triggered
        // explicitly via resolveBounty() so that no single submitter is forced to pay
        // the gas to resolve on behalf of everyone, and so submission cost stays
        // bounded and predictable.
    }

    /**
     * @dev Resolve a bounty by determining consensus and distributing rewards
     * @param bountyId ID of the bounty to resolve
     */
    function resolveBounty(
        uint256 bountyId
    ) external nonReentrant validBounty(bountyId) notPaused {
        Bounty storage bounty = bounties[bountyId];
        require(bounty.status == BountyStatus.Active, "Bounty not active");
        require(
            block.timestamp > bounty.deadline ||
                bounty.analysisCount >= MIN_ANALYSES_TO_RESOLVE,
            "Cannot resolve yet"
        );

        _resolveBountyInternal(bountyId);
    }

    /**
     * @dev Internal function to resolve bounty and distribute rewards
     */
    function _resolveBountyInternal(uint256 bountyId) internal {
        Bounty storage bounty = bounties[bountyId];
        address[] storage analysts = bountyAnalysts[bountyId];

        if (analysts.length == 0) {
            // No analyses submitted, refund creator (via pull-payment)
            bounty.status = BountyStatus.Cancelled;
            _credit(bounty.creator, bounty.rewardAmount);
            return;
        }

        // Calculate consensus
        (ThreatVerdict consensus, uint256 consensusCount) = _calculateConsensus(
            bountyId
        );

        bounty.consensusVerdict = consensus;
        bounty.status = BountyStatus.Completed;

        // Update reputation for all analysts based on their analysis accuracy
        for (uint256 i = 0; i < analysts.length; i++) {
            address analyst = analysts[i];
            Analysis storage analysis = analyses[bountyId][analyst];

            // Check if analyst's verdict matches consensus
            bool wasCorrect = (analysis.verdict == consensus);

            // Update reputation in reputation system
            reputationSystem.updateReputationForAnalysis(
                analyst,
                bountyId,
                wasCorrect,
                analysis.stakeAmount
            );
        }

        // Distribute rewards and slash stakes
        _distributeRewards(bountyId, consensus, consensusCount);

        // Calculate confidence score (percentage of consensus)
        uint256 totalAnalyses = bountyAnalysts[bountyId].length;
        uint256 confidenceScore = totalAnalyses > 0
            ? (consensusCount * 10000) / totalAnalyses
            : 0; // basis points

        emit ConsensusReached(
            bountyId,
            consensus,
            confidenceScore,
            totalAnalyses
        );
    }

    /**
     * @dev Calculate consensus from all analyses
     */
    function _calculateConsensus(
        uint256 bountyId
    ) internal view returns (ThreatVerdict consensus, uint256 consensusCount) {
        address[] storage analysts = bountyAnalysts[bountyId];
        uint256 maliciousCount = 0;
        uint256 benignCount = 0;
        uint256 totalWeight = 0;

        for (uint256 i = 0; i < analysts.length; i++) {
            Analysis storage analysis = analyses[bountyId][analysts[i]];
            uint256 weight = (analysis.stakeAmount * analysis.confidence) / 100;
            totalWeight += weight;

            if (analysis.verdict == ThreatVerdict.Malicious) {
                maliciousCount += weight;
            } else if (analysis.verdict == ThreatVerdict.Benign) {
                benignCount += weight;
            }
        }

        if (totalWeight == 0) {
            return (ThreatVerdict.Pending, 0);
        }

        uint256 maliciousPercent = (maliciousCount * 100) / totalWeight;
        uint256 benignPercent = (benignCount * 100) / totalWeight;

        if (maliciousPercent >= CONSENSUS_THRESHOLD) {
            consensus = ThreatVerdict.Malicious;
            consensusCount = _countCorrectAnalyses(
                bountyId,
                ThreatVerdict.Malicious
            );
        } else if (benignPercent >= CONSENSUS_THRESHOLD) {
            consensus = ThreatVerdict.Benign;
            consensusCount = _countCorrectAnalyses(
                bountyId,
                ThreatVerdict.Benign
            );
        } else {
            consensus = ThreatVerdict.Pending; // No clear consensus
            consensusCount = 0;
        }
    }

    /**
     * @dev Count analyses that match the consensus
     */
    function _countCorrectAnalyses(
        uint256 bountyId,
        ThreatVerdict consensus
    ) internal view returns (uint256 count) {
        address[] storage analysts = bountyAnalysts[bountyId];
        for (uint256 i = 0; i < analysts.length; i++) {
            if (analyses[bountyId][analysts[i]].verdict == consensus) {
                count++;
            }
        }
    }

    /**
     * @dev Distribute rewards to correct analysts and slash incorrect ones
     */
    function _distributeRewards(
        uint256 bountyId,
        ThreatVerdict consensus,
        uint256 winnerCount
    ) internal {
        Bounty storage bounty = bounties[bountyId];
        address[] storage analysts = bountyAnalysts[bountyId];

        uint256 totalRewardPool = bounty.rewardAmount;
        uint256 platformFee = (totalRewardPool * PLATFORM_FEE_PERCENT) / 100;
        uint256 rewardPool = totalRewardPool - platformFee;

        if (consensus == ThreatVerdict.Pending || winnerCount == 0) {
            // No consensus reached: refund creator minus platform fee, return stakes.
            // All amounts are credited for later withdrawal (no transfers in loops).
            uint256 refundAmount = totalRewardPool - platformFee;

            _credit(feeCollector, platformFee);
            _credit(bounty.creator, refundAmount);

            // Return stakes
            for (uint256 i = 0; i < analysts.length; i++) {
                address analyst = analysts[i];
                Analysis storage analysis = analyses[bountyId][analyst];
                _credit(analyst, analysis.stakeAmount);
            }
            return;
        }

        // Add slashed stakes to reward pool
        uint256 slashedAmount = _processSlashing(bountyId, consensus);
        rewardPool += slashedAmount;

        // Distribute rewards to winners
        uint256 individualReward = rewardPool / winnerCount;

        // Collect winners for event emission
        address[] memory winners = new address[](winnerCount);
        uint256[] memory rewards = new uint256[](winnerCount);
        uint256[] memory stakes = new uint256[](winnerCount);
        uint256 winnerIndex = 0;

        for (uint256 i = 0; i < analysts.length; i++) {
            address analyst = analysts[i];
            Analysis storage analysis = analyses[bountyId][analyst];

            if (analysis.verdict == consensus && !analysis.rewarded) {
                analysis.rewarded = true;

                // Credit stake + reward for later withdrawal
                uint256 totalPayout = analysis.stakeAmount + individualReward;
                _credit(analyst, totalPayout);

                // Collect for event
                winners[winnerIndex] = analyst;
                rewards[winnerIndex] = individualReward;
                stakes[winnerIndex] = analysis.stakeAmount;
                winnerIndex++;
            }
        }

        // Credit platform fee
        _credit(feeCollector, platformFee);

        // Emit rewards distributed event
        emit RewardsDistributed(bountyId, winners, rewards, stakes);
    }

    /**
     * @dev Credit an account's pull-payment balance. Funds are claimed via withdraw().
     */
    function _credit(address account, uint256 amount) internal {
        if (amount == 0) {
            return;
        }
        pendingWithdrawals[account] += amount;
        emit PaymentCredited(account, amount);
    }

    /**
     * @dev Withdraw funds owed to the caller (pull-payment pattern).
     * @notice This is the only path that moves tokens out of the contract to users,
     *         isolating external transfers from resolution so a single bad recipient
     *         cannot block everyone else.
     */
    function withdraw() external nonReentrant {
        uint256 amount = pendingWithdrawals[msg.sender];
        require(amount > 0, "Nothing to withdraw");

        // Effects before interaction
        pendingWithdrawals[msg.sender] = 0;
        totalEscrowed -= amount;

        threatToken.safeTransfer(msg.sender, amount);
        emit Withdrawal(msg.sender, amount);
    }

    /**
     * @dev Process slashing for incorrect analyses
     */
    function _processSlashing(
        uint256 bountyId,
        ThreatVerdict consensus
    ) internal returns (uint256 totalSlashed) {
        address[] storage analysts = bountyAnalysts[bountyId];

        for (uint256 i = 0; i < analysts.length; i++) {
            address analyst = analysts[i];
            Analysis storage analysis = analyses[bountyId][analyst];

            if (analysis.verdict != consensus) {
                totalSlashed += analysis.stakeAmount;
                // Stakes are slashed (added to reward pool)
            }
        }
    }

    // View functions
    function getBounty(
        uint256 bountyId
    ) external view validBounty(bountyId) returns (Bounty memory) {
        return bounties[bountyId];
    }

    function getAnalysis(
        uint256 bountyId,
        address analyst
    ) external view validBounty(bountyId) returns (Analysis memory) {
        return analyses[bountyId][analyst];
    }

    function getBountyAnalysts(
        uint256 bountyId
    ) external view validBounty(bountyId) returns (address[] memory) {
        return bountyAnalysts[bountyId];
    }

    function getUserBounties(
        address user
    ) external view returns (uint256[] memory) {
        return userBounties[user];
    }

    function getTotalBounties() external view returns (uint256) {
        return bountyCounter;
    }

    // Admin functions
    function pause() external onlyOwner {
        paused = true;
    }

    function unpause() external onlyOwner {
        paused = false;
    }

    function setFeeCollector(address _feeCollector) external onlyOwner {
        require(_feeCollector != address(0), "Invalid fee collector");
        feeCollector = _feeCollector;
    }

    /**
     * @dev Start a two-step ownership transfer to a new owner (e.g. a Gnosis Safe
     *      multisig or a timelock). The transfer only completes once `newOwner`
     *      calls acceptOwnership(), which guarantees the target can actually
     *      operate this contract before control is handed over.
     * @param newOwner Address of the incoming owner (multisig/timelock in prod).
     */
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "New owner is zero address");
        pendingOwner = newOwner;
        emit OwnershipTransferStarted(owner, newOwner);
    }

    /**
     * @dev Complete the ownership transfer. Callable only by the pending owner.
     */
    function acceptOwnership() external {
        require(msg.sender == pendingOwner, "Not pending owner");
        address previousOwner = owner;
        owner = pendingOwner;
        pendingOwner = address(0);
        emit OwnershipTransferred(previousOwner, owner);
    }

    /**
     * @dev Rescue tokens/ETH that are NOT part of user escrow.
     * @notice This can never touch funds the contract owes to users. For the
     *         threatToken, withdrawals are capped to the surplus above
     *         `totalEscrowed` (i.e. only tokens accidentally sent to the
     *         contract, never bounty rewards, analyst stakes, or credited-but-
     *         unwithdrawn balances). Native ETH and unrelated ERC20s are never
     *         escrowed here, so they can be rescued in full.
     *
     *         The `owner` should be a multisig/timelock in production so even
     *         this bounded rescue is not a single-key action.
     */
    function emergencyWithdraw(
        address token,
        uint256 amount
    ) external onlyOwner {
        require(paused, "Contract must be paused");
        if (token == address(0)) {
            payable(owner).transfer(amount);
        } else if (token == address(threatToken)) {
            // Only the balance in excess of escrowed obligations is withdrawable.
            uint256 balance = threatToken.balanceOf(address(this));
            uint256 surplus = balance > totalEscrowed
                ? balance - totalEscrowed
                : 0;
            require(amount <= surplus, "Exceeds unescrowed surplus");
            threatToken.safeTransfer(owner, amount);
        } else {
            IERC20(token).safeTransfer(owner, amount);
        }
    }
}
