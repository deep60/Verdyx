// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "./ThreatToken.sol";

/**
 * @title Governance
 * @dev Decentralized governance system for Verdyx platform
 * @notice Allows token holders to propose and vote on platform changes
 */
contract Governance is AccessControl, ReentrancyGuard {
    // ============ STATE VARIABLES ============

    ThreatToken public immutable threatToken;

    bytes32 public constant PROPOSER_ROLE = keccak256("PROPOSER_ROLE");
    bytes32 public constant EXECUTOR_ROLE = keccak256("EXECUTOR_ROLE");

    uint256 public proposalCount;
    uint256 public constant VOTING_PERIOD = 3 days;
    uint256 public constant EXECUTION_DELAY = 1 days;
    uint256 public constant QUORUM_PERCENTAGE = 10; // 10% of total supply
    uint256 public constant PROPOSAL_THRESHOLD = 10000 * 10 ** 18; // 10,000 tokens to propose

    // ============ ENUMS ============

    enum ProposalState {
        Pending,
        Active,
        Defeated,
        Succeeded,
        Queued,
        Executed,
        Cancelled
    }

    enum VoteType {
        Against,
        For,
        Abstain
    }

    // ============ STRUCTS ============

    struct Proposal {
        uint256 id;
        address proposer;
        string title;
        string description;
        address[] targets;
        uint256[] values;
        bytes[] calldatas;
        uint256 startTime;
        uint256 endTime;
        uint256 executionTime;
        uint256 forVotes;
        uint256 againstVotes;
        uint256 abstainVotes;
        ProposalState state;
        bool executed;
        bool cancelled;
    }

    struct Receipt {
        bool hasVoted;
        VoteType support;
        uint256 votes;
    }

    // ============ MAPPINGS ============

    mapping(uint256 => Proposal) public proposals;
    mapping(uint256 => mapping(address => Receipt)) public receipts;
    mapping(address => uint256[]) public userProposals;

    // ============ EVENTS ============

    event ProposalCreated(
        uint256 indexed proposalId,
        address indexed proposer,
        string title,
        uint256 startTime,
        uint256 endTime
    );

    event VoteCast(
        address indexed voter,
        uint256 indexed proposalId,
        VoteType support,
        uint256 votes
    );

    event ProposalQueued(uint256 indexed proposalId, uint256 executionTime);

    event ProposalExecuted(uint256 indexed proposalId);

    event ProposalCancelled(uint256 indexed proposalId);

    // ============ CONSTRUCTOR ============

    constructor(address _threatToken) {
        require(_threatToken != address(0), "Invalid token address");

        threatToken = ThreatToken(_threatToken);

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(PROPOSER_ROLE, msg.sender);
        _grantRole(EXECUTOR_ROLE, msg.sender);
    }

    // ============ PROPOSAL FUNCTIONS ============

    /**
     * @dev Create a new governance proposal
     * @param title Proposal title
     * @param description Detailed description
     * @param targets Target contract addresses
     * @param values ETH values for each call
     * @param calldatas Encoded function calls
     * @return Proposal ID
     */
    function propose(
        string memory title,
        string memory description,
        address[] memory targets,
        uint256[] memory values,
        bytes[] memory calldatas
    ) external returns (uint256) {
        require(
            threatToken.balanceOf(msg.sender) >= PROPOSAL_THRESHOLD,
            "Insufficient tokens to propose"
        );
        require(targets.length > 0, "Must provide actions");
        require(targets.length == values.length, "Length mismatch");
        require(targets.length == calldatas.length, "Length mismatch");
        require(bytes(title).length > 0, "Title required");

        proposalCount++;
        uint256 proposalId = proposalCount;

        Proposal storage proposal = proposals[proposalId];
        proposal.id = proposalId;
        proposal.proposer = msg.sender;
        proposal.title = title;
        proposal.description = description;
        proposal.targets = targets;
        proposal.values = values;
        proposal.calldatas = calldatas;
        proposal.startTime = block.timestamp;
        proposal.endTime = block.timestamp + VOTING_PERIOD;
        proposal.state = ProposalState.Active;

        userProposals[msg.sender].push(proposalId);

        emit ProposalCreated(
            proposalId,
            msg.sender,
            title,
            proposal.startTime,
            proposal.endTime
        );

        return proposalId;
    }

    /**
     * @dev Cast a vote on a proposal
     * @param proposalId ID of the proposal
     * @param support Vote type (Against, For, Abstain)
     */
    function castVote(
        uint256 proposalId,
        VoteType support
    ) external nonReentrant {
        require(
            proposalId > 0 && proposalId <= proposalCount,
            "Invalid proposal"
        );

        Proposal storage proposal = proposals[proposalId];
        require(proposal.state == ProposalState.Active, "Voting not active");
        require(block.timestamp <= proposal.endTime, "Voting ended");

        Receipt storage receipt = receipts[proposalId][msg.sender];
        require(!receipt.hasVoted, "Already voted");

        uint256 votes = threatToken.balanceOf(msg.sender);
        require(votes > 0, "No voting power");

        receipt.hasVoted = true;
        receipt.support = support;
        receipt.votes = votes;

        if (support == VoteType.For) {
            proposal.forVotes += votes;
        } else if (support == VoteType.Against) {
            proposal.againstVotes += votes;
        } else {
            proposal.abstainVotes += votes;
        }

        emit VoteCast(msg.sender, proposalId, support, votes);
    }

    /**
     * @dev Queue a successful proposal for execution
     * @param proposalId ID of the proposal
     */
    function queue(uint256 proposalId) external {
        require(
            proposalId > 0 && proposalId <= proposalCount,
            "Invalid proposal"
        );

        Proposal storage proposal = proposals[proposalId];
        require(proposal.state == ProposalState.Active, "Proposal not active");
        require(block.timestamp > proposal.endTime, "Voting not ended");
        require(!proposal.executed, "Already executed");
        require(!proposal.cancelled, "Proposal cancelled");

        // Check if proposal succeeded
        uint256 totalVotes = proposal.forVotes +
            proposal.againstVotes +
            proposal.abstainVotes;
        uint256 quorum = (threatToken.totalSupply() * QUORUM_PERCENTAGE) / 100;

        if (totalVotes >= quorum && proposal.forVotes > proposal.againstVotes) {
            proposal.state = ProposalState.Succeeded;
            proposal.executionTime = block.timestamp + EXECUTION_DELAY;
            proposal.state = ProposalState.Queued;

            emit ProposalQueued(proposalId, proposal.executionTime);
        } else {
            proposal.state = ProposalState.Defeated;
        }
    }

    /**
     * @dev Execute a queued proposal
     * @param proposalId ID of the proposal
     */
    function execute(
        uint256 proposalId
    ) external nonReentrant onlyRole(EXECUTOR_ROLE) {
        require(
            proposalId > 0 && proposalId <= proposalCount,
            "Invalid proposal"
        );

        Proposal storage proposal = proposals[proposalId];
        require(proposal.state == ProposalState.Queued, "Not queued");
        require(
            block.timestamp >= proposal.executionTime,
            "Execution delay not met"
        );
        require(!proposal.executed, "Already executed");

        proposal.executed = true;
        proposal.state = ProposalState.Executed;

        // Execute all actions
        for (uint256 i = 0; i < proposal.targets.length; i++) {
            (bool success, ) = proposal.targets[i].call{
                value: proposal.values[i]
            }(proposal.calldatas[i]);
            require(success, "Execution failed");
        }

        emit ProposalExecuted(proposalId);
    }

    /**
     * @dev Cancel a proposal (only by proposer or admin)
     * @param proposalId ID of the proposal
     */
    function cancel(uint256 proposalId) external {
        require(
            proposalId > 0 && proposalId <= proposalCount,
            "Invalid proposal"
        );

        Proposal storage proposal = proposals[proposalId];
        require(
            msg.sender == proposal.proposer ||
                hasRole(DEFAULT_ADMIN_ROLE, msg.sender),
            "Not authorized"
        );
        require(!proposal.executed, "Already executed");
        require(!proposal.cancelled, "Already cancelled");

        proposal.cancelled = true;
        proposal.state = ProposalState.Cancelled;

        emit ProposalCancelled(proposalId);
    }

    // ============ VIEW FUNCTIONS ============

    /**
     * @dev Get proposal state
     * @param proposalId ID of the proposal
     * @return Current state of the proposal
     */
    function getProposalState(
        uint256 proposalId
    ) external view returns (ProposalState) {
        require(
            proposalId > 0 && proposalId <= proposalCount,
            "Invalid proposal"
        );
        return proposals[proposalId].state;
    }

    /**
     * @dev Get proposal details
     * @param proposalId ID of the proposal
     * @return Proposal struct
     */
    function getProposal(
        uint256 proposalId
    ) external view returns (Proposal memory) {
        require(
            proposalId > 0 && proposalId <= proposalCount,
            "Invalid proposal"
        );
        return proposals[proposalId];
    }

    /**
     * @dev Get vote receipt for a voter
     * @param proposalId ID of the proposal
     * @param voter Address of the voter
     * @return Receipt struct
     */
    function getReceipt(
        uint256 proposalId,
        address voter
    ) external view returns (Receipt memory) {
        return receipts[proposalId][voter];
    }

    /**
     * @dev Get all proposals by a user
     * @param user Address of the user
     * @return Array of proposal IDs
     */
    function getUserProposals(
        address user
    ) external view returns (uint256[] memory) {
        return userProposals[user];
    }

    /**
     * @dev Get voting power for an address
     * @param voter Address to check
     * @return Number of votes (token balance)
     */
    function getVotingPower(address voter) external view returns (uint256) {
        return threatToken.balanceOf(voter);
    }

    /**
     * @dev Get current quorum requirement
     * @return Quorum in tokens
     */
    function getQuorum() external view returns (uint256) {
        return (threatToken.totalSupply() * QUORUM_PERCENTAGE) / 100;
    }

    /**
     * @dev Check if a proposal has reached quorum
     * @param proposalId ID of the proposal
     * @return Whether quorum is reached
     */
    function hasReachedQuorum(uint256 proposalId) external view returns (bool) {
        require(
            proposalId > 0 && proposalId <= proposalCount,
            "Invalid proposal"
        );

        Proposal storage proposal = proposals[proposalId];
        uint256 totalVotes = proposal.forVotes +
            proposal.againstVotes +
            proposal.abstainVotes;
        uint256 quorum = (threatToken.totalSupply() * QUORUM_PERCENTAGE) / 100;

        return totalVotes >= quorum;
    }

    // ============ ADMIN FUNCTIONS ============

    /**
     * @dev Grant proposer role to an address
     * @param account Address to grant role
     */
    function grantProposerRole(
        address account
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        grantRole(PROPOSER_ROLE, account);
    }

    /**
     * @dev Revoke proposer role from an address
     * @param account Address to revoke role
     */
    function revokeProposerRole(
        address account
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        revokeRole(PROPOSER_ROLE, account);
    }

    // ============ RECEIVE FUNCTION ============

    receive() external payable {}
}
