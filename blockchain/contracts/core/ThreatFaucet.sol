// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/**
 * @title ThreatFaucet
 * @notice Test THREAT for trying the marketplace on a test network. Anyone
 *         can claim a fixed amount from their own wallet, once per cooldown.
 *         It hands out only what it was funded with, so it can never mint.
 * @dev Deployed by scripts/deploy.ts on test networks only. Holds no ETH.
 */
contract ThreatFaucet is Ownable, ReentrancyGuard {
    using SafeERC20 for IERC20;

    /// Shortest cooldown the owner can set, so one wallet can't drain it in a burst.
    uint256 public constant MIN_COOLDOWN = 1 hours;

    IERC20 public immutable token;
    uint256 public dripAmount;
    uint256 public cooldown;
    /// When each wallet may claim again (0 for a wallet that never has).
    mapping(address => uint256) public claimableFrom;

    event Claimed(address indexed account, uint256 amount);
    event DripChanged(uint256 amount, uint256 cooldown);
    event Reclaimed(address indexed to, uint256 amount);

    constructor(
        address _token,
        uint256 _dripAmount,
        uint256 _cooldown
    ) Ownable(msg.sender) {
        require(_token != address(0), "Invalid token");
        require(_dripAmount > 0 && _cooldown >= MIN_COOLDOWN, "Invalid drip");
        token = IERC20(_token);
        dripAmount = _dripAmount;
        cooldown = _cooldown;
    }

    /// @notice When `account` can claim next; 0 means now.
    function nextClaimAt(address account) external view returns (uint256) {
        uint256 next = claimableFrom[account];
        // Comparing with the block's timestamp is the point of a cooldown.
        // slither-disable-next-line timestamp
        return block.timestamp < next ? next : 0;
    }

    /// @notice Send `dripAmount` THREAT to the caller.
    function claim() external nonReentrant {
        // slither-disable-next-line timestamp
        require(block.timestamp >= claimableFrom[msg.sender], "Come back later");
        require(token.balanceOf(address(this)) >= dripAmount, "Faucet is empty");

        claimableFrom[msg.sender] = block.timestamp + cooldown;
        token.safeTransfer(msg.sender, dripAmount);
        emit Claimed(msg.sender, dripAmount);
    }

    function setDrip(uint256 amount, uint256 newCooldown) external onlyOwner {
        require(amount > 0 && newCooldown >= MIN_COOLDOWN, "Invalid drip");
        dripAmount = amount;
        cooldown = newCooldown;
        emit DripChanged(amount, newCooldown);
    }

    /// @notice Take tokens back out, e.g. before retiring the faucet.
    function reclaim(uint256 amount) external onlyOwner nonReentrant {
        token.safeTransfer(msg.sender, amount);
        emit Reclaimed(msg.sender, amount);
    }
}
