// Smart contract interaction module
use alloy::sol;

// Token contract ABI
sol! {
    #[sol(rpc)]
    contract TokenContract {
        function transfer(address to, uint256 amount) external returns (bool);
        function balanceOf(address account) external view returns (uint256);
        function approve(address spender, uint256 amount) external returns (bool);
        function transferFrom(address from, address to, uint256 amount) external returns (bool);
        event Transfer(address indexed from, address indexed to, uint256 value);
    }
}

// Payment contract ABI
sol! {
    #[sol(rpc)]
    contract PaymentContract {
        function depositBounty(bytes32 bountyId, uint256 amount) external payable;
        function distributeBounty(bytes32 bountyId, address winner, uint256 amount) external;
        function lockStake(bytes32 bountyId, address user, uint256 amount) external;
        function unlockStake(bytes32 stakeId) external;
        function slashStake(bytes32 stakeId, uint256 amount) external;
        event BountyDeposited(bytes32 indexed bountyId, address indexed creator, uint256 amount);
        event BountyDistributed(bytes32 indexed bountyId, address indexed winner, uint256 amount);
        event StakeLocked(bytes32 indexed stakeId, address indexed user, uint256 amount);
        event StakeUnlocked(bytes32 indexed stakeId, address indexed user, uint256 amount);
        event StakeSlashed(bytes32 indexed stakeId, address indexed user, uint256 amount);
    }
}
