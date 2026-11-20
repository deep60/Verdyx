//! The one contract read this service makes. It holds no key, so there are
//! no transfers here.
use alloy::sol;

sol! {
    #[sol(rpc)]
    interface IThreatToken {
        function balanceOf(address account) external view returns (uint256);
    }
}
