//! Deploys the Verdyx contracts to a local dev chain for `#[ignore]`d tests.
//!
//! Start a chain, compile the contracts, then run the ignored tests one at a
//! time, because they share the chain's dev accounts:
//!
//! ```text
//! anvil &
//! (cd blockchain && npx hardhat compile)
//! cd backend && cargo test -p shared -p api-gateway -p bounty-manager -p payment-service \
//!     --features shared/evm-testing local_chain -- --ignored --test-threads=1
//! ```
//!
//! `LOCAL_CHAIN_RPC_URL` overrides the node URL (default `http://127.0.0.1:8545`)
//! and `CONTRACT_ARTIFACTS_DIR` the Hardhat `artifacts/contracts/core` directory.
//! The payment test also needs `DATABASE_URL` and `REDIS_URL`; the bounty sync
//! test uses `DATABASE_URL` when it is set.

use alloy::dyn_abi::DynSolValue;
use alloy::network::TransactionBuilder;
use alloy::primitives::{hex, Address, Bytes, U256};
use alloy::providers::{DynProvider, Provider, RootProvider};
use alloy::rpc::types::{TransactionReceipt, TransactionRequest};
use alloy::signers::local::PrivateKeySigner;
use alloy::sol;
use std::path::PathBuf;

use crate::evm::with_signer;

/// Anvil and Hardhat dev account #0: deployer, token admin and bounty creator.
pub const ADMIN_KEY: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
/// Dev account #1: a registered analysis engine holding tokens.
pub const ANALYST_KEY: &str = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
/// Dev account #2, which holds no tokens.
pub const RECIPIENT_KEY: &str =
    "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ea870594951055dca4b4d10";

/// One whole token, in base units.
pub const TOKEN: U256 = U256::from_limbs([1_000_000_000_000_000_000, 0, 0, 0]);

sol! {
    #[sol(rpc)]
    contract TestToken {
        function BOUNTY_MANAGER_ROLE() external view returns (bytes32);
        function REPUTATION_MANAGER_ROLE() external view returns (bytes32);
        function grantRole(bytes32 role, address account) external;
        function approve(address spender, uint256 amount) external returns (bool);
        function transfer(address to, uint256 amount) external returns (bool);
    }

    #[sol(rpc)]
    contract TestReputation {
        function BOUNTY_MANAGER_ROLE() external view returns (bytes32);
        function grantRole(bytes32 role, address account) external;
        function registerEngine(address engineAddress, uint8 engineType) external returns (bool);
    }

    #[sol(rpc)]
    contract TestBountyManager {
        function createBounty(
            string artifactHash,
            string artifactType,
            uint256 rewardAmount,
            uint256 deadline,
            string description
        ) external returns (uint256);
        function submitAnalysis(
            uint256 bountyId,
            uint8 verdict,
            uint256 confidence,
            uint256 stakeAmount,
            string analysisHash
        ) external;
    }
}

/// Freshly deployed contracts, wired up the way `blockchain/scripts/setup.ts` does.
pub struct LocalChain {
    pub rpc_url: String,
    pub chain_id: u64,
    pub admin: DynProvider,
    pub admin_address: Address,
    pub analyst: DynProvider,
    pub analyst_address: Address,
    pub recipient_address: Address,
    pub token: Address,
    pub reputation: Address,
    pub bounty_manager: Address,
}

/// The compiled contracts under test.
pub fn artifacts_dir() -> PathBuf {
    std::env::var_os("CONTRACT_ARTIFACTS_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../blockchain/artifacts/contracts/core")
        })
}

/// The ABIs the services load in production, in `blockchain/abis`.
pub fn abis_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../blockchain/abis")
}

fn signer(key: &str) -> PrivateKeySigner {
    key.parse().expect("dev account key is valid")
}

async fn deploy(provider: &DynProvider, name: &str, args: &[DynSolValue]) -> Address {
    let path = artifacts_dir().join(format!("{name}.sol/{name}.json"));
    let artifact: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display())),
    )
    .expect("artifact is JSON");
    let mut code = hex::decode(
        artifact["bytecode"]
            .as_str()
            .expect("artifact has bytecode"),
    )
    .expect("bytecode is hex");
    code.extend(DynSolValue::Tuple(args.to_vec()).abi_encode_params());

    let receipt = provider
        .send_transaction(TransactionRequest::default().with_deploy_code(Bytes::from(code)))
        .await
        .unwrap_or_else(|e| panic!("deploying {name}: {e}"))
        .get_receipt()
        .await
        .unwrap_or_else(|e| panic!("waiting for {name}: {e}"));
    assert!(receipt.status(), "{name} deployment reverted");
    receipt.contract_address.expect("deployment has an address")
}

impl LocalChain {
    pub async fn deploy() -> Self {
        let rpc_url = std::env::var("LOCAL_CHAIN_RPC_URL")
            .unwrap_or_else(|_| "http://127.0.0.1:8545".to_string());
        let root = RootProvider::new_http(rpc_url.parse().expect("valid node URL")).erased();
        let chain_id = root.get_chain_id().await.expect("a local chain is running");

        let admin_signer = signer(ADMIN_KEY);
        let analyst_signer = signer(ANALYST_KEY);
        let admin_address = admin_signer.address();
        let analyst_address = analyst_signer.address();
        let recipient_address = signer(RECIPIENT_KEY).address();
        let admin = with_signer(root.clone(), admin_signer, chain_id);
        let analyst = with_signer(root, analyst_signer, chain_id);

        let token = deploy(
            &admin,
            "ThreatToken",
            &[DynSolValue::Address(admin_address)],
        )
        .await;
        let reputation = deploy(&admin, "ReputationSystem", &[]).await;
        let bounty_manager = deploy(
            &admin,
            "BountyManager",
            &[
                DynSolValue::Address(token),
                DynSolValue::Address(reputation),
                DynSolValue::Address(admin_address),
            ],
        )
        .await;

        let token_admin = TestToken::new(token, &admin);
        let reputation_admin = TestReputation::new(reputation, &admin);

        let token_manager_role = token_admin.BOUNTY_MANAGER_ROLE().call().await.unwrap();
        let reputation_role = token_admin.REPUTATION_MANAGER_ROLE().call().await.unwrap();
        let engine_role = reputation_admin.BOUNTY_MANAGER_ROLE().call().await.unwrap();

        confirm(
            token_admin
                .grantRole(token_manager_role, bounty_manager)
                .send()
                .await,
        )
        .await;
        confirm(
            token_admin
                .grantRole(reputation_role, reputation)
                .send()
                .await,
        )
        .await;
        confirm(
            reputation_admin
                .grantRole(engine_role, bounty_manager)
                .send()
                .await,
        )
        .await;
        confirm(
            reputation_admin
                .grantRole(engine_role, admin_address)
                .send()
                .await,
        )
        .await;
        confirm(
            reputation_admin
                .registerEngine(analyst_address, 0)
                .send()
                .await,
        )
        .await;

        let stake_budget = TOKEN * U256::from(1_000);
        confirm(
            token_admin
                .transfer(analyst_address, stake_budget)
                .send()
                .await,
        )
        .await;
        confirm(
            TestToken::new(token, &analyst)
                .approve(bounty_manager, stake_budget)
                .send()
                .await,
        )
        .await;
        confirm(
            token_admin
                .approve(bounty_manager, stake_budget)
                .send()
                .await,
        )
        .await;

        Self {
            rpc_url,
            chain_id,
            admin,
            admin_address,
            analyst,
            analyst_address,
            recipient_address,
            token,
            reputation,
            bounty_manager,
        }
    }

    /// Create a bounty as the admin, with a deadline two hours from the chain's now.
    pub async fn create_bounty(&self, artifact_hash: &str, reward: U256) -> TransactionReceipt {
        let deadline = U256::from(self.now().await + 2 * 3600);
        confirm(
            TestBountyManager::new(self.bounty_manager, &self.admin)
                .createBounty(
                    artifact_hash.to_string(),
                    "file".to_string(),
                    reward,
                    deadline,
                    "local chain test".to_string(),
                )
                .send()
                .await,
        )
        .await
    }

    /// Submit an analysis as the registered analyst.
    pub async fn submit_analysis(
        &self,
        bounty_id: U256,
        verdict: u8,
        confidence: u64,
        stake: U256,
    ) -> TransactionReceipt {
        confirm(
            TestBountyManager::new(self.bounty_manager, &self.analyst)
                .submitAnalysis(
                    bounty_id,
                    verdict,
                    U256::from(confidence),
                    stake,
                    "ipfs://analysis".to_string(),
                )
                .send()
                .await,
        )
        .await
    }

    /// The latest block's timestamp.
    pub async fn now(&self) -> u64 {
        let block: serde_json::Value = self
            .admin
            .raw_request("eth_getBlockByNumber".into(), ("latest", false))
            .await
            .expect("latest block");
        let timestamp = block["timestamp"].as_str().expect("block has a timestamp");
        u64::from_str_radix(timestamp.trim_start_matches("0x"), 16).expect("hex timestamp")
    }

    /// Move the chain's clock forward and mine a block.
    pub async fn advance_time(&self, seconds: u64) {
        let _: serde_json::Value = self
            .admin
            .raw_request("evm_increaseTime".into(), (seconds,))
            .await
            .expect("evm_increaseTime");
        let _: serde_json::Value = self
            .admin
            .raw_request("evm_mine".into(), serde_json::json!([]))
            .await
            .expect("evm_mine");
    }
}

async fn confirm<E: std::fmt::Display, N>(
    pending: Result<alloy::providers::PendingTransactionBuilder<N>, E>,
) -> TransactionReceipt
where
    N: alloy::network::Network<ReceiptResponse = TransactionReceipt>,
{
    let receipt = pending
        .unwrap_or_else(|e| panic!("sending: {e}"))
        .get_receipt()
        .await
        .unwrap_or_else(|e| panic!("waiting: {e}"));
    assert!(receipt.status(), "transaction reverted: {receipt:?}");
    receipt
}

/// Ask the node to sign `message` with an unlocked dev account via `personal_sign`,
/// the same RPC a browser wallet exposes, and return the 0x-prefixed signature.
pub async fn personal_sign(chain: &LocalChain, account: Address, message: &str) -> String {
    chain
        .admin
        .raw_request(
            "personal_sign".into(),
            (format!("0x{}", hex::encode(message)), account),
        )
        .await
        .expect("personal_sign")
}
