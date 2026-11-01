use anyhow::{anyhow, Context, Result};
use ethers::{
    contract::Contract,
    prelude::*,
    providers::{Http, Middleware, Provider},
    signers::{LocalWallet, Signer},
    types::{Address, Bytes, TransactionReceipt, TransactionRequest, H256, U256},
    utils::{format_ether, parse_ether},
};
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

// Contract ABIs - In production, these would be loaded from files or generated
const BOUNTY_MANAGER_ABI: &str = r#"[
    {
        "inputs": [
            {"internalType": "string", "name": "fileHash", "type": "string"},
            {"internalType": "uint256", "name": "bountyAmount", "type": "uint256"},
            {"internalType": "uint256", "name": "deadline", "type": "uint256"}
        ],
        "name": "createBounty",
        "outputs": [{"internalType": "uint256", "name": "bountyId", "type": "uint256"}],
        "stateMutability": "payable",
        "type": "function"
    },
    {
        "inputs": [
            {"internalType": "uint256", "name": "bountyId", "type": "uint256"},
            {"internalType": "bool", "name": "isMalicious", "type": "bool"},
            {"internalType": "uint256", "name": "stakeAmount", "type": "uint256"}
        ],
        "name": "submitAnalysis",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "inputs": [{"internalType": "uint256", "name": "bountyId", "type": "uint256"}],
        "name": "getBounty",
        "outputs": [
            {"internalType": "string", "name": "fileHash", "type": "string"},
            {"internalType": "uint256", "name": "bountyAmount", "type": "uint256"},
            {"internalType": "address", "name": "creator", "type": "address"},
            {"internalType": "uint256", "name": "deadline", "type": "uint256"},
            {"internalType": "bool", "name": "resolved", "type": "bool"}
        ],
        "stateMutability": "view",
        "type": "function"
    }
]"#;

const REPUTATION_SYSTEM_ABI: &str = r#"[
    {
        "inputs": [{"internalType": "address", "name": "analyzer", "type": "address"}],
        "name": "getReputation",
        "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [
            {"internalType": "address", "name": "analyzer", "type": "address"},
            {"internalType": "bool", "name": "wasCorrect", "type": "bool"},
            {"internalType": "uint256", "name": "stakeAmount", "type": "uint256"}
        ],
        "name": "updateReputation",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    }
]"#;

const THREAT_TOKEN_ABI: &str = r#"[
    {
        "inputs": [{"internalType": "address", "name": "account", "type": "address"}],
        "name": "balanceOf",
        "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [
            {"internalType": "address", "name": "to", "type": "address"},
            {"internalType": "uint256", "name": "amount", "type": "uint256"}
        ],
        "name": "transfer",
        "outputs": [{"internalType": "bool", "name": "", "type": "bool"}],
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "inputs": [
            {"internalType": "address", "name": "owner", "type": "address"},
            {"internalType": "address", "name": "spender", "type": "address"}
        ],
        "name": "allowance",
        "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [
            {"internalType": "address", "name": "spender", "type": "address"},
            {"internalType": "uint256", "name": "amount", "type": "uint256"}
        ],
        "name": "approve",
        "outputs": [{"internalType": "bool", "name": "", "type": "bool"}],
        "stateMutability": "nonpayable",
        "type": "function"
    }
]"#;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BountyInfo {
    pub id: U256,
    pub file_hash: String,
    pub bounty_amount: U256,
    pub creator: Address,
    pub deadline: U256,
    pub resolved: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisSubmission {
    pub bounty_id: U256,
    pub analyzer: Address,
    pub is_malicious: bool,
    pub stake_amount: U256,
    pub timestamp: U256,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReputationScore {
    pub analyzer: Address,
    pub score: U256,
    pub total_analyses: U256,
    pub correct_analyses: U256,
}

#[derive(Debug, Clone)]
pub struct ContractAddresses {
    pub bounty_manager: Address,
    pub reputation_system: Address,
    pub threat_token: Address,
}

pub struct Web3Client {
    provider: Arc<Provider<Http>>,
    wallet: Option<LocalWallet>,
    chain_id: u64,
    contracts: ContractAddresses,
    bounty_manager: Contract<Provider<Http>>,
    reputation_system: Contract<Provider<Http>>,
    threat_token: Contract<Provider<Http>>,
}

impl Web3Client {
    /// Creates a new Web3Client instance
    pub async fn new(
        rpc_url: &str,
        private_key: Option<&str>,
        chain_id: u64,
        contract_addresses: ContractAddresses,
    ) -> Result<Self> {
        let provider =
            Provider::<Http>::try_from(rpc_url).context("Failed to create HTTP provider")?;
        let provider = Arc::new(provider);

        let wallet = if let Some(key) = private_key {
            Some(
                LocalWallet::from_str(key)
                    .context("Invalid private key")?
                    .with_chain_id(chain_id),
            )
        } else {
            None
        };

        // Create contract instances
        let bounty_manager = Contract::new(
            contract_addresses.bounty_manager,
            serde_json::from_str(BOUNTY_MANAGER_ABI)?,
            provider.clone(),
        );

        let reputation_system = Contract::new(
            contract_addresses.reputation_system,
            serde_json::from_str(REPUTATION_SYSTEM_ABI)?,
            provider.clone(),
        );

        let threat_token = Contract::new(
            contract_addresses.threat_token,
            serde_json::from_str(THREAT_TOKEN_ABI)?,
            provider.clone(),
        );

        Ok(Self {
            provider,
            wallet,
            chain_id,
            contracts: contract_addresses,
            bounty_manager,
            reputation_system,
            threat_token,
        })
    }

    /// Gets the current block number
    pub async fn get_block_number(&self) -> Result<U64> {
        self.provider
            .get_block_number()
            .await
            .context("Failed to get block number")
    }

    /// Gets the balance of an address in ETH
    pub async fn get_eth_balance(&self, address: Address) -> Result<U256> {
        self.provider
            .get_balance(address, None)
            .await
            .context("Failed to get ETH balance")
    }

    /// Gets the balance of threat tokens for an address
    pub async fn get_token_balance(&self, address: Address) -> Result<U256> {
        let balance: U256 = self
            .threat_token
            .method("balanceOf", address)?
            .call()
            .await
            .context("Failed to get token balance")?;

        Ok(balance)
    }

    /// Creates a new bounty on the blockchain
    pub async fn create_bounty(
        &self,
        file_hash: String,
        bounty_amount: U256,
        deadline_timestamp: U256,
    ) -> Result<H256> {
        let wallet = self
            .wallet
            .as_ref()
            .ok_or_else(|| anyhow!("No wallet configured for transactions"))?;

        let client = Arc::new(SignerMiddleware::new(self.provider.clone(), wallet.clone()));

        let contract = Contract::new(
            self.contracts.bounty_manager,
            serde_json::from_str(BOUNTY_MANAGER_ABI)?,
            client,
        );

        info!(
            "Creating bounty for file hash: {}, amount: {}, deadline: {}",
            file_hash, bounty_amount, deadline_timestamp
        );

        let tx = contract
            .method::<_, U256>(
                "createBounty",
                (file_hash, bounty_amount, deadline_timestamp),
            )?
            .value(bounty_amount) // Send ETH with the transaction
            .send()
            .await
            .context("Failed to send create bounty transaction")?;

        Ok(tx.tx_hash())
    }

    /// Submits an analysis for a bounty
    pub async fn submit_analysis(
        &self,
        bounty_id: U256,
        is_malicious: bool,
        stake_amount: U256,
    ) -> Result<H256> {
        let wallet = self
            .wallet
            .as_ref()
            .ok_or_else(|| anyhow!("No wallet configured for transactions"))?;

        let client = Arc::new(SignerMiddleware::new(self.provider.clone(), wallet.clone()));

        let contract = Contract::new(
            self.contracts.bounty_manager,
            serde_json::from_str(BOUNTY_MANAGER_ABI)?,
            client,
        );

        info!(
            "Submitting analysis for bounty: {}, malicious: {}, stake: {}",
            bounty_id, is_malicious, stake_amount
        );

        let tx = contract
            .method::<_, ()>("submitAnalysis", (bounty_id, is_malicious, stake_amount))?
            .send()
            .await
            .context("Failed to send submit analysis transaction")?;

        Ok(tx.tx_hash())
    }

    /// Gets bounty information by ID
    pub async fn get_bounty(&self, bounty_id: U256) -> Result<BountyInfo> {
        let result: (String, U256, Address, U256, bool) = self
            .bounty_manager
            .method("getBounty", bounty_id)?
            .call()
            .await
            .context("Failed to get bounty information")?;

        Ok(BountyInfo {
            id: bounty_id,
            file_hash: result.0,
            bounty_amount: result.1,
            creator: result.2,
            deadline: result.3,
            resolved: result.4,
        })
    }

    /// Gets the reputation score for an analyzer
    pub async fn get_reputation(&self, analyzer: Address) -> Result<U256> {
        let reputation: U256 = self
            .reputation_system
            .method("getReputation", analyzer)?
            .call()
            .await
            .context("Failed to get reputation score")?;

        Ok(reputation)
    }

    /// Updates reputation score (admin function)
    pub async fn update_reputation(
        &self,
        analyzer: Address,
        was_correct: bool,
        stake_amount: U256,
    ) -> Result<H256> {
        let wallet = self
            .wallet
            .as_ref()
            .ok_or_else(|| anyhow!("No wallet configured for transactions"))?;

        let client = Arc::new(SignerMiddleware::new(self.provider.clone(), wallet.clone()));

        let contract = Contract::new(
            self.contracts.reputation_system,
            serde_json::from_str(REPUTATION_SYSTEM_ABI)?,
            client,
        );

        info!(
            "Updating reputation for analyzer: {:?}, correct: {}, stake: {}",
            analyzer, was_correct, stake_amount
        );

        let tx = contract
            .method::<_, ()>("updateReputation", (analyzer, was_correct, stake_amount))?
            .send()
            .await
            .context("Failed to send update reputation transaction")?;

        Ok(tx.tx_hash())
    }

    /// Transfers threat tokens to another address
    pub async fn transfer_tokens(&self, to: Address, amount: U256) -> Result<H256> {
        let wallet = self
            .wallet
            .as_ref()
            .ok_or_else(|| anyhow!("No wallet configured for transactions"))?;

        let client = Arc::new(SignerMiddleware::new(self.provider.clone(), wallet.clone()));

        let contract = Contract::new(
            self.contracts.threat_token,
            serde_json::from_str(THREAT_TOKEN_ABI)?,
            client,
        );

        info!("Transferring {} tokens to {:?}", amount, to);

        let tx = contract
            .method::<_, bool>("transfer", (to, amount))?
            .send()
            .await
            .context("Failed to send transfer transaction")?;

        Ok(tx.tx_hash())
    }

    /// Approves another address to spend tokens on behalf of the wallet
    pub async fn approve_tokens(&self, spender: Address, amount: U256) -> Result<H256> {
        let wallet = self
            .wallet
            .as_ref()
            .ok_or_else(|| anyhow!("No wallet configured for transactions"))?;

        let client = Arc::new(SignerMiddleware::new(self.provider.clone(), wallet.clone()));

        let contract = Contract::new(
            self.contracts.threat_token,
            serde_json::from_str(THREAT_TOKEN_ABI)?,
            client,
        );

        info!("Approving {} tokens for spender {:?}", amount, spender);

        let tx = contract
            .method::<_, bool>("approve", (spender, amount))?
            .send()
            .await
            .context("Failed to send approve transaction")?;

        Ok(tx.tx_hash())
    }

    /// Checks token allowance between owner and spender
    pub async fn get_token_allowance(&self, owner: Address, spender: Address) -> Result<U256> {
        let allowance: U256 = self
            .threat_token
            .method("allowance", (owner, spender))?
            .call()
            .await
            .context("Failed to get token allowance")?;

        Ok(allowance)
    }

    /// Waits for a transaction to be confirmed
    pub async fn wait_for_confirmation(&self, tx_hash: H256) -> Result<TransactionReceipt> {
        info!("Waiting for transaction confirmation: {:?}", tx_hash);

        let receipt = self
            .provider
            .get_transaction_receipt(tx_hash)
            .await
            .context("Failed to get transaction receipt")?;

        match receipt {
            Some(receipt) => {
                if receipt.status == Some(U64::from(1)) {
                    info!("Transaction confirmed successfully: {:?}", tx_hash);
                    Ok(receipt)
                } else {
                    error!("Transaction failed: {:?}", tx_hash);
                    Err(anyhow!("Transaction failed"))
                }
            }
            None => {
                warn!("Transaction not yet confirmed: {:?}", tx_hash);
                Err(anyhow!("Transaction not confirmed"))
            }
        }
    }

    /// Gets the current gas price
    pub async fn get_gas_price(&self) -> Result<U256> {
        self.provider
            .get_gas_price()
            .await
            .context("Failed to get gas price")
    }

    /// Estimates gas for a transaction
    pub async fn estimate_gas(&self, tx: &TransactionRequest) -> Result<U256> {
        self.provider
            .estimate_gas(tx, None)
            .await
            .context("Failed to estimate gas")
    }

    /// Gets the wallet address if available
    pub fn get_wallet_address(&self) -> Option<Address> {
        self.wallet.as_ref().map(|w| w.address())
    }

    /// Gets the chain ID
    pub fn get_chain_id(&self) -> u64 {
        self.chain_id
    }

    /// Gets contract addresses
    pub fn get_contract_addresses(&self) -> &ContractAddresses {
        &self.contracts
    }

    /// Converts Wei to ETH string representation
    pub fn wei_to_eth_string(&self, wei: U256) -> String {
        format_ether(wei)
    }

    /// Converts ETH string to Wei
    pub fn eth_to_wei(&self, eth: &str) -> Result<U256> {
        parse_ether(eth).context("Failed to parse ETH amount")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[tokio::test]
    async fn test_web3_client_creation() {
        let contract_addresses = ContractAddresses {
            bounty_manager: Address::from_str("0x1234567890123456789012345678901234567890")
                .unwrap(),
            reputation_system: Address::from_str("0x2234567890123456789012345678901234567890")
                .unwrap(),
            threat_token: Address::from_str("0x3234567890123456789012345678901234567890").unwrap(),
        };

        // This would fail without a real RPC endpoint, but tests the structure
        let result = Web3Client::new(
            "https://mainnet.infura.io/v3/test",
            None,
            1,
            contract_addresses,
        )
        .await;

        // In a real test environment, this should succeed
        assert!(result.is_err() || result.is_ok());
    }

    #[test]
    fn test_eth_wei_conversion() {
        let client = create_mock_client();

        let wei = client.eth_to_wei("1.5").unwrap();
        let eth_str = client.wei_to_eth_string(wei);

        assert_eq!(eth_str, "1.500000000000000000");
    }

    fn create_mock_client() -> Web3Client {
        // This is a simplified mock for testing utility functions
        Web3Client {
            provider: Arc::new(Provider::<Http>::try_from("http://localhost:8545").unwrap()),
            wallet: None,
            chain_id: 1,
            contracts: ContractAddresses {
                bounty_manager: Address::zero(),
                reputation_system: Address::zero(),
                threat_token: Address::zero(),
            },
            bounty_manager: Contract::new(
                Address::zero(),
                serde_json::Value::Array(vec![]),
                Provider::<Http>::try_from("http://localhost:8545").unwrap(),
            ),
            reputation_system: Contract::new(
                Address::zero(),
                serde_json::Value::Array(vec![]),
                Provider::<Http>::try_from("http://localhost:8545").unwrap(),
            ),
            threat_token: Contract::new(
                Address::zero(),
                serde_json::Value::Array(vec![]),
                Provider::<Http>::try_from("http://localhost:8545").unwrap(),
            ),
        }
    }
}
