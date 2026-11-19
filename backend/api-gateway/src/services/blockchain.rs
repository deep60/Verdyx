//! Read-only access to the chain, for the health check.
//!
//! The gateway holds no signing key. Every transaction in the marketplace
//! (posting a bounty, staking on a verdict, resolving, withdrawing, claiming
//! test THREAT) is signed in the person's own wallet on the website. The
//! server only reads: here for `/health`, and in `chain_indexer` for the
//! bounty list.

use anyhow::{Context, Result};
use ethers::{
    providers::{Http, Middleware, Provider},
    types::Address,
};
use std::time::Duration;

use crate::config;

/// Reads the chain through the server's RPC (`BLOCKCHAIN_RPC_URL`).
pub struct BlockchainService {
    provider: Provider<Http>,
    bounty_manager: Address,
}

impl BlockchainService {
    /// Never fails on missing or malformed chain settings: the chain is
    /// optional, and the gateway must still serve everything else.
    pub fn new(config: &config::BlockchainConfig) -> Result<Self> {
        let provider = Provider::<Http>::try_from(config.rpc_url.as_str())
            .context("Failed to create HTTP provider")?;
        let bounty_manager =
            parse_contract_address("BOUNTY_MANAGER_ADDRESS", &config.contracts.bounty_manager);
        Ok(Self {
            provider,
            bounty_manager,
        })
    }

    /// Whether the RPC answers and the configured contracts exist on that
    /// chain. An RPC that answers says nothing about Verdyx: a public node
    /// replies even when no contract was ever deployed there.
    pub async fn health_check(&self) -> ChainHealth {
        let probe = async {
            self.provider.get_block_number().await?;
            self.provider.get_code(self.bounty_manager, None).await
        };
        match tokio::time::timeout(Duration::from_secs(5), probe).await {
            Ok(Ok(code)) if code.as_ref().is_empty() => ChainHealth::NotDeployed,
            Ok(Ok(_)) => ChainHealth::Ready,
            Ok(Err(e)) => {
                tracing::warn!("Blockchain health check failed: {}", e);
                ChainHealth::Unreachable
            }
            Err(_) => {
                tracing::warn!("Blockchain health check timed out");
                ChainHealth::Unreachable
            }
        }
    }
}

/// Parse a configured contract address, falling back to the zero address.
///
/// Returns `Address::zero()` for anything unusable (empty, whitespace or
/// malformed) after logging which variable was at fault. The zero address
/// has no code, so the health check reports the chain as not deployed.
///
/// Startup must never depend on chain configuration being present: a blank
/// address once stopped the gateway from starting at all.
fn parse_contract_address(var_name: &str, raw: &str) -> Address {
    let trimmed = raw.trim();

    if trimmed.is_empty() {
        tracing::warn!("{var_name} is not set; the chain is reported as not deployed");
        return Address::zero();
    }

    match trimmed.parse::<Address>() {
        Ok(addr) => {
            if addr.is_zero() {
                tracing::warn!(
                    "{var_name} is the zero address; the chain is reported as not deployed"
                );
            }
            addr
        }
        Err(e) => {
            tracing::warn!("{var_name} is not a valid address ({e}); treating it as unset");
            Address::zero()
        }
    }
}

/// Result of [`BlockchainService::health_check`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainHealth {
    /// RPC answers and the bounty contract has code.
    Ready,
    /// RPC answers but no contract is deployed at the configured address.
    NotDeployed,
    /// RPC error or timeout.
    Unreachable,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_contract_address_is_used_as_configured() {
        let addr = parse_contract_address(
            "BOUNTY_MANAGER_ADDRESS",
            "0x742b15C2d1f7a9fE9a8d2F1B22d7e3aF95c30B34",
        );
        assert_eq!(
            format!("{addr:?}").to_lowercase(),
            "0x742b15c2d1f7a9fe9a8d2f1b22d7e3af95c30b34"
        );
    }

    /// Unset config must degrade, never crash.
    #[test]
    fn unset_or_malformed_addresses_degrade_to_zero() {
        for raw in [
            "",
            "   ",
            "not-an-address",
            "0x123",
            "0xZZZZ15C2d1f7a9fE9a8d2F1B22d7e3aF95c30B34",
            "0x0000000000000000000000000000000000000000",
        ] {
            assert!(
                parse_contract_address("BOUNTY_MANAGER_ADDRESS", raw).is_zero(),
                "{raw:?}"
            );
        }
    }

    #[test]
    fn contract_address_tolerates_surrounding_whitespace() {
        let addr = parse_contract_address(
            "BOUNTY_MANAGER_ADDRESS",
            "  0x742b15C2d1f7a9fE9a8d2F1B22d7e3aF95c30B34\n",
        );
        assert!(!addr.is_zero());
    }

    /// The service starts with no chain configured at all, and holds no key.
    #[test]
    fn starts_without_any_chain_settings() {
        let cfg = config::BlockchainConfig {
            rpc_url: "http://localhost:8545".into(),
            ..Default::default()
        };
        assert!(BlockchainService::new(&cfg).is_ok());
    }
}
