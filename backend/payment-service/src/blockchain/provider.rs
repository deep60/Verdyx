use alloy::providers::{Provider, RootProvider};
use anyhow::{Context, Result};
use tracing::info;

use crate::config::BlockchainConfig;

/// A read-only HTTP provider. Cloning it is cheap.
pub type BlockchainProvider = RootProvider;

/// Connect to `BLOCKCHAIN_RPC_URL` and check that it serves the configured
/// chain.
///
/// Plain HTTP: the service only makes request/response reads (balances,
/// receipts, gas price) and listens to no events.
pub async fn create_provider(config: &BlockchainConfig) -> Result<BlockchainProvider> {
    let url = config
        .rpc_url
        .parse()
        .with_context(|| "BLOCKCHAIN_RPC_URL must be an http(s) URL")?;
    let provider = RootProvider::new_http(url);

    // Catch a wrong or unreachable RPC at startup rather than on first use.
    let chain_id = provider.get_chain_id().await?;
    info!("Connected to blockchain with chain ID: {}", chain_id);

    if chain_id != config.chain_id {
        return Err(anyhow::anyhow!(
            "Chain ID mismatch: expected {}, got {}",
            config.chain_id,
            chain_id
        ));
    }

    Ok(provider)
}
