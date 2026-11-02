use alloy::primitives::{TxHash, U256};
use alloy::providers::{DynProvider, Provider, ProviderBuilder, WsConnect};
use alloy::rpc::types::TransactionReceipt;
use anyhow::Result;
use tracing::info;

use crate::config::BlockchainConfig;

pub type BlockchainProvider = DynProvider;

/// Create blockchain provider.
///
/// The payment-service uses a WebSocket provider for live event listening. The
/// user may supply either:
///   - `BLOCKCHAIN_WS_URL` — used as-is (must be ws:// or wss://), or
///   - `BLOCKCHAIN_RPC_URL` — coerced from http(s) to ws(s) automatically.
///
/// Most managed providers (Alchemy, Infura) serve WS at the same path as HTTP,
/// so the coercion works transparently. If the user has a provider that
/// requires a different path, set `BLOCKCHAIN_WS_URL` explicitly.
pub async fn create_provider(config: &BlockchainConfig) -> Result<BlockchainProvider> {
    let raw_url = config.ws_url.as_ref().unwrap_or(&config.rpc_url);
    let ws_url = coerce_to_ws_url(raw_url)?;
    info!(target_url = %ws_url, "Connecting to blockchain over WebSocket");

    let provider = ProviderBuilder::new()
        .disable_recommended_fillers()
        .connect_ws(WsConnect::new(ws_url))
        .await?
        .erased();

    // Verify connection by fetching chain id (also catches handshake failures
    // that would otherwise surface only on first request).
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

/// Coerce an http(s) RPC URL into the equivalent ws(s) URL. Leaves ws(s) URLs
/// untouched. Returns an error on anything else.
fn coerce_to_ws_url(url: &str) -> Result<String> {
    if let Some(rest) = url.strip_prefix("https://") {
        Ok(format!("wss://{rest}"))
    } else if let Some(rest) = url.strip_prefix("http://") {
        Ok(format!("ws://{rest}"))
    } else if url.starts_with("ws://") || url.starts_with("wss://") {
        Ok(url.to_string())
    } else {
        Err(anyhow::anyhow!(
            "Unsupported blockchain URL scheme in '{url}'. \
             Expected http://, https://, ws://, or wss://."
        ))
    }
}

/// Get current gas price with multiplier
pub async fn get_gas_price(
    provider: &BlockchainProvider,
    multiplier: f64,
    max_gwei: u64,
) -> Result<U256> {
    let base_gas_price = provider.get_gas_price().await?;
    let adjusted = (base_gas_price as f64 * multiplier) as u128;
    let max_price = U256::from(max_gwei) * U256::from(1_000_000_000u64);

    Ok(U256::from(adjusted).min(max_price))
}

/// Wait for transaction confirmation
pub async fn wait_for_confirmations(
    provider: &BlockchainProvider,
    tx_hash: TxHash,
    confirmations: usize,
) -> Result<Option<TransactionReceipt>> {
    info!(
        "Waiting for {} confirmations for tx {}",
        confirmations, tx_hash
    );

    let receipt = provider.get_transaction_receipt(tx_hash).await?;

    if let Some(ref receipt) = receipt {
        let current_block = provider.get_block_number().await?;
        let tx_block = receipt.block_number.unwrap_or_default();

        if current_block >= tx_block + confirmations as u64 {
            return Ok(Some(receipt.clone()));
        }
    }

    Ok(None)
}

#[cfg(test)]
mod url_coercion_tests {
    use super::coerce_to_ws_url;

    #[test]
    fn https_becomes_wss() {
        assert_eq!(
            coerce_to_ws_url("https://eth-sepolia.example.com/v2/KEY").unwrap(),
            "wss://eth-sepolia.example.com/v2/KEY"
        );
    }

    #[test]
    fn http_becomes_ws() {
        assert_eq!(
            coerce_to_ws_url("http://localhost:8545").unwrap(),
            "ws://localhost:8545"
        );
    }

    #[test]
    fn ws_unchanged() {
        assert_eq!(
            coerce_to_ws_url("ws://node.local:8546").unwrap(),
            "ws://node.local:8546"
        );
        assert_eq!(
            coerce_to_ws_url("wss://mainnet.example.com").unwrap(),
            "wss://mainnet.example.com"
        );
    }

    #[test]
    fn unsupported_scheme_errors() {
        assert!(coerce_to_ws_url("ftp://example.com").is_err());
        assert!(coerce_to_ws_url("just-a-host").is_err());
    }
}
