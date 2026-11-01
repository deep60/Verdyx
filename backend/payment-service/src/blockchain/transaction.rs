// Transaction building and execution
use alloy::network::TransactionBuilder as _;
use alloy::primitives::{Address, Bytes, TxHash, U256};
use alloy::providers::Provider;
use alloy::rpc::types::{TransactionReceipt, TransactionRequest};
use anyhow::Result;
use tracing::info;

use super::provider::BlockchainProvider;

pub struct TransactionBuilder {
    pub from: Address,
    pub to: Address,
    pub value: U256,
    pub data: Option<Bytes>,
    pub gas_limit: Option<U256>,
    pub gas_price: Option<U256>,
    pub nonce: Option<U256>,
}

impl TransactionBuilder {
    pub fn new(from: Address, to: Address) -> Self {
        Self {
            from,
            to,
            value: U256::ZERO,
            data: None,
            gas_limit: None,
            gas_price: None,
            nonce: None,
        }
    }

    pub fn value(mut self, value: U256) -> Self {
        self.value = value;
        self
    }

    pub fn data(mut self, data: Bytes) -> Self {
        self.data = Some(data);
        self
    }

    pub fn gas_limit(mut self, limit: U256) -> Self {
        self.gas_limit = Some(limit);
        self
    }

    pub fn gas_price(mut self, price: U256) -> Self {
        self.gas_price = Some(price);
        self
    }

    pub fn build(self) -> TransactionRequest {
        TransactionRequest::default()
            .with_from(self.from)
            .with_to(self.to)
            .with_value(self.value)
            .with_input(self.data.unwrap_or_default())
    }
}

pub async fn send_transaction(
    provider: &BlockchainProvider,
    tx: TransactionRequest,
) -> Result<TxHash> {
    info!("Sending transaction...");
    let pending_tx = provider.send_transaction(tx).await?;
    Ok(*pending_tx.tx_hash())
}

pub async fn wait_for_confirmation(
    provider: &BlockchainProvider,
    tx_hash: TxHash,
    _confirmations: usize,
) -> Result<TransactionReceipt> {
    info!("Waiting for confirmation of tx {}", tx_hash);

    let receipt = provider
        .get_transaction_receipt(tx_hash)
        .await?
        .ok_or_else(|| anyhow::anyhow!("Transaction not found"))?;

    Ok(receipt)
}
