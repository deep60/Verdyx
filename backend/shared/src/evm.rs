//! Helpers shared by the services that talk to the chain.

use alloy::network::EthereumWallet;
use alloy::primitives::TxHash;
use alloy::providers::{DynProvider, Provider, ProviderBuilder};
use alloy::rpc::types::TransactionReceipt;
use alloy::signers::local::PrivateKeySigner;
use alloy::transports::TransportResult;
use std::time::Duration;

const RECEIPT_POLL_INTERVAL: Duration = Duration::from_secs(1);

/// Polls in a row the node may not know a transaction before it counts as
/// dropped. Load-balanced RPC endpoints can briefly miss a transaction they
/// have just accepted, and calling a live payout dropped invites a double pay.
const DROPPED_AFTER_POLLS: u32 = 30;

/// Add a signer to `provider`. Sends fill in gas, fees and the nonce, and are
/// signed for `chain_id` without asking the node which chain it is on.
pub fn with_signer(provider: DynProvider, signer: PrivateKeySigner, chain_id: u64) -> DynProvider {
    ProviderBuilder::new()
        .disable_recommended_fillers()
        .with_gas_estimation()
        .with_simple_nonce_management()
        .with_chain_id(chain_id)
        .wallet(EthereumWallet::from(signer))
        .connect_provider(provider)
        .erased()
}

/// Wait until `hash` has `confirmations` confirmations and return its receipt,
/// whether it succeeded or reverted. Returns `None` if the transaction was
/// dropped. A mined or pending transaction is waited on without a time limit:
/// failing a slow payout would mark money as unsent while it may still land.
pub async fn wait_for_receipt<P: Provider>(
    provider: &P,
    hash: TxHash,
    confirmations: u64,
) -> TransportResult<Option<TransactionReceipt>> {
    let mut misses = 0;
    loop {
        if let Some(receipt) = provider.get_transaction_receipt(hash).await? {
            let mined_at = receipt.block_number.unwrap_or_default();
            let head = provider.get_block_number().await?;
            if head + 1 >= mined_at + confirmations.max(1) {
                return Ok(Some(receipt));
            }
            misses = 0;
        } else if provider.get_transaction_by_hash(hash).await?.is_none() {
            misses += 1;
            if misses >= DROPPED_AFTER_POLLS {
                return Ok(None);
            }
        } else {
            misses = 0;
        }
        tokio::time::sleep(RECEIPT_POLL_INTERVAL).await;
    }
}

#[cfg(all(test, feature = "evm-testing"))]
mod tests {
    use super::*;
    use crate::evm_testing::LocalChain;
    use alloy::network::TransactionBuilder;
    use alloy::primitives::U256;
    use alloy::rpc::types::TransactionRequest;

    #[tokio::test]
    #[ignore = "needs a local chain and compiled contracts"]
    async fn local_chain_receipt_waits_for_confirmations() {
        let chain = LocalChain::deploy().await;
        let pending = chain
            .admin
            .send_transaction(
                TransactionRequest::default()
                    .with_to(chain.recipient_address)
                    .with_value(U256::from(1)),
            )
            .await
            .unwrap();
        let hash = *pending.tx_hash();

        // Mined but only once confirmed: this must still be waiting.
        let wait = wait_for_receipt(&chain.admin, hash, 3);
        let early = tokio::time::timeout(Duration::from_millis(1500), wait).await;
        assert!(early.is_err(), "one confirmation must not satisfy three");

        chain.advance_time(1).await;
        chain.advance_time(1).await;
        let receipt = wait_for_receipt(&chain.admin, hash, 3)
            .await
            .unwrap()
            .expect("mined");
        assert!(receipt.status());
        assert_eq!(receipt.transaction_hash, hash);
    }

    #[tokio::test]
    #[ignore = "needs a local chain and compiled contracts; takes 30 seconds"]
    async fn local_chain_unknown_transaction_counts_as_dropped() {
        let chain = LocalChain::deploy().await;
        let receipt = wait_for_receipt(&chain.admin, TxHash::repeat_byte(0x11), 1)
            .await
            .unwrap();
        assert!(receipt.is_none());
    }
}
