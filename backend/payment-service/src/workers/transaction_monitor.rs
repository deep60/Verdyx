use anyhow::Result;
use std::sync::Arc;
use tracing::{info, warn};

use crate::services::payment_service::PaymentService;

/// Transaction monitor: polls the database for pending transactions
/// and checks their on-chain receipt status, updating records accordingly.
pub async fn start(service: Arc<PaymentService>) -> Result<()> {
    info!("Transaction monitor worker started");
    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(30));

    loop {
        interval.tick().await;

        // Query pending transactions from DB
        let pending = sqlx::query_as::<_, PendingTx>(
            "SELECT id, transaction_hash as tx_hash FROM payment_transactions WHERE status = 'pending' AND transaction_hash IS NOT NULL LIMIT 50"
        )
        .fetch_all(service.db_pool())
        .await;

        match pending {
            Ok(txs) => {
                for tx in txs {
                    match service.get_tx_receipt(&tx.tx_hash).await {
                        Ok(Some(receipt)) => {
                            let status = if receipt.status() {
                                "confirmed"
                            } else {
                                "failed"
                            };
                            let _ = sqlx::query(
                                "UPDATE payment_transactions SET status = $1, block_number = $2, confirmed_at = NOW() WHERE id = $3"
                            )
                            .bind(status)
                            .bind(receipt.block_number.map(|n| n as i64))
                            .bind(tx.id)
                            .execute(service.db_pool())
                            .await;
                            info!("Transaction {} status: {}", tx.tx_hash, status);
                        }
                        Ok(None) => {
                            // Still pending, no action needed
                        }
                        Err(e) => {
                            warn!("Failed to check tx {}: {}", tx.tx_hash, e);
                        }
                    }
                }
            }
            Err(e) => {
                // Table may not exist yet — non-fatal
                if !e.to_string().contains("does not exist") {
                    warn!("Failed to query pending transactions: {}", e);
                }
            }
        }
    }
}

#[derive(sqlx::FromRow)]
struct PendingTx {
    id: uuid::Uuid,
    tx_hash: String,
}
