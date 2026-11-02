use anyhow::Result;
use std::sync::Arc;
use tracing::{info, warn};

use crate::services::payment_service::PaymentService;

/// Balance reconciliation: periodically compares on-chain token balances
/// against database records and logs discrepancies for investigation.
pub async fn start(service: Arc<PaymentService>) -> Result<()> {
    info!("Balance reconciliation worker started");
    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(300));

    loop {
        interval.tick().await;

        // Query tracked wallets from DB
        let wallets = sqlx::query_scalar::<_, String>(
            "SELECT DISTINCT address FROM wallet_balances WHERE tracked = true LIMIT 100",
        )
        .fetch_all(service.db_pool())
        .await;

        match wallets {
            Ok(addresses) => {
                for address in addresses {
                    // Get on-chain balance
                    match service.get_token_balance(&address).await {
                        Ok(on_chain) => {
                            // Get DB-recorded balance
                            let db_balance = sqlx::query_scalar::<_, String>(
                                "SELECT balance FROM wallet_balances WHERE address = $1",
                            )
                            .bind(&address)
                            .fetch_optional(service.db_pool())
                            .await
                            .ok()
                            .flatten()
                            .unwrap_or_else(|| "0".to_string());

                            let db_amount =
                                alloy::primitives::U256::from_str_radix(&db_balance, 10)
                                    .unwrap_or_default();

                            if on_chain != db_amount {
                                warn!(
                                    "Balance mismatch for {}: on-chain={}, db={}",
                                    address, on_chain, db_amount
                                );
                                // Update DB to match on-chain (source of truth)
                                let _ = sqlx::query(
                                    "UPDATE wallet_balances SET balance = $1, updated_at = NOW() WHERE address = $2"
                                )
                                .bind(format!("{on_chain}"))
                                .bind(&address)
                                .execute(service.db_pool())
                                .await;
                            }
                        }
                        Err(e) => {
                            warn!("Failed to get on-chain balance for {}: {}", address, e);
                        }
                    }
                }
            }
            Err(e) => {
                // Table may not exist yet — non-fatal
                if !e.to_string().contains("does not exist") {
                    warn!("Failed to query tracked wallets: {}", e);
                }
            }
        }
    }
}
