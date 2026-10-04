use anyhow::{Context, Result};
use ethers::middleware::SignerMiddleware;
use ethers::prelude::*;
use ethers::signers::{LocalWallet, Signer};
use redis::aio::ConnectionManager;
use rust_decimal::Decimal;
use sqlx::PgPool;
use std::sync::Arc;
use tracing::{info, warn};
use uuid::Uuid;

use crate::blockchain::{BlockchainProvider, TokenContract};
use crate::config::Config;
use crate::models::*;

/// Signer-bound client used for treasury-authored transactions.
pub type SignerClient = SignerMiddleware<BlockchainProvider, LocalWallet>;

pub struct PaymentService {
    config: Config,
    db_pool: PgPool,
    redis_conn: ConnectionManager,
    // None when the blockchain RPC is disabled/unreachable at startup. On-chain
    // operations return an error in that mode; DB-backed routes keep working.
    provider: Option<BlockchainProvider>,
}

/// Decimals used by ThreatToken, matching the ERC-20 default.
///
/// Everything on the wire is a whole-token `Decimal`; everything on-chain and
/// every bound in `PaymentConfig` (`min_withdraw_amount`, `max_withdraw_amount`)
/// is wei. `to_wei` is the only place the two meet.
const TOKEN_DECIMALS: u32 = 18;

impl PaymentService {
    pub async fn new(
        config: Config,
        db_pool: PgPool,
        redis_conn: ConnectionManager,
        provider: Option<BlockchainProvider>,
    ) -> Result<Self> {
        Ok(Self {
            config,
            db_pool,
            redis_conn,
            provider,
        })
    }

    pub fn db_pool(&self) -> &PgPool {
        &self.db_pool
    }

    /// The blockchain provider, or an error when the chain is unavailable.
    fn provider(&self) -> Result<&BlockchainProvider> {
        self.provider.as_ref().ok_or_else(|| {
            anyhow::anyhow!("blockchain provider unavailable (RPC disabled or unreachable)")
        })
    }

    /// Build a treasury-signing client (provider + treasury wallet).
    fn signer_client(&self) -> Result<Arc<SignerClient>> {
        let wallet = self
            .config
            .blockchain
            .treasury_private_key
            .parse::<LocalWallet>()
            .context("Invalid treasury private key")?
            .with_chain_id(self.config.blockchain.chain_id);

        let client = SignerMiddleware::new(self.provider()?.clone(), wallet);
        Ok(Arc::new(client))
    }

    fn token_contract(&self) -> Result<TokenContract<Provider<Ws>>> {
        let addr: Address = self
            .config
            .blockchain
            .token_contract_address
            .parse()
            .context("Invalid token contract address")?;
        Ok(TokenContract::new(addr, self.provider()?.clone()))
    }

    fn token_contract_signed(&self) -> Result<TokenContract<SignerClient>> {
        let addr: Address = self
            .config
            .blockchain
            .token_contract_address
            .parse()
            .context("Invalid token contract address")?;
        Ok(TokenContract::new(addr, self.signer_client()?))
    }

    // -- Reads ------------------------------------------------------------

    pub async fn get_token_balance(&self, address: &str) -> Result<U256> {
        let addr: Address = address.parse().context("Invalid Ethereum address")?;
        let token = self.token_contract()?;
        token
            .balance_of(addr)
            .call()
            .await
            .context("Failed to call balanceOf")
    }

    pub async fn get_tx_receipt(
        &self,
        tx_hash: &str,
    ) -> Result<Option<ethers::types::TransactionReceipt>> {
        let hash: H256 = tx_hash.parse().context("Invalid transaction hash")?;
        self.provider()?
            .get_transaction_receipt(hash)
            .await
            .context("Failed to get transaction receipt")
    }

    pub async fn estimate_gas_for_transfer(&self) -> Result<U256> {
        let gas_price = self
            .provider()?
            .get_gas_price()
            .await
            .context("Failed to get gas price")?;
        Ok(U256::from(65_000) * gas_price)
    }

    pub async fn health_check(&self) -> bool {
        let Some(provider) = self.provider.as_ref() else {
            return false;
        };
        matches!(
            tokio::time::timeout(
                std::time::Duration::from_secs(5),
                provider.get_block_number(),
            )
            .await,
            Ok(Ok(_))
        )
    }

    // -- Treasury-signed transfers ---------------------------------------

    /// Transfer tokens FROM the treasury to `to`, waiting for confirmations.
    /// Returns the transaction receipt on success.
    async fn treasury_transfer(
        &self,
        to: &str,
        amount: U256,
    ) -> Result<ethers::types::TransactionReceipt> {
        let to_addr: Address = to.parse().context("Invalid recipient address")?;
        let token = self.token_contract_signed()?;

        // Ensure the treasury can cover it.
        let treasury: Address = self
            .config
            .blockchain
            .treasury_address
            .parse()
            .context("Invalid treasury address")?;
        let balance = token.balance_of(treasury).call().await?;
        if balance < amount {
            anyhow::bail!("Treasury balance {balance} below required {amount}");
        }

        let call = token.transfer(to_addr, amount);
        let pending = call.send().await.context("Failed to broadcast transfer")?;

        info!("Treasury transfer broadcast: {:?}", pending.tx_hash());

        let confirmations = self.config.blockchain.confirmation_blocks as usize;
        let receipt = pending
            .confirmations(confirmations.max(1))
            .await
            .context("Failed waiting for confirmations")?
            .ok_or_else(|| anyhow::anyhow!("Transfer dropped from mempool"))?;

        if receipt.status != Some(1u64.into()) {
            anyhow::bail!("Transfer reverted on-chain: {:?}", receipt.transaction_hash);
        }

        Ok(receipt)
    }

    // -- Persistence helpers ---------------------------------------------

    /// Insert a payment row and return its id.
    async fn insert_payment(
        &self,
        bounty_id: Option<Uuid>,
        payer: &str,
        recipient: &str,
        amount: Decimal,
        payment_type: PaymentType,
        status: PaymentStatus,
    ) -> PaymentResult<Uuid> {
        let token_addr = self.config.blockchain.token_contract_address.clone();
        sqlx::query_scalar::<_, Uuid>(
            r#"
            INSERT INTO payments
                (bounty_id, payer_address, recipient_address, amount,
                 token_address, status, payment_type)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING id
            "#,
        )
        .bind(bounty_id.unwrap_or_else(Uuid::nil))
        .bind(payer)
        .bind(recipient)
        .bind(amount)
        .bind(token_addr)
        .bind(status.to_string())
        .bind(payment_type.to_string())
        .fetch_one(&self.db_pool)
        .await
        .map_err(|e| PaymentError::DatabaseError(e.to_string()))
    }

    async fn mark_payment(
        &self,
        id: Uuid,
        status: PaymentStatus,
        tx_hash: Option<&str>,
        block_number: Option<i64>,
        error: Option<&str>,
    ) -> PaymentResult<()> {
        let completed = matches!(status, PaymentStatus::Completed | PaymentStatus::Confirmed);
        sqlx::query(
            r#"
            UPDATE payments
            SET status = $2,
                transaction_hash = COALESCE($3, transaction_hash),
                metadata = COALESCE(metadata, '{}'::jsonb)
                    || jsonb_build_object('block_number', $4::bigint, 'error', $5::text),
                updated_at = NOW(),
                completed_at = CASE WHEN $6 THEN NOW() ELSE completed_at END
            WHERE id = $1
            "#,
        )
        .bind(id)
        .bind(status.to_string())
        .bind(tx_hash)
        .bind(block_number)
        .bind(error)
        .bind(completed)
        .execute(&self.db_pool)
        .await
        .map_err(|e| PaymentError::DatabaseError(e.to_string()))?;
        Ok(())
    }

    /// Convert a whole-token amount into base units (wei).
    ///
    /// Amounts travel through the API as whole tokens (`0.05` means five
    /// hundredths of a token); every on-chain value and every bound in
    /// `PaymentConfig` is denominated in wei. This is the conversion between
    /// the two, and it must scale by 10^[`TOKEN_DECIMALS`].
    ///
    /// Sub-wei dust is **truncated, not rounded**: a payout must never exceed
    /// what was asked for, and rounding up would mint value out of precision.
    fn to_wei(amount: &Decimal) -> PaymentResult<U256> {
        if amount.is_sign_negative() {
            return Err(PaymentError::ValidationError(format!(
                "amount must not be negative: {amount}"
            )));
        }

        let scale = Decimal::from(10u64.pow(TOKEN_DECIMALS));
        let scaled = amount.checked_mul(scale).ok_or_else(|| {
            PaymentError::ValidationError(format!("amount too large to represent: {amount}"))
        })?;

        // trunc() discards anything below one wei.
        U256::from_dec_str(&scaled.trunc().to_string())
            .map_err(|e| PaymentError::ValidationError(format!("invalid amount: {e}")))
    }

    // -- High-level operations -------------------------------------------

    /// Distribute a bounty reward: treasury → winner, real transfer.
    pub async fn distribute_reward(
        &self,
        req: &DistributeBountyRequest,
    ) -> PaymentResult<PaymentResponse> {
        let amount_wei = Self::to_wei(&req.amount)?;
        let payment_id = self
            .insert_payment(
                Some(req.bounty_id),
                &self.config.blockchain.treasury_address,
                &req.winner_address,
                req.amount,
                PaymentType::BountyReward,
                PaymentStatus::Processing,
            )
            .await?;

        match self
            .treasury_transfer(&req.winner_address, amount_wei)
            .await
        {
            Ok(receipt) => {
                let tx_hash = format!("{:?}", receipt.transaction_hash);
                let block = receipt.block_number.map(|b| b.as_u64() as i64);
                self.mark_payment(
                    payment_id,
                    PaymentStatus::Completed,
                    Some(&tx_hash),
                    block,
                    None,
                )
                .await?;
                Ok(PaymentResponse {
                    success: true,
                    payment_id: Some(payment_id),
                    tx_hash: Some(tx_hash),
                    message: "Bounty reward distributed".to_string(),
                    estimated_completion_time: None,
                })
            }
            Err(e) => {
                self.mark_payment(
                    payment_id,
                    PaymentStatus::Failed,
                    None,
                    None,
                    Some(&e.to_string()),
                )
                .await?;
                Err(PaymentError::TransactionFailed(e.to_string()))
            }
        }
    }

    /// Process a withdrawal: treasury → user, minus fee.
    pub async fn process_withdrawal(
        &self,
        req: &WithdrawRequest,
    ) -> PaymentResult<PaymentResponse> {
        let min = U256::from_dec_str(&self.config.payment.min_withdraw_amount).unwrap_or_default();
        let max = U256::from_dec_str(&self.config.payment.max_withdraw_amount).unwrap_or(U256::MAX);
        let amount_wei = Self::to_wei(&req.amount)?;

        if amount_wei < min {
            return Err(PaymentError::ValidationError(format!(
                "amount below minimum withdrawal ({min})"
            )));
        }
        if amount_wei > max {
            return Err(PaymentError::ValidationError(format!(
                "amount above maximum withdrawal ({max})"
            )));
        }

        // Apply withdrawal fee.
        let fee_bps = (self.config.payment.withdraw_fee_percentage * 100.0) as u64;
        let fee = amount_wei * U256::from(fee_bps) / U256::from(10_000u64);
        let net = amount_wei.saturating_sub(fee);

        let payment_id = self
            .insert_payment(
                None,
                &self.config.blockchain.treasury_address,
                &req.to_address,
                req.amount,
                PaymentType::Withdrawal,
                PaymentStatus::Processing,
            )
            .await?;

        match self.treasury_transfer(&req.to_address, net).await {
            Ok(receipt) => {
                let tx_hash = format!("{:?}", receipt.transaction_hash);
                let block = receipt.block_number.map(|b| b.as_u64() as i64);
                self.mark_payment(
                    payment_id,
                    PaymentStatus::Completed,
                    Some(&tx_hash),
                    block,
                    None,
                )
                .await?;
                Ok(PaymentResponse {
                    success: true,
                    payment_id: Some(payment_id),
                    tx_hash: Some(tx_hash),
                    message: format!("Withdrawal sent (fee {fee} wei)"),
                    estimated_completion_time: None,
                })
            }
            Err(e) => {
                self.mark_payment(
                    payment_id,
                    PaymentStatus::Failed,
                    None,
                    None,
                    Some(&e.to_string()),
                )
                .await?;
                Err(PaymentError::TransactionFailed(e.to_string()))
            }
        }
    }

    /// Record a bounty deposit intent. The actual transfer must be signed by
    /// the creator's wallet client-side; here we verify funds and persist a
    /// pending record that the transaction monitor reconciles once the
    /// on-chain deposit event arrives.
    pub async fn record_deposit_intent(
        &self,
        req: &DepositBountyRequest,
    ) -> PaymentResult<PaymentResponse> {
        let amount_wei = Self::to_wei(&req.amount)?;
        let balance = self
            .get_token_balance(&req.creator_address)
            .await
            .map_err(|e| PaymentError::BlockchainError(e.to_string()))?;
        if balance < amount_wei {
            return Err(PaymentError::InsufficientBalance(format!(
                "creator balance {balance} < required {amount_wei}"
            )));
        }

        let payment_id = self
            .insert_payment(
                Some(req.bounty_id),
                &req.creator_address,
                &self.config.blockchain.treasury_address,
                req.amount,
                PaymentType::BountyDeposit,
                PaymentStatus::Pending,
            )
            .await?;

        Ok(PaymentResponse {
            success: true,
            payment_id: Some(payment_id),
            tx_hash: None,
            message: "Deposit recorded; awaiting on-chain confirmation".to_string(),
            estimated_completion_time: None,
        })
    }

    /// Record a stake lock intent (user-signed on-chain).
    pub async fn record_stake_lock(
        &self,
        req: &LockStakeRequest,
    ) -> PaymentResult<PaymentResponse> {
        let amount_wei = Self::to_wei(&req.amount)?;
        let balance = self
            .get_token_balance(&req.address)
            .await
            .map_err(|e| PaymentError::BlockchainError(e.to_string()))?;
        if balance < amount_wei {
            return Err(PaymentError::InsufficientBalance(format!(
                "balance {balance} < stake {amount_wei}"
            )));
        }

        let payment_id = self
            .insert_payment(
                Some(req.bounty_id),
                &req.address,
                &self.config.blockchain.treasury_address,
                req.amount,
                PaymentType::StakeLock,
                PaymentStatus::Pending,
            )
            .await?;

        Ok(PaymentResponse {
            success: true,
            payment_id: Some(payment_id),
            tx_hash: None,
            message: "Stake lock recorded; awaiting on-chain confirmation".to_string(),
            estimated_completion_time: None,
        })
    }

    /// Slash a stake: treasury transfers the slashed portion out of the
    /// slashed user. In this model slashing is enforced by transferring the
    /// slashed amount from treasury custody to the bounty pool address.
    pub async fn slash_stake(&self, req: &SlashStakeRequest) -> PaymentResult<PaymentResponse> {
        let amount_wei = Self::to_wei(&req.slash_amount)?;
        let payment_id = self
            .insert_payment(
                None,
                &self.config.blockchain.treasury_address,
                &self.config.blockchain.treasury_address,
                req.slash_amount,
                PaymentType::StakeSlash,
                PaymentStatus::Processing,
            )
            .await?;

        // Slashed funds are moved to the payment/escrow contract address.
        let dest = self.config.blockchain.payment_contract_address.clone();
        match self.treasury_transfer(&dest, amount_wei).await {
            Ok(receipt) => {
                let tx_hash = format!("{:?}", receipt.transaction_hash);
                let block = receipt.block_number.map(|b| b.as_u64() as i64);
                self.mark_payment(
                    payment_id,
                    PaymentStatus::Completed,
                    Some(&tx_hash),
                    block,
                    None,
                )
                .await?;
                Ok(PaymentResponse {
                    success: true,
                    payment_id: Some(payment_id),
                    tx_hash: Some(tx_hash),
                    message: format!("Stake {} slashed", req.stake_id),
                    estimated_completion_time: None,
                })
            }
            Err(e) => {
                self.mark_payment(
                    payment_id,
                    PaymentStatus::Failed,
                    None,
                    None,
                    Some(&e.to_string()),
                )
                .await?;
                Err(PaymentError::TransactionFailed(e.to_string()))
            }
        }
    }

    /// Mark a stake as unlocked (no transfer needed; funds were never moved).
    pub async fn unlock_stake(&self, stake_id: Uuid) -> PaymentResult<PaymentResponse> {
        Ok(PaymentResponse {
            success: true,
            payment_id: None,
            tx_hash: None,
            message: format!("Stake {stake_id} marked for unlock"),
            estimated_completion_time: None,
        })
    }

    // -- Worker support ---------------------------------------------------

    /// Pending payments awaiting on-chain confirmation.
    pub async fn list_pending(&self) -> PaymentResult<Vec<Payment>> {
        sqlx::query_as::<_, Payment>(
            "SELECT * FROM payments WHERE status IN ('pending','processing') ORDER BY created_at ASC LIMIT 100",
        )
        .fetch_all(&self.db_pool)
        .await
        .map_err(|e| PaymentError::DatabaseError(e.to_string()))
    }

    /// Reconcile a processing payment that has a tx hash by checking its receipt.
    pub async fn reconcile_payment(&self, payment: &Payment) -> PaymentResult<()> {
        let Some(tx_hash) = &payment.tx_hash else {
            return Ok(());
        };
        match self.get_tx_receipt(tx_hash).await {
            Ok(Some(receipt)) => {
                let status = if receipt.status == Some(1u64.into()) {
                    PaymentStatus::Completed
                } else {
                    PaymentStatus::Failed
                };
                let block = receipt.block_number.map(|b| b.as_u64() as i64);
                self.mark_payment(payment.id, status, Some(tx_hash), block, None)
                    .await?;
            }
            Ok(None) => { /* still pending */ }
            Err(e) => warn!("reconcile {} failed: {}", payment.id, e),
        }
        Ok(())
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    #[allow(dead_code)]
    fn redis(&self) -> ConnectionManager {
        self.redis_conn.clone()
    }
}

#[cfg(test)]
mod money_tests {
    use super::*;
    use std::str::FromStr;

    fn wei(d: &str) -> U256 {
        PaymentService::to_wei(&Decimal::from_str(d).unwrap()).expect("valid amount")
    }

    /// One whole token is 10^18 wei. This is the invariant the original
    /// implementation violated: it rounded the token amount to an integer and
    /// used that as wei, so every payout was 10^18 times too small.
    #[test]
    fn one_token_is_ten_to_the_eighteen_wei() {
        assert_eq!(wei("1"), U256::from_dec_str("1000000000000000000").unwrap());
    }

    /// Regression: the README's own example bounty is 0.05 tokens. Under the
    /// old rounding it became 0 wei -- a winner would have been paid nothing,
    /// successfully, with a transaction hash to prove it.
    #[test]
    fn fractional_amounts_do_not_collapse_to_zero() {
        assert_eq!(wei("0.05"), U256::from_dec_str("50000000000000000").unwrap());
        assert_eq!(wei("0.5"), U256::from_dec_str("500000000000000000").unwrap());
        assert!(!wei("0.000001").is_zero(), "a micro-token must be non-zero in wei");
    }

    /// Values must clear the configured minimum withdrawal, which is written
    /// in wei (config.rs defaults to 1 token = 10^18). Before the fix a
    /// 5-token withdrawal produced 5 wei and was rejected as below minimum.
    #[test]
    fn amounts_are_comparable_with_wei_denominated_config_bounds() {
        let min_withdraw = U256::from_dec_str("1000000000000000000").unwrap(); // 1 token
        assert!(wei("5") > min_withdraw, "5 tokens must exceed a 1-token minimum");
        assert!(wei("1") == min_withdraw);
        assert!(wei("0.5") < min_withdraw);
    }

    /// Scaling must be monotonic: more tokens is always more wei. A rounding
    /// scheme that collapses distinct amounts to the same integer breaks
    /// ordering, and with it every bound check built on it.
    #[test]
    fn conversion_is_strictly_monotonic() {
        let ladder = ["0.001", "0.05", "0.5", "1", "1.5", "2", "10", "1000"];
        for pair in ladder.windows(2) {
            assert!(
                wei(pair[0]) < wei(pair[1]),
                "{} should convert to fewer wei than {}",
                pair[0],
                pair[1]
            );
        }
    }

    /// Sub-wei dust truncates. Paying out more than was asked for would mint
    /// value from nothing, so the rounding direction is a safety property,
    /// not a preference.
    #[test]
    fn sub_wei_dust_truncates_and_never_rounds_up() {
        // 1 wei + a half wei of dust stays 1 wei.
        let amount = Decimal::from_str("0.0000000000000000015").unwrap();
        assert_eq!(
            PaymentService::to_wei(&amount).unwrap(),
            U256::from(1u64),
            "dust below one wei must be discarded, not rounded up"
        );
    }

    /// Zero is a legitimate amount to convert; it must not error.
    #[test]
    fn zero_converts_to_zero() {
        assert_eq!(wei("0"), U256::zero());
    }

    /// Negative amounts are rejected explicitly rather than failing deep in
    /// U256 parsing with an opaque message.
    #[test]
    fn negative_amounts_are_rejected() {
        let err = PaymentService::to_wei(&Decimal::from_str("-1").unwrap());
        assert!(err.is_err(), "a negative payout must never convert");
    }

    /// An amount too large to scale must fail cleanly instead of panicking
    /// inside Decimal multiplication.
    #[test]
    fn oversized_amounts_fail_cleanly() {
        let huge = Decimal::MAX;
        let result = PaymentService::to_wei(&huge);
        assert!(result.is_err(), "overflow must be reported, not panic");
    }
}
