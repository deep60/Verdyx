// backend/bounty-manager/src/services/blockchain_sync.rs

use alloy::primitives::{Address, B256, U256};
use alloy::providers::Provider;
use alloy::rpc::types::Filter;
use alloy::sol;
use alloy::sol_types::SolEvent;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::{interval, Duration};
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::services::blockchain::BlockchainService;

/// Service for synchronizing blockchain state with database
#[derive(Clone)]
pub struct BlockchainSyncService {
    db: PgPool,
    blockchain: Arc<BlockchainService>,
    last_synced_block: Arc<RwLock<u64>>,
    sync_interval_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncStatus {
    pub last_synced_block: u64,
    pub current_block: u64,
    pub blocks_behind: u64,
    pub is_syncing: bool,
    pub last_sync_time: chrono::DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockchainEvent {
    pub event_type: BlockchainEventType,
    pub block_number: u64,
    pub transaction_hash: String,
    pub timestamp: i64,
    pub data: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BlockchainEventType {
    BountyCreated,
    BountyFunded,
    SubmissionStaked,
    ConsensusReached,
    PayoutDistributed,
    StakeSlashed,
    DisputeRaised,
    DisputeResolved,
}

impl BlockchainSyncService {
    pub fn new(db: PgPool, blockchain: Arc<BlockchainService>) -> Self {
        Self {
            db,
            blockchain,
            last_synced_block: Arc::new(RwLock::new(0)),
            sync_interval_seconds: 15, // Sync every 15 seconds
        }
    }

    /// Start the blockchain sync service
    pub async fn start(&self) -> Result<(), SyncError> {
        info!("Starting blockchain sync service...");

        // Initialize last synced block from database
        if let Ok(block) = self.get_last_synced_block_from_db().await {
            *self.last_synced_block.write().await = block;
            info!("Resuming sync from block {}", block);
        }

        let service = self.clone();
        tokio::spawn(async move {
            service.sync_loop().await;
        });

        Ok(())
    }

    /// Main sync loop
    async fn sync_loop(&self) {
        let mut ticker = interval(Duration::from_secs(self.sync_interval_seconds));

        loop {
            ticker.tick().await;

            if let Err(e) = self.sync_blocks().await {
                error!("Error syncing blocks: {}", e);
            }
        }
    }

    /// Sync new blocks from blockchain
    async fn sync_blocks(&self) -> Result<(), SyncError> {
        let last_synced = *self.last_synced_block.read().await;

        // Get current block number from blockchain
        let current_block = self.get_current_block_number().await?;

        if current_block <= last_synced {
            return Ok(());
        }

        info!(
            "Syncing blocks {} to {} ({} blocks)",
            last_synced + 1,
            current_block,
            current_block - last_synced
        );

        // Sync blocks in batches to avoid overwhelming the system
        let batch_size = 100;
        for start_block in (last_synced + 1..=current_block).step_by(batch_size) {
            let end_block = (start_block + batch_size as u64 - 1).min(current_block);

            if let Err(e) = self.sync_block_range(start_block, end_block).await {
                error!("Error syncing blocks {}-{}: {}", start_block, end_block, e);
                return Err(e);
            }

            // Update last synced block
            *self.last_synced_block.write().await = end_block;
            self.save_last_synced_block(end_block).await?;
        }

        Ok(())
    }

    /// Sync a range of blocks
    async fn sync_block_range(&self, start: u64, end: u64) -> Result<(), SyncError> {
        for block_num in start..=end {
            // Get events from this block
            let events = self.get_block_events(block_num).await?;

            for event in events {
                if let Err(e) = self.process_event(&event).await {
                    error!("Error processing event: {}", e);
                }
            }
        }

        Ok(())
    }

    /// Get events from a specific block
    async fn get_block_events(&self, block_number: u64) -> Result<Vec<BlockchainEvent>, SyncError> {
        let client = self.blockchain.get_client();
        let filter = Filter::new()
            .from_block(block_number)
            .to_block(block_number);

        let logs = client
            .get_logs(&filter)
            .await
            .map_err(|e| SyncError::BlockchainError(format!("Failed to fetch logs: {e}")))?;

        let events: Vec<BlockchainEvent> = logs
            .iter()
            .filter_map(|log| {
                let event_type = classify_event_topic(log.topics().first()?)?;
                let tx_hash = log
                    .transaction_hash
                    .map(|h| format!("{h:?}"))
                    .unwrap_or_default();
                let log_data = &log.data().data;
                // Stored as a hex quantity, the JSON-RPC form of a log index.
                let log_index = log.log_index.map(U256::from);
                let address = format!("{:?}", log.address());

                // ── Decode indexed topics ──
                // topic[0] = event signature hash
                // topic[1..] = indexed params (uint256 → U256, address → Address)
                let bounty_id = log
                    .topics()
                    .get(1)
                    .map(|t| U256::from_be_bytes(t.0).to_string());

                // For events with 2 indexed params: topic[2] is address (creator/analyst)
                let indexed_address = log
                    .topics()
                    .get(2)
                    .map(|t| format!("{:?}", Address::from_word(*t)));

                // ── Decode non-indexed data from log.data ──
                let data = match event_type {
                    // BountyCreated: data = (string artifactHash, uint256 reward, uint256 deadline)
                    BlockchainEventType::BountyCreated => {
                        let decoded = BountyCreated::abi_decode_data(log_data).ok();

                        serde_json::json!({
                            "bounty_id": bounty_id,
                            "creator": indexed_address,
                            "artifact_hash": decoded.as_ref().map(|d| &d.0),
                            "reward": decoded.as_ref().map(|d| d.1.to_string()),
                            "deadline": decoded.as_ref().map(|d| d.2.to_string()),
                            "log_index": log_index,
                            "address": address,
                        })
                    }

                    // AnalysisSubmitted: data = (uint8 verdict, uint256 stake, uint256 confidence)
                    BlockchainEventType::SubmissionStaked => {
                        let decoded = AnalysisSubmitted::abi_decode_data(log_data).ok();

                        serde_json::json!({
                            "bounty_id": bounty_id,
                            "analyst": indexed_address,
                            "verdict": decoded.as_ref().map(|d| d.0),
                            "stake_amount": decoded.as_ref().map(|d| d.1.to_string()),
                            "confidence": decoded.as_ref().map(|d| d.2.to_string()),
                            "log_index": log_index,
                            "address": address,
                        })
                    }

                    // ConsensusReached: data = (uint8 consensus, uint256 confidenceScore, uint256 totalAnalyses)
                    BlockchainEventType::ConsensusReached => {
                        let decoded = ConsensusReached::abi_decode_data(log_data).ok();

                        serde_json::json!({
                            "bounty_id": bounty_id,
                            "consensus_verdict": decoded.as_ref().map(|d| d.0),
                            "confidence_score": decoded.as_ref().map(|d| d.1.to_string()),
                            "total_analyses": decoded.as_ref().map(|d| d.2.to_string()),
                            "log_index": log_index,
                            "address": address,
                        })
                    }

                    // RewardsDistributed: data = (address[] winners, uint256[] rewards, uint256[] stakes)
                    // Dynamic arrays — complex ABI decoding
                    BlockchainEventType::PayoutDistributed => {
                        // For dynamic arrays, just store raw hex and decode later
                        let raw_hex: String = log_data.iter().map(|b| format!("{b:02x}")).collect();
                        serde_json::json!({
                            "bounty_id": bounty_id,
                            "raw_data": format!("0x{}", raw_hex),
                            "log_index": log_index,
                            "address": address,
                        })
                    }

                    // Other events — store what we can
                    _ => {
                        serde_json::json!({
                            "bounty_id": bounty_id,
                            "log_index": log_index,
                            "address": address,
                        })
                    }
                };

                Some(BlockchainEvent {
                    event_type,
                    block_number,
                    transaction_hash: tx_hash,
                    timestamp: chrono::Utc::now().timestamp(),
                    data,
                })
            })
            .collect();

        Ok(events)
    }

    /// Process a blockchain event
    async fn process_event(&self, event: &BlockchainEvent) -> Result<(), SyncError> {
        match &event.event_type {
            BlockchainEventType::BountyCreated => {
                self.handle_bounty_created(event).await?;
            }
            BlockchainEventType::BountyFunded => {
                self.handle_bounty_funded(event).await?;
            }
            BlockchainEventType::SubmissionStaked => {
                self.handle_submission_staked(event).await?;
            }
            BlockchainEventType::ConsensusReached => {
                self.handle_consensus_reached(event).await?;
            }
            BlockchainEventType::PayoutDistributed => {
                self.handle_payout_distributed(event).await?;
            }
            BlockchainEventType::StakeSlashed => {
                self.handle_stake_slashed(event).await?;
            }
            BlockchainEventType::DisputeRaised => {
                self.handle_dispute_raised(event).await?;
            }
            BlockchainEventType::DisputeResolved => {
                self.handle_dispute_resolved(event).await?;
            }
        }

        Ok(())
    }

    /// Handle BountyCreated event
    /// Decoded: bounty_id, creator, artifact_hash, reward, deadline
    async fn handle_bounty_created(&self, event: &BlockchainEvent) -> Result<(), SyncError> {
        let chain_bounty_id = event
            .data
            .get("bounty_id")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let creator = event
            .data
            .get("creator")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let artifact_hash = event
            .data
            .get("artifact_hash")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let reward = event
            .data
            .get("reward")
            .and_then(|v| v.as_str())
            .unwrap_or("0");

        info!(
            "BountyCreated: id={}, creator={}, artifact={}, reward={}, tx={}",
            chain_bounty_id, creator, artifact_hash, reward, event.transaction_hash
        );

        // Look up DB bounty by artifact_hash + creator and update it with on-chain data
        let result = sqlx::query(
            r#"
            UPDATE bounties
            SET status = 'Active',
                metadata = COALESCE(metadata, '{}'::jsonb) || jsonb_build_object(
                    'on_chain_id', $1::text,
                    'chain_tx_hash', $2::text,
                    'chain_block', $3::bigint
                ),
                updated_at = NOW()
            WHERE artifact_hash = $4 AND creator = $5 AND status = 'Pending'
            "#,
        )
        .bind(chain_bounty_id)
        .bind(&event.transaction_hash)
        .bind(event.block_number as i64)
        .bind(artifact_hash)
        .bind(creator)
        .execute(&self.db)
        .await;

        match result {
            Ok(r) if r.rows_affected() > 0 => {
                info!("Updated bounty to Active for chain id {}", chain_bounty_id);
            }
            Ok(_) => {
                warn!(
                    "No matching Pending bounty found for chain id {} (artifact={}, creator={})",
                    chain_bounty_id, artifact_hash, creator
                );
            }
            Err(e) => {
                error!("DB error updating bounty for chain event: {}", e);
                return Err(SyncError::DatabaseError(e.to_string()));
            }
        }

        Ok(())
    }

    /// Handle BountyFunded event
    async fn handle_bounty_funded(&self, event: &BlockchainEvent) -> Result<(), SyncError> {
        let bounty_id = event
            .data
            .get("bounty_id")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        info!(
            "BountyFunded: id={}, tx={}",
            bounty_id, event.transaction_hash
        );
        // Funding is implicit in createBounty (transferFrom) — no additional DB update needed
        Ok(())
    }

    /// Handle SubmissionStaked (AnalysisSubmitted) event
    /// Decoded: bounty_id, analyst, verdict, stake_amount, confidence
    async fn handle_submission_staked(&self, event: &BlockchainEvent) -> Result<(), SyncError> {
        let chain_bounty_id = event
            .data
            .get("bounty_id")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let analyst = event
            .data
            .get("analyst")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let verdict_num = event
            .data
            .get("verdict")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let stake = event
            .data
            .get("stake_amount")
            .and_then(|v| v.as_str())
            .unwrap_or("0");
        let confidence = event
            .data
            .get("confidence")
            .and_then(|v| v.as_str())
            .unwrap_or("0");

        info!(
            "AnalysisSubmitted: bounty={}, analyst={}, verdict={}, stake={}, confidence={}, tx={}",
            chain_bounty_id, analyst, verdict_num, stake, confidence, event.transaction_hash
        );

        // Map numeric verdict to string: Solidity ThreatVerdict enum
        // Pending=0, Benign=1, Malicious=2, Suspicious=3
        let verdict_str = match verdict_num {
            0 => "Pending",
            1 => "Benign",
            2 => "Malicious",
            3 => "Suspicious",
            _ => "Unknown",
        };

        // Look up the internal bounty UUID by on-chain ID stored in metadata
        let bounty_uuid: Option<Uuid> =
            sqlx::query_scalar("SELECT id FROM bounties WHERE metadata->>'on_chain_id' = $1")
                .bind(chain_bounty_id)
                .fetch_optional(&self.db)
                .await
                .unwrap_or(None);

        let bounty_id = match bounty_uuid {
            Some(id) => id,
            None => {
                warn!(
                    "No bounty found for chain id {}; skipping submission insert",
                    chain_bounty_id
                );
                return Ok(());
            }
        };

        // Parse stake and confidence to numeric types
        let stake_amount: i64 = stake.parse().unwrap_or(0);
        let confidence_f32: f32 = confidence.parse::<f64>().unwrap_or(0.0) as f32;

        // Insert submission record
        let submission_id = Uuid::new_v4();
        let result = sqlx::query(
            r#"
            INSERT INTO submissions (
                id, bounty_id, engine_id, engine_type, verdict, confidence,
                stake_amount, analysis_details, status, transaction_hash,
                submitted_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW())
            ON CONFLICT DO NOTHING
            "#,
        )
        .bind(submission_id)
        .bind(bounty_id)
        .bind(analyst)
        .bind("blockchain_analyst")
        .bind(verdict_str)
        .bind(confidence_f32)
        .bind(stake_amount)
        .bind(serde_json::json!({ "source": "blockchain_sync", "block": event.block_number }))
        .bind("Confirmed")
        .bind(&event.transaction_hash)
        .execute(&self.db)
        .await;

        match result {
            Ok(r) if r.rows_affected() > 0 => {
                info!(
                    "Created submission {} for bounty {}",
                    submission_id, bounty_id
                );
            }
            Ok(_) => {
                warn!(
                    "Submission already existed for tx {}",
                    event.transaction_hash
                );
            }
            Err(e) => {
                error!("DB error creating submission: {}", e);
                return Err(SyncError::DatabaseError(e.to_string()));
            }
        }

        Ok(())
    }

    /// Handle ConsensusReached event
    /// Decoded: bounty_id, consensus_verdict, confidence_score, total_analyses
    async fn handle_consensus_reached(&self, event: &BlockchainEvent) -> Result<(), SyncError> {
        let chain_bounty_id = event
            .data
            .get("bounty_id")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let verdict = event
            .data
            .get("consensus_verdict")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let confidence = event
            .data
            .get("confidence_score")
            .and_then(|v| v.as_str())
            .unwrap_or("0");
        let total = event
            .data
            .get("total_analyses")
            .and_then(|v| v.as_str())
            .unwrap_or("0");

        info!(
            "ConsensusReached: bounty={}, verdict={}, confidence={}, analyses={}, tx={}",
            chain_bounty_id, verdict, confidence, total, event.transaction_hash
        );

        // Solidity ThreatVerdict enum: Pending=0, Benign=1, Malicious=2, Suspicious=3
        let verdict_str = match verdict {
            0 => "Pending",
            1 => "Benign",
            2 => "Malicious",
            3 => "Suspicious",
            _ => "Unknown",
        };

        // Update bounty status to Completed and store consensus data
        let result = sqlx::query(
            r#"
            UPDATE bounties
            SET status = 'Completed',
                metadata = COALESCE(metadata, '{}'::jsonb) || jsonb_build_object(
                    'consensus_verdict', $1::text,
                    'consensus_confidence', $2::text,
                    'total_analyses', $3::text,
                    'consensus_tx_hash', $4::text
                ),
                updated_at = NOW()
            WHERE metadata->>'on_chain_id' = $5
            "#,
        )
        .bind(verdict_str)
        .bind(confidence)
        .bind(total)
        .bind(&event.transaction_hash)
        .bind(chain_bounty_id)
        .execute(&self.db)
        .await;

        match result {
            Ok(r) if r.rows_affected() > 0 => {
                info!(
                    "Updated bounty {} to Completed with consensus {}",
                    chain_bounty_id, verdict_str
                );
            }
            Ok(_) => {
                warn!(
                    "No bounty found for chain id {} to mark Completed",
                    chain_bounty_id
                );
            }
            Err(e) => {
                error!("DB error updating consensus: {}", e);
                return Err(SyncError::DatabaseError(e.to_string()));
            }
        }

        Ok(())
    }

    /// Handle PayoutDistributed (RewardsDistributed) event
    /// Decoded: bounty_id (from topic), raw_data (dynamic arrays not yet decoded)
    async fn handle_payout_distributed(&self, event: &BlockchainEvent) -> Result<(), SyncError> {
        let chain_bounty_id = event
            .data
            .get("bounty_id")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        info!(
            "RewardsDistributed: bounty={}, tx={}",
            chain_bounty_id, event.transaction_hash
        );

        // Look up the internal bounty UUID
        let bounty_uuid: Option<Uuid> =
            sqlx::query_scalar("SELECT id FROM bounties WHERE metadata->>'on_chain_id' = $1")
                .bind(chain_bounty_id)
                .fetch_optional(&self.db)
                .await
                .unwrap_or(None);

        let bounty_id = match bounty_uuid {
            Some(id) => id,
            None => {
                warn!(
                    "No bounty found for chain id {}; skipping payout record",
                    chain_bounty_id
                );
                return Ok(());
            }
        };

        // Create a payout record for the overall distribution event
        // (Individual winner payouts would need raw_data decoded — stored in metadata for later)
        let payout_id = Uuid::new_v4();
        let result = sqlx::query(
            r#"
            INSERT INTO payouts (
                id, bounty_id, recipient, amount, currency, payout_type,
                status, transaction_hash, created_at, processed_at, metadata
            )
            VALUES ($1, $2, 'contract', 0, 'ETH', 'reward', 'Confirmed', $3, NOW(), NOW(), $4)
            "#,
        )
        .bind(payout_id)
        .bind(bounty_id)
        .bind(&event.transaction_hash)
        .bind(&event.data)
        .execute(&self.db)
        .await;

        match result {
            Ok(_) => {
                info!(
                    "Created payout record {} for bounty {}",
                    payout_id, bounty_id
                );
                // Also mark bounty as Paid
                let _ = sqlx::query(
                    "UPDATE bounties SET status = 'Paid', updated_at = NOW() WHERE id = $1",
                )
                .bind(bounty_id)
                .execute(&self.db)
                .await;
            }
            Err(e) => {
                error!("DB error creating payout: {}", e);
                return Err(SyncError::DatabaseError(e.to_string()));
            }
        }

        Ok(())
    }

    /// Handle StakeSlashed event
    async fn handle_stake_slashed(&self, event: &BlockchainEvent) -> Result<(), SyncError> {
        let chain_bounty_id = event
            .data
            .get("bounty_id")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        info!(
            "Processing StakeSlashed event in block {}",
            event.block_number
        );

        // Mark all submissions for this bounty as Slashed
        let result = sqlx::query(
            r#"
            UPDATE submissions SET status = 'Slashed', processed_at = NOW()
            WHERE bounty_id IN (SELECT id FROM bounties WHERE metadata->>'on_chain_id' = $1)
              AND status != 'Confirmed'
            "#,
        )
        .bind(chain_bounty_id)
        .execute(&self.db)
        .await;

        match result {
            Ok(r) => info!(
                "Slashed {} submissions for chain bounty {}",
                r.rows_affected(),
                chain_bounty_id
            ),
            Err(e) => {
                error!("DB error slashing submissions: {}", e);
                return Err(SyncError::DatabaseError(e.to_string()));
            }
        }

        Ok(())
    }

    /// Handle DisputeRaised event
    async fn handle_dispute_raised(&self, event: &BlockchainEvent) -> Result<(), SyncError> {
        let chain_bounty_id = event
            .data
            .get("bounty_id")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        info!(
            "Processing DisputeRaised event in block {}",
            event.block_number
        );

        let result = sqlx::query(
            r#"
            UPDATE bounties
            SET status = 'Disputed',
                metadata = COALESCE(metadata, '{}'::jsonb) || jsonb_build_object(
                    'dispute_tx_hash', $1::text,
                    'dispute_block', $2::bigint
                ),
                updated_at = NOW()
            WHERE metadata->>'on_chain_id' = $3
            "#,
        )
        .bind(&event.transaction_hash)
        .bind(event.block_number as i64)
        .bind(chain_bounty_id)
        .execute(&self.db)
        .await;

        match result {
            Ok(r) => info!(
                "Marked {} bounties as Disputed for chain id {}",
                r.rows_affected(),
                chain_bounty_id
            ),
            Err(e) => {
                error!("DB error creating dispute: {}", e);
                return Err(SyncError::DatabaseError(e.to_string()));
            }
        }

        Ok(())
    }

    /// Handle DisputeResolved event
    async fn handle_dispute_resolved(&self, event: &BlockchainEvent) -> Result<(), SyncError> {
        let chain_bounty_id = event
            .data
            .get("bounty_id")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        info!(
            "Processing DisputeResolved event in block {}",
            event.block_number
        );

        let result = sqlx::query(
            r#"
            UPDATE bounties
            SET status = 'Completed',
                metadata = COALESCE(metadata, '{}'::jsonb) || jsonb_build_object(
                    'dispute_resolved_tx', $1::text,
                    'dispute_resolved_block', $2::bigint
                ),
                updated_at = NOW()
            WHERE metadata->>'on_chain_id' = $3 AND status = 'Disputed'
            "#,
        )
        .bind(&event.transaction_hash)
        .bind(event.block_number as i64)
        .bind(chain_bounty_id)
        .execute(&self.db)
        .await;

        match result {
            Ok(r) => info!(
                "Resolved dispute for {} bounties with chain id {}",
                r.rows_affected(),
                chain_bounty_id
            ),
            Err(e) => {
                error!("DB error resolving dispute: {}", e);
                return Err(SyncError::DatabaseError(e.to_string()));
            }
        }

        Ok(())
    }

    /// Get current block number from blockchain
    async fn get_current_block_number(&self) -> Result<u64, SyncError> {
        let client = self.blockchain.get_client();
        client
            .get_block_number()
            .await
            .map_err(|e| SyncError::BlockchainError(format!("Failed to get block number: {e}")))
    }

    /// Get last synced block from database
    async fn get_last_synced_block_from_db(&self) -> Result<u64, SyncError> {
        // Query sync_state table for the last synced block number
        // If table doesn't exist or no row, return 0 (start from genesis)
        let result = sqlx::query_scalar::<_, i64>(
            "SELECT COALESCE(MAX(block_number), 0) FROM sync_state WHERE service = 'bounty_sync'",
        )
        .fetch_one(&self.db)
        .await;

        match result {
            Ok(block) => Ok(block as u64),
            Err(e) => {
                warn!("Could not read sync state (table may not exist yet): {}", e);
                Ok(0)
            }
        }
    }

    /// Save last synced block to database
    async fn save_last_synced_block(&self, block_number: u64) -> Result<(), SyncError> {
        // Upsert sync state
        let result = sqlx::query(
            r#"
            INSERT INTO sync_state (service, block_number, updated_at)
            VALUES ('bounty_sync', $1, NOW())
            ON CONFLICT (service)
            DO UPDATE SET block_number = $1, updated_at = NOW()
            "#,
        )
        .bind(block_number as i64)
        .execute(&self.db)
        .await;

        match result {
            Ok(_) => {
                info!("Saved sync progress: block {}", block_number);
                Ok(())
            }
            Err(e) => {
                warn!("Could not save sync state (table may not exist yet): {}", e);
                Ok(()) // Non-fatal — sync progress is also tracked in memory
            }
        }
    }

    /// Get current sync status
    pub async fn get_sync_status(&self) -> Result<SyncStatus, SyncError> {
        let last_synced = *self.last_synced_block.read().await;
        let current_block = self.get_current_block_number().await?;

        Ok(SyncStatus {
            last_synced_block: last_synced,
            current_block,
            blocks_behind: current_block.saturating_sub(last_synced),
            is_syncing: current_block > last_synced,
            last_sync_time: Utc::now(),
        })
    }

    /// Force sync from a specific block
    pub async fn force_sync_from_block(&self, block_number: u64) -> Result<(), SyncError> {
        info!("Force syncing from block {}", block_number);
        *self.last_synced_block.write().await = block_number;
        self.save_last_synced_block(block_number).await?;
        Ok(())
    }

    /// Resync recent blocks (useful for reorg handling)
    pub async fn resync_recent_blocks(&self, num_blocks: u64) -> Result<(), SyncError> {
        let last_synced = *self.last_synced_block.read().await;
        let resync_from = last_synced.saturating_sub(num_blocks);

        warn!(
            "Resyncing last {} blocks from block {}",
            num_blocks, resync_from
        );
        self.force_sync_from_block(resync_from).await?;

        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
#[allow(clippy::enum_variant_names)]
pub enum SyncError {
    #[error("Database error: {0}")]
    DatabaseError(String),

    #[error("Blockchain error: {0}")]
    BlockchainError(String),

    #[error("Parse error: {0}")]
    ParseError(String),

    #[error("Event processing error: {0}")]
    EventProcessingError(String),
}

impl From<sqlx::Error> for SyncError {
    fn from(err: sqlx::Error) -> Self {
        SyncError::DatabaseError(err.to_string())
    }
}

impl From<uuid::Error> for SyncError {
    fn from(err: uuid::Error) -> Self {
        SyncError::ParseError(err.to_string())
    }
}

// Canonical event signatures from BountyManager.sol. ThreatVerdict is a uint8.
sol! {
    event BountyCreated(
        uint256 indexed bountyId,
        address indexed creator,
        string artifactHash,
        uint256 reward,
        uint256 deadline
    );
    event AnalysisSubmitted(
        uint256 indexed bountyId,
        address indexed engine,
        uint8 verdict,
        uint256 stake,
        uint256 confidence
    );
    event ConsensusReached(
        uint256 indexed bountyId,
        uint8 consensus,
        uint256 confidenceScore,
        uint256 totalAnalyses
    );
    event RewardsDistributed(
        uint256 indexed bountyId,
        address[] winners,
        uint256[] rewards,
        uint256[] stakes
    );
}

/// Classify a Solidity event log topic to a BlockchainEventType
/// Topic[0] = keccak256(event_signature)
fn classify_event_topic(topic: &B256) -> Option<BlockchainEventType> {
    match *topic {
        BountyCreated::SIGNATURE_HASH => Some(BlockchainEventType::BountyCreated),
        AnalysisSubmitted::SIGNATURE_HASH => Some(BlockchainEventType::SubmissionStaked),
        ConsensusReached::SIGNATURE_HASH => Some(BlockchainEventType::ConsensusReached),
        RewardsDistributed::SIGNATURE_HASH => Some(BlockchainEventType::PayoutDistributed),
        _ => None, // Unknown event
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sync_status_creation() {
        let status = SyncStatus {
            last_synced_block: 100,
            current_block: 150,
            blocks_behind: 50,
            is_syncing: true,
            last_sync_time: Utc::now(),
        };

        assert_eq!(status.blocks_behind, 50);
        assert!(status.is_syncing);
    }

    /// Emit each event from the real contracts and read it back through the
    /// service, and through the database handler when `DATABASE_URL` is set.
    /// See `shared::evm_testing` for how to run it.
    #[tokio::test]
    #[ignore = "needs a local chain and compiled contracts"]
    async fn local_chain_bounty_event_round_trip() {
        use shared::evm_testing::{artifacts_dir, LocalChain, ADMIN_KEY, TOKEN};

        let chain = LocalChain::deploy().await;
        let abi = |name: &str| {
            crate::load_abi(artifacts_dir().join(name).to_str().unwrap()).expect("ABI loads")
        };
        let service = BlockchainService::new(
            &chain.rpc_url,
            ADMIN_KEY,
            chain.chain_id,
            &format!("{:?}", chain.bounty_manager),
            &format!("{:?}", chain.token),
            abi("BountyManager.sol/BountyManager.json"),
            abi("ThreatToken.sol/ThreatToken.json"),
        )
        .await
        .expect("service builds");
        assert!(service.health_check().await);

        let database_url = std::env::var("DATABASE_URL").ok();
        let db = PgPool::connect_lazy(
            database_url
                .as_deref()
                .unwrap_or("postgres://unused@127.0.0.1/unused"),
        )
        .unwrap();
        let service = Arc::new(service);
        let sync = BlockchainSyncService::new(db.clone(), service.clone());

        let creator = format!("{:?}", chain.admin_address);
        let analyst = format!("{:?}", chain.analyst_address);
        let artifact_hash = format!("Qm{}", Uuid::new_v4().simple());
        let bounty_row = Uuid::new_v4();
        let reward = TOKEN * U256::from(100);

        // ── BountyCreated ──
        let created = chain.create_bounty(&artifact_hash, reward).await;
        let events = sync
            .get_block_events(created.block_number.unwrap())
            .await
            .unwrap();
        let event = events
            .iter()
            .find(|e| matches!(e.event_type, BlockchainEventType::BountyCreated))
            .expect("BountyCreated was decoded");
        let bounty_id = event.data["bounty_id"].as_str().unwrap().to_string();
        assert_eq!(event.data["creator"], creator);
        assert_eq!(event.data["artifact_hash"], artifact_hash);
        assert_eq!(event.data["reward"], reward.to_string());
        assert!(event.data["deadline"]
            .as_str()
            .unwrap()
            .parse::<u64>()
            .is_ok());
        assert!(event.data["log_index"].as_str().unwrap().starts_with("0x"));
        assert_eq!(event.data["address"], format!("{:?}", chain.bounty_manager));
        assert_eq!(
            event.transaction_hash,
            format!("{:?}", created.transaction_hash)
        );

        if database_url.is_some() {
            sqlx::query(
                "INSERT INTO bounties (id, creator, title, description, artifact_type, \
                 artifact_hash, reward_amount, currency, min_stake, deadline, status) \
                 VALUES ($1, $2, 'chain test', 'chain test', 'file', $3, 1, 'THREAT', 1, \
                 NOW() + INTERVAL '1 day', 'Pending')",
            )
            .bind(bounty_row)
            .bind(&creator)
            .bind(&artifact_hash)
            .execute(&db)
            .await
            .unwrap();

            sync.process_event(event).await.unwrap();

            let (status, on_chain_id): (String, Option<String>) = sqlx::query_as(
                "SELECT status, metadata->>'on_chain_id' FROM bounties WHERE id = $1",
            )
            .bind(bounty_row)
            .fetch_one(&db)
            .await
            .unwrap();
            assert_eq!(status, "Active", "the event must activate the DB bounty");
            assert_eq!(on_chain_id.as_deref(), Some(bounty_id.as_str()));
        }

        // ── AnalysisSubmitted ──
        let stake = TOKEN * U256::from(25);
        let on_chain_id: U256 = bounty_id.parse().unwrap();
        let submitted = chain.submit_analysis(on_chain_id, 2, 90, stake).await;
        let events = sync
            .get_block_events(submitted.block_number.unwrap())
            .await
            .unwrap();
        let event = events
            .iter()
            .find(|e| matches!(e.event_type, BlockchainEventType::SubmissionStaked))
            .expect("AnalysisSubmitted was decoded");
        assert_eq!(event.data["bounty_id"], bounty_id);
        assert_eq!(event.data["analyst"], analyst);
        assert_eq!(event.data["verdict"], 2);
        assert_eq!(event.data["stake_amount"], stake.to_string());
        assert_eq!(event.data["confidence"], "90");

        // ── ConsensusReached and RewardsDistributed, from the service's own resolve ──
        chain.advance_time(3 * 3600).await;
        let tx_hash = service.resolve_bounty(on_chain_id.to()).await.unwrap();
        assert!(service.verify_transaction(&tx_hash).await.unwrap());
        assert!(matches!(
            service.get_transaction_status(&tx_hash).await.unwrap(),
            crate::services::blockchain::TransactionStatus::Confirmed
        ));

        let block = sync.get_current_block_number().await.unwrap();
        let events = sync.get_block_events(block).await.unwrap();
        let consensus = events
            .iter()
            .find(|e| matches!(e.event_type, BlockchainEventType::ConsensusReached))
            .expect("ConsensusReached was decoded");
        assert_eq!(consensus.data["bounty_id"], bounty_id);
        assert_eq!(consensus.data["consensus_verdict"], 2);
        assert_eq!(consensus.data["total_analyses"], "1");
        let payout = events
            .iter()
            .find(|e| matches!(e.event_type, BlockchainEventType::PayoutDistributed))
            .expect("RewardsDistributed was decoded");
        assert!(payout.data["raw_data"].as_str().unwrap().len() > 2);

        // ── Signed token calls and reads ──
        let recipient = format!("{:?}", chain.recipient_address);
        let bounty_uuid = Uuid::new_v4();
        let stake_tx = service
            .create_stake_transaction(&creator, bounty_uuid, 1_000)
            .await
            .unwrap();
        assert_eq!(stake_tx.from_address, creator);
        assert!(stake_tx.block_number.is_some());
        let before = service.get_balance(&recipient).await.unwrap_or(0);
        let payout_tx = service
            .create_payout_transaction(&recipient, bounty_uuid, 1_000)
            .await
            .unwrap();
        assert!(payout_tx.block_number.is_some());
        assert_eq!(
            service.get_balance(&recipient).await.unwrap(),
            before + 1_000
        );

        assert_eq!(service.get_pending_withdrawal(&recipient).await.unwrap(), 0);
        // Wei amounts above u64::MAX are reported rather than a panic.
        assert!(service.get_balance(&creator).await.is_err());

        if database_url.is_some() {
            sqlx::query("DELETE FROM bounties WHERE id = $1")
                .bind(bounty_row)
                .execute(&db)
                .await
                .unwrap();
        }
    }

    #[test]
    fn event_signatures_match_the_contract() {
        assert_eq!(
            BountyCreated::SIGNATURE,
            "BountyCreated(uint256,address,string,uint256,uint256)"
        );
        assert_eq!(
            AnalysisSubmitted::SIGNATURE,
            "AnalysisSubmitted(uint256,address,uint8,uint256,uint256)"
        );
        assert_eq!(
            ConsensusReached::SIGNATURE,
            "ConsensusReached(uint256,uint8,uint256,uint256)"
        );
        assert_eq!(
            RewardsDistributed::SIGNATURE,
            "RewardsDistributed(uint256,address[],uint256[],uint256[])"
        );
    }
}
