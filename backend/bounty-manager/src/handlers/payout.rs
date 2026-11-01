// backend/bounty-manager/src/handlers/payout_handler.rs

use super::bounty_crud::PaginationParams;
use crate::handlers::bounty_crud::{BountyManagerState, ThreatVerdict};
use crate::handlers::submission::{Submission, SubmissionStatus};
use crate::models::{BountyModel, PayoutModel, ReputationModel, SubmissionModel};
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Json,
    Extension,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use shared::types::ApiResponse;
use std::collections::HashMap;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayoutInfo {
    pub id: Uuid,
    pub bounty_id: Uuid,
    pub total_reward_pool: u64,
    pub consensus_verdict: ThreatVerdict,
    pub consensus_confidence: f32,
    pub total_correct_submissions: u32,
    pub total_incorrect_submissions: u32,
    pub reward_distributions: Vec<RewardDistribution>,
    pub slashed_stakes: Vec<SlashedStake>,
    pub status: PayoutStatus,
    pub processing_started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub blockchain_transactions: Vec<PayoutTransaction>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PayoutStatus {
    Calculating,    // Determining consensus and rewards
    Processing,     // Executing blockchain transactions
    Completed,      // All payouts processed
    Failed,         // Error in processing
    PartialFailure, // Some transactions failed
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RewardDistribution {
    pub engine_id: String,
    pub submission_id: Uuid,
    pub base_reward: u64,           // Share of bounty reward
    pub accuracy_bonus: u64,        // Bonus for high confidence in correct verdict
    pub reputation_multiplier: f32, // Reputation-based multiplier
    pub stake_return: u64,          // Original stake returned
    pub total_payout: u64,          // Total amount to be paid
    pub transaction_hash: Option<String>,
    pub processed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlashedStake {
    pub engine_id: String,
    pub submission_id: Uuid,
    pub stake_amount: u64,
    pub slashing_reason: SlashingReason,
    pub redistributed_amount: u64, // Amount redistributed to correct submissions
    pub transaction_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SlashingReason {
    IncorrectVerdict,   // Wrong consensus verdict
    LowConfidence,      // High confidence in wrong verdict
    MaliciousActivity,  // Detected coordinated false submissions
    TechnicalViolation, // Violated submission rules
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayoutTransaction {
    pub transaction_hash: String,
    pub transaction_type: TransactionType,
    pub recipient: String,
    pub amount: u64,
    pub gas_used: Option<u64>,
    pub status: TransactionStatus,
    pub block_number: Option<u64>,
    pub processed_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TransactionType {
    RewardPayout,
    StakeReturn,
    StakeSlashing,
    BountyRefund,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TransactionStatus {
    Pending,
    Confirmed,
    Failed,
}

#[derive(Debug, Serialize)]
pub struct PayoutSummary {
    pub total_rewards_distributed: u64,
    pub total_stakes_slashed: u64,
    pub successful_engines: u32,
    pub slashed_engines: u32,
    pub consensus_accuracy: f32,
    pub average_confidence: f32,
}

#[derive(Debug, Deserialize)]
pub struct PayoutFilters {
    pub status: Option<PayoutStatus>,
    pub bounty_id: Option<Uuid>,
    pub engine_id: Option<String>,
    pub min_amount: Option<u64>,
}

// Handler implementations

pub async fn process_bounty_completion(
    State(state): State<BountyManagerState>,
    Extension(caller_id): Extension<String>, // From auth middleware
    Path(bounty_id): Path<Uuid>,
) -> Result<Json<ApiResponse<PayoutInfo>>, StatusCode> {
    // Fetch bounty from database
    let bounty = BountyModel::find_by_id(&state.db, bounty_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to fetch bounty {}: {}", bounty_id, e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .ok_or_else(|| {
            tracing::warn!("Bounty {} not found for payout processing", bounty_id);
            StatusCode::NOT_FOUND
        })?;

    // Only the bounty creator may trigger payout processing
    if bounty.creator != caller_id {
        tracing::warn!(
            "Caller {} denied payout on bounty {} (creator: {})",
            caller_id,
            bounty_id,
            bounty.creator
        );
        return Err(StatusCode::FORBIDDEN);
    }

    // Guard against double-processing: payout only allowed on Active/InProgress bounties
    if bounty.status == "Completed" || bounty.status == "Cancelled" {
        tracing::warn!(
            "Bounty {} already {} — cannot process payout",
            bounty_id,
            bounty.status
        );
        return Err(StatusCode::CONFLICT);
    }

    // Fetch all submissions for this bounty
    let db_submissions = SubmissionModel::find_by_bounty(&state.db, bounty_id)
        .await
        .map_err(|e| {
            tracing::error!(
                "Failed to fetch submissions for bounty {}: {}",
                bounty_id,
                e
            );
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    if db_submissions.is_empty() {
        tracing::warn!(
            "Bounty {} has no submissions — cannot process payout",
            bounty_id
        );
        return Err(StatusCode::BAD_REQUEST);
    }

    // Build reputation weights from the database
    let mut reputation_weights: HashMap<String, f32> = HashMap::new();
    for sub in &db_submissions {
        if !reputation_weights.contains_key(&sub.engine_id) {
            let weight = ReputationModel::find_by_id(&state.db, &sub.engine_id)
                .await
                .ok()
                .flatten()
                .map(|r| r.reputation_score.max(0.1)) // Floor at 0.1
                .unwrap_or(1.0);
            reputation_weights.insert(sub.engine_id.clone(), weight);
        }
    }

    // Convert DB submissions to handler Submission for consensus calculation
    let handler_submissions: Vec<Submission> = db_submissions
        .iter()
        .map(|s| db_sub_to_submission(s.clone()))
        .collect();

    // Calculate consensus based on weighted voting
    let (consensus_verdict, consensus_confidence) =
        calculate_weighted_consensus(&handler_submissions, &reputation_weights);

    // Determine which submissions agree/disagree with consensus
    let consensus_verdict_str = format!("{consensus_verdict:?}");
    let correct_submissions: Vec<Submission> = handler_submissions
        .iter()
        .filter(|s| {
            format!("{:?}", s.verdict) == consensus_verdict_str
                && s.status == SubmissionStatus::Active
        })
        .cloned()
        .collect();

    let incorrect_submissions: Vec<Submission> = handler_submissions
        .iter()
        .filter(|s| {
            format!("{:?}", s.verdict) != consensus_verdict_str
                && s.status == SubmissionStatus::Active
        })
        .cloned()
        .collect();

    // Calculate reward distribution
    let total_reward = bounty.reward_amount as u64;
    let reward_distributions =
        calculate_reward_distribution(total_reward, &correct_submissions, &reputation_weights);

    // Calculate slashed stakes for incorrect submissions
    let slashed_stakes: Vec<SlashedStake> = incorrect_submissions
        .iter()
        .map(|sub| {
            let slash_percentage = if sub.confidence > 0.8 { 0.5 } else { 0.3 };
            let slashed = (sub.stake_amount as f32 * slash_percentage) as u64;
            SlashedStake {
                engine_id: sub.engine_id.clone(),
                submission_id: sub.id,
                stake_amount: sub.stake_amount,
                slashing_reason: SlashingReason::IncorrectVerdict,
                redistributed_amount: (slashed as f32 * 0.8) as u64, // 80% redistributed
                transaction_hash: None,
            }
        })
        .collect();

    let payout_id = Uuid::new_v4();
    let now = Utc::now();

    let payout_info = PayoutInfo {
        id: payout_id,
        bounty_id,
        total_reward_pool: total_reward,
        consensus_verdict,
        consensus_confidence,
        total_correct_submissions: correct_submissions.len() as u32,
        total_incorrect_submissions: incorrect_submissions.len() as u32,
        reward_distributions: reward_distributions.clone(),
        slashed_stakes: slashed_stakes.clone(),
        status: PayoutStatus::Calculating,
        processing_started_at: now,
        completed_at: None,
        blockchain_transactions: vec![],
    };

    // Persist individual payout records for each reward distribution
    for dist in &reward_distributions {
        let payout_record = PayoutModel {
            id: Uuid::new_v4(),
            bounty_id,
            submission_id: Some(dist.submission_id),
            recipient: dist.engine_id.clone(),
            amount: dist.total_payout as i64,
            currency: bounty.currency.clone(),
            payout_type: "RewardPayout".to_string(),
            status: "Pending".to_string(),
            transaction_hash: None,
            created_at: now,
            processed_at: None,
            metadata: Some(serde_json::json!({
                "base_reward": dist.base_reward,
                "accuracy_bonus": dist.accuracy_bonus,
                "reputation_multiplier": dist.reputation_multiplier,
                "stake_return": dist.stake_return,
                "payout_session_id": payout_id,
            })),
        };
        if let Err(e) = PayoutModel::create(&state.db, &payout_record).await {
            tracing::error!("Failed to save payout record for {}: {}", dist.engine_id, e);
        }
    }

    // Persist slashing records
    for slash in &slashed_stakes {
        let slash_record = PayoutModel {
            id: Uuid::new_v4(),
            bounty_id,
            submission_id: Some(slash.submission_id),
            recipient: slash.engine_id.clone(),
            amount: -(slash.stake_amount as i64), // Negative for slashing
            currency: bounty.currency.clone(),
            payout_type: "StakeSlashing".to_string(),
            status: "Pending".to_string(),
            transaction_hash: None,
            created_at: now,
            processed_at: None,
            metadata: Some(serde_json::json!({
                "slashing_reason": format!("{:?}", slash.slashing_reason),
                "redistributed_amount": slash.redistributed_amount,
                "payout_session_id": payout_id,
            })),
        };
        if let Err(e) = PayoutModel::create(&state.db, &slash_record).await {
            tracing::error!(
                "Failed to save slashing record for {}: {}",
                slash.engine_id,
                e
            );
        }
    }

    // Update bounty status to Completed
    if let Err(e) = BountyModel::update_status(&state.db, bounty_id, "Completed").await {
        tracing::error!("Failed to update bounty status to Completed: {}", e);
    }

    tracing::info!(
        bounty_id = %bounty_id,
        payout_id = %payout_id,
        consensus = ?payout_info.consensus_verdict,
        confidence = payout_info.consensus_confidence,
        correct = payout_info.total_correct_submissions,
        incorrect = payout_info.total_incorrect_submissions,
        "Bounty completion processed"
    );

    Ok(Json(ApiResponse::success(payout_info)))
}

pub async fn distribute_rewards(
    State(state): State<BountyManagerState>,
    Extension(caller_id): Extension<String>, // From auth middleware
    Path(payout_id): Path<Uuid>,
) -> Result<Json<ApiResponse<PayoutInfo>>, StatusCode> {
    // Fetch pending payout records for this session
    let pending_payouts = PayoutModel::get_pending(&state.db).await.map_err(|e| {
        tracing::error!("Failed to fetch pending payouts: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // Filter to only records belonging to this payout session
    let session_payouts: Vec<PayoutModel> = pending_payouts
        .into_iter()
        .filter(|p| {
            p.metadata
                .as_ref()
                .and_then(|m| m.get("payout_session_id"))
                .and_then(|v| v.as_str())
                .map(|s| s == payout_id.to_string())
                .unwrap_or(false)
        })
        .collect();

    if session_payouts.is_empty() {
        return Err(StatusCode::NOT_FOUND);
    }

    // Verify caller is the bounty creator for these payouts
    let bounty_id = session_payouts[0].bounty_id;
    let bounty = BountyModel::find_by_id(&state.db, bounty_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to fetch bounty {}: {}", bounty_id, e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .ok_or(StatusCode::NOT_FOUND)?;

    if bounty.creator != caller_id {
        tracing::warn!(
            "Caller {} denied reward distribution on bounty {} (creator: {})",
            caller_id,
            bounty_id,
            bounty.creator
        );
        return Err(StatusCode::FORBIDDEN);
    }

    let mut reward_distributions = Vec::new();
    let mut blockchain_transactions = Vec::new();
    let mut had_failure = false;

    // On-chain client, when configured. `None` in dev/CI or when the chain env
    // is unset — in that case we record the reward off-chain and leave it to
    // settle once the chain is wired (graceful degradation, never a crash).
    let chain = state.blockchain.as_ref();

    for payout in &session_payouts {
        if payout.payout_type == "StakeSlashing" {
            continue; // Handle slashing separately
        }

        let amount = payout.amount as u64;
        let is_correct = payout.amount > 0;

        // Settle the reward on-chain: ThreatToken.transfer(recipient, amount).
        // Zero-amount rewards and the blockchain-disabled path skip the transfer
        // and are recorded off-chain as pending settlement.
        //
        // NOTE: this awaits the transaction receipt inline, so a slow chain slows
        // the request. Acceptable for the operator-triggered distribute endpoint;
        // move to a background settlement queue if this becomes hot.
        let settlement: Result<(String, TransactionStatus, Option<u64>), String> =
            match (chain, amount) {
                (Some(bc), amt) if amt > 0 => bc
                    .create_payout_transaction(&payout.recipient, bounty_id, amt)
                    .await
                    .map(|tx| {
                        (
                            tx.transaction_hash,
                            TransactionStatus::Confirmed,
                            tx.block_number,
                        )
                    })
                    .map_err(|e| e.to_string()),
                _ => Ok((
                    format!("offchain_{}", payout.id),
                    TransactionStatus::Pending,
                    None,
                )),
            };

        let (tx_hash, tx_status, block_number) = match settlement {
            Ok(v) => v,
            Err(e) => {
                // On-chain transfer failed: record the failure and leave the
                // payout un-settled for retry. Do NOT credit reputation or flip
                // the submission — nothing actually moved.
                had_failure = true;
                tracing::error!(
                    payout_id = %payout.id,
                    recipient = %payout.recipient,
                    amount,
                    "on-chain reward transfer FAILED: {e}"
                );
                PayoutModel::update_status(&state.db, payout.id, "Failed", None)
                    .await
                    .map_err(|e| {
                        tracing::error!("Failed to update payout status: {}", e);
                        StatusCode::INTERNAL_SERVER_ERROR
                    })?;
                reward_distributions.push(RewardDistribution {
                    engine_id: payout.recipient.clone(),
                    submission_id: payout.submission_id.unwrap_or_else(Uuid::nil),
                    base_reward: amount,
                    accuracy_bonus: 0,
                    reputation_multiplier: 1.0,
                    stake_return: 0,
                    total_payout: amount,
                    transaction_hash: None,
                    processed: false,
                });
                blockchain_transactions.push(PayoutTransaction {
                    transaction_hash: format!("failed_{}", payout.id),
                    transaction_type: TransactionType::RewardPayout,
                    recipient: payout.recipient.clone(),
                    amount,
                    gas_used: None,
                    status: TransactionStatus::Failed,
                    block_number: None,
                    processed_at: Utc::now(),
                });
                continue;
            }
        };

        let settled = matches!(tx_status, TransactionStatus::Confirmed);
        if settled {
            tracing::info!(
                payout_id = %payout.id, recipient = %payout.recipient, amount,
                tx = %tx_hash, "on-chain reward transfer confirmed"
            );
        } else {
            tracing::warn!(
                payout_id = %payout.id, recipient = %payout.recipient, amount,
                "blockchain disabled or zero reward — recorded off-chain, on-chain settlement pending"
            );
        }

        // Persist the payout: the real tx hash + Processed once settled on-chain,
        // otherwise PendingOnChain with no hash yet.
        let db_status = if settled {
            "Processed"
        } else {
            "PendingOnChain"
        };
        PayoutModel::update_status(
            &state.db,
            payout.id,
            db_status,
            if settled {
                Some(tx_hash.as_str())
            } else {
                None
            },
        )
        .await
        .map_err(|e| {
            tracing::error!("Failed to update payout status: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

        // Update engine reputation: increment correct submission
        if let Err(e) =
            ReputationModel::increment_submission(&state.db, &payout.recipient, is_correct).await
        {
            tracing::error!(
                "Failed to update reputation for {}: {}",
                payout.recipient,
                e
            );
        }

        // Update submission status to Correct
        if let Some(sub_id) = payout.submission_id {
            if let Err(e) = SubmissionModel::update_status(&state.db, sub_id, "Correct").await {
                tracing::error!("Failed to update submission {} status: {}", sub_id, e);
            }
        }

        reward_distributions.push(RewardDistribution {
            engine_id: payout.recipient.clone(),
            submission_id: payout.submission_id.unwrap_or_else(Uuid::nil),
            base_reward: amount,
            accuracy_bonus: 0,
            reputation_multiplier: 1.0,
            stake_return: 0,
            total_payout: amount,
            transaction_hash: Some(tx_hash.clone()),
            processed: true,
        });

        blockchain_transactions.push(PayoutTransaction {
            transaction_hash: tx_hash,
            transaction_type: TransactionType::RewardPayout,
            recipient: payout.recipient.clone(),
            amount,
            gas_used: None,
            status: tx_status,
            block_number,
            processed_at: Utc::now(),
        });
    }

    // bounty_id already available from auth check above

    let processed_count = reward_distributions.iter().filter(|r| r.processed).count() as u32;
    let payout_info = PayoutInfo {
        id: payout_id,
        bounty_id,
        total_reward_pool: reward_distributions
            .iter()
            .filter(|r| r.processed)
            .map(|r| r.total_payout)
            .sum(),
        consensus_verdict: ThreatVerdict::Unknown, // Already determined in process_bounty_completion
        consensus_confidence: 0.0,
        total_correct_submissions: processed_count,
        total_incorrect_submissions: 0,
        reward_distributions,
        slashed_stakes: vec![],
        status: if had_failure {
            PayoutStatus::PartialFailure
        } else {
            PayoutStatus::Completed
        },
        processing_started_at: Utc::now(),
        completed_at: Some(Utc::now()),
        blockchain_transactions,
    };

    tracing::info!(payout_id = %payout_id, "Reward distribution completed");

    Ok(Json(ApiResponse::success(payout_info)))
}

pub async fn handle_stake_slashing(
    State(state): State<BountyManagerState>,
    Extension(caller_id): Extension<String>, // From auth middleware
    Path(payout_id): Path<Uuid>,
) -> Result<Json<ApiResponse<Vec<SlashedStake>>>, StatusCode> {
    // Fetch slashing records for this payout session from DB
    let pending_payouts = PayoutModel::get_pending(&state.db).await.map_err(|e| {
        tracing::error!("Failed to fetch pending slashing records: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let slashing_records: Vec<PayoutModel> = pending_payouts
        .into_iter()
        .filter(|p| {
            p.payout_type == "StakeSlashing"
                && p.metadata
                    .as_ref()
                    .and_then(|m| m.get("payout_session_id"))
                    .and_then(|v| v.as_str())
                    .map(|s| s == payout_id.to_string())
                    .unwrap_or(false)
        })
        .collect();

    if slashing_records.is_empty() {
        return Err(StatusCode::NOT_FOUND);
    }

    // Verify caller is the bounty creator for these slashing records
    let bounty_id = slashing_records[0].bounty_id;
    let bounty = BountyModel::find_by_id(&state.db, bounty_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to fetch bounty {}: {}", bounty_id, e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .ok_or(StatusCode::NOT_FOUND)?;

    if bounty.creator != caller_id {
        tracing::warn!(
            "Caller {} denied stake slashing on bounty {} (creator: {})",
            caller_id,
            bounty_id,
            bounty.creator
        );
        return Err(StatusCode::FORBIDDEN);
    }

    let mut slashed_stakes = Vec::new();

    for record in &slashing_records {
        // Blockchain slashing transaction (not yet connected)
        tracing::warn!(
            recipient = %record.recipient,
            amount = record.amount.abs(),
            "Blockchain stake slashing not yet implemented — recorded off-chain"
        );

        // Mark as processed
        PayoutModel::update_status(&state.db, record.id, "Processed", None)
            .await
            .map_err(|e| {
                tracing::error!("Failed to update slashing status: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

        // Update reputation negatively
        if let Err(e) =
            ReputationModel::increment_submission(&state.db, &record.recipient, false).await
        {
            tracing::error!(
                "Failed to update reputation for slashed engine {}: {}",
                record.recipient,
                e
            );
        }

        // Update submission status to Incorrect
        if let Some(sub_id) = record.submission_id {
            if let Err(e) = SubmissionModel::update_status(&state.db, sub_id, "Incorrect").await {
                tracing::error!("Failed to update submission {} status: {}", sub_id, e);
            }
        }

        let redistributed = record
            .metadata
            .as_ref()
            .and_then(|m| m.get("redistributed_amount"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0);

        slashed_stakes.push(SlashedStake {
            engine_id: record.recipient.clone(),
            submission_id: record.submission_id.unwrap_or_else(Uuid::nil),
            stake_amount: record.amount.unsigned_abs(),
            slashing_reason: SlashingReason::IncorrectVerdict,
            redistributed_amount: redistributed,
            transaction_hash: None,
        });
    }

    tracing::info!(payout_id = %payout_id, slashed = slashed_stakes.len(), "Stake slashing processed");

    Ok(Json(ApiResponse::success(slashed_stakes)))
}

pub async fn get_payout_history(
    State(state): State<BountyManagerState>,
    Query(_pagination): Query<PaginationParams>,
    Query(filters): Query<PayoutFilters>,
    Extension(engine_id): Extension<Option<String>>, // Optional - admin vs engine view
) -> Result<Json<ApiResponse<Vec<PayoutInfo>>>, StatusCode> {
    // Fetch from database, filtering by permissions
    let db_payouts = if let Some(ref bounty_id) = filters.bounty_id {
        PayoutModel::find_by_bounty(&state.db, *bounty_id).await
    } else if let Some(ref eid) = engine_id {
        // Engine can only see their own payouts
        PayoutModel::find_by_recipient(&state.db, eid).await
    } else if let Some(ref eid) = filters.engine_id {
        PayoutModel::find_by_recipient(&state.db, eid).await
    } else {
        // Admin view: return pending payouts as a fallback
        PayoutModel::get_pending(&state.db).await
    };

    let records = db_payouts.map_err(|e| {
        tracing::error!("Failed to fetch payout history: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // Group payouts by bounty_id into PayoutInfo summaries
    let mut grouped: HashMap<Uuid, Vec<PayoutModel>> = HashMap::new();
    for record in records {
        grouped.entry(record.bounty_id).or_default().push(record);
    }

    let payouts: Vec<PayoutInfo> = grouped
        .into_iter()
        .map(|(bounty_id, records)| {
            let reward_distributions: Vec<RewardDistribution> = records
                .iter()
                .filter(|r| r.payout_type == "RewardPayout")
                .map(|r| RewardDistribution {
                    engine_id: r.recipient.clone(),
                    submission_id: r.submission_id.unwrap_or_else(Uuid::nil),
                    base_reward: r.amount as u64,
                    accuracy_bonus: 0,
                    reputation_multiplier: 1.0,
                    stake_return: 0,
                    total_payout: r.amount as u64,
                    transaction_hash: r.transaction_hash.clone(),
                    processed: r.status == "Processed",
                })
                .collect();

            PayoutInfo {
                id: records.first().map(|r| r.id).unwrap_or_else(Uuid::nil),
                bounty_id,
                total_reward_pool: reward_distributions.iter().map(|r| r.total_payout).sum(),
                consensus_verdict: ThreatVerdict::Unknown,
                consensus_confidence: 0.0,
                total_correct_submissions: reward_distributions.len() as u32,
                total_incorrect_submissions: 0,
                reward_distributions,
                slashed_stakes: vec![],
                status: if records.iter().all(|r| r.status == "Processed") {
                    PayoutStatus::Completed
                } else {
                    PayoutStatus::Processing
                },
                processing_started_at: records
                    .first()
                    .map(|r| r.created_at)
                    .unwrap_or_else(Utc::now),
                completed_at: records.last().and_then(|r| r.processed_at),
                blockchain_transactions: vec![],
            }
        })
        .collect();

    Ok(Json(ApiResponse::success(payouts)))
}

pub async fn get_payout_summary(
    State(state): State<BountyManagerState>,
    Path(bounty_id): Path<Uuid>,
) -> Result<Json<ApiResponse<PayoutSummary>>, StatusCode> {
    // Aggregate real data from the payouts table for this bounty
    let payouts = PayoutModel::find_by_bounty(&state.db, bounty_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to fetch payouts for bounty {}: {}", bounty_id, e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let total_rewards_distributed: u64 = payouts
        .iter()
        .filter(|p| p.payout_type == "RewardPayout" && p.amount > 0)
        .map(|p| p.amount as u64)
        .sum();

    let total_stakes_slashed: u64 = payouts
        .iter()
        .filter(|p| p.payout_type == "StakeSlashing")
        .map(|p| p.amount.unsigned_abs())
        .sum();

    let successful_engines = payouts
        .iter()
        .filter(|p| p.payout_type == "RewardPayout")
        .count() as u32;

    let slashed_engines = payouts
        .iter()
        .filter(|p| p.payout_type == "StakeSlashing")
        .count() as u32;

    // Fetch submissions to calculate averages
    let submissions = SubmissionModel::find_by_bounty(&state.db, bounty_id)
        .await
        .unwrap_or_default();

    let avg_confidence = if submissions.is_empty() {
        0.0
    } else {
        submissions.iter().map(|s| s.confidence).sum::<f32>() / submissions.len() as f32
    };

    let summary = PayoutSummary {
        total_rewards_distributed,
        total_stakes_slashed,
        successful_engines,
        slashed_engines,
        consensus_accuracy: avg_confidence, // Approximation
        average_confidence: avg_confidence,
    };

    Ok(Json(ApiResponse::success(summary)))
}

// Internal helper functions for consensus calculation
pub fn calculate_weighted_consensus(
    submissions: &[Submission],
    reputation_weights: &HashMap<String, f32>,
) -> (ThreatVerdict, f32) {
    let mut verdict_scores: HashMap<String, f32> = HashMap::new();
    let mut total_weight = 0.0;

    for submission in submissions {
        if submission.status != SubmissionStatus::Active {
            continue;
        }

        let reputation_weight = reputation_weights
            .get(&submission.engine_id)
            .unwrap_or(&1.0);
        let stake_weight = submission.stake_amount as f32 / 100000.0; // Normalize stake
        let confidence_weight = submission.confidence;

        let combined_weight = reputation_weight * stake_weight * confidence_weight;

        let verdict_key = format!("{:?}", submission.verdict);
        *verdict_scores.entry(verdict_key).or_insert(0.0) += combined_weight;
        total_weight += combined_weight;
    }

    // Find consensus verdict
    let unknown_str = "Unknown".to_string();
    let (consensus_verdict_str, consensus_score) = verdict_scores
        .iter()
        .max_by(|a, b| a.1.partial_cmp(b.1).unwrap())
        .unwrap_or((&unknown_str, &0.0));

    let consensus_confidence = if total_weight > 0.0 {
        consensus_score / total_weight
    } else {
        0.0
    };

    let consensus_verdict = match consensus_verdict_str.as_str() {
        "Malicious" => ThreatVerdict::Malicious,
        "Benign" => ThreatVerdict::Benign,
        "Suspicious" => ThreatVerdict::Suspicious,
        _ => ThreatVerdict::Unknown,
    };

    (consensus_verdict, consensus_confidence)
}

pub fn calculate_reward_distribution(
    total_reward: u64,
    correct_submissions: &[Submission],
    reputation_weights: &HashMap<String, f32>,
) -> Vec<RewardDistribution> {
    let mut distributions = Vec::new();
    let total_stake: u64 = correct_submissions.iter().map(|s| s.stake_amount).sum();

    if total_stake == 0 {
        return distributions;
    }

    for submission in correct_submissions {
        let reputation_multiplier = reputation_weights
            .get(&submission.engine_id)
            .unwrap_or(&1.0);

        // Base reward proportional to stake
        let stake_proportion = submission.stake_amount as f32 / total_stake as f32;
        let base_reward = (total_reward as f32 * stake_proportion) as u64;

        // Accuracy bonus for high confidence
        let accuracy_bonus = if submission.confidence > 0.9 {
            (base_reward as f32 * 0.2) as u64
        } else if submission.confidence > 0.8 {
            (base_reward as f32 * 0.1) as u64
        } else {
            0
        };

        let total_payout = ((base_reward + accuracy_bonus) as f32 * reputation_multiplier) as u64
            + submission.stake_amount;

        distributions.push(RewardDistribution {
            engine_id: submission.engine_id.clone(),
            submission_id: submission.id,
            base_reward,
            accuracy_bonus,
            reputation_multiplier: *reputation_multiplier,
            stake_return: submission.stake_amount,
            total_payout,
            transaction_hash: None,
            processed: false,
        });
    }

    distributions
}

// ── Conversion helper ────────────────────────────────────────

fn db_sub_to_submission(s: SubmissionModel) -> Submission {
    use crate::handlers::submission::*;
    let verdict = match s.verdict.as_str() {
        "Malicious" => ThreatVerdict::Malicious,
        "Benign" => ThreatVerdict::Benign,
        "Suspicious" => ThreatVerdict::Suspicious,
        _ => ThreatVerdict::Unknown,
    };
    let engine_type = match s.engine_type.as_str() {
        "Human" => EngineType::Human,
        "Hybrid" => EngineType::Hybrid,
        _ => EngineType::Automated,
    };
    let status = match s.status.as_str() {
        "Active" => SubmissionStatus::Active,
        "Correct" => SubmissionStatus::Correct,
        "Incorrect" => SubmissionStatus::Incorrect,
        "Invalid" => SubmissionStatus::Invalid,
        _ => SubmissionStatus::Pending,
    };
    let analysis_details: AnalysisDetails = serde_json::from_value(s.analysis_details.clone())
        .unwrap_or_else(|_| AnalysisDetails {
            malware_families: Vec::new(),
            threat_indicators: Vec::new(),
            behavioral_analysis: None,
            static_analysis: None,
            network_analysis: None,
            metadata: HashMap::new(),
        });

    Submission {
        id: s.id,
        bounty_id: s.bounty_id,
        engine_id: s.engine_id,
        engine_type,
        verdict,
        confidence: s.confidence,
        stake_amount: s.stake_amount as u64,
        analysis_details,
        status,
        transaction_hash: s.transaction_hash,
        submitted_at: s.submitted_at,
        processed_at: s.processed_at,
        accuracy_score: s.accuracy_score,
    }
}
