//! Copies on-chain bounties into the `chain_bounties` table so a scan report
//! can list the bounties posted on its file or URL.
//!
//! It reads the BountyManager contract's state rather than its event logs:
//! - every cycle it reads `getTotalBounties()` and fetches each new bounty
//!   with `getBounty(id)`, so it backfills from bounty #1 on its own;
//! - it re-reads bounties that are still open until they settle. Cancelling
//!   a bounty nobody analyzed emits no bounty event, so logs alone would
//!   leave it "open" forever.
//!
//! This keeps clear of public RPCs' limits on log queries and of chain
//! reorganisations: a re-read always reflects the chain as it is now.
//!
//! It runs when the contracts are configured (see `handlers::chain`), uses
//! the server's own RPC (`BLOCKCHAIN_RPC_URL`), and only reads: it never
//! signs or sends anything.

use std::time::Duration;

use chrono::{DateTime, TimeZone, Utc};
use ethers::abi::{self, ParamType, Token};
use ethers::providers::{Http, Middleware, Provider};
use ethers::types::{
    transaction::eip2718::TypedTransaction, Address, Bytes, TransactionRequest, U256,
};
use ethers::utils::keccak256;
use sqlx::PgPool;

use crate::handlers::chain::{chain_info, server_rpc_url};
use crate::AppState;

/// New bounties fetched per cycle (the rest follow on the next cycles).
const NEW_PER_CYCLE: u64 = 100;
/// Open bounties re-read per cycle, stalest first.
const REFRESH_PER_CYCLE: i64 = 50;

#[derive(Debug, Clone, PartialEq)]
pub struct IndexedBounty {
    pub id: u64,
    pub creator: String,
    pub artifact_hash: String,
    pub artifact_type: String,
    pub reward: U256,
    pub deadline: u64,
    pub description: String,
    pub status: u8,
    pub consensus_verdict: u8,
    pub total_staked: U256,
    pub analysis_count: u64,
    pub created_at: u64,
}

fn selector(signature: &str) -> [u8; 4] {
    let h = keccak256(signature.as_bytes());
    [h[0], h[1], h[2], h[3]]
}

pub fn get_total_bounties_call() -> Bytes {
    selector("getTotalBounties()").to_vec().into()
}

pub fn get_bounty_call(id: u64) -> Bytes {
    let mut data = selector("getBounty(uint256)").to_vec();
    data.extend(abi::encode(&[Token::Uint(U256::from(id))]));
    data.into()
}

pub fn decode_total(raw: &[u8]) -> Result<u64, String> {
    let tokens = abi::decode(&[ParamType::Uint(256)], raw).map_err(|e| e.to_string())?;
    match tokens.as_slice() {
        [Token::Uint(n)] if *n <= U256::from(i64::MAX as u64) => Ok(n.as_u64()),
        _ => Err("getTotalBounties returned something unexpected".into()),
    }
}

/// Decodes `getBounty`'s `Bounty` struct.
pub fn decode_bounty(raw: &[u8]) -> Result<IndexedBounty, String> {
    let bounty = ParamType::Tuple(vec![
        ParamType::Uint(256), // id
        ParamType::Address,   // creator
        ParamType::String,    // artifactHash
        ParamType::String,    // artifactType
        ParamType::Uint(256), // rewardAmount
        ParamType::Uint(256), // deadline
        ParamType::String,    // description
        ParamType::Uint(8),   // status
        ParamType::Uint(8),   // consensusVerdict
        ParamType::Uint(256), // totalStaked
        ParamType::Uint(256), // analysisCount
        ParamType::Uint(256), // createdAt
    ]);
    let mut tokens = abi::decode(&[bounty], raw).map_err(|e| e.to_string())?;
    let Some(Token::Tuple(f)) = tokens.pop() else {
        return Err("getBounty returned something unexpected".into());
    };
    let uint = |i: usize| match &f[i] {
        Token::Uint(n) => Ok(*n),
        _ => Err(format!("getBounty field {i} isn't a number")),
    };
    let small = |i: usize| -> Result<u64, String> {
        let n = uint(i)?;
        if n > U256::from(i64::MAX as u64) {
            return Err(format!("getBounty field {i} is out of range"));
        }
        Ok(n.as_u64())
    };
    let text = |i: usize| match &f[i] {
        Token::String(s) => Ok(s.clone()),
        _ => Err(format!("getBounty field {i} isn't text")),
    };
    let creator = match &f[1] {
        Token::Address(a) => format!("{a:#x}"),
        _ => return Err("getBounty creator isn't an address".into()),
    };
    Ok(IndexedBounty {
        id: small(0)?,
        creator,
        artifact_hash: text(2)?,
        artifact_type: text(3)?,
        reward: uint(4)?,
        deadline: small(5)?,
        description: text(6)?,
        status: small(7)? as u8,
        consensus_verdict: small(8)? as u8,
        total_staked: uint(9)?,
        analysis_count: small(10)?,
        created_at: small(11)?,
    })
}

/// How a bounty's artifact is looked up: a SHA-256 or URL, trimmed and lowercased.
pub fn artifact_key(artifact: &str) -> String {
    artifact.trim().to_lowercase()
}

fn timestamp(secs: u64) -> DateTime<Utc> {
    Utc.timestamp_opt(secs.min(i64::MAX as u64) as i64, 0)
        .single()
        .unwrap_or_else(Utc::now)
}

struct Indexer {
    provider: Provider<Http>,
    db: PgPool,
    chain_id: i64,
    contract: Address,
    contract_key: String,
}

impl Indexer {
    async fn call(&self, data: Bytes) -> Result<Bytes, String> {
        let tx: TypedTransaction = TransactionRequest::new()
            .to(self.contract)
            .data(data)
            .into();
        self.provider
            .call(&tx, None)
            .await
            .map_err(|e| e.to_string())
    }

    async fn fetch(&self, id: u64) -> Result<IndexedBounty, String> {
        decode_bounty(&self.call(get_bounty_call(id)).await?)
    }

    async fn store(&self, b: &IndexedBounty) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            INSERT INTO chain_bounties (
                chain_id, contract, bounty_id, creator, artifact_hash, artifact_key,
                artifact_type, description, reward_wei, total_staked_wei, deadline,
                status, consensus_verdict, analysis_count, created_on_chain, updated_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, NOW())
            ON CONFLICT (chain_id, contract, bounty_id) DO UPDATE SET
                total_staked_wei = EXCLUDED.total_staked_wei,
                status = EXCLUDED.status,
                consensus_verdict = EXCLUDED.consensus_verdict,
                analysis_count = EXCLUDED.analysis_count,
                updated_at = NOW()
            "#,
        )
        .bind(self.chain_id)
        .bind(&self.contract_key)
        .bind(b.id as i64)
        .bind(&b.creator)
        .bind(&b.artifact_hash)
        .bind(artifact_key(&b.artifact_hash))
        .bind(&b.artifact_type)
        .bind(&b.description)
        .bind(b.reward.to_string())
        .bind(b.total_staked.to_string())
        .bind(timestamp(b.deadline))
        .bind(b.status as i16)
        .bind(b.consensus_verdict as i16)
        .bind(b.analysis_count.min(i32::MAX as u64) as i32)
        .bind(timestamp(b.created_at))
        .execute(&self.db)
        .await?;
        Ok(())
    }

    /// One pass: new bounties, then the stalest open ones. Returns how many it stored.
    async fn run_once(&self) -> Result<usize, String> {
        let total = decode_total(&self.call(get_total_bounties_call()).await?)?;
        let known: Option<i64> = sqlx::query_scalar(
            "SELECT MAX(bounty_id) FROM chain_bounties WHERE chain_id = $1 AND contract = $2",
        )
        .bind(self.chain_id)
        .bind(&self.contract_key)
        .fetch_one(&self.db)
        .await
        .map_err(|e| e.to_string())?;
        let known = known.unwrap_or(0).max(0) as u64;

        let mut stored = 0;
        for id in (known + 1)..=total.min(known + NEW_PER_CYCLE) {
            let b = self.fetch(id).await?;
            self.store(&b).await.map_err(|e| e.to_string())?;
            stored += 1;
        }

        let open: Vec<i64> = sqlx::query_scalar(
            "SELECT bounty_id FROM chain_bounties
             WHERE chain_id = $1 AND contract = $2 AND status = 0
             ORDER BY updated_at LIMIT $3",
        )
        .bind(self.chain_id)
        .bind(&self.contract_key)
        .bind(REFRESH_PER_CYCLE)
        .fetch_all(&self.db)
        .await
        .map_err(|e| e.to_string())?;
        for id in open {
            let b = self.fetch(id as u64).await?;
            self.store(&b).await.map_err(|e| e.to_string())?;
            stored += 1;
        }
        Ok(stored)
    }
}

/// Starts the indexer when the marketplace contracts are configured.
/// `CHAIN_INDEX_INTERVAL_SECS` sets how often it runs (default 30).
pub fn spawn(state: AppState) {
    let cfg = &state.config.blockchain;
    let info = chain_info(cfg, None, None);
    let Some(contracts) = info.contracts.filter(|_| info.enabled) else {
        tracing::info!("chain indexer: off (marketplace contracts not configured)");
        return;
    };
    let Some(rpc) = server_rpc_url(cfg) else {
        tracing::warn!("chain indexer: off (no RPC URL for chain {})", cfg.chain_id);
        return;
    };
    let provider = match Provider::<Http>::try_from(rpc.as_str()) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!("chain indexer: off (bad RPC URL: {e})");
            return;
        }
    };
    let contract: Address = match contracts.bounty_manager.parse() {
        Ok(a) => a,
        Err(_) => return,
    };
    let every = std::env::var("CHAIN_INDEX_INTERVAL_SECS")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|s| *s >= 5)
        .unwrap_or(30);
    let indexer = Indexer {
        provider,
        db: state.db.pool().clone(),
        chain_id: cfg.chain_id as i64,
        contract,
        contract_key: format!("{contract:#x}"),
    };
    tracing::info!(
        chain = cfg.chain_id,
        every_secs = every,
        "chain indexer: on"
    );
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(every));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut failing = false;
        loop {
            tick.tick().await;
            match indexer.run_once().await {
                Ok(n) => {
                    if failing {
                        tracing::info!("chain indexer: reading the chain again");
                    }
                    failing = false;
                    if n > 0 {
                        tracing::debug!(stored = n, "chain indexer: pass done");
                    }
                }
                // Log once per outage, not every cycle.
                Err(e) if !failing => {
                    failing = true;
                    tracing::warn!("chain indexer: pass failed, will retry: {e}");
                }
                Err(_) => {}
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encoded_bounty() -> Vec<u8> {
        let creator: Address = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
            .parse()
            .unwrap();
        abi::encode(&[Token::Tuple(vec![
            Token::Uint(U256::from(7)),
            Token::Address(creator),
            Token::String("AB12cd".into()),
            Token::String("file".into()),
            Token::Uint(U256::exp10(20)), // 100 THREAT
            Token::Uint(U256::from(2_000_000_000u64)),
            Token::String("Is it malicious?".into()),
            Token::Uint(U256::from(2)),
            Token::Uint(U256::from(2)),
            Token::Uint(U256::exp10(19) * 4),
            Token::Uint(U256::from(3)),
            Token::Uint(U256::from(1_999_000_000u64)),
        ])])
    }

    #[test]
    fn calls_use_the_contract_selectors() {
        assert_eq!(
            get_total_bounties_call().as_ref(),
            &keccak256("getTotalBounties()")[..4]
        );
        let call = get_bounty_call(5);
        assert_eq!(&call[..4], &keccak256("getBounty(uint256)")[..4]);
        assert_eq!(call.len(), 36);
        assert_eq!(call[35], 5);
    }

    #[test]
    fn decodes_a_bounty_struct() {
        let b = decode_bounty(&encoded_bounty()).unwrap();
        assert_eq!(b.id, 7);
        assert_eq!(b.creator, "0x70997970c51812dc3a010c7d01b50e0d17dc79c8");
        assert_eq!(b.artifact_hash, "AB12cd");
        assert_eq!(b.reward.to_string(), "100000000000000000000");
        assert_eq!(b.status, 2);
        assert_eq!(b.consensus_verdict, 2);
        assert_eq!(b.total_staked.to_string(), "40000000000000000000");
        assert_eq!(b.analysis_count, 3);
        assert_eq!(b.deadline, 2_000_000_000);
    }

    #[test]
    fn refuses_garbage() {
        assert!(decode_bounty(&[1, 2, 3]).is_err());
        assert!(decode_total(&[]).is_err());
        assert_eq!(
            decode_total(&abi::encode(&[Token::Uint(U256::from(12))])),
            Ok(12)
        );
        assert!(decode_total(&abi::encode(&[Token::Uint(U256::MAX)])).is_err());
    }

    #[test]
    fn artifacts_are_matched_case_insensitively() {
        assert_eq!(artifact_key("  AB12CD \n"), "ab12cd");
        assert_eq!(
            artifact_key("https://Example.org/X"),
            "https://example.org/x"
        );
    }
}
