//! What the website needs to talk to the marketplace contracts directly.
//!
//! The marketplace is non-custodial: people sign every transaction in their
//! own wallet, and the server never holds their tokens. The website only
//! needs the network and contract addresses, which this endpoint publishes.
//!
//! The server's own RPC URL (`BLOCKCHAIN_RPC_URL`) may carry a provider key,
//! so it is never sent to browsers: `PUBLIC_CHAIN_RPC_URL`, or the network's
//! public endpoint, is published instead.

use axum::{
    extract::{Query, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};

use crate::{config::BlockchainConfig, services::chain_indexer::artifact_key, AppState};

#[derive(Debug, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ChainInfo {
    /// False until the contracts are deployed and configured.
    pub enabled: bool,
    pub chain_id: u64,
    pub chain_name: String,
    pub native_currency: &'static str,
    pub rpc_url: Option<String>,
    pub explorer_url: Option<String>,
    pub contracts: Option<Contracts>,
}

#[derive(Debug, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Contracts {
    pub threat_token: String,
    pub bounty_manager: String,
    pub reputation_system: Option<String>,
}

struct Network {
    name: &'static str,
    rpc: &'static str,
    explorer: &'static str,
}

fn known_network(chain_id: u64) -> Option<Network> {
    match chain_id {
        84532 => Some(Network {
            name: "Base Sepolia",
            rpc: "https://sepolia.base.org",
            explorer: "https://sepolia.basescan.org",
        }),
        8453 => Some(Network {
            name: "Base",
            rpc: "https://mainnet.base.org",
            explorer: "https://basescan.org",
        }),
        11155111 => Some(Network {
            name: "Sepolia",
            rpc: "https://ethereum-sepolia-rpc.publicnode.com",
            explorer: "https://sepolia.etherscan.io",
        }),
        31337 | 1337 => Some(Network {
            name: "Hardhat (local)",
            rpc: "http://127.0.0.1:8545",
            explorer: "",
        }),
        _ => None,
    }
}

/// A non-zero `0x` address of 20 bytes, or None.
fn contract_address(raw: &str) -> Option<String> {
    let s = raw.trim();
    let hex = s.strip_prefix("0x")?;
    if hex.len() != 40 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    if hex.bytes().all(|b| b == b'0') {
        return None;
    }
    Some(s.to_string())
}

/// An http(s) URL with no credentials in it, or None.
fn public_url(raw: &str) -> Option<String> {
    let url = url::Url::parse(raw.trim()).ok()?;
    if !matches!(url.scheme(), "http" | "https")
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return None;
    }
    Some(raw.trim().trim_end_matches('/').to_string())
}

pub(crate) fn chain_info(
    cfg: &BlockchainConfig,
    public_rpc: Option<&str>,
    explorer: Option<&str>,
) -> ChainInfo {
    let network = known_network(cfg.chain_id);
    let token = contract_address(&cfg.contracts.threat_token);
    let bounty = contract_address(&cfg.contracts.bounty_manager);
    let rpc_url = public_rpc
        .and_then(public_url)
        .or_else(|| network.as_ref().map(|n| n.rpc.to_string()));
    let explorer_url = explorer.and_then(public_url).or_else(|| {
        network
            .as_ref()
            .map(|n| n.explorer.to_string())
            .filter(|e| !e.is_empty())
    });
    let contracts = match (token, bounty) {
        (Some(threat_token), Some(bounty_manager)) => Some(Contracts {
            threat_token,
            bounty_manager,
            reputation_system: contract_address(&cfg.contracts.reputation_system),
        }),
        _ => None,
    };
    ChainInfo {
        enabled: cfg.chain_id != 0 && contracts.is_some() && rpc_url.is_some(),
        chain_id: cfg.chain_id,
        chain_name: network
            .map(|n| n.name.to_string())
            .unwrap_or_else(|| format!("Chain {}", cfg.chain_id)),
        native_currency: "ETH",
        rpc_url,
        explorer_url,
        contracts,
    }
}

/// `GET /api/v1/chain`: public.
pub async fn get_chain(State(state): State<AppState>) -> Json<ChainInfo> {
    let public_rpc = std::env::var("PUBLIC_CHAIN_RPC_URL").ok();
    let explorer = std::env::var("CHAIN_EXPLORER_URL").ok();
    Json(chain_info(
        &state.config.blockchain,
        public_rpc.as_deref(),
        explorer.as_deref(),
    ))
}

/// The RPC the server itself reads the chain through: `BLOCKCHAIN_RPC_URL`,
/// or the network's public endpoint when that is empty. Never published.
pub(crate) fn server_rpc_url(cfg: &BlockchainConfig) -> Option<String> {
    let own = cfg.rpc_url.trim();
    if !own.is_empty() {
        return Some(own.to_string());
    }
    known_network(cfg.chain_id).map(|n| n.rpc.to_string())
}

#[derive(Debug, Deserialize)]
pub struct BountiesQuery {
    /// A file's SHA-256 or a URL, as a bounty points at it.
    pub artifact: String,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct IndexedBountyView {
    #[sqlx(rename = "bounty_id")]
    pub id: i64,
    pub creator: String,
    pub artifact_hash: String,
    pub artifact_type: String,
    pub description: String,
    /// In the smallest unit of THREAT, as a decimal string (uint256).
    #[sqlx(rename = "reward_wei")]
    pub reward: String,
    #[sqlx(rename = "total_staked_wei")]
    pub total_staked: String,
    /// Unix seconds.
    pub deadline: i64,
    pub status: i16,
    pub consensus_verdict: i16,
    pub analysis_count: i32,
    pub created_at: i64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BountiesResponse {
    /// False when the marketplace isn't configured, so nothing is indexed.
    pub indexed: bool,
    pub bounties: Vec<IndexedBountyView>,
}

/// `GET /api/v1/chain/bounties?artifact=<sha256 or URL>`: public.
/// The bounties posted on one file or URL, newest first, from the indexer's
/// copy of the chain (it lags the chain by up to one indexer cycle).
pub async fn get_chain_bounties(
    State(state): State<AppState>,
    Query(q): Query<BountiesQuery>,
) -> Result<Json<BountiesResponse>, (StatusCode, Json<serde_json::Value>)> {
    let key = artifact_key(&q.artifact);
    if key.is_empty() || key.len() > 2048 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "artifact must be a SHA-256 or a URL" })),
        ));
    }
    let cfg = &state.config.blockchain;
    let info = chain_info(cfg, None, None);
    let Some(contracts) = info.contracts.filter(|_| info.enabled) else {
        return Ok(Json(BountiesResponse {
            indexed: false,
            bounties: vec![],
        }));
    };
    let bounties = sqlx::query_as::<_, IndexedBountyView>(
        r#"
        SELECT bounty_id, creator, artifact_hash, artifact_type, description,
               reward_wei, total_staked_wei,
               EXTRACT(EPOCH FROM deadline)::BIGINT AS deadline,
               status, consensus_verdict, analysis_count,
               EXTRACT(EPOCH FROM created_on_chain)::BIGINT AS created_at
        FROM chain_bounties
        WHERE chain_id = $1 AND contract = $2 AND artifact_key = $3
        ORDER BY bounty_id DESC
        LIMIT 20
        "#,
    )
    .bind(cfg.chain_id as i64)
    .bind(contracts.bounty_manager.to_lowercase())
    .bind(key)
    .fetch_all(state.db.pool())
    .await
    .map_err(|e| {
        tracing::error!("chain bounties lookup failed: {e}");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "Couldn't look up bounties" })),
        )
    })?;
    Ok(Json(BountiesResponse {
        indexed: true,
        bounties,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ContractsConfig;

    const TOKEN: &str = "0x5FbDB2315678afecb367f032d93F642f64180aa3";
    const BOUNTY: &str = "0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0";

    fn cfg(chain_id: u64, token: &str, bounty: &str) -> BlockchainConfig {
        BlockchainConfig {
            chain_id,
            rpc_url: "https://base-sepolia.g.alchemy.com/v2/server-only".to_string(),
            contracts: ContractsConfig {
                bounty_manager: bounty.to_string(),
                threat_token: token.to_string(),
                reputation_system: String::new(),
                governance: None,
            },
            ..BlockchainConfig::default()
        }
    }

    #[test]
    fn base_sepolia_with_contracts_is_enabled() {
        let info = chain_info(&cfg(84532, TOKEN, BOUNTY), None, None);
        assert!(info.enabled);
        assert_eq!(info.chain_name, "Base Sepolia");
        assert_eq!(info.rpc_url.as_deref(), Some("https://sepolia.base.org"));
        assert_eq!(
            info.explorer_url.as_deref(),
            Some("https://sepolia.basescan.org")
        );
        let c = info.contracts.unwrap();
        assert_eq!(c.bounty_manager, BOUNTY);
        assert_eq!(c.reputation_system, None);
    }

    #[test]
    fn the_server_rpc_url_is_never_published() {
        let info = chain_info(&cfg(84532, TOKEN, BOUNTY), None, None);
        let json = serde_json::to_string(&info).unwrap();
        assert!(!json.contains("alchemy"));
    }

    #[test]
    fn zero_or_missing_addresses_disable_it() {
        let zero = "0x0000000000000000000000000000000000000000";
        assert!(!chain_info(&cfg(11155111, zero, zero), None, None).enabled);
        assert!(!chain_info(&cfg(84532, TOKEN, ""), None, None).enabled);
        assert!(!chain_info(&cfg(84532, "0x123", BOUNTY), None, None).enabled);
    }

    #[test]
    fn unknown_chains_need_a_public_rpc() {
        assert!(!chain_info(&cfg(999, TOKEN, BOUNTY), None, None).enabled);
        let info = chain_info(&cfg(999, TOKEN, BOUNTY), Some("https://rpc.example/"), None);
        assert!(info.enabled);
        assert_eq!(info.rpc_url.as_deref(), Some("https://rpc.example"));
        assert_eq!(info.explorer_url, None);
    }

    #[test]
    fn the_server_reads_through_its_own_rpc_or_the_public_one() {
        let c = cfg(84532, TOKEN, BOUNTY);
        assert_eq!(
            server_rpc_url(&c).as_deref(),
            Some("https://base-sepolia.g.alchemy.com/v2/server-only")
        );
        let public = BlockchainConfig {
            rpc_url: " ".into(),
            ..cfg(84532, TOKEN, BOUNTY)
        };
        assert_eq!(
            server_rpc_url(&public).as_deref(),
            Some("https://sepolia.base.org")
        );
        let unknown = BlockchainConfig {
            rpc_url: String::new(),
            ..cfg(999, TOKEN, BOUNTY)
        };
        assert_eq!(server_rpc_url(&unknown), None);
    }

    #[test]
    fn rpc_urls_with_credentials_are_refused() {
        let info = chain_info(
            &cfg(999, TOKEN, BOUNTY),
            Some("https://user:pw@rpc.example"),
            None,
        );
        assert!(!info.enabled);
        assert!(public_url("javascript:alert(1)").is_none());
    }
}
