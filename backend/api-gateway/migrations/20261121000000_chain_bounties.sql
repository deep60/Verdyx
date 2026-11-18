-- On-chain bounties, copied from the BountyManager contract by the gateway's
-- indexer (src/services/chain_indexer.rs) so a scan report can find the
-- bounties posted on its file or URL without reading every bounty from the
-- chain. The contract stays the source of truth; the bounty page reads it
-- directly.
--
-- Keyed by chain and contract address, so a redeployed contract starts a
-- fresh set rather than mixing with the old one.
CREATE TABLE IF NOT EXISTS chain_bounties (
    chain_id BIGINT NOT NULL,
    contract TEXT NOT NULL,               -- lowercase 0x address
    bounty_id BIGINT NOT NULL,
    creator TEXT NOT NULL,
    artifact_hash TEXT NOT NULL,          -- as posted: a SHA-256 or a URL
    artifact_key TEXT NOT NULL,           -- lowercased and trimmed, for lookups
    artifact_type TEXT NOT NULL,
    description TEXT NOT NULL,
    reward_wei TEXT NOT NULL,             -- uint256 as a decimal string
    total_staked_wei TEXT NOT NULL,
    deadline TIMESTAMPTZ NOT NULL,
    status SMALLINT NOT NULL,             -- 0 Active, 1 InReview, 2 Completed, 3 Cancelled, 4 Disputed
    consensus_verdict SMALLINT NOT NULL,  -- 0 Pending, 1 Benign, 2 Malicious, 3 Suspicious
    analysis_count INTEGER NOT NULL,
    created_on_chain TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (chain_id, contract, bounty_id)
);

CREATE INDEX IF NOT EXISTS idx_chain_bounties_artifact
    ON chain_bounties (chain_id, contract, artifact_key);

-- Open bounties are re-read until they settle; this finds the stalest first.
CREATE INDEX IF NOT EXISTS idx_chain_bounties_open
    ON chain_bounties (chain_id, contract, updated_at)
    WHERE status = 0;
