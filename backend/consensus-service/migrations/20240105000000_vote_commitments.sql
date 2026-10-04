-- Commit-reveal voting.
--
-- With open voting, a late voter can read the running tally and copy whoever
-- is ahead. Twenty "independent" analysts then produce one opinion echoed
-- nineteen times, and every accuracy figure computed from that consensus is
-- measuring herd size rather than judgement.
--
-- Commit-reveal closes that: during the commit window a voter submits only
-- sha256(bounty_id:engine_id:verdict:confidence:salt), which reveals nothing.
-- Once the window shuts they publish the plaintext, and the hash is checked.
-- A vote cannot be changed after the fact and cannot be copied beforehand.
--
-- This cannot be retrofitted once people are voting: you cannot un-teach a
-- population to herd, and historical verdicts stay contaminated.

CREATE TABLE IF NOT EXISTS consensus_vote_commits (
    bounty_id    UUID NOT NULL,
    engine_id    VARCHAR(255) NOT NULL,

    -- Lowercase hex sha256 of the commitment preimage. 64 chars exactly.
    commitment   CHAR(64) NOT NULL,

    committed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Set when the matching plaintext is accepted. A commit may be revealed
    -- at most once; the revealed vote itself lands in consensus_submissions.
    revealed_at  TIMESTAMPTZ,

    PRIMARY KEY (bounty_id, engine_id),

    -- Reject anything that is not lowercase hex of the right length, so a
    -- malformed commitment fails at write time rather than at reveal time
    -- when the voter can no longer do anything about it.
    CONSTRAINT commitment_is_hex_sha256
        CHECK (commitment ~ '^[0-9a-f]{64}$')
);

-- The phase anchor: "when did voting open on this bounty?" is MIN(committed_at),
-- and the reveal worker asks it constantly.
CREATE INDEX IF NOT EXISTS idx_vote_commits_bounty_committed
    ON consensus_vote_commits(bounty_id, committed_at);

-- "Which commits are still unrevealed?" -- drives both the reveal deadline
-- check and any future slashing of no-shows.
CREATE INDEX IF NOT EXISTS idx_vote_commits_unrevealed
    ON consensus_vote_commits(bounty_id) WHERE revealed_at IS NULL;
