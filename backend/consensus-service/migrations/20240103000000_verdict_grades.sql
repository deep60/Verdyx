-- Delayed re-grading of finalized consensus results.
--
-- A finalized consensus is the crowd's opinion, not the truth. This table
-- records what a bounty's verdict looked like once the world had more
-- information -- a later re-scan, a retro-scan with a newer rule, or a human
-- review. Payouts held back at finalization settle against THIS verdict, and
-- reputation is corrected from it.
--
-- One row per bounty: the grade is the current best answer, not a log. The
-- history of how it changed lives in reputation_history / payout records.

CREATE TABLE IF NOT EXISTS verdict_grades (
    bounty_id        UUID PRIMARY KEY,

    -- What consensus said when the bounty finalized.
    original_verdict VARCHAR(50) NOT NULL,

    -- What we believe now, after the grading delay.
    graded_verdict   VARCHAR(50) NOT NULL,

    -- Denormalized so "how often was the crowd wrong?" is an index scan,
    -- not a full-table string comparison. Kept honest by a CHECK.
    verdict_changed  BOOLEAN NOT NULL,

    -- Where the grade came from: 'rescan', 'retroscan', 'dispute', 'admin'.
    grade_source     VARCHAR(32) NOT NULL,

    -- Hash of the sample this grade was derived from, when known.
    sample_hash      TEXT,

    -- Free-text context, e.g. which engine flipped, or an admin's reason.
    notes            TEXT,

    graded_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT verdict_changed_matches
        CHECK (verdict_changed = (original_verdict IS DISTINCT FROM graded_verdict))
);

-- "Show me every bounty the crowd got wrong" -- the query this table exists for.
CREATE INDEX IF NOT EXISTS idx_verdict_grades_changed
    ON verdict_grades(verdict_changed) WHERE verdict_changed = true;

CREATE INDEX IF NOT EXISTS idx_verdict_grades_graded_at
    ON verdict_grades(graded_at DESC);

CREATE INDEX IF NOT EXISTS idx_verdict_grades_source
    ON verdict_grades(grade_source);

-- The regrader needs to re-scan the original sample. consensus_results had no
-- reference to it, so carry the hash alongside the verdict. Nullable: results
-- finalized before this migration have no hash and are skipped by the worker
-- until one is supplied.
ALTER TABLE consensus_results
    ADD COLUMN IF NOT EXISTS sample_hash TEXT;

-- Partial index: the regrader's hot query is "finalized, old enough, ungraded".
CREATE INDEX IF NOT EXISTS idx_consensus_results_finalized_at
    ON consensus_results(finalized_at) WHERE is_finalized = true;
