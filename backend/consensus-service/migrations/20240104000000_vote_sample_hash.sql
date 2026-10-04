-- Carry the sample's hash alongside each vote.
--
-- The regrader re-scans a bounty's sample after the grading delay, but nothing
-- in consensus-service knew *which* sample a bounty was about: votes recorded
-- an engine and a verdict, never the artifact. The hash arrives with the vote
-- (whoever casts one has the sample in front of them), and is promoted onto
-- consensus_results when the bounty finalizes.
--
-- Nullable: votes cast before this migration have no hash, and a bounty whose
-- votes all lack one is simply skipped by the regrader rather than guessed at.

ALTER TABLE consensus_submissions
    ADD COLUMN IF NOT EXISTS sample_hash TEXT;

CREATE INDEX IF NOT EXISTS idx_consensus_submissions_sample_hash
    ON consensus_submissions(sample_hash) WHERE sample_hash IS NOT NULL;
