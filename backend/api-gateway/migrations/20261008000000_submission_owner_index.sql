-- Dashboard list is always "this user's uploads, newest first".
-- The single-column submitter index does not cover that ORDER BY.
CREATE INDEX IF NOT EXISTS idx_submissions_owner_created
    ON submissions (submitter_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_analysis_results_submission
    ON analysis_results (submission_id);
